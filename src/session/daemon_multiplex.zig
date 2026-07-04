//! stdio<->socket passthrough client modes (`--stdio-attach` multiplex and
//! `--mux-attach` passthrough) for the remote session daemon. Split out of
//! daemon.zig; `run` dispatches here. Pure move — bodies are byte-identical.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const session = @import("../session.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h"); // setenv / unsetenv (cmux execve self-handoff)
    @cInclude("sys/ioctl.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/un.h");
    @cInclude("sys/wait.h");
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.ssh_session);

const daemon_net = @import("daemon_net.zig");
const connectUnixSocket = daemon_net.connectUnixSocket;
const closeFd = daemon_net.closeFd;
const daemonLog = daemon_net.daemonLog;
const sendFrameFd = session.shared.sendFrameFd;
const shiftBuffer = session.shared.shiftBuffer;

/// Direct stdio↔socket bidirectional pump for ClientMux frames.
///
/// Why this exists: cmux opens a second SSH channel dedicated to ClientMux
/// (browser_proxy / port_listener / tcp_connect / tcp_accepted) traffic via
/// `client.openMultiplexChannel`. That channel is exec'd here. Unlike the
/// terminal-side `multiplex` mode, which is itself a *demultiplexer* that
/// only understands `.open`/`.close`/`.data_in`/... and silently drops
/// `.channel_*` frames (the bug this mode fixes — see the multiplex switch
/// in this file: `.channel_open` falls into `else => {}` and disappears),
/// this mode is a pure passthrough: every byte from stdin goes to the main
/// daemon's unix socket, and every byte read from that socket goes to
/// stdout. The main daemon's `ClientThread` (this file, ~line 376) already
/// dispatches `.channel_*` frames to its `channel_registry`, which has
/// `browser_proxy`, `port_listener`, `tcp_connect`, `tcp_accepted`,
/// `file_transfer` registered.
///
/// Lifecycle: exits when either side EOFs or errors. The main daemon must
/// already be running — `client.ensureRemoteDaemon(--daemonize)` is the
/// caller's responsibility before exec'ing this mode.
pub fn muxAttach(alloc: Allocator, stderr: *std.Io.Writer) !u8 {
    _ = stderr;

    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    const sock_fd = connectUnixSocket(socket_path) catch |err| {
        daemonLog("mux-attach: connect to daemon socket failed: {}", .{err});
        return 1;
    };
    defer closeFd(sock_fd);

    const stdin_fd = posix.STDIN_FILENO;
    const stdout_fd = posix.STDOUT_FILENO;

    var pollfds = [2]c.struct_pollfd{
        .{ .fd = stdin_fd, .events = c.POLLIN, .revents = 0 },
        .{ .fd = sock_fd, .events = c.POLLIN, .revents = 0 },
    };

    var buf: [16 * 1024]u8 = undefined;

    while (true) {
        const rc = c.poll(&pollfds, 2, -1);
        if (rc < 0) {
            if (std.c._errno().* == c.EINTR) continue;
            return 1;
        }

        // stdin → socket
        if (pollfds[0].revents & c.POLLIN != 0) {
            const n = posix.read(stdin_fd, &buf) catch return 0;
            if (n == 0) return 0;
            try writeAll(sock_fd, buf[0..n]);
        }
        if (pollfds[0].revents & (c.POLLHUP | c.POLLERR) != 0 and
            pollfds[0].revents & c.POLLIN == 0)
        {
            return 0;
        }

        // socket → stdout
        if (pollfds[1].revents & c.POLLIN != 0) {
            const n = posix.read(sock_fd, &buf) catch return 0;
            if (n == 0) return 0;
            try writeAll(stdout_fd, buf[0..n]);
        }
        if (pollfds[1].revents & (c.POLLHUP | c.POLLERR) != 0 and
            pollfds[1].revents & c.POLLIN == 0)
        {
            return 0;
        }
    }
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch |err| return err;
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

// ============================================================================
// Multiplexer — pure passthrough between SSH stdin/stdout and daemon socket
// ============================================================================
const max_mux_sessions = 64;

const MuxSession = struct {
    target: u16,
    daemon_fd: posix.fd_t,
    read_buf: std.ArrayList(u8),

    fn deinit(self: *MuxSession, alloc: Allocator) void {
        closeFd(self.daemon_fd);
        self.read_buf.deinit(alloc);
    }
};

/// Multiplexed stdio-attach mode. Pure frame passthrough between SSH channel
/// and daemon Unix sockets. The daemon handles all VT processing and state.
pub fn multiplex(alloc: Allocator, stderr: *std.Io.Writer) !u8 {
    _ = stderr;

    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    var sessions: [max_mux_sessions]?MuxSession = .{null} ** max_mux_sessions;
    var stdin_buf = std.ArrayList(u8).empty;
    defer stdin_buf.deinit(alloc);

    // Keepalive state
    const now_init = std.time.nanoTimestamp();
    var last_keepalive_sent: i128 = now_init;
    var last_keepalive_received: i128 = now_init;

    defer {
        for (&sessions) |*slot| {
            if (slot.*) |*s| {
                s.deinit(alloc);
                slot.* = null;
            }
        }
    }

    const stdout_file = std.fs.File.stdout();
    const stdin_fd = posix.STDIN_FILENO;

    while (true) {
        // Build poll fds: [0] = stdin, [1..] = daemon sockets
        var pollfds: [1 + max_mux_sessions]c.struct_pollfd = undefined;
        pollfds[0] = .{
            .fd = stdin_fd,
            .events = c.POLLIN,
            .revents = 0,
        };

        var poll_session_idx: [max_mux_sessions]usize = undefined;
        var n_fds: usize = 1;
        for (&sessions, 0..) |*slot, i| {
            if (slot.* != null) {
                pollfds[n_fds] = .{
                    .fd = slot.*.?.daemon_fd,
                    .events = c.POLLIN,
                    .revents = 0,
                };
                poll_session_idx[n_fds - 1] = i;
                n_fds += 1;
            }
        }

        const poll_rc = c.poll(&pollfds, @intCast(n_fds), 50);

        if (poll_rc < 0) {
            if (std.c._errno().* == c.EINTR) continue;
            return error.PollFailed;
        }

        // Check stdin for frames from client
        if (pollfds[0].revents & c.POLLIN != 0) {
            var raw_buf: [8192]u8 = undefined;
            const n = posix.read(stdin_fd, &raw_buf) catch break;
            if (n == 0) break;
            try stdin_buf.appendSlice(alloc, raw_buf[0..n]);
        }

        if (pollfds[0].revents & (c.POLLHUP | c.POLLERR) != 0 and
            pollfds[0].revents & c.POLLIN == 0)
        {
            break;
        }

        // Process complete frames from stdin buffer
        while (stdin_buf.items.len >= session.protocol.header_size) {
            const header = session.protocol.Header.parseFromBuf(
                stdin_buf.items[0..session.protocol.header_size],
            ) catch {
                shiftBuffer(&stdin_buf, session.protocol.header_size);
                continue;
            };
            const kind = header.kind;
            const target = header.target;
            const total = session.protocol.header_size + header.len;
            if (stdin_buf.items.len < total) break;

            const payload = stdin_buf.items[session.protocol.header_size..total];

            switch (kind) {
                .ping => {
                    last_keepalive_received = std.time.nanoTimestamp();
                    session.shared.sendFrameFile(stdout_file, .pong, .{}, 0, "") catch {};
                },
                .open => {
                    handleOpenFrame(
                        &sessions,
                        kind,
                        target,
                        payload,
                        socket_path,
                    ) catch |err| {
                        const msg = std.fmt.allocPrint(alloc, "open failed: {}", .{err}) catch {
                            session.shared.sendFrameFile(stdout_file, .err, .{}, target, "open failed") catch {};
                            shiftBuffer(&stdin_buf, total);
                            continue;
                        };
                        defer alloc.free(msg);
                        session.shared.sendFrameFile(stdout_file, .err, .{}, target, msg) catch {};
                    };
                },
                .close => {
                    const close_data = session.protocol.Close.parse(payload) catch {
                        shiftBuffer(&stdin_buf, total);
                        continue;
                    };
                    switch (close_data.mode) {
                        .surface => {
                            // Forward to daemon so it can kill the surface process
                            if (findMuxSession(&sessions, target)) |s| {
                                sendFrameFd(s.daemon_fd, .close, 0, payload) catch {};
                            }
                            closeMuxSession(&sessions, alloc, target);
                        },
                        .session => {
                            // Forward to daemon for session-level kill
                            if (findMuxSession(&sessions, target)) |s| {
                                sendFrameFd(s.daemon_fd, .close, 0, payload) catch {};
                            }
                            closeMuxSession(&sessions, alloc, target);
                        },
                        .detach => {
                            if (findMuxSession(&sessions, target)) |s| {
                                sendFrameFd(s.daemon_fd, .close, 0, payload) catch {};
                            }
                            closeMuxSession(&sessions, alloc, target);
                        },
                    }
                },
                // All other frames: passthrough to the daemon socket
                .data_in,
                .resize,
                .layout,
                .rename,
                .size_mode_change,
                .kick_viewer,
                .session_meta,
                => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, kind, target, payload) catch {
                            session.shared.sendFrameFile(stdout_file, .eof, .{}, target, "") catch {};
                            closeMuxSession(&sessions, alloc, target);
                        };
                    }
                },
                .list_request => {
                    handleSessionListRequest(socket_path, stdout_file) catch |err| {
                        log.warn("session_list failed err={}", .{err});
                    };
                },
                else => {},
            }

            shiftBuffer(&stdin_buf, total);
        }

        // Check daemon sockets for frames — pure passthrough
        var pidx: usize = 1;
        while (pidx < n_fds) : (pidx += 1) {
            const sess_idx = poll_session_idx[pidx - 1];
            const slot = &sessions[sess_idx];
            if (slot.*) |*s| {
                if (pollfds[pidx].revents & c.POLLIN != 0) {
                    var daemon_buf: [8192]u8 = undefined;
                    const n = posix.read(s.daemon_fd, &daemon_buf) catch {
                        session.shared.sendFrameFile(stdout_file, .eof, .{}, s.target, "") catch {};
                        s.deinit(alloc);
                        slot.* = null;
                        continue;
                    };
                    if (n == 0) {
                        session.shared.sendFrameFile(stdout_file, .eof, .{}, s.target, "") catch {};
                        s.deinit(alloc);
                        slot.* = null;
                        continue;
                    }
                    try s.read_buf.appendSlice(alloc, daemon_buf[0..n]);
                }

                if (pollfds[pidx].revents & (c.POLLHUP | c.POLLERR) != 0 and
                    pollfds[pidx].revents & c.POLLIN == 0)
                {
                    session.shared.sendFrameFile(stdout_file, .eof, .{}, s.target, "") catch {};
                    s.deinit(alloc);
                    slot.* = null;
                    continue;
                }

                // Forward complete frames from daemon to stdout (rewrite target)
                while (s.read_buf.items.len >= session.protocol.header_size) {
                    const dheader = session.protocol.Header.parseFromBuf(
                        s.read_buf.items[0..session.protocol.header_size],
                    ) catch {
                        shiftBuffer(&s.read_buf, session.protocol.header_size);
                        continue;
                    };
                    const dtotal = session.protocol.header_size + dheader.len;
                    if (s.read_buf.items.len < dtotal) break;

                    const dpayload = s.read_buf.items[session.protocol.header_size..dtotal];

                    // Rewrite target ID and forward to client (preserve flags)
                    session.shared.sendFrameFile(stdout_file, dheader.kind, dheader.flags, s.target, dpayload) catch {};
                    shiftBuffer(&s.read_buf, dtotal);
                }
            }
        }

        // Keepalive: send ping if interval elapsed
        {
            const ka_now = std.time.nanoTimestamp();
            if (ka_now - last_keepalive_sent >= session.protocol.keepalive_interval_ns) {
                session.shared.sendFrameFile(stdout_file, .ping, .{}, 0, "") catch {};
                last_keepalive_sent = ka_now;
            }

            if (ka_now - last_keepalive_received > session.protocol.keepalive_server_timeout_ns) {
                log.warn("no keepalive from client for {d}s, closing", .{
                    @as(i64, @intCast(@divFloor(ka_now - last_keepalive_received, std.time.ns_per_s))),
                });
                break;
            }
        }

        // Exit if all sessions closed and stdin is gone
        var any_active = false;
        for (&sessions) |slot| {
            if (slot != null) {
                any_active = true;
                break;
            }
        }
        if (!any_active and stdin_buf.items.len == 0 and
            pollfds[0].revents & (c.POLLHUP | c.POLLERR) != 0)
        {
            break;
        }
    }

    return 0;
}

fn handleOpenFrame(
    sessions: *[max_mux_sessions]?MuxSession,
    kind: session.protocol.Kind,
    target: u16,
    payload: []const u8,
    socket_path: []const u8,
) !void {
    var free_idx: ?usize = null;
    for (0..max_mux_sessions) |i| {
        if (sessions[i] == null) {
            free_idx = i;
            break;
        }
    }
    const idx = free_idx orelse return error.TooManySessions;

    const daemon_fd = try connectUnixSocket(socket_path);
    errdefer closeFd(daemon_fd);

    // Send the open frame directly to the daemon (binary protocol)
    sendFrameFd(daemon_fd, kind, target, payload) catch {
        return error.DaemonWriteFailed;
    };

    sessions[idx] = .{
        .target = target,
        .daemon_fd = daemon_fd,
        .read_buf = std.ArrayList(u8).empty,
    };
}

fn handleSessionListRequest(
    socket_path: []const u8,
    stdout_file: std.fs.File,
) !void {
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Send list_request frame to daemon
    sendFrameFd(fd, .list_request, 0, "") catch return;

    // Read and forward response frames
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        stdout_file.writeAll(buf[0..n]) catch break;
    }
}

fn findMuxSession(sessions: *[max_mux_sessions]?MuxSession, target: u16) ?*MuxSession {
    for (sessions) |*slot| {
        if (slot.*) |*s| {
            if (s.target == target) return s;
        }
    }
    return null;
}

fn closeMuxSession(sessions: *[max_mux_sessions]?MuxSession, alloc: Allocator, target: u16) void {
    for (sessions) |*slot| {
        if (slot.*) |*s| {
            if (s.target == target) {
                s.deinit(alloc);
                slot.* = null;
                return;
            }
        }
    }
}
