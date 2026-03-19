const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const Command = @import("../Command.zig");
const ptypkg = @import("../pty.zig");
const Pty = ptypkg.Pty;
const session = @import("../session.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("signal.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("sys/wait.h");
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.session_helper);

pub const Options = struct {
    daemonize: bool = false,
    daemon: bool = false,
    list: bool = false,
    @"protocol-version": bool = false,
    @"stdio-attach": bool = false,
    kill: ?[]const u8 = null,
    session: ?[]const u8 = null,
    new: bool = false,
    label: ?[]const u8 = null,
};

pub fn run(
    alloc: Allocator,
    opts: Options,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !u8 {
    if (comptime builtin.os.tag == .windows) {
        try stderr.writeAll("remote sessions are only implemented on POSIX platforms.\n");
        return 1;
    }

    if (opts.@"protocol-version") {
        try stdout.print("GHOSTTY_SESSION_PROTOCOL {d}\n", .{session.protocol.protocol_version});
        try stdout.flush();
        return 0;
    }

    if (opts.daemonize) {
        try daemonize(alloc);
        return 0;
    }

    if (opts.daemon) {
        try daemonMain(alloc);
        return 0;
    }

    if (opts.list) {
        try listSessions(alloc, stdout);
        return 0;
    }

    if (opts.kill) |id| {
        try killSession(alloc, id, stdout);
        return 0;
    }

    if (opts.@"stdio-attach") {
        return try multiplex(alloc, stderr);
    }

    try stderr.writeAll("missing helper mode\n");
    return 1;
}

fn daemonize(alloc: Allocator) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    if (try canConnect(socket_path)) return;

    // Classic POSIX double-fork to fully detach the daemon process.
    // This ensures the daemon has no inherited FDs from the parent
    // (important when launched via SSH, where inherited channel FDs
    // keep the SSH connection open forever).
    const pid1 = c.fork();
    if (pid1 < 0) return error.ForkFailed;
    if (pid1 > 0) {
        // Parent: wait for first child to exit, then poll for readiness.
        _ = c.waitpid(pid1, null, 0);
        var attempts: u32 = 0;
        while (attempts < 50) : (attempts += 1) {
            if (try canConnect(socket_path)) return;
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
        return;
    }

    // First child: create new session and fork again.
    _ = c.setsid();
    const pid2 = c.fork();
    if (pid2 < 0) c._exit(1);
    if (pid2 > 0) c._exit(0);

    // Grandchild: the actual daemon process.
    closeAllFds();
    reopenStdFds();
    _ = c.chdir("/");
    // Use page_allocator instead of the inherited GPA — the GPA captures
    // stack traces in debug builds, which requires debug info infrastructure
    // (opening the ELF binary) that breaks after closeAllFds.
    daemonMain(std.heap.page_allocator) catch {
        c._exit(1);
    };
    c._exit(0);
}

/// Close all file descriptors >= 3 to prevent inheriting FDs from the parent
/// (especially important when launched via SSH).
fn closeAllFds() void {
    // Try /proc/self/fd first (Linux).
    if (std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true })) |dir_| {
        var dir = dir_;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
            if (fd >= 3 and fd != dir.fd) posix.close(fd);
        }
    } else |_| {
        // Fallback: brute-force close FDs 3..1023.
        var fd: posix.fd_t = 3;
        while (fd < 1024) : (fd += 1) {
            posix.close(fd);
        }
    }
}

/// Reopen stdin/stdout/stderr as /dev/null.
fn reopenStdFds() void {
    const devnull = c.open("/dev/null", c.O_RDWR);
    if (devnull < 0) return;
    _ = c.dup2(devnull, 0);
    _ = c.dup2(devnull, 1);
    _ = c.dup2(devnull, 2);
    if (devnull > 2) _ = c.close(devnull);
}

fn daemonMain(alloc: Allocator) !void {
    const state_dir = try session.shared.stateDir(alloc);
    defer alloc.free(state_dir);
    try std.fs.cwd().makePath(state_dir);

    const sessions_dir = try session.shared.sessionDir(alloc);
    defer alloc.free(sessions_dir);
    try std.fs.cwd().makePath(sessions_dir);

    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    var daemon: Daemon = .{
        .alloc = alloc,
        .sessions_dir = try alloc.dupe(u8, sessions_dir),
        .socket_path = try alloc.dupe(u8, socket_path),
        .sessions = .init(alloc),
        .listener = try bindUnixSocket(socket_path),
    };
    defer daemon.deinit();

    while (true) {
        const client_fd = try acceptUnixSocket(daemon.listener);
        const client = try alloc.create(ClientThread);
        client.* = .{
            .daemon = &daemon,
            .fd = client_fd,
        };
        const thread = try std.Thread.spawn(.{}, ClientThread.main, .{client});
        thread.detach();
    }
}

const ClientThread = struct {
    daemon: *Daemon,
    fd: posix.fd_t,

    fn main(self: *ClientThread) void {
        defer {
            closeFd(self.fd);
            self.daemon.alloc.destroy(self);
        }

        self.main_() catch |err| {
            log.warn("client thread error err={}", .{err});
        };
    }

    fn main_(self: *ClientThread) !void {
        // Read command using raw posix.read — Zig 0.15's buffered reader
        // panics on socket fds after closeAllFds due to positional-read
        // fallback bugs in the I/O infrastructure.
        var cmd: [4096]u8 = undefined;
        var pos: usize = 0;
        while (pos < cmd.len) {
            var byte: [1]u8 = undefined;
            const n = posix.read(self.fd, &byte) catch break;
            if (n == 0) break;
            if (byte[0] == '\n') break;
            cmd[pos] = byte[0];
            pos += 1;
        }
        const trimmed = std.mem.trim(u8, cmd[0..pos], " \t\r\n");
        if (trimmed.len == 0) return;

        var writer_buf: [1024]u8 = undefined;
        var file: std.fs.File = .{ .handle = self.fd };
        var writer_ = file.writerStreaming(&writer_buf);
        const writer = &writer_.interface;

        if (std.mem.eql(u8, trimmed, "LIST")) {
            try self.daemon.handleList(writer);
            try writer.flush();
            return;
        }

        if (std.mem.startsWith(u8, trimmed, "KILL ")) {
            try self.daemon.handleKill(trimmed["KILL ".len..], writer);
            try writer.flush();
            return;
        }

        if (std.mem.startsWith(u8, trimmed, "ATTACH ")) {
            try self.daemon.handleAttach(trimmed["ATTACH ".len..], self.fd, writer);
            try writer.flush();
            return;
        }

        try writer.writeAll("ERR unknown-command\n");
        try writer.flush();
    }
};

const Daemon = struct {
    alloc: Allocator,
    sessions_dir: []const u8,
    socket_path: []const u8,
    listener: posix.fd_t,
    mutex: std.Thread.Mutex = .{},
    sessions: std.StringHashMap(*Session),

    fn deinit(self: *Daemon) void {
        var it = self.sessions.iterator();
        while (it.next()) |kv| kv.value_ptr.*.deinit();
        self.sessions.deinit();
        closeFd(self.listener);
        std.fs.cwd().deleteFile(self.socket_path) catch {};
        self.alloc.free(self.sessions_dir);
        self.alloc.free(self.socket_path);
    }

    fn handleList(self: *Daemon, writer: *std.Io.Writer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.sessions.iterator();
        while (it.next()) |kv| {
            const sess = kv.value_ptr.*;
            sess.mutex.lock();
            const attached = sess.attached_fd != null;
            const alive = sess.alive;
            const created_at = sess.created_at;
            sess.mutex.unlock();

            try writer.print(
                "{s}|{s}|{s}|{d}|{s}|{s}\n",
                .{
                    sess.id,
                    sess.label,
                    if (alive) "alive" else "dead",
                    created_at,
                    if (attached) "attached" else "detached",
                    sess.log_path,
                },
            );
        }
    }

    fn handleKill(self: *Daemon, id: []const u8, writer: *std.Io.Writer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sess = self.sessions.get(id) orelse {
            try writer.writeAll("ERR not-found\n");
            return;
        };

        sess.kill();
        try writer.writeAll("OK\n");
    }

    fn handleAttach(
        self: *Daemon,
        args: []const u8,
        fd: posix.fd_t,
        writer: *std.Io.Writer,
    ) !void {
        var it = std.mem.tokenizeScalar(u8, args, ' ');
        const mode = it.next() orelse {
            try writer.writeAll("ERR invalid-attach\n");
            return;
        };

        const rows = try std.fmt.parseInt(u16, it.next() orelse "24", 10);
        const cols = try std.fmt.parseInt(u16, it.next() orelse "80", 10);
        const width_px = try std.fmt.parseInt(u16, it.next() orelse "800", 10);
        const height_px = try std.fmt.parseInt(u16, it.next() orelse "600", 10);
        const resize: session.protocol.Resize = .{
            .rows = rows,
            .cols = cols,
            .width_px = width_px,
            .height_px = height_px,
        };

        const sess: *Session = if (std.mem.eql(u8, mode, "NEW")) create: {
            const raw_label = it.next() orelse "session";
            break :create try self.createSession(raw_label, resize);
        } else if (std.mem.eql(u8, mode, "EXISTING")) existing: {
            const id = it.next() orelse {
                try writer.writeAll("ERR missing-session\n");
                return;
            };
            self.mutex.lock();
            defer self.mutex.unlock();
            break :existing self.sessions.get(id) orelse {
                try writer.writeAll("ERR not-found\n");
                return;
            };
        } else {
            try writer.writeAll("ERR invalid-attach\n");
            return;
        };

        try writer.print("OK {s}\n", .{sess.id});
        try writer.flush();
        try sess.attachAndServe(fd, resize);
    }

    fn createSession(
        self: *Daemon,
        raw_label: []const u8,
        resize: session.protocol.Resize,
    ) !*Session {
        const label = try session.shared.sanitizeLabelAlloc(self.alloc, raw_label);
        errdefer self.alloc.free(label);
        const id = try session.shared.generateSessionId(self.alloc);
        errdefer self.alloc.free(id);

        const dir = try std.fs.path.join(self.alloc, &.{ self.sessions_dir, id });
        errdefer self.alloc.free(dir);
        try std.fs.cwd().makePath(dir);

        const log_path = try std.fs.path.join(self.alloc, &.{ dir, "output.log" });
        errdefer self.alloc.free(log_path);
        const log_file = try std.fs.createFileAbsolute(log_path, .{
            .truncate = true,
            .read = true,
            .mode = 0o600,
        });
        errdefer log_file.close();

        const pty = try Pty.open(.{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.width_px,
            .ws_ypixel = resize.height_px,
        });
        errdefer closeFd(pty.master);
        errdefer closeFd(pty.slave);

        const shell = posix.getenv("SHELL") orelse "/bin/sh";
        const command_path = try self.alloc.dupeZ(u8, shell);
        errdefer self.alloc.free(command_path);
        const command_args = try self.alloc.alloc([:0]const u8, 1);
        errdefer self.alloc.free(command_args);
        command_args[0] = command_path;

        var command: Command = .{
            .path = command_path,
            .args = command_args,
            .stdin = .{ .handle = pty.slave },
            .stdout = .{ .handle = pty.slave },
            .stderr = .{ .handle = pty.slave },
            .os_pre_exec = preExecPty,
            .rt_pre_exec = null,
            .rt_pre_exec_info = std.mem.zeroInit(Command.RtPreExecInfo, .{}),
            .rt_post_fork = null,
            .rt_post_fork_info = std.mem.zeroInit(Command.RtPostForkInfo, .{}),
        };
        errdefer {
            self.alloc.free(command.path);
            self.alloc.free(command.args);
        }
        command.setData(@constCast(&pty));
        try command.start(self.alloc);
        closeFd(pty.slave);

        const sess = try self.alloc.create(Session);
        errdefer self.alloc.destroy(sess);
        sess.* = .{
            .alloc = self.alloc,
            .id = id,
            .label = label,
            .dir_path = dir,
            .log_path = log_path,
            .log_file = log_file,
            .pty = .{ .master = pty.master, .slave = -1 },
            .command = command,
            .created_at = std.time.timestamp(),
        };
        sess.reader_thread = try std.Thread.spawn(.{}, Session.readerMain, .{sess});
        sess.reader_thread.detach();

        self.mutex.lock();
        try self.sessions.put(sess.id, sess);
        self.mutex.unlock();

        return sess;
    }
};

const Session = struct {
    alloc: Allocator,
    id: []u8,
    label: []u8,
    dir_path: []u8,
    log_path: []u8,
    log_file: std.fs.File,
    pty: Pty,
    command: Command,
    created_at: i64,
    mutex: std.Thread.Mutex = .{},
    attached_fd: ?posix.fd_t = null,
    replaying: bool = false,
    alive: bool = true,
    log_size: u64 = 0,
    reader_thread: std.Thread = undefined,

    fn deinit(self: *Session) void {
        closeFd(self.pty.master);
        self.log_file.close();
        self.alloc.free(self.command.path);
        self.alloc.free(self.command.args);
        self.alloc.free(self.id);
        self.alloc.free(self.label);
        self.alloc.free(self.dir_path);
        self.alloc.free(self.log_path);
        self.alloc.destroy(self);
    }

    fn kill(self: *Session) void {
        if (self.command.pid) |pid| _ = posix.kill(pid, posix.SIG.TERM) catch {};
    }

    fn readerMain(self: *Session) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = posix.read(self.pty.master, &buf) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => break,
            };
            if (n == 0) break;

            self.log_file.writeAll(buf[0..n]) catch |err| {
                log.warn("session log write failed id={s} err={}", .{ self.id, err });
            };

            self.mutex.lock();
            self.log_size += n;
            if (self.attached_fd) |fd| {
                if (!self.replaying) sendFrameFd(fd, .stdout, 0, buf[0..n]) catch |err| {
                    log.warn("attached client write failed id={s} err={}", .{ self.id, err });
                    self.attached_fd = null;
                };
            }
            self.mutex.unlock();
        }

        self.mutex.lock();
        self.alive = false;
        if (self.attached_fd) |fd| _ = sendFrameFd(fd, .eof, 0, "") catch {};
        self.mutex.unlock();
        _ = self.command.wait(false) catch {};
    }

    fn attachAndServe(
        self: *Session,
        fd: posix.fd_t,
        resize: session.protocol.Resize,
    ) !void {
        try self.pty.setSize(.{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.width_px,
            .ws_ypixel = resize.height_px,
        });

        self.mutex.lock();
        if (self.attached_fd != null) {
            self.mutex.unlock();
            return error.SessionAlreadyAttached;
        }
        self.replaying = true;
        self.mutex.unlock();

        var offset: u64 = 0;
        while (true) {
            offset = try self.replayLog(fd, offset);
            self.mutex.lock();
            const stable = self.log_size == offset;
            if (stable) {
                self.attached_fd = fd;
                self.replaying = false;
                self.mutex.unlock();
                break;
            }
            self.mutex.unlock();
        }

        var file: std.fs.File = .{ .handle = fd };
        var reader_buf: [1024]u8 = undefined;
        var reader_ = file.readerStreaming(&reader_buf);
        const reader = &reader_.interface;

        while (true) {
            const header = session.protocol.readHeader(reader) catch break;
            const payload = try session.protocol.readPayloadAlloc(self.alloc, reader, header);
            defer self.alloc.free(payload);

            switch (header.kind) {
                .stdin => _ = posix.write(self.pty.master, payload) catch |err| {
                    log.warn("session write failed id={s} err={}", .{ self.id, err });
                    break;
                },
                .resize => {
                    const parsed = try session.protocol.Resize.parse(payload);
                    try self.pty.setSize(.{
                        .ws_row = parsed.rows,
                        .ws_col = parsed.cols,
                        .ws_xpixel = parsed.width_px,
                        .ws_ypixel = parsed.height_px,
                    });
                },
                .detach => break,
                else => {},
            }
        }

        self.mutex.lock();
        if (self.attached_fd == fd) self.attached_fd = null;
        self.mutex.unlock();
    }

    fn replayLog(self: *Session, fd: posix.fd_t, offset: u64) !u64 {
        const file = try std.fs.openFileAbsolute(self.log_path, .{});
        defer file.close();
        try file.seekTo(offset);

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try file.read(&buf);
            if (n == 0) return try file.getPos();
            try sendFrameFd(fd, .stdout, 0, buf[0..n]);
        }
    }
};

// -- Multiplexed helper --

const MAX_MUX_SESSIONS = 64;

const terminal = @import("../terminal/main.zig");

const MuxSession = struct {
    target: u16,
    daemon_fd: posix.fd_t,
    read_buf: std.ArrayList(u8),
    render_mode: session.protocol.RenderMode = .raw,
    /// Terminal instance for state_sync mode. Processes raw PTY output
    /// and produces delta frames instead of forwarding raw bytes.
    sync_terminal: ?*terminal.Terminal = null,

    fn deinit(self: *MuxSession, alloc: Allocator) void {
        closeFd(self.daemon_fd);
        self.read_buf.deinit(alloc);
        if (self.sync_terminal) |t| {
            t.deinit(alloc);
            alloc.destroy(t);
            self.sync_terminal = null;
        }
    }
};

/// Multiplexed stdio-attach mode. Reads frames from stdin (SSH channel),
/// dispatches to per-session daemon Unix sockets. Reads frames from daemon
/// sockets, rewrites with the correct target, and writes to stdout.
fn multiplex(alloc: Allocator, stderr: *std.Io.Writer) !u8 {
    _ = stderr;
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    var sessions: [MAX_MUX_SESSIONS]?MuxSession = .{null} ** MAX_MUX_SESSIONS;
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
        var pollfds: [1 + MAX_MUX_SESSIONS]c.struct_pollfd = undefined;
        pollfds[0] = .{
            .fd = stdin_fd,
            .events = c.POLLIN,
            .revents = 0,
        };

        var poll_session_idx: [MAX_MUX_SESSIONS]usize = undefined;
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
            const kind_byte = stdin_buf.items[0];
            const target = std.mem.readInt(u16, stdin_buf.items[2..4], .little);
            const payload_len = std.mem.readInt(u32, stdin_buf.items[4..8], .little);
            const total = session.protocol.header_size + payload_len;
            if (stdin_buf.items.len < total) break;

            const kind = std.meta.intToEnum(session.protocol.Kind, kind_byte) catch {
                shiftBuffer(&stdin_buf, total);
                continue;
            };

            const payload = stdin_buf.items[session.protocol.header_size..total];

            switch (kind) {
                .keepalive => {
                    last_keepalive_received = std.time.nanoTimestamp();
                },
                .session_open => {
                    handleSessionOpen(
                        alloc,
                        &sessions,
                        target,
                        payload,
                        socket_path,
                        stdout_file,
                    ) catch |err| {
                        log.warn("session_open failed target={d} err={}", .{ target, err });
                        const msg = std.fmt.allocPrint(alloc, "session open failed: {}", .{err}) catch {
                            sendFrameFile(stdout_file, .err, target, "session open failed") catch {};
                            shiftBuffer(&stdin_buf, total);
                            continue;
                        };
                        defer alloc.free(msg);
                        sendFrameFile(stdout_file, .err, target, msg) catch {};
                    };
                },
                .session_close => {
                    closeMuxSession(&sessions, alloc, target);
                },
                .detach => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, .detach, 0, "") catch {};
                    }
                    closeMuxSession(&sessions, alloc, target);
                },
                .stdin => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, .stdin, 0, payload) catch {
                            sendFrameFile(stdout_file, .eof, target, "") catch {};
                            closeMuxSession(&sessions, alloc, target);
                        };
                    }
                },
                .resize => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, .resize, 0, payload) catch {};
                    }
                },
                else => {},
            }

            shiftBuffer(&stdin_buf, total);
        }

        // Check daemon sockets for frames
        var pidx: usize = 1;
        while (pidx < n_fds) : (pidx += 1) {
            const sess_idx = poll_session_idx[pidx - 1];
            const slot = &sessions[sess_idx];
            if (slot.*) |*s| {
                if (pollfds[pidx].revents & c.POLLIN != 0) {
                    var daemon_buf: [8192]u8 = undefined;
                    const n = posix.read(s.daemon_fd, &daemon_buf) catch {
                        sendFrameFile(stdout_file, .eof, s.target, "") catch {};
                        s.deinit(alloc);
                        slot.* = null;
                        continue;
                    };
                    if (n == 0) {
                        sendFrameFile(stdout_file, .eof, s.target, "") catch {};
                        s.deinit(alloc);
                        slot.* = null;
                        continue;
                    }
                    try s.read_buf.appendSlice(alloc, daemon_buf[0..n]);
                }

                if (pollfds[pidx].revents & (c.POLLHUP | c.POLLERR) != 0 and
                    pollfds[pidx].revents & c.POLLIN == 0)
                {
                    sendFrameFile(stdout_file, .eof, s.target, "") catch {};
                    s.deinit(alloc);
                    slot.* = null;
                    continue;
                }

                // Process complete frames from this daemon's buffer
                while (s.read_buf.items.len >= session.protocol.header_size) {
                    const dk = s.read_buf.items[0];
                    const dplen = std.mem.readInt(u32, s.read_buf.items[4..8], .little);
                    const dtotal = session.protocol.header_size + dplen;
                    if (s.read_buf.items.len < dtotal) break;

                    const dkind = std.meta.intToEnum(session.protocol.Kind, dk) catch {
                        shiftBuffer(&s.read_buf, dtotal);
                        continue;
                    };
                    const dpayload = s.read_buf.items[session.protocol.header_size..dtotal];

                    // For state_sync sessions with a terminal, process stdout
                    // through the Terminal and send deltas.
                    // NOTE: Full VT processing requires a Stream handler which
                    // is complex to set up in the helper context. For now,
                    // state_sync mode falls back to raw forwarding. The protocol
                    // negotiation and frame types are in place for when the
                    // full Stream integration is added.
                    sendFrameFile(stdout_file, dkind, s.target, dpayload) catch {};

                    if (dkind == .eof) {
                        shiftBuffer(&s.read_buf, dtotal);
                        s.deinit(alloc);
                        slot.* = null;
                        break;
                    }

                    shiftBuffer(&s.read_buf, dtotal);
                }
            }
        }

        // Keepalive: send if interval elapsed
        {
            const ka_now = std.time.nanoTimestamp();
            if (ka_now - last_keepalive_sent >= session.protocol.keepalive_interval_ns) {
                var ts_buf: [8]u8 = undefined;
                std.mem.writeInt(u64, &ts_buf, @intCast(@as(u128, @bitCast(ka_now)) & 0xFFFFFFFFFFFFFFFF), .little);
                sendFrameFile(stdout_file, .keepalive, 0, &ts_buf) catch {};
                last_keepalive_sent = ka_now;
            }

            // Server timeout: close if no keepalive from client for 60s
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

fn handleSessionOpen(
    alloc: Allocator,
    sessions: *[MAX_MUX_SESSIONS]?MuxSession,
    target: u16,
    payload: []const u8,
    socket_path: []const u8,
    stdout_file: std.fs.File,
) !void {
    const open_data = try session.protocol.SessionOpen.parse(payload);

    var free_idx: ?usize = null;
    for (0..MAX_MUX_SESSIONS) |i| {
        if (sessions[i] == null) {
            free_idx = i;
            break;
        }
    }
    const idx = free_idx orelse return error.TooManySessions;

    const daemon_fd = try connectUnixSocket(socket_path);
    errdefer closeFd(daemon_fd);

    var cmd_buf: [512]u8 = undefined;
    const safe_label = if (open_data.label.len > 0) open_data.label else "session";
    const cmd = std.fmt.bufPrint(&cmd_buf, "ATTACH NEW {d} {d} {d} {d} {s}\n", .{
        open_data.resize.rows,
        open_data.resize.cols,
        open_data.resize.width_px,
        open_data.resize.height_px,
        safe_label,
    }) catch return error.CommandTooLong;
    try writeAllFd(daemon_fd, cmd);

    // Read the OK response byte-by-byte (unbuffered) to avoid consuming
    // any subsequent frame data that the daemon may have already sent.
    const response = try readLineRawAlloc(alloc, daemon_fd, 4096);
    defer alloc.free(response);
    const trimmed = std.mem.trim(u8, response, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "OK ")) {
        return error.DaemonAttachFailed;
    }

    const session_id = trimmed["OK ".len..];

    // Initialize terminal for state_sync mode
    var sync_term: ?*terminal.Terminal = null;
    if (open_data.render_mode == .state_sync) {
        if (alloc.create(terminal.Terminal)) |tp| {
            if (terminal.Terminal.init(alloc, .{
                .cols = open_data.resize.cols,
                .rows = open_data.resize.rows,
            })) |t_val| {
                tp.* = t_val;
                sync_term = tp;
            } else |_| {
                alloc.destroy(tp);
            }
        } else |_| {}
    }

    sessions[idx] = .{
        .target = target,
        .daemon_fd = daemon_fd,
        .read_buf = std.ArrayList(u8).empty,
        .render_mode = open_data.render_mode,
        .sync_terminal = sync_term,
    };

    sendFrameFile(stdout_file, .session_opened, target, session_id) catch {};
}

fn findMuxSession(sessions: *[MAX_MUX_SESSIONS]?MuxSession, target: u16) ?*MuxSession {
    for (sessions) |*slot| {
        if (slot.*) |*s| {
            if (s.target == target) return s;
        }
    }
    return null;
}

fn closeMuxSession(sessions: *[MAX_MUX_SESSIONS]?MuxSession, alloc: Allocator, target: u16) void {
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

fn listSessions(
    alloc: Allocator,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    try writeAllFd(fd, "LIST\n");
    try drainFdToWriter(fd, writer);
}

fn killSession(
    alloc: Allocator,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    const line = try std.fmt.allocPrint(alloc, "KILL {s}\n", .{id});
    defer alloc.free(line);
    try writeAllFd(fd, line);
    try drainFdToWriter(fd, writer);
}

fn preExecPty(cmd: *Command) ?u8 {
    const pty = cmd.getData(Pty) orelse return 1;
    pty.childPreExec() catch return 1;
    return null;
}

fn canConnect(path: []const u8) !bool {
    const fd = connectUnixSocket(path) catch return false;
    closeFd(fd);
    return true;
}

fn bindUnixSocket(path: []const u8) !posix.fd_t {
    std.fs.cwd().deleteFile(path) catch {};

    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer closeFd(fd);

    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.NameTooLong;
    @memcpy(addr.sun_path[0..path.len], path);

    if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) {
        return error.BindFailed;
    }
    if (c.listen(fd, 64) != 0) return error.ListenFailed;
    return fd;
}

fn acceptUnixSocket(listener: posix.fd_t) !posix.fd_t {
    const fd = c.accept(listener, null, null);
    if (fd < 0) return error.AcceptFailed;
    return fd;
}

fn connectUnixSocket(path: []const u8) !posix.fd_t {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer closeFd(fd);

    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.NameTooLong;
    @memcpy(addr.sun_path[0..path.len], path);

    if (c.connect(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) return error.ConnectFailed;
    return fd;
}

fn sendFrameFd(fd: posix.fd_t, kind: session.protocol.Kind, target: u16, payload: []const u8) !void {
    var file: std.fs.File = .{ .handle = fd };
    var buf: [1024]u8 = undefined;
    var writer_ = file.writerStreaming(&buf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, kind, target, payload);
    try writer.flush();
}

fn sendFrameFile(file: std.fs.File, kind: session.protocol.Kind, target: u16, payload: []const u8) !void {
    var header: [session.protocol.header_size]u8 = undefined;
    header[0] = @intFromEnum(kind);
    header[1] = 0;
    std.mem.writeInt(u16, header[2..4], target, .little);
    std.mem.writeInt(u32, header[4..8], @intCast(payload.len), .little);
    try file.writeAll(&header);
    try file.writeAll(payload);
}

fn writeAllFd(fd: posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try posix.write(fd, bytes[offset..]);
        offset += written;
    }
}

fn drainFdToWriter(fd: posix.fd_t, writer: *std.Io.Writer) !void {
    var file: std.fs.File = .{ .handle = fd };
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        try writer.writeAll(buf[0..n]);
    }
    try writer.flush();
}

fn shiftBuffer(buf: *std.ArrayList(u8), amount: usize) void {
    if (amount >= buf.items.len) {
        buf.shrinkRetainingCapacity(0);
    } else {
        std.mem.copyForwards(u8, buf.items, buf.items[amount..]);
        buf.shrinkRetainingCapacity(buf.items.len - amount);
    }
}

fn closeFd(fd: posix.fd_t) void {
    posix.close(fd);
}

fn readLineAlloc(alloc: Allocator, fd: posix.fd_t, max_bytes: usize) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(alloc);

    var file: std.fs.File = .{ .handle = fd };
    var reader_buf: [1024]u8 = undefined;
    // Use readerStreaming for sockets — file.reader() defaults to positional
    // mode (preadv) which panics on non-seekable fds in Zig 0.15.
    var reader_ = file.readerStreaming(&reader_buf);
    const reader = &reader_.interface;

    while (bytes.items.len < max_bytes) {
        var byte: [1]u8 = undefined;
        reader.readSliceAll(&byte) catch break;
        if (byte[0] == '\n') break;
        try bytes.append(alloc, byte[0]);
    }

    return try bytes.toOwnedSlice(alloc);
}

/// Read a line from fd byte-by-byte using raw posix.read (no buffering).
/// This ensures we never consume data beyond the newline, which is critical
/// for the multiplex helper where subsequent bytes are binary frame data.
fn readLineRawAlloc(alloc: Allocator, fd: posix.fd_t, max_bytes: usize) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(alloc);

    while (bytes.items.len < max_bytes) {
        var byte: [1]u8 = undefined;
        const n = posix.read(fd, &byte) catch break;
        if (n == 0) break;
        if (byte[0] == '\n') break;
        try bytes.append(alloc, byte[0]);
    }

    return try bytes.toOwnedSlice(alloc);
}
