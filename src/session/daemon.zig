const std = @import("std");
const builtin = @import("builtin");
const build_config = @import("../build_config.zig");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const Command = @import("../Command.zig");
const ptypkg = @import("../pty.zig");
const Pty = ptypkg.Pty;
const session = @import("../session.zig");
const RemoteSession = session.remote_session.RemoteSession;
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;
const terminal = @import("../terminal/main.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("signal.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/un.h");
    @cInclude("sys/wait.h");
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.ssh_session);

/// Write a diagnostic line to stderr (which is daemon.log in daemon mode).
/// Works in release builds unlike std.log.info.
fn daemonLog(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = std.posix.write(2, msg) catch {};
}

pub const Options = struct {
    daemonize: bool = false,
    daemon: bool = false,
    @"kill-daemon": bool = false,
    list: bool = false,
    @"protocol-version": bool = false,
    @"stdio-attach": bool = false,
    kill: ?[]const u8 = null,
    rename: ?[]const u8 = null,
    @"detach-others": ?[]const u8 = null,
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

    if (opts.@"kill-daemon") {
        try killDaemon(alloc);
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

    if (opts.rename) |id| {
        const new_label = opts.label orelse {
            try stderr.writeAll("Error: --label is required for rename\n");
            try stderr.flush();
            return 1;
        };
        try renameSession(alloc, id, new_label, stdout);
        return 0;
    }

    if (opts.@"detach-others") |id| {
        try detachOthersSession(alloc, id, stdout);
        return 0;
    }

    if (opts.@"stdio-attach") {
        return try multiplex(alloc, stderr);
    }

    try stderr.writeAll("missing helper mode\n");
    return 1;
}

/// Kill any running daemon by connecting to its socket and signaling it.
/// Removes the socket file so daemonize will start a fresh one.
fn killDaemon(alloc: Allocator) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    // Try to connect to trigger graceful shutdown
    const fd = connectUnixSocket(socket_path) catch {
        // Can't connect — daemon not running, just clean up socket
        std.fs.cwd().deleteFile(socket_path) catch {};
        return;
    };
    closeFd(fd);

    // Remove socket file so accept() fails in the old daemon
    std.fs.cwd().deleteFile(socket_path) catch {};

    // Give the old daemon a moment to notice
    std.Thread.sleep(200 * std.time.ns_per_ms);
}

fn daemonize(alloc: Allocator) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    if (try canConnect(socket_path)) return;

    // Classic POSIX double-fork to fully detach the daemon process.
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
    // In debug builds, skip closeAllFds so the panic handler can read the
    // ELF binary for stack traces. In release, close everything.
    if (builtin.mode != .Debug) {
        closeAllFds();
    }
    reopenStdFds();
    _ = c.chdir("/");

    // Use c_allocator — the parent's GPA is NOT fork-safe.
    daemonMain(std.heap.c_allocator) catch {
        c._exit(1);
    };
    c._exit(0);
}

/// Close all file descriptors >= 3 to prevent inheriting FDs from the parent.
fn closeAllFds() void {
    if (std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true })) |dir_| {
        var dir = dir_;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
            if (fd >= 3 and fd != dir.fd) posix.close(fd);
        }
    } else |_| {
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

// ============================================================================
// Daemon — binary frame protocol on Unix socket, uses RemoteSession
// ============================================================================

fn daemonMain(alloc: Allocator) !void {
    const state_dir = try session.shared.stateDir(alloc);
    defer alloc.free(state_dir);
    try std.fs.cwd().makePath(state_dir);

    // Open a daemon log file for debugging (daemon stderr is /dev/null).
    const log_path = try std.fs.path.join(alloc, &.{ state_dir, "daemon.log" });
    defer alloc.free(log_path);
    const log_file = std.fs.cwd().createFile(log_path, .{ .truncate = true }) catch null;
    defer if (log_file) |f| f.close();
    if (log_file) |f| {
        // Redirect stderr to the log file. Note: std.log.info is a no-op
        // in ReleaseFast, so we write directly for daemon diagnostics.
        const stderr_fd: c_int = 2;
        _ = c.dup2(f.handle, stderr_fd);
        f.writeAll("daemon started\n") catch {};
    }

    // Secure the state directory permissions
    {
        var dir = try std.fs.cwd().openDir(state_dir, .{});
        defer dir.close();
        const dir_fd = dir.fd;
        if (c.fchmod(dir_fd, 0o700) != 0) {
            log.warn("failed to set state dir permissions", .{});
        }
    }

    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    var daemon: Daemon = .{
        .alloc = alloc,
        .socket_path = try alloc.dupe(u8, socket_path),
        .groups = std.AutoArrayHashMap(Uuid, *SessionGroup).init(alloc),
        .listener = try bindUnixSocket(socket_path),
        .channel_registry = session.channel_mux.Registry.init(alloc),
    };
    defer daemon.deinit();

    // Register channel-mux services. These are the daemon's built-in
    // services advertised in every Capabilities frame.
    try session.services.tcp_connect.register(&daemon.channel_registry);

    while (true) {
        // Poll with timeout so we can periodically reap empty groups
        var pollfds = [1]c.struct_pollfd{
            .{ .fd = daemon.listener, .events = c.POLLIN, .revents = 0 },
        };
        const rc = c.poll(&pollfds, 1, 60_000); // 60 second timeout
        if (rc < 0) {
            if (std.c._errno().* == c.EINTR) continue;
            return error.PollFailed;
        }

        // On timeout, check if our socket file has been replaced by a new daemon.
        if (rc == 0) {
            if (!isSocketOurs(daemon.listener, daemon.socket_path)) {
                daemonLog("socket replaced, shutting down", .{});
                return;
            }
            continue;
        }

        if (pollfds[0].revents & c.POLLIN != 0) {
            const client_fd = try acceptUnixSocket(daemon.listener);
            verifyPeerUid(client_fd) catch {
                closeFd(client_fd);
                continue;
            };
            const client = try alloc.create(ClientThread);
            client.* = .{
                .daemon = &daemon,
                .fd = client_fd,
            };
            const thread = try std.Thread.spawn(.{}, ClientThread.main, .{client});
            thread.detach();
        }
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
        var header_buf: [session.protocol.header_size]u8 = undefined;
        readAllRaw(self.fd, &header_buf) catch return;

        const header = session.protocol.Header.parseFromBuf(&header_buf) catch return;
        const kind = header.kind;
        const target = header.target;

        if (header.len > session.protocol.max_payload) return;
        const payload = try self.daemon.alloc.alloc(u8, header.len);
        defer self.daemon.alloc.free(payload);
        readAllRaw(self.fd, payload) catch return;

        switch (kind) {
            .capabilities => {
                // Channel-mux mode: the peer announced its capabilities
                // first. Handshake, then loop dispatching channel frames.
                try self.runMuxMode(payload);
            },
            .open => {
                const open_data = session.protocol.Open.parse(payload) catch {
                    sendFrameFd(self.fd, .err, target, "invalid open payload") catch {};
                    return;
                };
                switch (open_data.open_type) {
                    .session_new, .session_attach => {
                        self.daemon.handleSessionOpen(self.fd, target, open_data) catch {
                            sendFrameFd(self.fd, .err, target, "session open failed") catch {};
                        };
                    },
                    .surface_new, .surface_attach => {
                        self.daemon.handleSurfaceOpen(self.fd, target, open_data) catch {
                            sendFrameFd(self.fd, .err, target, "surface open failed") catch {};
                        };
                    },
                }
            },
            .close => {
                const close_data = session.protocol.Close.parse(payload) catch return;
                self.daemon.handleClose(close_data);
            },
            .list_request => {
                self.daemon.handleSessionList(self.fd) catch |err| {
                    log.warn("session_list failed err={}", .{err});
                };
            },
            .rename => {
                const rename_data = session.protocol.Rename.parse(payload) catch return;
                self.daemon.handleRename(rename_data);
            },
            else => {},
        }
    }

    /// Run the channel-mux loop after the peer sent its initial
    /// `capabilities` frame. Handshakes, then reads frames until EOF
    /// or a fatal protocol error, dispatching channel kinds to the
    /// per-connection `Mux` and rejecting legacy session-lifecycle
    /// kinds with an `err` frame (terminals-as-a-service comes in a
    /// later phase).
    fn runMuxMode(self: *ClientThread, first_payload: []const u8) !void {
        var mux = session.channel_mux.Mux.init(
            self.daemon.alloc,
            self.fd,
            &self.daemon.channel_registry,
        );
        defer mux.deinit();

        // Capability exchange. `handshake` parses the already-read
        // payload and sends our reply.
        const peer = mux.handshake(first_payload) catch |err| {
            log.warn("capability handshake failed: {}", .{err});
            return;
        };
        defer self.daemon.alloc.free(peer.services);

        // Frame pump. Each iteration reads one frame and dispatches.
        while (true) {
            var hbuf: [session.protocol.header_size]u8 = undefined;
            readAllRaw(self.fd, &hbuf) catch return;
            const hdr = session.protocol.Header.parseFromBuf(&hbuf) catch return;
            if (hdr.len > session.protocol.max_payload) return;

            const buf = try self.daemon.alloc.alloc(u8, hdr.len);
            defer self.daemon.alloc.free(buf);
            readAllRaw(self.fd, buf) catch return;

            switch (hdr.kind) {
                .channel_open,
                .channel_opened,
                .channel_data,
                .channel_window,
                .channel_eof,
                .channel_close,
                .channel_control,
                .capabilities,
                => mux.dispatch(hdr.kind, buf) catch |err| {
                    log.warn("mux dispatch error: {}", .{err});
                    return;
                },
                // Legacy session-lifecycle kinds are not supported on
                // mux-mode connections in this phase. Reject so the
                // client knows to use a separate connection (or wait
                // for the terminal-as-a-service implementation).
                .open, .close, .list_request, .rename => {
                    sendFrameFd(self.fd, .err, 0, "legacy frame on mux connection") catch {};
                },
                else => {
                    log.debug("ignoring unexpected kind={} on mux connection", .{hdr.kind});
                },
            }
        }
    }
};

const Uuid = session.shared.Uuid;

/// A group of related surfaces that share a layout and can be
/// reconnected together. Every session belongs to a group, even
/// single-surface ones.
pub const SessionGroup = struct {
    alloc: Allocator,
    id: Uuid,
    label: []u8,
    /// Session color: -1 = none (no badge), 0-7 = color index.
    /// Default derived from group UUID for consistency.
    color: i8 = -1,
    surfaces: std.AutoArrayHashMap(Uuid, *RemoteSession),
    layout_blob: ?[]u8 = null,
    created_at: i64,
    mutex: std.Thread.Mutex = .{},

    pub fn deinit(self: *SessionGroup) void {
        for (self.surfaces.values()) |sess| sess.deinit();
        self.surfaces.deinit();
        if (self.layout_blob) |blob| self.alloc.free(blob);
        self.alloc.free(self.label);
        self.alloc.destroy(self);
    }

    /// Store a layout blob (opaque, from client). Thread-safe.
    pub fn updateLayout(self: *SessionGroup, alloc: Allocator, blob: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.layout_blob) |old| alloc.free(old);
        self.layout_blob = alloc.dupe(u8, blob) catch |err| blk: {
            log.warn("failed to store layout blob: {}", .{err});
            break :blk null;
        };
    }

    /// Update the group label and/or color, then broadcast to all surface viewers.
    /// Returns false if label allocation failed.
    pub fn updateLabel(self: *SessionGroup, alloc: Allocator, new_label: ?[]const u8, new_color: ?i8) bool {
        self.mutex.lock();
        if (new_label) |raw| {
            const label = session.shared.sanitizeLabelAlloc(alloc, raw) catch {
                self.mutex.unlock();
                return false;
            };
            alloc.free(self.label);
            self.label = label;
        }
        if (new_color) |col| self.color = col;
        for (self.surfaces.values()) |surf| {
            surf.mutex.lock();
            surf.broadcastViewerStateWithLabel(.name_change, self.label, self.color);
            surf.mutex.unlock();
        }
        self.mutex.unlock();
        return true;
    }

    /// Get the first alive surface in the group (for reconnect).
    pub fn firstAliveSurface(self: *SessionGroup) ?*RemoteSession {
        for (self.surfaces.values()) |sess| {
            sess.mutex.lock();
            const alive = sess.alive;
            sess.mutex.unlock();
            if (alive) return sess;
        }
        return null;
    }
};

const Daemon = struct {
    alloc: Allocator,
    socket_path: []const u8,
    listener: posix.fd_t,
    mutex: std.Thread.Mutex = .{},
    groups: std.AutoArrayHashMap(Uuid, *SessionGroup),
    /// Registry of channel-mux services. Populated at startup; read-only
    /// thereafter. Empty in Phase 6A.2 — every channel_open is rejected
    /// with service_not_supported until services land in 6A.3.
    channel_registry: session.channel_mux.Registry,

    fn deinit(self: *Daemon) void {
        for (self.groups.values()) |group| group.deinit();
        self.groups.deinit();
        self.channel_registry.deinit();
        closeFd(self.listener);
        std.fs.cwd().deleteFile(self.socket_path) catch {};
        self.alloc.free(self.socket_path);
    }

    /// Find a group by UUID or by label (for named sessions).
    fn findGroup(self: *Daemon, id_or_label: []const u8) ?*SessionGroup {
        // Try UUID lookup first (32-char hex or 36-char dashed)
        const uuid = session.shared.parseUuid(id_or_label) catch
            session.shared.parseUuidDashed(id_or_label) catch null;

        if (uuid) |u| {
            if (self.groups.get(u)) |g| return g;
        }

        // Fall back to label search
        for (self.groups.values()) |group| {
            if (std.mem.eql(u8, group.label, id_or_label)) return group;
        }
        return null;
    }

    fn handleSessionOpen(
        self: *Daemon,
        fd: posix.fd_t,
        target: u16,
        open_data: session.protocol.Open,
    ) !void {
        switch (open_data.open_type) {
            .session_new => {
                // Create group with client-provided group_id + first surface
                const group_id = if (!session.shared.isZeroUuid(open_data.group_id))
                    open_data.group_id
                else
                    session.shared.generateUuid();

                // Daemon generates session name if client didn't provide one.
                const generated_label: ?[]u8 = if (open_data.label.len == 0)
                    session.shared.generateReadableName(self.alloc, group_id) catch null
                else
                    null;
                defer if (generated_label) |gl| self.alloc.free(gl);
                const raw_label = generated_label orelse
                    if (open_data.label.len > 0) open_data.label else "session";
                daemonLog("session_new: label='{s}' generated={any}", .{ raw_label, generated_label != null });
                const group = try self.createGroup(raw_label, group_id);

                const surface_id = if (!session.shared.isZeroUuid(open_data.surface_id))
                    open_data.surface_id
                else
                    session.shared.generateUuid();

                const sess = try self.createSurface(group, surface_id, open_data.resize, open_data.max_scrollback);

                self.sendOpenedResponse(fd, target, group, surface_id, 0, null);
                sess.attachAndServe(fd, target, open_data) catch {};
                self.cleanupDetachedSurface(group, sess, surface_id);
            },
            .session_attach => {
                // Find group by UUID or label, or create a new one if
                // the label was provided but no matching group exists
                // (named session create-or-attach).
                self.mutex.lock();
                var created_new = false;
                const group = blk: {
                    if (!session.shared.isZeroUuid(open_data.group_id)) {
                        if (self.groups.get(open_data.group_id)) |g| break :blk g;
                    }
                    // Fall back to label search
                    if (open_data.label.len > 0) {
                        if (self.findGroup(open_data.label)) |g| break :blk g;
                    }

                    // If a label was provided, create a new group with that
                    // name (named session create-or-attach semantics).
                    // Hold the lock through lookup-or-create to prevent
                    // duplicate groups from concurrent attach requests.
                    if (open_data.label.len > 0) {
                        const new_group = self.createGroupLocked(
                            open_data.label,
                            session.shared.generateUuid(),
                        ) catch {
                            self.mutex.unlock();
                            sendFrameFd(fd, .err, target, "failed to create session") catch {};
                            return;
                        };
                        created_new = true;
                        break :blk new_group;
                    }

                    self.mutex.unlock();
                    sendFrameFd(fd, .err, target, "session not found") catch {};
                    return;
                };
                self.mutex.unlock();

                // Find the surface to attach to BEFORE sending opened,
                // so we can include the attached surface_id.
                // When no specific surface_id is requested, prefer the
                // first leaf from the serialized layout (preserves tab
                // order) and fall back to firstAliveSurface() if layout
                // parsing fails or the surface isn't found.
                // Dupe the layout blob once under mutex — used for both
                // first-leaf lookup and the opened response payload.
                const layout_blob: ?[]u8 = lbl: {
                    group.mutex.lock();
                    defer group.mutex.unlock();
                    break :lbl if (group.layout_blob) |blob|
                        (self.alloc.dupe(u8, blob) catch null)
                    else
                        null;
                };
                defer if (layout_blob) |d| self.alloc.free(d);

                const sess = if (!session.shared.isZeroUuid(open_data.surface_id)) blk: {
                    group.mutex.lock();
                    defer group.mutex.unlock();
                    break :blk group.surfaces.get(open_data.surface_id);
                } else blk: {
                    // Try layout-aware lookup: prefer the first leaf from
                    // serialized layout to preserve tab order.
                    if (layout_blob) |blob| {
                        if (session.layout.findFirstLeafId(blob)) |first_id| {
                            group.mutex.lock();
                            const candidate = group.surfaces.get(first_id);
                            group.mutex.unlock();
                            if (candidate) |cand| {
                                cand.mutex.lock();
                                const alive = cand.alive;
                                cand.mutex.unlock();
                                if (alive) break :blk candidate;
                            }
                        }
                    }
                    // Fall back to arbitrary alive surface
                    break :blk group.firstAliveSurface();
                };

                const attached_sid = if (sess) |s| s.surface_id else session.shared.zero_uuid;

                // Compute history rows for the attached surface
                const history_rows: u32 = if (sess) |s| blk: {
                    s.mutex.lock();
                    defer s.mutex.unlock();
                    break :blk s.computeHistoryRows();
                } else 0;

                self.sendOpenedResponse(fd, target, group, attached_sid, history_rows, layout_blob);

                if (sess) |s| {
                    s.attachAndServe(fd, target, open_data) catch {
                        sendFrameFd(fd, .err, target, "failed to attach to session") catch {};
                        sendFrameFd(fd, .eof, target, "") catch {};
                    };

                    self.cleanupDetachedSurface(group, s, attached_sid);
                } else if (created_new) {
                    // New group via create-or-attach: create the first surface.
                    const surface_id = if (!session.shared.isZeroUuid(open_data.surface_id))
                        open_data.surface_id
                    else
                        session.shared.generateUuid();
                    const new_sess = self.createSurface(group, surface_id, open_data.resize, open_data.max_scrollback) catch {
                        sendFrameFd(fd, .eof, target, "") catch {};
                        return;
                    };
                    new_sess.attachAndServe(fd, target, open_data) catch |err| {
                        log.warn("attach to new session failed: {}", .{err});
                        sendFrameFd(fd, .eof, target, "") catch {};
                    };

                    self.cleanupDetachedSurface(group, new_sess, surface_id);
                } else {
                    // Send diagnostic info back to client
                    group.mutex.lock();
                    const total = group.surfaces.count();
                    var dead_count: usize = 0;
                    for (group.surfaces.values()) |s_| {
                        s_.mutex.lock();
                        if (!s_.alive) dead_count += 1;
                        s_.mutex.unlock();
                    }
                    group.mutex.unlock();
                    var err_buf: [256]u8 = undefined;
                    const err_msg = std.fmt.bufPrint(&err_buf, "no alive surfaces in session ({d} total, {d} dead)", .{ total, dead_count }) catch "no alive surfaces in session";
                    sendFrameFd(fd, .err, target, err_msg) catch {};
                    sendFrameFd(fd, .eof, target, "") catch {};
                }
            },
            else => unreachable, // surface types handled in handleSurfaceOpen
        }
    }

    fn handleSurfaceOpen(
        self: *Daemon,
        fd: posix.fd_t,
        target: u16,
        open_data: session.protocol.Open,
    ) !void {

        self.mutex.lock();
        const group = self.groups.get(open_data.group_id) orelse {
            self.mutex.unlock();
            sendFrameFd(fd, .err, target, "group not found") catch {};
            return;
        };
        self.mutex.unlock();

        switch (open_data.open_type) {
            .surface_new => {
                const sess = try self.createSurface(group, open_data.surface_id, open_data.resize, open_data.max_scrollback);
                self.sendOpenedResponse(fd, target, group, open_data.surface_id, 0, null);
                sess.attachAndServe(fd, target, open_data) catch {};
                self.cleanupDetachedSurface(group, sess, open_data.surface_id);
            },
            .surface_attach => {
                group.mutex.lock();
                const sess = group.surfaces.get(open_data.surface_id);
                group.mutex.unlock();

                if (sess) |s| {
                    // Compute history rows for the attached surface
                    s.mutex.lock();
                    const surf_history = s.computeHistoryRows();
                    s.mutex.unlock();

                    self.sendOpenedResponse(fd, target, group, open_data.surface_id, surf_history, null);
                    s.attachAndServe(fd, target, open_data) catch {};
                    self.cleanupDetachedSurface(group, s, open_data.surface_id);
                } else {
                    sendFrameFd(fd, .eof, target, "") catch {};
                }
            },
            else => unreachable, // session types handled in handleSessionOpen
        }
    }

    /// Unified close handler. Dispatches based on Close.mode.
    fn handleClose(self: *Daemon, close_data: session.protocol.Close) void {
        switch (close_data.mode) {
            .surface => {
                self.mutex.lock();
                defer self.mutex.unlock();

                for (self.groups.values()) |group| {
                    group.mutex.lock();
                    if (group.surfaces.get(close_data.id)) |sess| {
                        sess.kill();
                        _ = group.surfaces.orderedRemove(close_data.id);
                        group.mutex.unlock();
                        self.maybeRemoveEmptyGroup(group);
                        return;
                    }
                    group.mutex.unlock();
                }
            },
            .session => {
                self.mutex.lock();
                defer self.mutex.unlock();

                if (self.groups.get(close_data.id)) |group| {
                    group.mutex.lock();
                    for (group.surfaces.values()) |sess| sess.kill();
                    group.surfaces.clearRetainingCapacity();
                    group.mutex.unlock();
                    self.maybeRemoveEmptyGroup(group);
                }
            },
            .detach => {
                // Detach is handled at the multiplexer level; no daemon action needed.
            },
        }
    }

    fn handleSessionList(self: *Daemon, fd: posix.fd_t) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Build structured ListResponse
        var entries: std.ArrayList(session.protocol.ListEntry) = .empty;
        defer entries.deinit(self.alloc);

        for (self.groups.values()) |group| {
            group.mutex.lock();
            const surface_count = group.surfaces.count();
            const created_at = group.created_at;

            // Count alive and attached surfaces
            var alive_count: usize = 0;
            var attached_count: usize = 0;
            for (group.surfaces.values()) |sess| {
                sess.mutex.lock();
                if (sess.alive) alive_count += 1;
                if (sess.viewers.items.len > 0) attached_count += 1;
                sess.mutex.unlock();
            }
            group.mutex.unlock();

            const status: session.protocol.ListStatus = if (alive_count == 0)
                .dead
            else if (attached_count > 0)
                .attached
            else
                .detached;

            entries.append(self.alloc, .{
                .group_id = group.id,
                .status = status,
                .surface_count = @intCast(surface_count),
                .alive_count = @intCast(alive_count),
                .created_at = created_at,
                .label = group.label,
            }) catch continue;
        }

        const resp = session.protocol.ListResponse{ .entries = entries.items };
        const payload = resp.encode(self.alloc) catch return;
        defer self.alloc.free(payload);
        sendFrameFd(fd, .list_response, 0, payload) catch {};
    }

    /// Unified rename handler. Dispatches based on Rename.scope.
    fn handleRename(self: *Daemon, rename_data: session.protocol.Rename) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        switch (rename_data.scope) {
            .group => {
                const group = self.groups.get(rename_data.id) orelse return;
                if (!group.updateLabel(self.alloc, rename_data.label, null)) {
                    log.warn("failed to update group label (OOM)", .{});
                }
            },
            .surface => {
                // Find the surface across all groups.
                for (self.groups.values()) |group| {
                    group.mutex.lock();
                    defer group.mutex.unlock();
                    if (group.surfaces.get(rename_data.id)) |sess| {
                        const new_label = session.shared.sanitizeLabelAlloc(self.alloc, rename_data.label) catch return;
                        sess.mutex.lock();
                        self.alloc.free(sess.label);
                        sess.label = new_label;
                        sess.mutex.unlock();
                        log.info("renamed surface to '{s}'", .{new_label});
                        return;
                    }
                }
            },
        }
    }

    /// If the group has no surfaces left, remove it immediately from the
    /// daemon's group map and free it. Otherwise clear the reap mark.
    /// Caller must hold daemon.mutex. Group mutex should NOT be held.
    /// After this returns, `group` may be dangling — caller must not use it.
    fn maybeRemoveEmptyGroup(self: *Daemon, group: *SessionGroup) void {
        group.mutex.lock();
        const is_empty = group.surfaces.count() == 0;
        group.mutex.unlock();
        if (!is_empty) return;

        log.info("group {s} is empty, removing immediately", .{group.label});
        _ = self.groups.swapRemove(group.id);
        group.deinit();
    }

    /// If the session was closed by the client, kill its process and remove
    /// it from the group. Removes the group entirely if it becomes empty.
    fn cleanupDetachedSurface(self: *Daemon, group: *SessionGroup, sess: *RemoteSession, surface_id: Uuid) void {
        if (!sess.closed) return;
        sess.kill();
        self.mutex.lock();
        group.mutex.lock();
        _ = group.surfaces.orderedRemove(surface_id);
        group.mutex.unlock();
        self.maybeRemoveEmptyGroup(group);
        self.mutex.unlock();
    }

    /// Encode and send an .opened response frame to the client.
    fn sendOpenedResponse(self: *Daemon, fd: posix.fd_t, target: u16, group: *SessionGroup, surface_id: Uuid, history_rows: u32, layout_blob: ?[]const u8) void {
        const opened = session.protocol.Opened{
            .label = group.label,
            .color = group.color,
            .group_id = group.id,
            .surface_id = surface_id,
            .history_rows = history_rows,
            .layout_blob = layout_blob,
        };
        const payload = opened.encode(self.alloc) catch return;
        defer self.alloc.free(payload);
        sendFrameFd(fd, .opened, target, payload) catch {};
    }

    /// Allocate and register a new session group. Acquires self.mutex internally.
    fn createGroup(self: *Daemon, raw_label: []const u8, group_id: Uuid) !*SessionGroup {
        const group = try self.allocGroup(raw_label, group_id);
        errdefer self.destroyGroup(group);

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.groups.put(group.id, group);

        return group;
    }

    /// Like createGroup but assumes self.mutex is already held.
    fn createGroupLocked(self: *Daemon, raw_label: []const u8, group_id: Uuid) !*SessionGroup {
        const group = try self.allocGroup(raw_label, group_id);
        errdefer self.destroyGroup(group);
        try self.groups.put(group.id, group);
        return group;
    }

    /// Allocate a SessionGroup without registering it.
    fn allocGroup(self: *Daemon, raw_label: []const u8, group_id: Uuid) !*SessionGroup {
        const label = try session.shared.sanitizeLabelAlloc(self.alloc, raw_label);
        errdefer self.alloc.free(label);

        const group = try self.alloc.create(SessionGroup);
        group.* = .{
            .alloc = self.alloc,
            .id = group_id,
            .label = label,
            .color = @as(i8, @intCast(group_id[0] % 8)), // Deterministic color from UUID
            .surfaces = std.AutoArrayHashMap(Uuid, *RemoteSession).init(self.alloc),
            .created_at = std.time.timestamp(),
        };
        return group;
    }

    fn destroyGroup(self: *Daemon, group: *SessionGroup) void {
        self.alloc.free(group.label);
        self.alloc.destroy(group);
    }

    fn createSurface(
        self: *Daemon,
        group: *SessionGroup,
        surface_id: Uuid,
        resize: session.protocol.Resize,
        max_scrollback: u32,
    ) !*RemoteSession {
        const label = try self.alloc.dupe(u8, group.label);
        errdefer self.alloc.free(label);
        const id = try session.shared.generateSessionId(self.alloc);
        errdefer self.alloc.free(id);

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

        // Start shell in user's home directory (daemon cwd is / from daemonization).
        const home_dir = posix.getenv("HOME") orelse "/";

        // Build environment for the shell. Inherit the daemon's env (HOME, SHELL,
        // USER, PATH, LANG, etc.) and set terminal-related variables that are
        // missing because the daemon was started via an SSH exec channel (no TTY).
        var env = try std.process.getEnvMap(self.alloc);
        defer env.deinit();

        // Prefer xterm-ghostty if its terminfo is installed, else xterm-256color.
        const term = if (ghosttyTerminfoAvailable(home_dir)) "xterm-ghostty" else "xterm-256color";
        try env.put("TERM", term);
        try env.put("COLORTERM", "truecolor");
        try env.put("TERM_PROGRAM", "ghostty");
        try env.put("TERM_PROGRAM_VERSION", build_config.version_string);

        var command: Command = .{
            .path = command_path,
            .args = command_args,
            .cwd = home_dir,
            .stdin = .{ .handle = pty.slave },
            .stdout = .{ .handle = pty.slave },
            .stderr = .{ .handle = pty.slave },
            .env = &env,
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

        var t = try terminal.Terminal.init(self.alloc, .{
            .cols = resize.cols,
            .rows = resize.rows,
            .max_scrollback = if (max_scrollback > 0) max_scrollback else 10_000_000,
        });
        errdefer t.deinit(self.alloc);

        const sess = try self.alloc.create(RemoteSession);
        errdefer self.alloc.destroy(sess);
        sess.* = .{
            .alloc = self.alloc,
            .id = id,
            .label = label,
            .surface_id = surface_id,
            .pty = .{ .master = pty.master, .slave = -1 },
            .command = command,
            .terminal_instance = t,
            .stream = undefined,
            .group = group,
            .viewers = .empty,
            .created_at = std.time.timestamp(),
        };

        sess.stream = .init(.{
            .alloc = self.alloc,
            .terminal = &sess.terminal_instance,
            .pty_fd = pty.master,
        });

        sess.reader_thread = try std.Thread.spawn(.{}, RemoteSession.readerMain, .{sess});
        sess.reader_thread.detach();

        group.mutex.lock();
        try group.surfaces.put(surface_id, sess);
        group.mutex.unlock();

        return sess;
    }
};

/// Check whether the xterm-ghostty terminfo entry is installed on this system.
fn ghosttyTerminfoAvailable(home_dir: []const u8) bool {
    const paths = [_][]const u8{
        "/usr/share/terminfo/x/xterm-ghostty",
        "/usr/lib/terminfo/x/xterm-ghostty",
    };

    // Check user-local terminfo first (~/.terminfo/x/xterm-ghostty).
    if (home_dir.len > 0 and home_dir[0] == '/') {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const user_path = std.fmt.bufPrint(&buf, "{s}/.terminfo/x/xterm-ghostty", .{home_dir}) catch return false;
        if (std.fs.accessAbsolute(user_path, .{})) |_| return true else |_| {}
    }

    for (&paths) |p| {
        if (std.fs.accessAbsolute(p, .{})) |_| return true else |_| {}
    }
    return false;
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
fn multiplex(alloc: Allocator, stderr: *std.Io.Writer) !u8 {
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

/// List sessions via the daemon's binary frame protocol.
fn listSessions(
    alloc: Allocator,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Send list_request frame
    sendFrameFd(fd, .list_request, 0, "") catch return;

    // Read response frames
    var buf: [8192]u8 = undefined;
    var read_buf = std.ArrayList(u8).empty;
    defer read_buf.deinit(alloc);

    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        try read_buf.appendSlice(alloc, buf[0..n]);

        // Process complete frames
        while (read_buf.items.len >= session.protocol.header_size) {
            const dk = read_buf.items[0];
            const dplen = std.mem.readInt(u32, read_buf.items[4..8], .little);
            const dtotal = session.protocol.header_size + dplen;
            if (read_buf.items.len < dtotal) break;

            const dkind = std.meta.intToEnum(session.protocol.Kind, dk) catch {
                shiftBuffer(&read_buf, dtotal);
                continue;
            };
            const dpayload = read_buf.items[session.protocol.header_size..dtotal];

            if (dkind == .list_response) {
                // Parse structured binary list response
                const entries = session.protocol.ListResponse.parse(alloc, dpayload) catch {
                    shiftBuffer(&read_buf, dtotal);
                    continue;
                };
                defer alloc.free(entries);

                for (entries) |entry| {
                    const gid_hex = session.shared.formatUuid(entry.group_id);
                    const status_str: []const u8 = switch (entry.status) {
                        .dead => "dead",
                        .attached => "attached",
                        .detached => "detached",
                    };
                    writer.print("{s}|{s}|{d} surfaces ({d} alive)|{d}|{s}\n", .{
                        &gid_hex,
                        entry.label,
                        entry.surface_count,
                        entry.alive_count,
                        entry.created_at,
                        status_str,
                    }) catch {};
                }
            }

            shiftBuffer(&read_buf, dtotal);
        }
    }

    try writer.flush();
}

/// Kill a session via the daemon's binary frame protocol.
fn killSession(
    alloc: Allocator,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Parse id as UUID for the Close struct
    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        // Fall back: try as label — find via list first
        // For simplicity, just send the raw bytes (daemon will handle it)
        const close_data = session.protocol.Close{ .mode = .session, .id = session.shared.zero_uuid };
        const close_payload = close_data.encode(alloc) catch return;
        defer alloc.free(close_payload);
        sendFrameFd(fd, .close, 0, close_payload) catch return;
        try writer.writeAll("OK\n");
        try writer.flush();
        return;
    };
    const close_data = session.protocol.Close{ .mode = .session, .id = uuid };
    const close_payload = close_data.encode(alloc) catch return;
    defer alloc.free(close_payload);
    sendFrameFd(fd, .close, 0, close_payload) catch return;
    try writer.writeAll("OK\n");
    try writer.flush();
}

/// Rename a session via the daemon's binary frame protocol.
fn renameSession(
    alloc: Allocator,
    id: []const u8,
    new_label: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        log.warn("invalid session id for rename: {s}", .{id});
        return;
    };

    const rename_data = session.protocol.Rename{
        .scope = .group,
        .id = uuid,
        .label = new_label,
    };
    const rename_payload = try rename_data.encode(alloc);
    defer alloc.free(rename_payload);
    try sendFrameFd(fd, .rename, 0, rename_payload);
    try writer.writeAll("OK\n");
    try writer.flush();
}

/// Detach all other viewers from a session by sending a kick_viewer frame
/// with zero UUID (meaning "kick everyone except the sender").
fn detachOthersSession(
    alloc: Allocator,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        log.warn("invalid session id for detach-others: {s}", .{id});
        return;
    };

    // The kick_viewer payload is: 16-byte target viewer UUID.
    // Zero UUID means "kick all viewers except the sender".
    // We also need to tell the daemon which session group to act on,
    // so we prepend the group UUID followed by the zero target UUID.
    // However, the kick_viewer frame is handled per-session in
    // processClientFrames, so we send it with the group UUID as target
    // for the multiplexer to route, and zero UUID as the payload.
    var payload: [session.protocol.uuid_size]u8 = session.shared.zero_uuid;

    // We need to open the session first to get routed to it.
    // Send an open frame to attach temporarily, then send kick_viewer.
    const open_data = session.protocol.Open{
        .open_type = .session_attach,
        .group_id = uuid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 },
    };
    const open_payload = try open_data.encode(alloc);
    defer alloc.free(open_payload);
    try sendFrameFd(fd, .open, 0, open_payload);

    // Wait for the opened response.
    var hdr_buf: [session.protocol.header_size]u8 = undefined;
    const file: std.fs.File = .{ .handle = fd };
    _ = file.readAll(&hdr_buf) catch return;
    const hdr = session.protocol.Header.parseFromBuf(&hdr_buf) catch return;

    // Skip the opened payload.
    if (hdr.len > 0) {
        var skip_buf: [512]u8 = undefined;
        var remaining = hdr.len;
        while (remaining > 0) {
            const to_read = @min(remaining, skip_buf.len);
            const n = file.read(skip_buf[0..to_read]) catch break;
            if (n == 0) break;
            remaining -= @intCast(n);
        }
    }

    if (hdr.kind != .opened) {
        log.warn("detach-others: expected opened response, got {}", .{hdr.kind});
        return;
    }

    // Now we're attached to the session. Send kick_viewer with zero UUID.
    try sendFrameFd(fd, .kick_viewer, 0, &payload);
    try writer.writeAll("OK\n");
    try writer.flush();
}

fn preExecPty(cmd: *Command) ?u8 {
    const pty = cmd.getData(Pty) orelse return 1;
    pty.childPreExec() catch return 1;
    return null;
}

// ============================================================================
// Low-level helpers
// ============================================================================

/// Verify that the connecting peer has the same UID as us.
/// Uses platform-specific mechanisms: SO_PEERCRED on Linux,
/// getpeereid() on macOS/BSD.
fn verifyPeerUid(fd: posix.fd_t) !void {
    const our_uid = c.getuid();

    if (comptime builtin.os.tag == .linux) {
        // Use SO_PEERCRED on Linux
        var cred: extern struct {
            pid: c_int,
            uid: c_uint,
            gid: c_uint,
        } = undefined;
        var len: c.socklen_t = @sizeOf(@TypeOf(cred));
        if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_PEERCRED, @ptrCast(&cred), &len) != 0) {
            return error.PeerAuthFailed;
        }
        if (cred.uid != our_uid) {
            log.warn("peer UID {d} != our UID {d}, rejecting", .{ cred.uid, our_uid });
            return error.PeerAuthFailed;
        }
    } else if (comptime builtin.os.tag.isDarwin()) {
        // Use getpeereid() on macOS
        var peer_uid: c.uid_t = undefined;
        var peer_gid: c.gid_t = undefined;
        if (c.getpeereid(fd, &peer_uid, &peer_gid) != 0) {
            return error.PeerAuthFailed;
        }
        if (peer_uid != our_uid) {
            log.warn("peer UID {d} != our UID {d}, rejecting", .{ peer_uid, our_uid });
            return error.PeerAuthFailed;
        }
    }
    // On unsupported platforms, skip verification (Windows is excluded via comptime)
}

fn canConnect(path: []const u8) !bool {
    const fd = connectUnixSocket(path) catch return false;
    closeFd(fd);
    return true;
}

/// Check whether the socket file on disk still belongs to this daemon.
/// Returns false if the file is gone or points to a different inode.
fn isSocketOurs(listener: posix.fd_t, path: []const u8) bool {
    var listener_st: c.struct_stat = undefined;
    if (c.fstat(listener, &listener_st) != 0) return false;
    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= path_buf.len) return false;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    var file_st: c.struct_stat = undefined;
    if (c.stat(&path_buf, &file_st) != 0) return false;
    return listener_st.st_ino == file_st.st_ino and listener_st.st_dev == file_st.st_dev;
}

fn bindUnixSocket(path: []const u8) !posix.fd_t {
    std.fs.cwd().deleteFile(path) catch {};

    const sock_flags = if (@hasDecl(c, "SOCK_CLOEXEC"))
        c.SOCK_STREAM | c.SOCK_CLOEXEC
    else
        c.SOCK_STREAM;
    const fd = c.socket(c.AF_UNIX, sock_flags, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer closeFd(fd);

    // On platforms without SOCK_CLOEXEC (e.g. macOS), set close-on-exec via fcntl.
    if (!@hasDecl(c, "SOCK_CLOEXEC")) {
        if (c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC) < 0) return error.SocketCreateFailed;
    }

    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.NameTooLong;
    @memcpy(addr.sun_path[0..path.len], path);

    if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) {
        return error.BindFailed;
    }

    // Restrict socket permissions to owner only (prevents local hijacking)
    if (c.fchmod(fd, 0o700) != 0) {
        return error.PermissionDenied;
    }

    if (c.listen(fd, 64) != 0) return error.ListenFailed;
    return fd;
}

fn acceptUnixSocket(listener: posix.fd_t) !posix.fd_t {
    const fd = c.accept(listener, null, null);
    if (fd < 0) return error.AcceptFailed;
    // Prevent child processes from inheriting client connection fds.
    _ = c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC);
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

const sendFrameFd = session.shared.sendFrameFd;

/// Read exactly `buf.len` bytes from fd using raw posix.read.
fn readAllRaw(fd: posix.fd_t, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = posix.read(fd, buf[offset..]) catch |err| return err;
        if (n == 0) return error.UnexpectedEOF;
        offset += n;
    }
}

fn writeAllFd(fd: posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try posix.write(fd, bytes[offset..]);
        offset += written;
    }
}

const shiftBuffer = session.shared.shiftBuffer;

fn closeFd(fd: posix.fd_t) void {
    posix.close(fd);
}
