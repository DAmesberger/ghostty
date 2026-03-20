const std = @import("std");
const builtin = @import("builtin");
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

pub const Options = struct {
    daemonize: bool = false,
    daemon: bool = false,
    @"kill-daemon": bool = false,
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

    // Try to connect and send a session_close to trigger graceful shutdown
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
    };
    defer daemon.deinit();

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

        // Periodically reap groups that have been empty past grace period
        daemon.reapEmptyGroups();

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

        const kind = std.meta.intToEnum(session.protocol.Kind, header_buf[0]) catch return;
        const target = std.mem.readInt(u16, header_buf[2..4], .little);
        const payload_len = std.mem.readInt(u32, header_buf[4..8], .little);

        if (payload_len > session.protocol.max_payload) return;
        const payload = try self.daemon.alloc.alloc(u8, payload_len);
        defer self.daemon.alloc.free(payload);
        readAllRaw(self.fd, payload) catch return;

        switch (kind) {
            .session_open => {
                self.daemon.handleSessionOpen(self.fd, target, payload) catch {
                    sendFrameFd(self.fd, .err, target, "session open failed") catch {};
                };
            },
            .surface_open => {
                self.daemon.handleSurfaceOpen(self.fd, target, payload) catch {
                    sendFrameFd(self.fd, .err, target, "surface open failed") catch {};
                };
            },
            .session_list_request => {
                self.daemon.handleSessionList(self.fd) catch |err| {
                    log.warn("session_list failed err={}", .{err});
                };
            },
            .session_close => {
                self.daemon.handleSessionClose(payload);
            },
            .surface_close => {
                self.daemon.handleSurfaceClose(payload);
            },
            .session_rename => {
                self.daemon.handleSessionRename(payload);
            },
            .surface_rename => {
                self.daemon.handleSurfaceRename(payload);
            },
            else => {},
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
    surfaces: std.AutoArrayHashMap(Uuid, *RemoteSession),
    layout_blob: ?[]u8 = null,
    created_at: i64,
    /// Timestamp when the group became empty (all surfaces removed).
    /// Used for grace-period reaping. Reset to null when a surface is added.
    last_empty_at: ?i64 = null,
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
        self.layout_blob = alloc.dupe(u8, blob) catch null;
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

    fn deinit(self: *Daemon) void {
        for (self.groups.values()) |group| group.deinit();
        self.groups.deinit();
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
        payload: []const u8,
    ) !void {
        const open_data = try session.protocol.SessionOpen.parse(payload);

        switch (open_data.mode) {
            .new => {
                // Create group with client-provided group_id + first surface
                const raw_label = if (open_data.label.len > 0) open_data.label else "session";
                const group_id = if (!session.shared.isZeroUuid(open_data.group_id))
                    open_data.group_id
                else
                    session.shared.generateUuid();
                const group = try self.createGroup(raw_label, group_id);

                const surface_id = if (!session.shared.isZeroUuid(open_data.surface_id))
                    open_data.surface_id
                else
                    session.shared.generateUuid();

                const sess = try self.createSurface(group, surface_id, open_data.resize);

                const gid_hex = session.shared.formatUuid(group.id);
                sendFrameFd(fd, .session_opened, target, &gid_hex) catch {};

                sess.attachAndServe(fd, target, open_data.resize) catch {};

                if (sess.closed) {
                    sess.kill();
                    self.mutex.lock();
                    group.mutex.lock();
                    _ = group.surfaces.orderedRemove(surface_id);
                    group.mutex.unlock();
                    maybeMarkGroupEmpty(group);
                    self.mutex.unlock();
                }
            },
            .attach => {
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
                    self.mutex.unlock();

                    // If a label was provided, create a new group with that
                    // name (named session create-or-attach semantics).
                    if (open_data.label.len > 0) {
                        const new_group = self.createGroup(
                            open_data.label,
                            session.shared.generateUuid(),
                        ) catch {
                            sendFrameFd(fd, .err, target, "failed to create session") catch {};
                            return;
                        };
                        created_new = true;
                        break :blk new_group;
                    }

                    sendFrameFd(fd, .err, target, "session not found") catch {};
                    return;
                };
                if (!created_new) self.mutex.unlock();

                const gid_hex = session.shared.formatUuid(group.id);
                sendFrameFd(fd, .session_opened, target, &gid_hex) catch {};

                // Send layout_restore if available
                group.mutex.lock();
                if (group.layout_blob) |blob| {
                    sendFrameFd(fd, .layout_restore, target, blob) catch {};
                }
                group.mutex.unlock();

                // Find the surface to attach to
                const sess = if (!session.shared.isZeroUuid(open_data.surface_id)) blk: {
                    group.mutex.lock();
                    defer group.mutex.unlock();
                    break :blk group.surfaces.get(open_data.surface_id);
                } else group.firstAliveSurface();

                if (sess) |s| {
                    s.attachAndServe(fd, target, open_data.resize) catch |err| {
                        const msg = switch (err) {
                            error.SessionAlreadyAttached => "session is already attached by another client",
                            else => "failed to attach to session",
                        };
                        sendFrameFd(fd, .err, target, msg) catch {};
                        sendFrameFd(fd, .eof, target, "") catch {};
                    };
                } else if (created_new) {
                    // New group via create-or-attach: create the first surface.
                    const surface_id = if (!session.shared.isZeroUuid(open_data.surface_id))
                        open_data.surface_id
                    else
                        session.shared.generateUuid();
                    const new_sess = self.createSurface(group, surface_id, open_data.resize) catch {
                        sendFrameFd(fd, .eof, target, "") catch {};
                        return;
                    };
                    new_sess.attachAndServe(fd, target, open_data.resize) catch |err| {
                        log.warn("attach to new session failed: {}", .{err});
                        sendFrameFd(fd, .eof, target, "") catch {};
                    };

                    if (new_sess.closed) {
                        new_sess.kill();
                        self.mutex.lock();
                        group.mutex.lock();
                        _ = group.surfaces.orderedRemove(surface_id);
                        group.mutex.unlock();
                        maybeMarkGroupEmpty(group);
                        self.mutex.unlock();
                    }
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
        }
    }

    fn handleSurfaceOpen(
        self: *Daemon,
        fd: posix.fd_t,
        target: u16,
        payload: []const u8,
    ) !void {
        const open_data = try session.protocol.SurfaceOpen.parse(payload);

        self.mutex.lock();
        const group = self.groups.get(open_data.group_id) orelse {
            self.mutex.unlock();
            sendFrameFd(fd, .err, target, "group not found") catch {};
            return;
        };
        self.mutex.unlock();

        switch (open_data.mode) {
            .new => {
                const sess = try self.createSurface(group, open_data.surface_id, open_data.resize);
                const gid_hex = session.shared.formatUuid(group.id);
                sendFrameFd(fd, .session_opened, target, &gid_hex) catch {};
                sess.attachAndServe(fd, target, open_data.resize) catch {};

                if (sess.closed) {
                    sess.kill();
                    self.mutex.lock();
                    group.mutex.lock();
                    _ = group.surfaces.orderedRemove(open_data.surface_id);
                    group.mutex.unlock();
                    maybeMarkGroupEmpty(group);
                    self.mutex.unlock();
                }
            },
            .attach => {
                group.mutex.lock();
                const sess = group.surfaces.get(open_data.surface_id);
                group.mutex.unlock();

                if (sess) |s| {
                    const gid_hex = session.shared.formatUuid(group.id);
                    sendFrameFd(fd, .session_opened, target, &gid_hex) catch {};
                    s.attachAndServe(fd, target, open_data.resize) catch {};
                } else {
                    sendFrameFd(fd, .eof, target, "") catch {};
                }
            },
        }
    }

    fn handleSurfaceClose(self: *Daemon, payload: []const u8) void {
        if (payload.len < 16) return;
        const surface_id: Uuid = payload[0..16].*;

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.groups.values()) |group| {
            group.mutex.lock();
            if (group.surfaces.get(surface_id)) |sess| {
                sess.kill();
                _ = group.surfaces.orderedRemove(surface_id);
                group.mutex.unlock();
                maybeMarkGroupEmpty(group);
                return;
            }
            group.mutex.unlock();
        }
    }

    fn handleSessionList(self: *Daemon, fd: posix.fd_t) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
                if (sess.attached_fd != null) attached_count += 1;
                sess.mutex.unlock();
            }
            group.mutex.unlock();

            const gid_hex = session.shared.formatUuid(group.id);
            var entry_buf: [512]u8 = undefined;
            const status: []const u8 = if (alive_count == 0)
                "dead"
            else if (attached_count > 0)
                "attached"
            else
                "detached";
            const entry = std.fmt.bufPrint(&entry_buf, "{s}|{s}|{d} surfaces ({d} alive)|{d}|{s}", .{
                &gid_hex,
                group.label,
                surface_count,
                alive_count,
                created_at,
                status,
            }) catch continue;
            sendFrameFd(fd, .session_list_entry, 0, entry) catch {};

            // Also list individual surfaces
            group.mutex.lock();
            for (group.surfaces.keys(), group.surfaces.values()) |sid, sess| {
                sess.mutex.lock();
                const s_alive = sess.alive;
                const s_attached = sess.attached_fd != null;
                sess.mutex.unlock();

                const sid_hex = session.shared.formatUuid(sid);
                const surface_entry = std.fmt.bufPrint(&entry_buf, "  {s}|{s}|{s}|{s}", .{
                    &sid_hex,
                    sess.label,
                    if (s_alive) "alive" else "dead",
                    if (s_attached) "attached" else "detached",
                }) catch continue;
                sendFrameFd(fd, .session_list_entry, 0, surface_entry) catch {};
            }
            group.mutex.unlock();
        }
    }

    fn handleSessionClose(self: *Daemon, payload: []const u8) void {
        const id = std.mem.trim(u8, payload, " \t\r\n");
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try as group UUID
        const uuid = session.shared.parseUuid(id) catch
            session.shared.parseUuidDashed(id) catch null;

        if (uuid) |u| {
            if (self.groups.get(u)) |group| {
                group.mutex.lock();
                for (group.surfaces.values()) |sess| sess.kill();
                group.mutex.unlock();
                return;
            }
        }

        // Try as label
        for (self.groups.values()) |group| {
            if (std.mem.eql(u8, group.label, id)) {
                group.mutex.lock();
                for (group.surfaces.values()) |sess| sess.kill();
                group.mutex.unlock();
                return;
            }
        }
    }

    /// Rename a session group. Payload: [16] group_id + [N] new_label.
    fn handleSessionRename(self: *Daemon, payload: []const u8) void {
        if (payload.len < 17) return; // need at least UUID + 1 byte label
        const group_id: Uuid = payload[0..16].*;
        const new_label_raw = payload[16..];

        self.mutex.lock();
        defer self.mutex.unlock();

        const group = self.groups.get(group_id) orelse return;
        const new_label = session.shared.sanitizeLabelAlloc(self.alloc, new_label_raw) catch return;
        group.mutex.lock();
        self.alloc.free(group.label);
        group.label = new_label;
        group.mutex.unlock();
        log.info("renamed group to '{s}'", .{new_label});
    }

    /// Rename a surface. Payload: [16] surface_id + [N] new_label.
    fn handleSurfaceRename(self: *Daemon, payload: []const u8) void {
        if (payload.len < 17) return; // need at least UUID + 1 byte label
        const surface_id: Uuid = payload[0..16].*;
        const new_label_raw = payload[16..];

        self.mutex.lock();
        defer self.mutex.unlock();

        // Find the surface across all groups.
        for (self.groups.values()) |group| {
            group.mutex.lock();
            defer group.mutex.unlock();
            if (group.surfaces.get(surface_id)) |sess| {
                const new_label = session.shared.sanitizeLabelAlloc(self.alloc, new_label_raw) catch return;
                sess.mutex.lock();
                self.alloc.free(sess.label);
                sess.label = new_label;
                sess.mutex.unlock();
                log.info("renamed surface to '{s}'", .{new_label});
                return;
            }
        }
    }

    /// Grace period before reaping empty groups (5 minutes).
    const group_reap_grace_s: i64 = 5 * 60;

    /// Check if a group is empty after a surface was removed, and mark
    /// it for reaping if so. Also clears the mark if the group is non-empty.
    /// Caller must hold daemon.mutex. Group mutex should NOT be held.
    fn maybeMarkGroupEmpty(group: *SessionGroup) void {
        group.mutex.lock();
        defer group.mutex.unlock();
        if (group.surfaces.count() == 0) {
            if (group.last_empty_at == null) {
                group.last_empty_at = std.time.timestamp();
                log.info("group {s} is now empty, scheduled for reaping", .{group.label});
            }
        } else {
            group.last_empty_at = null;
        }
    }

    /// Remove groups that have been empty longer than the grace period.
    /// Must be called without holding daemon.mutex (acquires it internally).
    fn reapEmptyGroups(self: *Daemon) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var i: usize = 0;
        while (i < self.groups.count()) {
            const group = self.groups.values()[i];
            group.mutex.lock();
            const should_reap = if (group.last_empty_at) |t|
                (now - t) > group_reap_grace_s
            else
                false;
            group.mutex.unlock();

            if (should_reap) {
                log.info("reaping empty group {s} (empty for >{d}s)", .{
                    group.label, group_reap_grace_s,
                });
                self.groups.swapRemoveAt(i);
                group.deinit();
                // Don't increment i — the swap moved a new element here
            } else {
                i += 1;
            }
        }
    }

    fn createGroup(self: *Daemon, raw_label: []const u8, group_id: Uuid) !*SessionGroup {
        const label = try session.shared.sanitizeLabelAlloc(self.alloc, raw_label);
        errdefer self.alloc.free(label);

        const group = try self.alloc.create(SessionGroup);
        errdefer self.alloc.destroy(group);
        group.* = .{
            .alloc = self.alloc,
            .id = group_id,
            .label = label,
            .surfaces = std.AutoArrayHashMap(Uuid, *RemoteSession).init(self.alloc),
            .created_at = std.time.timestamp(),
        };

        self.mutex.lock();
        try self.groups.put(group.id, group);
        self.mutex.unlock();

        return group;
    }

    fn createSurface(
        self: *Daemon,
        group: *SessionGroup,
        surface_id: Uuid,
        resize: session.protocol.Resize,
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

        var t = try terminal.Terminal.init(self.alloc, .{
            .cols = resize.cols,
            .rows = resize.rows,
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
        group.last_empty_at = null; // Group is no longer empty
        group.mutex.unlock();

        return sess;
    }
};

// ============================================================================
// Multiplexer — pure passthrough between SSH stdin/stdout and daemon socket
// ============================================================================

const MAX_MUX_SESSIONS = 64;

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
                .session_open, .surface_open => {
                    handleOpenFrame(
                        alloc,
                        &sessions,
                        kind,
                        target,
                        payload,
                        socket_path,
                        stdout_file,
                    ) catch |err| {
                        const msg = std.fmt.allocPrint(alloc, "open failed: {}", .{err}) catch {
                            sendFrameFile(stdout_file, .err, target, "open failed") catch {};
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
                .surface_close => {
                    // Forward to daemon so it can kill the surface process
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, .surface_close, 0, payload) catch {};
                    }
                    closeMuxSession(&sessions, alloc, target);
                },
                .detach => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, .detach, 0, "") catch {};
                    }
                    closeMuxSession(&sessions, alloc, target);
                },
                // All other frames: passthrough to the daemon socket
                .stdin,
                .resize,
                .layout_update,
                .session_rename,
                .surface_rename,
                => {
                    if (findMuxSession(&sessions, target)) |s| {
                        sendFrameFd(s.daemon_fd, kind, target, payload) catch {
                            sendFrameFile(stdout_file, .eof, target, "") catch {};
                            closeMuxSession(&sessions, alloc, target);
                        };
                    }
                },
                .session_list_request => {
                    handleSessionListRequest(alloc, socket_path, stdout_file) catch |err| {
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

                // Forward complete frames from daemon to stdout (rewrite target)
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

                    // Rewrite target ID and forward to client
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
    alloc: Allocator,
    sessions: *[MAX_MUX_SESSIONS]?MuxSession,
    kind: session.protocol.Kind,
    target: u16,
    payload: []const u8,
    socket_path: []const u8,
    stdout_file: std.fs.File,
) !void {
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

    // Send the open frame directly to the daemon (binary protocol)
    sendFrameFd(daemon_fd, kind, target, payload) catch {
        return error.DaemonWriteFailed;
    };

    sessions[idx] = .{
        .target = target,
        .daemon_fd = daemon_fd,
        .read_buf = std.ArrayList(u8).empty,
    };

    _ = alloc;
    _ = stdout_file;
}

fn handleSessionListRequest(
    alloc: Allocator,
    socket_path: []const u8,
    stdout_file: std.fs.File,
) !void {
    _ = alloc;
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Send session_list_request frame to daemon
    sendFrameFd(fd, .session_list_request, 0, "") catch return;

    // Read and forward response frames
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        stdout_file.writeAll(buf[0..n]) catch break;
    }
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

/// List sessions via the daemon's binary frame protocol.
fn listSessions(
    alloc: Allocator,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Send session_list_request frame
    sendFrameFd(fd, .session_list_request, 0, "") catch return;

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

            if (dkind == .session_list_entry) {
                try writer.writeAll(dpayload);
                try writer.writeAll("\n");
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

    sendFrameFd(fd, .session_close, 0, id) catch return;
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
    if (payload.len > session.protocol.max_payload) return error.PayloadTooLarge;
    var file: std.fs.File = .{ .handle = fd };
    var buf: [1024]u8 = undefined;
    var writer_ = file.writerStreaming(&buf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, kind, target, payload);
    try writer.flush();
}

fn sendFrameFile(file: std.fs.File, kind: session.protocol.Kind, target: u16, payload: []const u8) !void {
    if (payload.len > session.protocol.max_payload) return error.PayloadTooLarge;
    var header: [session.protocol.header_size]u8 = undefined;
    header[0] = @intFromEnum(kind);
    header[1] = 0;
    std.mem.writeInt(u16, header[2..4], target, .little);
    std.mem.writeInt(u32, header[4..8], @intCast(payload.len), .little);
    try file.writeAll(&header);
    try file.writeAll(payload);
}

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
