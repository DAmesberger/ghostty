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
    version: bool = false,
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

    if (opts.version) {
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
        return try stdioAttach(alloc, opts, stderr);
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
    daemonMain(alloc) catch {
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
        var writer_buf: [1024]u8 = undefined;
        var file: std.fs.File = .{ .handle = self.fd };
        var writer_ = file.writer(&writer_buf);
        const writer = &writer_.interface;

        const line = try readLineAlloc(self.daemon.alloc, self.fd, 4096);
        defer self.daemon.alloc.free(line);
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) return;

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
                if (!self.replaying) sendFrameFd(fd, .stdout, buf[0..n]) catch |err| {
                    log.warn("attached client write failed id={s} err={}", .{ self.id, err });
                    self.attached_fd = null;
                };
            }
            self.mutex.unlock();
        }

        self.mutex.lock();
        self.alive = false;
        if (self.attached_fd) |fd| _ = sendFrameFd(fd, .eof, "") catch {};
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
        var reader_ = file.reader(&reader_buf);
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
            try sendFrameFd(fd, .stdout, buf[0..n]);
        }
    }
};

fn stdioAttach(
    alloc: Allocator,
    opts: Options,
    stderr: *std.Io.Writer,
) !u8 {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    var file: std.fs.File = .{ .handle = fd };
    var writer_buf: [1024]u8 = undefined;
    var writer_ = file.writer(&writer_buf);
    const writer = &writer_.interface;

    const label = opts.label orelse "session";
    const resize = localResize();
    if (opts.new or opts.session == null) {
        const safe = try session.shared.sanitizeLabelAlloc(alloc, label);
        defer alloc.free(safe);
        try writer.print(
            "ATTACH NEW {d} {d} {d} {d} {s}\n",
            .{ resize.rows, resize.cols, resize.width_px, resize.height_px, safe },
        );
    } else {
        try writer.print(
            "ATTACH EXISTING {d} {d} {d} {d} {s}\n",
            .{ resize.rows, resize.cols, resize.width_px, resize.height_px, opts.session.? },
        );
    }
    try writer.flush();

    const line = try readLineAlloc(alloc, fd, 4096);
    defer alloc.free(line);
    const response = std.mem.trim(u8, line, " \t\r\n");
    if (!std.mem.startsWith(u8, response, "OK ")) {
        try stderr.print("{s}\n", .{response});
        return 1;
    }

    const session_id = response["OK ".len..];
    {
        var out_buf: [1024]u8 = undefined;
        var stdout_writer_ = std.fs.File.stdout().writer(&out_buf);
        const stdout = &stdout_writer_.interface;
        try session.protocol.writeFrame(stdout, .info, session_id);
        try stdout.flush();
    }

    const stdin_thread = try std.Thread.spawn(.{}, proxyLocalToSocket, .{fd});
    defer stdin_thread.join();
    try proxySocketToLocal(alloc, fd);
    return 0;
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

fn sendFrameFd(fd: posix.fd_t, kind: session.protocol.Kind, payload: []const u8) !void {
    var file: std.fs.File = .{ .handle = fd };
    var buf: [1024]u8 = undefined;
    var writer_ = file.writer(&buf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, kind, payload);
    try writer.flush();
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

fn proxyLocalToSocket(fd: posix.fd_t) void {
    var stdin_file: std.fs.File = .stdin();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = stdin_file.read(&buf) catch break;
        if (n == 0) break;
        sendFrameFd(fd, .stdin, buf[0..n]) catch break;
    }
}

fn proxySocketToLocal(alloc: Allocator, fd: posix.fd_t) !void {
    var socket_file: std.fs.File = .{ .handle = fd };
    var socket_reader_buf: [1024]u8 = undefined;
    var socket_reader_ = socket_file.reader(&socket_reader_buf);
    const socket_reader = &socket_reader_.interface;

    var stdout_file: std.fs.File = .stdout();
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer_ = stdout_file.writer(&stdout_buf);
    const stdout = &stdout_writer_.interface;

    while (true) {
        const header = session.protocol.readHeader(socket_reader) catch break;
        const payload = try session.protocol.readPayloadAlloc(alloc, socket_reader, header);
        defer alloc.free(payload);
        switch (header.kind) {
            .stdout => try stdout.writeAll(payload),
            .err => try std.fs.File.stderr().writeAll(payload),
            .eof => break,
            else => {},
        }
        try stdout.flush();
    }
}

fn localResize() session.protocol.Resize {
    var ws: ptypkg.winsize = .{};
    _ = c.ioctl(posix.STDIN_FILENO, c.TIOCGWINSZ, @intFromPtr(&ws));
    return .{
        .rows = ws.ws_row,
        .cols = ws.ws_col,
        .width_px = ws.ws_xpixel,
        .height_px = ws.ws_ypixel,
    };
}

fn closeFd(fd: posix.fd_t) void {
    posix.close(fd);
}

fn readLineAlloc(alloc: Allocator, fd: posix.fd_t, max_bytes: usize) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(alloc);

    var file: std.fs.File = .{ .handle = fd };
    var reader_buf: [1024]u8 = undefined;
    var reader_ = file.reader(&reader_buf);
    const reader = &reader_.interface;

    while (bytes.items.len < max_bytes) {
        var byte: [1]u8 = undefined;
        reader.readSliceAll(&byte) catch break;
        if (byte[0] == '\n') break;
        try bytes.append(alloc, byte[0]);
    }

    return try bytes.toOwnedSlice(alloc);
}
