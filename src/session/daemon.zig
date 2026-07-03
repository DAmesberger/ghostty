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
const persist = session.persist;

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

/// Write a diagnostic line to stderr (which is daemon.log in daemon mode).
/// Works in release builds unlike std.log.info.
fn daemonLog(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = std.posix.write(2, msg) catch {};
}

/// Resolve the directory that holds this daemon binary on the remote — the dir
/// the client provisioned it into (see `shared.remoteInstallDir`). It is
/// prepended to every spawned shell's PATH so `ghostty-daemon` is invokable by
/// name and embedder-installed tools placed here are found. Caller owns the
/// returned slice.
fn resolveBinDir(alloc: Allocator) ![]u8 {
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const self_exe = try std.fs.selfExePath(&exe_buf);
    const dir = std.fs.path.dirname(self_exe) orelse ".";
    return alloc.dupe(u8, dir);
}

/// Install an embedder-supplied shim into `bin_dir`, if one was provided via the
/// daemon launch environment (`control_bridge_config.env_shim_*`). The embedder
/// (e.g. cmux) base64-encodes an executable and names it; the daemon writes it
/// verbatim onto the on-PATH bin dir. ghostty has no knowledge of what the shim
/// does. No-op when the env vars are absent. Best-effort — the caller logs and
/// never treats failure as fatal.
fn installEmbedderShim(alloc: Allocator, bin_dir: []const u8) !void {
    const name = std.posix.getenv(session.control_bridge_config.env_shim_name) orelse return;
    const body_b64 = std.posix.getenv(session.control_bridge_config.env_shim_body_b64) orelse return;
    if (name.len == 0 or body_b64.len == 0) return;

    // The shim is a bare filename in bin_dir; reject path traversal.
    if (std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        return error.InvalidShimName;
    }

    const Decoder = std.base64.standard.Decoder;
    const decoded_len = try Decoder.calcSizeForSlice(body_b64);
    const body = try alloc.alloc(u8, decoded_len);
    defer alloc.free(body);
    try Decoder.decode(body, body_b64);

    const mode: std.fs.File.Mode = mode: {
        const m = std.posix.getenv(session.control_bridge_config.env_shim_mode) orelse
            break :mode 0o755;
        break :mode std.fmt.parseInt(
            std.fs.File.Mode,
            std.mem.trim(u8, m, " \t\r\n"),
            8,
        ) catch 0o755;
    };

    const shim_path = try std.fs.path.join(alloc, &.{ bin_dir, name });
    defer alloc.free(shim_path);

    var file = try std.fs.cwd().createFile(shim_path, .{ .mode = mode, .truncate = true });
    defer file.close();
    try file.writeAll(body);
}

pub const Options = struct {
    daemonize: bool = false,
    daemon: bool = false,
    @"kill-daemon": bool = false,
    list: bool = false,
    @"protocol-version": bool = false,
    @"stdio-attach": bool = false,
    @"mux-attach": bool = false,
    kill: ?[]const u8 = null,
    rename: ?[]const u8 = null,
    @"detach-others": ?[]const u8 = null,
    session: ?[]const u8 = null,
    new: bool = false,
    label: ?[]const u8 = null,
    /// cmux Phase 2 (GATED): probe the running daemon for execve-handoff
    /// capability. Prints `REEXEC 1` iff it can, else `REEXEC 0` (incl. EOF
    /// against a pre-feature daemon). Always exits 0.
    @"query-reexec": bool = false,
    /// cmux Phase 2 (GATED): ask the running daemon to execve-replace itself
    /// with the binary at this absolute path, preserving live shells. Exits 0
    /// on a clean handoff (EOF without a preceding `.err`), non-zero otherwise
    /// so the caller falls back to `--kill-daemon` + `--daemonize`.
    reexec: ?[]const u8 = null,
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

    if (opts.@"query-reexec") {
        try queryReexec(alloc, stdout);
        return 0;
    }

    if (opts.reexec) |newbin| {
        return try requestReexec(alloc, newbin, stdout);
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

    if (opts.@"mux-attach") {
        return try muxAttach(alloc, stderr);
    }

    try stderr.writeAll("missing helper mode\n");
    return 1;
}

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
fn muxAttach(alloc: Allocator, stderr: *std.Io.Writer) !u8 {
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

// ============================================================================
// cmux execve self-handoff (Phase 2, GATED) — CLI client probes
//
// IMPORTANT: both helpers run inside `<remote_bin> +ssh-session ...`. After a
// runtime update the client already `mv -f`'d the NEW binary over remote_bin,
// so THIS process is the new image — but that is irrelevant: these are runtime
// PROBES of the *already-running* (old) daemon over its unix socket, not a
// self-test of the client binary. Do not "fix" this by re-resolving the path.
// ============================================================================

/// `--query-reexec`: ask the running daemon whether it can execve-handoff.
/// Prints exactly `REEXEC 1` on a yes, `REEXEC 0` on anything else (no daemon,
/// EOF from a pre-feature daemon that dropped the unknown frame, short read,
/// or an explicit no). Always succeeds (exit 0); the client parses the line.
fn queryReexec(alloc: Allocator, stdout: *std.Io.Writer) !void {
    const answer: u8 = blk: {
        const socket_path = session.shared.socketPath(alloc) catch break :blk 0;
        defer alloc.free(socket_path);
        const fd = connectUnixSocket(socket_path) catch break :blk 0;
        defer closeFd(fd);
        sendFrameFd(fd, .reexec_query, 0, "") catch break :blk 0;
        var hbuf: [session.protocol.header_size]u8 = undefined;
        readAllRaw(fd, &hbuf) catch break :blk 0;
        const hdr = session.protocol.Header.parseFromBuf(&hbuf) catch break :blk 0;
        if (hdr.kind != .reexec_caps or hdr.len < 1 or hdr.len > 64) break :blk 0;
        var pbuf: [64]u8 = undefined;
        readAllRaw(fd, pbuf[0..hdr.len]) catch break :blk 0;
        break :blk if (pbuf[0] == 1) @as(u8, 1) else 0;
    };
    try stdout.print("REEXEC {d}\n", .{answer});
    try stdout.flush();
}

/// `--reexec <abs path>`: ask the running daemon to execve-replace itself with
/// the binary at `newbin`, preserving live shells. Reads reply frames to EOF: a
/// preceding `.err` frame means the daemon ABORTED (exit 1 → caller falls back);
/// a plain EOF (the daemon's connection fd closing on a successful execve) means
/// the handoff was launched (exit 0). No daemon / connect failure → exit 1.
fn requestReexec(alloc: Allocator, newbin: []const u8, stdout: *std.Io.Writer) !u8 {
    _ = stdout;
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = connectUnixSocket(socket_path) catch return 1;
    defer closeFd(fd);

    sendFrameFd(fd, .reexec, 0, newbin) catch return 1;

    var saw_err = false;
    while (true) {
        var hbuf: [session.protocol.header_size]u8 = undefined;
        readAllRaw(fd, &hbuf) catch break; // EOF/err → handoff launched (or done)
        const hdr = session.protocol.Header.parseFromBuf(&hbuf) catch break;
        if (hdr.len > session.protocol.max_payload) break;
        if (hdr.len > 0) {
            const pbuf = alloc.alloc(u8, hdr.len) catch break;
            defer alloc.free(pbuf);
            readAllRaw(fd, pbuf) catch break;
        }
        if (hdr.kind == .err) saw_err = true;
    }
    return if (saw_err) 1 else 0;
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

    // cmux execve self-handoff (Phase 2, GATED): if a predecessor execve'd into
    // us it set GHOSTTY_DAEMON_REEXEC (the handoff nonce) and left a manifest
    // carrying the inherited (CLOEXEC-cleared) listener + alive-master fds. When
    // the nonce + writer_pid validate we ADOPT the inherited listener (skip
    // bind → same socket inode → isSocketOurs stays true, accept backlog
    // preserved). Any mismatch / torn manifest → close every carried fd and
    // bind fresh (== today's behavior). Surfaces are adopted after the Daemon
    // is constructed (see below).
    var reexec_manifest: ?persist.ReexecManifest = null;
    errdefer if (reexec_manifest) |*m| m.deinit(alloc);
    var adopted_listener: ?posix.fd_t = null;
    if (posix.getenv("GHOSTTY_DAEMON_REEXEC")) |nonce_env| {
        reexecLogTo(state_dir, "adopt: env GHOSTTY_DAEMON_REEXEC present len={d}", .{nonce_env.len});
        if (persist.readReexecManifest(alloc, state_dir) catch null) |m_| {
            var m = m_;
            const my_pid: i32 = @intCast(c.getpid());
            const nonce_ok = nonce_env.len == m.nonce_hex.len and
                std.mem.eql(u8, &m.nonce_hex, nonce_env);
            const pid_ok = m.writer_pid == my_pid;
            reexecLogTo(state_dir, "adopt: manifest version={d} nonce_ok={} pid_ok={} writer={d} me={d} surfaces={d}", .{ m.version, nonce_ok, pid_ok, m.writer_pid, my_pid, m.surfaces.len });
            if (nonce_ok and pid_ok) {
                // We ARE the genuine execve successor: the carried fd numbers
                // refer to fds WE inherited (CLOEXEC was cleared on them).
                if (m.bodyValid()) {
                    adopted_listener = m.listener_fd;
                    reexec_manifest = m; // adopt surfaces after Daemon is built
                    reexecLogTo(state_dir, "adopt: listener_fd={d} (skip bind)", .{m.listener_fd});
                } else {
                    // Right successor, unknown body version → close our inherited
                    // carried fds and bind fresh (sessions reload-on-attach).
                    for (m.carried_fds) |cfd| if (cfd >= 0) closeFd(cfd);
                    reexecLogTo(state_dir, "adopt: body version mismatch — closed {d} inherited fds, fresh bind", .{m.carried_fds.len});
                    m.deinit(alloc);
                }
            } else {
                // Stale/foreign manifest: the carried fd NUMBERS belong to a
                // DIFFERENT process. Do NOT close them (that would clobber our
                // own fds). Just bind fresh.
                reexecLogTo(state_dir, "adopt: nonce/pid mismatch — ignoring stale manifest, fresh bind", .{});
                m.deinit(alloc);
            }
        } else {
            reexecLogTo(state_dir, "adopt: manifest read failed — fresh start", .{});
        }
        // The env var and file are single-use; clear both now so a crash-restart
        // can't re-adopt stale fd numbers.
        _ = c.unsetenv("GHOSTTY_DAEMON_REEXEC");
        persist.deleteReexecManifest(alloc, state_dir);
    }

    const listener_fd = adopted_listener orelse try bindUnixSocket(socket_path);
    // Capture the filesystem inode of our bound socket file *now*. The
    // `isSocketOurs` poll-timeout check compares this against the file
    // currently on disk at `socket_path`. Comparing fstat(listener_fd)
    // against stat(path) is wrong for unix-domain sockets: the listener
    // fd's `st_ino` is an anonymous kernel-socket inode (matches what
    // `/proc/net/unix` shows, e.g. 191054754) while the path's `st_ino`
    // is the filesystem inode of the socket entry (e.g. 9306784).
    // Those never match, so the original implementation made the daemon
    // commit suicide on every 60s poll-timeout — surfacing as "remote
    // terminals vanish after exactly 1 minute".
    var stbuf: c.struct_stat = undefined;
    {
        var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        if (socket_path.len >= path_buf.len) return error.SocketPathTooLong;
        @memcpy(path_buf[0..socket_path.len], socket_path);
        path_buf[socket_path.len] = 0;
        if (c.stat(&path_buf, &stbuf) != 0) return error.StatBoundSocketFailed;
    }
    const socket_file_inode: u64 = @intCast(stbuf.st_ino);

    var daemon: Daemon = .{
        .alloc = alloc,
        .socket_path = try alloc.dupe(u8, socket_path),
        .socket_file_inode = socket_file_inode,
        .groups = std.AutoArrayHashMap(Uuid, *SessionGroup).init(alloc),
        .listener = listener_fd,
        .channel_registry = session.channel_mux.Registry.init(alloc),
        .state_dir = try alloc.dupe(u8, state_dir),
        // cmux execve self-handoff is advertised + accepted only when launched
        // with GHOSTTY_SSH_REEXEC=1 (default OFF → answers REEXEC 0 → client
        // falls back to today's kill+restart).
        .reexec_enabled = blk: {
            if (posix.getenv("GHOSTTY_SSH_REEXEC")) |v| break :blk std.mem.eql(u8, v, "1");
            break :blk false;
        },
    };
    defer daemon.deinit();
    daemon.reexecLog("daemon boot pid={d} reexec_enabled={} adopted_listener={}", .{ c.getpid(), daemon.reexec_enabled, adopted_listener != null });

    // Register channel-mux services. These are the daemon's built-in
    // services advertised in every Capabilities frame.
    try session.services.tcp_connect.register(&daemon.channel_registry);
    try session.services.browser_proxy.register(&daemon.channel_registry);
    try session.services.file_transfer.register(&daemon.channel_registry);
    try session.services.port_listener.register(&daemon.channel_registry);
    try session.services.tcp_accepted.register(&daemon.channel_registry);
    try session.services.control_bridge.register(&daemon.channel_registry);

    // Derive the per-daemon control-bridge reverse-channel socket path and
    // auth token now (before any client connects). The socket itself is
    // bound lazily on each mux connection (see `runMuxMode`); the path +
    // token are injected into every spawned shell's env (see
    // `createSurface`) so the remote control CLI can reach the client.
    daemon.control_bridge_socket_path = session.services.control_bridge.deriveSocketPath(alloc) catch |err| blk: {
        daemonLog("control_bridge: socket path derive failed: {}", .{err});
        break :blk null;
    };
    daemon.control_bridge_token = session.services.control_bridge.deriveToken(alloc) catch |err| blk: {
        daemonLog("control_bridge: token derive failed: {}", .{err});
        break :blk null;
    };

    // Resolve the on-PATH remote bin dir (where this daemon binary lives) and
    // install any embedder-supplied shim. ghostty itself installs nothing by
    // default; the embedder (e.g. cmux) delivers a shim via the daemon launch
    // env (`control_bridge_config.env_shim_*`). The bin dir is prepended to
    // PATH in `createSurface` so `ghostty-daemon` and the shim resolve by name.
    daemon.control_bridge_bin_dir = resolveBinDir(alloc) catch |err| blk: {
        daemonLog("control_bridge: bin dir resolve failed: {}", .{err});
        break :blk null;
    };
    if (daemon.control_bridge_bin_dir) |bin_dir| {
        installEmbedderShim(alloc, bin_dir) catch |err| {
            daemonLog("control_bridge: embedder shim install failed: {}", .{err});
        };
    }

    // cmux scrollback persistence (first cut): set up the on-disk state dir
    // and start the periodic checkpoint thread. Disabled with
    // GHOSTTY_SSH_PERSIST=0 (safety off-switch). If the dir can't be created
    // persistence simply stays off (persist_dir == null) and the daemon runs
    // exactly as before.
    const persist_enabled = blk: {
        if (posix.getenv("GHOSTTY_SSH_PERSIST")) |v| {
            if (std.mem.eql(u8, v, "0")) break :blk false;
        }
        break :blk true;
    };
    if (persist_enabled) {
        const pdir = session.shared.persistDir(alloc) catch null;
        if (pdir) |p| {
            std.fs.cwd().makePath(p) catch {};
            {
                var dir = std.fs.cwd().openDir(p, .{}) catch null;
                if (dir) |*d| {
                    d.chmod(0o700) catch {};
                    d.close();
                }
            }
            daemon.persist_dir = p;
            // Startup index + TTL sweep: repopulate the group map (metadata +
            // detached surface ids) from disk so `--list` / the chooser / the
            // layout survive a restart before any attach. Single-threaded here:
            // no clients are connected and the checkpoint thread isn't spawned
            // yet, so this runs without lock contention and spawns no shells.
            // MUST run BEFORE re-exec surface adoption so adopted surfaces land
            // in groups already carrying their real metadata (not a placeholder).
            daemon.loadPersistedGroupsOnStartup();
            // TODO(cmux): SIGTERM handler that calls checkpointAll to tighten
            //   the graceful-but-signaled path. The 30s periodic checkpoint
            //   already bounds loss on SIGKILL. Deferred per design §6.6.
        }
    }

    // cmux execve self-handoff (Phase 2, GATED): adopt the alive surfaces the
    // predecessor carried (inherited PTY master + child pid → fresh
    // RemoteSession, NO fork). Runs after the startup index so groups already
    // have correct metadata; per-surface failures degrade to reload-on-attach
    // (fresh shell + restored scrollback), other shells stay live. Single-
    // threaded here (checkpoint thread not yet spawned, no clients).
    if (reexec_manifest) |*m| {
        daemon.adoptReexecSurfaces(m);
        m.deinit(alloc);
        reexec_manifest = null;
    }

    // Spawn the periodic checkpoint thread last, after the startup index + any
    // re-exec adoption have settled the group/surface maps.
    if (daemon.persist_dir != null) {
        daemon.persist_thread = std.Thread.spawn(.{}, Daemon.checkpointLoop, .{&daemon}) catch null;
        if (daemon.persist_thread == null) {
            daemonLog("persist: checkpoint thread spawn failed; persistence disabled", .{});
        }
    }
    // Stop + join the checkpoint thread on the way out (covers every return
    // path from the accept loop below) before daemon.deinit frees state.
    defer {
        daemon.persist_should_stop.store(true, .release);
        if (daemon.persist_thread) |t| t.join();
    }

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
            if (!isSocketOurs(daemon.socket_file_inode, daemon.socket_path)) {
                daemonLog("socket replaced, shutting down", .{});
                // cmux scrollback persistence: this is the common graceful
                // `--kill-daemon` restart path. Checkpoint everything one last
                // time so the new daemon can reload scrollback on attach. The
                // deferred stop/join above tears down the checkpoint thread.
                daemon.checkpointAll();
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
            // cmux execve self-handoff (Phase 2, GATED). Inert when the daemon
            // was not launched with GHOSTTY_SSH_REEXEC=1 (answers caps=0; rejects
            // the reexec request with an .err so the client falls back to today's
            // kill+restart).
            .reexec_query => {
                const caps: u8 = if (self.daemon.reexec_enabled) 1 else 0;
                sendFrameFd(self.fd, .reexec_caps, 0, &[_]u8{caps}) catch {};
            },
            .reexec => {
                if (!self.daemon.reexec_enabled) {
                    sendFrameFd(self.fd, .err, target, "reexec disabled") catch {};
                    return;
                }
                // Runs on THIS client thread. On success `execve` replaces the
                // whole process (every thread) and this never returns; on any
                // failure it sends `.err` and returns so we drop the connection.
                self.daemon.handleReexec(self.fd, payload);
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

        // Start the control-bridge reverse-channel listener for this mux
        // connection. It binds the per-daemon AF_UNIX socket and opens a
        // daemon-originated `control_bridge` child channel for each accepted
        // connection. Stop it BEFORE `mux.deinit()` so no new child
        // channels are opened during teardown.
        var control_listener: ?*session.services.control_bridge.Listener = null;
        if (self.daemon.control_bridge_socket_path) |sock_path| {
            if (self.daemon.control_bridge_token) |token| {
                control_listener = session.services.control_bridge.startListener(
                    self.daemon.alloc,
                    &mux,
                    sock_path,
                    token,
                ) catch |err| blk: {
                    log.warn("control_bridge: listener start failed: {}", .{err});
                    break :blk null;
                };
            }
        }
        defer if (control_listener) |l| l.stop();

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
                // Keepalive: answer the client's session-level ping with a
                // pong. Without this the mux path drops `.ping` into the
                // `else` branch below, the client never sees a pong, and its
                // stale-detection (no pong for keepalive_stale_ns = 12s)
                // forces a needless reconnect every interval on an idle mux
                // connection — which manifests as the workspace flashing a
                // "Reconnecting" overlay every ~12s. The legacy `multiplex`
                // loop already answers pings; the mux path was missing it.
                .ping => sendFrameFd(self.fd, .pong, 0, "") catch {},
                .pong => {},
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
    /// Surface ids that have a `<id>.term` on disk but are NOT yet live in
    /// `surfaces` this daemon generation (persisted-but-not-attached). Kept
    /// DISJOINT from `surfaces` keys by invariant: `createSurfaceInner`
    /// removes an id from here the instant it registers a live surface, and
    /// the close paths drop it. Lets `--list`/the chooser show persisted
    /// sessions before any attach lazily reloads them. Guarded by `mutex`
    /// (same as `surfaces`).
    detached_surfaces: std.AutoArrayHashMap(Uuid, void),
    layout_blob: ?[]u8 = null,
    created_at: i64,
    mutex: std.Thread.Mutex = .{},

    pub fn deinit(self: *SessionGroup) void {
        for (self.surfaces.values()) |sess| sess.deinit();
        self.surfaces.deinit();
        self.detached_surfaces.deinit();
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

/// Shared, atomically-mutated control block for the GATED execve self-handoff
/// (cmux Phase 2). Pointed at by every `RemoteSession.reexec` so the reader
/// threads can observe `in_progress` and park themselves (no PTY reads) while
/// the daemon checkpoints + builds the handoff manifest, and report back via
/// `active_readers` when they have parked. Default-inert: `in_progress` is only
/// ever set when the daemon was launched with `GHOSTTY_SSH_REEXEC=1`.
pub const ReexecControl = struct {
    /// Set true just before quiescing for an execve handoff; gates new surface
    /// creation and tells every reader thread to drain + park.
    in_progress: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Count of live reader threads currently NOT parked. handleReexec waits
    /// for this to reach 0 (with a timeout) before clearing CLOEXEC + execve.
    active_readers: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

/// Append one fsync'd line to `<state_dir>/reexec.log`. Separate from the
/// truncated `daemon.log` so the pre-exec / post-exec handoff diagnostics
/// survive the execve (append mode, never truncated). Best-effort.
fn reexecLogTo(state_dir: []const u8, comptime fmt: []const u8, args: anytype) void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/reexec.log", .{state_dir}) catch return;
    var file = std.fs.cwd().createFile(path, .{ .truncate = false, .mode = 0o600 }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch {};
    var line_buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&line_buf, fmt ++ "\n", args) catch return;
    file.writeAll(msg) catch {};
    std.posix.fsync(file.handle) catch {};
}

const Daemon = struct {
    alloc: Allocator,
    socket_path: []const u8,
    /// Filesystem inode of the bound socket file, captured by
    /// `stat(socket_path)` immediately after `bindUnixSocket`. The
    /// poll-timeout `isSocketOurs` check compares this against the
    /// current `stat(socket_path).st_ino` to detect "a new daemon
    /// has replaced our socket file" without conflating it with the
    /// listener fd's anonymous kernel-socket inode.
    socket_file_inode: u64,
    listener: posix.fd_t,
    mutex: std.Thread.Mutex = .{},
    groups: std.AutoArrayHashMap(Uuid, *SessionGroup),
    /// Registry of channel-mux services. Populated at startup; read-only
    /// thereafter. Empty in Phase 6A.2 — every channel_open is rejected
    /// with service_not_supported until services land in 6A.3.
    channel_registry: session.channel_mux.Registry,
    /// Per-daemon AF_UNIX path the `control_bridge` reverse channel binds
    /// on each mux connection, and the path injected into every spawned
    /// shell as `GHOSTTY_CONTROL_SOCKET`. Owned here; null if derivation failed.
    control_bridge_socket_path: ?[]u8 = null,
    /// Per-daemon auth token the remote forwarder must present on the
    /// reverse-channel socket, injected as `GHOSTTY_CONTROL_TOKEN`. Owned
    /// here; null if derivation failed.
    control_bridge_token: ?[]u8 = null,
    /// The remote bin dir holding this daemon binary (and any embedder shim),
    /// prepended to every spawned shell's PATH so `ghostty-daemon` and the
    /// shim resolve by name. Owned here; null if resolution failed. NOT
    /// deleted on deinit — it is the provisioned install dir, not a temp dir.
    control_bridge_bin_dir: ?[]u8 = null,

    // ---- cmux scrollback persistence (first cut) -----------------------
    /// Root dir `<stateDir>/state` where per-group/per-surface scrollback
    /// snapshots are checkpointed. Owned here; null if persistence is
    /// disabled (env `GHOSTTY_SSH_PERSIST=0`) or path derivation failed.
    persist_dir: ?[]u8 = null,
    /// Set by the checkpoint thread's stop signal. The thread loops on a
    /// timed wait of `checkpoint_interval_ns` and exits when this flips.
    persist_should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    persist_thread: ?std.Thread = null,

    // ---- cmux execve self-handoff (Phase 2, GATED) ---------------------
    /// `<stateDir>` (parent of `persist_dir`). Owned; used for the re-exec
    /// manifest path and the append-only `reexec.log`. Set in daemonMain.
    state_dir: ?[]const u8 = null,
    /// True only when launched with `GHOSTTY_SSH_REEXEC=1`. The ENTIRE execve
    /// handoff path (reexec_query reply, --reexec handling) is inert unless set,
    /// so an ungated daemon always answers `REEXEC 0` and the client falls back
    /// to today's `--kill-daemon` + `--daemonize`.
    reexec_enabled: bool = false,
    reexec: ReexecControl = .{},

    /// Checkpoint cadence. 30s bounds scrollback loss on SIGKILL/OOM while
    /// keeping disk writes infrequent.
    const checkpoint_interval_ns: u64 = 30 * std.time.ns_per_s;

    /// TTL for the startup sweep: any group dir whose `group.meta` is older
    /// than this is deleted on boot so abandoned state can't grow unbounded.
    const persist_ttl_secs: i64 = 7 * 24 * 3600;

    fn deinit(self: *Daemon) void {
        for (self.groups.values()) |group| group.deinit();
        self.groups.deinit();
        self.channel_registry.deinit();
        closeFd(self.listener);
        std.fs.cwd().deleteFile(self.socket_path) catch {};
        self.alloc.free(self.socket_path);
        if (self.control_bridge_socket_path) |p| self.alloc.free(p);
        if (self.control_bridge_token) |t| self.alloc.free(t);
        // Free the bin-dir string only. Do NOT delete the dir — it is the
        // provisioned install dir holding the daemon binary (and the embedder
        // shim), which must persist across daemon generations.
        if (self.control_bridge_bin_dir) |d| self.alloc.free(d);
        // cmux scrollback persistence: free the path only. Do NOT delete the
        // on-disk state here — deinit runs on the graceful-restart path and we
        // WANT the snapshots to survive for the next daemon generation.
        if (self.persist_dir) |p| self.alloc.free(p);
        if (self.state_dir) |s| self.alloc.free(s);
    }

    /// Append one fsync'd diagnostic line to `<stateDir>/reexec.log`. No-op if
    /// the state dir is unknown. See `reexecLogTo`.
    fn reexecLog(self: *Daemon, comptime fmt: []const u8, args: anytype) void {
        const sd = self.state_dir orelse return;
        reexecLogTo(sd, fmt, args);
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
                // cmux scrollback persistence: if the requested group is not
                // in memory but a snapshot exists on disk (daemon restarted),
                // lazily reload it (group.meta + recreate). reloadGroupFromDisk
                // registers the group under self.mutex internally, so the
                // normal in-memory lookup below then finds it. No-op if no
                // group_id, no persisted state, or already in memory.
                if (!session.shared.isZeroUuid(open_data.group_id)) {
                    self.mutex.lock();
                    const in_mem = self.groups.contains(open_data.group_id);
                    self.mutex.unlock();
                    if (!in_mem) _ = self.reloadGroupFromDisk(open_data.group_id);
                }

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
                    const in_mem = group.surfaces.get(open_data.surface_id);
                    group.mutex.unlock();
                    if (in_mem) |s| break :blk s;
                    // cmux scrollback persistence: surface not in memory — try
                    // reloading it from disk (spawns a fresh shell with the
                    // restored scrollback). null on no persisted state.
                    break :blk self.reloadSurfaceFromDisk(group, open_data.surface_id, open_data.resize, open_data.max_scrollback);
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
                            // cmux scrollback persistence: first leaf not in
                            // memory — reload it from disk to preserve tab order.
                            if (self.reloadSurfaceFromDisk(group, first_id, open_data.resize, open_data.max_scrollback)) |r| {
                                break :blk r;
                            }
                        }
                    }
                    // Fall back to an arbitrary alive surface, and — when the
                    // group was only repopulated from disk by the startup index
                    // (no live surfaces yet, no usable layout) — to reloading
                    // the first detached on-disk surface so a bare attach after
                    // a daemon restart still lands on a real surface.
                    break :blk group.firstAliveSurface() orelse rb: {
                        group.mutex.lock();
                        const first: ?Uuid = if (group.detached_surfaces.count() > 0)
                            group.detached_surfaces.keys()[0]
                        else
                            null;
                        group.mutex.unlock();
                        break :rb if (first) |fid|
                            self.reloadSurfaceFromDisk(group, fid, open_data.resize, open_data.max_scrollback)
                        else
                            null;
                    };
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
        const in_mem_group = self.groups.get(open_data.group_id);
        self.mutex.unlock();

        // cmux scrollback persistence: the group may only exist on disk after
        // a daemon restart. Try a lazy reload before failing.
        const group = in_mem_group orelse
            self.reloadGroupFromDisk(open_data.group_id) orelse {
                sendFrameFd(fd, .err, target, "group not found") catch {};
                return;
            };

        switch (open_data.open_type) {
            .surface_new => {
                const sess = try self.createSurface(group, open_data.surface_id, open_data.resize, open_data.max_scrollback);
                self.sendOpenedResponse(fd, target, group, open_data.surface_id, 0, null);
                sess.attachAndServe(fd, target, open_data) catch {};
                self.cleanupDetachedSurface(group, sess, open_data.surface_id);
            },
            .surface_attach => {
                group.mutex.lock();
                const in_mem_sess = group.surfaces.get(open_data.surface_id);
                group.mutex.unlock();

                // cmux scrollback persistence: reload the surface from disk
                // (fresh shell + restored scrollback) on an in-memory miss.
                const sess = in_mem_sess orelse
                    self.reloadSurfaceFromDisk(group, open_data.surface_id, open_data.resize, open_data.max_scrollback);

                if (sess) |s| {
                    // Compute history rows for the attached surface
                    s.mutex.lock();
                    const surf_history = s.computeHistoryRows();
                    s.mutex.unlock();

                    self.sendOpenedResponse(fd, target, group, open_data.surface_id, surf_history, null);
                    s.attachAndServe(fd, target, open_data) catch {};
                    self.cleanupDetachedSurface(group, s, open_data.surface_id);
                } else {
                    daemonLog("VANISH surface-attach-miss group={s} surface={s} target={d}", .{ &session.shared.formatUuid(open_data.group_id), &session.shared.formatUuid(open_data.surface_id), target }); // TEMP(cmux-vanish-probe)
                    sendFrameFd(fd, .eof, target, "") catch {};
                }
            },
            else => unreachable, // session types handled in handleSessionOpen
        }
    }

    /// Unified close handler. Dispatches based on Close.mode.
    fn handleClose(self: *Daemon, close_data: session.protocol.Close) void {
        daemonLog("VANISH handleClose mode={s} id={s}", .{ @tagName(close_data.mode), &session.shared.formatUuid(close_data.id) }); // TEMP(cmux-vanish-probe)
        switch (close_data.mode) {
            .surface => {
                self.mutex.lock();
                defer self.mutex.unlock();

                for (self.groups.values()) |group| {
                    group.mutex.lock();
                    if (group.surfaces.get(close_data.id)) |sess| {
                        sess.kill();
                        _ = group.surfaces.orderedRemove(close_data.id);
                        // Keep the id-set disjoint (no-op for a live surface,
                        // which is never in detached_surfaces by invariant).
                        _ = group.detached_surfaces.swapRemove(close_data.id);
                        const gid = group.id;
                        group.mutex.unlock();
                        // cmux scrollback persistence: explicit close removes
                        // the on-disk snapshot so it can't be reloaded later.
                        self.deletePersistedSurface(gid, close_data.id);
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
                    // Session close wipes the whole group: drop the on-disk
                    // surface id-set too so maybeRemoveEmptyGroup reaps it.
                    group.detached_surfaces.clearRetainingCapacity();
                    group.mutex.unlock();
                    // cmux scrollback persistence: explicit session close wipes
                    // the whole group's on-disk state.
                    self.deletePersistedGroup(close_data.id);
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
            // Surfaces persisted on disk but not yet reloaded this generation.
            // They are reattachable (reload-on-attach respawns them), so they
            // count toward both the total and the "alive/reattachable" tally.
            const detached_disk = group.detached_surfaces.count();
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

            const total_surfaces = surface_count + detached_disk;
            const reattachable = alive_count + detached_disk;

            const status: session.protocol.ListStatus = if (attached_count > 0)
                .attached
            else if (reattachable > 0)
                .detached
            else
                .dead;

            entries.append(self.alloc, .{
                .group_id = group.id,
                .status = status,
                .surface_count = @intCast(total_surfaces),
                .alive_count = @intCast(reattachable),
                .created_at = created_at,
                .session_color = group.color,
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
        // A group is only truly empty when it has NO live surfaces AND no
        // surfaces still persisted on disk. Gating on `surfaces` alone would
        // reap (and `deletePersistedGroup`) a group whose last *live* surface
        // closed while other surfaces remain reloadable on disk — wiping their
        // `.term` files. (cmux: detached_surfaces are reattachable.)
        const is_empty = group.surfaces.count() == 0 and group.detached_surfaces.count() == 0;
        group.mutex.unlock();
        if (!is_empty) return;

        log.info("group {s} is empty, removing immediately", .{group.label});
        const gid = group.id;
        _ = self.groups.swapRemove(group.id);
        group.deinit();
        // cmux scrollback persistence: an emptied group leaves no reloadable
        // surfaces — drop its on-disk state too (bounds disk growth).
        self.deletePersistedGroup(gid);
    }

    /// If the session was closed by the client, kill its process and remove
    /// it from the group. Removes the group entirely if it becomes empty.
    fn cleanupDetachedSurface(self: *Daemon, group: *SessionGroup, sess: *RemoteSession, surface_id: Uuid) void {
        if (!sess.closed) return;
        daemonLog("VANISH cleanup-kill surface={s} group={s}", .{ &session.shared.formatUuid(surface_id), &session.shared.formatUuid(group.id) }); // TEMP(cmux-vanish-probe)
        sess.kill();
        self.mutex.lock();
        group.mutex.lock();
        const gid = group.id;
        _ = group.surfaces.orderedRemove(surface_id);
        // Keep the id-set disjoint (no-op for a live surface by invariant).
        _ = group.detached_surfaces.swapRemove(surface_id);
        group.mutex.unlock();
        // cmux scrollback persistence: a client-closed surface should not be
        // reloadable; drop its on-disk snapshot. maybeRemoveEmptyGroup below
        // additionally drops the whole group dir if it becomes empty.
        self.deletePersistedSurface(gid, surface_id);
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
            .detached_surfaces = std.AutoArrayHashMap(Uuid, void).init(self.alloc),
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
        return self.createSurfaceInner(group, surface_id, resize, max_scrollback, null);
    }

    /// Shared surface-creation path. When `restore_snapshot` is non-null the
    /// new Terminal is rebuilt from it (cmux scrollback reload) instead of a
    /// blank terminal; everything else — fresh PTY + shell spawn, reader
    /// thread, group registration — is identical to a live create. The old
    /// shell PID is dead after a daemon restart, so we always spawn a NEW
    /// shell and restore only scrollback/viewport.
    fn createSurfaceInner(
        self: *Daemon,
        group: *SessionGroup,
        surface_id: Uuid,
        resize: session.protocol.Resize,
        max_scrollback: u32,
        restore_snapshot: ?*persist.Snapshot,
    ) !*RemoteSession {
        // cmux execve self-handoff (GATED): refuse new surface creation while
        // the daemon is quiescing for a handoff so the manifest's surface set
        // is stable and no half-built shell races the execve. Inert unless
        // GHOSTTY_SSH_REEXEC=1 (in_progress is never set otherwise).
        if (self.reexec.in_progress.load(.acquire)) return error.ReexecInProgress;

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

        // Reverse control channel: point the remote control CLI at the
        // per-daemon AF_UNIX socket the `control_bridge` listener binds, and
        // hand it the per-daemon auth token it must present on that socket
        // (the daemon enforces the token before forwarding any line to the
        // client). The env var names come from `control_bridge_config` (one
        // source of truth shared with the remote forwarder); without these the
        // remote control CLI has nowhere to connect.
        const bridge_cfg = session.control_bridge_config;
        if (self.control_bridge_socket_path) |sock_path| {
            try env.put(bridge_cfg.env_socket_path, sock_path);
        }
        if (self.control_bridge_token) |token| {
            try env.put(bridge_cfg.env_socket_token, token);
        }

        // Prepend the remote bin dir to PATH so `ghostty-daemon` and any
        // embedder-installed shim resolve by name. Preserve the inherited PATH;
        // if it was unset, fall back to a sane default so basic tools still work.
        if (self.control_bridge_bin_dir) |shim_dir| {
            if (env.get("PATH")) |existing| {
                const new_path = try std.fmt.allocPrint(
                    self.alloc,
                    "{s}:{s}",
                    .{ shim_dir, existing },
                );
                defer self.alloc.free(new_path);
                try env.put("PATH", new_path);
            } else {
                const new_path = try std.fmt.allocPrint(
                    self.alloc,
                    "{s}:/usr/local/bin:/usr/bin:/bin",
                    .{shim_dir},
                );
                defer self.alloc.free(new_path);
                try env.put("PATH", new_path);
            }
        }

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

        var t = if (restore_snapshot) |snap|
            // cmux scrollback reload: rebuild from the persisted snapshot
            // (viewport replayed + scrollback chunks applied). Falls back to a
            // blank terminal at the requested size on any restore failure.
            persist.restore(self.alloc, snap.*, resize.cols, resize.rows) catch
                try terminal.Terminal.init(self.alloc, .{
                    .cols = resize.cols,
                    .rows = resize.rows,
                    .max_scrollback = if (max_scrollback > 0) max_scrollback else 10_000_000,
                })
        else
            try terminal.Terminal.init(self.alloc, .{
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
            .max_scrollback = if (max_scrollback > 0) max_scrollback else 10_000_000,
            // cmux execve self-handoff: reader threads observe this to park
            // during a handoff. Inert unless GHOSTTY_SSH_REEXEC=1.
            .reexec = &self.reexec,
        };

        sess.stream = .init(.{
            .alloc = self.alloc,
            .terminal = &sess.terminal_instance,
            .pty_fd = pty.master,
        });

        // Register the surface AND start its reader atomically under
        // group.mutex. Checking membership here (instead of a plain `put`)
        // makes reload-on-attach race-safe: if a concurrent attach already
        // reloaded this surface_id, we tear down the loser — which has no
        // reader thread yet, so `deinit` is safe — and return the winner.
        // (Live `surface_new` callers pass fresh ids and never collide.)
        //
        // group.mutex is held across the reader spawn, which is deadlock-free:
        // readerMain only ever locks the per-session mutex, never group.mutex
        // (updateLabel/updateLayout run on the client-frame path, not the
        // reader path), so the global order group.mutex → sess.mutex holds.
        group.mutex.lock();
        // Reserve first so the insert below is infallible and cannot trip the
        // errdefers above after `sess` is committed to the map.
        group.surfaces.ensureUnusedCapacity(1) catch {
            group.mutex.unlock();
            return error.OutOfMemory; // sess has no reader yet → errdefers clean up
        };
        const gop = group.surfaces.getOrPutAssumeCapacity(surface_id);
        if (gop.found_existing) {
            const existing = gop.value_ptr.*;
            group.mutex.unlock();
            // Lost the race. Tear down our just-built (reader-less) session.
            // A SUCCESS return ⇒ the errdefers above do NOT fire (no double free).
            sess.kill();
            sess.deinit();
            return existing;
        }
        gop.value_ptr.* = sess;
        // Invariant: a live surface is never also "detached on disk".
        _ = group.detached_surfaces.swapRemove(surface_id);

        sess.reader_thread = std.Thread.spawn(.{}, RemoteSession.readerMain, .{sess}) catch |err| {
            // Essentially OOM-only. Un-register and return the error so the
            // errdefers above tear `sess` down exactly once (no reader started).
            _ = group.surfaces.swapRemove(surface_id);
            group.mutex.unlock();
            return err;
        };
        sess.reader_thread.detach();
        group.mutex.unlock();

        return sess;
    }

    // ====================================================================
    // cmux scrollback persistence (first cut): checkpoint + reload
    // ====================================================================

    /// Background checkpoint loop. Wakes every `checkpoint_interval_ns`,
    /// snapshots every changed surface to disk, and exits when
    /// `persist_should_stop` flips. Spawned only when persistence is enabled.
    fn checkpointLoop(self: *Daemon) void {
        while (!self.persist_should_stop.load(.acquire)) {
            // Sleep in small slices so a stop request is observed promptly.
            var slept: u64 = 0;
            const slice: u64 = 500 * std.time.ns_per_ms;
            while (slept < checkpoint_interval_ns) : (slept += slice) {
                if (self.persist_should_stop.load(.acquire)) return;
                std.Thread.sleep(slice);
            }
            self.checkpointAll();
        }
    }

    /// Snapshot every changed surface to disk. Safe to call from the
    /// checkpoint thread and from the graceful-shutdown path. Disk I/O
    /// happens OUTSIDE the per-session mutex so it never blocks `readerMain`.
    fn checkpointAll(self: *Daemon) void {
        const persist_dir = self.persist_dir orelse return;

        // Snapshot the group pointers under daemon.mutex, then release it so
        // we don't hold it across disk I/O.
        var group_buf: [256]*SessionGroup = undefined;
        var group_count: usize = 0;
        self.mutex.lock();
        for (self.groups.values()) |g| {
            if (group_count >= group_buf.len) break;
            group_buf[group_count] = g;
            group_count += 1;
        }
        self.mutex.unlock();

        for (group_buf[0..group_count]) |group| {
            self.checkpointGroup(persist_dir, group);
        }
    }

    /// Checkpoint one group: writes group.meta plus each changed surface.
    fn checkpointGroup(self: *Daemon, persist_dir: []const u8, group: *SessionGroup) void {
        // Build the per-group dir path: <persist_dir>/<group_hex>.
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group.id) catch return;
        defer self.alloc.free(group_dir);

        // Snapshot surface pointers + group meta under group.mutex.
        var surf_buf: [256]*RemoteSession = undefined;
        var surf_count: usize = 0;
        group.mutex.lock();
        const color = group.color;
        const created_at = group.created_at;
        const label_copy = self.alloc.dupe(u8, group.label) catch null;
        const layout_copy: ?[]u8 = if (group.layout_blob) |b| (self.alloc.dupe(u8, b) catch null) else null;
        for (group.surfaces.values()) |s| {
            if (surf_count >= surf_buf.len) break;
            surf_buf[surf_count] = s;
            surf_count += 1;
        }
        group.mutex.unlock();
        defer if (label_copy) |l| self.alloc.free(l);
        defer if (layout_copy) |l| self.alloc.free(l);

        if (label_copy) |label| {
            persist.writeGroupMeta(self.alloc, group_dir, color, created_at, label, layout_copy) catch |err| {
                daemonLog("persist: writeGroupMeta failed group={s} err={}", .{ &session.shared.formatUuid(group.id), err });
            };
        }

        for (surf_buf[0..surf_count]) |sess| {
            self.checkpointSurface(group_dir, sess);
        }
    }

    /// Checkpoint a single surface if it changed since its last snapshot.
    /// Captures under the session mutex (mandatory — readerMain mutates the
    /// terminal), then writes to disk after releasing the mutex.
    fn checkpointSurface(self: *Daemon, group_dir: []const u8, sess: *RemoteSession) void {
        sess.mutex.lock();
        if (sess.dirty_seq == sess.checkpointed_seq) {
            sess.mutex.unlock();
            return;
        }
        const seq = sess.dirty_seq;
        var snap = persist.capture(self.alloc, &sess.terminal_instance, sess.max_scrollback) catch {
            sess.mutex.unlock();
            return;
        };
        const surface_id = sess.surface_id;
        sess.mutex.unlock();
        defer snap.deinit(self.alloc);

        const hex = session.shared.formatUuid(surface_id);
        persist.writeTermFile(self.alloc, group_dir, &hex, snap) catch |err| {
            daemonLog("persist: writeTermFile failed err={}", .{err});
            return;
        };
        // Only advance the persisted seq after a successful write.
        sess.checkpointed_seq = seq;
    }

    /// Startup index: scan `<persist_dir>/state` once on boot and repopulate
    /// `self.groups` with every persisted group as a metadata-only entry whose
    /// surfaces live in `detached_surfaces` (NOT spawned). This makes
    /// `+ssh-session --list`, the session chooser, and the tab layout survive
    /// a daemon restart BEFORE any client attaches; the first attach then
    /// lazily reloads each surface (fresh shell + restored scrollback) via the
    /// existing reload-on-attach path, which moves the id out of
    /// `detached_surfaces` into `surfaces`.
    ///
    /// MUST be called single-threaded during `daemonMain` startup — before the
    /// checkpoint thread spawns and before the accept loop — so no locking
    /// races exist. (Locks are still taken for uniformity.) Spawns NO shells:
    /// it only calls `createGroupLocked` + populates the id-set.
    fn loadPersistedGroupsOnStartup(self: *Daemon) void {
        const persist_dir = self.persist_dir orelse return;

        // Drop abandoned state first so it isn't indexed (or swept later).
        persist.sweepExpiredGroups(self.alloc, persist_dir, persist_ttl_secs);

        const infos = persist.scanPersistedGroups(self.alloc, persist_dir) catch |err| {
            daemonLog("persist-startup: scan failed err={}", .{err});
            return;
        };
        defer {
            for (infos) |*gi| gi.deinit(self.alloc);
            self.alloc.free(infos);
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var loaded: usize = 0;
        for (infos) |gi| {
            const group = self.groups.get(gi.group_id) orelse
                (self.createGroupLocked(gi.label, gi.group_id) catch continue);

            group.mutex.lock();
            // Only seed metadata onto a freshly-created (still-empty) group so
            // we never clobber a group an earlier pass already populated.
            if (group.surfaces.count() == 0) {
                group.color = gi.color;
                group.created_at = gi.created_at;
                if (group.layout_blob == null) {
                    if (gi.layout_blob) |b| group.layout_blob = self.alloc.dupe(u8, b) catch null;
                }
            }
            for (gi.surface_ids) |sid| {
                if (!group.surfaces.contains(sid)) group.detached_surfaces.put(sid, {}) catch {};
            }
            group.mutex.unlock();
            loaded += 1;
        }

        daemonLog("persist-startup: scanned={d} loaded_groups={d}", .{ infos.len, loaded });
    }

    /// Reload a group from disk on attach-miss. Returns the recreated group
    /// (registered in self.groups, with its surfaces reloaded) or null if no
    /// persisted state exists. Caller must NOT hold self.mutex.
    fn reloadGroupFromDisk(self: *Daemon, group_id: Uuid) ?*SessionGroup {
        const persist_dir = self.persist_dir orelse return null;
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group_id) catch return null;
        defer self.alloc.free(group_dir);

        var meta = (persist.readGroupMeta(self.alloc, group_dir) catch return null) orelse return null;
        defer meta.deinit(self.alloc);

        self.mutex.lock();
        defer self.mutex.unlock();
        // Race guard: a concurrent attach may have already created/reloaded it.
        if (self.groups.get(group_id)) |existing| return existing;

        const group = self.createGroupLocked(meta.label, group_id) catch return null;
        group.mutex.lock();
        group.color = meta.color;
        group.created_at = meta.created_at;
        if (meta.layout_blob) |blob| {
            group.layout_blob = self.alloc.dupe(u8, blob) catch null;
        }
        group.mutex.unlock();
        return group;
    }

    /// Reload a single surface from disk into an existing group on
    /// attach-miss. Spawns a FRESH PTY+shell with the restored scrollback.
    /// Returns the new RemoteSession or null if no persisted surface exists.
    fn reloadSurfaceFromDisk(
        self: *Daemon,
        group: *SessionGroup,
        surface_id: Uuid,
        resize: session.protocol.Resize,
        max_scrollback: u32,
    ) ?*RemoteSession {
        const persist_dir = self.persist_dir orelse return null;
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group.id) catch return null;
        defer self.alloc.free(group_dir);

        const hex = session.shared.formatUuid(surface_id);
        var snap = (persist.readTermFile(self.alloc, group_dir, &hex) catch null) orelse {
            // Missing or undecodable `.term` (e.g. a term_format_version bump):
            // the id is a stale ghost. Drop it from the detached id-set so
            // `--list` counts stay honest and we don't keep retrying it.
            group.mutex.lock();
            _ = group.detached_surfaces.swapRemove(surface_id);
            group.mutex.unlock();
            return null;
        };
        defer snap.deinit(self.alloc);

        const eff_max = if (max_scrollback > 0) max_scrollback else snap.max_scrollback;
        const sess = self.createSurfaceInner(group, surface_id, resize, eff_max, &snap) catch return null;
        // The reloaded terminal already reflects the on-disk snapshot; mark it
        // as checkpointed so we don't immediately rewrite an identical file.
        sess.checkpointed_seq = sess.dirty_seq;
        return sess;
    }

    /// Delete a single surface's persisted `.term` file (explicit surface
    /// close). Bounds disk growth and prevents reloadable ghosts.
    fn deletePersistedSurface(self: *Daemon, group_id: Uuid, surface_id: Uuid) void {
        const persist_dir = self.persist_dir orelse return;
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group_id) catch return;
        defer self.alloc.free(group_dir);
        const hex = session.shared.formatUuid(surface_id);
        persist.deleteTermFile(self.alloc, group_dir, &hex);
    }

    /// Delete an entire group's persisted state dir (session close / empty
    /// group reap).
    fn deletePersistedGroup(self: *Daemon, group_id: Uuid) void {
        const persist_dir = self.persist_dir orelse return;
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group_id) catch return;
        defer self.alloc.free(group_dir);
        persist.deleteGroupDir(group_dir);
    }

    // ====================================================================
    // cmux execve self-handoff (Phase 2, GATED behind GHOSTTY_SSH_REEXEC)
    //
    // Same-PID `execve` keeps every child shell + PTY master alive across a
    // binary update. The OLD image quiesces (parks readers, blocks new
    // creates), checkpoints scrollback, writes a handoff manifest, clears
    // CLOEXEC on the carry-set, and execve's into the new binary. The NEW
    // image (daemonMain branch above + adoptReexecSurfaces below) re-wires the
    // inherited fds into fresh RemoteSessions. Failable-first ordering: every
    // catastrophic branch before the execve rolls back to today's behavior.
    // ====================================================================

    /// Wait for every reader thread to PARK (active_readers == 0), polling in
    /// small slices up to `timeout_ms`. Returns true iff it reached zero.
    fn waitActiveReadersZeroOrTimeout(self: *Daemon, timeout_ms: u64) bool {
        var waited: u64 = 0;
        const slice: u64 = 5;
        while (waited < timeout_ms) : (waited += slice) {
            if (self.reexec.active_readers.load(.acquire) == 0) return true;
            std.Thread.sleep(slice * std.time.ns_per_ms);
        }
        return self.reexec.active_readers.load(.acquire) == 0;
    }

    /// Roll back a failed handoff: un-park readers, drop the half-written
    /// manifest, restart the checkpoint thread, send `.err`. Does NOT touch
    /// CLOEXEC — the execve-fail path re-sets it on the carry-set first.
    fn abortReexec(self: *Daemon, fd: posix.fd_t, reason: []const u8) void {
        self.reexec.in_progress.store(false, .release); // un-parks readers
        if (self.state_dir) |sd| persist.deleteReexecManifest(self.alloc, sd);
        if (self.persist_dir != null and self.persist_thread == null) {
            self.persist_should_stop.store(false, .release);
            self.persist_thread = std.Thread.spawn(.{}, Daemon.checkpointLoop, .{self}) catch null;
        }
        self.reexecLog("ABORT done reason={s}", .{reason});
        sendFrameFd(fd, .err, 0, reason) catch {};
    }

    /// Collect every ALIVE surface into the manifest input list. Each entry
    /// owns a freshly-dup'd label + a version-stable viewport-VT capture (same
    /// serializer the reload path replays). Caller frees label/viewport.
    fn collectReexecSurfaces(self: *Daemon, out: *std.ArrayList(persist.ReexecSurface)) void {
        var group_buf: [256]*SessionGroup = undefined;
        var gcount: usize = 0;
        self.mutex.lock();
        for (self.groups.values()) |g| {
            if (gcount >= group_buf.len) break;
            group_buf[gcount] = g;
            gcount += 1;
        }
        self.mutex.unlock();

        for (group_buf[0..gcount]) |group| {
            group.mutex.lock();
            defer group.mutex.unlock();
            const gid = group.id;
            for (group.surfaces.values()) |sess| {
                sess.mutex.lock();
                defer sess.mutex.unlock();
                if (!sess.alive) continue;
                const pid = sess.command.pid orelse continue;
                const vp = session.remote_session.serializeViewportAsVT(self.alloc, &sess.terminal_instance) catch (self.alloc.alloc(u8, 0) catch continue);
                const lbl = self.alloc.dupe(u8, sess.label) catch (self.alloc.alloc(u8, 0) catch {
                    self.alloc.free(vp);
                    continue;
                });
                out.append(self.alloc, .{
                    .group_id = gid,
                    .surface_id = sess.surface_id,
                    .pty_master_fd = sess.pty.master,
                    .child_pid = pid,
                    .cols = sess.terminal_instance.cols,
                    .rows = sess.terminal_instance.rows,
                    .xpix = 0,
                    .ypix = 0,
                    .max_scrollback = sess.max_scrollback,
                    .size_mode = @intFromEnum(sess.size_mode),
                    .label = lbl,
                    .viewport = vp,
                }) catch {
                    self.alloc.free(vp);
                    self.alloc.free(lbl);
                };
            }
        }
    }

    /// Handle a `.reexec` request. Returns ONLY on failure (after `.err` +
    /// rollback). On success `execve` replaces the whole process.
    fn handleReexec(self: *Daemon, fd: posix.fd_t, newbin: []const u8) void {
        self.reexecLog("req newbin={s} gate={} live_groups={d}", .{ newbin, self.reexec_enabled, self.groups.count() });

        const state_dir = self.state_dir orelse {
            sendFrameFd(fd, .err, 0, "reexec: no state dir") catch {};
            return;
        };
        const newbinZ = self.alloc.dupeZ(u8, newbin) catch {
            sendFrameFd(fd, .err, 0, "reexec: oom") catch {};
            return;
        };
        defer self.alloc.free(newbinZ);

        // STEP 6 (pre-flight, BEFORE any quiescing — fully reversible): the new
        // binary must exist, be executable, and carry a native exec header.
        if (!preflightNewBinary(newbinZ)) {
            self.reexecLog("ABORT step=preflight newbin={s}", .{newbin});
            sendFrameFd(fd, .err, 0, "reexec: new binary pre-flight failed") catch {};
            return;
        }
        self.reexecLog("preflight newbin ok", .{});

        // STEP 1: claim the handoff + block NEW surface creation + tell readers
        // to drain/park. GAP A: use a compare-and-swap so a SECOND concurrent
        // `--reexec` (e.g. two cmux windows updating the same host at once) is
        // rejected here instead of racing this thread into the persist-thread
        // `join()` below — two threads joining the same std.Thread is a
        // double-consume crash. Only the CAS winner proceeds; abortReexec /
        // execve release the claim.
        if (self.reexec.in_progress.cmpxchgStrong(false, true, .seq_cst, .seq_cst) != null) {
            self.reexecLog("ABORT step=concurrent-reexec", .{});
            sendFrameFd(fd, .err, 0, "reexec: another handoff already in progress") catch {};
            return;
        }

        // STEP 2: wait for readers to park (active_readers==0), cap ~500ms.
        const parked = self.waitActiveReadersZeroOrTimeout(500);
        self.reexecLog("parked readers ok={} active={d}", .{ parked, self.reexec.active_readers.load(.acquire) });

        // STEP 3: stop + join the checkpoint thread so it can't race step 4/5.
        self.persist_should_stop.store(true, .release);
        if (self.persist_thread) |t| {
            t.join();
            self.persist_thread = null;
        }
        self.reexecLog("checkpoint-thread stopped", .{});

        // STEP 4: final checkpoint of every surface (refresh .term + group.meta).
        self.checkpointAll();
        self.reexecLog("checkpointAll done", .{});

        // STEP 5: build the manifest surface list (alive only, version-stable
        // viewport captured under each sess.mutex while readers are parked).
        var surfaces = std.ArrayList(persist.ReexecSurface).empty;
        defer {
            for (surfaces.items) |*s| {
                self.alloc.free(s.label);
                self.alloc.free(s.viewport);
            }
            surfaces.deinit(self.alloc);
        }
        self.collectReexecSurfaces(&surfaces);

        var nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        const nonce_hex = std.fmt.bytesToHex(nonce, .lower);

        // STEP 7: write + fsync the manifest atomically. Failure → abort (still
        // trivially reversible: readers parked, CLOEXEC intact).
        persist.writeReexecManifest(self.alloc, state_dir, .{
            .writer_pid = @intCast(c.getpid()),
            .nonce = nonce,
            .listener_fd = self.listener,
            .ctl_sock = self.control_bridge_socket_path,
            .ctl_tok = self.control_bridge_token,
            .surfaces = surfaces.items,
        }) catch |err| {
            self.reexecLog("ABORT step=manifest err={}", .{err});
            self.abortReexec(fd, "reexec: manifest write failed");
            return;
        };
        self.reexecLog("manifest written surfaces={d} nonce={s}", .{ surfaces.items.len, &nonce_hex });

        // STEP 8: CLOEXEC flip — LAST mutating step. Force CLOEXEC on ALL fds,
        // then clear it ONLY on the carry-set (listener + each alive master).
        var master_buf: [512]posix.fd_t = undefined;
        var master_count: usize = 0;
        for (surfaces.items) |s| {
            if (master_count >= master_buf.len) break;
            master_buf[master_count] = s.pty_master_fd;
            master_count += 1;
        }
        flipCloexecForReexec(self.listener, master_buf[0..master_count]);
        self.reexecLog("CLOEXEC cleared listener_fd={d} masters={d}", .{ self.listener, master_count });

        // STEP 9: execve SAME PID into `<newbin> +ssh-session --daemon`. Export
        // the nonce (NOT the path) so the successor validates the inherited
        // manifest. `--daemon` (not `--daemonize`): no re-double-fork, no
        // closeAllFds — we stay in this process image.
        var nonce_hexZ: [33]u8 = undefined;
        @memcpy(nonce_hexZ[0..32], &nonce_hex);
        nonce_hexZ[32] = 0;
        _ = c.setenv("GHOSTTY_DAEMON_REEXEC", &nonce_hexZ, 1);
        self.reexecLog("execve newbin={s} argv=[+ssh-session --daemon]", .{newbin});

        const sub: [:0]const u8 = session.shared.remote_subcommand;
        const flag: [:0]const u8 = "--daemon";
        const argv = [_:null]?[*:0]const u8{ newbinZ.ptr, sub.ptr, flag.ptr };
        const exec_err = std.posix.execveZ(newbinZ.ptr, &argv, std.c.environ);

        // execveZ returns ONLY on failure. Re-set CLOEXEC on the carry-set so
        // the cleared listener/masters don't leak into a later legit fork, then
        // roll back fully (the client's `.err` → exit 1 → --kill-daemon net).
        self.reexecLog("execve FAILED err={} — ABORT (CLOEXEC reset, readers resumed, checkpoint restarted)", .{exec_err});
        forceCloexecOnFds(self.listener, master_buf[0..master_count]);
        self.abortReexec(fd, "reexec: execve failed");
    }

    /// Re-derive `detached_surfaces` = (on-disk *.term) \ (live surfaces) for a
    /// group. Used after adoption so a surface that FAILED adoption is still
    /// visible (and reattachable) as detached. Caller holds self.mutex (NOT
    /// group.mutex).
    fn reconcileDetachedSurfacesLocked(self: *Daemon, group: *SessionGroup) void {
        const persist_dir = self.persist_dir orelse return;
        const group_dir = session.shared.groupPersistDir(self.alloc, persist_dir, group.id) catch return;
        defer self.alloc.free(group_dir);
        const ids = persist.listSurfaceIds(self.alloc, group_dir) catch return;
        defer self.alloc.free(ids);
        group.mutex.lock();
        defer group.mutex.unlock();
        group.detached_surfaces.clearRetainingCapacity();
        for (ids) |sid| {
            if (group.surfaces.contains(sid)) continue;
            group.detached_surfaces.put(sid, {}) catch {};
        }
    }

    /// Adopt every alive surface from the handoff manifest. Single-threaded
    /// boot context (no clients, no checkpoint thread yet).
    fn adoptReexecSurfaces(self: *Daemon, m: *persist.ReexecManifest) void {
        const state_dir = self.state_dir orelse "";

        // Restore the control-bridge identity so reconnecting mux clients reach
        // the SAME reverse-channel socket/token the live shells were told about.
        if (m.ctl_sock) |s| {
            const dup = self.alloc.dupe(u8, s) catch null;
            if (dup) |d| {
                if (self.control_bridge_socket_path) |old| self.alloc.free(old);
                self.control_bridge_socket_path = d;
            }
        }
        if (m.ctl_tok) |t| {
            const dup = self.alloc.dupe(u8, t) catch null;
            if (dup) |d| {
                if (self.control_bridge_token) |old| self.alloc.free(old);
                self.control_bridge_token = d;
            }
        }

        var adopted: usize = 0;
        var skipped: usize = 0;
        for (m.surfaces) |surf| {
            const group = blk: {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.groups.get(surf.group_id)) |g| break :blk g;
                // No startup-index entry (persist disabled or meta gone): create
                // a placeholder-labelled group so the shell still lives.
                break :blk self.createGroupLocked("session", surf.group_id) catch null;
            } orelse {
                closeFd(surf.pty_master_fd);
                skipped += 1;
                continue;
            };

            if (self.adoptSurface(group, surf)) |_| {
                adopted += 1;
            } else |err| {
                // adoptSurface already closed the inherited master on failure.
                reexecLogTo(state_dir, "adopt: surface={s} FAILED err={} — degraded to reload-on-attach", .{ &session.shared.formatUuid(surf.surface_id), err });
                skipped += 1;
            }
        }

        // Make on-disk-but-unadopted surfaces visible as detached for --list.
        self.mutex.lock();
        for (self.groups.values()) |g| self.reconcileDetachedSurfacesLocked(g);
        self.mutex.unlock();

        reexecLogTo(state_dir, "adopt: done adopted={d} skipped={d}", .{ adopted, skipped });
    }

    /// Rebuild a surface's emulator for adoption: prefer the on-disk `.term`
    /// (full scrollback + viewport); on miss / term_format_version bump, fall
    /// back to the manifest's version-stable viewport only (shell lives,
    /// scrollback dropped); last resort a blank terminal.
    fn restoreAdoptedTerminal(self: *Daemon, group_id: Uuid, m: persist.ReexecSurface) ?terminal.Terminal {
        if (self.persist_dir) |pdir| {
            if (session.shared.groupPersistDir(self.alloc, pdir, group_id) catch null) |gdir| {
                defer self.alloc.free(gdir);
                const hex = session.shared.formatUuid(m.surface_id);
                if (persist.readTermFile(self.alloc, gdir, &hex) catch null) |disk| {
                    var s = disk;
                    defer s.deinit(self.alloc);
                    if (persist.restore(self.alloc, s, m.cols, m.rows)) |t| return t else |_| {}
                }
            }
        }
        // Manifest viewport-only fallback (borrowed bytes; restore never frees).
        var empty_sb = [_]u8{};
        var empty_cr = [_]persist.ChunkRef{};
        const snap = persist.Snapshot{
            .cols = m.cols,
            .rows = m.rows,
            .max_scrollback = if (m.max_scrollback > 0) m.max_scrollback else 10_000_000,
            .history_rows = 0,
            .viewport = m.viewport,
            .scrollback = &empty_sb,
            .chunk_index = &empty_cr,
        };
        if (persist.restore(self.alloc, snap, m.cols, m.rows)) |t| return t else |_| {}
        return terminal.Terminal.init(self.alloc, .{
            .cols = if (m.cols > 0) m.cols else 80,
            .rows = if (m.rows > 0) m.rows else 24,
            .max_scrollback = if (m.max_scrollback > 0) m.max_scrollback else 10_000_000,
        }) catch null;
    }

    /// Re-wire one inherited PTY master + child pid into a fresh RemoteSession
    /// (NO fork, NO Pty.open, NO command.start). On any failure the inherited
    /// master fd is closed and an error is returned (caller degrades that one
    /// surface to reload-on-attach). Mirrors `createSurfaceInner`'s registration.
    fn adoptSurface(self: *Daemon, group: *SessionGroup, m: persist.ReexecSurface) !*RemoteSession {
        // The inherited fd MUST still be a PTY master (TIOCGWINSZ succeeds).
        if (!fdIsPtyMaster(m.pty_master_fd)) {
            if (self.state_dir) |sd| reexecLogTo(sd, "adopt: surface={s} master_fd={d} fstat=SKIP(not a pty)", .{ &session.shared.formatUuid(m.surface_id), m.pty_master_fd });
            if (m.pty_master_fd >= 0) closeFd(m.pty_master_fd);
            return error.NotAPtyMaster;
        }
        errdefer closeFd(m.pty_master_fd);

        const label = try self.alloc.dupe(u8, group.label);
        errdefer self.alloc.free(label);
        const id = try session.shared.generateSessionId(self.alloc);
        errdefer self.alloc.free(id);

        var t = self.restoreAdoptedTerminal(group.id, m) orelse return error.RestoreFailed;
        errdefer t.deinit(self.alloc);

        // Synthetic Command — only `.pid` is needed by `command.wait`; path/args
        // are placeholders freed by RemoteSession.deinit. The adopted child is
        // still OUR child across execve (same pid), so waitpid works.
        const command_path = try self.alloc.dupeZ(u8, "(adopted)");
        errdefer self.alloc.free(command_path);
        const command_args = try self.alloc.alloc([:0]const u8, 1);
        errdefer self.alloc.free(command_args);
        command_args[0] = command_path;

        const sess = try self.alloc.create(RemoteSession);
        errdefer self.alloc.destroy(sess);
        sess.* = .{
            .alloc = self.alloc,
            .id = id,
            .label = label,
            .surface_id = m.surface_id,
            .pty = .{ .master = m.pty_master_fd, .slave = -1 },
            .command = .{
                .path = command_path,
                .args = command_args,
                .os_pre_exec = null,
                .rt_pre_exec = null,
                .rt_pre_exec_info = std.mem.zeroInit(Command.RtPreExecInfo, .{}),
                .rt_post_fork = null,
                .rt_post_fork_info = std.mem.zeroInit(Command.RtPostForkInfo, .{}),
                .pid = m.child_pid,
            },
            .terminal_instance = t,
            .stream = undefined,
            .group = group,
            .viewers = .empty,
            .size_mode = sizeModeFromU8(m.size_mode),
            .created_at = std.time.timestamp(),
            .max_scrollback = if (m.max_scrollback > 0) m.max_scrollback else 10_000_000,
            .reexec = &self.reexec,
        };
        sess.stream = .init(.{
            .alloc = self.alloc,
            .terminal = &sess.terminal_instance,
            .pty_fd = m.pty_master_fd,
        });

        group.mutex.lock();
        group.surfaces.ensureUnusedCapacity(1) catch {
            group.mutex.unlock();
            return error.OutOfMemory;
        };
        const gop = group.surfaces.getOrPutAssumeCapacity(m.surface_id);
        if (gop.found_existing) {
            group.mutex.unlock();
            // Single-threaded boot — should not happen. Treat as a no-op adopt.
            return error.AlreadyAdopted;
        }
        gop.value_ptr.* = sess;
        _ = group.detached_surfaces.swapRemove(m.surface_id);
        sess.reader_thread = std.Thread.spawn(.{}, RemoteSession.readerMain, .{sess}) catch |err| {
            _ = group.surfaces.swapRemove(m.surface_id);
            group.mutex.unlock();
            return err;
        };
        sess.reader_thread.detach();
        group.mutex.unlock();

        // Already reflects the live state; don't immediately rewrite the file.
        sess.checkpointed_seq = sess.dirty_seq;
        if (self.state_dir) |sd| reexecLogTo(sd, "adopt: surface={s} master_fd={d} pid={d} OK", .{ &session.shared.formatUuid(m.surface_id), m.pty_master_fd, m.child_pid });
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
// cmux execve self-handoff (Phase 2, GATED) — fd / CLOEXEC helpers
//
// The design premise "everything except the carry-set is already CLOEXEC" is
// FALSE: the channel-mux service sockets (port_listener/control_bridge/
// tcp_connect/browser_proxy) and accepted client/viewer fds are NON-CLOEXEC.
// So we INVERT: force CLOEXEC on EVERY fd, then clear it on the carry-set only
// (listener + each alive PTY master), LAST, with nothing forkable before execve.
// ============================================================================

fn forceCloexec(fd: posix.fd_t) void {
    const flags = c.fcntl(fd, c.F_GETFD);
    if (flags < 0) return;
    _ = c.fcntl(fd, c.F_SETFD, flags | c.FD_CLOEXEC);
}

fn clearCloexec(fd: posix.fd_t) void {
    const flags = c.fcntl(fd, c.F_GETFD);
    if (flags < 0) return;
    _ = c.fcntl(fd, c.F_SETFD, flags & ~@as(c_int, c.FD_CLOEXEC));
}

/// Force FD_CLOEXEC on every fd >= 3 (reuses `closeAllFds`' enumeration with
/// the same 3..1024 fallback, but F_SETFD instead of close). fds 0/1/2 are left
/// alone (daemon.log lives on 2 and is re-dup2'd by the successor's daemonMain).
fn forceCloexecAllFds() void {
    if (std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true })) |dir_| {
        var dir = dir_;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
            if (fd >= 3 and fd != dir.fd) forceCloexec(fd);
        }
    } else |_| {
        var fd: posix.fd_t = 3;
        while (fd < 1024) : (fd += 1) forceCloexec(fd);
    }
}

/// STEP 8: force CLOEXEC on ALL fds, then clear it on the carry-set ONLY.
fn flipCloexecForReexec(listener: posix.fd_t, masters: []const posix.fd_t) void {
    forceCloexecAllFds();
    clearCloexec(listener);
    for (masters) |m| clearCloexec(m);
}

/// Re-set CLOEXEC on the carry-set after an execve FAILURE so the cleared
/// listener/masters don't leak into a later legit fork (shell spawn).
fn forceCloexecOnFds(listener: posix.fd_t, masters: []const posix.fd_t) void {
    forceCloexec(listener);
    for (masters) |m| forceCloexec(m);
}

/// Pre-flight the new binary BEFORE quiescing: executable + native exec header.
/// Cheap, reversible; shrinks the dangerous post-park window.
fn preflightNewBinary(path: [:0]const u8) bool {
    if (c.access(path.ptr, c.X_OK) != 0) return false;
    const f = std.fs.cwd().openFile(path, .{}) catch return false;
    defer f.close();
    var hdr: [4]u8 = undefined;
    const n = f.readAll(&hdr) catch return false;
    if (n < 4) return false;
    // ELF: 7F 45 4C 46. Mach-O: FEEDFACE/FEEDFACF (either endianness) or the
    // CAFEBABE fat header. Native-arch verification is deferred (the client
    // uploads the target-matched binary and already content-hash-gates it).
    if (hdr[0] == 0x7f and hdr[1] == 'E' and hdr[2] == 'L' and hdr[3] == 'F') return true;
    const le = std.mem.readInt(u32, &hdr, .little);
    const be = std.mem.readInt(u32, &hdr, .big);
    return le == 0xFEEDFACE or le == 0xFEEDFACF or be == 0xFEEDFACE or
        be == 0xFEEDFACF or le == 0xCAFEBABE or be == 0xCAFEBABE;
}

/// True iff `fd` is a usable PTY master (TIOCGWINSZ succeeds). Guards adoption
/// against a stale/foreign manifest claiming a non-PTY fd number.
fn fdIsPtyMaster(fd: posix.fd_t) bool {
    if (fd < 0) return false;
    var ws: [4]u16 = undefined;
    return c.ioctl(fd, c.TIOCGWINSZ, @intFromPtr(&ws)) == 0;
}

fn sizeModeFromU8(v: u8) session.protocol.SizeMode {
    return std.meta.intToEnum(session.protocol.SizeMode, v) catch .smallest_wins;
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
                            daemonLog("VANISH mux-fwd-fail target={d} kind={s} fd={d}", .{ target, @tagName(kind), s.daemon_fd }); // TEMP(cmux-vanish-probe)
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
                        daemonLog("VANISH mux-daemon-readerr target={d} fd={d}", .{ s.target, s.daemon_fd }); // TEMP(cmux-vanish-probe)
                        session.shared.sendFrameFile(stdout_file, .eof, .{}, s.target, "") catch {};
                        s.deinit(alloc);
                        slot.* = null;
                        continue;
                    };
                    if (n == 0) {
                        daemonLog("VANISH mux-daemon-eof0 target={d} fd={d}", .{ s.target, s.daemon_fd }); // TEMP(cmux-vanish-probe)
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
                    daemonLog("VANISH mux-daemon-hup target={d} fd={d}", .{ s.target, s.daemon_fd }); // TEMP(cmux-vanish-probe)
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
    // DEFECT 1: close every other inherited fd so the spawned shell can never
    // leak the daemon's listener socket, other sessions' PTY masters, or
    // accepted client/viewer sockets. Some of those are non-CLOEXEC, and
    // during a reexec handoff the masters+listener are DELIBERATELY
    // CLOEXEC-cleared — a create racing that window would otherwise pin them
    // open for the shell's whole lifetime. Safe here: setupFd already dup'd
    // the PTY slave onto 0/1/2 and childPreExec closed the original
    // slave+master before this runs, so closing 3.. leaks nothing the shell
    // needs (the control-bridge socket is passed by path via env, not by fd).
    closeInheritedFdsForShell();
    return null;
}

/// Close every inherited fd >= 3 in the just-forked, pre-exec child. Used by
/// `preExecPty` (DEFECT 1). Async-signal-safe: a bounded raw `close()` loop
/// only — NO allocation and NO `/proc` walk (those can deadlock in a child
/// forked from a multi-threaded process). Uses `std.c.close` (not
/// `posix.close`, which asserts `unreachable` on EBADF) so already-closed fds
/// (the slave+master childPreExec just closed) are tolerated.
fn closeInheritedFdsForShell() void {
    var max_fd: usize = 1024;
    if (posix.getrlimit(.NOFILE)) |rl| {
        const cur: u64 = @intCast(rl.cur);
        max_fd = if (cur == 0 or cur > 65536) 65536 else @intCast(cur);
    } else |_| {}
    var fd: usize = 3;
    while (fd < max_fd) : (fd += 1) {
        _ = std.c.close(@intCast(fd));
    }
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
///
/// Compares the filesystem inode of the path against the inode we
/// captured at bind time. The listener fd's `st_ino` is a kernel
/// anonymous-socket inode and CANNOT be compared against the path's
/// filesystem inode — they live in different namespaces and never
/// match. Using fstat(listener) here used to make the daemon shut
/// itself down on every 60s poll-timeout, manifesting as remote
/// terminals vanishing after exactly 1 minute of idle.
fn isSocketOurs(bound_inode: u64, path: []const u8) bool {
    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= path_buf.len) return false;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    var file_st: c.struct_stat = undefined;
    if (c.stat(&path_buf, &file_st) != 0) return false;
    return @as(u64, @intCast(file_st.st_ino)) == bound_inode;
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
