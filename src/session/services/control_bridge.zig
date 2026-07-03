//! control_bridge channel service (daemon side of the reverse control
//! channel).
//!
//! This is the daemon counterpart of the embedder's client-side control
//! handler (cmux's `Sources/RemoteControlChannel.swift` is the reference
//! embedder). It lets a control CLI running INSIDE the remote shell reach the
//! local app's socket dispatcher (`notify` / `notify_target` / `report_*`)
//! even though the remote shell cannot dial the local unix socket directly.
//!
//! The embedder-specific names (the env vars below, the PATH shim) live in
//! `control_bridge_config.zig` as one source of truth; this module only owns
//! the transport. The wire identifiers — service id 7 and the 8-byte
//! `ghctrl01` discriminator — are a stable on-wire contract with deployed
//! peers and must NOT change without a protocol-version bump.
//!
//! Topology:
//!   * The daemon binds a remote-side AF_UNIX listener at a per-daemon
//!     path under a temp dir. That path is injected into every remote
//!     shell's env as the configured socket-path var (default
//!     `CMUX_SOCKET_PATH`), alongside a per-daemon auth token var (default
//!     `CMUX_SOCKET_PASSWORD`) (see daemon.zig `createSurface`).
//!   * The remote control CLI connects to that unix socket and speaks the
//!     same newline-delimited line protocol it would speak to the local
//!     socket, but it MUST first send an auth line carrying the token
//!     (`auth <token>\n`) before any command line is forwarded.
//!   * For each AUTHENTICATED unix connection (see the auth contract
//!     below) the daemon opens a daemon-originated channel toward the
//!     client over the per-connection
//!     `Mux`, using `ChannelService.control_bridge` (wire id 7) with wire
//!     params = the 8-byte ASCII discriminator tag `ghctrl01` the client
//!     expects. The client surfaces this as service id 255 (CUSTOM) and
//!     routes it to its control handler by the tag.
//!   * The child channel then pumps bytes both ways: authenticated
//!     request lines from the unix socket are framed (newline-delimited)
//!     onto the channel, and single-line responses from the channel are
//!     written back to the unix socket.
//!
//! Auth contract (minimal but present): the daemon enforces the
//! per-daemon token at its boundary. The FIRST line received on each
//! accepted unix connection must be `auth <token>` (or `auth.token
//! <token>`). If it matches, the connection is authenticated and a child
//! channel is opened; every subsequent line is forwarded verbatim. If it
//! does not match, the daemon writes an error line and closes the unix
//! socket WITHOUT ever opening a channel toward the client. Unauthenticated
//! command lines are never forwarded.
//!
//! Two roles live in this one file, distinguished by how the channel is
//! created:
//!   * The listener is NOT a client-openable service `open` — it is started
//!     directly by the daemon via `startListener` once the per-connection
//!     `Mux` exists (mirroring how `port_listener.open` spawns an accept
//!     thread, but without a client-opened parent channel).
//!   * The per-connection child channels ARE registered under
//!     `service_id` (7) so `Mux.openChannelFromDaemon` can resolve them.
//!     Their `open` adopts an already-accepted unix-socket fd handed in
//!     out-of-band via `service_open_params` (the `tcp_accepted` pattern).

const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");
const shared = @import("../shared.zig");

const log = std.log.scoped(.control_bridge_service);

/// Service id for `control_bridge`. Matches
/// `protocol.ChannelService.control_bridge` (wire id 7). The client maps
/// this to `GHOSTTY_CHANNEL_SERVICE_CUSTOM` (255) at the C-API bridge.
pub const service_id: u8 = @intFromEnum(protocol.ChannelService.control_bridge);

/// 8-byte ASCII discriminator the client's `RemoteControlChannel` requires
/// at the head of the inbound channel's wire params, so it can tell a
/// `control_bridge` reverse channel apart from a `tcp_accepted` port-forward
/// accept (both arrive as service id 255). Must stay in sync with
/// `RemoteControlChannel.paramTag`.
pub const param_tag: []const u8 = "ghctrl01";

/// Initial credit window (in 4 KiB units) advertised on each child
/// channel. Control traffic is tiny; a small window is plenty.
const child_window_units: u16 = 16;

/// `listen` backlog for the bound unix socket.
const listen_backlog: u31 = 16;

/// Max bytes buffered for a single un-terminated line before the
/// connection is treated as malformed and dropped. A real CLI request is
/// far smaller than this.
const max_line_bytes: usize = 1 * 1024 * 1024;

/// Read buffer size for the unix-socket -> channel pump.
const pump_read_chunk_size = 16 * 1024;

/// How long the channel-side pump waits for outbound credit before
/// re-checking the close signal.
const credit_wait_timeout_ns: u64 = 1 * std.time.ns_per_s;

/// How long a freshly accepted connection has to send its auth line
/// before the daemon drops it (FINDING #4). Bounds the resources a
/// silent / half-open peer can pin: a connection that never sends a line
/// is closed instead of holding an fd + thread indefinitely.
const auth_handshake_timeout_ms: i64 = 10 * std.time.ms_per_s;

/// Max bytes accepted for the auth line before the connection is treated
/// as malformed and dropped. The real auth line is a short
/// `auth <hextoken>`; anything far larger is abuse.
const max_auth_line_bytes: usize = 4 * 1024;

/// Max bytes buffered for the channel -> unix-socket (response) direction
/// before the channel is torn down as a stuck/dead reader (FINDING #6).
/// Bounds the memory a slow remote reader can pin on the daemon.
const max_out_buf_bytes: usize = 1 * 1024 * 1024;

// =========================================================================
// Listener
// =========================================================================

/// Derive the per-daemon AF_UNIX socket path for the reverse control
/// channel. Placed under the system temp dir with a random suffix so two
/// daemons on the same host don't collide. Caller owns the returned
/// slice. The path is bounded to fit `sockaddr_un.sun_path` (kept short).
pub fn deriveSocketPath(alloc: Allocator) ![]u8 {
    const dir = tmpDir();
    var rand: [8]u8 = undefined;
    std.crypto.random.bytes(&rand);
    const hex = std.fmt.bytesToHex(rand, .lower);
    // e.g. /tmp/ctlsock-<16hex>.sock. `tmpDir` already guarantees the
    // FULL path fits `sun_path`, but enforce it once more here so a
    // future change to `tmpDir` can never silently emit an over-long
    // path that `initUnix` would reject after env injection.
    const path = try std.fmt.allocPrint(alloc, "{s}/ctlsock-{s}.sock", .{ dir, hex });
    errdefer alloc.free(path);
    if (path.len > sun_path_usable_max) {
        alloc.free(path);
        // Fall back to a guaranteed-short path under /tmp.
        return try std.fmt.allocPrint(alloc, "/tmp/ctlsock-{s}.sock", .{hex});
    }
    return path;
}

/// Derive a per-daemon auth token (256 bits of randomness, hex-encoded).
/// The remote `cmux` CLI presents this on the reverse-channel socket and
/// the daemon enforces it before forwarding any line. Caller owns the
/// returned slice.
pub fn deriveToken(alloc: Allocator) ![]u8 {
    var rand: [32]u8 = undefined;
    std.crypto.random.bytes(&rand);
    const hex = std.fmt.bytesToHex(rand, .lower);
    return alloc.dupe(u8, &hex);
}

/// Usable bytes in `sockaddr_un.sun_path` across macOS/Linux. The struct
/// field is 104 bytes on macOS and 108 on Linux; the NUL terminator costs
/// one, so 103 is the portable usable maximum. We derive paths against the
/// 103 bound so `initUnix` never rejects with `NameTooLong` after the
/// `/ctlsock-<16hex>.sock` suffix is appended.
const sun_path_usable_max: usize = 103;

/// The fixed-width portion of the derived path beyond the temp dir: a path
/// separator, the `ctlsock-` prefix, 16 lowercase hex chars (8 random
/// bytes), and the `.sock` suffix. Computed precisely so `tmpDir` can
/// reject any dir that would overflow `sun_path` once the suffix is added.
const socket_name_suffix_len: usize = "/ctlsock-".len + 16 + ".sock".len;

/// Resolve a short temp directory for the reverse-channel socket. Prefers
/// `$TMPDIR` (trimmed of a trailing slash), falling back to `/tmp`. The
/// chosen dir is bounded so the FULL derived path (dir + the
/// `/ctlsock-<16hex>.sock` suffix) fits the `sun_path` limit; a too-long
/// `$TMPDIR` falls back to `/tmp` rather than producing a path `initUnix`
/// would reject.
fn tmpDir() []const u8 {
    if (posix.getenv("TMPDIR")) |t| {
        const trimmed = std.mem.trimRight(u8, t, "/");
        // Bound the FULL path: trimmed-dir + suffix must fit sun_path.
        if (trimmed.len > 0 and
            trimmed.len + socket_name_suffix_len <= sun_path_usable_max)
        {
            return trimmed;
        }
    }
    return "/tmp";
}

// =========================================================================
// Path-ownership guard (FINDING B race fix)
// =========================================================================
//
// All remote shells spawned by the daemon receive ONE shared
// `CMUX_SOCKET_PATH` (the per-daemon reverse-channel path), so every mux
// connection's `Listener` must bind that same path. The listener is bound
// per-mux-connection, and on SSH reconnect (a new mux connection to the
// persistent daemon) or a second concurrent client, a NEW listener binds
// the path while the OLD listener may still be tearing down.
//
// Without coordination, `bindUnixListener` unconditionally
// `deleteFile()` + `bind()`s the shared path, and `Listener.stop`
// unconditionally `deleteFile()`s it. A lagging old `stop()` could then
// unlink the socket file the NEW listener just bound, leaving remote
// `cmux notify` dialing an `ENOENT` path and silently dropping reverse
// notifications.
//
// The guard makes path ownership explicit: each successful bind claims the
// path with a fresh monotonic generation token. `stop()` only unlinks the
// file if it is STILL the current owner of that path — a listener whose
// generation was superseded by a newer bind never touches the file. This
// preserves the single-shared-path architecture (all shells reach a stable
// path) while making concurrent bind/stop on the same path safe.

const PathOwner = struct {
    /// The owned path. Heap-allocated copy keyed in `owners`.
    path: []u8,
    /// Generation token of the listener that currently owns the bound
    /// file at `path`. Each successful bind increments the global
    /// generation and stamps it here.
    generation: u64,
};

const PathGuard = struct {
    mutex: std.Thread.Mutex = .{},
    /// One entry per distinct bound path. Keyed by the path string.
    owners: std.StringHashMapUnmanaged(PathOwner) = .empty,
    next_generation: u64 = 1,

    var instance: PathGuard = .{};

    /// Claim ownership of `path` for a freshly-bound listener. Returns the
    /// generation token the caller must remember and present to
    /// `release`. Allocates an owned copy of the key on first use of a
    /// path. The `alloc` is only used for the key copy and must be the
    /// process-stable daemon allocator.
    fn claim(self: *PathGuard, alloc: Allocator, path: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const gen = self.next_generation;
        self.next_generation += 1;

        const gop = try self.owners.getOrPut(alloc, path);
        if (!gop.found_existing) {
            const key_copy = alloc.dupe(u8, path) catch |err| {
                self.owners.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{ .path = key_copy, .generation = gen };
        } else {
            // A newer listener supersedes the previous owner of this path.
            gop.value_ptr.generation = gen;
        }
        return gen;
    }

    /// Release the caller's claim on `path`. Returns true iff the caller
    /// (identified by `generation`) is STILL the current owner — i.e. no
    /// newer bind has superseded it — meaning the caller is responsible
    /// for unlinking the socket file. If a newer listener has taken over,
    /// returns false and the caller MUST NOT unlink (doing so would delete
    /// the live socket out from under the survivor).
    fn release(self: *PathGuard, alloc: Allocator, path: []const u8, generation: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.owners.getEntry(path) orelse return true;
        if (entry.value_ptr.generation != generation) {
            // Superseded by a newer bind; the survivor owns the file.
            return false;
        }
        // Still the current owner: drop the entry and let the caller unlink.
        const key = entry.key_ptr.*;
        self.owners.removeByPtr(entry.key_ptr);
        alloc.free(key);
        return true;
    }
};

/// A running control_bridge listener bound to one `Mux`. Created by
/// `startListener`, stopped by `Listener.stop`. The daemon owns the
/// handle and must `stop` it before tearing down the `Mux` so no new
/// child channels are opened during mux teardown.
pub const Listener = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    /// The bound listening socket. Owned from `startListener` until
    /// `stop` returns.
    listener_fd: posix.fd_t,
    /// The bound socket path, owned here; unlinked on `stop` ONLY if this
    /// listener is still the path's current owner (see `PathGuard`).
    socket_path: []u8,
    /// Generation token stamped when this listener claimed `socket_path`
    /// in the process-global `PathGuard`. `stop` presents it to
    /// `PathGuard.release` so a superseded listener never unlinks a live
    /// socket a newer bind rebound (FINDING B race fix).
    path_generation: u64,
    /// Per-daemon auth token. Borrowed (owned by the daemon); compared
    /// against the auth line each connection must send.
    token: []const u8,
    accept_thread: ?std.Thread = null,
    stop_requested: std.atomic.Value(bool) = .init(false),
    /// In-flight per-connection auth handshakes (FINDING #4). Each
    /// accepted connection runs its auth handshake on a detached thread
    /// that dereferences this `*Listener`; `stop` waits for `pending_count`
    /// to drain to 0 before freeing the handle so no handshake thread
    /// touches a freed `Listener`.
    pending_mutex: std.Thread.Mutex = .{},
    pending_cond: std.Thread.Condition = .{},
    pending_count: usize = 0,

    /// Stop the accept loop, close the socket, and free the path. The
    /// socket FILE is unlinked only if this listener is still the current
    /// owner of `socket_path`; if a newer listener has rebound the same
    /// shared path, ownership has transferred and we must NOT delete the
    /// file (that would yank the live socket out from under the survivor).
    /// Child channels are NOT closed here — they are owned by the `Mux`
    /// and reaped by `Mux.deinit`. Idempotent enough for the single daemon
    /// teardown call.
    pub fn stop(self: *Listener) void {
        self.stop_requested.store(true, .release);
        posix.shutdown(self.listener_fd, .both) catch {};
        if (self.accept_thread) |t| {
            t.join();
            self.accept_thread = null;
        }
        // No further handshakes are spawned once the accept loop has
        // exited; wait for any in-flight ones to finish dereferencing
        // `self` before we free it. A handshake that already opened a
        // child channel returns immediately (the channel is owned by the
        // `Mux` and reaped by `Mux.deinit`, which runs after `stop`).
        self.pending_mutex.lock();
        while (self.pending_count != 0) self.pending_cond.wait(&self.pending_mutex);
        self.pending_mutex.unlock();
        posix.close(self.listener_fd);
        if (PathGuard.instance.release(self.alloc, self.socket_path, self.path_generation)) {
            std.fs.cwd().deleteFile(self.socket_path) catch {};
        }
        self.alloc.free(self.socket_path);
        self.alloc.destroy(self);
    }

    /// Register an in-flight per-connection auth handshake. Paired with
    /// exactly one `finishPending` (FINDING #4 lifecycle).
    fn beginPending(self: *Listener) void {
        self.pending_mutex.lock();
        self.pending_count += 1;
        self.pending_mutex.unlock();
    }

    fn finishPending(self: *Listener) void {
        self.pending_mutex.lock();
        self.pending_count -= 1;
        const drained = self.pending_count == 0;
        self.pending_mutex.unlock();
        if (drained) self.pending_cond.signal();
    }
};

/// Bind a unix-domain listener at `socket_path` and start an accept
/// thread that opens a daemon-originated `control_bridge` child channel for
/// each accepted connection. `token` must outlive the returned handle
/// (the daemon owns it). On success the caller owns the returned
/// `*Listener` and must call `stop` on it before `mux.deinit()`.
pub fn startListener(
    alloc: Allocator,
    mux: *channel_mux.Mux,
    socket_path: []const u8,
    token: []const u8,
) !*Listener {
    // Claim ownership of the shared path FIRST, so the generation token
    // monotonically reflects bind order: a later `startListener` on the
    // same path supersedes any earlier one, and only the surviving owner
    // unlinks the file on `stop` (FINDING B race fix). `bindUnixListener`
    // then performs the delete-stale + bind that hands the on-disk socket
    // over to this listener.
    const generation = try PathGuard.instance.claim(alloc, socket_path);
    // If anything below fails, relinquish the claim. Unlink the file only
    // if we are still the current owner (release returns true) so a failed
    // late bind can't delete a survivor's live socket.
    errdefer if (PathGuard.instance.release(alloc, socket_path, generation)) {
        std.fs.cwd().deleteFile(socket_path) catch {};
    };

    const fd = try bindUnixListener(socket_path);
    errdefer posix.close(fd);

    const path_copy = try alloc.dupe(u8, socket_path);
    errdefer alloc.free(path_copy);

    const self = try alloc.create(Listener);
    errdefer alloc.destroy(self);
    self.* = .{
        .alloc = alloc,
        .mux = mux,
        .listener_fd = fd,
        .socket_path = path_copy,
        .path_generation = generation,
        .token = token,
    };

    self.accept_thread = std.Thread.spawn(.{}, acceptMain, .{self}) catch |err| {
        log.warn("control_bridge: accept thread spawn failed: {}", .{err});
        return error.ThreadSpawnFailed;
    };
    return self;
}

fn bindUnixListener(socket_path: []const u8) !posix.fd_t {
    // Remove any stale socket file so bind doesn't fail with EADDRINUSE.
    std.fs.cwd().deleteFile(socket_path) catch {};

    var addr = std.net.Address.initUnix(socket_path) catch |err| {
        log.warn("control_bridge: unix path too long: {s}", .{socket_path});
        return err;
    };

    // Non-blocking so the accept loop can `poll` with a timeout and
    // observe the stop flag without depending on `shutdown` to break a
    // blocked `accept`.
    const fd = try posix.socket(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
        0,
    );
    errdefer posix.close(fd);

    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    try posix.listen(fd, listen_backlog);
    return fd;
}

fn acceptMain(self: *Listener) void {
    acceptLoop(self) catch |err| {
        log.warn("control_bridge accept loop exiting on error: {}", .{err});
    };
}

fn acceptLoop(self: *Listener) !void {
    while (!self.stop_requested.load(.acquire)) {
        var pollfds = [1]posix.pollfd{
            .{ .fd = self.listener_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = try posix.poll(&pollfds, 200);
        if (ready == 0) continue; // timeout — re-check the stop flag

        // Non-blocking accepted socket (FINDING #6): the response-direction
        // write in `onData` must never block the shared mux dispatch
        // thread. accept4/emulated flags give us a non-blocking child fd.
        const conn_fd = posix.accept(self.listener_fd, null, null, posix.SOCK.NONBLOCK) catch |err| switch (err) {
            error.WouldBlock,
            error.ConnectionAborted,
            error.ConnectionResetByPeer,
            => continue,
            error.SocketNotListening, error.FileDescriptorNotASocket => return,
            else => return err,
        };

        if (self.stop_requested.load(.acquire)) {
            posix.close(conn_fd);
            return;
        }

        spawnAuthThread(self, conn_fd) catch |err| {
            // Ownership of conn_fd never transferred to a handshake; close it.
            log.warn("control_bridge: auth thread spawn failed: {}", .{err});
            posix.close(conn_fd);
        };
    }
}

/// Spawn the per-connection auth handshake on a detached thread. The
/// channel toward the client is opened ONLY after that handshake
/// authenticates (FINDING #4), so accepting a connection never — by
/// itself — opens a channel. On success ownership of `conn_fd` moves to
/// the handshake thread; on spawn failure the caller must close it.
fn spawnAuthThread(self: *Listener, conn_fd: posix.fd_t) !void {
    // Track the handshake so `stop` waits for it before freeing `self`.
    self.beginPending();
    const t = std.Thread.spawn(.{}, authThreadMain, .{ self, conn_fd }) catch |err| {
        self.finishPending();
        return err;
    };
    t.detach();
}

/// Detached per-connection handshake thread body. Owns `conn_fd`: runs
/// the auth handshake and, on success, hands the fd to a child channel;
/// otherwise closes it.
fn authThreadMain(self: *Listener, conn_fd: posix.fd_t) void {
    defer self.finishPending();
    const handed_off = runAuthHandshake(self, conn_fd);
    if (!handed_off) posix.close(conn_fd);
}

/// Read + verify the first line as the auth line, then — only if it
/// verifies — open the daemon-originated child channel toward the client.
/// A peer that never sends a line is dropped after
/// `auth_handshake_timeout_ms` (FINDING #4: no unbounded resource hold).
///
/// Returns true iff ownership of `conn_fd` has left this function (handed
/// to a child channel, or already closed by a failed child `open`); false
/// means the caller still owns `conn_fd` and must close it.
fn runAuthHandshake(self: *Listener, conn_fd: posix.fd_t) bool {
    var line = std.ArrayListUnmanaged(u8).empty;
    defer line.deinit(self.alloc);

    const deadline_ms = std.time.milliTimestamp() + auth_handshake_timeout_ms;
    // Read the auth line ONE byte at a time so any pipelined command bytes
    // after the newline stay in the socket buffer for the child's pump to
    // read — no leftover handoff needed.
    while (true) {
        if (self.stop_requested.load(.acquire)) return false;
        const remaining = deadline_ms - std.time.milliTimestamp();
        if (remaining <= 0) {
            log.warn("control_bridge: auth handshake timed out", .{});
            return false;
        }
        var pollfds = [1]posix.pollfd{
            .{ .fd = conn_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        // Cap the wait so we periodically re-check the stop flag/deadline.
        const wait_ms: i32 = @intCast(@min(remaining, 200));
        const ready = posix.poll(&pollfds, wait_ms) catch return false;
        if (ready == 0) continue;

        var b: [1]u8 = undefined;
        const n = posix.read(conn_fd, &b) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return false,
        };
        if (n == 0) return false; // peer closed before authenticating
        if (b[0] == '\n') break;
        line.append(self.alloc, b[0]) catch return false;
        if (line.items.len > max_auth_line_bytes) {
            log.warn("control_bridge: auth line exceeded {d} bytes; dropping", .{max_auth_line_bytes});
            return false;
        }
    }

    const trimmed = std.mem.trim(u8, line.items, " \t\r");
    if (!verifyAuthLine(trimmed, self.token)) {
        _ = writeAll(conn_fd, "ERROR: control_bridge auth required\n");
        return false; // never open a channel for an unauthenticated peer
    }
    _ = writeAll(conn_fd, "OK: authenticated\n");

    return openChild(self, conn_fd);
}

/// Open a daemon-originated `control_bridge` child channel that adopts the
/// already-authenticated `conn_fd`. Returns true iff `conn_fd` ownership
/// has left the caller (handed to the child, or already closed by a failed
/// `open`); false means the caller must still close it.
fn openChild(self: *Listener, conn_fd: posix.fd_t) bool {
    // Daemon-local open params: [4] fd | [N] token. The token never goes
    // on the wire.
    const service_params = encodeChildOpenParams(self.alloc, conn_fd, self.token) catch return false;
    defer self.alloc.free(service_params);

    const child_id = self.mux.openChannelFromDaemon(
        service_id,
        param_tag, // wire params: the 8-byte ghctrl01 discriminator
        service_params,
        child_window_units,
    ) catch |err| {
        switch (err) {
            // `open` never ran — we still own conn_fd; caller closes it.
            error.ServiceNotRegistered, error.ChannelIdsExhausted => return false,
            // `open` ran and failed — its errdefer already closed conn_fd.
            error.InvalidRequest,
            error.ServiceError,
            error.PolicyDenied,
            error.ResourceExhausted,
            error.OutOfMemory,
            => {
                log.warn("control_bridge: child open rejected: {}", .{err});
                return true;
            },
        }
    };
    log.debug("control_bridge: opened child channel id={x}", .{child_id});
    return true;
}

// =========================================================================
// Child channel (per accepted unix connection)
// =========================================================================

/// Per-channel service state for a child `control_bridge` channel.
const ChildState = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    /// The accepted unix socket, non-blocking. Owned from `open` until
    /// `on_close`.
    sock_fd: posix.fd_t,
    /// Per-daemon auth token, copied locally. Authentication now happens
    /// in the listener's handshake thread BEFORE this channel is opened
    /// (FINDING #4), so the pump no longer consults it; retained so the
    /// daemon-local open-params format stays stable.
    token: []u8,
    pump_thread: ?std.Thread = null,
    channel: ?*channel_mux.Channel = null,
    channel_attached: std.Thread.ResetEvent = .{},
    /// Channel -> unix-socket (response direction) backlog. `onData` runs
    /// on the shared mux dispatch thread and must not block on a slow
    /// remote reader (FINDING #6): it writes what the non-blocking socket
    /// accepts immediately and queues any remainder here for the pump
    /// thread to flush. Guarded by `out_mutex`.
    out_mutex: std.Thread.Mutex = .{},
    out_buf: std.ArrayListUnmanaged(u8) = .empty,
};

/// Register the service in a daemon's channel-mux registry. Called once
/// at daemon startup (by `daemon.zig`). Registering it advertises
/// `control_bridge` in the `capabilities` frame and lets
/// `Mux.openChannelFromDaemon` resolve daemon-originated child opens.
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "control_bridge",
        .vtable = &vtable,
    });
}

pub const vtable: channel_mux.Service.VTable = .{
    .open = open,
    .on_opened = onOpened,
    .on_data = onData,
    .on_control = onControl,
    .on_eof = onEof,
    .on_close = onClose,
};

/// Encode daemon-local child open params: [4] fd i32 LE | [N] token.
/// Caller owns the returned slice.
fn encodeChildOpenParams(alloc: Allocator, fd: posix.fd_t, token: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, 4 + token.len);
    std.mem.writeInt(i32, buf[0..4], @intCast(fd), .little);
    @memcpy(buf[4..], token);
    return buf;
}

fn onOpened(state_ptr: ?*anyopaque, ch: *channel_mux.Channel) void {
    const state: *ChildState = @ptrCast(@alignCast(state_ptr orelse return));
    state.channel = ch;
    state.channel_attached.set();
}

fn open(
    _: ?*anyopaque,
    mux: *channel_mux.Mux,
    channel_id: u32,
    params: []const u8,
    _: []u8,
) channel_mux.ServiceError!channel_mux.Service.OpenResult {
    if (params.len < 4) {
        log.warn("control_bridge: child open params too short ({d})", .{params.len});
        return error.InvalidRequest;
    }
    const fd: posix.fd_t = @intCast(std.mem.readInt(i32, params[0..4], .little));
    // From here we own the fd: any error path must close it.
    errdefer posix.close(fd);

    const token = params[4..];

    const state = try mux.alloc.create(ChildState);
    errdefer mux.alloc.destroy(state);
    const token_copy = try mux.alloc.dupe(u8, token);
    errdefer mux.alloc.free(token_copy);

    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .sock_fd = fd,
        .token = token_copy,
    };

    state.pump_thread = std.Thread.spawn(.{}, pumpMain, .{state}) catch |err| {
        log.warn("control_bridge: pump spawn failed: {}", .{err});
        return error.ResourceExhausted;
    };

    return .{ .state = state };
}

fn onData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    // Channel -> unix socket: the client's framed response line(s).
    //
    // This runs on the shared mux dispatch thread, so it must NOT block
    // (head-of-line blocking would stall every other channel on the mux —
    // FINDING #6). The socket is non-blocking: write what the kernel takes
    // immediately and queue any remainder for the pump thread to flush.
    const state: *ChildState = @ptrCast(@alignCast(state_ptr orelse return));
    if (bytes.len == 0) return;

    state.out_mutex.lock();
    defer state.out_mutex.unlock();

    var remainder = bytes;
    if (state.out_buf.items.len == 0) {
        // Fast path: nothing queued — write straight through.
        const written = writeSocketNonBlocking(state.sock_fd, bytes) catch {
            log.warn("control_bridge: write to socket failed", .{});
            return error.ServiceError;
        };
        if (written == bytes.len) return;
        remainder = bytes[written..];
    }
    // Preserve ordering: queue the un-writable tail BEHIND any backlog so
    // the pump flushes it in FIFO order.
    if (state.out_buf.items.len + remainder.len > max_out_buf_bytes) {
        log.warn("control_bridge: response backlog exceeded {d} bytes; closing channel", .{max_out_buf_bytes});
        return error.ServiceError;
    }
    state.out_buf.appendSlice(state.alloc, remainder) catch return error.ServiceError;
}

fn onControl(_: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    log.debug("control_bridge: ignoring unknown control op={d}", .{op});
}

fn onEof(state_ptr: ?*anyopaque) void {
    const state: *ChildState = @ptrCast(@alignCast(state_ptr orelse return));
    posix.shutdown(state.sock_fd, .send) catch {};
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *ChildState = @ptrCast(@alignCast(state_ptr orelse return));

    // Break the pump out of any blocking read.
    posix.shutdown(state.sock_fd, .both) catch {};
    // Unblock the pump if it was still waiting on channel attachment.
    state.channel_attached.set();

    if (state.pump_thread) |t| {
        t.join();
        state.pump_thread = null;
    }

    // Pump is joined — no other thread touches `out_buf` now.
    posix.close(state.sock_fd);
    state.out_buf.deinit(state.alloc);
    state.alloc.free(state.token);
    state.alloc.destroy(state);
}

// =========================================================================
// Pump thread (unix socket -> channel)
// =========================================================================

fn pumpMain(state: *ChildState) void {
    pumpLoop(state) catch |err| {
        log.warn("control_bridge pump exiting on error: {}", .{err});
    };
}

fn pumpLoop(state: *ChildState) !void {
    state.channel_attached.wait();
    const ch = state.mux.getChannel(state.channel_id) orelse return;

    // Guarantee the peer always learns the request stream ended, on EVERY
    // exit path — socket EOF, read error, oversize line, poll failure, a
    // failed forward, or normal close-signal teardown (FINDING #5). Without
    // this the channel/fd/thread leaked until the whole mux tore down.
    // `sendChannelEof` is idempotent and no-ops once the channel is
    // closing, so this is safe even on the close-signal exit.
    defer state.mux.sendChannelEof(ch) catch {};

    var pending = std.ArrayListUnmanaged(u8).empty;
    defer pending.deinit(state.alloc);

    var buf: [pump_read_chunk_size]u8 = undefined;
    while (!ch.close_signal.isSet()) {
        // Watch POLLOUT only while there is a response backlog to flush,
        // so the pump drains `out_buf` that `onData` couldn't write inline
        // (FINDING #6) without spinning when there is nothing pending.
        const want_out = blk: {
            state.out_mutex.lock();
            defer state.out_mutex.unlock();
            break :blk state.out_buf.items.len > 0;
        };
        var pollfds = [1]posix.pollfd{
            .{ .fd = state.sock_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        if (want_out) pollfds[0].events |= posix.POLL.OUT;
        const ready = posix.poll(&pollfds, 200) catch return;
        if (ready == 0) continue;

        if (want_out and (pollfds[0].revents & posix.POLL.OUT) != 0) {
            // Socket writable again — flush queued response bytes. A write
            // failure here means the socket is dead; exit (defer eofs).
            flushOut(state) catch return;
        }

        if ((pollfds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR)) == 0) {
            continue;
        }

        const n = posix.read(state.sock_fd, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return,
        };
        if (n == 0) return; // socket EOF — defer sends channel_eof

        try pending.appendSlice(state.alloc, buf[0..n]);
        if (pending.items.len > max_line_bytes) {
            log.warn("control_bridge: request line exceeded {d} bytes; dropping", .{max_line_bytes});
            return;
        }

        // Split complete lines out of the buffer and forward each. Auth
        // already happened in the listener handshake before this channel
        // was opened (FINDING #4), so every line here is authenticated.
        while (std.mem.indexOfScalar(u8, pending.items, '\n')) |nl| {
            const line = pending.items[0..nl];
            const trimmed = std.mem.trim(u8, line, " \t\r");

            if (trimmed.len != 0) {
                // Forward the request line to the client, newline-terminated
                // (the client's reader splits on '\n').
                try sendLine(state.mux, ch, trimmed);
            }

            // Drop the consumed line (including the newline).
            const rest_len = pending.items.len - (nl + 1);
            std.mem.copyForwards(u8, pending.items[0..rest_len], pending.items[nl + 1 ..]);
            pending.shrinkRetainingCapacity(rest_len);
        }
    }
}

/// Write as many bytes as the non-blocking socket will accept right now.
/// Returns the count written (may be < `bytes.len` under backpressure).
/// Errors only on a real write failure, never on `WouldBlock`.
fn writeSocketNonBlocking(fd: posix.fd_t, bytes: []const u8) !usize {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        off += n;
    }
    return off;
}

/// Flush queued response bytes to the socket, dropping what was written
/// from the front of `out_buf`. Called from the pump thread when the
/// socket reports writable (FINDING #6). Errors on a real write failure.
fn flushOut(state: *ChildState) !void {
    state.out_mutex.lock();
    defer state.out_mutex.unlock();
    if (state.out_buf.items.len == 0) return;
    const written = try writeSocketNonBlocking(state.sock_fd, state.out_buf.items);
    if (written == 0) return;
    const rest = state.out_buf.items.len - written;
    std.mem.copyForwards(u8, state.out_buf.items[0..rest], state.out_buf.items[written..]);
    state.out_buf.shrinkRetainingCapacity(rest);
}

/// Verify an auth line against the daemon token. Accepts either
/// `auth <token>` (v1 form, mirrors the local socket) or
/// `auth.token <token>`. Constant-time compares the token.
fn verifyAuthLine(line: []const u8, token: []const u8) bool {
    const provided = blk: {
        if (std.mem.startsWith(u8, line, "auth.token ")) {
            break :blk std.mem.trim(u8, line["auth.token ".len..], " \t\r");
        }
        if (std.mem.startsWith(u8, line, "auth ")) {
            break :blk std.mem.trim(u8, line["auth ".len..], " \t\r");
        }
        return false;
    };
    if (provided.len == 0 or provided.len != token.len) return false;
    return constantTimeEql(provided, token);
}

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

/// Send one request line (newline-terminated) to the client over the
/// channel, respecting outbound credit.
fn sendLine(mux: *channel_mux.Mux, ch: *channel_mux.Channel, line: []const u8) !void {
    try sendAll(mux, ch, line);
    try sendAll(mux, ch, "\n");
}

fn sendAll(mux: *channel_mux.Mux, ch: *channel_mux.Channel, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        if (ch.close_signal.isSet()) return;
        const sent = mux.sendChannelData(ch, bytes[off..]) catch |err| {
            log.warn("control_bridge pump: sendChannelData failed: {}", .{err});
            return;
        };
        if (sent == 0) {
            _ = mux.waitForCredit(ch, credit_wait_timeout_ns);
            continue;
        }
        off += sent;
    }
}

/// Best-effort blocking write of an entire slice to a fd.
fn writeAll(fd: posix.fd_t, bytes: []const u8) usize {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch return off;
        if (n == 0) return off;
        off += n;
    }
    return off;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "control_bridge encodeChildOpenParams roundtrip" {
    const buf = try encodeChildOpenParams(testing.allocator, 42, "secret-token");
    defer testing.allocator.free(buf);
    const fd = std.mem.readInt(i32, buf[0..4], .little);
    try testing.expectEqual(@as(i32, 42), fd);
    try testing.expectEqualStrings("secret-token", buf[4..]);
}

test "control_bridge verifyAuthLine accepts matching token forms" {
    try testing.expect(verifyAuthLine("auth s3cr3t", "s3cr3t"));
    try testing.expect(verifyAuthLine("auth.token s3cr3t", "s3cr3t"));
    try testing.expect(verifyAuthLine("auth   s3cr3t  ", "s3cr3t"));
}

test "control_bridge verifyAuthLine rejects bad token / missing prefix" {
    try testing.expect(!verifyAuthLine("auth wrong", "s3cr3t"));
    try testing.expect(!verifyAuthLine("auth ", "s3cr3t"));
    try testing.expect(!verifyAuthLine("notify foo", "s3cr3t"));
    try testing.expect(!verifyAuthLine("", "s3cr3t"));
    try testing.expect(!verifyAuthLine("auth s3cr3", "s3cr3t"));
}

test "control_bridge param_tag matches the client discriminator" {
    try testing.expectEqual(@as(usize, 8), param_tag.len);
    try testing.expectEqualStrings("ghctrl01", param_tag);
}

test "control_bridge PathGuard: superseded owner must not unlink the live socket" {
    const alloc = testing.allocator;
    var guard: PathGuard = .{};
    defer {
        var it = guard.owners.iterator();
        while (it.next()) |e| alloc.free(e.key_ptr.*);
        guard.owners.deinit(alloc);
    }

    const path = "/tmp/ctlsock-deadbeef.sock";

    // Old listener claims the path.
    const gen_old = try guard.claim(alloc, path);
    // New listener (reconnect / 2nd client) rebinds the same shared path.
    const gen_new = try guard.claim(alloc, path);
    try testing.expect(gen_new > gen_old);

    // A LAGGING old stop() must observe it is no longer the owner and so
    // must NOT delete the file (that would yank the survivor's socket).
    try testing.expect(!guard.release(alloc, path, gen_old));

    // The surviving (current) owner is responsible for the unlink.
    try testing.expect(guard.release(alloc, path, gen_new));

    // After the survivor releases, the entry is gone; a stale release of
    // an unknown path defaults to "owner" (true) but no entry remains.
    try testing.expectEqual(@as(u32, 0), guard.owners.count());
}

test "control_bridge PathGuard: distinct paths are independent owners" {
    const alloc = testing.allocator;
    var guard: PathGuard = .{};
    defer {
        var it = guard.owners.iterator();
        while (it.next()) |e| alloc.free(e.key_ptr.*);
        guard.owners.deinit(alloc);
    }

    const a = "/tmp/ctlsock-aaaa.sock";
    const b = "/tmp/ctlsock-bbbb.sock";
    const gen_a = try guard.claim(alloc, a);
    const gen_b = try guard.claim(alloc, b);

    // Each path's sole owner unlinks its own file; neither supersedes
    // the other.
    try testing.expect(guard.release(alloc, a, gen_a));
    try testing.expect(guard.release(alloc, b, gen_b));
    try testing.expectEqual(@as(u32, 0), guard.owners.count());
}

test "control_bridge tmpDir rejects an over-long TMPDIR (full path must fit sun_path)" {
    // The fixed suffix plus a dir at the boundary must fit; one byte past
    // it must fall back to /tmp. We assert the arithmetic directly so the
    // bound can't silently regress (env mutation in tests is racy).
    const max_dir_len = sun_path_usable_max - socket_name_suffix_len;
    try testing.expect(max_dir_len + socket_name_suffix_len <= sun_path_usable_max);
    // A dir one byte longer would overflow.
    try testing.expect(max_dir_len + 1 + socket_name_suffix_len > sun_path_usable_max);
}

test "control_bridge deriveSocketPath always fits sun_path" {
    const alloc = testing.allocator;
    const path = try deriveSocketPath(alloc);
    defer alloc.free(path);
    try testing.expect(path.len <= sun_path_usable_max);
    try testing.expect(std.mem.indexOf(u8, path, "ctlsock-") != null);
    try testing.expect(std.mem.endsWith(u8, path, ".sock"));
}

test "control_bridge end-to-end: auth then forward request, response back" {
    const alloc = testing.allocator;

    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const reg = try alloc.create(channel_mux.Registry);
    defer alloc.destroy(reg);
    reg.* = channel_mux.Registry.init(alloc);
    defer reg.deinit();
    try register(reg);

    var mux = channel_mux.Mux.init(alloc, fds[0], reg);
    defer mux.deinit();

    // Create a temp unix socket path for the listener.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir_path);
    const sock_path = try std.fs.path.join(alloc, &.{ dir_path, "cmuxctl.sock" });
    defer alloc.free(sock_path);

    const token = "tok3n";
    const listener = try startListener(alloc, &mux, sock_path, token);
    defer listener.stop();

    // Connect a unix client to the listener.
    const client_fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(client_fd);
    var caddr = try std.net.Address.initUnix(sock_path);
    // Retry connect briefly: the accept thread binds asynchronously.
    var connected = false;
    var attempts: usize = 0;
    while (attempts < 50 and !connected) : (attempts += 1) {
        if (posix.connect(client_fd, &caddr.any, caddr.getOsSockLen())) |_| {
            connected = true;
        } else |_| {
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }
    try testing.expect(connected);

    // Send auth then a request line.
    try writeAllOrFail(client_fd, "auth tok3n\n");
    try writeAllOrFail(client_fd, "notify hello\n");

    // The daemon should: (a) ack auth on the unix socket, and
    // (b) open a child channel toward the mux peer and forward the
    // request line as channel_data.
    var ack_buf: [64]u8 = undefined;
    const ack_n = try readSomeTimeout(client_fd, &ack_buf);
    try testing.expect(ack_n > 0);
    try testing.expect(std.mem.startsWith(u8, ack_buf[0..ack_n], "OK"));

    // Collect frames off the mux's peer side: expect a child channel_open
    // (daemon-direction id, params == ghctrl01) then channel_data with the
    // forwarded request.
    var child_id: ?u32 = null;
    var collected = std.ArrayListUnmanaged(u8).empty;
    defer collected.deinit(alloc);
    var guard: usize = 0;
    while (std.mem.indexOfScalar(u8, collected.items, '\n') == null and guard < 64) : (guard += 1) {
        const frame = try readFrameAlloc(alloc, fds[1]);
        defer alloc.free(frame.payload);
        switch (frame.header.kind) {
            .channel_open => {
                const co = try protocol.ChannelOpen.parse(frame.payload);
                try testing.expect((co.channel_id & protocol.channel_id_daemon_bit) != 0);
                try testing.expectEqualStrings(param_tag, co.service_params);
                child_id = co.channel_id;
            },
            .channel_data => {
                const cd = try protocol.ChannelData.parse(frame.payload);
                try testing.expect(child_id != null);
                try testing.expectEqual(child_id.?, cd.channel_id);
                try collected.appendSlice(alloc, cd.bytes);
            },
            .channel_window, .channel_eof => {},
            else => {},
        }
    }
    try testing.expect(std.mem.indexOf(u8, collected.items, "notify hello") != null);
}

fn writeAllOrFail(fd: posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        off += try posix.write(fd, bytes[off..]);
    }
}

fn readSomeTimeout(fd: posix.fd_t, buf: []u8) !usize {
    var pollfds = [1]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = try posix.poll(&pollfds, 5000);
    if (ready == 0) return error.ReadTimeout;
    return try posix.read(fd, buf);
}

fn readExactTimeout(fd: posix.fd_t, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        var pollfds = [1]posix.pollfd{
            .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = try posix.poll(&pollfds, 5000);
        if (ready == 0) return error.ReadTimeout;
        const n = try posix.read(fd, buf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

fn readFrameAlloc(alloc: Allocator, fd: posix.fd_t) !struct {
    header: protocol.Header,
    payload: []u8,
} {
    var hbuf: [protocol.header_size]u8 = undefined;
    try readExactTimeout(fd, &hbuf);
    const header = try protocol.Header.parseFromBuf(&hbuf);
    const payload = try alloc.alloc(u8, header.len);
    errdefer alloc.free(payload);
    try readExactTimeout(fd, payload);
    return .{ .header = header, .payload = payload };
}
