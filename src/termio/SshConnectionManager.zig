//! Shared SSH connection pool keyed by (ssh_target, jump).
//! Multiple surfaces (tabs/splits) to the same host share one SSH connection,
//! one SSH channel to the remote ghostty process, and multiplexed sessions via target IDs.
//! A dedicated SSH thread per connection exclusively owns all libssh2 calls,
//! since libssh2 is NOT thread-safe. Surfaces communicate via a thread-safe
//! write queue and receive frames via direct processOutput calls.
const SshConnectionManager = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const page_diff = session.page_diff;
const ssh = session.ssh;
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");
const config = @import("../config.zig").Config;

const log = std.log.scoped(.ssh_connection_manager);

mutex: std.Thread.Mutex = .{},
/// Entries are heap-allocated so that pointers remain stable across
/// hash map growth and ordered removal (which shifts internal arrays).
connections: std.StringArrayHashMap(*Entry),
alloc: Allocator,

pub const Uuid = session.shared.Uuid;

pub const SurfaceSlot = struct {
    target_id: u16,
    io: *termio.Termio,
    surface_mailbox: *apprt.surface.Mailbox,
    /// Stable surface UUID for reconnect (survives target_id changes).
    surface_id: Uuid = session.shared.zero_uuid,
    /// Current tab/session label, synced from title changes. Used on reconnect.
    label: ?[]const u8 = null,
    /// True after prependBlankPages has been called for this surface.
    /// Prevents duplicate prepends on reconnect.
    history_prepended: bool = false,
    /// Set when a `snapshot_begin` frame is received for this surface (the
    /// daemon is about to send a full-viewport snapshot). On the NEXT
    /// `data_out` for this surface the client resets the terminal + VT parser
    /// to a clean baseline before applying the snapshot, then clears this
    /// flag. Guarantees the snapshot lands on a known-empty state with no
    /// desync from leftover partial state. Old daemons never send
    /// snapshot_begin, so this stays false and behavior is unchanged.
    pending_snapshot_reset: bool = false,
};

/// A group of surfaces sharing the same remote session (group_id).
/// Layout sync and detach operate at the session level.
pub const Session = struct {
    group_id: Uuid,
    surfaces: std.ArrayList(SurfaceSlot) = .empty,
    layout_blob: ?[]const u8 = null,
    layout_hash: u64 = 0,

    pub fn deinit(self: *Session, alloc: Allocator) void {
        for (self.surfaces.items) |s| {
            if (s.label) |l| alloc.free(l);
        }
        self.surfaces.deinit(alloc);
        if (self.layout_blob) |b| alloc.free(b);
    }

    pub fn findSurfaceByTargetId(self: *const Session, target_id: u16) ?SurfaceSlot {
        for (self.surfaces.items) |s| {
            if (s.target_id == target_id) return s;
        }
        return null;
    }

    fn removeSurface(self: *Session, target_id: u16, alloc: Allocator) bool {
        for (self.surfaces.items, 0..) |s, i| {
            if (s.target_id == target_id) {
                if (s.label) |l| alloc.free(l);
                _ = self.surfaces.swapRemove(i);
                return true;
            }
        }
        return false;
    }
};

pub const WriteRequest = struct {
    kind: session.protocol.Kind,
    target_id: u16,
    data: []const u8, // owned by entry allocator, freed after send
};

pub const EntryState = enum(u8) {
    uninitialized,
    connecting,
    ready,
    failed,
};

pub const Entry = struct {
    alloc: Allocator,
    ctx: session.client.SshContext,
    remote_bin_path: []const u8,
    ref_count: u32,
    /// Shared SSH channel to the multiplexed ghostty process (one per host).
    channel: ?ssh.Channel = null,
    /// Next target ID to assign for multiplexing.
    next_target: u16 = 1,

    ssh_thread: ?std.Thread = null,
    quit_pipe: [2]posix.fd_t = .{ -1, -1 },
    write_pipe: [2]posix.fd_t = .{ -1, -1 },

    /// Serialises ALL libssh2 calls on this Entry's underlying session.
    /// Acquired by `sshThreadMain` around every libssh2 call AND by any
    /// `SshChannelStreamTransport` running against a mux channel on the
    /// same session (via `Config.external_mutex`). libssh2 is not
    /// thread-safe; without this lock, concurrent reads/writes on
    /// different channels of the same session corrupt the shared
    /// transport-level state inside libssh2 (the original M1-revealed
    /// crash was a memmove on a freed transport buffer in
    /// `_libssh2_transport_read`). Never held across a blocking wait —
    /// the SSH thread releases it before `posix.poll`, the transport
    /// threads release before their `pollForRead`/`pollForWrite` helpers.
    libssh2_mutex: std.Thread.Mutex = .{},

    // Registered sessions (keyed by group_id) for frame dispatch
    sessions: std.AutoArrayHashMap(Uuid, *Session),
    surfaces_mutex: std.Thread.Mutex = .{},

    // Write queue (thread-safe)
    write_queue_mu: std.Thread.Mutex = .{},
    write_queue: std.ArrayList(WriteRequest) = .empty,

    // Connection state for race prevention between surfaces
    conn_state: std.atomic.Value(EntryState) = .{ .raw = .uninitialized },

    // Keepalive tracking (written/read only by the SSH thread)
    last_keepalive_received: i128 = 0,
    /// Set to true after receiving the first pong from the remote.
    /// Stale detection is only active when this is true, ensuring backward
    /// compatibility with older remote ghostty versions that don't support keepalive.
    keepalive_active: bool = false,

    // Client scrollback limit (bytes), propagated to daemon via Open frame.
    scrollback_limit: u32 = 10_000_000,

    // Reconnect configuration (set from config during setupConnection)
    max_reconnect_attempts: u32 = 5,
    reconnect_backoff: config.SshReconnectBackoff = .exponential,
    reconnect_interval_ms: u32 = 1000,
    /// Upper bound on the per-attempt sleep after exponential / linear
    /// growth. Embedders that want truly persistent reconnect set
    /// `max_reconnect_attempts` very high and pick a small ceiling
    /// here (e.g. 8000ms) so the loop is patient but doesn't drift
    /// into multi-minute sleeps once the network has been down for a
    /// while.
    reconnect_max_interval_ms: u32 = 30_000,

    // Reconnect IPC pipe (write end signaled from GTK thread, read end polled by SSH thread)
    reconnect_pipe: [2]posix.fd_t = .{ -1, -1 },

    /// Always-present cancel pipe. Created in acquire() so it exists for the
    /// FIRST tcpConnect — before quit_pipe/reconnect_pipe are created in
    /// attachRemoteSurface. The read end (cancel_pipe[0]) is wired into
    /// ctx.cancel_fd and polled by tcpConnect; the write end is latched by
    /// Remote.requestStop on surface teardown so a dead-host connect aborts
    /// promptly instead of blocking io_thr.join. Closed in release()/deinit().
    cancel_pipe: [2]posix.fd_t = .{ -1, -1 },

    // Atomic flags for manual reconnect / cancel (set from GTK thread, read by SSH thread)
    reconnect_requested: std.atomic.Value(bool) = .{ .raw = false },
    cancel_reconnect: std.atomic.Value(bool) = .{ .raw = false },

    // Authentication state (for password prompts)
    auth_state: AuthState = .{},

    // Remote-daemon update-confirmation gate state. The SSH setup
    // thread blocks on this when a session-killing daemon update needs
    // user approval; the UI thread (or C-API submit) records the
    // decision and signals the cond. Mirrors `auth_state`.
    update_state: UpdateState = .{},

    // Session list query state (set by requester, collected by SSH thread)
    session_list: SessionListState = .{},

    /// Generic connection-state listeners. Used by the libghostty C API
    /// to surface ConnectionState transitions to embedders without
    /// piggybacking on per-surface mailboxes. Guarded by
    /// `listener_mutex`; the listener callback fires on the SSH thread
    /// (i.e. whatever thread `broadcastConnectionState` runs on) — the
    /// embedder is responsible for hopping to its own queue if needed.
    ///
    /// `last_state` snapshots the most recent broadcast so newly-
    /// registered listeners can be replayed the current state under
    /// the same lock that guards the live list — this prevents a
    /// listener that registers concurrently with a state change from
    /// either missing it or seeing it twice.
    listener_mutex: std.Thread.Mutex = .{},
    ssh_listeners: std.ArrayListUnmanaged(SshListener) = .empty,
    last_state: ?session.protocol.ConnectionState = null,

    pub const AuthState = session.shared.AuthState;
    pub const UpdateState = session.shared.UpdateState;

    /// A connection-state subscriber registered via
    /// `registerStateListener`. `ctx` is the caller's identity (also
    /// the key used by `unregisterStateListener`). `on_state` fires
    /// once at registration time with the most recently broadcast
    /// state (if any) and then on every subsequent
    /// `broadcastConnectionState` call.
    pub const SshListener = struct {
        ctx: *anyopaque,
        on_state: *const fn (ctx: *anyopaque, state: session.protocol.ConnectionState) void,
    };

    pub const SessionListState = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        /// Accumulated session list entries (newline-delimited text).
        buf: std.ArrayList(u8) = .empty,
        /// True once the SSH thread has finished collecting entries.
        done: bool = false,
        /// True if a query is in progress.
        active: bool = false,
    };
};

pub fn init(alloc: Allocator) SshConnectionManager {
    return .{
        .connections = std.StringArrayHashMap(*Entry).init(alloc),
        .alloc = alloc,
    };
}

pub fn deinit(self: *SshConnectionManager) void {
    var it = self.connections.iterator();
    while (it.next()) |kv| {
        self.alloc.free(kv.key_ptr.*);
        const entry = kv.value_ptr.*;
        if (entry.remote_bin_path.len > 0) self.alloc.free(entry.remote_bin_path);
        if (entry.cancel_pipe[0] != -1) posix.close(entry.cancel_pipe[0]);
        if (entry.cancel_pipe[1] != -1) posix.close(entry.cancel_pipe[1]);
        if (entry.channel) |*ch| ch.close();
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);
        deinitSessions(entry);
        entry.ssh_listeners.deinit(entry.alloc);
        entry.ctx.deinit();
        self.alloc.destroy(entry);
    }
    self.connections.deinit();
}

fn deinitSessions(entry: *Entry) void {
    var sit = entry.sessions.iterator();
    while (sit.next()) |skv| {
        skv.value_ptr.*.deinit(entry.alloc);
        entry.alloc.destroy(skv.value_ptr.*);
    }
    entry.sessions.deinit();
}

/// Build the lookup key from ssh_target + optional jump.
fn makeKey(alloc: Allocator, ssh_target: []const u8, jump: ?[]const u8) ![]u8 {
    if (jump) |j| {
        return std.fmt.allocPrint(alloc, "{s}|{s}", .{ ssh_target, j });
    }
    return alloc.dupe(u8, ssh_target);
}

/// Look up an existing connection entry without changing ref_count.
/// Returns null if no connection to the given target exists.
pub fn findEntry(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) ?*Entry {
    self.mutex.lock();
    defer self.mutex.unlock();
    const key = makeKey(self.alloc, ssh_target, jump) catch return null;
    defer self.alloc.free(key);
    return if (self.connections.get(key)) |entry| entry else null;
}

/// Acquire a connection entry. If the entry already exists its ref_count
/// is incremented; otherwise a new entry is created.
pub fn acquire(
    self: *SshConnectionManager,
    ssh_target: []const u8,
    jump: ?[]const u8,
) !*Entry {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = try makeKey(self.alloc, ssh_target, jump);

    if (self.connections.get(key)) |entry| {
        self.alloc.free(key);
        entry.ref_count += 1;
        return entry;
    }

    // Always-present cancel pipe — created here so it exists for the FIRST
    // tcpConnect (quit_pipe/reconnect_pipe are only created later in
    // attachRemoteSurface). Its read end feeds ctx.cancel_fd so a teardown
    // can abort an in-flight connect.
    const cancel_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(cancel_pipe[0]);
        posix.close(cancel_pipe[1]);
    }

    const entry = try self.alloc.create(Entry);
    errdefer self.alloc.destroy(entry);
    entry.* = .{
        .alloc = self.alloc,
        .ctx = .{
            .alloc = self.alloc,
            .ssh_target = ssh_target,
            .jump = jump,
            .cancel_fd = cancel_pipe[0],
        },
        .remote_bin_path = &.{},
        .ref_count = 1,
        .cancel_pipe = cancel_pipe,
        .sessions = std.AutoArrayHashMap(Uuid, *Session).init(self.alloc),
    };
    try self.connections.put(key, entry);
    return entry;
}

/// Allocate the next target ID for a session on this entry.
pub fn allocateTarget(self: *SshConnectionManager, entry: *Entry) u16 {
    self.mutex.lock();
    defer self.mutex.unlock();
    const target = entry.next_target;
    entry.next_target +%= 1;
    if (entry.next_target == 0) entry.next_target = 1; // skip 0
    return target;
}

/// Register a surface for frame dispatch from the SSH thread.
/// The surface is placed into the session matching `group_id`, creating
/// one if it doesn't exist yet.
/// Returns true on success, false on allocation failure.
pub fn registerSurface(
    entry: *Entry,
    target_id: u16,
    io: *termio.Termio,
    mailbox: *apprt.surface.Mailbox,
    surface_id: Uuid,
    group_id: Uuid,
    initial_label: ?[]const u8,
) bool {
    const owned_label = if (initial_label) |l|
        (entry.alloc.dupe(u8, l) catch null)
    else
        null;

    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();

    const sess = findOrCreateSession(entry, group_id) orelse {
        if (owned_label) |l| entry.alloc.free(l);
        return false;
    };
    sess.surfaces.append(entry.alloc, .{
        .target_id = target_id,
        .io = io,
        .surface_mailbox = mailbox,
        .surface_id = surface_id,
        .label = owned_label,
    }) catch {
        if (owned_label) |l| entry.alloc.free(l);
        return false;
    };
    return true;
}

/// Update the label for a registered surface (e.g. after a title change).
/// The new label is duplicated; the old one is freed.
pub fn updateSurfaceLabel(entry: *Entry, target_id: u16, new_label: []const u8) void {
    const owned = entry.alloc.dupe(u8, new_label) catch return;
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) {
                if (s.label) |old| entry.alloc.free(old);
                s.label = owned;
                return;
            }
        }
    }
    entry.alloc.free(owned);
}

/// Move a surface to the session matching `new_group_id`, creating it if needed.
/// Removes the source session if it becomes empty.
pub fn updateSurfaceGroupId(entry: *Entry, target_id: u16, new_group_id: Uuid) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    moveSurfaceToSession(entry, target_id, new_group_id);
}

/// Unregister a surface. After this returns, the SSH thread will not
/// access the surface's io pointer (surfaces_mutex acts as barrier).
pub fn unregisterSurface(entry: *Entry, target_id: u16) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        if (sess.removeSurface(target_id, entry.alloc)) {
            if (sess.surfaces.items.len == 0) {
                removeSession(entry, sess.group_id);
            }
            return;
        }
    }
}

/// Enqueue a write request for the SSH thread to send.
/// The data is duplicated internally; the caller retains ownership of the input.
pub fn enqueueWrite(entry: *Entry, kind: session.protocol.Kind, target_id: u16, data: []const u8) void {
    const alloc = entry.alloc;
    const owned_data = alloc.dupe(u8, data) catch return;

    entry.write_queue_mu.lock();

    // Cap write queue to prevent unbounded memory growth (DoS protection)
    const max_queue_size = 4096;
    if (entry.write_queue.items.len >= max_queue_size) {
        entry.write_queue_mu.unlock();
        alloc.free(owned_data);
        log.warn("write queue full ({d} entries), dropping frame", .{max_queue_size});
        return;
    }

    entry.write_queue.append(alloc, .{
        .kind = kind,
        .target_id = target_id,
        .data = owned_data,
    }) catch {
        entry.write_queue_mu.unlock();
        alloc.free(owned_data);
        return;
    };
    entry.write_queue_mu.unlock();

    // Wake the SSH thread
    _ = posix.write(entry.write_pipe[1], "w") catch {};
}

/// Store and send a layout blob for a specific session, deduplicating by hash.
/// Thread-safe: acquires surfaces_mutex internally.
pub fn storeAndSendLayout(entry: *Entry, group_id: Uuid, target: u16, blob: []const u8) void {
    const hash = std.hash.XxHash64.hash(0, blob);

    entry.surfaces_mutex.lock();
    const sess = entry.sessions.get(group_id);
    if (sess) |s| {
        if (hash == s.layout_hash) {
            entry.surfaces_mutex.unlock();
            return;
        }
        s.layout_hash = hash;
        if (s.layout_blob) |old| entry.alloc.free(old);
        s.layout_blob = entry.alloc.dupe(u8, blob) catch null;
    }
    entry.surfaces_mutex.unlock();

    log.info("storeAndSendLayout: sending layout ({d} bytes) for session", .{blob.len});
    enqueueWrite(entry, .layout, target, blob);
}

/// Detach all surfaces in a single session. Caller must hold surfaces_mutex.
fn detachSessionLocked(entry: *Entry, sess: *Session) void {
    for (sess.surfaces.items) |s| {
        s.io.backend.remote.detaching = true;
        enqueueWrite(entry, .close, s.target_id, &.{@intFromEnum(session.protocol.CloseMode.detach)});
        _ = s.surface_mailbox.push(.close, .{ .forever = {} });
    }
}

/// Detach all surfaces belonging to a specific session (by group_id).
pub fn detachSession(entry: *Entry, group_id: Uuid) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    if (entry.sessions.get(group_id)) |sess| {
        detachSessionLocked(entry, sess);
    }
}

/// Query available sessions on the remote host via the existing multiplexed
/// connection. Sends a list_request frame and collects list_response
/// responses. Returns the raw text (newline-delimited). Caller owns the result.
/// Times out after `timeout_ms`. Returns null on timeout or if no connection.
pub fn querySessions(entry: *Entry, alloc: Allocator, timeout_ms: u64) ?[]const u8 {
    const state = &entry.session_list;

    // Initialize the query
    state.mutex.lock();
    state.active = true;
    state.done = false;
    state.buf.clearRetainingCapacity();
    state.mutex.unlock();

    // Send the request through the write queue
    enqueueWrite(entry, .list_request, 0, "");

    // Wait for responses with timeout. The multiplexer sends all entries
    // synchronously, so we wait for a brief quiet period after the last entry.
    const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ms) * std.time.ns_per_ms;
    var last_len: usize = 0;

    state.mutex.lock();
    while (true) {
        // Wait up to 500ms for new data (or overall deadline)
        const now = std.time.nanoTimestamp();
        if (now >= deadline) break;

        const wait_ns: u64 = @intCast(@min(
            deadline - now,
            500 * std.time.ns_per_ms,
        ));
        state.cond.timedWait(&state.mutex, wait_ns) catch {};

        const cur_len = state.buf.items.len;
        if (cur_len > 0 and cur_len == last_len) {
            // No new data since last wake — all entries received.
            break;
        }
        last_len = cur_len;
    }

    // Harvest results
    const result = if (state.buf.items.len > 0)
        alloc.dupe(u8, state.buf.items) catch null
    else
        null;

    state.active = false;
    state.buf.clearRetainingCapacity();
    state.mutex.unlock();

    return result;
}

/// Release a reference. When ref_count reaches 0, shut down the SSH thread
/// and clean up the connection.
pub fn release(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    if (self.connections.get(key)) |entry| {
        if (entry.ref_count > 1) {
            entry.ref_count -= 1;
            return;
        }

        // Last reference — shut down SSH thread and clean up.
        if (entry.ssh_thread) |thread| {
            _ = posix.write(entry.quit_pipe[1], "q") catch {};
            thread.join();
            // Close write ends (read ends are closed by the thread)
            posix.close(entry.quit_pipe[1]);
            posix.close(entry.write_pipe[1]);
            if (entry.reconnect_pipe[1] != -1) posix.close(entry.reconnect_pipe[1]);
        }

        // Close the always-present cancel pipe. It exists even when the SSH
        // thread was never spawned (e.g. the initial connect was aborted), so
        // close it unconditionally here. tcpConnect only polls cancel_pipe[0]
        // and requestStop only writes cancel_pipe[1] — neither closes — so
        // release owns the close and there is no double-close.
        if (entry.cancel_pipe[0] != -1) posix.close(entry.cancel_pipe[0]);
        if (entry.cancel_pipe[1] != -1) posix.close(entry.cancel_pipe[1]);

        // Clean up remaining write queue
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);

        // Zero and free password if one was provided
        if (entry.auth_state.password) |pw| {
            session.shared.secureZeroAndFree(entry.alloc, pw);
            entry.auth_state.password = null;
        }

        if (entry.remote_bin_path.len > 0) self.alloc.free(entry.remote_bin_path);
        if (entry.channel) |*ch| ch.close();
        deinitSessions(entry);
        entry.ssh_listeners.deinit(entry.alloc);
        entry.ctx.deinit();
        self.alloc.destroy(entry);

        const removed = self.connections.fetchOrderedRemove(key);
        if (removed) |r| self.alloc.free(r.key);
    }
}

/// Abort an in-flight initial-connect / reconnect for the connection keyed by
/// (ssh_target, jump), if this is the LAST reference. Called from the MAIN
/// thread during surface teardown (via Remote.requestStop) immediately before
/// io_thr.join(), so a dead-host connect aborts instead of hanging the join.
///
/// The whole body runs under `mutex` — the SAME lock `release()` holds for its
/// entire teardown (including `destroy(entry)`). That serialization is
/// load-bearing: the cancel signals below unblock the IO thread, which then
/// unwinds into `release()` and frees the Entry. Holding `mutex` guarantees
/// `release()` cannot free the Entry until we finish touching its fields,
/// closing the use-after-free window. Lock order is `mutex` → `auth_state.mutex`
/// (no path takes them in the reverse order), so this is deadlock-free.
pub fn abortInFlightConnect(
    self: *SshConnectionManager,
    ssh_target: []const u8,
    jump: ?[]const u8,
) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    const entry = self.connections.get(key) orelse return;

    // Only the last reference may latch a cancel — a shared (ref_count>1) live
    // connection must keep working for the surviving sibling.
    if (entry.ref_count > 1) return;

    // Latch the always-present cancel pipe (created in acquire): aborts an
    // in-flight tcpConnect on the IO thread (initial connect) OR the SSH
    // thread (reconnect). Write-only here; release()/deinit own the close.
    if (entry.cancel_pipe[1] != -1)
        _ = posix.write(entry.cancel_pipe[1], "c") catch {};

    // Make the reconnect loop bail promptly to its quit-parked wait. Inert in
    // steady state: the main SSH poll does not watch reconnect_pipe, so this
    // byte is simply drained on the next reconnect or closed at release.
    entry.cancel_reconnect.store(true, .release);
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "c") catch {};

    // Unblock a password-prompt cond wait (not poll-interruptible).
    entry.auth_state.mutex.lock();
    entry.auth_state.cancelled = true;
    entry.auth_state.cond.signal();
    entry.auth_state.mutex.unlock();
}

// SSH thread — exclusively owns all libssh2 calls for one connection.
// Modeled after Exec.ReadThread: blocks in posix.poll when idle, zero CPU.
pub fn sshThreadMain(entry: *Entry) void {

    // Close read ends of pipes on exit
    defer posix.close(entry.quit_pipe[0]);
    defer posix.close(entry.write_pipe[0]);
    defer if (entry.reconnect_pipe[0] != -1) posix.close(entry.reconnect_pipe[0]);

    var sess = &entry.ctx.session.?;
    var channel = &entry.channel.?;
    const ssh_sock = sess.getPollSocket();

    // Set pipe read ends to non-blocking for drain
    setNonBlocking(entry.write_pipe[0]);
    if (entry.reconnect_pipe[0] != -1) setNonBlocking(entry.reconnect_pipe[0]);

    var pollfds: [3]posix.pollfd = .{
        .{ .fd = ssh_sock, .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.write_pipe[0], .events = posix.POLL.IN, .revents = undefined },
    };

    var frame_buf: std.ArrayList(u8) = .empty;
    defer frame_buf.deinit(entry.alloc);

    var read_buf: [4096]u8 = undefined;

    // Keepalive state.
    // Stale detection only activates after receiving the first pong
    // from the remote (entry.keepalive_active). This ensures backward
    // compatibility with older remote ghostty versions that don't support keepalive.
    const now_init = std.time.nanoTimestamp();
    var last_keepalive_sent: i128 = now_init;
    entry.last_keepalive_received = now_init;
    entry.keepalive_active = false;

    // Transport-level keepalive (libssh2). Distinct from the cmux
    // session-protocol channel ping/pong above: this emits SSH transport
    // keepalives that reset the remote sshd's ClientAlive/idle timer so
    // sshd does not tear the transport down (the 15s = 5s*3 ClientAlive
    // disconnect that manifested as an EOF-driven reconnect flicker).
    // Due immediately on the first loop so we never start behind.
    var next_transport_keepalive_at: i128 = now_init;

    while (true) {
        // 1. Process SSH transport (needed for tunneled sessions).
        //    libssh2 is single-threaded per-session; the per-Entry mutex
        //    serialises this with any SshChannelStreamTransport running
        //    on a mux channel of the same session (see Entry.libssh2_mutex).
        entry.libssh2_mutex.lock();
        sess.pollTransport(1);
        entry.libssh2_mutex.unlock();

        // 2. Drain reads (non-blocking tight loop). Re-acquire per
        //    iteration so a transport-reader thread can make progress
        //    between our reads instead of starving on a long burst.
        while (true) {
            entry.libssh2_mutex.lock();
            const rc = channel.readNonBlock(&read_buf);
            entry.libssh2_mutex.unlock();
            if (rc > 0) {
                frame_buf.appendSlice(
                    entry.alloc,
                    read_buf[0..@intCast(rc)],
                ) catch break;
            } else break;
        }

        // Check channel EOF. Two distinct causes:
        //   1. The remote ghostty-daemon exited cleanly (genuine
        //      session-end — surfaces should die).
        //   2. The SSH transport itself dropped (tunnel/VPN down,
        //      laptop sleep, network partition). The daemon is
        //      almost certainly still alive on the other side; we
        //      want to drive the reconnect loop instead of tearing
        //      surfaces down.
        //
        // We can't reliably distinguish (1) from (2) from EOF alone,
        // but `attemptReconnect` is the right thing to try first —
        // if max_reconnect_attempts is exhausted (or set to 0) the
        // function returns false and we fall through to the
        // session-end behaviour. With a "patient but persistent"
        // config (max_reconnect_attempts = u32.max) we essentially
        // never give up on tunnel drops, which is what cmux wants.
        entry.libssh2_mutex.lock();
        const channel_is_eof = channel.eof();
        entry.libssh2_mutex.unlock();
        if (channel_is_eof) {
            log.info("ssh channel EOF — attempting reconnect", .{});
            if (attemptReconnect(entry)) {
                // Reconnected — refresh local refs and continue the loop.
                const reconnect_now = std.time.nanoTimestamp();
                last_keepalive_sent = reconnect_now;
                entry.last_keepalive_received = reconnect_now;
                next_transport_keepalive_at = reconnect_now;
                sess = &entry.ctx.session.?;
                channel = &entry.channel.?;
                // Discard any partial frame bytes left over from the OLD
                // channel. The reopened channel is a fresh stream starting at
                // frame offset 0; concatenating the stale tail with the new
                // bytes mis-aligns the (sync-markerless) frame parser, which
                // silently consumes/drops real `.data_out` terminal output
                // mid-UTF-8 → permanent scrambling (U+FFFD) until it happens
                // to realign. reopenSurfaces re-sends the attach, so the stale
                // tail carries nothing we need.
                frame_buf.clearRetainingCapacity();
                broadcastConnectionState(entry, .connected);
                continue;
            }
            notifyAllSurfaces(entry);
            return;
        }

        // Process complete protocol frames (updates entry.last_keepalive_received).
        // processFrames is in-memory only — never calls libssh2 — so the
        // mutex stays released here, letting the transport thread make
        // progress while we dispatch frames.
        processFrames(&frame_buf, entry);

        // 3. Drain write queue. sendFrame issues 1-2 libssh2 writes; the
        //    lock is re-taken per request so the transport thread gets
        //    interleaved time between bursts.
        {
            entry.write_queue_mu.lock();
            for (entry.write_queue.items) |req| {
                entry.libssh2_mutex.lock();
                const send_err = sendFrame(channel, req.kind, req.target_id, req.data);
                entry.libssh2_mutex.unlock();
                send_err catch |err| {
                    log.warn("ssh write failed: {}", .{err});
                };
                entry.alloc.free(req.data);
            }
            entry.write_queue.clearRetainingCapacity();
            entry.write_queue_mu.unlock();
        }

        // Drain write pipe notification bytes
        drainPipe(entry.write_pipe[0]);

        // 4. Keepalive: send ping if interval elapsed, detect stale via pong
        const now = std.time.nanoTimestamp();
        if (now - last_keepalive_sent >= session.protocol.keepalive_interval_ns) {
            entry.libssh2_mutex.lock();
            const ping_err = sendFrame(channel, .ping, 0, "");
            entry.libssh2_mutex.unlock();
            if (ping_err) |_| {
                // Diagnostic: confirm pings are leaving on the main multiplex
                // channel. Multiplex-side keepalive_server_timeout (60s) fires
                // a terminal-vanish if these stop arriving.
                log.info("keepalive: sent ping (interval={d}s)", .{
                    @as(i64, @intCast(@divFloor(now - last_keepalive_sent, std.time.ns_per_s))),
                });
            } else |err| {
                log.warn("ping send failed: {}", .{err});
            }
            last_keepalive_sent = now;
        }

        // 4b. Transport-level keepalive: emit an SSH transport keepalive
        //     (keepalive@openssh.com, want_reply=1) when due so the remote
        //     sshd's ClientAlive/idle timer is reset and it does not tear
        //     the transport down. keepaliveSend returns the seconds until
        //     the next one is due; we schedule off that. A transient send
        //     error is non-fatal (keepaliveSend logs and returns 0) — we do
        //     NOT trigger attemptReconnect here, since the channel EOF and
        //     stale-pong paths already cover genuine transport loss.
        if (now >= next_transport_keepalive_at) {
            entry.libssh2_mutex.lock();
            const seconds_to_next = sess.keepaliveSend();
            entry.libssh2_mutex.unlock();
            // Clamp the reschedule so a stale/garbage value can't push the
            // next keepalive past the 15s sshd disconnect window.
            const next_s: u32 = @min(seconds_to_next, session.client.transport_keepalive_interval_s);
            next_transport_keepalive_at = now + @as(i128, next_s) * std.time.ns_per_s;
        }

        if (entry.keepalive_active and
            now - entry.last_keepalive_received > session.protocol.keepalive_stale_ns)
        {
            log.warn("ssh connection stale (no pong for {d}s)", .{
                @as(i64, @intCast(@divFloor(now - entry.last_keepalive_received, std.time.ns_per_s))),
            });
            // Attempt reconnection
            if (attemptReconnect(entry)) {
                // Reconnected — reset keepalive state and continue
                const reconnect_now = std.time.nanoTimestamp();
                last_keepalive_sent = reconnect_now;
                entry.last_keepalive_received = reconnect_now;
                next_transport_keepalive_at = reconnect_now;

                // Update local references (session/channel may have changed)
                sess = &entry.ctx.session.?;
                channel = &entry.channel.?;

                // Discard stale partial-frame bytes from the old channel — see
                // the EOF reconnect path above; carrying them across the reopen
                // desyncs the frame parser and scrambles terminal output.
                frame_buf.clearRetainingCapacity();

                // Notify surfaces that we're back
                broadcastConnectionState(entry, .connected);
                continue;
            } else {
                // Reconnect failed — give up
                notifyAllSurfaces(entry);
                return;
            }
        }

        // 5. Compute poll events based on libssh2 block directions
        pollfds[0].events = posix.POLL.IN;
        entry.libssh2_mutex.lock();
        const sess_needs_write = sess.needsWrite();
        entry.libssh2_mutex.unlock();
        if (sess_needs_write) pollfds[0].events |= posix.POLL.OUT;

        // 6. Compute poll timeout: wake up in time to send the next
        //    session-protocol ping AND the next transport-level keepalive,
        //    whichever is sooner. Missing the transport keepalive deadline
        //    is what lets sshd disconnect the transport, so it must gate the
        //    poll timeout too.
        const elapsed_since_send = now - last_keepalive_sent;
        const remaining_ping_ns = session.protocol.keepalive_interval_ns - elapsed_since_send;
        const remaining_transport_ns = next_transport_keepalive_at - now;
        const remaining_ns = @min(remaining_ping_ns, remaining_transport_ns);
        const timeout_ms: i32 = if (remaining_ns <= 0)
            1
        else
            @intCast(@min(@as(i128, 15000), @divFloor(remaining_ns, std.time.ns_per_ms)));

        // 7. Block in poll until next event or timeout
        _ = posix.poll(&pollfds, timeout_ms) catch |err| {
            log.warn("poll failed: {}", .{err});
            return;
        };

        // 8. Check quit pipe
        if (pollfds[1].revents & posix.POLL.IN != 0) {
            log.info("ssh thread got quit signal", .{});
            // Drain write queue one final time so close frames are sent
            entry.write_queue_mu.lock();
            for (entry.write_queue.items) |req| {
                entry.libssh2_mutex.lock();
                const send_err = sendFrame(channel, req.kind, req.target_id, req.data);
                entry.libssh2_mutex.unlock();
                send_err catch |err| {
                    log.warn("final write failed: {}", .{err});
                };
                entry.alloc.free(req.data);
            }
            entry.write_queue.clearRetainingCapacity();
            entry.write_queue_mu.unlock();

            // Flush SSH transport so close frames reach the remote.
            // In non-blocking mode, channel.write() may leave data in
            // libssh2's internal buffer. Switch to blocking and poll
            // until the transport has no more outbound data.
            entry.libssh2_mutex.lock();
            sess.setBlocking(1);
            sess.pollTransport(500);
            entry.libssh2_mutex.unlock();

            return;
        }
    }
}

fn notifyAllSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |s| {
            _ = s.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        }
    }
}

/// Broadcast a connection-state transition to every consumer attached
/// to the Entry — both the per-surface mailbox fan-out (for the GTK
/// terminal renderer) and the generic SshListener registry (for the
/// libghostty C API and any other embedder). Public so the shared
/// attach helper in `session/client.zig` can drive it.
pub fn broadcastConnectionState(entry: *Entry, state: session.protocol.ConnectionState) void {
    // Surface fan-out runs under surfaces_mutex. Scope-block so the
    // defer releases it before we touch listener_mutex — the two
    // locks intentionally do not nest, so a listener callback that
    // (e.g. via the libghostty C API) eventually calls back into a
    // surfaces-mutex-guarded API never deadlocks on this thread.
    {
        entry.surfaces_mutex.lock();
        defer entry.surfaces_mutex.unlock();
        var it = entry.sessions.iterator();
        while (it.next()) |kv| {
            for (kv.value_ptr.*.surfaces.items) |s| {
                _ = s.surface_mailbox.push(.{ .connection_state = state }, .{ .forever = {} });
            }
        }
    }
    // Generic listeners (e.g. libghostty C API embedders). Cache the
    // state for late-arriving registrations under listener_mutex,
    // then dupe the slice and release the lock BEFORE invoking
    // callbacks — listeners that re-enter the listener API (e.g.
    // unregister from inside on_state) would otherwise deadlock.
    // Listeners must still be cheap (no blocking work, no embedder
    // I/O) because they run on the SSH thread.
    entry.listener_mutex.lock();
    entry.last_state = state;
    const dup_snapshot = entry.alloc.dupe(Entry.SshListener, entry.ssh_listeners.items) catch null;
    if (dup_snapshot) |snapshot| {
        entry.listener_mutex.unlock();
        defer entry.alloc.free(snapshot);
        for (snapshot) |listener| listener.on_state(listener.ctx, state);
    } else {
        // Allocation failure: fall back to iterating under the lock.
        // A listener that re-enters the listener API from on_state
        // will deadlock here — better than dropping the broadcast,
        // which is the only other option.
        defer entry.listener_mutex.unlock();
        for (entry.ssh_listeners.items) |listener| listener.on_state(listener.ctx, state);
    }
}

/// Subscribe to ConnectionState transitions on this Entry. The
/// listener's `on_state` callback fires immediately with the most
/// recent broadcasted state (if any) so registrants never miss the
/// initial transition, then on every subsequent transition.
///
/// Both the initial replay and the regular fan-out run under
/// `listener_mutex`, so a listener registered concurrent with a
/// state change observes that change exactly once. Callbacks fire on
/// the SSH thread — embedders MUST hop to their own queue before
/// doing any blocking work.
///
/// Listeners are keyed by `listener.ctx`. Re-registering the same
/// ctx replaces the previous entry (so embedders can swap callbacks
/// without an unregister round-trip).
pub fn registerStateListener(entry: *Entry, listener: Entry.SshListener) !void {
    entry.listener_mutex.lock();
    defer entry.listener_mutex.unlock();
    for (entry.ssh_listeners.items) |*existing| {
        if (existing.ctx == listener.ctx) {
            existing.* = listener;
            // Replay the cached state under the lock so the new
            // callback sees the current state before any future
            // broadcast races past us.
            if (entry.last_state) |s| listener.on_state(listener.ctx, s);
            return;
        }
    }
    try entry.ssh_listeners.append(entry.alloc, listener);
    if (entry.last_state) |s| listener.on_state(listener.ctx, s);
}

/// Drop a previously-registered listener. Idempotent: unknown ctx is
/// a no-op. After this returns, the listener's `on_state` is
/// guaranteed not to fire again from any thread.
pub fn unregisterStateListener(entry: *Entry, ctx: *anyopaque) void {
    entry.listener_mutex.lock();
    defer entry.listener_mutex.unlock();
    for (entry.ssh_listeners.items, 0..) |existing, i| {
        if (existing.ctx == ctx) {
            _ = entry.ssh_listeners.swapRemove(i);
            return;
        }
    }
}

/// Attempt to reconnect the SSH connection with configurable backoff.
/// Returns true if reconnection succeeded, false if we should give up
/// (thread should exit).
fn attemptReconnect(entry: *Entry) bool {
    // Reset atomic flags
    entry.reconnect_requested.store(false, .release);
    entry.cancel_reconnect.store(false, .release);

    // Close old channel under the per-Entry libssh2 mutex. The mux
    // transport's reader/writer threads (SshChannelStreamTransport) may
    // still be calling libssh2 on the SAME session — they are only torn
    // down later, when the surfaces are re-opened — so `ch.close()`
    // (libssh2_channel_close + libssh2_channel_free) must serialise with
    // them, otherwise the free races inside libssh2's internal lists and
    // crashes (same class as the close-time SEGV in
    // SshChannelStreamTransport.close()). Mirrors the close/open-under-
    // mutex pattern at SshChannelStreamTransport.zig:214-219 and
    // `tryOpenChannel` below, which lock this same `entry.libssh2_mutex`.
    if (entry.channel) |*ch| {
        entry.libssh2_mutex.lock();
        defer entry.libssh2_mutex.unlock();
        ch.close();
        entry.channel = null;
    }

    // If auto-reconnect is disabled, go straight to disconnected state
    if (entry.max_reconnect_attempts == 0) {
        broadcastConnectionState(entry, .{ .disconnected = .{
            .attempts_made = 0,
            .reason = .disabled,
        } });
        if (waitForManualReconnect(entry)) {
            return attemptReconnect(entry);
        }
        return false;
    }

    var attempt: u32 = 0;
    while (attempt < entry.max_reconnect_attempts) {
        attempt += 1;
        const elapsed = std.time.nanoTimestamp();

        // Broadcast "actively connecting" phase (next_retry_ns = 0)
        broadcastConnectionState(entry, .{ .reconnecting = .{
            .attempt = attempt,
            .max_attempts = entry.max_reconnect_attempts,
            .elapsed_ns = 0,
            .next_retry_ns = 0,
        } });

        log.info("reconnect attempt {d}/{d}", .{ attempt, entry.max_reconnect_attempts });

        // Close old session state
        entry.ctx.deinit();
        entry.ctx.session = null;
        entry.ctx.jump_session = null;

        // Try to reconnect
        var stderr_buf: [256]u8 = undefined;
        var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer_.interface;

        const connect_ok = if (entry.ctx.connect(stderr)) |_| true else |_| false;

        if (connect_ok) {
            // Reopen the TERMINAL channel in `--stdio-attach` mode (the mode
            // the initial connect used), NOT the `--mux-attach` proxy opener
            // `tryOpenChannel` — see `tryReopenTerminalChannel`. Using the mux
            // opener here reopened the terminal channel in a mode that EOFs in
            // ~77ms, causing an infinite reconnect flicker once terminal+proxy
            // shared one Entry.
            if (tryReopenTerminalChannel(entry)) |new_channel| {
                // Switch to non-blocking
                var sess = &entry.ctx.session.?;
                sess.setBlocking(0);
                entry.channel = new_channel;

                // Re-open sessions for registered surfaces
                reopenSurfaces(entry);

                log.info("reconnected after {d} attempts", .{attempt});
                return true;
            }
        }

        // Connection failed — wait with backoff before next attempt
        if (attempt < entry.max_reconnect_attempts) {
            const delay_ms = computeBackoff(entry, attempt - 1);
            const now = std.time.nanoTimestamp();
            const next_retry_ns = now + @as(i128, delay_ms) * std.time.ns_per_ms;

            // Broadcast "waiting for backoff" phase
            broadcastConnectionState(entry, .{ .reconnecting = .{
                .attempt = attempt,
                .max_attempts = entry.max_reconnect_attempts,
                .elapsed_ns = now - elapsed,
                .next_retry_ns = next_retry_ns,
            } });

            // Interruptible sleep — can be woken by quit, Retry Now, or Cancel
            if (interruptibleSleep(entry, delay_ms)) return false; // quit signaled

            // Check cancel
            if (entry.cancel_reconnect.load(.acquire)) {
                entry.cancel_reconnect.store(false, .release);
                broadcastConnectionState(entry, .{ .disconnected = .{
                    .attempts_made = attempt,
                    .reason = .cancelled,
                } });
                if (waitForManualReconnect(entry)) {
                    return attemptReconnect(entry);
                }
                return false;
            }

            // Check "Retry Now" — skip remaining backoff, loop immediately
            if (entry.reconnect_requested.load(.acquire)) {
                entry.reconnect_requested.store(false, .release);
                // Continue loop immediately (don't increment attempt — retry same one)
                continue;
            }
        }
    }

    // Exhausted all attempts
    log.warn("reconnect exhausted after {d} attempts", .{entry.max_reconnect_attempts});
    broadcastConnectionState(entry, .{ .disconnected = .{
        .attempts_made = entry.max_reconnect_attempts,
        .reason = .exhausted,
    } });

    if (waitForManualReconnect(entry)) {
        return attemptReconnect(entry);
    }
    return false;
}

/// Re-open sessions for registered surfaces using their stable IDs after reconnect.
/// Sends one `surface_attach` Open per surface in each session (group) — NOT just
/// the first surface. Each surface re-enters the daemon's viewers list keyed by its
/// own target_id and receives its own snapshot, so every pane of a split group is
/// resynced. The shared group_id ties them to the same remote session.
fn reopenSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();

    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        if (sess.surfaces.items.len == 0) continue;

        // Reset history_prepended for all surfaces so reconnect can prepend fresh
        for (sess.surfaces.items) |*surf| {
            surf.history_prepended = false;
        }

        // Re-attach EVERY surface in the group, each with its own surface_id,
        // target_id, label, and LIVE grid size. Without this, surfaces[1+] of a
        // split group never re-enter the daemon viewers list and get nothing
        // after reconnect.
        for (sess.surfaces.items) |s| {
            // Re-open at the surface's CURRENT grid size, not a hardcoded 24x80.
            // A stale 24x80 resizes the remote PTY on every reconnect, so a wider
            // TUI then redraws column-misaligned against an 80-col PTY and corrupts
            // output (compounding any frame-desync scramble). Read the live size
            // from the surface terminal under its renderer lock (the same lock
            // dispatchFrame takes); fall back to 24x80 only if unreadable.
            var attach_rows: u16 = 24;
            var attach_cols: u16 = 80;
            {
                s.io.renderer_state.mutex.lock();
                defer s.io.renderer_state.mutex.unlock();
                const t = s.io.renderer_state.terminal;
                if (t.rows > 0 and t.cols > 0) {
                    attach_rows = @intCast(t.rows);
                    attach_cols = @intCast(t.cols);
                }
            }

            const open_payload = (session.protocol.Open{
                .open_type = .surface_attach,
                .resize = .{ .rows = attach_rows, .cols = attach_cols, .width_px = 0, .height_px = 0 },
                .surface_id = s.surface_id,
                .group_id = sess.group_id,
                .max_scrollback = entry.scrollback_limit,
                .label = s.label orelse "reconnected",
            }).encode(entry.alloc) catch continue;
            defer entry.alloc.free(open_payload);
            sendFrame(&entry.channel.?, .open, s.target_id, open_payload) catch {
                log.warn("reconnect: failed to re-open surface target={d}", .{s.target_id});
                // Notify just this surface — the others are attached independently.
                _ = s.surface_mailbox.push(.{
                    .child_exited = .{ .exit_code = 1, .runtime_ms = 0 },
                }, .{ .forever = {} });
            };
        }
    }
}

/// Try to open a multiplexed channel, restarting the daemon if needed.
/// Copies remote_bin_path under surfaces_mutex to avoid racing with setupConnection.
/// Public so the C-API layer can open a dedicated mux channel from the SSH thread.
pub fn tryOpenChannel(entry: *Entry) ?ssh.Channel {
    const alloc = entry.alloc;

    // Copy remote_bin_path under mutex — setupConnection writes it from another thread.
    entry.surfaces_mutex.lock();
    const remote_bin_path = alloc.dupe(u8, entry.remote_bin_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(remote_bin_path);

    // tryOpenChannel can be called concurrently with `sshThreadMain`
    // on the same Entry (e.g. from `onStateListener` running on the
    // M1 SetupWorker's thread after broadcasting `.connected`). The
    // libssh2 calls inside `openClientMuxChannel` and
    // `ensureRemoteDaemon` MUST serialise with the SSH thread's calls
    // on the same session, otherwise concurrent `libssh2_channel_*`
    // and transport-level reads/writes corrupt internal lists (we hit
    // this as a SEGV inside `_libssh2_list_first` ← `_libssh2_packet_ask`
    // ← `_libssh2_channel_free` during the M6 smoke).
    entry.libssh2_mutex.lock();
    defer entry.libssh2_mutex.unlock();

    // Use `openClientMuxChannel` (--mux-attach) not `openMultiplexChannel`
    // (--stdio-attach). The latter is the terminal-frame demuxer which
    // silently drops `.channel_*` frames in its else => {} branch.
    // --mux-attach is a pure stdio↔daemon-socket pump that lets
    // ClientMux's channel_open / channel_data / etc. reach the main
    // daemon's channel_registry where browser_proxy + port_listener +
    // tcp_connect + tcp_accepted are registered.

    // First attempt
    if (session.client.openClientMuxChannel(alloc, &entry.ctx, remote_bin_path)) |ch| {
        return ch;
    } else |_| {}

    // Daemon might be dead — try starting without killing existing one first
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, false, null) catch return null;

    return session.client.openClientMuxChannel(alloc, &entry.ctx, remote_bin_path) catch null;
}

/// Reopen the Entry's TERMINAL transport channel after a drop, using the
/// SAME `--stdio-attach` mode the initial connect used (`openMultiplexChannel`
/// → the daemon `multiplex` terminal-frame loop), NOT the `--mux-attach`
/// proxy/control opener `tryOpenChannel` (`openClientMuxChannel` → runMuxMode).
///
/// `attemptReconnect` previously reopened `entry.channel` via `tryOpenChannel`.
/// Once the SSH pool unified the terminal transport and the C-API proxy onto
/// ONE shared Entry / one `entry.channel`, that silently reopened the terminal
/// channel in mux mode after the first drop. A mux-mode channel is not a
/// long-lived terminal session: it EOFs within ~77ms, `sshThreadMain` sees
/// `channel.eof()` and reconnects, reopens-in-mux-mode, EOFs again — an
/// infinite ~340ms connect↔reconnect flicker (every reconnect succeeds, so it
/// never escalates past attempt 1). Reopening in `--stdio-attach` keeps the
/// terminal channel a real terminal session so it stays up. The proxy/control
/// mux channel is reopened separately by `onStateListener` via `tryOpenChannel`.
pub fn tryReopenTerminalChannel(entry: *Entry) ?ssh.Channel {
    const alloc = entry.alloc;

    entry.surfaces_mutex.lock();
    const remote_bin_path = alloc.dupe(u8, entry.remote_bin_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(remote_bin_path);

    // Serialise libssh2 calls with the SSH thread on the same session
    // (see the note in `tryOpenChannel`).
    entry.libssh2_mutex.lock();
    defer entry.libssh2_mutex.unlock();

    // First attempt: the terminal-frame `--stdio-attach` channel.
    if (session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path)) |ch| {
        return ch;
    } else |_| {}

    // Daemon might be dead — try starting without killing the existing one.
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, false, null) catch return null;

    return session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path) catch null;
}

fn processFrames(frame_buf: *std.ArrayList(u8), entry: *Entry) void {
    while (frame_buf.items.len >= session.protocol.header_size) {
        const header = session.protocol.Header.parseFromBuf(
            frame_buf.items[0..session.protocol.header_size],
        ) catch {
            shiftBuffer(frame_buf, session.protocol.header_size);
            continue;
        };
        const kind = header.kind;
        const frame_target = header.target;
        // Defense-in-depth: a header whose len exceeds max_payload is a desync
        // (the frame format has no sync marker, so a garbage byte can parse as
        // a plausible kind with a bogus 4-byte len). Trusting it would either
        // stall forever waiting for gigabytes (the `break` below) or over-
        // consume real output. Treat it as a desync — drop one byte and rescan.
        if (header.len > session.protocol.max_payload) {
            shiftBuffer(frame_buf, 1);
            continue;
        }
        const total = session.protocol.header_size + header.len;
        if (frame_buf.items.len < total) break;

        var payload = frame_buf.items[session.protocol.header_size..total];

        // Decompress if flags indicate compression.
        var decompressed: ?[]u8 = null;
        defer if (decompressed) |d| entry.alloc.free(d);
        if (header.flags.compressed) {
            decompressed = session.shared.decompressPayload(entry.alloc, payload) catch {
                log.warn("decompression failed for {s} frame", .{@tagName(kind)});
                shiftBuffer(frame_buf, total);
                continue;
            };
            payload = decompressed.?;
        }

        // Handle pong: update timestamp, don't dispatch to surfaces
        if (kind == .pong) {
            entry.last_keepalive_received = std.time.nanoTimestamp();
            entry.keepalive_active = true;
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Collect list_response frames into the query buffer
        if (kind == .list_response) {
            entry.session_list.mutex.lock();
            if (entry.session_list.active) {
                entry.session_list.buf.appendSlice(entry.alloc, payload) catch {};
                entry.session_list.buf.append(entry.alloc, '\n') catch {};
                entry.session_list.cond.signal();
            }
            entry.session_list.mutex.unlock();
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Hold surfaces_mutex during dispatch to prevent use-after-free
        // on surface io pointers (unregisterSurface acquires the same lock).
        entry.surfaces_mutex.lock();
        if (frame_target == 0) {
            // Broadcast to all surfaces across all sessions
            var sit = entry.sessions.iterator();
            while (sit.next()) |kv| {
                for (kv.value_ptr.*.surfaces.items) |s| {
                    dispatchFrame(entry, kind, s, payload);
                }
            }
        } else {
            if (findSurfaceAcrossSessions(entry, frame_target)) |s| {
                dispatchFrame(entry, kind, s, payload);
            }
        }
        entry.surfaces_mutex.unlock();

        shiftBuffer(frame_buf, total);
    }
}

fn dispatchFrame(entry: *Entry, kind: session.protocol.Kind, s: SurfaceSlot, payload: []const u8) void {
    switch (kind) {
        .snapshot_begin => {
            // The daemon is about to send a full-viewport snapshot for this
            // target. Mark the surface so the NEXT data_out resets the
            // terminal + VT parser to a clean baseline before applying the
            // snapshot. We persist this on the slot (not the by-value `s`
            // copy) so it survives to the following frame. Caller holds
            // surfaces_mutex, so findSurfaceSlotPtr is safe here.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                slot.pending_snapshot_reset = true;
            }
        },
        .data_out => {
            // If a snapshot_begin preceded this data_out, reset the terminal
            // and VT parsing state to a clean baseline first so the snapshot
            // lands on a known-empty terminal (no desync). resetForSnapshot
            // acquires renderer_state.mutex itself, so it must run before we
            // take any lock here. Clear the flag so subsequent live data_out
            // frames are applied normally.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                if (slot.pending_snapshot_reset) {
                    slot.pending_snapshot_reset = false;
                    s.io.resetForSnapshot();
                }
            }
            // Suppress write-back responses (DA, DSR, OSC colors, etc.) during
            // remote data processing. The daemon already responded to queries.
            s.io.terminal_stream.handler.suppress_responses = true;
            defer s.io.terminal_stream.handler.suppress_responses = false;
            @call(.always_inline, termio.Termio.processOutput, .{ s.io, payload });
        },
        .opened => {
            // Parse the bundled opened response
            const parsed = session.protocol.Opened.parseHeader(payload) catch {
                log.warn("opened: invalid payload", .{});
                return;
            };
            log.info("remote session opened history_rows={d} label='{s}' (len={d})", .{ parsed.history_rows, parsed.label, parsed.label.len });

            // Move surface to the correct session and update surface_id.
            // surfaces_mutex is held by caller.
            moveSurfaceToSession(entry, s.target_id, parsed.group_id);
            updateSurfaceIdLocked(entry, s.target_id, parsed.surface_id);

            // Send IDs to GTK thread via mailbox so it can update ssh_ctx
            // without racing this (SSH) thread. All GTK-thread readers see
            // the update before any subsequent messages (data_out,
            // layout_restore) because the mailbox is FIFO.
            var opened_msg: apprt.surface.Message = .{
                .remote_opened = .{
                    .group_id = parsed.group_id,
                    .surface_id = parsed.surface_id,
                },
            };
            // Copy daemon-authoritative session label.
            const ol = parsed.label;
            const ol_len = @min(ol.len, 64);
            @memcpy(opened_msg.remote_opened.label[0..ol_len], ol[0..ol_len]);
            opened_msg.remote_opened.label_len = @intCast(ol_len);
            opened_msg.remote_opened.color = parsed.color;
            _ = s.surface_mailbox.push(opened_msg, .{ .forever = {} });

            // NOTE: blank history pages for scrollback restore are NOT
            // prepended here. The daemon sends `opened` BEFORE the
            // `snapshot_begin`+`data_out` pair, and that `data_out` runs
            // `resetForSnapshot()` → `terminal.fullReset()` →
            // `Screen.reset()` → `pages.reset()`, which DROPS every page —
            // including any we prepended here. The following
            // `scrollback_response` chunks would then land on a terminal with
            // no history rows and scramble the screen. So the prepend is
            // deferred to the `.scrollback_response` handler below, which runs
            // AFTER the snapshot reset, on a clean terminal. (`history_rows`
            // is re-derived there from `total_history_rows`.)

            // If layout blob is included, send it to surface for tree recreation.
            // Bundle group_id/surface_id in the message to avoid a race:
            // the GTK thread must not read these from the Remote backend
            // since we just wrote them on this (SSH) thread.
            if (parsed.layout_blob) |layout_blob| {
                log.info("received layout blob in opened response len={d}", .{layout_blob.len});
                const blob_copy = std.heap.page_allocator.dupe(u8, layout_blob) catch {
                    log.err("failed to allocate layout blob", .{});
                    return;
                };
                _ = s.surface_mailbox.push(.{
                    .layout_restore = .{
                        .blob = blob_copy.ptr,
                        .len = @intCast(blob_copy.len),
                        .group_id = parsed.group_id,
                        .surface_id = parsed.surface_id,
                    },
                }, .{ .forever = {} });
            }
        },
        .scrollback_response => {
            // Parse scrollback chunk header
            const resp = session.protocol.ScrollbackResponse.parse(payload) catch {
                log.warn("scrollback_response: invalid payload", .{});
                return;
            };

            // row_count == 0 is the done marker
            if (resp.row_count == 0) {
                log.info("scrollback restore complete ({d} history rows)", .{resp.total_history_rows});
                _ = s.surface_mailbox.push(.{
                    .scrollback_progress = .{
                        .received = resp.total_history_rows,
                        .total = resp.total_history_rows,
                    },
                }, .{ .forever = {} });
                return;
            }

            // Apply the chunk to the client's terminal
            s.io.renderer_state.mutex.lock();
            defer s.io.renderer_state.mutex.unlock();
            const t = s.io.renderer_state.terminal;

            // Pre-allocate the blank history pages on the FIRST chunk, here —
            // AFTER the snapshot's `data_out` already ran `fullReset()`. Doing
            // this in the `.opened` handler instead places the blank pages
            // BEFORE that reset, which drops them and scrambles the restored
            // screen (see the note in the `.opened` handler). Guard with
            // `history_prepended` (reset per-surface on reconnect in
            // `reopenSurfaces`) so we prepend exactly once per attach.
            // `surfaces_mutex` is held by the caller, so findSurfaceSlotPtr is
            // safe.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                if (!slot.history_prepended and resp.total_history_rows > 0) {
                    t.screens.active.pages.prependBlankPages(resp.total_history_rows) catch |err| {
                        log.warn("failed to prepend history pages: {}", .{err});
                    };
                    slot.history_prepended = true;
                }
            }

            page_diff.applyScrollbackChunk(
                t,
                resp.chunk_start_row,
                resp.row_count,
                resp.chunk_data,
            );

            // Notify surface of progress
            const received = resp.chunk_start_row + resp.row_count;
            _ = s.surface_mailbox.push(.{
                .scrollback_progress = .{
                    .received = received,
                    .total = resp.total_history_rows,
                },
            }, .{ .forever = {} });
        },
        .layout => {
            log.info("received layout blob len={d}", .{payload.len});
            // page_allocator is used intentionally: this blob crosses thread
            // boundaries via the surface mailbox. The receiver (GTK thread)
            // frees it and does not have access to entry.alloc.
            const blob_copy = std.heap.page_allocator.dupe(u8, payload) catch {
                log.err("failed to allocate layout blob", .{});
                return;
            };
            _ = s.surface_mailbox.push(.{
                .layout_restore = .{
                    .blob = blob_copy.ptr,
                    .len = @intCast(blob_copy.len),
                },
            }, .{ .forever = {} });
        },
        .viewer_state => {
            const hdr = session.protocol.ViewerState.parseHeader(payload) catch {
                log.warn("viewer_state: invalid payload", .{});
                return;
            };
            log.info("viewer_state: reason={s} viewers={d} label='{s}' (len={d})", .{
                @tagName(hdr.reason),
                hdr.viewer_count,
                hdr.session_label,
                hdr.session_label.len,
            });

            var msg: apprt.surface.Message = .{
                .viewer_state = .{
                    .reason = hdr.reason,
                    .size_mode = hdr.size_mode,
                    .controller_id = hdr.controller_id,
                    .effective_rows = hdr.effective_rows,
                    .effective_cols = hdr.effective_cols,
                    .viewer_count = hdr.viewer_count,
                    .session_color = hdr.session_color,
                },
            };

            // Copy session label into fixed buffer.
            const sl = hdr.session_label;
            const sl_len = @min(sl.len, 64);
            @memcpy(msg.viewer_state.session_label[0..sl_len], sl[0..sl_len]);
            msg.viewer_state.session_label_len = @intCast(sl_len);

            // Parse viewer entries from remaining payload.
            var remaining = hdr.remaining;
            const count = @min(hdr.viewer_count, 8); // Cap at inline roster size
            for (0..count) |i| {
                const uuid_end = session.protocol.uuid_size;
                if (remaining.len < session.protocol.ViewerState.viewer_fixed_size) break;
                // Skip UUID (16 bytes)
                remaining = remaining[uuid_end..];
                const label_len = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                const is_ctrl = remaining[0] != 0;
                remaining = remaining[1..];
                const rows = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                const cols = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                // Read label
                const actual_label_len = @min(label_len, 64);
                if (remaining.len < label_len) break;
                var vi: apprt.surface.Message.ViewerInfo = .{
                    .is_controller = is_ctrl,
                    .rows = rows,
                    .cols = cols,
                    .label_len = @intCast(actual_label_len),
                };
                @memcpy(vi.label[0..actual_label_len], remaining[0..actual_label_len]);
                remaining = remaining[label_len..];
                msg.viewer_state.viewers[i] = vi;
            }

            _ = s.surface_mailbox.push(msg, .{ .forever = {} });
        },
        .info => log.info("remote info: {s}", .{payload}),
        .err => log.err("remote error: {s}", .{payload}),
        .eof => {
            log.info("remote session EOF target={d}", .{s.target_id});
            _ = s.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        },
        else => {},
    }
}

/// Find a surface by target_id across all sessions. Returns a copy.
/// Caller must hold surfaces_mutex.
/// Find a surface slot by target ID, returning a mutable pointer.
/// Caller must hold surfaces_mutex.
fn findSurfaceSlotPtr(entry: *Entry, target_id: u16) ?*SurfaceSlot {
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) return s;
        }
    }
    return null;
}

fn findSurfaceAcrossSessions(entry: *const Entry, target_id: u16) ?SurfaceSlot {
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.*.findSurfaceByTargetId(target_id)) |s| return s;
    }
    return null;
}

/// Find or create a session for the given group_id. Caller must hold surfaces_mutex.
fn findOrCreateSession(entry: *Entry, group_id: Uuid) ?*Session {
    if (entry.sessions.get(group_id)) |s| return s;

    const sess = entry.alloc.create(Session) catch return null;
    sess.* = .{ .group_id = group_id };
    entry.sessions.put(group_id, sess) catch {
        entry.alloc.destroy(sess);
        return null;
    };
    return sess;
}

/// Remove an empty session. Caller must hold surfaces_mutex.
fn removeSession(entry: *Entry, group_id: Uuid) void {
    if (entry.sessions.fetchSwapRemove(group_id)) |kv| {
        kv.value.deinit(entry.alloc);
        entry.alloc.destroy(kv.value);
    }
}

/// Move a surface between sessions. Caller must hold surfaces_mutex.
fn moveSurfaceToSession(entry: *Entry, target_id: u16, new_group_id: Uuid) void {
    // Find and remove from current session
    var old_session: ?*Session = null;
    var surface_data: ?SurfaceSlot = null;

    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        for (sess.surfaces.items, 0..) |s, i| {
            if (s.target_id == target_id) {
                // Check if already in correct session
                if (std.mem.eql(u8, &sess.group_id, &new_group_id)) return;

                surface_data = s;
                old_session = sess;
                _ = sess.surfaces.swapRemove(i);
                break;
            }
        }
        if (surface_data != null) break;
    }

    const surf = surface_data orelse return;
    const target_sess = findOrCreateSession(entry, new_group_id) orelse return;
    target_sess.surfaces.append(entry.alloc, surf) catch return;

    // Remove empty source session
    if (old_session) |old| {
        if (old.surfaces.items.len == 0) {
            removeSession(entry, old.group_id);
        }
    }
}

/// Update surface_id for a surface. Caller must hold surfaces_mutex.
fn updateSurfaceIdLocked(entry: *Entry, target_id: u16, new_surface_id: Uuid) void {
    if (session.shared.isZeroUuid(new_surface_id)) return;
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) {
                s.surface_id = new_surface_id;
                return;
            }
        }
    }
}

fn sendFrame(channel: *ssh.Channel, kind: session.protocol.Kind, target: u16, data: []const u8) !void {
    if (data.len > session.protocol.max_payload) return error.PayloadTooLarge;
    const header = (session.protocol.Header{
        .kind = kind,
        .target = target,
        .len = @intCast(data.len),
    }).encodeToBuf();
    try channel.write(&header);
    if (data.len > 0) try channel.write(data);
}

const shiftBuffer = session.shared.shiftBuffer;

fn setNonBlocking(fd: posix.fd_t) void {
    const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    _ = posix.fcntl(fd, posix.F.SETFL, flags | @as(usize, @as(u32, @bitCast(posix.O{ .NONBLOCK = true })))) catch {};
}

fn drainPipe(fd: posix.fd_t) void {
    var buf: [64]u8 = undefined;
    while (true) {
        _ = posix.read(fd, &buf) catch return;
    }
}

// Public reconnect/cancel API — called from the GTK thread.

/// Signal the SSH thread to (re-)attempt reconnection.
/// Works during backoff wait ("Retry Now") and after exhaustion ("Reconnect").
pub fn requestReconnect(entry: *Entry) void {
    entry.reconnect_requested.store(true, .release);
    entry.cancel_reconnect.store(false, .release);
    // Wake the SSH thread's reconnect_pipe poll
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "r") catch {};
}

/// Signal the SSH thread to cancel the current auto-reconnect loop.
pub fn cancelReconnect(entry: *Entry) void {
    entry.cancel_reconnect.store(true, .release);
    entry.reconnect_requested.store(false, .release);
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "c") catch {};
}

/// Compute backoff delay in milliseconds for the given attempt (0-based).
/// `pub` so the C-API setup worker can reuse the same backoff curve for
/// its relentless *initial*-connect retry loop (see ssh_capi.zig).
pub fn computeBackoff(entry: *const Entry, attempt: u32) u64 {
    const base: u64 = entry.reconnect_interval_ms;
    const cap: u64 = entry.reconnect_max_interval_ms;
    return switch (entry.reconnect_backoff) {
        .exponential => @min(base *| (@as(u64, 1) << @intCast(@min(attempt, 30))), cap),
        .linear => @min(base *| (@as(u64, attempt) + 1), cap),
        .constant => base,
    };
}

/// Sleep for `delay_ms` but wake early if quit_pipe or reconnect_pipe
/// becomes readable. Returns true if quit was signaled (thread should exit).
fn interruptibleSleep(entry: *Entry, delay_ms: u64) bool {
    var fds: [2]posix.pollfd = .{
        .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.reconnect_pipe[0], .events = posix.POLL.IN, .revents = undefined },
    };
    const timeout: i32 = if (delay_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(delay_ms);
    _ = posix.poll(&fds, timeout) catch {};

    // Check quit
    if (fds[0].revents & posix.POLL.IN != 0) return true;
    // Drain reconnect pipe (caller checks atomic flags)
    if (fds[1].revents & posix.POLL.IN != 0) drainPipe(entry.reconnect_pipe[0]);
    return false;
}

/// Block indefinitely until quit or reconnect_pipe signal.
/// Returns true if reconnect was requested, false if quit.
fn waitForManualReconnect(entry: *Entry) bool {
    while (true) {
        var fds: [2]posix.pollfd = .{
            .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
            .{ .fd = entry.reconnect_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        };
        _ = posix.poll(&fds, -1) catch return false;

        if (fds[0].revents & posix.POLL.IN != 0) return false;
        if (fds[1].revents & posix.POLL.IN != 0) {
            drainPipe(entry.reconnect_pipe[0]);
            if (entry.reconnect_requested.load(.acquire)) {
                entry.reconnect_requested.store(false, .release);
                return true;
            }
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

// Regression: a remote terminal surface whose ssh_target encodes the
// ProxyJump via the ` via ` syntax must resolve the SAME pool key as the
// C-API proxy connection, which calls `makeKey(host, jump)` with a separate
// jump argument. Before the cmux fix the terminal surface keyed on the bare
// host (jump=null) while the proxy keyed on host|jump, so a ProxyJump user
// got two libssh2 connections instead of one shared Entry.
test "makeKey: terminal host-via-jump target pools with proxy (host, jump)" {
    const alloc = testing.allocator;

    const host = "user@example.com:2222";
    const jump = "bastion@jump.example.com";

    // Proxy path: target and jump arrive as separate arguments.
    const proxy_key = try makeKey(alloc, host, jump);
    defer alloc.free(proxy_key);

    // Terminal path: the surface ssh_target is the canonical
    // "host via jump" string; `parseSshTarget` splits it back into
    // (target, jump) exactly as `Remote.threadEnter` does before acquire.
    const surface_target = "user@example.com:2222 via bastion@jump.example.com";
    const parsed = session.shared.parseSshTarget(surface_target);
    const terminal_key = try makeKey(alloc, parsed.target, parsed.jump);
    defer alloc.free(terminal_key);

    try testing.expectEqualStrings(host, parsed.target);
    try testing.expectEqualStrings(jump, parsed.jump.?);
    try testing.expectEqualStrings(proxy_key, terminal_key);
    try testing.expectEqualStrings("user@example.com:2222|bastion@jump.example.com", terminal_key);
}

// With no ProxyJump configured the terminal surface keeps the bare target,
// `parseSshTarget` returns jump=null, and the key is just the host — matching
// a direct (jump=null) proxy connection so they still share one Entry.
test "makeKey: bare target keys on host with no jump" {
    const alloc = testing.allocator;

    const host = "user@example.com:2222";
    const parsed = session.shared.parseSshTarget(host);
    try testing.expect(parsed.jump == null);

    const key = try makeKey(alloc, parsed.target, parsed.jump);
    defer alloc.free(key);

    const direct_key = try makeKey(alloc, host, null);
    defer alloc.free(direct_key);

    try testing.expectEqualStrings(host, key);
    try testing.expectEqualStrings(direct_key, key);
}
