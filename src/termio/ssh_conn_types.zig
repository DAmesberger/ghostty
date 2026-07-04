//! Shared types for the SSH connection manager: the per-host connection
//! `Entry`, per-surface `SurfaceSlot`, the `Session` grouping, the
//! `WriteRequest` queue element, and the `EntryState` enum. Split out of
//! `SshConnectionManager.zig`, which re-exports all of these unchanged so
//! external importers doing `SshConnectionManager.Entry` etc. keep resolving.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const ssh = session.ssh;
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");
const config = @import("../config.zig").Config;

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

    pub fn removeSurface(self: *Session, target_id: u16, alloc: Allocator) bool {
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
