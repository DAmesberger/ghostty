//! C-API glue for the libghostty SSH connection + channel multiplexing
//! surface declared in `include/ghostty.h` (see "SSH connection +
//! channel multiplexing API" section). Phase 6B.1 lays down the
//! handle layout, the extern C entry points, and the buffer/callback
//! plumbing.
//!
//! Currently functional:
//!
//!   * `ghostty_ssh_open` acquires an `SshConnectionManager.Entry`
//!     via the embedder-provided `ghostty_app_t`, registers a
//!     `SshListener` on the Entry, and translates each broadcast
//!     `ConnectionState` into a C `ghostty_ssh_state_t` to fire the
//!     embedder's `on_state`.
//!   * `ghostty_ssh_close` / `ghostty_ssh_free` unregister the
//!     listener, release the Entry, and cascade an
//!     `on_close(reason=daemon_shutdown)` to every live channel
//!     handle rooted on the connection.
//!
//! Still gated on a follow-up:
//!
//!   * Channel transport: write/eof/close currently only manipulate
//!     the channel handle's local state. Real byte flow needs a
//!     client-side channel mux (the existing daemon-side
//!     `channel_mux.Mux` only dispatches inbound `channel_open`, not
//!     outbound). Tracked as TODO(client-mux).
//!   * `ghostty_ssh_attach_surface` would call the shared helper
//!     `session.client.attachRemoteSurface` (which now backs the
//!     GTK terminal-surface path too) from a worker thread, but
//!     the worker-thread spawn plus the subsequent frame-dispatch
//!     routing to the channel callbacks both land alongside the
//!     channel-mux follow-up. For now it returns a handle that
//!     immediately reports `on_close(SERVICE_ERROR)` so embedders
//!     can exercise that edge.
//!   * `ghostty_ssh_submit_host_key_decision` is a no-op today —
//!     the underlying libssh2 host-key check (src/session/ssh.zig
//!     verifyHostKey) auto-accepts unknown keys via TOFU and never
//!     fires `on_host_key`. The C entry point is present for
//!     forward compatibility; wiring lands alongside a redesign of
//!     verifyHostKey to surface a prompt.
//!
//! Threading & ownership rules (mirrors the contract documented in
//! include/ghostty.h):
//!
//!   * Every exported function is non-blocking and may be called from
//!     any thread.
//!   * Callbacks fire on libghostty-owned worker threads. The handle
//!     holds the callback set behind a mutex so submit_* calls from
//!     inside a callback are safe.
//!   * ONE EXCEPTION: ghostty_ssh_open fires on_state SYNCHRONOUSLY
//!     on the calling thread for the initial CONNECTING transition
//!     AND for any FAILED transitions emitted before this function
//!     returns (e.g. when Entry acquisition or jump-spec duplication
//!     fails). From the moment ghostty_ssh_open returns successfully,
//!     all subsequent on_state fires on libghostty worker threads.
//!     Embedders that hop to a serial queue from on_state should be
//!     prepared to see the very first one (and possibly a FAILED
//!     transition, depending on the config) happen on the open
//!     caller's thread.
//!   * Buffers passed in are copied; buffers handed to callbacks are
//!     borrowed for the callback duration.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const protocol = @import("../../session/protocol.zig");
const session_shared = @import("../../session/shared.zig");
const SshConnectionManager = @import("../../termio/SshConnectionManager.zig");
const apprt_embedded = @import("../embedded.zig");

const log = std.log.scoped(.ssh_capi);

const global = &@import("../../global.zig").state;

// =========================================================================
// C-ABI types. These mirror `include/ghostty.h` exactly. Any change
// here MUST be reflected in the header.
// =========================================================================

/// Mirror of `ghostty_ssh_state_kind_e`.
pub const StateKind = enum(c_int) {
    connecting = 0,
    password_required = 1,
    uploading = 2,
    downloading = 3,
    setup = 4,
    connected = 5,
    reconnecting = 6,
    stale = 7,
    failed = 8,
    disconnected = 9,
};

/// Mirror of `ghostty_ssh_provision_source_e`.
pub const ProvisionSource = enum(c_int) {
    local_daemon = 0,
    local_self = 1,
    github = 2,

    fn fromZig(src: protocol.ConnectionState.ProvisionSource) ProvisionSource {
        return switch (src) {
            .local_daemon => .local_daemon,
            .local_self => .local_self,
            .github => .github,
        };
    }
};

/// Mirror of `ghostty_ssh_disconnect_reason_e`.
pub const DisconnectReason = enum(c_int) {
    exhausted = 0,
    cancelled = 1,
    disabled = 2,

    fn fromZig(r: protocol.ConnectionState.DisconnectReason) DisconnectReason {
        return switch (r) {
            .exhausted => .exhausted,
            .cancelled => .cancelled,
            .disabled => .disabled,
        };
    }
};

/// Mirror of `ghostty_ssh_fail_reason_e`.
pub const FailReason = enum(c_int) {
    unknown = 0,
    auth_failed = 1,
    timeout = 2,
    helper_failed = 3,

    fn fromZig(r: protocol.ConnectionState.FailReason) FailReason {
        return switch (r) {
            .unknown => .unknown,
            .auth_failed => .auth_failed,
            .timeout => .timeout,
            .helper_failed => .helper_failed,
        };
    }
};

/// Mirror of `ghostty_channel_service_e`. Values match
/// `protocol.ChannelService` for built-ins; `terminal` is a
/// libghostty-only sugar value (the surface attachment path uses the
/// legacy session frames and doesn't ride channel_* frames).
pub const ChannelService = enum(c_int) {
    invalid = 0,
    tcp_connect = 1,
    port_listener = 2,
    file_transfer = 3,
    browser_proxy = 4,
    process_exec = 5,
    terminal = 6,
    custom = 255,
};

/// Mirror of `ghostty_channel_close_reason_e`. Includes
/// libghostty-synthesized values for transport-level closes.
pub const ChannelCloseReason = enum(c_int) {
    normal = 0,
    peer_reset = 1,
    service_error = 2,
    policy_denied = 3,
    idle_timeout = 4,
    daemon_shutdown = 5,
    transport = 254,
    unknown = 255,

    fn fromProtocol(r: protocol.ChannelCloseReason) ChannelCloseReason {
        return switch (r) {
            .normal => .normal,
            .peer_reset => .peer_reset,
            .service_error => .service_error,
            .policy_denied => .policy_denied,
            .idle_timeout => .idle_timeout,
            .daemon_shutdown => .daemon_shutdown,
            _ => .unknown,
        };
    }
};

/// Mirror of `ghostty_ssh_host_key_policy_e`.
pub const HostKeyPolicy = enum(c_int) {
    strict = 0,
    tofu = 1,
    insecure = 2,
};

/// Mirror of `ghostty_ssh_state_password_t`.
pub const StatePassword = extern struct {
    is_jump: bool,
    host: [*:0]const u8,
    auth_token: u64,
};

/// Mirror of `ghostty_ssh_state_upload_t`.
pub const StateUpload = extern struct {
    bytes_sent: u64,
    total_bytes: u64,
    source: ProvisionSource,
};

/// Mirror of `ghostty_ssh_state_reconnect_t`.
pub const StateReconnect = extern struct {
    attempt: u32,
    max_attempts: u32,
    elapsed_ns: i64,
    next_retry_ns: i64,
};

/// Mirror of `ghostty_ssh_state_disconnect_t`.
pub const StateDisconnect = extern struct {
    attempts_made: u32,
    reason: DisconnectReason,
};

/// Mirror of `ghostty_ssh_state_fail_t`.
pub const StateFail = extern struct {
    reason: FailReason,
    message: ?[*:0]const u8,
};

/// Mirror of `ghostty_ssh_state_t`. C uses an anonymous union; Zig
/// builds the equivalent extern union sized to the largest variant.
pub const State = extern struct {
    kind: StateKind,
    payload: Payload,

    pub const Payload = extern union {
        password: StatePassword,
        upload: StateUpload,
        reconnect: StateReconnect,
        disconnect: StateDisconnect,
        fail: StateFail,
    };
};

/// Mirror of `ghostty_ssh_host_key_t`.
pub const HostKey = extern struct {
    host: [*:0]const u8,
    fingerprint_sha256: [*:0]const u8,
    key_type: [*:0]const u8,
    known_match: bool,
    known_mismatch: bool,
    decision_token: u64,
};

/// Mirror of `ghostty_ssh_config_t`. All pointers are borrowed for the
/// duration of ghostty_ssh_open; the impl copies before returning.
pub const Config = extern struct {
    target: [*:0]const u8,
    jump: ?[*:0]const u8,
    identity_file: ?[*:0]const u8,
    keepalive_interval_ms: u32,
    max_reconnect_attempts: u32,
    reconnect_interval_ms: u32,
    host_key_policy: HostKeyPolicy,
    scrollback_limit_bytes: u32,
};

/// Mirror of `ghostty_ssh_callbacks_t`.
pub const SshCallbacks = extern struct {
    on_state: ?*const fn (userdata: ?*anyopaque, state: *const State) callconv(.c) void,
    on_host_key: ?*const fn (userdata: ?*anyopaque, hk: *const HostKey) callconv(.c) void,
    userdata: ?*anyopaque,
};

/// Mirror of `ghostty_channel_callbacks_t`.
pub const ChannelCallbacks = extern struct {
    on_opened: ?*const fn (
        userdata: ?*anyopaque,
        service_ack: ?*const anyopaque,
        ack_len: usize,
        initial_peer_window: u32,
    ) callconv(.c) void,
    on_data: ?*const fn (
        userdata: ?*anyopaque,
        bytes: ?*const anyopaque,
        len: usize,
    ) callconv(.c) void,
    on_window_credit: ?*const fn (userdata: ?*anyopaque, credit_bytes: u32) callconv(.c) void,
    on_eof: ?*const fn (userdata: ?*anyopaque) callconv(.c) void,
    on_close: ?*const fn (
        userdata: ?*anyopaque,
        reason: ChannelCloseReason,
        message: ?[*:0]const u8,
    ) callconv(.c) void,
    userdata: ?*anyopaque,
};

/// Mirror of `ghostty_ssh_session_entry_t`.
pub const SessionEntry = extern struct {
    group_id: [*]const u8, // 16 bytes
    label: [*:0]const u8,
    surface_count: u32,
    created_at_ns: i64,
};

// =========================================================================
// Internal state. Handle = heap-allocated SshHandle / ChannelHandle.
// =========================================================================

/// Owned copy of the C config — owns the duplicated string memory so
/// we can safely outlive the caller's buffers.
const OwnedConfig = struct {
    target: [:0]u8,
    jump: ?[:0]u8,
    identity_file: ?[:0]u8,
    keepalive_interval_ms: u32,
    max_reconnect_attempts: u32,
    reconnect_interval_ms: u32,
    host_key_policy: HostKeyPolicy,
    scrollback_limit_bytes: u32,

    fn fromC(alloc: Allocator, cfg: *const Config) !OwnedConfig {
        const target = try alloc.dupeZ(u8, std.mem.span(cfg.target));
        errdefer alloc.free(target);
        const jump: ?[:0]u8 = if (cfg.jump) |p| try alloc.dupeZ(u8, std.mem.span(p)) else null;
        errdefer if (jump) |j| alloc.free(j);
        const id_file: ?[:0]u8 = if (cfg.identity_file) |p| try alloc.dupeZ(u8, std.mem.span(p)) else null;
        return .{
            .target = target,
            .jump = jump,
            .identity_file = id_file,
            .keepalive_interval_ms = cfg.keepalive_interval_ms,
            .max_reconnect_attempts = cfg.max_reconnect_attempts,
            .reconnect_interval_ms = cfg.reconnect_interval_ms,
            .host_key_policy = cfg.host_key_policy,
            .scrollback_limit_bytes = cfg.scrollback_limit_bytes,
        };
    }

    fn deinit(self: *OwnedConfig, alloc: Allocator) void {
        alloc.free(self.target);
        if (self.jump) |j| alloc.free(j);
        if (self.identity_file) |p| alloc.free(p);
    }
};

/// The runtime state behind a `ghostty_ssh_t` handle. Heap-allocated;
/// the handle pointer is the address of this struct. Free order: all
/// child channels first, then SshHandle (asserted in `freeHandle`).
pub const SshHandle = struct {
    alloc: Allocator,
    config: OwnedConfig,
    callbacks: SshCallbacks,
    /// Guards `callbacks` (so embedders can swap callbacks via a future
    /// API without racing dispatch) and the channel registry.
    mutex: std.Thread.Mutex = .{},
    /// Connection-pool manager that owns the underlying Entry. Borrowed;
    /// outlives this handle. NULL only in unit tests that exercise the
    /// handle plumbing without a real CoreApp.
    manager: ?*SshConnectionManager = null,
    /// Pool entry acquired in ghostty_ssh_open and released in
    /// ghostty_ssh_close. Null when `manager` is null.
    entry: ?*SshConnectionManager.Entry = null,
    /// Set to true once the listener is registered on the Entry so
    /// close knows to unregister it (and so unit tests that bypass the
    /// manager don't try to).
    listener_registered: bool = false,
    /// Stable per-host name used when releasing the Entry. Owned copy
    /// because `entry.ctx.ssh_target` may be invalidated under us if
    /// the Entry is freed before our close path runs.
    release_target: ?[]u8 = null,
    release_jump: ?[]u8 = null,
    /// Live channels rooted on this connection. Used to validate the
    /// "free channels before ssh" invariant and to broadcast TRANSPORT
    /// closes on reconnect.
    channels: std.AutoArrayHashMapUnmanaged(usize, *ChannelHandle) = .empty,
    /// Atomic snapshot of the current connection state kind. Useful
    /// for embedder polling and for tearing through partial state on
    /// close.
    state_kind: std.atomic.Value(c_int) = .{ .raw = @intFromEnum(StateKind.connecting) },
    /// Stable storage for the host string surfaced via a PASSWORD_REQUIRED
    /// `ghostty_ssh_state_t`. ConnectionState.PasswordPrompt carries the
    /// host inline in a stack-resident `[128]u8`; once the broadcast call
    /// frame unwinds those bytes are dead, so we copy into this buffer
    /// under `mutex` before firing the embedder's callback. Buffer is
    /// valid for the callback duration and remains valid until the NEXT
    /// PASSWORD_REQUIRED arrives — embedders that incidentally retain
    /// the pointer past the immediate callback see the same bytes until
    /// the next prompt rewrites them. +1 reserves space for the NUL
    /// terminator the C type requires.
    last_password_host: [129]u8 = [_]u8{0} ** 129,
    last_password_host_len: u8 = 0,
    /// Per-prompt monotonic auth token allocator. Issued under
    /// `mutex` whenever a PASSWORD_REQUIRED state is translated for
    /// the embedder; the previously-issued token is immediately
    /// invalidated. Skips zero so embedders can use 0 as an
    /// "uninitialized" sentinel.
    next_auth_token: u64 = 1,
    /// The auth_token currently advertised on the latest
    /// PASSWORD_REQUIRED. Submit/cancel only accept this exact value
    /// — any other token (including a stale token from a prior
    /// prompt) is rejected as a silent no-op. Cleared back to null
    /// once the auth attempt is dispatched (success OR cancel) so a
    /// double-submit doesn't double-signal the daemon's auth_state
    /// condition variable.
    current_auth_token: ?u64 = null,
    /// In-flight worker threads spawned by ghostty_ssh_list_sessions.
    /// ghostty_ssh_free refuses to destroy the handle until this
    /// drops to 0 — the embedder must keep the handle alive at
    /// least until the on_entry(null) sentinel fires.
    active_workers: std.atomic.Value(u32) = .{ .raw = 0 },
    /// Set when ghostty_ssh_close has been called; channel ops error
    /// out after this.
    closed: std.atomic.Value(bool) = .{ .raw = false },

    fn init(alloc: Allocator, cfg: *const Config, cbs: *const SshCallbacks) !*SshHandle {
        const self = try alloc.create(SshHandle);
        errdefer alloc.destroy(self);
        self.* = .{
            .alloc = alloc,
            .config = try OwnedConfig.fromC(alloc, cfg),
            .callbacks = cbs.*,
        };
        return self;
    }

    fn deinit(self: *SshHandle) void {
        std.debug.assert(self.channels.count() == 0);
        if (self.release_target) |t| self.alloc.free(t);
        if (self.release_jump) |j| self.alloc.free(j);
        self.config.deinit(self.alloc);
        self.channels.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// Dispatch a state change to the embedder's `on_state`. Safe to
    /// call from any thread; the callback fires on the calling thread.
    ///
    /// Note: this is the low-level path used by code that has already
    /// constructed a fully-owned `State`. For broadcasts coming from
    /// the listener bridge (which carry a stack-resident host string in
    /// the PasswordPrompt case), use `emitStateFromConnectionState`
    /// instead so the host string gets copied into the handle-owned
    /// stable buffer.
    fn emitState(self: *SshHandle, state: State) void {
        self.state_kind.store(@intFromEnum(state.kind), .release);
        self.mutex.lock();
        const cb = self.callbacks.on_state;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| f(ud, &state);
    }

    /// Translate a `protocol.ConnectionState` and emit it to the
    /// embedder. Stashes the PasswordPrompt host string into the
    /// handle-owned `last_password_host` buffer under `mutex` (so
    /// concurrent password broadcasts can't tear the buffer) and
    /// rewrites `state.payload.password.host` to point at the stable
    /// storage. The mutex is released BEFORE firing the callback —
    /// the header contract allows embedders to call entry points
    /// (which take the same mutex) from inside on_state.
    ///
    /// Concurrent two-PASSWORD_REQUIRED-on-the-same-handle is impossible
    /// today because the manager's listener fan-out is serialized on
    /// the SSH thread (see broadcastConnectionState); the buffer race
    /// window is therefore mutex_lock..callback_dispatch, not the
    /// callback duration itself.
    fn emitStateFromConnectionState(
        self: *SshHandle,
        zig_state: protocol.ConnectionState,
    ) void {
        var state = translateState(zig_state);
        self.mutex.lock();
        const cb = self.callbacks.on_state;
        const ud = self.callbacks.userdata;
        if (state.kind == .password_required) {
            const prompt = zig_state.password_required;
            const src = prompt.host[0..prompt.host_len];
            const max = self.last_password_host.len - 1; // reserve NUL
            const n = @min(src.len, max);
            @memcpy(self.last_password_host[0..n], src[0..n]);
            self.last_password_host[n] = 0;
            self.last_password_host_len = @intCast(n);
            state.payload.password.host = @ptrCast(&self.last_password_host[0]);

            // Issue a fresh auth_token for this prompt. The previous
            // token (if any) is immediately invalidated by the
            // overwrite of `current_auth_token`, so a stale embedder
            // submitting an old token against the new prompt is
            // rejected. Skip zero to keep that reserved as an
            // "uninitialized" sentinel.
            if (self.next_auth_token == 0) self.next_auth_token = 1;
            const tok = self.next_auth_token;
            self.next_auth_token +%= 1;
            self.current_auth_token = tok;
            state.payload.password.auth_token = tok;
        }
        self.state_kind.store(@intFromEnum(state.kind), .release);
        self.mutex.unlock();
        if (cb) |f| f(ud, &state);
    }

    fn registerChannel(self: *SshHandle, ch: *ChannelHandle) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.channels.put(self.alloc, @intFromPtr(ch), ch);
    }

    fn unregisterChannel(self: *SshHandle, ch: *ChannelHandle) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.channels.swapRemove(@intFromPtr(ch));
    }

    /// Bridge from `SshConnectionManager.Entry`'s SshListener to the
    /// embedder's `on_state`. Translates the rich
    /// `protocol.ConnectionState` union into a flat
    /// `ghostty_ssh_state_t` and forwards via the stash-aware path so
    /// the PasswordPrompt host string survives the broadcaster's
    /// stack frame. Fires on the SSH thread per the listener-hook
    /// contract.
    fn onStateListener(ctx: *anyopaque, state: protocol.ConnectionState) void {
        const self: *SshHandle = @ptrCast(@alignCast(ctx));
        // Once closed, swallow late events — the listener is
        // unregistered in close() before we get here in steady state,
        // but a state already in flight on the SSH thread could race
        // past the unregister.
        if (self.closed.load(.acquire)) return;
        self.emitStateFromConnectionState(state);
    }
};

/// The runtime state behind a `ghostty_channel_t` handle.
pub const ChannelHandle = struct {
    alloc: Allocator,
    ssh: *SshHandle,
    service: ChannelService,
    callbacks: ChannelCallbacks,
    /// Guards `callbacks` and `state`.
    mutex: std.Thread.Mutex = .{},
    /// Lifecycle phase. Stored as u32 atomic so the close-after-free
    /// race window stays observable.
    state: std.atomic.Value(u32) = .{ .raw = @intFromEnum(ChannelState.opening) },
    /// True after the embedder has called ghostty_channel_close (or an
    /// on_close has been fired). Writes after this return SIZE_MAX.
    closed: std.atomic.Value(bool) = .{ .raw = false },
    /// channel_id allocated by the (future) client mux. Until the
    /// mux is wired this stays at `invalid_channel_id`.
    channel_id: u32 = protocol.invalid_channel_id,

    pub const ChannelState = enum(u32) {
        opening = 0,
        open = 1,
        local_eof = 2,
        closed_state = 3,
    };

    fn init(
        alloc: Allocator,
        ssh: *SshHandle,
        service: ChannelService,
        cbs: *const ChannelCallbacks,
    ) !*ChannelHandle {
        const self = try alloc.create(ChannelHandle);
        errdefer alloc.destroy(self);
        self.* = .{
            .alloc = alloc,
            .ssh = ssh,
            .service = service,
            .callbacks = cbs.*,
        };
        try ssh.registerChannel(self);
        return self;
    }

    fn deinit(self: *ChannelHandle) void {
        // De-register from parent first; the parent's destruction path
        // asserts the registry is empty.
        self.ssh.unregisterChannel(self);
        self.alloc.destroy(self);
    }

    /// Synchronously emit on_close to the embedder. Used by close +
    /// transport-loss paths. Idempotent.
    fn emitClose(self: *ChannelHandle, reason: ChannelCloseReason, message: ?[*:0]const u8) void {
        if (self.closed.swap(true, .acq_rel)) return;
        self.state.store(@intFromEnum(ChannelState.closed_state), .release);
        self.mutex.lock();
        const cb = self.callbacks.on_close;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| f(ud, reason, message);
    }
};

// =========================================================================
// Internal helpers — state translation, manager access.
// =========================================================================

/// Translate `protocol.ConnectionState` into the flat C `ghostty_ssh_state_t`.
/// PasswordPrompt currently surfaces `auth_token=0` because the
/// token-allocation plumbing lands with the password follow-up; embedders
/// can recognize a PASSWORD_REQUIRED transition today but must wait for
/// the follow-up before driving submit_password against a specific token.
fn translateState(state: protocol.ConnectionState) State {
    return switch (state) {
        .connecting => .{ .kind = .connecting, .payload = .{
            .password = std.mem.zeroes(StatePassword),
        } },
        .uploading => |u| .{ .kind = .uploading, .payload = .{ .upload = .{
            .bytes_sent = u.bytes_sent,
            .total_bytes = u.total_bytes,
            .source = ProvisionSource.fromZig(u.source),
        } } },
        .downloading => .{ .kind = .downloading, .payload = .{
            .password = std.mem.zeroes(StatePassword),
        } },
        .setup => .{ .kind = .setup, .payload = .{
            .password = std.mem.zeroes(StatePassword),
        } },
        .connected => .{ .kind = .connected, .payload = .{
            .password = std.mem.zeroes(StatePassword),
        } },
        .reconnecting => |r| .{ .kind = .reconnecting, .payload = .{ .reconnect = .{
            .attempt = r.attempt,
            .max_attempts = r.max_attempts,
            .elapsed_ns = @intCast(r.elapsed_ns),
            .next_retry_ns = @intCast(r.next_retry_ns),
        } } },
        .stale => .{ .kind = .stale, .payload = .{
            .password = std.mem.zeroes(StatePassword),
        } },
        .failed => |f| .{ .kind = .failed, .payload = .{ .fail = .{
            .reason = FailReason.fromZig(f),
            .message = null,
        } } },
        .disconnected => |d| .{ .kind = .disconnected, .payload = .{ .disconnect = .{
            .attempts_made = d.attempts_made,
            .reason = DisconnectReason.fromZig(d.reason),
        } } },
        .password_required => |p| .{ .kind = .password_required, .payload = .{ .password = .{
            .is_jump = p.is_jump,
            // The host pointer is NEVER set here — `&p.host` would dangle
            // the instant this switch prong's stack frame unwinds. The
            // caller (typically SshHandle.emitStateFromConnectionState)
            // stashes the bytes into a stable handle-owned buffer and
            // overlays the pointer before firing the embedder callback.
            .host = "",
            .auth_token = 0,
        } } },
    };
}

/// Resolve the SshConnectionManager from a ghostty_app_t (cast to
/// *apprt.embedded.App on import). Returns null in environments where
/// the embedded app isn't available (e.g. when invoked from a test
/// harness that doesn't construct a CoreApp).
fn managerFromAppPtr(app: ?*anyopaque) ?*SshConnectionManager {
    const app_ptr = app orelse return null;
    const embedded_app: *apprt_embedded.App = @ptrCast(@alignCast(app_ptr));
    return &embedded_app.core_app.ssh_connection_manager;
}

// =========================================================================
// C-ABI exports. These match the declarations in `include/ghostty.h`.
// =========================================================================

/// Implements `ghostty_ssh_open`.
export fn ghostty_ssh_open(
    app: ?*anyopaque, // ghostty_app_t — used to reach the shared SshConnectionManager
    config: ?*const Config,
    callbacks: ?*const SshCallbacks,
) ?*SshHandle {
    const cfg = config orelse {
        log.warn("ghostty_ssh_open: null config", .{});
        return null;
    };
    const cbs = callbacks orelse {
        log.warn("ghostty_ssh_open: null callbacks", .{});
        return null;
    };
    const handle = SshHandle.init(global.alloc, cfg, cbs) catch |err| {
        log.warn("ghostty_ssh_open: alloc failed: {}", .{err});
        return null;
    };
    errdefer handle.deinit();

    // Initial CONNECTING — fired before we touch the manager so the
    // embedder always sees this transition first, even if Entry
    // acquisition fails below.
    handle.emitState(.{ .kind = .connecting, .payload = .{
        .password = std.mem.zeroes(StatePassword),
    } });

    // Optional manager — embedders may pass null in test harnesses;
    // the handle is still usable as a state-machine driver against
    // the synthetic transitions we generate here.
    if (managerFromAppPtr(app)) |mgr| {
        const target_slice = std.mem.span(@as([*:0]const u8, handle.config.target));
        const jump_slice: ?[]const u8 = if (handle.config.jump) |j| std.mem.span(@as([*:0]const u8, j)) else null;

        const entry = mgr.acquire(target_slice, jump_slice) catch |err| {
            log.warn("ghostty_ssh_open: acquire failed: {}", .{err});
            handle.emitState(.{ .kind = .failed, .payload = .{ .fail = .{
                .reason = .unknown,
                .message = null,
            } } });
            return null;
        };

        // Cache the (target, jump) pair for the symmetric release in
        // close — entry.ctx fields are owned by SshContext and we
        // don't want to assume they survive a failed connect.
        handle.release_target = global.alloc.dupe(u8, target_slice) catch {
            mgr.release(target_slice, jump_slice);
            handle.emitState(.{ .kind = .failed, .payload = .{ .fail = .{
                .reason = .unknown,
                .message = null,
            } } });
            return null;
        };
        if (jump_slice) |j| {
            handle.release_jump = global.alloc.dupe(u8, j) catch {
                mgr.release(target_slice, jump_slice);
                handle.emitState(.{ .kind = .failed, .payload = .{ .fail = .{
                    .reason = .unknown,
                    .message = null,
                } } });
                return null;
            };
        }
        handle.manager = mgr;
        handle.entry = entry;

        // Apply reconnect-related config knobs. Surface attach is what
        // actually drives `setupConnection` today; the C-API doesn't
        // own that path, but the Entry-level knobs (interval, max
        // attempts) belong to the connection-pool level and must be
        // set before the first attach so reconnect respects them.
        if (cfg.max_reconnect_attempts != std.math.maxInt(u32)) {
            entry.max_reconnect_attempts = cfg.max_reconnect_attempts;
        }
        if (cfg.reconnect_interval_ms != 0) {
            entry.reconnect_interval_ms = cfg.reconnect_interval_ms;
        }
        if (cfg.scrollback_limit_bytes != 0) {
            entry.scrollback_limit = cfg.scrollback_limit_bytes;
        }

        // Register the listener AFTER the manager + entry are set up
        // so the very first replayed state is delivered through the
        // bridge with all pointers valid.
        SshConnectionManager.registerStateListener(entry, .{
            .ctx = handle,
            .on_state = SshHandle.onStateListener,
        }) catch |err| {
            log.warn("ghostty_ssh_open: registerStateListener failed: {}", .{err});
            mgr.release(target_slice, jump_slice);
            handle.manager = null;
            handle.entry = null;
            handle.emitState(.{ .kind = .failed, .payload = .{ .fail = .{
                .reason = .unknown,
                .message = null,
            } } });
            return null;
        };
        handle.listener_registered = true;
    }

    return handle;
}

/// Implements `ghostty_ssh_submit_password`. Validates the token
/// against the latest-prompt invariant under SshHandle.mutex, then
/// hands the password to the underlying `Entry.auth_state` so the
/// attachRemoteSurface helper's connectWithAuth loop can pick it up
/// and signal the condition variable. The password is duped + zeroed
/// using the same secure-zero discipline as the GTK overlay path.
export fn ghostty_ssh_submit_password(
    ssh: ?*SshHandle,
    auth_token: u64,
    password: ?[*:0]const u8,
) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse {
        log.debug("ghostty_ssh_submit_password: no entry (test handle?)", .{});
        return;
    };

    // Validate + consume the token under SshHandle.mutex. Reject
    // stale tokens silently — the embedder gets no error, but the
    // daemon's auth_state cond stays untouched, so the connection
    // remains parked on the new prompt.
    h.mutex.lock();
    const current = h.current_auth_token;
    const matches = current != null and current.? == auth_token;
    if (matches) h.current_auth_token = null;
    h.mutex.unlock();

    if (!matches) {
        log.debug("ghostty_ssh_submit_password: stale or invalid auth_token={d}", .{auth_token});
        return;
    }

    // Dup the password into the entry's allocator. The helper's
    // connectWithAuth loop secure-zeroes + frees it after consumption.
    const pwd_span = if (password) |p| std.mem.span(p) else "";
    const owned = entry.alloc.dupe(u8, pwd_span) catch |err| {
        log.warn("ghostty_ssh_submit_password: dup failed: {}", .{err});
        return;
    };

    entry.auth_state.mutex.lock();
    // If there's a stale leftover password (e.g. an earlier submit
    // raced past the consumer), secure-zero + free it so we don't
    // leak a credential.
    if (entry.auth_state.password) |old| {
        session_shared.secureZeroAndFree(entry.alloc, @constCast(old));
    }
    entry.auth_state.password = owned;
    entry.auth_state.cancelled = false;
    entry.auth_state.cond.signal();
    entry.auth_state.mutex.unlock();
}

/// Implements `ghostty_ssh_cancel_password`. Same token-validity
/// contract as submit_password: stale tokens are silently rejected.
/// On a current-token match this signals the daemon's auth_state so
/// the connectWithAuth loop wakes up and observes `cancelled = true`,
/// which transitions the connection to FAILED(AUTH_FAILED).
export fn ghostty_ssh_cancel_password(ssh: ?*SshHandle, auth_token: u64) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse return;

    h.mutex.lock();
    const current = h.current_auth_token;
    const matches = current != null and current.? == auth_token;
    if (matches) h.current_auth_token = null;
    h.mutex.unlock();

    if (!matches) {
        log.debug("ghostty_ssh_cancel_password: stale or invalid auth_token={d}", .{auth_token});
        return;
    }

    entry.auth_state.mutex.lock();
    entry.auth_state.cancelled = true;
    entry.auth_state.cond.signal();
    entry.auth_state.mutex.unlock();
}

/// Implements `ghostty_ssh_submit_host_key_decision`. No-op today:
/// the underlying `verifyHostKey` in src/session/ssh.zig auto-accepts
/// unknown keys via TOFU and does not surface an `on_host_key`
/// callback. When the prompt path lands (a redesign of verifyHostKey
/// to route through a callback rather than auto-pin), this routes the
/// embedder's accept/persist decision back to that callback by
/// `decision_token`.
export fn ghostty_ssh_submit_host_key_decision(
    ssh: ?*SshHandle,
    decision_token: u64,
    accept: bool,
    persist: bool,
) void {
    _ = ssh;
    _ = decision_token;
    _ = accept;
    _ = persist;
    log.debug("ghostty_ssh_submit_host_key_decision: TOFU auto-accept; no-op", .{});
}

/// Implements `ghostty_ssh_request_reconnect`. Routes to the
/// SshConnectionManager's atomic Retry-Now signal so a backed-off
/// reconnect loop fires immediately instead of finishing its sleep.
export fn ghostty_ssh_request_reconnect(ssh: ?*SshHandle) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse return;
    SshConnectionManager.requestReconnect(entry);
}

/// Implements `ghostty_ssh_cancel_reconnect`. Cancels in-flight
/// reconnect attempts; the manager then broadcasts
/// `DISCONNECTED(reason=cancelled)` which flows back through the
/// listener bridge.
export fn ghostty_ssh_cancel_reconnect(ssh: ?*SshHandle) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse return;
    SshConnectionManager.cancelReconnect(entry);
}

/// Implements `ghostty_ssh_close`. After this, channels are
/// transitioned to TRANSPORT-closed and new opens fail.
export fn ghostty_ssh_close(ssh: ?*SshHandle) void {
    const h = ssh orelse return;
    if (h.closed.swap(true, .acq_rel)) return;

    // Unregister the listener BEFORE we tear down channels so any
    // late state broadcasts from the SSH thread (e.g. as the Entry
    // notices the channel drop) don't race with the close cascade.
    if (h.listener_registered) {
        if (h.entry) |entry| {
            SshConnectionManager.unregisterStateListener(entry, h);
        }
        h.listener_registered = false;
    }

    // Snapshot the channel list under the mutex, then close each
    // outside the mutex (emitClose calls back into the embedder).
    // append() failures are intentionally swallowed: if we OOM here,
    // any channel we couldn't enqueue stays live, ghostty_ssh_free's
    // live-channels guard refuses to destroy the parent handle, and
    // the embedder sees a loud leak instead of a use-after-free.
    h.mutex.lock();
    var snapshot = std.ArrayList(*ChannelHandle).empty;
    defer snapshot.deinit(h.alloc);
    var it = h.channels.iterator();
    while (it.next()) |entry| snapshot.append(h.alloc, entry.value_ptr.*) catch {};
    h.mutex.unlock();

    for (snapshot.items) |ch| {
        ch.emitClose(.daemon_shutdown, null);
    }

    // Release the pool entry symmetrically with acquire. Use the
    // cached target/jump from open since entry.ctx may have been
    // partially torn down by a failed connect.
    if (h.manager) |mgr| {
        if (h.release_target) |t| {
            mgr.release(t, h.release_jump);
        }
        h.manager = null;
        h.entry = null;
    }

    h.emitState(.{ .kind = .disconnected, .payload = .{ .disconnect = .{
        .attempts_made = 0,
        .reason = .cancelled,
    } } });
}

/// Implements `ghostty_ssh_free`.
export fn ghostty_ssh_free(ssh: ?*SshHandle) void {
    const h = ssh orelse return;
    if (!h.closed.load(.acquire)) ghostty_ssh_close(h);

    // If background workers (e.g. ghostty_ssh_list_sessions) are
    // still in flight, refuse to free — they hold a *SshHandle and
    // would UAF on a hot-released handle. Embedders MUST keep the
    // handle alive until their on_entry(null) sentinel fires.
    const workers = h.active_workers.load(.acquire);
    if (workers != 0) {
        log.err(
            "ghostty_ssh_free: {d} in-flight worker(s) — refusing to free",
            .{workers},
        );
        if (builtin.mode == .Debug) std.debug.panic(
            "ghostty_ssh_free called with {d} in-flight workers",
            .{workers},
        );
        return;
    }

    // If channels are still live, the embedder violated the
    // contract. Refuse to free to avoid a use-after-free in their
    // callback; leak instead.
    h.mutex.lock();
    const live = h.channels.count();
    h.mutex.unlock();
    if (live != 0) {
        log.err(
            "ghostty_ssh_free: {d} live channel handle(s) — refusing to free",
            .{live},
        );
        if (builtin.mode == .Debug) std.debug.panic(
            "ghostty_ssh_free called with {d} live channels",
            .{live},
        );
        return;
    }
    h.deinit();
}

/// Implements `ghostty_ssh_open_channel`. Until the client-side mux
/// helper lands (TODO(client-mux)), this returns a handle that
/// immediately reports on_close(SERVICE_ERROR, "client mux not wired").
export fn ghostty_ssh_open_channel(
    ssh: ?*SshHandle,
    service: ChannelService,
    params: ?*const anyopaque,
    params_len: usize,
    callbacks: ?*const ChannelCallbacks,
) ?*ChannelHandle {
    _ = params;
    _ = params_len;
    const h = ssh orelse return null;
    const cbs = callbacks orelse return null;
    if (h.closed.load(.acquire)) return null;

    const ch = ChannelHandle.init(h.alloc, h, service, cbs) catch |err| {
        log.warn("ghostty_ssh_open_channel: alloc failed: {}", .{err});
        return null;
    };

    // Synthesize an immediate failure until the mux is wired so
    // embedders' code paths exercise the on_close edge.
    ch.emitClose(.service_error, null);
    return ch;
}

/// Implements `ghostty_channel_write`.
export fn ghostty_channel_write(
    channel: ?*ChannelHandle,
    bytes: ?*const anyopaque,
    len: usize,
) usize {
    _ = bytes;
    const ch = channel orelse return std.math.maxInt(usize);
    if (ch.closed.load(.acquire)) return std.math.maxInt(usize);
    if (len == 0) return 0;
    // TODO(client-mux): real credit-based write path will hand off to
    // ClientMux.writeChannel(ch.channel_id, bytes[0..len]) and return
    // the number of bytes accepted. For now, every non-empty write
    // reports terminal failure (SIZE_MAX, per the header contract:
    // "channel closed; caller should expect on_close shortly"). This
    // pairs with the synthetic on_close(SERVICE_ERROR) fired from
    // ghostty_ssh_open_channel so embedders see the channel is dead
    // immediately instead of parking on credit that will never arrive.
    return std.math.maxInt(usize);
}

/// Implements `ghostty_channel_eof`.
export fn ghostty_channel_eof(channel: ?*ChannelHandle) void {
    const ch = channel orelse return;
    if (ch.closed.load(.acquire)) return;
    // TODO(client-mux): ClientMux.channelEof(ch.channel_id)
    ch.state.store(@intFromEnum(ChannelHandle.ChannelState.local_eof), .release);
}

/// Implements `ghostty_channel_close`.
export fn ghostty_channel_close(
    channel: ?*ChannelHandle,
    reason: ChannelCloseReason,
) void {
    const ch = channel orelse return;
    // TODO(client-mux): emit channel_close frame via ClientMux.
    // The `message` arg to emitClose is NULL today; round-tripping a
    // reason string from the embedder + back through on_close is a
    // follow-up alongside the real channel_close-frame plumbing.
    ch.emitClose(reason, null);
}

/// Implements `ghostty_channel_free`.
export fn ghostty_channel_free(channel: ?*ChannelHandle) void {
    const ch = channel orelse return;
    if (!ch.closed.load(.acquire)) ch.emitClose(.normal, null);
    ch.deinit();
}

/// Implements `ghostty_ssh_attach_surface`. Terminal channels are
/// sugar over the legacy session-protocol frames; the channel handle
/// shape is identical to non-terminal channels for embedder
/// uniformity (per the design doc).
///
/// Part 3 (this commit) plumbs the shared
/// `session.client.attachRemoteSurface` helper for the eventual
/// real-attach path: when a manager + entry are available we know
/// how to drive the helper, the only missing piece is the worker-
/// thread spawn so the call doesn't block the embedder. That spawn
/// — together with the post-attach frame-dispatch routing to the
/// channel callbacks — is the channel-mux follow-up that arrives
/// once port-listener's ClientMux lands. Until then the handle
/// still emits an immediate on_close(SERVICE_ERROR) so embedders
/// exercise that edge.
export fn ghostty_ssh_attach_surface(
    ssh: ?*SshHandle,
    group_id: ?[*]const u8,
    surface_id: ?[*]const u8,
    rows: u16,
    cols: u16,
    width_px: u32,
    height_px: u32,
    label: ?[*:0]const u8,
    callbacks: ?*const ChannelCallbacks,
) ?*ChannelHandle {
    _ = group_id;
    _ = surface_id;
    _ = rows;
    _ = cols;
    _ = width_px;
    _ = height_px;
    _ = label;
    const h = ssh orelse return null;
    const cbs = callbacks orelse return null;
    if (h.closed.load(.acquire)) return null;

    const ch = ChannelHandle.init(h.alloc, h, .terminal, cbs) catch |err| {
        log.warn("ghostty_ssh_attach_surface: alloc failed: {}", .{err});
        return null;
    };

    // TODO(client-mux): when client-mux + worker-thread spawn land,
    // call session.client.attachRemoteSurface from a worker:
    //
    //   if (h.manager) |mgr| if (h.entry) |entry| {
    //       _ = std.Thread.spawn(.{}, attachWorker, .{ ch, mgr, entry, .{...} }) catch …;
    //   }
    //
    // For now the call would block the embedder, so we synthesize
    // an immediate failure so the on_close edge stays observable.
    ch.emitClose(.service_error, null);
    return ch;
}

/// Implements `ghostty_ssh_list_sessions`. Spawns a worker thread
/// that calls `SshConnectionManager.querySessions` (blocking, with a
/// 5 s timeout), parses the binary `ListResponse`, and fires the
/// embedder's `on_entry` once per session followed by a NULL
/// sentinel. Returns true if the query was kicked off, false if the
/// handle isn't ready (no entry, closed, etc.). The embedder MUST
/// keep the handle alive until the sentinel arrives — see
/// `ghostty_ssh_free`'s active-workers guard.
export fn ghostty_ssh_list_sessions(
    ssh: ?*SshHandle,
    on_entry: ?*const fn (userdata: ?*anyopaque, entry: ?*const SessionEntry) callconv(.c) void,
    userdata: ?*anyopaque,
) bool {
    const h = ssh orelse return false;
    if (h.closed.load(.acquire)) return false;
    const entry = h.entry orelse return false;

    // Refuse queries while the connection isn't ready — the
    // querySessions write would just time out anyway, and we want
    // an immediate observable "not ready" signal for the embedder.
    if (entry.conn_state.load(.acquire) != .ready) return false;

    const cb = on_entry orelse return false;

    const Worker = struct {
        handle: *SshHandle,
        entry: *SshConnectionManager.Entry,
        cb: *const fn (userdata: ?*anyopaque, entry: ?*const SessionEntry) callconv(.c) void,
        userdata: ?*anyopaque,

        fn run(self: *@This()) void {
            defer {
                // Read self.handle.alloc BEFORE decrementing active_workers:
                // once the counter drops to 0, the embedder may race us to
                // ghostty_ssh_free (which acquire-loads active_workers and
                // proceeds to destroy the SshHandle when it sees 0), so any
                // subsequent dereference of self.handle.* would be a UAF.
                // Allocator is a value type — capturing by value is safe.
                const alloc = self.handle.alloc;
                _ = self.handle.active_workers.fetchSub(1, .acq_rel);
                alloc.destroy(self);
            }

            const alloc = self.handle.alloc;
            const raw = SshConnectionManager.querySessions(self.entry, alloc, 5000) orelse {
                // No data → fire the sentinel so the embedder can
                // distinguish "empty list" from "query rejected".
                self.cb(self.userdata, null);
                return;
            };
            defer alloc.free(raw);

            const parsed = protocol.ListResponse.parse(alloc, raw) catch {
                self.cb(self.userdata, null);
                return;
            };
            defer alloc.free(parsed);

            for (parsed) |list_entry| {
                // SessionEntry.label is a [*:0]const u8 — we need a
                // local NUL-terminated copy that lives at least
                // through the callback's duration.
                var label_buf: [256]u8 = undefined;
                const lbl_len = @min(list_entry.label.len, label_buf.len - 1);
                @memcpy(label_buf[0..lbl_len], list_entry.label[0..lbl_len]);
                label_buf[lbl_len] = 0;

                const se = SessionEntry{
                    .group_id = &list_entry.group_id,
                    .label = @ptrCast(&label_buf[0]),
                    .surface_count = list_entry.surface_count,
                    .created_at_ns = list_entry.created_at,
                };
                self.cb(self.userdata, &se);
            }

            // Sentinel.
            self.cb(self.userdata, null);
        }
    };

    const worker = h.alloc.create(Worker) catch return false;
    worker.* = .{
        .handle = h,
        .entry = entry,
        .cb = cb,
        .userdata = userdata,
    };

    _ = h.active_workers.fetchAdd(1, .acq_rel);
    const thread = std.Thread.spawn(.{}, Worker.run, .{worker}) catch {
        _ = h.active_workers.fetchSub(1, .acq_rel);
        h.alloc.destroy(worker);
        return false;
    };
    thread.detach();
    return true;
}

/// Implements `ghostty_ssh_rename_session`. Enqueues a `.rename`
/// frame on the live SSH connection with `RenameScope.group` so the
/// daemon updates the session-level label. The frame is sent
/// asynchronously via the existing write queue; embedders that need
/// confirmation should observe the daemon's subsequent
/// `viewer_state(name_change)` broadcast.
export fn ghostty_ssh_rename_session(
    ssh: ?*SshHandle,
    group_id: ?[*]const u8,
    label: ?[*:0]const u8,
) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse return;
    const gid_ptr = group_id orelse return;
    const lbl_span: []const u8 = if (label) |p| std.mem.span(p) else "";

    var gid_buf: protocol.Uuid = undefined;
    @memcpy(&gid_buf, gid_ptr[0..protocol.uuid_size]);

    const payload = (protocol.Rename{
        .scope = .group,
        .id = gid_buf,
        .label = lbl_span,
    }).encode(entry.alloc) catch |err| {
        log.warn("ghostty_ssh_rename_session: encode failed: {}", .{err});
        return;
    };
    defer entry.alloc.free(payload);
    // enqueueWrite duplicates the payload onto the write queue —
    // free is safe immediately afterwards.
    SshConnectionManager.enqueueWrite(entry, .rename, 0, payload);
}

/// Implements `ghostty_ssh_kill_session`. Sends a `.close` frame
/// with `CloseMode.session` — the daemon kills all surfaces in the
/// matching group. Embedders observe the dead session via a
/// subsequent `list_sessions` query (the daemon does not broadcast
/// session deaths on the live connection).
export fn ghostty_ssh_kill_session(ssh: ?*SshHandle, group_id: ?[*]const u8) void {
    const h = ssh orelse return;
    if (h.closed.load(.acquire)) return;
    const entry = h.entry orelse return;
    const gid_ptr = group_id orelse return;

    var gid_buf: protocol.Uuid = undefined;
    @memcpy(&gid_buf, gid_ptr[0..protocol.uuid_size]);

    const payload = (protocol.Close{
        .mode = .session,
        .id = gid_buf,
    }).encode(entry.alloc) catch |err| {
        log.warn("ghostty_ssh_kill_session: encode failed: {}", .{err});
        return;
    };
    defer entry.alloc.free(payload);
    SshConnectionManager.enqueueWrite(entry, .close, 0, payload);
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

/// In-process test harness: takes the place of the embedder. Captures
/// the most recent state + close callbacks so tests can assert on
/// observed transitions.
const Capture = struct {
    last_state_kind: ?StateKind = null,
    last_close_reason: ?ChannelCloseReason = null,
    /// Inline copy of the most recent state.payload.password.host
    /// observed at on_state time. Test code can assert that the
    /// bytes survived the broadcaster's stack frame by reading from
    /// here AFTER on_state has returned + further stack frames have
    /// been pushed and popped.
    last_password_host_copy: [128]u8 = [_]u8{0} ** 128,
    last_password_host_len: usize = 0,

    fn onState(ud: ?*anyopaque, st: *const State) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(ud.?));
        self.last_state_kind = st.kind;
        if (st.kind == .password_required) {
            const span = std.mem.span(st.payload.password.host);
            const n = @min(span.len, self.last_password_host_copy.len);
            @memcpy(self.last_password_host_copy[0..n], span[0..n]);
            self.last_password_host_len = n;
        }
    }

    fn onClose(
        ud: ?*anyopaque,
        reason: ChannelCloseReason,
        _: ?[*:0]const u8,
    ) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(ud.?));
        self.last_close_reason = reason;
    }

    fn cbs(self: *Capture) SshCallbacks {
        return .{
            .on_state = onState,
            .on_host_key = null,
            .userdata = self,
        };
    }

    fn chCbs(self: *Capture) ChannelCallbacks {
        return .{
            .on_opened = null,
            .on_data = null,
            .on_window_credit = null,
            .on_eof = null,
            .on_close = onClose,
            .userdata = self,
        };
    }
};

test "ghostty_ssh_open returns a handle and emits initial CONNECTING" {
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs);
    try testing.expect(handle != null);
    defer ghostty_ssh_free(handle);

    try testing.expectEqual(@as(?StateKind, .connecting), cap.last_state_kind);
}

test "ghostty_ssh_open with null config returns null" {
    var cap: Capture = .{};
    const ssh_cbs = cap.cbs();
    try testing.expect(ghostty_ssh_open(null, null, &ssh_cbs) == null);
}

test "ghostty_ssh_open with null callbacks returns null" {
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    try testing.expect(ghostty_ssh_open(null, &cfg, null) == null);
}

test "ghostty_ssh_open_channel synthesizes a close until mux wires" {
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    const ch_cbs = cap.chCbs();
    const ch = ghostty_ssh_open_channel(handle, .tcp_connect, null, 0, &ch_cbs);
    try testing.expect(ch != null);
    try testing.expectEqual(@as(?ChannelCloseReason, .service_error), cap.last_close_reason);

    // After the stub close, free still works.
    ghostty_channel_free(ch);
}

test "ghostty_ssh_attach_surface — stub round-trip and initial state" {
    // Phase 6B.1 Part 3 stub-path coverage. With no real CoreApp
    // (app=null), ghostty_ssh_open emits the synchronous CONNECTING
    // transition, attach_surface allocates the terminal channel
    // handle, and the synthetic on_close(SERVICE_ERROR) keeps the
    // edge observable until the channel-mux follow-up lands.
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    try testing.expectEqual(@as(?StateKind, .connecting), cap.last_state_kind);

    var ch_cap: Capture = .{};
    const ch_cbs = ch_cap.chCbs();
    const ch = ghostty_ssh_attach_surface(
        handle,
        null, // group_id
        null, // surface_id
        24, // rows
        80, // cols
        640, // width_px
        480, // height_px
        "test-session", // label
        &ch_cbs,
    );
    try testing.expect(ch != null);
    try testing.expectEqual(@as(?ChannelCloseReason, .service_error), ch_cap.last_close_reason);

    // Channel handle must be release-safe after the synthetic close.
    ghostty_channel_free(ch);
}

test "ghostty_ssh_attach_surface — rejects null callbacks" {
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    try testing.expect(ghostty_ssh_attach_surface(
        handle,
        null,
        null,
        24,
        80,
        640,
        480,
        null,
        null,
    ) == null);
}

test "ghostty_channel_write returns SIZE_MAX on the stubbed mux path" {
    // While the client-mux is stubbed, non-empty writes MUST report
    // terminal failure (SIZE_MAX) instead of silently parking the
    // caller on credit that will never arrive. Empty writes (len=0)
    // still succeed as a no-op for embedder convenience.
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    const ch_cbs = cap.chCbs();
    const ch = ghostty_ssh_open_channel(handle, .tcp_connect, null, 0, &ch_cbs).?;
    defer ghostty_channel_free(ch);

    // Channel was closed during open; write must report SIZE_MAX
    // for both empty and non-empty writes — the closed check fires
    // first and is the dominant signal an embedder needs.
    const payload = "hi";
    try testing.expectEqual(std.math.maxInt(usize), ghostty_channel_write(
        ch,
        payload.ptr,
        payload.len,
    ));
    try testing.expectEqual(std.math.maxInt(usize), ghostty_channel_write(ch, null, 0));
}

test "ghostty_channel_write on null handle is a terminal error" {
    try testing.expectEqual(std.math.maxInt(usize), ghostty_channel_write(null, null, 0));
    const payload = "hi";
    try testing.expectEqual(std.math.maxInt(usize), ghostty_channel_write(
        null,
        payload.ptr,
        payload.len,
    ));
}

test "ghostty_ssh_close closes live channels before freeing" {
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;

    // Need a separate capture for the channel so the SshHandle close
    // path can observe the channel close it generates.
    var ch_cap: Capture = .{};
    const ch_cbs = ch_cap.chCbs();
    const ch = ghostty_ssh_open_channel(handle, .tcp_connect, null, 0, &ch_cbs).?;
    // Stub path emitted SERVICE_ERROR immediately — reset so we can
    // observe the daemon_shutdown from ssh_close.
    ch_cap.last_close_reason = null;

    ghostty_ssh_close(handle);
    // Channel was already closed by open stub, so close() is a no-op
    // for that handle. The state transition should have happened.
    try testing.expectEqual(@as(?StateKind, .disconnected), cap.last_state_kind);

    ghostty_channel_free(ch);
    ghostty_ssh_free(handle);
}

test "OwnedConfig duplicates string fields" {
    var buf_target = [_:0]u8{ 'u', '@', 'h', 0 };
    var buf_jump = [_:0]u8{ 'j', '@', 'k', 0 };
    const cfg = Config{
        .target = &buf_target,
        .jump = &buf_jump,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };

    var owned = try OwnedConfig.fromC(testing.allocator, &cfg);
    defer owned.deinit(testing.allocator);

    // Mutate the original buffers — the owned copy must be unaffected.
    buf_target[0] = 'X';
    buf_jump[0] = 'X';
    try testing.expectEqualStrings("u@h", owned.target);
    try testing.expectEqualStrings("j@k", owned.jump.?);
}

test "translateState — simple variants map to the right kind" {
    try testing.expectEqual(StateKind.connecting, translateState(.connecting).kind);
    try testing.expectEqual(StateKind.downloading, translateState(.downloading).kind);
    try testing.expectEqual(StateKind.setup, translateState(.setup).kind);
    try testing.expectEqual(StateKind.connected, translateState(.connected).kind);
    try testing.expectEqual(StateKind.stale, translateState(.stale).kind);
}

test "translateState — uploading payload carries progress" {
    const s = translateState(.{ .uploading = .{
        .bytes_sent = 1024,
        .total_bytes = 4096,
        .source = .github,
    } });
    try testing.expectEqual(StateKind.uploading, s.kind);
    try testing.expectEqual(@as(u64, 1024), s.payload.upload.bytes_sent);
    try testing.expectEqual(@as(u64, 4096), s.payload.upload.total_bytes);
    try testing.expectEqual(ProvisionSource.github, s.payload.upload.source);
}

test "translateState — reconnect payload carries attempt + timing" {
    const s = translateState(.{ .reconnecting = .{
        .attempt = 2,
        .max_attempts = 5,
        .elapsed_ns = 1_500_000_000,
        .next_retry_ns = 3_000_000_000,
    } });
    try testing.expectEqual(StateKind.reconnecting, s.kind);
    try testing.expectEqual(@as(u32, 2), s.payload.reconnect.attempt);
    try testing.expectEqual(@as(u32, 5), s.payload.reconnect.max_attempts);
    try testing.expectEqual(@as(i64, 1_500_000_000), s.payload.reconnect.elapsed_ns);
    try testing.expectEqual(@as(i64, 3_000_000_000), s.payload.reconnect.next_retry_ns);
}

test "translateState — failed payload carries reason" {
    const s = translateState(.{ .failed = .auth_failed });
    try testing.expectEqual(StateKind.failed, s.kind);
    try testing.expectEqual(FailReason.auth_failed, s.payload.fail.reason);
}

test "translateState — disconnected payload carries reason + attempts" {
    const s = translateState(.{ .disconnected = .{
        .attempts_made = 3,
        .reason = .exhausted,
    } });
    try testing.expectEqual(StateKind.disconnected, s.kind);
    try testing.expectEqual(@as(u32, 3), s.payload.disconnect.attempts_made);
    try testing.expectEqual(DisconnectReason.exhausted, s.payload.disconnect.reason);
}

test "translateState — password_required carries is_jump and a zero host" {
    // translateState intentionally returns a state with `host = ""`
    // for password_required — the host pointer would otherwise dangle
    // into the input's stack frame the moment translateState returns.
    // The stable-buffer copy lives in SshHandle.emitStateFromConnectionState;
    // see the next test for end-to-end coverage.
    var prompt: protocol.ConnectionState.PasswordPrompt = .{
        .is_jump = true,
        .auth_state = null,
    };
    prompt.setHost("user@bastion.example");
    const s = translateState(.{ .password_required = prompt });
    try testing.expectEqual(StateKind.password_required, s.kind);
    try testing.expect(s.payload.password.is_jump);
    // host pointer should reference an empty NUL-terminated string,
    // NOT &prompt.host (which is dead after translateState returns).
    try testing.expectEqualStrings("", std.mem.span(s.payload.password.host));
}

test "emitStateFromConnectionState — host bytes survive stack reuse" {
    // Regression for the dangling-host-pointer bug: drive a
    // password_required broadcast through the listener bridge, then
    // push and pop a noisy stack frame BEFORE asserting on the host
    // bytes. If the bug ever re-appears (host pointer aliases the
    // broadcaster's stack), Capture.last_password_host_copy will
    // contain whatever overwrote the dead frame.
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    // Helper that simulates a broadcast call frame: build a prompt
    // on its OWN stack frame, fire emitStateFromConnectionState,
    // then return. By the time the helper returns, prompt.host's
    // backing storage is reclaimable.
    const Driver = struct {
        fn fire(h: *SshHandle) void {
            var prompt: protocol.ConnectionState.PasswordPrompt = .{
                .is_jump = true,
                .auth_state = null,
            };
            prompt.setHost("user@bastion.example");
            h.emitStateFromConnectionState(.{ .password_required = prompt });
        }
        fn noise() void {
            // Push a sizable stack frame and write distinctive
            // bytes into it. If the embedder's host pointer were
            // pointing into the prior frame, this would clobber it.
            var clobber: [8192]u8 = undefined;
            @memset(&clobber, 0xAB);
            std.mem.doNotOptimizeAway(&clobber);
        }
    };

    Driver.fire(handle);
    Driver.noise();

    try testing.expectEqual(@as(?StateKind, .password_required), cap.last_state_kind);
    try testing.expectEqualStrings(
        "user@bastion.example",
        cap.last_password_host_copy[0..cap.last_password_host_len],
    );

    // Buffer must remain valid until the next password_required —
    // emitting an intervening state (e.g. CONNECTED) must NOT clear
    // the host bytes.
    handle.emitStateFromConnectionState(.connected);
    try testing.expectEqualStrings(
        "user@bastion.example",
        handle.last_password_host[0..handle.last_password_host_len],
    );

    // A new password_required overwrites the buffer.
    const Driver2 = struct {
        fn fire(h: *SshHandle) void {
            var prompt: protocol.ConnectionState.PasswordPrompt = .{
                .is_jump = false,
                .auth_state = null,
            };
            prompt.setHost("deploy@target");
            h.emitStateFromConnectionState(.{ .password_required = prompt });
        }
    };
    Driver2.fire(handle);
    try testing.expectEqualStrings(
        "deploy@target",
        cap.last_password_host_copy[0..cap.last_password_host_len],
    );
}

test "ChannelCloseReason.fromProtocol maps protocol codes" {
    try testing.expectEqual(ChannelCloseReason.normal, ChannelCloseReason.fromProtocol(.normal));
    try testing.expectEqual(ChannelCloseReason.peer_reset, ChannelCloseReason.fromProtocol(.peer_reset));
    try testing.expectEqual(ChannelCloseReason.service_error, ChannelCloseReason.fromProtocol(.service_error));
    try testing.expectEqual(ChannelCloseReason.policy_denied, ChannelCloseReason.fromProtocol(.policy_denied));
    try testing.expectEqual(ChannelCloseReason.idle_timeout, ChannelCloseReason.fromProtocol(.idle_timeout));
    try testing.expectEqual(ChannelCloseReason.daemon_shutdown, ChannelCloseReason.fromProtocol(.daemon_shutdown));
    // Unknown protocol value maps to .unknown via the `_` arm.
    try testing.expectEqual(ChannelCloseReason.unknown, ChannelCloseReason.fromProtocol(@enumFromInt(99)));
}

test "SshHandle.onStateListener forwards through translateState" {
    // Build a handle in test-mode (no manager). The listener bridge is
    // a pure function of (handle.closed, callbacks, state) — we drive
    // it directly to verify the translation arrives at the embedder.
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    // After open, last_state_kind is CONNECTING (the synchronous
    // initial emit). Drive the listener directly with each rich state
    // and verify the kind makes it through translation.
    SshHandle.onStateListener(handle, .setup);
    try testing.expectEqual(@as(?StateKind, .setup), cap.last_state_kind);

    SshHandle.onStateListener(handle, .{ .reconnecting = .{
        .attempt = 1,
        .max_attempts = 5,
        .elapsed_ns = 0,
        .next_retry_ns = 0,
    } });
    try testing.expectEqual(@as(?StateKind, .reconnecting), cap.last_state_kind);

    SshHandle.onStateListener(handle, .connected);
    try testing.expectEqual(@as(?StateKind, .connected), cap.last_state_kind);
}

test "SshHandle.onStateListener swallows events after close" {
    var cap: Capture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    ghostty_ssh_close(handle);
    // close() emitted DISCONNECTED — record it.
    try testing.expectEqual(@as(?StateKind, .disconnected), cap.last_state_kind);

    // Now any late listener event must be ignored.
    cap.last_state_kind = null;
    SshHandle.onStateListener(handle, .connected);
    try testing.expect(cap.last_state_kind == null);

    ghostty_ssh_free(handle);
}

// =========================================================================
// Part 4 tests — auth-token allocation, submit/cancel validity rules.
// =========================================================================

/// Capture variant for password tests — records the auth_token value
/// observed at on_state time so the test can drive
/// submit/cancel_password back through the C API.
const PasswordCapture = struct {
    last_state_kind: ?StateKind = null,
    last_auth_token: u64 = 0,
    last_host_copy: [128]u8 = [_]u8{0} ** 128,
    last_host_len: usize = 0,

    fn onState(ud: ?*anyopaque, st: *const State) callconv(.c) void {
        const self: *PasswordCapture = @ptrCast(@alignCast(ud.?));
        self.last_state_kind = st.kind;
        if (st.kind == .password_required) {
            self.last_auth_token = st.payload.password.auth_token;
            const span = std.mem.span(st.payload.password.host);
            const n = @min(span.len, self.last_host_copy.len);
            @memcpy(self.last_host_copy[0..n], span[0..n]);
            self.last_host_len = n;
        }
    }

    fn cbs(self: *PasswordCapture) SshCallbacks {
        return .{
            .on_state = onState,
            .on_host_key = null,
            .userdata = self,
        };
    }
};

/// Build a PasswordPrompt with the given host + jump-bit. Used by
/// the auth-token tests to drive emitStateFromConnectionState
/// without a live SSH connection.
fn buildPrompt(host: []const u8, is_jump: bool) protocol.ConnectionState.PasswordPrompt {
    var p: protocol.ConnectionState.PasswordPrompt = .{
        .is_jump = is_jump,
        .auth_state = null,
    };
    p.setHost(host);
    return p;
}

test "auth token — issued per PASSWORD_REQUIRED, monotonic, invalidates prior" {
    var cap: PasswordCapture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@target", false) });
    const t1 = cap.last_auth_token;
    try testing.expect(t1 != 0);
    try testing.expectEqual(t1, handle.current_auth_token.?);

    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@bastion", true) });
    const t2 = cap.last_auth_token;
    try testing.expect(t2 != 0);
    try testing.expect(t2 != t1);
    try testing.expectEqual(t2, handle.current_auth_token.?);
}

/// Heap-allocate a freshly-defaulted Entry suitable for token-
/// validation tests that need to reach the entry.auth_state path.
/// The Entry's ssh_thread / channel / pipes are all left at defaults,
/// so the helper never crosses into libssh2 land. Caller frees via
/// `freeEntryFixture`.
fn newEntryFixture(alloc: Allocator) !*SshConnectionManager.Entry {
    const entry = try alloc.create(SshConnectionManager.Entry);
    entry.* = .{
        .alloc = alloc,
        .ctx = .{
            .alloc = alloc,
            .ssh_target = "",
            .jump = null,
        },
        .remote_bin_path = &.{},
        .ref_count = 1,
        .sessions = std.AutoArrayHashMap(SshConnectionManager.Uuid, *SshConnectionManager.Session).init(alloc),
    };
    return entry;
}

fn freeEntryFixture(alloc: Allocator, entry: *SshConnectionManager.Entry) void {
    // Match the partial-teardown that `release` does for a fixture
    // that never reached the channel/thread states. ssh_listeners
    // may be empty; deinit is still required to match
    // SshConnectionManager.release behavior.
    entry.ssh_listeners.deinit(entry.alloc);
    if (entry.auth_state.password) |pw| {
        session_shared.secureZeroAndFree(entry.alloc, @constCast(pw));
        entry.auth_state.password = null;
    }
    entry.sessions.deinit();
    alloc.destroy(entry);
}

test "submit_password — current token reaches entry.auth_state" {
    var cap: PasswordCapture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    const entry = try newEntryFixture(testing.allocator);
    defer freeEntryFixture(testing.allocator, entry);
    handle.entry = entry;
    defer handle.entry = null;

    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@target", false) });
    const tok = cap.last_auth_token;
    try testing.expect(tok != 0);

    ghostty_ssh_submit_password(handle, tok, "hunter2");

    // Password should be on the auth_state, NUL-free (raw bytes),
    // dupe via entry.alloc. Cancelled flag must NOT be set.
    entry.auth_state.mutex.lock();
    defer entry.auth_state.mutex.unlock();
    try testing.expect(entry.auth_state.password != null);
    try testing.expectEqualStrings("hunter2", entry.auth_state.password.?);
    try testing.expect(!entry.auth_state.cancelled);

    // Token must be consumed: current_auth_token cleared.
    try testing.expect(handle.current_auth_token == null);
}

test "submit_password — stale token after new PASSWORD_REQUIRED is rejected" {
    var cap: PasswordCapture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    const entry = try newEntryFixture(testing.allocator);
    defer freeEntryFixture(testing.allocator, entry);
    handle.entry = entry;
    defer handle.entry = null;

    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@target", false) });
    const stale = cap.last_auth_token;
    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@bastion", true) });
    const current = cap.last_auth_token;
    try testing.expect(stale != current);

    ghostty_ssh_submit_password(handle, stale, "wrong-password");
    // Stale submission must NOT have touched auth_state.password.
    entry.auth_state.mutex.lock();
    try testing.expect(entry.auth_state.password == null);
    try testing.expect(!entry.auth_state.cancelled);
    entry.auth_state.mutex.unlock();
    // Current token must still be live for a follow-up submit.
    try testing.expectEqual(current, handle.current_auth_token.?);

    // Submitting against the current token now succeeds.
    ghostty_ssh_submit_password(handle, current, "right-password");
    entry.auth_state.mutex.lock();
    try testing.expectEqualStrings("right-password", entry.auth_state.password.?);
    entry.auth_state.mutex.unlock();
}

test "cancel_password — current token sets cancelled, stale is rejected" {
    var cap: PasswordCapture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);

    const entry = try newEntryFixture(testing.allocator);
    defer freeEntryFixture(testing.allocator, entry);
    handle.entry = entry;
    defer handle.entry = null;

    handle.emitStateFromConnectionState(.{ .password_required = buildPrompt("user@target", false) });
    const tok1 = cap.last_auth_token;

    // Cancel with a wrong token → must NOT flip cancelled.
    ghostty_ssh_cancel_password(handle, tok1 +% 999);
    entry.auth_state.mutex.lock();
    try testing.expect(!entry.auth_state.cancelled);
    entry.auth_state.mutex.unlock();
    try testing.expectEqual(tok1, handle.current_auth_token.?);

    // Cancel with the current token → cancelled flag is set; token consumed.
    ghostty_ssh_cancel_password(handle, tok1);
    entry.auth_state.mutex.lock();
    try testing.expect(entry.auth_state.cancelled);
    entry.auth_state.mutex.unlock();
    try testing.expect(handle.current_auth_token == null);

    // A second cancel with the now-stale token must be a no-op
    // (it's already invalidated). cancelled stays true.
    ghostty_ssh_cancel_password(handle, tok1);
    entry.auth_state.mutex.lock();
    try testing.expect(entry.auth_state.cancelled);
    entry.auth_state.mutex.unlock();
}

test "submit_password / cancel_password — no-op without an entry" {
    var cap: PasswordCapture = .{};
    const cfg = Config{
        .target = "alice@example.com",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = ghostty_ssh_open(null, &cfg, &ssh_cbs).?;
    defer ghostty_ssh_free(handle);
    // No entry attached — both calls must early-return without crashing.
    ghostty_ssh_submit_password(handle, 1, "ignored");
    ghostty_ssh_cancel_password(handle, 1);
}
