//! C-API glue for the libghostty SSH connection + channel multiplexing
//! surface declared in `include/ghostty.h` (see "SSH connection +
//! channel multiplexing API" section). Phase 6B.1 lays down the
//! handle layout, the extern C entry points, and the buffer/callback
//! plumbing. The actual transport wiring — driving
//! `SshConnectionManager` for connection lifecycle and a per-Entry
//! client-side channel mux for the channel ops — is gated on:
//!
//!   * A state-listener hook on `SshConnectionManager.Entry` so the
//!     C API can subscribe to connection-state transitions without
//!     piggybacking on per-surface mailboxes (the existing fan-out).
//!     Tracked as TODO(state-listener).
//!   * A client-side channel mux helper in `src/session/` that owns
//!     the outbound `channel_open` / inbound `channel_opened`
//!     state machine the daemon-side `Mux` doesn't provide.
//!     Tracked as TODO(client-mux).
//!
//! Until both land, the entry points either return a handle that
//! reports CONNECTING + FAILED(unknown) (so embedders can exercise
//! their state-machine wrapper) or no-op with a log message.
//!
//! Threading & ownership rules (mirrors the contract documented in
//! include/ghostty.h):
//!
//!   * Every exported function is non-blocking and may be called from
//!     any thread.
//!   * Callbacks fire on libghostty-owned worker threads. The handle
//!     holds the callback set behind a small spinlock so submit_*
//!     calls from inside a callback are safe.
//!   * Buffers passed in are copied; buffers handed to callbacks are
//!     borrowed for the callback duration.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const protocol = @import("../../session/protocol.zig");

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
    /// Live channels rooted on this connection. Used to validate the
    /// "free channels before ssh" invariant and to broadcast TRANSPORT
    /// closes on reconnect.
    channels: std.AutoArrayHashMapUnmanaged(usize, *ChannelHandle) = .empty,
    /// Atomic snapshot of the current connection state kind. Useful
    /// for embedder polling and for tearing through partial state on
    /// close.
    state_kind: std.atomic.Value(c_int) = .{ .raw = @intFromEnum(StateKind.connecting) },
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
        self.config.deinit(self.alloc);
        self.channels.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// Dispatch a state change to the embedder's `on_state`. Safe to
    /// call from any thread; the callback fires on the calling thread.
    fn emitState(self: *SshHandle, state: State) void {
        self.state_kind.store(@intFromEnum(state.kind), .release);
        self.mutex.lock();
        const cb = self.callbacks.on_state;
        const ud = self.callbacks.userdata;
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
// C-ABI exports. These match the declarations in `include/ghostty.h`.
// =========================================================================

/// Implements `ghostty_ssh_open`.
export fn ghostty_ssh_open(
    _: ?*anyopaque, // ghostty_app_t — reserved for future per-app pooling
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

    // Emit the initial CONNECTING state synchronously. The actual
    // transport wiring (acquiring an Entry from SshConnectionManager,
    // driving its threads) is gated on the state-listener hook —
    // tracked as TODO(state-listener). Until that lands, the handle
    // stays in CONNECTING until the embedder calls ghostty_ssh_close
    // or a future code path transitions it.
    handle.emitState(.{ .kind = .connecting, .payload = .{
        .password = std.mem.zeroes(StatePassword),
    } });
    return handle;
}

/// Implements `ghostty_ssh_submit_password`. No-op until the auth
/// state-machine bridge lands (TODO(state-listener)).
export fn ghostty_ssh_submit_password(
    ssh: ?*SshHandle,
    auth_token: u64,
    password: ?[*:0]const u8,
) void {
    _ = ssh;
    _ = auth_token;
    _ = password;
    log.debug("ghostty_ssh_submit_password: not yet wired", .{});
}

/// Implements `ghostty_ssh_cancel_password`.
export fn ghostty_ssh_cancel_password(ssh: ?*SshHandle, auth_token: u64) void {
    _ = ssh;
    _ = auth_token;
    log.debug("ghostty_ssh_cancel_password: not yet wired", .{});
}

/// Implements `ghostty_ssh_submit_host_key_decision`.
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
    log.debug("ghostty_ssh_submit_host_key_decision: not yet wired", .{});
}

/// Implements `ghostty_ssh_request_reconnect`.
export fn ghostty_ssh_request_reconnect(ssh: ?*SshHandle) void {
    _ = ssh;
    log.debug("ghostty_ssh_request_reconnect: not yet wired", .{});
}

/// Implements `ghostty_ssh_cancel_reconnect`.
export fn ghostty_ssh_cancel_reconnect(ssh: ?*SshHandle) void {
    _ = ssh;
    log.debug("ghostty_ssh_cancel_reconnect: not yet wired", .{});
}

/// Implements `ghostty_ssh_close`. After this, channels are
/// transitioned to TRANSPORT-closed and new opens fail.
export fn ghostty_ssh_close(ssh: ?*SshHandle) void {
    const h = ssh orelse return;
    if (h.closed.swap(true, .acq_rel)) return;

    // Snapshot the channel list under the mutex, then close each
    // outside the mutex (emitClose calls back into the embedder).
    h.mutex.lock();
    var snapshot = std.ArrayList(*ChannelHandle).empty;
    defer snapshot.deinit(h.alloc);
    var it = h.channels.iterator();
    while (it.next()) |entry| snapshot.append(h.alloc, entry.value_ptr.*) catch {};
    h.mutex.unlock();

    for (snapshot.items) |ch| {
        ch.emitClose(.daemon_shutdown, null);
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
    // TODO(client-mux): hand off to ClientMux.writeChannel(ch.channel_id, bytes[0..len])
    // and return the number of bytes accepted. Until then, accept
    // nothing (caller will park waiting for on_window_credit).
    return if (len == 0) 0 else 0;
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

    // TODO(state-listener) + TODO(client-mux): drive the existing
    // session.protocol Open/Opened frames through SshConnectionManager,
    // bridge frame events to the channel callbacks.
    ch.emitClose(.service_error, null);
    return ch;
}

/// Implements `ghostty_ssh_list_sessions`.
export fn ghostty_ssh_list_sessions(
    ssh: ?*SshHandle,
    on_entry: ?*const fn (userdata: ?*anyopaque, entry: ?*const SessionEntry) callconv(.c) void,
    userdata: ?*anyopaque,
) bool {
    const h = ssh orelse return false;
    if (h.closed.load(.acquire)) return false;
    // TODO(state-listener): drive the existing SessionListState
    // mailbox path. Until then, immediately signal "no entries".
    if (on_entry) |cb| cb(userdata, null);
    return true;
}

/// Implements `ghostty_ssh_rename_session`.
export fn ghostty_ssh_rename_session(
    ssh: ?*SshHandle,
    group_id: ?[*]const u8,
    label: ?[*:0]const u8,
) void {
    _ = ssh;
    _ = group_id;
    _ = label;
    log.debug("ghostty_ssh_rename_session: not yet wired", .{});
}

/// Implements `ghostty_ssh_kill_session`.
export fn ghostty_ssh_kill_session(ssh: ?*SshHandle, group_id: ?[*]const u8) void {
    _ = ssh;
    _ = group_id;
    log.debug("ghostty_ssh_kill_session: not yet wired", .{});
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

    fn onState(ud: ?*anyopaque, st: *const State) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(ud.?));
        self.last_state_kind = st.kind;
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
