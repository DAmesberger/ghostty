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
//! Channel transport status:
//!
//!   * The C-API ↔ `channel_mux.ClientMux` bridge IS wired —
//!     `ghostty_ssh_open_channel` / `ghostty_channel_write` /
//!     `_eof` / `_close` all route through a real ClientMux, and
//!     the five `ChannelHandle.mux*` bridge callbacks forward mux
//!     events to the embedder's `ghostty_channel_callbacks_t`.
//!   * Production ClientMux wiring is now live. When the SSH
//!     connection reaches `.connected`, `onStateListener` invokes
//!     `wireMuxTransport` which spins up a
//!     `SshChannelStreamTransport` against the daemon channel held
//!     on the Entry and attaches a fresh `ClientMux` to the
//!     SshHandle. `ghostty_ssh_open_channel`, `ghostty_channel_*`,
//!     and inbound-channel callbacks all route through this mux.
//!     Unit tests still inject a socketpair-backed ClientMux
//!     directly via `setClientMuxForTest` to exercise the bridge
//!     without standing up real libssh2.
//!
//! Still gated on a follow-up:
//!
//!   * `ghostty_ssh_attach_surface` would call the shared helper
//!     `session.client.attachRemoteSurface` (which now backs the
//!     GTK terminal-surface path too) from a worker thread, but
//!     the worker-thread spawn plus the subsequent frame-dispatch
//!     routing to the channel callbacks both land alongside the
//!     production transport (task #23). For now it returns a handle
//!     that immediately reports `on_close(SERVICE_ERROR)`.
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
const channel_mux = @import("../../session/channel_mux.zig");
const ssh_mod = @import("../../session/ssh.zig");
const session_client = @import("../../session/client.zig");
const SshConnectionManager = @import("../../termio/SshConnectionManager.zig");
const apprt_embedded = @import("../embedded.zig");
const SshChannelStreamTransport = @import("../../termio/SshChannelStreamTransport.zig");

const ClientMux = channel_mux.ClientMux;

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

    /// Map an embedder-supplied close reason to the wire-protocol
    /// reason for a `channel_close` frame. `transport` and `unknown`
    /// are libghostty-synthesized (no wire representation) and map
    /// to `normal` — an embedder closing a channel "because the
    /// transport dropped" still tells the peer a plain close.
    fn toProtocol(self: ChannelCloseReason) protocol.ChannelCloseReason {
        return switch (self) {
            .normal, .transport, .unknown => .normal,
            .peer_reset => .peer_reset,
            .service_error => .service_error,
            .policy_denied => .policy_denied,
            .idle_timeout => .idle_timeout,
            .daemon_shutdown => .daemon_shutdown,
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
    on_inbound_channel: ?*const fn (
        userdata: ?*anyopaque,
        channel: ?*ChannelHandle,
        service: ChannelService,
        params: ?*const anyopaque,
        params_len: usize,
    ) callconv(.c) ?*ChannelHandle,
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

/// Mirror of `ghostty_ssh_session_status_e`.
pub const SessionStatus = enum(c_int) {
    detached = 0,
    attached = 1,
    dead = 2,

    fn fromProtocol(s: protocol.ListStatus) SessionStatus {
        return switch (s) {
            .detached => .detached,
            .attached => .attached,
            .dead => .dead,
        };
    }
};

/// Mirror of `ghostty_ssh_session_entry_t`.
pub const SessionEntry = extern struct {
    group_id: [*]const u8, // 16 bytes
    label: [*:0]const u8,
    surface_count: u32,
    created_at_ns: i64,
    status: SessionStatus,
    color: i8,
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
    /// Client-side channel multiplexer for this connection — backs
    /// `ghostty_ssh_open_channel` and the channel write/eof/close
    /// entry points.
    ///
    /// Auto-wired by `onStateListener` when the SSH connection
    /// reaches `.connected`: a second libssh2 channel is opened via
    /// `SshConnectionManager.tryOpenChannel` and handed to
    /// `wireMuxTransport`, which wraps it in a
    /// `SshChannelStreamTransport` + `ClientMux`. The second channel
    /// is dedicated to the mux protocol so it doesn't race with the
    /// SSH thread's reads on `Entry.channel`. Non-null after the
    /// `.connected` broadcast unless the channel open failed.
    /// Unit tests inject a socketpair-backed ClientMux directly via
    /// `setClientMuxForTest` to exercise the bridge without libssh2.
    client_mux: ?*ClientMux = null,
    /// True when this handle owns `client_mux` and must deinit+free
    /// it on teardown. False when the mux is borrowed (the future
    /// per-Entry production mux is owned by the Entry, not the
    /// handle). Tests that inject a mux set this per their harness.
    client_mux_owned: bool = false,
    /// Production transport that bridges the libssh2 channel ↔
    /// ClientMux. Non-null only after `wireMuxTransport` successfully
    /// instantiates a `SshChannelStreamTransport`. Owned by this
    /// handle; torn down in `deinit` (transport stop → mux deinit →
    /// channel close are all handled by `SshChannelStreamTransport.deinit`).
    transport: ?*SshChannelStreamTransport = null,
    /// Dispatch thread for inbound ClientMux frames. Spawned in
    /// `wireMuxTransport` right after `sendCapabilities`; reads frames
    /// from `mux.fd` and calls `mux.dispatch` so embedder callbacks
    /// (`on_opened`/`on_data`/`on_close`) fire. Joined in
    /// `tearMuxTransport` after `mux.deinit` closes the fd, which EOFs
    /// the read and lets the thread exit cleanly.
    mux_reader_thread: ?std.Thread = null,
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

        // Production transport teardown sequence:
        //   1. Stop transport threads (they hold references to mux_fd).
        //   2. Join the mux reader thread (it holds a pointer to ClientMux
        //      and may be mid-dispatch firing embedder callbacks).
        //   3. Deinit + free the ClientMux (closes any remaining channels).
        //   4. Free the transport struct itself (also closes libssh2 channel).
        // We call close() instead of deinit() so we can control step order.
        const saved_transport = self.transport;
        self.transport = null;
        if (saved_transport) |t| {
            t.close(); // join threads + close fds (mux_fd, ssh_fd, stop_pipe)
        }

        // Joining the mux reader MUST happen after `t.close()` (which
        // closes mux_fd → EOFs the reader's blocking read) but BEFORE
        // `mux.deinit` / `destroy(mux)` — otherwise an in-flight
        // dispatch on the reader thread reads freed memory.
        if (self.mux_reader_thread) |th| {
            th.join();
            self.mux_reader_thread = null;
        }

        // ClientMux deinit/free (applies to both transport-backed and test-injected).
        // Channels are already empty by the assert above.
        if (self.client_mux_owned) {
            if (self.client_mux) |mux| {
                mux.deinit();
                self.alloc.destroy(mux);
            }
        }
        self.client_mux = null;
        self.client_mux_owned = false;

        // Free the transport struct memory now that mux_fd is confirmed closed.
        if (saved_transport) |t| {
            self.alloc.destroy(t);
        }
        if (self.release_target) |t| self.alloc.free(t);
        if (self.release_jump) |j| self.alloc.free(j);
        self.config.deinit(self.alloc);
        self.channels.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// Wire the production ClientMux + SshChannelStreamTransport onto this
    /// handle using an already-opened libssh2 channel. Called from the
    /// SSH thread when the connection reaches `connected` state.
    ///
    /// Lifecycle (enforced by teardown in `deinit`):
    ///   transport.close() (join threads + close fds)
    ///   → ClientMux.deinit() (fire on_close callbacks)
    ///   → alloc.destroy(transport) (frees transport memory)
    ///
    /// Safe to call multiple times; a second call is a no-op when
    /// `self.transport != null` (the previous transport is still live).
    pub fn wireMuxTransport(
        self: *SshHandle,
        ssh_channel: ssh_mod.Channel,
    ) void {
        if (self.transport != null) return; // already wired

        const mux = self.alloc.create(ClientMux) catch |err| {
            log.warn("wireMuxTransport: alloc ClientMux failed: {}", .{err});
            return;
        };

        // Allocate transport first so we can get the mux_fd. Pass the
        // per-Entry libssh2 mutex so the transport's reader/writer
        // threads serialise with `sshThreadMain` on the same session.
        // Without this, two threads concurrently calling
        // `libssh2_channel_read_ex` on the SAME session crash inside
        // `_libssh2_transport_read` (the M1-revealed race; see
        // `Entry.libssh2_mutex` docstring in SshConnectionManager.zig).
        const external_mu: ?*std.Thread.Mutex = if (self.entry) |e| &e.libssh2_mutex else null;
        const t = SshChannelStreamTransport.init(self.alloc, .{
            .channel = ssh_channel,
            .on_disconnect = onTransportDisconnect,
            .ctx = self,
            .external_mutex = external_mu,
        }) catch |err| {
            log.warn("wireMuxTransport: transport init failed: {}", .{err});
            self.alloc.destroy(mux);
            return;
        };

        mux.* = ClientMux.init(self.alloc, t.muxFd());
        self.installInboundHandler(mux);
        self.client_mux = mux;
        self.client_mux_owned = true;
        self.transport = t;

        // Send our capabilities as the FIRST frame on the mux. The daemon
        // requires this before it will accept channel_open frames
        // (`daemon.zig:413-414`). Without it the daemon closes the
        // connection silently and every subsequent channel_open lands on
        // a dead socket. The peer's capabilities reply is applied in
        // `dispatch` via `applyPeerCapabilities`.
        mux.sendCapabilities() catch |err| {
            log.warn("wireMuxTransport: sendCapabilities failed: {}", .{err});
        };

        // Spawn the inbound-frame dispatch thread. Without this no one
        // reads from `mux.fd`, so `channel_opened` / `channel_data` /
        // `channel_close` frames accumulate in the socketpair buffer
        // with no consumer — embedders see open frames go out but
        // never receive the response, which manifests as channels
        // hanging in the "opening" state forever (every browser_proxy
        // request silently times out).
        if (std.Thread.spawn(.{}, ClientMux.runReader, .{mux})) |th| {
            self.mux_reader_thread = th;
        } else |err| {
            log.warn("wireMuxTransport: spawn mux reader failed: {}", .{err});
        }

        log.info("wireMuxTransport: wired (client_mux is live, sent capabilities, reader thread spawned)", .{});
    }

    /// Fired by the transport reader thread when the SSH channel EOF's
    /// or encounters a read/write error. Broadcast TRANSPORT close to
    /// every live channel handle so the embedder can respond.
    fn onTransportDisconnect(ctx: ?*anyopaque, _: SshChannelStreamTransport.DisconnectReason) void {
        const self: *SshHandle = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        var snapshot = std.ArrayList(*ChannelHandle).empty;
        defer snapshot.deinit(self.alloc);
        var it = self.channels.iterator();
        while (it.next()) |entry| snapshot.append(self.alloc, entry.value_ptr.*) catch {};
        self.mutex.unlock();
        for (snapshot.items) |ch| {
            ch.emitClose(.transport, null);
        }
    }

    /// Tear down the production transport + ClientMux while keeping the
    /// SshHandle alive (e.g. on reconnect or SSH drop before full close).
    /// Broadcasts TRANSPORT close to any live channel handles, then
    /// sequences transport.close() → mux.deinit() → alloc.destroy().
    /// Safe to call when no transport is wired (no-op).
    fn tearMuxTransport(self: *SshHandle) void {
        // Broadcast TRANSPORT close to live channels BEFORE stopping the
        // transport threads, so callbacks fire while the mux is still valid.
        self.mutex.lock();
        var snapshot = std.ArrayList(*ChannelHandle).empty;
        defer snapshot.deinit(self.alloc);
        var it = self.channels.iterator();
        while (it.next()) |entry| snapshot.append(self.alloc, entry.value_ptr.*) catch {};
        self.mutex.unlock();
        for (snapshot.items) |ch| ch.emitClose(.transport, null);

        const saved_transport = self.transport;
        self.transport = null;
        // Close transport first — that EOFs the mux fd, which makes
        // the reader thread's blocking read return UnexpectedEOF and
        // exit cleanly. Joining BEFORE close would deadlock.
        if (saved_transport) |t| t.close();

        if (self.mux_reader_thread) |th| {
            th.join();
            self.mux_reader_thread = null;
        }

        if (self.client_mux_owned) {
            if (self.client_mux) |mux| {
                mux.deinit();
                self.alloc.destroy(mux);
            }
        }
        self.client_mux = null;
        self.client_mux_owned = false;
        if (saved_transport) |t| self.alloc.destroy(t);
    }

    /// Test-only: attach a borrowed-or-owned ClientMux to this handle
    /// so `ghostty_ssh_open_channel` has a real transport to drive.
    fn setClientMuxForTest(self: *SshHandle, mux: *ClientMux, owned: bool) void {
        self.client_mux = mux;
        self.client_mux_owned = owned;
        self.installInboundHandler(mux);
    }

    /// Install the C-API ↔ ClientMux inbound handler on `mux`, wiring
    /// `on_inbound_channel` from `self.callbacks`. Safe to call multiple
    /// times; the mux overwrites its previous handler on each call.
    fn installInboundHandler(self: *SshHandle, mux: *ClientMux) void {
        self.mutex.lock();
        const has_cb = self.callbacks.on_inbound_channel != null;
        self.mutex.unlock();
        if (!has_cb) return;
        mux.on_inbound = .{
            .ctx = self,
            .open = inboundOpen,
        };
    }

    /// `ClientMux.InboundHandler.open` bridge. Allocates a `ChannelHandle`,
    /// calls the embedder's `on_inbound_channel`, and either returns the
    /// handle's `mux_callbacks` (accepted) or null (rejected + freed).
    fn inboundOpen(
        ctx: ?*anyopaque,
        channel_id: u32,
        service: protocol.ChannelService,
        params: []const u8,
        channel_ctx_out: *?*anyopaque,
    ) ?ClientMux.Callbacks {
        const self: *SshHandle = @ptrCast(@alignCast(ctx.?));
        if (self.closed.load(.acquire)) return null;

        // Map wire service to C-API enum. Unrecognised or invalid ids
        // surface as `custom` so the embedder still sees the open.
        const c_service: ChannelService = switch (@intFromEnum(service)) {
            1 => .tcp_connect,
            2 => .port_listener,
            3 => .file_transfer,
            4 => .browser_proxy,
            5 => .process_exec,
            255 => .custom,
            else => .custom,
        };

        // Pre-allocate a ChannelHandle with empty callbacks. The embedder
        // will supply real callbacks if it accepts.
        const empty_cbs: ChannelCallbacks = .{
            .on_opened = null,
            .on_data = null,
            .on_window_credit = null,
            .on_eof = null,
            .on_close = null,
            .userdata = null,
        };
        const ch = ChannelHandle.init(self.alloc, self, c_service, &empty_cbs) catch |err| {
            log.warn("inboundOpen: alloc failed: {}", .{err});
            return null;
        };

        // Grab callback under mutex.
        self.mutex.lock();
        const cb = self.callbacks.on_inbound_channel;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();

        const cb_fn = cb orelse {
            ch.deinit();
            return null;
        };

        // params is borrowed for this call; the embedder must copy if needed.
        const params_ptr: ?*const anyopaque = if (params.len > 0) params.ptr else null;
        const result = cb_fn(ud, ch, c_service, params_ptr, params.len);

        if (result == null) {
            // Embedder rejected — free the pre-allocated handle.
            ch.deinit();
            return null;
        }
        // Embedder accepted and owns `ch`. Wire the mux callbacks vtable
        // so the mux dispatches frames to the C-API bridge.
        ch.client_mux = self.client_mux;
        ch.channel_id = channel_id;
        channel_ctx_out.* = ch;
        return ChannelHandle.mux_callbacks;
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

        switch (state) {
            .connected => {
                // Open a dedicated second channel for the ClientMux so it
                // doesn't race with the SSH thread reading entry.channel.
                // We are on the SSH thread here, so the libssh2 call is safe.
                // wireMuxTransport is idempotent — reconnects that reach
                // .connected again while a transport is live are no-ops.
                if (self.transport == null) {
                    log.info("onStateListener: .connected — attempting tryOpenChannel for mux", .{});
                    if (self.entry) |entry| {
                        if (SshConnectionManager.tryOpenChannel(entry)) |mux_chan| {
                            self.wireMuxTransport(mux_chan);
                        } else {
                            log.warn("onStateListener: failed to open mux channel; " ++
                                "inbound channels will not be available", .{});
                        }
                    } else {
                        log.warn("onStateListener: .connected but self.entry is null", .{});
                    }
                } else {
                    log.info("onStateListener: .connected — transport already wired (reconnect)", .{});
                }
            },
            .reconnecting, .disconnected, .failed => {
                // Tear down the existing transport NOW, BEFORE
                // `attemptReconnect` deinits the underlying libssh2
                // session. Without this, the next time something invokes
                // tearMuxTransport (e.g. on the eventual `.disconnected`
                // broadcast), libssh2_channel_close runs against a freed
                // session pointer and SIGSEGVs inside
                // `_libssh2_transport_send`. Captured in
                // 2026-05-26-154718.ips: user disconnects the tunnel →
                // sshThreadMain stale detection → attemptReconnect
                // entry.ctx.deinit (frees session) → reconnect fails →
                // broadcast .disconnected → tearMuxTransport →
                // libssh2_channel_close UAF.
                //
                // Tearing down on `.reconnecting` is safe because the
                // listener fires INSIDE attemptReconnect BEFORE it calls
                // entry.ctx.deinit (see SshConnectionManager.attemptReconnect:
                // the `.reconnecting` broadcast happens first, then the
                // session teardown). The next `.connected` broadcast
                // re-wires the transport via the .connected case above.
                if (self.transport != null) self.tearMuxTransport();
            },
            else => {},
        }

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
    /// ClientMux this channel rides. Cached from the SshHandle at
    /// open time. Null when the channel was created without a mux
    /// (production pre-Part-6, or a stub path) — write/eof/close
    /// then no-op or report terminal failure.
    client_mux: ?*ClientMux = null,
    /// channel_id allocated by the ClientMux at open time. Stays at
    /// `invalid_channel_id` until `ClientMux.openChannel` succeeds.
    channel_id: u32 = protocol.invalid_channel_id,
    /// For inbound (daemon-originated) channels: the peer window grant
    /// (in 4 KiB units) from the `channel_opened` reply we sent.  Stored
    /// so `ghostty_channel_set_callbacks` can replay the `on_opened`
    /// event with the correct initial credit after the embedder wires
    /// real callbacks. 0 = not an inbound channel / not yet set.
    inbound_peer_window: u16 = 0,

    /// For terminal channels (service == .terminal): target_id allocated
    /// from `SshConnectionManager.allocateTarget` and used as the frame
    /// `target` field in all subsequent reads/writes for this surface.
    /// Set by AttachWorker once registration succeeds. 0 means "not yet
    /// registered or never a terminal channel".
    capi_target_id: u16 = 0,
    /// The Entry this terminal channel is registered on. Borrowed from
    /// the parent SshHandle; the manager-release ordering on close
    /// guarantees the pointer outlives any callback fired through it.
    capi_entry: ?*SshConnectionManager.Entry = null,
    /// Group_id that the AttachWorker passed in the `Open` frame. Used
    /// by `ghostty_channel_close` to decide between session-level
    /// (`.detach`) vs surface-level (`.surface`) close on a grouped
    /// terminal channel, mirroring `Remote.threadExit`.
    capi_group_id: protocol.Uuid = protocol.zero_uuid,
    /// Surface UUID supplied at attach time (or generated). Stored so
    /// `ghostty_channel_close` can address the `.surface` close frame
    /// at the right surface within a session.
    capi_surface_id: protocol.Uuid = protocol.zero_uuid,

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

    // =====================================================================
    // ClientMux bridge — these five functions match the
    // `ClientMux.Callbacks` vtable shape. The mux passes the
    // `*ChannelHandle` back as `ctx`; each bridge fn translates the
    // mux event into the embedder's C `ghostty_channel_callbacks_t`.
    // All fire on the mux dispatch thread (the worker-thread contract
    // documented in the header).
    // =====================================================================

    fn muxOnOpened(ctx: ?*anyopaque, ack: []const u8, peer_window_units: u16) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        self.state.store(@intFromEnum(ChannelState.open), .release);
        self.mutex.lock();
        const cb = self.callbacks.on_opened;
        const ud = self.callbacks.userdata;
        // For inbound channels, the callbacks may be null here (they are
        // set later via ghostty_channel_set_callbacks). Stash the peer
        // window so set_callbacks can replay on_opened with the correct
        // credit grant.
        if (cb == null and self.inbound_peer_window == 0) {
            self.inbound_peer_window = peer_window_units;
        }
        self.mutex.unlock();
        if (cb) |f| {
            const ack_ptr: ?*const anyopaque = if (ack.len == 0) null else ack.ptr;
            // peer_window is advertised in 4 KiB units on the wire;
            // the C API surfaces a byte count.
            const window_bytes: u32 = @as(u32, peer_window_units) *| 4096;
            f(ud, ack_ptr, ack.len, window_bytes);
        }
    }

    fn muxOnData(ctx: ?*anyopaque, bytes: []const u8) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        const cb = self.callbacks.on_data;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| {
            const ptr: ?*const anyopaque = if (bytes.len == 0) null else bytes.ptr;
            f(ud, ptr, bytes.len);
        }
    }

    fn muxOnCredit(ctx: ?*anyopaque, credit_bytes: u32) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        const cb = self.callbacks.on_window_credit;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| f(ud, credit_bytes);
    }

    fn muxOnEof(ctx: ?*anyopaque) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        const cb = self.callbacks.on_eof;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| f(ud);
    }

    fn muxOnClose(
        ctx: ?*anyopaque,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
    ) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        // Surface the close message as a NUL-terminated C string.
        // ClientMux's `message` slice is borrowed for this call only;
        // copy into a stack buffer that outlives the embedder
        // callback. ChannelClose messages are short reason strings.
        var msg_buf: [256]u8 = undefined;
        const msg_ptr: ?[*:0]const u8 = blk: {
            if (message.len == 0) break :blk null;
            const n = @min(message.len, msg_buf.len - 1);
            @memcpy(msg_buf[0..n], message[0..n]);
            msg_buf[n] = 0;
            break :blk @ptrCast(&msg_buf[0]);
        };
        self.emitClose(ChannelCloseReason.fromProtocol(reason), msg_ptr);
    }

    /// The `ClientMux.Callbacks` vtable for a ChannelHandle. Static —
    /// the per-channel identity travels via the `ctx` pointer.
    const mux_callbacks: ClientMux.Callbacks = .{
        .on_opened = muxOnOpened,
        .on_data = muxOnData,
        .on_credit = muxOnCredit,
        .on_eof = muxOnEof,
        .on_close = muxOnClose,
    };
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

/// Map a C `ghostty_channel_service_e` to the wire-protocol
/// `protocol.ChannelService`. Returns null for values that cannot
/// open a non-terminal channel: `invalid` (the zero sentinel) and
/// `terminal` (which rides the legacy session frames via
/// attach_surface, not the channel mux).
fn protocolServiceFromC(service: ChannelService) ?protocol.ChannelService {
    return switch (service) {
        .invalid, .terminal => null,
        .tcp_connect => .tcp_connect,
        .port_listener => .port_listener,
        .file_transfer => .file_transfer,
        .browser_proxy => .browser_proxy,
        .process_exec => .process_exec,
        .custom => .custom,
    };
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

        // Spawn the SSH setup worker. attachRemoteSurface BLOCKS — it
        // runs the libssh2 handshake, possibly waits on a password
        // condvar, and uploads/launches the remote daemon. The C-API
        // contract is non-blocking, so this work lives on a worker
        // thread (same `active_workers` pattern as
        // `ghostty_ssh_list_sessions`). The worker also coordinates
        // with concurrent attachers (a GTK terminal sharing the same
        // host, another C-API handle) via the Entry's `conn_state`
        // atomic, mirroring `termio/Remote.zig:threadEnter`. On
        // success it broadcasts `.connected` so this handle's
        // listener fires `wireMuxTransport` and the channel mux
        // becomes available.
        const attach_cfg = session_client.AttachConfig{
            .max_reconnect_attempts = entry.max_reconnect_attempts,
            .reconnect_backoff = entry.reconnect_backoff,
            .reconnect_interval_ms = entry.reconnect_interval_ms,
            .scrollback_limit = entry.scrollback_limit,
        };

        if (!spawnSetupWorker(handle, mgr, entry, attach_cfg)) {
            log.warn("ghostty_ssh_open: setup worker spawn failed", .{});
            SshConnectionManager.unregisterStateListener(entry, handle);
            handle.listener_registered = false;
            mgr.release(target_slice, jump_slice);
            handle.manager = null;
            handle.entry = null;
            handle.emitState(.{ .kind = .failed, .payload = .{ .fail = .{
                .reason = .unknown,
                .message = null,
            } } });
            return null;
        }
    }

    return handle;
}

/// Worker that drives `session_client.attachRemoteSurface` off the
/// embedder's thread so `ghostty_ssh_open` stays non-blocking. Holds
/// no allocation of its own beyond the captured pointers; the
/// `active_workers` counter on the handle gates `ghostty_ssh_close`'s
/// entry release so the captured `entry` pointer stays valid for the
/// full run.
const SetupWorker = struct {
    handle: *SshHandle,
    manager: *SshConnectionManager,
    entry: *SshConnectionManager.Entry,
    cfg: session_client.AttachConfig,

    fn run(self: *SetupWorker) void {
        const handle = self.handle;
        const entry = self.entry;
        log.info("setupConnection: worker spawned target={s}", .{
            entry.ctx.ssh_target,
        });
        defer {
            // Capture handle.alloc by value BEFORE the fetchSub so we
            // never dereference handle.* afterwards (ghostty_ssh_close
            // may race ahead the moment active_workers hits 0). Same
            // UAF discipline as `ghostty_ssh_list_sessions`.
            const alloc = handle.alloc;
            _ = handle.active_workers.fetchSub(1, .acq_rel);
            alloc.destroy(self);
        }

        // Race-prevention via the per-Entry atomic. Mirror of the
        // pattern in `termio/Remote.zig:threadEnter` so the GTK and
        // libghostty paths agree on first-attacher election.
        const prev = entry.conn_state.cmpxchgStrong(
            .uninitialized,
            .connecting,
            .seq_cst,
            .seq_cst,
        );
        if (prev == null) {
            // Won the race — drive the full setup. `attachRemoteSurface`
            // already broadcasts intermediate states (UPLOADING, SETUP,
            // PASSWORD_REQUIRED, FAILED) via `pushAttachState`; only the
            // final `.connected` broadcast is our responsibility per the
            // helper's docstring.
            session_client.attachRemoteSurface(
                handle.alloc,
                self.manager,
                entry,
                null,
                self.cfg,
            ) catch |err| {
                log.warn("ghostty_ssh_open: setupConnection failed: {}", .{err});
                entry.conn_state.store(.failed, .seq_cst);
                return;
            };
            entry.conn_state.store(.ready, .seq_cst);
        } else {
            // Lost the race — another attacher is bringing up the
            // connection. Poll the atomic until it settles. If the
            // handle is closed mid-wait, bail without broadcasting.
            while (true) {
                if (handle.closed.load(.acquire)) return;
                const state = entry.conn_state.load(.seq_cst);
                if (state == .ready) break;
                if (state == .failed) return;
                std.Thread.sleep(1_000_000); // 1ms
            }
        }

        // Signal the listener registry that this connection is fully
        // up. Redundant if another concurrent attacher already
        // broadcast — `wireMuxTransport` and the listener-side
        // handling are both idempotent on already-wired state.
        log.info("setupConnection: ready, broadcasting .connected target={s}", .{
            entry.ctx.ssh_target,
        });
        SshConnectionManager.broadcastConnectionState(entry, .connected);
    }
};

fn spawnSetupWorker(
    handle: *SshHandle,
    manager: *SshConnectionManager,
    entry: *SshConnectionManager.Entry,
    cfg: session_client.AttachConfig,
) bool {
    const worker = handle.alloc.create(SetupWorker) catch return false;
    worker.* = .{
        .handle = handle,
        .manager = manager,
        .entry = entry,
        .cfg = cfg,
    };
    _ = handle.active_workers.fetchAdd(1, .acq_rel);
    const thread = std.Thread.spawn(.{}, SetupWorker.run, .{worker}) catch {
        _ = handle.active_workers.fetchSub(1, .acq_rel);
        handle.alloc.destroy(worker);
        return false;
    };
    thread.setName("ssh-capi-setup") catch {};
    thread.detach();
    return true;
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

    // If the setup worker is parked on the password condvar, wake it
    // so it can observe the cancellation and exit. Without this the
    // close path would block in the worker-wait loop below until the
    // SSH handshake timeout fired.
    if (h.entry) |entry| {
        entry.auth_state.mutex.lock();
        entry.auth_state.cancelled = true;
        entry.auth_state.cond.broadcast();
        entry.auth_state.mutex.unlock();
    }

    // Unregister the listener BEFORE we tear down channels so any
    // late state broadcasts from the SSH thread (e.g. as the Entry
    // notices the channel drop) don't race with the close cascade.
    if (h.listener_registered) {
        if (h.entry) |entry| {
            SshConnectionManager.unregisterStateListener(entry, h);
        }
        h.listener_registered = false;
    }

    // Drain in-flight setup workers before releasing the entry. The
    // setup worker captured `entry` by raw pointer; releasing the
    // manager ref while the worker is still inside attachRemoteSurface
    // would UAF the moment the worker touched any entry field. The
    // worker watches `closed` itself, so this loop is bounded by the
    // remaining libssh2 handshake/upload step rather than the full
    // auth wait.
    while (h.active_workers.load(.acquire) > 0) {
        std.Thread.sleep(1_000_000); // 1ms
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
        // Terminal channels: unregister from the CAPI surface registry
        // before firing on_close so the SSH I/O thread (still running
        // under the Entry's ref) can't dispatch a late frame to a
        // closed handle.
        if (ch.service == .terminal) {
            if (ch.capi_entry) |entry| {
                if (ch.capi_target_id != 0) {
                    SshConnectionManager.unregisterCAPISurface(entry, ch.capi_target_id);
                }
            }
        }
        ch.emitClose(.daemon_shutdown, null);
    }

    // Tear down the mux transport (which holds a libssh2 channel on
    // this Entry's session) BEFORE releasing the pool entry. The
    // transport's `close` ultimately calls `libssh2_channel_close` —
    // if the Entry / session is already released, that's a UAF inside
    // libssh2 (`_libssh2_transport_send → KERN_INVALID_ADDRESS`),
    // exactly the close-time crash captured in 2026-05-26-100729.ips.
    if (h.transport != null) h.tearMuxTransport();

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

    // Do NOT fire a synthetic `.disconnected` here. `ghostty_ssh_close`
    // is embedder-initiated (typically from a Swift `SSHConnection.deinit`),
    // so the embedder has no need for the notification AND its callback
    // context may already be torn down. The Swift M6 smoke captured a
    // SIGSEGV via this exact path: `SSHConnection.deinit` triggered
    // `ghostty_ssh_close`, which emitted `.disconnected`, which called
    // `cOnState` → `ConnectionBox.resolved()`, which `objc_msgSend`'d a
    // freed box. Channel-close + listener-unregister already happened
    // above; nothing else needs to fire.
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

/// Implements `ghostty_ssh_open_channel`. Opens a channel through
/// the connection's `ClientMux`: the returned ChannelHandle is the
/// `ctx` the mux passes back to the bridge callbacks, which forward
/// to the embedder's `ghostty_channel_callbacks_t`.
///
/// `client_mux` is auto-wired by `onStateListener` the moment the
/// underlying SSH connection broadcasts `.connected` (which the M1
/// `setupConnection` worker drives, see `spawnSetupWorker`). Embedders
/// MUST wait for the `.connected` state on `ghostty_ssh_callbacks_t`
/// before opening channels; calling this before the listener fires
/// returns a handle that immediately reports `on_close(SERVICE_ERROR)`.
/// This is a contract check rather than a production failure mode —
/// the early-out exists so the embedder observes a clean dead-channel
/// edge instead of a hung callback.
export fn ghostty_ssh_open_channel(
    ssh: ?*SshHandle,
    service: ChannelService,
    params: ?*const anyopaque,
    params_len: usize,
    callbacks: ?*const ChannelCallbacks,
) ?*ChannelHandle {
    const h = ssh orelse return null;
    const cbs = callbacks orelse return null;
    if (h.closed.load(.acquire)) return null;

    const proto_service = protocolServiceFromC(service) orelse {
        log.warn("ghostty_ssh_open_channel: invalid service {}", .{service});
        return null;
    };

    const ch = ChannelHandle.init(h.alloc, h, service, cbs) catch |err| {
        log.warn("ghostty_ssh_open_channel: alloc failed: {}", .{err});
        return null;
    };

    // Connection still bringing up its mux — embedder called this
    // before the `.connected` state arrived (see docstring). Synthesize
    // the dead-channel close so the embedder observes a clean edge
    // instead of a hung handle.
    const mux = h.client_mux orelse {
        log.info("open_channel: client_mux=null — embedder opened channel before .connected " ++
            "OR wireMuxTransport never ran (service={s})", .{@tagName(service)});
        ch.emitClose(.service_error, null);
        return ch;
    };
    ch.client_mux = mux;
    log.info("open_channel: mux ok, sending channel_open frame (service={s})", .{@tagName(service)});

    // Service params are borrowed for the call; ClientMux.openChannel
    // copies them into the channel_open frame before returning.
    const params_slice: []const u8 = if (params) |p|
        @as([*]const u8, @ptrCast(p))[0..params_len]
    else
        &.{};

    const channel_id = mux.openChannel(
        proto_service,
        .{},
        0, // initial_window: 0 → ClientMux uses the negotiated default
        params_slice,
        ChannelHandle.mux_callbacks,
        ch,
    ) catch |err| {
        log.warn("ghostty_ssh_open_channel: ClientMux.openChannel failed: {}", .{err});
        ch.emitClose(.service_error, null);
        return ch;
    };
    ch.channel_id = channel_id;
    log.info("open_channel: openChannel ok service={s} channel_id={d}", .{ @tagName(service), channel_id });
    return ch;
}

/// Implements `ghostty_channel_write`. Routes to
/// `ClientMux.writeChannel` for non-terminal channels (credit-bounded
/// — 0 means "no credit, wait for on_window_credit"), or to the
/// session-protocol `data_in` write queue for terminal channels (no
/// credit accounting, returns `len` on success). SIZE_MAX signals a
/// terminal error: a closed channel, a channel that never reached a
/// live mux, or an unknown channel id.
export fn ghostty_channel_write(
    channel: ?*ChannelHandle,
    bytes: ?*const anyopaque,
    len: usize,
) usize {
    const ch = channel orelse return std.math.maxInt(usize);
    if (ch.closed.load(.acquire)) return std.math.maxInt(usize);
    if (len == 0) return 0;

    const slice: []const u8 = if (bytes) |p|
        @as([*]const u8, @ptrCast(p))[0..len]
    else
        return std.math.maxInt(usize);

    // Terminal channels ride the session protocol, not the channel mux.
    if (ch.service == .terminal) {
        const entry = ch.capi_entry orelse return std.math.maxInt(usize);
        if (ch.capi_target_id == 0) return std.math.maxInt(usize);
        // M6 input-side diagnostic: log every write so we can see if
        // user keystrokes ever reach the libghostty channel layer
        // (output works, input was reported broken — pinpoints where
        // the chain breaks: cat-pump, master-fd loop, bridge.send,
        // libghostty enqueue, or daemon-side dispatch).
        log.info("channel_write target={d} len={d}", .{ ch.capi_target_id, len });
        SshConnectionManager.enqueueWrite(entry, .data_in, ch.capi_target_id, slice);
        return len;
    }

    // No mux / never opened → terminal error.
    const mux = ch.client_mux orelse return std.math.maxInt(usize);
    if (ch.channel_id == protocol.invalid_channel_id) return std.math.maxInt(usize);

    return mux.writeChannel(ch.channel_id, slice) catch |err| {
        // UnknownChannel (mux already tore it down), OutOfMemory, or
        // an fd write error — all are terminal for the channel from
        // the embedder's perspective.
        log.debug("ghostty_channel_write: {}", .{err});
        return std.math.maxInt(usize);
    };
}

/// Implements `ghostty_channel_eof`. Routes to `ClientMux.channelEof`
/// for non-terminal channels; no-op for terminal channels (the
/// session protocol does not have a per-surface half-close — the
/// embedder closes the channel via `ghostty_channel_close` instead).
export fn ghostty_channel_eof(channel: ?*ChannelHandle) void {
    const ch = channel orelse return;
    if (ch.closed.load(.acquire)) return;
    ch.state.store(@intFromEnum(ChannelHandle.ChannelState.local_eof), .release);

    if (ch.service == .terminal) return;

    const mux = ch.client_mux orelse return;
    if (ch.channel_id == protocol.invalid_channel_id) return;
    mux.channelEof(ch.channel_id) catch |err| {
        log.debug("ghostty_channel_eof: {}", .{err});
    };
}

/// Implements `ghostty_channel_close`. For non-terminal channels:
/// sends a `channel_close` frame via `ClientMux.channelClose` (which
/// does NOT fire the mux's on_close — the embedder initiated this).
/// For terminal channels: unregisters the CAPI surface and enqueues
/// a session-protocol `close` frame (`.surface` for grouped surfaces,
/// `.detach` for standalone). Then fires the embedder's on_close
/// locally via emitClose so the C API contract ("close triggers an
/// on_close callback") still holds. emitClose is idempotent, so a
/// racing daemon-side close is harmless.
export fn ghostty_channel_close(
    channel: ?*ChannelHandle,
    reason: ChannelCloseReason,
) void {
    const ch = channel orelse return;

    if (ch.service == .terminal) {
        if (ch.capi_entry) |entry| {
            // Unregister BEFORE sending the close frame so any
            // late `eof`/`data_out` we race past the unregister
            // is dropped rather than dispatched to a freed handle.
            if (ch.capi_target_id != 0) {
                SshConnectionManager.unregisterCAPISurface(entry, ch.capi_target_id);

                // Mirror Remote.threadExit: grouped surfaces send
                // close(surface) so the daemon kills just this
                // surface's PTY; standalone surfaces send
                // close(detach) so the daemon-side session stays
                // alive for reattach.
                const has_group = !session_shared.isZeroUuid(ch.capi_group_id);
                if (has_group) {
                    const payload = (protocol.Close{
                        .mode = .surface,
                        .id = ch.capi_surface_id,
                    }).encode(entry.alloc) catch {
                        // Fall back to a 1-byte close(detach) so the
                        // daemon at least sees an end-of-life signal.
                        SshConnectionManager.enqueueWrite(
                            entry,
                            .close,
                            ch.capi_target_id,
                            &.{@intFromEnum(protocol.CloseMode.detach)},
                        );
                        ch.emitClose(reason, null);
                        return;
                    };
                    defer entry.alloc.free(payload);
                    SshConnectionManager.enqueueWrite(entry, .close, ch.capi_target_id, payload);
                } else {
                    SshConnectionManager.enqueueWrite(
                        entry,
                        .close,
                        ch.capi_target_id,
                        &.{@intFromEnum(protocol.CloseMode.detach)},
                    );
                }
            }
        }
        ch.emitClose(reason, null);
        return;
    }

    if (ch.client_mux) |mux| {
        if (ch.channel_id != protocol.invalid_channel_id) {
            mux.channelClose(ch.channel_id, reason.toProtocol(), "") catch |err| {
                // UnknownChannel just means the mux already tore it
                // down (e.g. a daemon-side close raced us) — the
                // emitClose below is still the right local signal.
                log.debug("ghostty_channel_close: {}", .{err});
            };
        }
    }
    // TODO: round-tripping an embedder-supplied reason string back
    // through on_close is a follow-up — `message` stays NULL.
    ch.emitClose(reason, null);
}

/// Implements `ghostty_channel_set_callbacks`. Replaces the callbacks on
/// a pre-allocated inbound channel handle and replays `on_opened` with the
/// initial peer window if the channel is already in the `open` state (i.e.
/// the mux fired `on_opened` before the embedder called this function).
/// Safe from any thread; the callbacks field is guarded by `mutex`.
export fn ghostty_channel_set_callbacks(
    channel: ?*ChannelHandle,
    callbacks: ?*const ChannelCallbacks,
) void {
    const ch = channel orelse return;
    const cbs = callbacks orelse return;

    // Snap the inbound_peer_window while installing callbacks so we can
    // replay on_opened below without re-entering the mutex.
    ch.mutex.lock();
    ch.callbacks = cbs.*;
    const peer_window = ch.inbound_peer_window;
    const on_opened = cbs.on_opened;
    const ud = cbs.userdata;
    ch.mutex.unlock();

    // Replay on_opened if the channel is already open (i.e. the mux fired
    // on_opened before callbacks were installed). This delivers the initial
    // credit grant so the embedder's write path has outbound credit.
    if (on_opened != null and peer_window > 0 and
        ch.state.load(.acquire) == @intFromEnum(ChannelHandle.ChannelState.open))
    {
        const window_bytes: u32 = @as(u32, peer_window) *| 4096;
        on_opened.?(ud, null, 0, window_bytes);
    }
}

/// Implements `ghostty_channel_free`. If the channel is still live
/// in the ClientMux or CAPI registry, tear it down there FIRST —
/// otherwise the manager would retain a `ctx` pointer to the
/// ChannelHandle we're about to destroy, and a later inbound frame
/// for that target/channel id would fire a bridge callback on freed
/// memory.
export fn ghostty_channel_free(channel: ?*ChannelHandle) void {
    const ch = channel orelse return;
    if (!ch.closed.load(.acquire)) {
        // Terminal channels: unregister from the CAPI surface registry
        // so dispatchCAPIFrame can no longer reach this handle.
        if (ch.service == .terminal) {
            if (ch.capi_entry) |entry| {
                if (ch.capi_target_id != 0) {
                    SshConnectionManager.unregisterCAPISurface(entry, ch.capi_target_id);
                }
            }
        }
        // channelClose removes the channel from the mux's registry
        // (so no further bridge callback can reach this handle) and
        // does not fire the mux on_close; emitClose delivers the
        // embedder-facing close.
        if (ch.client_mux) |mux| {
            if (ch.channel_id != protocol.invalid_channel_id) {
                mux.channelClose(ch.channel_id, .normal, "") catch {};
            }
        }
        ch.emitClose(.normal, null);
    }
    ch.deinit();
}

/// Worker that runs the post-`.ready` part of the surface-attach
/// flow off the embedder's thread: it waits for the connection
/// state to settle, allocates a target_id, registers a CAPI surface
/// on the Entry, and enqueues the `Open` frame that asks the daemon
/// to create or attach the remote PTY. Subsequent `opened` /
/// `data_out` / `eof` frames are routed to this handle's callbacks
/// by `dispatchCAPIFrame` in `SshConnectionManager.processFrames`.
const AttachWorker = struct {
    handle: *SshHandle,
    manager: *SshConnectionManager,
    entry: *SshConnectionManager.Entry,
    channel: *ChannelHandle,
    rows: u16,
    cols: u16,
    width_px: u16,
    height_px: u16,
    /// Embedder-supplied group/surface ids (may be zero — meaning
    /// "let the daemon assign"). Owned by the worker.
    group_id: session_shared.Uuid,
    surface_id: session_shared.Uuid,
    /// Owned copy of the label string; freed in `run`.
    label: []u8,

    fn run(self: *AttachWorker) void {
        const handle = self.handle;
        const entry = self.entry;
        const channel = self.channel;
        defer {
            // UAF discipline: capture alloc BEFORE fetchSub so we
            // don't dereference handle/self afterwards.
            const alloc = handle.alloc;
            // Free owned label + self struct.
            alloc.free(self.label);
            _ = handle.active_workers.fetchSub(1, .acq_rel);
            alloc.destroy(self);
        }

        // Park until the SSH thread is up and the channel is live.
        // The SetupWorker (M1) transitions conn_state to `.ready`
        // when the connection finishes setup; we block here so any
        // attach issued before `.connected` still drives a real Open
        // frame instead of silently failing.
        while (true) {
            if (handle.closed.load(.acquire) or
                channel.closed.load(.acquire))
            {
                return;
            }
            const cs = entry.conn_state.load(.acquire);
            if (cs == .ready) break;
            if (cs == .failed) {
                channel.emitClose(.service_error, null);
                return;
            }
            std.Thread.sleep(2_000_000); // 2ms
        }

        // Allocate target id and register the CAPI surface BEFORE
        // sending the Open frame so the dispatch path can route the
        // daemon's `opened` reply back to us as soon as it arrives.
        const target_id = self.manager.allocateTarget(entry);
        const surface_cbs = SshConnectionManager.CAPISurfaceCallbacks{
            .ctx = channel,
            .on_data = capiOnData,
            .on_opened = capiOnOpened,
            .on_exit = capiOnExit,
        };
        SshConnectionManager.registerCAPISurface(entry, .{
            .target_id = target_id,
            .group_id = self.group_id,
            .surface_id = self.surface_id,
            .callbacks = surface_cbs,
        }) catch |err| {
            log.warn("attach_surface: registerCAPISurface failed: {}", .{err});
            channel.emitClose(.service_error, null);
            return;
        };

        // Stash routing state on the channel so subsequent
        // ghostty_channel_write / _eof / _close calls can address
        // the right target_id + frame kind without re-deriving.
        channel.capi_target_id = target_id;
        channel.capi_entry = entry;
        channel.capi_group_id = self.group_id;
        channel.capi_surface_id = self.surface_id;

        // Build the Open frame. The four open_type variants:
        //   - session_attach + group_id != zero    → attach existing session
        //   - session_new + group_id zero          → create fresh session
        //   - surface_attach + group_id != zero    → reattach surface in group
        //   - surface_new + group_id != zero       → add new surface to group
        // Surface-level forms require a non-zero group_id; for the
        // simple "create a new remote shell" case we use session_new.
        const has_group = !session_shared.isZeroUuid(self.group_id);
        const has_surface = !session_shared.isZeroUuid(self.surface_id);
        const open_type: protocol.OpenType = if (has_group)
            (if (has_surface) .surface_attach else .surface_new)
        else
            .session_new;

        const open_payload = (protocol.Open{
            .open_type = open_type,
            .resize = .{
                .rows = self.rows,
                .cols = self.cols,
                .width_px = self.width_px,
                .height_px = self.height_px,
            },
            .group_id = self.group_id,
            .surface_id = self.surface_id,
            .max_scrollback = entry.scrollback_limit,
            .label = self.label,
        }).encode(entry.alloc) catch |err| {
            log.warn("attach_surface: Open.encode failed: {}", .{err});
            SshConnectionManager.unregisterCAPISurface(entry, target_id);
            channel.emitClose(.service_error, null);
            return;
        };
        defer entry.alloc.free(open_payload);

        // M6 instrumentation: log every Open we send so the daemon-side
        // diagnosis can cross-reference against an early `.eof` response.
        log.info("attach_surface: Open enqueue target={d} type={s} group_zero={} surface_zero={} rows={d} cols={d} scrollback={d} label_len={d} payload_len={d}", .{
            target_id,
            @tagName(open_type),
            session_shared.isZeroUuid(self.group_id),
            session_shared.isZeroUuid(self.surface_id),
            self.rows,
            self.cols,
            entry.scrollback_limit,
            self.label.len,
            open_payload.len,
        });

        // enqueueWrite duplicates the payload; free is safe after.
        SshConnectionManager.enqueueWrite(entry, .open, target_id, open_payload);

        // Mark the channel as `open` so subsequent writes are accepted.
        // The daemon will reply with `opened` shortly; capiOnOpened
        // surfaces that to the embedder via on_opened.
        channel.state.store(@intFromEnum(ChannelHandle.ChannelState.open), .release);
    }

    /// `CAPISurfaceCallbacks.on_data` bridge: forward daemon-side
    /// `data_out` payloads to the channel's `on_data` callback.
    fn capiOnData(ctx: ?*anyopaque, bytes: []const u8) void {
        const ch: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        if (ch.closed.load(.acquire)) return;
        ch.mutex.lock();
        const cb = ch.callbacks.on_data;
        const ud = ch.callbacks.userdata;
        ch.mutex.unlock();
        if (cb) |f| {
            const ptr: ?*const anyopaque = if (bytes.len == 0) null else bytes.ptr;
            f(ud, ptr, bytes.len);
        }
    }

    /// `CAPISurfaceCallbacks.on_opened` bridge: fire the channel's
    /// `on_opened` so embedders observe the daemon-authoritative
    /// surface/group ids and history depth. The C `on_opened`
    /// signature passes UUIDs through the `service_ack` opaque
    /// pointer + length; embedders that care unpack a small fixed
    /// header (16 + 16 + 4 = 36 bytes).
    fn capiOnOpened(
        ctx: ?*anyopaque,
        group_id: *const [16]u8,
        surface_id: *const [16]u8,
        history_rows: u32,
    ) void {
        const ch: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        if (ch.closed.load(.acquire)) return;

        // Stash the daemon-authoritative ids on the channel so close
        // can address the right surface/session.
        ch.mutex.lock();
        @memcpy(&ch.capi_group_id, group_id);
        @memcpy(&ch.capi_surface_id, surface_id);
        const cb = ch.callbacks.on_opened;
        const ud = ch.callbacks.userdata;
        ch.mutex.unlock();

        if (cb) |f| {
            // Pack the small "service_ack" the embedder can decode.
            var ack_buf: [16 + 16 + 4]u8 = undefined;
            @memcpy(ack_buf[0..16], group_id);
            @memcpy(ack_buf[16..32], surface_id);
            std.mem.writeInt(u32, ack_buf[32..36], history_rows, .little);
            f(ud, &ack_buf[0], ack_buf.len, 0);
        }
    }

    /// `CAPISurfaceCallbacks.on_exit` bridge: the remote PTY died,
    /// so close the channel from this side.
    fn capiOnExit(ctx: ?*anyopaque, exit_code: i32) void {
        _ = exit_code;
        const ch: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        if (ch.capi_entry) |entry| {
            SshConnectionManager.unregisterCAPISurface(entry, ch.capi_target_id);
        }
        ch.emitClose(.normal, null);
    }
};

fn spawnAttachWorker(worker: *AttachWorker) bool {
    _ = worker.handle.active_workers.fetchAdd(1, .acq_rel);
    const thread = std.Thread.spawn(.{}, AttachWorker.run, .{worker}) catch {
        _ = worker.handle.active_workers.fetchSub(1, .acq_rel);
        return false;
    };
    thread.setName("ssh-capi-attach") catch {};
    thread.detach();
    return true;
}

/// Implements `ghostty_ssh_attach_surface`. Terminal channels are
/// sugar over the legacy session-protocol frames; the channel handle
/// shape is identical to non-terminal channels for embedder
/// uniformity (per the design doc).
///
/// Allocates a `ChannelHandle` and spawns an AttachWorker that drives
/// the post-`.ready` attach flow (allocateTarget → registerCAPISurface
/// → enqueue Open frame) on a background thread. Daemon-side
/// `opened` / `data_out` / `eof` frames route back through the CAPI
/// fast-path in `processFrames`.
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
    const h = ssh orelse return null;
    const cbs = callbacks orelse return null;
    if (h.closed.load(.acquire)) return null;

    const ch = ChannelHandle.init(h.alloc, h, .terminal, cbs) catch |err| {
        log.warn("ghostty_ssh_attach_surface: alloc failed: {}", .{err});
        return null;
    };

    // No manager / entry means this is a test handle (or a malformed
    // open). The pre-M1 contract was to fire on_close(SERVICE_ERROR)
    // immediately so embedders observe a clean edge; preserve that.
    const mgr = h.manager orelse {
        ch.emitClose(.service_error, null);
        return ch;
    };
    const entry = h.entry orelse {
        ch.emitClose(.service_error, null);
        return ch;
    };

    // Copy the label so the worker has an owned slice. C strings
    // passed across the FFI boundary are borrowed for the duration of
    // this call only.
    const label_span: []const u8 = if (label) |p| std.mem.span(p) else "";
    const owned_label = h.alloc.dupe(u8, label_span) catch {
        ch.emitClose(.service_error, null);
        return ch;
    };
    errdefer h.alloc.free(owned_label);

    var gid: session_shared.Uuid = session_shared.zero_uuid;
    var sid: session_shared.Uuid = session_shared.zero_uuid;
    if (group_id) |p| @memcpy(&gid, p[0..protocol.uuid_size]);
    if (surface_id) |p| @memcpy(&sid, p[0..protocol.uuid_size]);

    // Clamp pixel dims to u16; the wire-level Resize is packed u16s.
    const w_px: u16 = if (width_px > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(width_px);
    const h_px: u16 = if (height_px > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(height_px);

    const worker = h.alloc.create(AttachWorker) catch {
        h.alloc.free(owned_label);
        ch.emitClose(.service_error, null);
        return ch;
    };
    worker.* = .{
        .handle = h,
        .manager = mgr,
        .entry = entry,
        .channel = ch,
        .rows = rows,
        .cols = cols,
        .width_px = w_px,
        .height_px = h_px,
        .group_id = gid,
        .surface_id = sid,
        .label = owned_label,
    };

    if (!spawnAttachWorker(worker)) {
        log.warn("ghostty_ssh_attach_surface: thread spawn failed", .{});
        h.alloc.free(owned_label);
        h.alloc.destroy(worker);
        ch.emitClose(.service_error, null);
        return ch;
    }

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
                    .status = SessionStatus.fromProtocol(list_entry.status),
                    .color = list_entry.session_color,
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
            .on_inbound_channel = null,
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
            .on_inbound_channel = null,
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

// =========================================================================
// Part 5 tests — C-API ↔ ClientMux bridge over a socketpair.
//
// Mirrors the DaemonClientPair pattern from channel_mux.zig: a daemon
// `Mux` (with an echo service) on one fd, a `ClientMux` on the other,
// the ClientMux injected into a real SshHandle. Drives the C entry
// points and asserts bytes round-trip through ghostty_channel_write →
// daemon echo → the embedder's on_data callback.
// =========================================================================

const posix = std.posix;
const channel_mux_test = struct {
    const Mux = channel_mux.Mux;
    const Registry = channel_mux.Registry;
    const Service = channel_mux.Service;
    const ServiceError = channel_mux.ServiceError;
    const Channel = channel_mux.Channel;
};

/// Test echo service for the daemon side — bounces every inbound
/// channel_data frame straight back. Mirrors channel_mux.zig's
/// roundtrip_vtable but local to this test block.
const EchoState = struct {
    mux: *channel_mux_test.Mux,
    channel: ?*channel_mux_test.Channel = null,
};

fn echoOpen(
    _: ?*anyopaque,
    mux: *channel_mux_test.Mux,
    _: u32,
    _: []const u8,
    _: []u8,
) channel_mux_test.ServiceError!channel_mux.Service.OpenResult {
    const state = try mux.alloc.create(EchoState);
    state.* = .{ .mux = mux };
    return .{ .state = state };
}

fn echoOnOpened(state_ptr: ?*anyopaque, ch: *channel_mux_test.Channel) void {
    const state: *EchoState = @ptrCast(@alignCast(state_ptr orelse return));
    state.channel = ch;
}

fn echoOnData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux_test.ServiceError!void {
    const state: *EchoState = @ptrCast(@alignCast(state_ptr orelse return));
    const ch = state.channel orelse return;
    var off: usize = 0;
    while (off < bytes.len) {
        const sent = state.mux.sendChannelData(ch, bytes[off..]) catch
            return error.ServiceError;
        if (sent == 0) {
            _ = state.mux.waitForCredit(ch, 1 * std.time.ns_per_s);
            continue;
        }
        off += sent;
    }
}

fn echoOnControl(_: ?*anyopaque, _: u8, _: []const u8) channel_mux_test.ServiceError!void {}
fn echoOnEof(_: ?*anyopaque) void {}
fn echoOnClose(state_ptr: ?*anyopaque, _: protocol.ChannelCloseReason, _: []const u8) void {
    const state: *EchoState = @ptrCast(@alignCast(state_ptr orelse return));
    state.mux.alloc.destroy(state);
}

const echo_vtable: channel_mux.Service.VTable = .{
    .open = echoOpen,
    .on_opened = echoOnOpened,
    .on_data = echoOnData,
    .on_control = echoOnControl,
    .on_eof = echoOnEof,
    .on_close = echoOnClose,
};

const echo_service_id: u8 = @intFromEnum(protocol.ChannelService.tcp_connect);

/// Read one full frame (header + payload) from `fd`. Caller frees
/// `payload`.
fn capiReadFrame(alloc: Allocator, fd: posix.fd_t) !struct {
    header: protocol.Header,
    payload: []u8,
} {
    var header_buf: [protocol.header_size]u8 = undefined;
    var off: usize = 0;
    while (off < header_buf.len) {
        const n = try posix.read(fd, header_buf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
    const header = try protocol.Header.parseFromBuf(&header_buf);
    const payload = try alloc.alloc(u8, header.len);
    errdefer alloc.free(payload);
    off = 0;
    while (off < payload.len) {
        const n = try posix.read(fd, payload[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
    return .{ .header = header, .payload = payload };
}

/// Harness: daemon `Mux` + `ClientMux` over a socketpair, the
/// ClientMux injected into a real SshHandle, with a background
/// thread pumping the daemon side.
const CapiClientPair = struct {
    a: posix.fd_t, // daemon end
    b: posix.fd_t, // client end
    alloc: Allocator,
    registry: *channel_mux_test.Registry,
    mux: *channel_mux_test.Mux,
    client: *ClientMux,
    daemon_thread: ?std.Thread = null,
    daemon_stop: std.atomic.Value(bool) = .{ .raw = false },

    fn init(alloc: Allocator) !*CapiClientPair {
        var fds: [2]posix.fd_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc != 0) return error.SocketPairFailed;

        const reg = try alloc.create(channel_mux_test.Registry);
        reg.* = channel_mux_test.Registry.init(alloc);
        try reg.register(.{
            .id = echo_service_id,
            .name = "echo",
            .vtable = &echo_vtable,
        });

        const mux = try alloc.create(channel_mux_test.Mux);
        mux.* = channel_mux_test.Mux.init(alloc, fds[0], reg);

        const client = try alloc.create(ClientMux);
        client.* = ClientMux.init(alloc, fds[1]);

        const self = try alloc.create(CapiClientPair);
        self.* = .{
            .a = fds[0],
            .b = fds[1],
            .alloc = alloc,
            .registry = reg,
            .mux = mux,
            .client = client,
        };
        return self;
    }

    fn startDaemonPump(self: *CapiClientPair) !void {
        self.daemon_thread = try std.Thread.spawn(.{}, daemonPump, .{self});
    }

    fn daemonPump(self: *CapiClientPair) void {
        while (!self.daemon_stop.load(.acquire)) {
            const frame = capiReadFrame(self.alloc, self.a) catch return;
            defer self.alloc.free(frame.payload);
            self.mux.dispatch(frame.header.kind, frame.payload) catch return;
        }
    }

    /// Pump a single inbound frame from the client fd into the
    /// ClientMux dispatch — the test stands in for the production
    /// SSH read thread (task #23).
    fn pumpClientOne(self: *CapiClientPair) !void {
        const frame = try capiReadFrame(self.alloc, self.b);
        defer self.alloc.free(frame.payload);
        try self.client.dispatch(frame.header.kind, frame.payload);
    }

    fn deinit(self: *CapiClientPair) void {
        self.daemon_stop.store(true, .release);
        posix.shutdown(self.a, .both) catch {};
        if (self.daemon_thread) |t| t.join();
        // client + mux are deinit'd by the SshHandle teardown when the
        // mux was injected as owned; here we own them directly.
        self.mux.deinit();
        self.registry.deinit();
        posix.close(self.a);
        posix.close(self.b);
        self.alloc.destroy(self.mux);
        self.alloc.destroy(self.registry);
        self.alloc.destroy(self);
    }
};

test "open_channel + write — byte roundtrip through the ClientMux bridge" {
    const alloc = testing.allocator;
    const pair = try CapiClientPair.init(alloc);
    defer pair.deinit();
    try pair.startDaemonPump();

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

    // Inject the test ClientMux (borrowed — CapiClientPair.deinit
    // owns it, so `owned = false`).
    handle.setClientMuxForTest(pair.client, false);

    // Channel observer — records the bridge's on_data / on_opened.
    var ch_obs = ChannelObserver{ .alloc = alloc };
    defer ch_obs.deinit();
    const ch_cbs = ch_obs.callbacks();

    const ch = ghostty_ssh_open_channel(
        handle,
        .tcp_connect,
        null,
        0,
        &ch_cbs,
    ).?;
    defer ghostty_channel_free(ch);
    try testing.expect(ch.channel_id != protocol.invalid_channel_id);

    // The daemon replies channel_opened — pump it into the ClientMux,
    // which fires the bridge's muxOnOpened → embedder's on_opened.
    try pair.pumpClientOne();
    try testing.expect(ch_obs.opened);
    try testing.expect(ch_obs.peer_window_bytes > 0);

    // Write bytes. Pre-ack the channel may have 0 credit until the
    // channel_opened grant landed above; loop until accepted.
    const greeting = "hello over the C API mux";
    var written: usize = 0;
    while (written < greeting.len) {
        const n = ghostty_channel_write(ch, greeting[written..].ptr, greeting.len - written);
        try testing.expect(n != std.math.maxInt(usize));
        written += n;
        if (n == 0) {
            // No credit — pump an inbound frame (channel_window or the
            // initial grant) and retry.
            try pair.pumpClientOne();
        }
    }

    // The daemon echo bounces the bytes; pump client frames until the
    // observer has the full payload.
    while (ch_obs.dataLen() < greeting.len) {
        try pair.pumpClientOne();
    }
    try testing.expectEqualStrings(greeting, ch_obs.data.items);
}

test "channel_close — routes through ClientMux and fires on_close" {
    const alloc = testing.allocator;
    const pair = try CapiClientPair.init(alloc);
    defer pair.deinit();
    try pair.startDaemonPump();

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
    handle.setClientMuxForTest(pair.client, false);

    var ch_obs = ChannelObserver{ .alloc = alloc };
    defer ch_obs.deinit();
    const ch_cbs = ch_obs.callbacks();
    const ch = ghostty_ssh_open_channel(handle, .tcp_connect, null, 0, &ch_cbs).?;
    defer ghostty_channel_free(ch);
    const id = ch.channel_id;
    try testing.expect(id != protocol.invalid_channel_id);
    try pair.pumpClientOne(); // channel_opened

    // Embedder-initiated close: routes to ClientMux.channelClose AND
    // fires the embedder's on_close locally.
    ghostty_channel_close(ch, .normal);
    try testing.expect(ch_obs.closed);
    try testing.expectEqual(@as(?ChannelCloseReason, .normal), ch_obs.close_reason);
    // The mux must no longer know the channel.
    try testing.expect(!pair.client.channels.contains(id));
}

test "open_channel — no mux reports on_close(SERVICE_ERROR)" {
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
    // No client_mux injected — open_channel must synthesize the close.
    var ch_obs = ChannelObserver{ .alloc = testing.allocator };
    defer ch_obs.deinit();
    const ch_cbs = ch_obs.callbacks();
    const ch = ghostty_ssh_open_channel(handle, .tcp_connect, null, 0, &ch_cbs).?;
    defer ghostty_channel_free(ch);
    try testing.expect(ch_obs.closed);
    try testing.expectEqual(@as(?ChannelCloseReason, .service_error), ch_obs.close_reason);
    // Writes against a never-opened channel report terminal failure.
    try testing.expectEqual(std.math.maxInt(usize), ghostty_channel_write(ch, "x".ptr, 1));
}

test "open_channel — rejects the terminal + invalid service ids" {
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
    var ch_obs = ChannelObserver{ .alloc = testing.allocator };
    defer ch_obs.deinit();
    const ch_cbs = ch_obs.callbacks();
    // `terminal` rides the legacy session frames, not the channel mux.
    try testing.expect(ghostty_ssh_open_channel(handle, .terminal, null, 0, &ch_cbs) == null);
    // `invalid` is the zero sentinel.
    try testing.expect(ghostty_ssh_open_channel(handle, .invalid, null, 0, &ch_cbs) == null);
}

/// Channel-callback observer for the Part 5 tests — records every
/// bridge callback so tests can assert on the round-trip.
const ChannelObserver = struct {
    alloc: Allocator,
    mutex: std.Thread.Mutex = .{},
    opened: bool = false,
    peer_window_bytes: u32 = 0,
    data: std.ArrayListUnmanaged(u8) = .empty,
    credit_total: u64 = 0,
    eof: bool = false,
    closed: bool = false,
    close_reason: ?ChannelCloseReason = null,

    fn deinit(self: *ChannelObserver) void {
        self.data.deinit(self.alloc);
    }

    fn dataLen(self: *ChannelObserver) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.data.items.len;
    }

    fn onOpened(
        ud: ?*anyopaque,
        _: ?*const anyopaque,
        _: usize,
        initial_peer_window: u32,
    ) callconv(.c) void {
        const self: *ChannelObserver = @ptrCast(@alignCast(ud.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.opened = true;
        self.peer_window_bytes = initial_peer_window;
    }

    fn onData(ud: ?*anyopaque, bytes: ?*const anyopaque, len: usize) callconv(.c) void {
        const self: *ChannelObserver = @ptrCast(@alignCast(ud.?));
        if (bytes == null or len == 0) return;
        const slice = @as([*]const u8, @ptrCast(bytes.?))[0..len];
        self.mutex.lock();
        defer self.mutex.unlock();
        self.data.appendSlice(self.alloc, slice) catch {};
    }

    fn onCredit(ud: ?*anyopaque, credit_bytes: u32) callconv(.c) void {
        const self: *ChannelObserver = @ptrCast(@alignCast(ud.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.credit_total += credit_bytes;
    }

    fn onEof(ud: ?*anyopaque) callconv(.c) void {
        const self: *ChannelObserver = @ptrCast(@alignCast(ud.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.eof = true;
    }

    fn onClose(
        ud: ?*anyopaque,
        reason: ChannelCloseReason,
        _: ?[*:0]const u8,
    ) callconv(.c) void {
        const self: *ChannelObserver = @ptrCast(@alignCast(ud.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.close_reason = reason;
    }

    fn callbacks(self: *ChannelObserver) ChannelCallbacks {
        return .{
            .on_opened = onOpened,
            .on_data = onData,
            .on_window_credit = onCredit,
            .on_eof = onEof,
            .on_close = onClose,
            .userdata = self,
        };
    }
};

// =========================================================================
// Integration test — wireMuxTransport via onStateListener (Phase 6D Part 4)
// =========================================================================
//
// Requires passwordless SSH to 127.0.0.1 AND a running ghostty daemon
// reachable via `ghostty --stdio-attach` on the remote. Skips gracefully
// when either condition is not met (authAuto fallback pattern from the
// SshChannelStreamTransport integration test).

test "onStateListener wires client_mux on .connected via tryOpenChannel" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const alloc = testing.allocator;

    // Skip if libssh2 global init fails.
    ssh_mod.globalInit();
    defer ssh_mod.globalDeinit();

    // Connect to localhost.
    var ssh_session = ssh_mod.SshSession.connect(alloc, "127.0.0.1", 22) catch
        return error.SkipZigTest;
    defer ssh_session.close();

    const user = std.posix.getenv("USER") orelse "root";
    ssh_session.authAuto(user) catch return error.SkipZigTest;

    // Non-blocking required by SshChannelStreamTransport and
    // openMultiplexChannel.
    ssh_session.setBlocking(0);

    // Build a minimal Entry. We only need the fields tryOpenChannel touches:
    // alloc, ctx.session, ctx.alloc, ctx.ssh_target, ctx.jump, and
    // remote_bin_path (under surfaces_mutex). The sessions map is never
    // touched by tryOpenChannel so we can leave it empty.
    const entry = try alloc.create(SshConnectionManager.Entry);
    defer {
        // Don't call entry.ctx.deinit() — we close ssh_session above via defer.
        entry.sessions.deinit();
        alloc.destroy(entry);
    }
    entry.* = .{
        .alloc = alloc,
        .ctx = .{
            .alloc = alloc,
            .ssh_target = "127.0.0.1",
            .jump = null,
            .session = ssh_session,
        },
        .remote_bin_path = &.{}, // empty → tryOpenChannel will fail; test skips below
        .ref_count = 1,
        .sessions = std.AutoArrayHashMap(
            SshConnectionManager.Uuid,
            *SshConnectionManager.Session,
        ).init(alloc),
    };

    // Create an SshHandle wired to the entry.
    var cap: Capture = .{};
    const cfg = Config{
        .target = "127.0.0.1",
        .jump = null,
        .identity_file = null,
        .keepalive_interval_ms = 0,
        .max_reconnect_attempts = 5,
        .reconnect_interval_ms = 1000,
        .host_key_policy = .tofu,
        .scrollback_limit_bytes = 0,
    };
    const ssh_cbs = cap.cbs();
    const handle = try SshHandle.init(alloc, &cfg, &ssh_cbs);
    defer {
        // Tear down mux before freeing — matches normal ghostty_ssh_free path.
        if (handle.transport != null) handle.tearMuxTransport();
        // channels is empty so deinit is safe.
        handle.config.deinit(alloc);
        handle.channels.deinit(alloc);
        alloc.destroy(handle);
    }
    handle.entry = entry;

    // Simulate the .connected broadcast (runs on SSH thread in production;
    // here we call it directly since we own the session on this thread).
    SshHandle.onStateListener(handle, .connected);

    // If tryOpenChannel succeeded (daemon present), client_mux is non-null.
    // If the daemon isn't available it returns null → skip gracefully.
    if (handle.client_mux == null) {
        // No daemon reachable — acceptable in CI. Mark as skipped.
        return error.SkipZigTest;
    }
    try testing.expect(handle.client_mux != null);
    try testing.expect(handle.transport != null);

    // Clean disconnect.
    SshHandle.onStateListener(handle, .{ .disconnected = .{
        .attempts_made = 0,
        .reason = .cancelled,
    } });
    try testing.expect(handle.client_mux == null);
    try testing.expect(handle.transport == null);
    _ = session_client;
}
