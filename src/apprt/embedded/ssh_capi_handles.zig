//! Runtime state behind the libghostty SSH C-API handles: `OwnedConfig`,
//! `SshHandle`, `ChannelHandle`, and the state-translation /
//! manager-resolution helpers. Split out of `ssh_capi.zig`; the facade
//! re-exports the public symbols. No `export fn`s live here — the C-ABI
//! entry points live in `ssh_capi_exports.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const protocol = @import("../../session/protocol.zig");
const channel_mux = @import("../../session/channel_mux.zig");
const ssh_mod = @import("../../session/ssh.zig");
const SshConnectionManager = @import("../../termio/SshConnectionManager.zig");
const apprt_embedded = @import("../embedded.zig");
const SshChannelStreamTransport = @import("../../termio/SshChannelStreamTransport.zig");

const ClientMux = channel_mux.ClientMux;

const log = std.log.scoped(.ssh_capi);

// Shared C-ABI types live in the types sibling; alias them so the moved
// bodies below stay byte-identical.
const types = @import("ssh_capi_types.zig");
const StateKind = types.StateKind;
const ProvisionSource = types.ProvisionSource;
const DisconnectReason = types.DisconnectReason;
const FailReason = types.FailReason;
const ChannelService = types.ChannelService;
const ChannelCloseReason = types.ChannelCloseReason;
const HostKeyPolicy = types.HostKeyPolicy;
const StatePassword = types.StatePassword;
const State = types.State;
const Config = types.Config;
const SshCallbacks = types.SshCallbacks;
const ChannelCallbacks = types.ChannelCallbacks;

/// Owned copy of the C config — owns the duplicated string memory so
/// we can safely outlive the caller's buffers.
pub const OwnedConfig = struct {
    target: [:0]u8,
    jump: ?[:0]u8,
    identity_file: ?[:0]u8,
    keepalive_interval_ms: u32,
    max_reconnect_attempts: u32,
    reconnect_interval_ms: u32,
    host_key_policy: HostKeyPolicy,
    scrollback_limit_bytes: u32,
    reconnect_max_interval_ms: u32,

    pub fn fromC(alloc: Allocator, cfg: *const Config) !OwnedConfig {
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
            .reconnect_max_interval_ms = if (cfg.reconnect_max_interval_ms == 0)
                30_000
            else
                cfg.reconnect_max_interval_ms,
        };
    }

    pub fn deinit(self: *OwnedConfig, alloc: Allocator) void {
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
    /// Stable storage for the host string surfaced via an
    /// UPDATE_CONFIRMATION_REQUIRED state. Same lifetime contract as
    /// `last_password_host`: copied under `mutex` before the callback,
    /// valid until the next UPDATE_CONFIRMATION_REQUIRED rewrites it.
    last_update_host: [129]u8 = [_]u8{0} ** 129,
    last_update_host_len: u8 = 0,
    /// Per-prompt monotonic token for the update-confirmation gate.
    /// Issued under `mutex` whenever an UPDATE_CONFIRMATION_REQUIRED
    /// state is translated; the previous token is invalidated so a
    /// stale submit is rejected. Skips zero (reserved sentinel).
    next_update_token: u64 = 1,
    /// The decision_token currently advertised on the latest
    /// UPDATE_CONFIRMATION_REQUIRED. submit_update_decision only accepts
    /// this exact value; cleared once consumed so a double-submit can't
    /// double-signal the daemon's update_state cond.
    current_update_token: ?u64 = null,
    /// In-flight worker threads spawned by ghostty_ssh_list_sessions.
    /// ghostty_ssh_free refuses to destroy the handle until this
    /// drops to 0 — the embedder must keep the handle alive at
    /// least until the on_entry(null) sentinel fires.
    active_workers: std.atomic.Value(u32) = .{ .raw = 0 },
    /// Set when ghostty_ssh_close has been called; channel ops error
    /// out after this.
    closed: std.atomic.Value(bool) = .{ .raw = false },

    pub fn init(alloc: Allocator, cfg: *const Config, cbs: *const SshCallbacks) !*SshHandle {
        const self = try alloc.create(SshHandle);
        errdefer alloc.destroy(self);
        self.* = .{
            .alloc = alloc,
            .config = try OwnedConfig.fromC(alloc, cfg),
            .callbacks = cbs.*,
        };
        return self;
    }

    pub fn deinit(self: *SshHandle) void {
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
    pub fn tearMuxTransport(self: *SshHandle) void {
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
    pub fn setClientMuxForTest(self: *SshHandle, mux: *ClientMux, owned: bool) void {
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
    pub fn emitState(self: *SshHandle, state: State) void {
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
    pub fn emitStateFromConnectionState(
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
        } else if (state.kind == .update_confirmation_required) {
            const conf = zig_state.update_confirmation_required;
            const src = conf.host[0..conf.host_len];
            const max = self.last_update_host.len - 1; // reserve NUL
            const n = @min(src.len, max);
            @memcpy(self.last_update_host[0..n], src[0..n]);
            self.last_update_host[n] = 0;
            self.last_update_host_len = @intCast(n);
            state.payload.update_confirmation.host = @ptrCast(&self.last_update_host[0]);

            // Issue a fresh decision token, invalidating any prior one.
            if (self.next_update_token == 0) self.next_update_token = 1;
            const tok = self.next_update_token;
            self.next_update_token +%= 1;
            self.current_update_token = tok;
            state.payload.update_confirmation.decision_token = tok;
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
    pub fn onStateListener(ctx: *anyopaque, state: protocol.ConnectionState) void {
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

    pub const ChannelState = enum(u32) {
        opening = 0,
        open = 1,
        local_eof = 2,
        closed_state = 3,
    };

    pub fn init(
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

    pub fn deinit(self: *ChannelHandle) void {
        // De-register from parent first; the parent's destruction path
        // asserts the registry is empty.
        self.ssh.unregisterChannel(self);
        self.alloc.destroy(self);
    }

    /// Synchronously emit on_close to the embedder. Used by close +
    /// transport-loss paths. Idempotent.
    pub fn emitClose(self: *ChannelHandle, reason: ChannelCloseReason, message: ?[*:0]const u8) void {
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

    fn muxOnControl(ctx: ?*anyopaque, op: u8, op_payload: []const u8) void {
        const self: *ChannelHandle = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        const cb = self.callbacks.on_control;
        const ud = self.callbacks.userdata;
        self.mutex.unlock();
        if (cb) |f| {
            const ptr: ?*const anyopaque = if (op_payload.len == 0) null else op_payload.ptr;
            f(ud, op, ptr, op_payload.len);
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
    pub const mux_callbacks: ClientMux.Callbacks = .{
        .on_opened = muxOnOpened,
        .on_data = muxOnData,
        .on_credit = muxOnCredit,
        .on_eof = muxOnEof,
        .on_close = muxOnClose,
        .on_control = muxOnControl,
    };
};

// =========================================================================
// Internal helpers — state translation, manager access.
// =========================================================================

/// Public re-export of `translateState` for the per-surface
/// `on_remote_state` callback in `apprt/embedded.zig`. The surface path
/// has no PasswordPrompt token plumbing (a terminal `Remote` backend
/// never prompts), so the password-variant `host` stays empty exactly
/// as the SSH-connection path leaves it before stashing the bytes.
pub fn translateConnectionState(state: protocol.ConnectionState) State {
    return translateState(state);
}

/// Translate `protocol.ConnectionState` into the flat C `ghostty_ssh_state_t`.
/// PasswordPrompt currently surfaces `auth_token=0` because the
/// token-allocation plumbing lands with the password follow-up; embedders
/// can recognize a PASSWORD_REQUIRED transition today but must wait for
/// the follow-up before driving submit_password against a specific token.
pub fn translateState(state: protocol.ConnectionState) State {
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
        .update_confirmation_required => |u| .{ .kind = .update_confirmation_required, .payload = .{ .update_confirmation = .{
            // Host pointer + decision_token are NEVER set here for the
            // same dangling-stack reason as password_required; the caller
            // (emitStateFromConnectionState) stashes the host into the
            // handle-owned buffer and issues the token.
            .host = "",
            .session_count = u.session_count,
            .is_mandatory = u.is_mandatory,
            .decision_token = 0,
        } } },
    };
}

/// Resolve the SshConnectionManager from a ghostty_app_t (cast to
/// *apprt.embedded.App on import). Returns null in environments where
/// the embedded app isn't available (e.g. when invoked from a test
/// harness that doesn't construct a CoreApp).
pub fn managerFromAppPtr(app: ?*anyopaque) ?*SshConnectionManager {
    const app_ptr = app orelse return null;
    const embedded_app: *apprt_embedded.App = @ptrCast(@alignCast(app_ptr));
    return &embedded_app.core_app.ssh_connection_manager;
}

/// Map a C `ghostty_channel_service_e` to the wire-protocol
/// `protocol.ChannelService`. Returns null for values that cannot
/// open a non-terminal channel: `invalid` (the zero sentinel) and
/// `terminal` (which rides the legacy session frames via
/// attach_surface, not the channel mux).
pub fn protocolServiceFromC(service: ChannelService) ?protocol.ChannelService {
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
