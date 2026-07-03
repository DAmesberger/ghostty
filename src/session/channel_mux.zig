//! Per-connection channel multiplexer.
//!
//! Sits on top of the wire protocol (kinds 30-36) and demultiplexes a
//! single connection's frame stream into a set of independent
//! credit-flow-controlled byte channels. Each channel is bound to a
//! `Service` implementation (looked up via a daemon-global `Registry`)
//! that owns the per-channel state and pumps bytes for that channel.
//!
//! Phase 6A.2 lands the wiring skeleton: capability handshake, frame
//! dispatch, channel lifecycle. The service registry is empty in this
//! phase — every `channel_open` is rejected with
//! `status=service_not_supported`. Phase 6A.3 adds the first real
//! services (tcp_connect, browser_proxy, file_transfer, etc.).
//!
//! Threading model:
//!   * `dispatch()` is called by the connection's read thread; it
//!     reads frames serially. No other code touches `channels` from
//!     this side.
//!   * `sendFrame()` is the only mutex-guarded helper; service pump
//!     threads (future) call it concurrently to emit outbound
//!     `channel_data` / `channel_window` / `channel_control` frames.
//!   * Per-channel state owned by a service is the service's
//!     responsibility — services that spawn pump threads must
//!     synchronize their own state.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("protocol.zig");
const shared = @import("shared.zig");

const log = std.log.scoped(.channel_mux);

/// Daemon-global registry of channel services. Keyed by service id;
/// `register` is called at daemon startup, `lookup` is called by the
/// mux on every `channel_open`. The registry is read-only after
/// startup (no `unregister`).
pub const Registry = struct {
    alloc: Allocator,
    services: std.AutoHashMapUnmanaged(u8, Service) = .empty,

    pub fn init(alloc: Allocator) Registry {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Registry) void {
        self.services.deinit(self.alloc);
    }

    /// Register a service. The vtable + ctx must outlive the registry.
    /// `name` is borrowed and must also outlive the registry — typically
    /// a string literal.
    pub fn register(self: *Registry, service: Service) !void {
        try self.services.put(self.alloc, service.id, service);
    }

    pub fn lookup(self: *const Registry, id: u8) ?Service {
        return self.services.get(id);
    }

    /// Snapshot the registered services for the `capabilities` frame.
    /// Caller frees the returned slice.
    pub fn snapshot(self: *const Registry, alloc: Allocator) ![]protocol.CapabilityService {
        // Iterating an empty AutoHashMapUnmanaged that's never been
        // grown segfaults inside the stdlib (the metadata pointer is
        // null and `iterator().next()` doesn't guard against that),
        // so short-circuit the empty case.
        if (self.services.count() == 0) return alloc.alloc(protocol.CapabilityService, 0);
        const out = try alloc.alloc(protocol.CapabilityService, self.services.count());
        var it = self.services.iterator();
        var i: usize = 0;
        while (it.next()) |entry| : (i += 1) {
            out[i] = .{ .id = entry.value_ptr.id, .name = entry.value_ptr.name };
        }
        return out;
    }
};

/// Service interface. A service is registered once at daemon startup
/// and is responsible for instantiating per-channel state on `open`.
pub const Service = struct {
    /// Service id used in `channel_open` frames. Matches a value in
    /// `protocol.ChannelService` (or a custom id ≥ 6).
    id: u8,
    /// Service name, used for capability advertisement and diagnostics.
    /// Must outlive the service; typically a string literal.
    name: []const u8,
    /// Service-defined context passed to every vtable call. May be null.
    ctx: ?*anyopaque = null,
    /// Vtable of per-channel callbacks.
    vtable: *const VTable,

    pub const VTable = struct {
        /// Open a new channel. Returns an opaque per-channel state
        /// pointer (or null for stateless services). The mux owns the
        /// pointer until `on_close` returns; it must not outlive the
        /// channel.
        ///
        /// On error, the mux replies with `channel_opened` carrying a
        /// non-OK status and the channel is never instantiated.
        open: *const fn (
            ctx: ?*anyopaque,
            mux: *Mux,
            channel_id: u32,
            params: []const u8,
            ack_buf: []u8,
        ) ServiceError!OpenResult,

        /// Optional: called once after `open` succeeds and the channel
        /// has been registered in the mux. Services that spawn pump
        /// threads can use this to hand the pump a stable `*Channel`
        /// pointer (which isn't available during `open` itself).
        /// `state` and `ch` are valid until `on_close` returns.
        on_opened: ?*const fn (state: ?*anyopaque, ch: *Channel) void = null,

        /// Inbound `channel_data` frame. `bytes` is borrowed; copy if
        /// you need it past the callback.
        on_data: *const fn (state: ?*anyopaque, bytes: []const u8) ServiceError!void,

        /// Inbound `channel_control` frame.
        on_control: *const fn (state: ?*anyopaque, op: u8, bytes: []const u8) ServiceError!void,

        /// Peer sent EOF (half-close).
        on_eof: *const fn (state: ?*anyopaque) void,

        /// Channel is being torn down. The service MUST release all
        /// resources (sockets, fds, pump threads). After this returns,
        /// the state pointer is invalid.
        on_close: *const fn (state: ?*anyopaque, reason: protocol.ChannelCloseReason, message: []const u8) void,
    };

    pub const OpenResult = struct {
        /// Per-channel state pointer, or null for stateless services.
        state: ?*anyopaque = null,
        /// Service ack bytes to include in the `channel_opened` frame.
        /// May reference `ack_buf` from the `open` call. Empty by
        /// default.
        ack: []const u8 = "",
        /// If non-zero, advertises the credit window the daemon grants
        /// the opener (in 4 KiB units). 0 means "use the negotiated
        /// default".
        peer_window: u16 = 0,
        /// Negotiated flags echoed back to the opener (e.g. compression
        /// commitment).
        flags: protocol.ChannelOpenFlags = .{},
    };
};

pub const ServiceError = error{
    /// Open params were malformed or out of range. Triggers
    /// status=invalid_request.
    InvalidRequest,
    /// Service-level error (e.g. dial refused). Triggers
    /// status=service_error.
    ServiceError,
    /// Policy/sandbox decision. Triggers status=policy_denied.
    PolicyDenied,
    /// Too many concurrent channels. Triggers status=resource_exhausted.
    ResourceExhausted,
    /// Allocator failure.
    OutOfMemory,
};

/// Errors from `Mux.openChannelFromDaemon`.
///
/// The error tells the caller whether the service's `open` callback
/// ran — this matters for resource ownership (e.g. a caller that passed
/// an fd in `service_open_params` needs to know whether the service
/// adopted it):
///   * `ServiceNotRegistered`, `ChannelIdsExhausted` — `open` did NOT
///     run; the caller still owns anything it passed in.
///   * `InvalidRequest`, `ServiceError`, `PolicyDenied`,
///     `ResourceExhausted`, `OutOfMemory` — `open` ran and rejected;
///     the service's own error path has released what it adopted.
pub const OpenChannelError = error{
    /// Service id is not registered in the mux's `Registry`. This is a
    /// programmer error inside the daemon — distinct from a peer
    /// rejecting the open (that surfaces later via `handleOpened`).
    /// `open` did not run.
    ServiceNotRegistered,
    /// Daemon-direction channel-id space exhausted. Requires ~2^31
    /// opens on a single connection without rollover; effectively
    /// unreachable. `open` did not run.
    ChannelIdsExhausted,
    /// The service's `open` callback rejected the request.
    InvalidRequest,
    ServiceError,
    PolicyDenied,
    /// The service's `open` callback ran out of a resource (e.g. could
    /// not spawn a pump thread).
    ResourceExhausted,
    /// Allocator failure (either the service's `open` callback or the
    /// mux's own channel allocation).
    OutOfMemory,
};

/// Which side of the connection opened a channel. The opener picks the
/// channel_id; this enum records, on each end, whether *we* sent the
/// `channel_open` (`local`) or received it (`remote`). `handleOpened`
/// gates on `origin == .local` — only a channel we opened expects a
/// `channel_opened` reply.
pub const ChannelOrigin = enum(u1) {
    /// Opened by the local end (we sent the `channel_open` frame).
    local,
    /// Opened by the peer (we received the `channel_open` frame).
    remote,
};

/// Per-channel state owned by the mux. Pointers into here are stable
/// for the channel's lifetime (i.e. until `Service.on_close` returns).
///
/// A `Channel` is driven by exactly one of two backends:
///   * daemon-side, service-driven: `vtable` is set, `client_callbacks`
///     is null. The mux dispatches inbound frames to the service vtable.
///   * client-side, embedder-driven: `client_callbacks` is set, `vtable`
///     is null. `ClientMux` dispatches inbound frames to the embedder
///     callbacks.
/// Exactly one is non-null; both-null or both-set is a bug.
pub const Channel = struct {
    id: u32,
    service_id: u8,
    /// Which side opened this channel. See `ChannelOrigin`.
    origin: ChannelOrigin,
    /// Per-service state returned by `Service.open`. Null for stateless
    /// services and for client-side channels.
    service_state: ?*anyopaque,
    /// Vtable for fast dispatch (cached from the service entry). Null on
    /// client-side channels — see `client_callbacks`.
    vtable: ?*const Service.VTable,
    /// Embedder callbacks for client-side channels. Null on daemon-side
    /// channels — see `vtable`.
    client_callbacks: ?ClientMux.Callbacks = null,
    /// Embedder context passed to every `client_callbacks` call.
    client_ctx: ?*anyopaque = null,
    /// Outbound credit available to us in bytes (peer's window for our
    /// data). Decremented as we send `channel_data`; incremented by
    /// inbound `channel_window` frames. Read/written under `Mux.mutex`.
    out_credit: usize,
    /// Inbound credit we've granted the peer in bytes. Decremented as
    /// we consume their `channel_data`; replenished by sending
    /// `channel_window`. Read/written under `Mux.mutex`.
    in_credit: usize,
    /// Initial window in bytes (so we can compute the 25% replenish
    /// threshold without re-reading the open params).
    initial_window_bytes: usize,
    /// Bytes the peer has consumed since our last `channel_window`
    /// update — when this reaches initial_window_bytes/4 we send an
    /// update.
    in_unacked: usize,
    /// True once we've sent `channel_eof`.
    local_eof: bool = false,
    /// True once we've received `channel_eof`.
    remote_eof: bool = false,
    /// True once teardown has been initiated. Service pumps must
    /// stop sending after this is observed true.
    closing: bool = false,
    /// Negotiated flags (e.g. compression actually enabled).
    flags: protocol.ChannelOpenFlags,
    /// Set by `handleWindow` after `out_credit` grows. Service pump
    /// threads parked in `waitForCredit` are woken up.
    credit_signal: std.Thread.ResetEvent = .{},
    /// Set by `closeChannel` before invoking `on_close` so pump
    /// threads waiting on credit can exit promptly.
    close_signal: std.Thread.ResetEvent = .{},
    /// Number of dispatch-thread handlers currently holding this
    /// `*Channel` outside `Mux.mutex` (see `Mux.pinChannel`). A teardown
    /// path (`requestClose`, `closeChannelById`, `closeChannel`) may claim
    /// the channel and run its teardown concurrently, but it MUST NOT
    /// `alloc.destroy` the struct while this is non-zero — it hands the
    /// free off via `free_deferred` instead. Read/written under
    /// `Mux.mutex` only. (Client-side channels never use this field.)
    dispatch_refs: usize = 0,
    /// Set by the teardown owner (whoever claimed `closing`) when it
    /// reaches the free step but finds `dispatch_refs > 0`. Whoever then
    /// drops the last dispatch ref performs the deferred `alloc.destroy`.
    /// Guarantees the struct is freed exactly once. Read/written under
    /// `Mux.mutex` only.
    free_deferred: bool = false,

    /// Assert the backend invariant: exactly one of `vtable` /
    /// `client_callbacks` is set. Called right after construction at
    /// every channel-creation site; compiled out in release builds.
    pub fn assertBackendInvariant(self: *const Channel) void {
        const has_vtable = self.vtable != null;
        const has_callbacks = self.client_callbacks != null;
        std.debug.assert(has_vtable != has_callbacks);
    }
};

/// Per-connection multiplexer.
pub const Mux = struct {
    alloc: Allocator,
    /// File descriptor for the connection. The mux does not own the
    /// fd; the caller closes it.
    fd: posix.fd_t,
    /// Service registry (borrowed from the daemon).
    registry: *const Registry,
    /// Negotiated default window (in 4 KiB units), from the peer's
    /// `capabilities` frame. Falls back to
    /// `protocol.default_channel_window_units` if the peer didn't
    /// advertise.
    negotiated_default_window_units: u16 = protocol.default_channel_window_units,
    /// Negotiated max window cap.
    negotiated_max_window_units: u16 = protocol.max_channel_window_units,
    /// Active channels keyed by channel_id.
    channels: std.AutoHashMapUnmanaged(u32, *Channel) = .empty,
    /// Next channel id to allocate for daemon-originated opens. Starts
    /// at `protocol.channel_id_daemon_bit | 1` (daemon-direction ids
    /// always have the high bit set) and increments monotonically under
    /// `mutex`. Wrapping past `0xFFFF_FFFF` yields
    /// `error.ResourceExhausted` — effectively unreachable (2^31 opens
    /// on one connection).
    next_daemon_channel_id: u32 = protocol.channel_id_daemon_bit | 1,
    /// Guards `fd` writes (every outbound frame), the channels map
    /// (since service pump threads also look channels up), and every
    /// channel field that's mutated outside the dispatch thread
    /// (notably `out_credit`).
    mutex: std.Thread.Mutex = .{},

    pub fn init(alloc: Allocator, fd: posix.fd_t, registry: *const Registry) Mux {
        return .{
            .alloc = alloc,
            .fd = fd,
            .registry = registry,
        };
    }

    pub fn deinit(self: *Mux) void {
        // Tear down any channels that didn't close cleanly.
        //
        // A service's `on_close` may itself reach back into the mux and
        // remove other channels (e.g. `port_listener` closing its
        // accepted children via `closeChannelById`). Mutating
        // `self.channels` while iterating it would invalidate the
        // iterator, so snapshot the channel pointers and clear the map
        // up front: any `closeChannelById` from within an `on_close`
        // then becomes a safe no-op, and we own every pointer exactly
        // once for teardown.
        if (self.channels.count() != 0) {
            const snapshot = self.alloc.alloc(*Channel, self.channels.count()) catch {
                // Allocation failure during teardown — fall back to a
                // best-effort in-place close. The map is not mutated
                // here, but a misbehaving `on_close` could; this path
                // only runs under genuine OOM.
                var it = self.channels.iterator();
                while (it.next()) |entry| {
                    const ch = entry.value_ptr.*;
                    ch.closing = true;
                    ch.close_signal.set();
                    ch.credit_signal.set();
                    if (ch.vtable) |vt| vt.on_close(ch.service_state, .daemon_shutdown, "");
                    self.alloc.destroy(ch);
                }
                self.channels.deinit(self.alloc);
                return;
            };
            defer self.alloc.free(snapshot);
            var it = self.channels.iterator();
            var i: usize = 0;
            while (it.next()) |entry| : (i += 1) snapshot[i] = entry.value_ptr.*;
            self.channels.clearRetainingCapacity();

            // Signal every pump first so each `on_close` can join.
            for (snapshot) |ch| {
                ch.closing = true;
                ch.close_signal.set();
                ch.credit_signal.set();
            }
            for (snapshot) |ch| {
                if (ch.vtable) |vt| vt.on_close(ch.service_state, .daemon_shutdown, "");
                self.alloc.destroy(ch);
            }
        }
        self.channels.deinit(self.alloc);
    }

    /// Send a protocol frame with the per-connection mutex held. All
    /// outbound frames on a mux connection must use this helper.
    pub fn sendFrame(
        self: *Mux,
        kind: protocol.Kind,
        payload: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sendFrameLocked(kind, payload);
    }

    /// Same as `sendFrame` but assumes the caller already holds
    /// `self.mutex`. Internal helper for sites that need to combine a
    /// frame send with other mutex-guarded work.
    fn sendFrameLocked(
        self: *Mux,
        kind: protocol.Kind,
        payload: []const u8,
    ) !void {
        try shared.sendFrameFd(self.fd, kind, 0, payload);
    }

    /// Perform the capability handshake. Sends our `capabilities`
    /// frame and parses the peer's reply, recording the negotiated
    /// defaults. Returns the parsed peer capabilities (caller must
    /// free `services` via `alloc.free`).
    pub fn handshake(self: *Mux, peer_first_frame_payload: []const u8) !protocol.Capabilities {
        // Parse the peer's capabilities (already-read first frame).
        const peer = try protocol.Capabilities.parse(self.alloc, peer_first_frame_payload);
        errdefer self.alloc.free(peer.services);

        // Send ours: the full set of services from the registry.
        const services = try self.registry.snapshot(self.alloc);
        defer self.alloc.free(services);

        const ours = protocol.Capabilities{
            .protocol_version = protocol.protocol_version,
            .services = services,
            .default_window = protocol.default_channel_window_units,
            .max_window = protocol.max_channel_window_units,
            .max_payload_kib = protocol.max_payload / 1024,
            .compression_algo = .lz4,
        };
        const encoded = try ours.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrame(.capabilities, encoded);

        // Apply intersection: take the smaller of the two for safety.
        if (peer.default_window > 0 and
            peer.default_window < self.negotiated_default_window_units)
        {
            self.negotiated_default_window_units = peer.default_window;
        }
        if (peer.max_window > 0 and peer.max_window < self.negotiated_max_window_units) {
            self.negotiated_max_window_units = peer.max_window;
        }
        return peer;
    }

    /// Dispatch a frame whose kind is one of the channel kinds
    /// (channel_open..channel_control) or `capabilities`. Returns an
    /// error only on fatal protocol violations; per-channel errors are
    /// handled internally (Close frame sent, channel torn down).
    pub fn dispatch(
        self: *Mux,
        kind: protocol.Kind,
        payload: []const u8,
    ) !void {
        switch (kind) {
            .channel_open => try self.handleOpen(payload),
            .channel_opened => try self.handleOpened(payload),
            .channel_data => try self.handleData(payload),
            .channel_window => try self.handleWindow(payload),
            .channel_eof => try self.handleEof(payload),
            .channel_close => try self.handleClose(payload),
            .channel_control => try self.handleControl(payload),
            .capabilities => {
                // Late capabilities — peer can update its declared
                // limits, but this is rare and we just log + ignore.
                log.debug("late capabilities frame, ignoring", .{});
            },
            else => unreachable, // caller must filter
        }
    }

    fn handleOpen(self: *Mux, payload: []const u8) !void {
        const open = protocol.ChannelOpen.parse(payload) catch {
            log.warn("malformed channel_open frame", .{});
            return;
        };

        // Reject duplicate channel ids.
        self.mutex.lock();
        const duplicate = self.channels.contains(open.channel_id);
        self.mutex.unlock();
        if (duplicate) {
            try self.sendOpened(open.channel_id, .invalid_request, .{}, 0, "duplicate channel_id");
            return;
        }

        // Resolve the service.
        const service = self.registry.lookup(@intFromEnum(open.service)) orelse {
            try self.sendOpened(
                open.channel_id,
                .service_not_supported,
                .{},
                0,
                "",
            );
            return;
        };

        // Resolve the requested window. Caps at the negotiated max.
        const requested_units = if (open.initial_window == 0)
            self.negotiated_default_window_units
        else
            @min(open.initial_window, self.negotiated_max_window_units);
        const window_bytes: usize = @as(usize, requested_units) * 4 * 1024;

        // Service-driven open. We give the service a stack-allocated
        // ack scratch buffer; if it needs more space it can supply its
        // own. Called outside the mux mutex — the service may call
        // back into the mux during its open (e.g. to learn the
        // negotiated window).
        var ack_buf: [256]u8 = undefined;
        const result: Service.OpenResult = service.vtable.open(
            service.ctx,
            self,
            open.channel_id,
            open.service_params,
            &ack_buf,
        ) catch |err| {
            const status: protocol.ChannelOpenStatus = switch (err) {
                error.InvalidRequest => .invalid_request,
                error.ServiceError => .service_error,
                error.PolicyDenied => .policy_denied,
                error.ResourceExhausted => .resource_exhausted,
                error.OutOfMemory => .resource_exhausted,
            };
            try self.sendOpened(open.channel_id, status, .{}, 0, "");
            return;
        };

        // Service accepted — record the channel.
        const ch = try self.alloc.create(Channel);
        ch.* = .{
            .id = open.channel_id,
            .service_id = service.id,
            .origin = .remote,
            .service_state = result.state,
            .vtable = service.vtable,
            .out_credit = window_bytes,
            .in_credit = window_bytes,
            .initial_window_bytes = window_bytes,
            .in_unacked = 0,
            .flags = result.flags,
        };
        ch.assertBackendInvariant();
        errdefer {
            ch.vtable.?.on_close(ch.service_state, .normal, "");
            self.alloc.destroy(ch);
        }
        self.mutex.lock();
        const put_err = self.channels.put(self.alloc, open.channel_id, ch);
        self.mutex.unlock();
        try put_err;

        // Hand the now-registered *Channel to the service, in case it
        // needs the pointer to feed a pump thread spawned in `open`.
        if (service.vtable.on_opened) |hook| {
            hook(result.state, ch);
        }

        const peer_window_units: u16 = if (result.peer_window > 0)
            result.peer_window
        else
            requested_units;
        try self.sendOpened(
            open.channel_id,
            .ok,
            result.flags,
            peer_window_units,
            result.ack,
        );
    }

    /// Handle an inbound `channel_opened` frame. Only meaningful for
    /// daemon-originated channels (`origin == .local`): the peer is
    /// acking an open *we* initiated via `openChannelFromDaemon`. For
    /// channels the peer opened we sent the `channel_opened` ourselves
    /// and never expect one back, so those are logged and ignored.
    fn handleOpened(self: *Mux, payload: []const u8) !void {
        const opened = protocol.ChannelOpened.parse(payload) catch {
            log.warn("malformed channel_opened frame", .{});
            return;
        };
        // Pin so the `closeChannel` / `credit_signal.set()` paths below
        // can't race a pump thread freeing the channel.
        const ch = self.pinChannel(opened.channel_id) orelse {
            log.debug(
                "channel_opened for unknown/closing channel_id={x} — discarding",
                .{opened.channel_id},
            );
            return;
        };
        defer self.unpinChannel(ch);
        // `origin` is immutable after construction, so it's safe to read
        // without the lock.
        if (ch.origin != .local) {
            // We received this open from the peer; we already replied.
            log.debug(
                "ignoring channel_opened for peer-opened channel_id={x}",
                .{opened.channel_id},
            );
            return;
        }
        if (opened.status != .ok) {
            // Peer rejected our open. Tear down our half of the channel.
            log.warn(
                "peer rejected daemon-originated channel_id={x}: status={}",
                .{ opened.channel_id, opened.status },
            );
            try self.closeChannel(ch, .peer_reset, "peer rejected open");
            return;
        }
        // Record the negotiated outbound window. The open frame we sent
        // pre-set `out_credit` to our advertised initial window; the
        // peer's reply is authoritative, so override it.
        self.mutex.lock();
        if (opened.peer_window > 0) {
            ch.out_credit = @as(usize, opened.peer_window) * 4 * 1024;
        }
        self.mutex.unlock();
        // Wake any pump thread parked in `waitForCredit` now that the
        // authoritative window is in place.
        ch.credit_signal.set();
    }

    /// Open a channel from the daemon side. Allocates a daemon-direction
    /// channel_id (high bit set), invokes the service's `open` callback,
    /// records the channel locally, sends `channel_open` to the peer,
    /// and returns the id. Best-effort: does NOT block waiting for the
    /// peer's `channel_opened` ack; if the peer never acks, the channel
    /// still exists on our side until torn down.
    ///
    /// `wire_params` is encoded into the `channel_open` frame sent to
    /// the peer. `service_open_params` is passed to the service's
    /// `open` callback and stays local — it can carry out-of-band state
    /// (e.g. an already-accepted fd) that must not appear on the wire.
    /// Daemon-originated services with no out-of-band state pass the
    /// same slice for both.
    ///
    /// `initial_window_units` (in 4 KiB units) is the inbound window we
    /// advertise to the peer; 0 means "use the negotiated default".
    /// Until the peer's `channel_opened` reply arrives, `out_credit`
    /// holds the same provisional value; `handleOpened` overrides it
    /// with the peer's authoritative grant.
    pub fn openChannelFromDaemon(
        self: *Mux,
        service_id: u8,
        wire_params: []const u8,
        service_open_params: []const u8,
        initial_window_units: u16,
    ) OpenChannelError!u32 {
        // Resolve the service before allocating an id.
        const service = self.registry.lookup(service_id) orelse
            return error.ServiceNotRegistered;

        // Allocate a daemon-direction channel id under the mutex. This
        // happens before `open` runs — `ChannelIdsExhausted` therefore
        // signals to the caller that `open` never ran.
        const channel_id = try self.allocDaemonChannelId();

        // Resolve the window. Caps at the negotiated max, falls back to
        // the negotiated default — same policy as `handleOpen`.
        const requested_units: u16 = if (initial_window_units == 0)
            self.negotiated_default_window_units
        else
            @min(initial_window_units, self.negotiated_max_window_units);
        const window_bytes: usize = @as(usize, requested_units) * 4 * 1024;

        // Service-driven open. Called outside the mutex — the service
        // may call back into the mux during its open. On a service
        // error the service's own error path has released whatever it
        // adopted; we just remap the error.
        var ack_buf: [256]u8 = undefined;
        const result: Service.OpenResult = service.vtable.open(
            service.ctx,
            self,
            channel_id,
            service_open_params,
            &ack_buf,
        ) catch |err| return switch (err) {
            error.InvalidRequest => error.InvalidRequest,
            error.ServiceError => error.ServiceError,
            error.PolicyDenied => error.PolicyDenied,
            error.ResourceExhausted => error.ResourceExhausted,
            error.OutOfMemory => error.OutOfMemory,
        };
        // `open` succeeded — from here every error path must tear the
        // service down via `on_close` (which joins any pump thread the
        // service spawned in `open`).
        errdefer service.vtable.on_close(result.state, .normal, "");

        // Record the channel.
        const ch = try self.alloc.create(Channel);
        errdefer self.alloc.destroy(ch);
        ch.* = .{
            .id = channel_id,
            .service_id = service.id,
            .origin = .local,
            .service_state = result.state,
            .vtable = service.vtable,
            .out_credit = window_bytes,
            .in_credit = window_bytes,
            .initial_window_bytes = window_bytes,
            .in_unacked = 0,
            .flags = result.flags,
        };
        ch.assertBackendInvariant();
        self.mutex.lock();
        const put_err = self.channels.put(self.alloc, channel_id, ch);
        self.mutex.unlock();
        try put_err;

        // The channel is now registered and fully live; no failure past
        // this point rolls it back (the `errdefer`s above stop firing
        // once we return success). The peer announcement below is
        // best-effort: if encoding or sending the `channel_open` frame
        // fails the channel still exists locally — it gets reaped by
        // `Mux.deinit` or by the connection's outer teardown when the
        // fd dies, the same as any other un-acked channel.

        // Send the `channel_open` frame to the peer FIRST — before
        // firing `on_opened`. `on_opened` unblocks the service's pump
        // thread, which may immediately emit `channel_data`; the peer
        // must see `channel_open` ahead of any data frame for the
        // channel, so the open send has to win that race.
        const open = protocol.ChannelOpen{
            .channel_id = channel_id,
            .service = @enumFromInt(service.id),
            .flags = result.flags,
            .initial_window = requested_units,
            .service_params = wire_params,
        };
        if (open.encode(self.alloc)) |encoded| {
            defer self.alloc.free(encoded);
            self.sendFrame(.channel_open, encoded) catch |err| {
                log.warn("failed to send channel_open: {}", .{err});
            };
        } else |err| {
            log.warn("failed to encode channel_open: {}", .{err});
        }

        // Hand the now-registered *Channel to the service so a pump
        // thread spawned in `open` can grab a stable pointer and start
        // producing data.
        if (service.vtable.on_opened) |hook| {
            hook(result.state, ch);
        }
        return channel_id;
    }

    /// Allocate the next daemon-direction channel id. Caller must NOT
    /// hold `mutex`. Monotonic, skips ids already in `channels`.
    fn allocDaemonChannelId(self: *Mux) error{ChannelIdsExhausted}!u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Bound the search by the channel count + 1: with N live
        // channels at most N+1 probes find a free slot.
        var probes: usize = self.channels.count() + 1;
        while (probes > 0) : (probes -= 1) {
            const candidate = self.next_daemon_channel_id;
            // Advance, wrapping back into the daemon-direction range.
            // `invalid_channel_id` (all-ones) is reserved, so the range
            // is [daemon_bit | 1, 0xFFFF_FFFF).
            self.next_daemon_channel_id =
                if (candidate >= protocol.invalid_channel_id - 1)
                    protocol.channel_id_daemon_bit | 1
                else
                    candidate + 1;
            if (!self.channels.contains(candidate)) return candidate;
        }
        return error.ChannelIdsExhausted;
    }

    /// Look up a channel by id and pin it for the calling dispatch-thread
    /// handler. Returns null (nothing pinned) if the channel is unknown or
    /// already tearing down (`closing`); the inbound frame is then dropped.
    ///
    /// While pinned, the `*Channel` struct is guaranteed to remain
    /// allocated even if a service pump thread concurrently claims and
    /// tears the channel down via `requestClose` / `closeChannelById`:
    /// those paths detect the pin (`dispatch_refs > 0`) and defer the
    /// final `alloc.destroy` to the matching `unpinChannel`. This closes
    /// the window where a handler cached a `*Channel` under the lock,
    /// released it, and then dereferenced a pointer a pump had freed.
    ///
    /// The caller MUST pair every non-null return with exactly one
    /// `unpinChannel` (use `defer`). This only ever *defers* a
    /// non-blocking `destroy`; it never blocks a teardown thread and adds
    /// no new lock, so it cannot deadlock. Dispatch-thread only.
    fn pinChannel(self: *Mux, channel_id: u32) ?*Channel {
        self.mutex.lock();
        defer self.mutex.unlock();
        const ch = self.channels.get(channel_id) orelse return null;
        if (ch.closing) return null;
        ch.dispatch_refs += 1;
        return ch;
    }

    /// Drop a dispatch-thread pin taken by `pinChannel`. If the channel
    /// was torn down while pinned (its teardown owner set `free_deferred`)
    /// and this is the last outstanding pin, perform the deferred free.
    fn unpinChannel(self: *Mux, ch: *Channel) void {
        self.mutex.lock();
        ch.dispatch_refs -= 1;
        const do_free = ch.free_deferred and ch.dispatch_refs == 0;
        self.mutex.unlock();
        if (do_free) self.alloc.destroy(ch);
    }

    fn handleData(self: *Mux, payload: []const u8) !void {
        const data = protocol.ChannelData.parse(payload) catch {
            log.warn("malformed channel_data frame", .{});
            return;
        };
        // Pin the channel for the whole dispatch so a service pump thread's
        // requestClose / closeChannelById can't free `ch` (nor its
        // `service_state`) while we dereference it below.
        const ch = self.pinChannel(data.channel_id) orelse {
            log.debug("channel_data for unknown/closing channel_id={d} — discarding", .{data.channel_id});
            return;
        };
        defer self.unpinChannel(ch);

        // Flow-control: peer is sending against the credit we granted.
        // Drop + close if they exceed it.
        self.mutex.lock();
        if (data.bytes.len > ch.in_credit) {
            log.warn("channel_id={d} window violation: sent {d}, credit {d}", .{
                ch.id, data.bytes.len, ch.in_credit,
            });
            self.mutex.unlock();
            try self.closeChannel(ch, .peer_reset, "window violation");
            return;
        }
        ch.in_credit -= data.bytes.len;
        ch.in_unacked += data.bytes.len;
        self.mutex.unlock();

        // Hand bytes to the service outside the mutex — the service
        // may call back into the mux (e.g. to send response data).
        ch.vtable.?.on_data(ch.service_state, data.bytes) catch |err| {
            const reason: protocol.ChannelCloseReason = switch (err) {
                error.PolicyDenied => .policy_denied,
                else => .service_error,
            };
            try self.closeChannel(ch, reason, @errorName(err));
            return;
        };

        // Replenish the credit window eagerly. Skip if the channel began
        // closing while `on_data` ran (it's still pinned/alive, but a
        // window update for a torn-down channel would be pointless).
        self.mutex.lock();
        const should_replenish = !ch.closing and ch.in_unacked >= ch.initial_window_bytes / 4;
        var credit_to_grant: u32 = 0;
        if (should_replenish) {
            credit_to_grant = @intCast(ch.in_unacked);
            ch.in_credit += ch.in_unacked;
            ch.in_unacked = 0;
        }
        if (should_replenish) {
            const win = protocol.ChannelWindow{
                .channel_id = ch.id,
                .credit_bytes = credit_to_grant,
            };
            const win_bytes = win.encode();
            self.sendFrameLocked(.channel_window, &win_bytes) catch |err| {
                log.warn("failed to send channel_window: {}", .{err});
            };
        }
        self.mutex.unlock();
    }

    fn handleWindow(self: *Mux, payload: []const u8) !void {
        const win = protocol.ChannelWindow.parse(payload) catch {
            log.warn("malformed channel_window frame", .{});
            return;
        };
        // Pin so `ch.credit_signal.set()` below can't race a pump thread
        // freeing the channel.
        const ch = self.pinChannel(win.channel_id) orelse return;
        defer self.unpinChannel(ch);
        self.mutex.lock();
        // Saturating-add to prevent overflow on misbehaving peers.
        ch.out_credit = std.math.add(usize, ch.out_credit, win.credit_bytes) catch
            std.math.maxInt(usize);
        self.mutex.unlock();
        // Wake any pump threads parked in waitForCredit.
        ch.credit_signal.set();
    }

    fn handleEof(self: *Mux, payload: []const u8) !void {
        const eof = protocol.ChannelEof.parse(payload) catch return;
        // Pin so the `on_eof` deref below can't race a pump thread freeing
        // the channel.
        const ch = self.pinChannel(eof.channel_id) orelse return;
        defer self.unpinChannel(ch);
        self.mutex.lock();
        if (ch.remote_eof) {
            self.mutex.unlock();
            return; // duplicate
        }
        ch.remote_eof = true;
        self.mutex.unlock();
        ch.vtable.?.on_eof(ch.service_state);
    }

    fn handleClose(self: *Mux, payload: []const u8) !void {
        const close = protocol.ChannelClose.parse(payload) catch return;
        // Resolve the id and claim the teardown in one critical
        // section. If a pump thread already claimed it via
        // `requestClose`, back off — that thread owns the destroy.
        self.mutex.lock();
        const ch = self.channels.get(close.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        if (ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.closing = true;
        self.mutex.unlock();
        try self.teardownClaimedChannel(ch, close.reason, close.message, false);
    }

    fn handleControl(self: *Mux, payload: []const u8) !void {
        const ctrl = protocol.ChannelControl.parse(payload) catch return;
        // Pin so the `on_control` deref (and any `closeChannel` on error)
        // below can't race a pump thread freeing the channel.
        const ch = self.pinChannel(ctrl.channel_id) orelse return;
        defer self.unpinChannel(ch);
        ch.vtable.?.on_control(ch.service_state, ctrl.op, ctrl.op_payload) catch |err| {
            const reason: protocol.ChannelCloseReason = switch (err) {
                error.PolicyDenied => .policy_denied,
                else => .service_error,
            };
            try self.closeChannel(ch, reason, @errorName(err));
        };
    }

    /// Initiate teardown from the daemon side: notify the service,
    /// emit `channel_close`, remove from the registry. Called from
    /// the dispatch thread only (handleData on window violation,
    /// handleControl on service error).
    fn closeChannel(
        self: *Mux,
        ch: *Channel,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
    ) !void {
        // Claim the teardown: flip `closing` false->true under the lock.
        // The thread that wins this claim owns the destroy; any other
        // path observing `closing == true` backs off. If it was already
        // claimed this is a no-op — `closeChannel` is now idempotent.
        self.mutex.lock();
        if (ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.closing = true;
        self.mutex.unlock();
        try self.teardownClaimedChannel(ch, reason, message, true);
    }

    /// Run the teardown for a channel whose `closing` flag this caller
    /// has already claimed (flipped false->true under `mutex`). Once
    /// claimed, the `*Channel` is stable — no other path destroys a
    /// channel it did not claim — so this is safe to run with the lock
    /// released.
    ///
    /// `send_close_frame` controls whether a `channel_close` frame is
    /// emitted to the peer: true for daemon-initiated teardown, false
    /// when responding to a peer-initiated close (the peer already tore
    /// down its side — echoing a close back would be redundant).
    fn teardownClaimedChannel(
        self: *Mux,
        ch: *Channel,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
        send_close_frame: bool,
    ) !void {
        const id = ch.id;
        // Signal first so the service's pump threads can exit before
        // `on_close` tries to join them.
        ch.close_signal.set();
        ch.credit_signal.set();
        // on_close outside the mutex — pump threads may be blocked
        // acquiring it.
        ch.vtable.?.on_close(ch.service_state, reason, message);

        // Send the close frame. Best-effort — if the peer is gone the
        // outer loop will tear everything down anyway.
        if (send_close_frame) {
            const close = protocol.ChannelClose{
                .channel_id = id,
                .reason = reason,
                .message = message,
            };
            if (close.encode(self.alloc)) |encoded| {
                defer self.alloc.free(encoded);
                self.sendFrame(.channel_close, encoded) catch |err| {
                    log.warn("failed to send channel_close: {}", .{err});
                };
            } else |err| {
                log.warn("failed to encode channel_close: {}", .{err});
            }
        }

        self.mutex.lock();
        _ = self.channels.remove(id);
        // If a dispatch-thread handler is currently pinning `ch`, hand the
        // free off to its `unpinChannel`; otherwise free now. Deciding
        // this under the lock (where `dispatch_refs` is stable) makes the
        // handoff race-free — see `pinChannel`.
        const do_free = ch.dispatch_refs == 0;
        if (!do_free) ch.free_deferred = true;
        self.mutex.unlock();
        if (do_free) self.alloc.destroy(ch);
    }

    /// Tear down a channel by id, running the full close path: the
    /// service's `on_close` (which joins any pump threads), a
    /// `channel_close` frame to the peer, removal from the registry,
    /// and free. No-op if the channel id is unknown or already closing.
    ///
    /// This is the safe way for one daemon-side service to tear down
    /// another channel it spawned (e.g. `port_listener` closing its
    /// accepted child channels on listener teardown). Only the
    /// `channel_id` crosses the lock boundary — the id lookup and the
    /// `closing` claim happen in one critical section, so this never
    /// holds a `*Channel` another thread could free. Safe to call from
    /// any thread.
    pub fn closeChannelById(
        self: *Mux,
        channel_id: u32,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
    ) void {
        // Resolve the id and claim the teardown in one critical
        // section. Whoever flips `closing` owns the destroy.
        self.mutex.lock();
        const ch = self.channels.get(channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        if (ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.closing = true;
        self.mutex.unlock();
        self.teardownClaimedChannel(ch, reason, message, true) catch |err| {
            log.warn("closeChannelById: {}", .{err});
        };
    }

    // =====================================================================
    // Service-facing API
    // =====================================================================
    //
    // These are the helpers a `Service` implementation calls from its
    // pump threads (or from inside vtable callbacks). They handle
    // credit accounting and locking so services don't have to.

    /// Look up a channel by id. Returns null if the channel doesn't
    /// exist. The pointer is only valid while the service's
    /// `on_close` has not yet returned (the mux frees the Channel
    /// immediately after).
    pub fn getChannel(self: *Mux, channel_id: u32) ?*Channel {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.channels.get(channel_id);
    }

    /// Send up to `bytes.len` bytes as one or more `channel_data`
    /// frames, respecting the outbound credit window. Returns the
    /// number of bytes actually sent. Returns 0 only if the channel
    /// is closing OR there is currently no credit — the caller is
    /// expected to wait on `waitForCredit` and retry. May return less
    /// than `bytes.len` even when credit > 0, because each frame is
    /// capped at `protocol.max_payload - ChannelData.fixed_size`.
    pub fn sendChannelData(self: *Mux, ch: *Channel, bytes: []const u8) !usize {
        if (bytes.len == 0) return 0;
        const max_data = protocol.max_payload - protocol.ChannelData.fixed_size;

        self.mutex.lock();
        if (ch.closing or ch.local_eof) {
            self.mutex.unlock();
            return 0;
        }
        if (ch.out_credit == 0) {
            // Caller must wait on credit_signal.
            ch.credit_signal.reset();
            self.mutex.unlock();
            return 0;
        }
        const to_send = @min(@min(bytes.len, ch.out_credit), max_data);
        ch.out_credit -= to_send;

        // Build + send the frame while still holding the mutex so
        // outbound frames remain serialized on the wire.
        const frame = protocol.ChannelData{ .channel_id = ch.id, .bytes = bytes[0..to_send] };
        const encoded = try frame.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrameLocked(.channel_data, encoded);
        self.mutex.unlock();
        return to_send;
    }

    /// Send a `channel_eof` frame for the given channel. Idempotent —
    /// subsequent calls are no-ops.
    pub fn sendChannelEof(self: *Mux, ch: *Channel) !void {
        self.mutex.lock();
        if (ch.local_eof or ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.local_eof = true;
        const eof_bytes = (protocol.ChannelEof{ .channel_id = ch.id }).encode();
        try self.sendFrameLocked(.channel_eof, &eof_bytes);
        self.mutex.unlock();
    }

    /// Send a `channel_close` frame and tear down the channel from
    /// the service side. Used when a service decides the channel
    /// should die (e.g. upstream TCP dropped with RST). The service's
    /// `on_close` callback is NOT called — the service initiated this
    /// teardown and already knows.
    pub fn requestClose(
        self: *Mux,
        ch: *Channel,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
    ) !void {
        self.mutex.lock();
        if (ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.closing = true;
        const id = ch.id;
        const frame = protocol.ChannelClose{
            .channel_id = id,
            .reason = reason,
            .message = message,
        };
        const encoded = try frame.encode(self.alloc);
        defer self.alloc.free(encoded);
        // Best-effort send. If the peer is gone, the outer loop will
        // tear everything down anyway.
        self.sendFrameLocked(.channel_close, encoded) catch |err| {
            log.warn("failed to send channel_close: {}", .{err});
        };
        // Remove the channel from the registry. The service must NOT
        // touch ch after this returns.
        _ = self.channels.remove(id);
        // Wake any other pumps for the same channel (defensive). Done
        // under the lock so a concurrent `unpinChannel` can't free `ch`
        // out from under us between here and the destroy decision below.
        // (ResetEvent.set() does not take `Mux.mutex`, so this can't
        // self-deadlock.)
        ch.close_signal.set();
        ch.credit_signal.set();
        // If a dispatch-thread handler is currently pinning `ch`, hand the
        // free off to its `unpinChannel`; otherwise free now.
        const do_free = ch.dispatch_refs == 0;
        if (!do_free) ch.free_deferred = true;
        self.mutex.unlock();
        if (do_free) self.alloc.destroy(ch);
    }

    /// Block until `out_credit` is non-zero for the given channel,
    /// the channel begins closing, or the timeout expires. Returns
    /// `true` if credit is available, `false` if the channel is
    /// closing OR the timeout fired.
    pub fn waitForCredit(self: *Mux, ch: *Channel, timeout_ns: ?u64) bool {
        // Fast path under lock.
        self.mutex.lock();
        if (ch.closing) {
            self.mutex.unlock();
            return false;
        }
        if (ch.out_credit > 0) {
            self.mutex.unlock();
            return true;
        }
        ch.credit_signal.reset();
        self.mutex.unlock();

        // Slow path: wait. `timeout_ns == null` waits forever.
        if (timeout_ns) |ns| {
            ch.credit_signal.timedWait(ns) catch return false;
        } else {
            ch.credit_signal.wait();
        }

        // Re-check under lock.
        self.mutex.lock();
        defer self.mutex.unlock();
        return !ch.closing and ch.out_credit > 0;
    }

    fn sendOpened(
        self: *Mux,
        channel_id: u32,
        status: protocol.ChannelOpenStatus,
        flags: protocol.ChannelOpenFlags,
        peer_window_units: u16,
        ack: []const u8,
    ) !void {
        const opened = protocol.ChannelOpened{
            .channel_id = channel_id,
            .status = status,
            .flags = flags,
            .peer_window = peer_window_units,
            .service_ack = ack,
        };
        const encoded = try opened.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrame(.channel_opened, encoded);
    }
};

// =========================================================================
// Client-side multiplexer
// =========================================================================
//
// `ClientMux` is the opener-side counterpart to `Mux`. Where `Mux`
// serves a daemon's `Registry` of services, `ClientMux` is driven by an
// embedder (libghostty → Swift): the embedder opens channels, supplies
// per-channel callbacks, and writes/reads bytes. It reuses the shared
// `Channel` struct (with `client_callbacks` set instead of `vtable`),
// the same credit-accounting and max-payload chunking, and a symmetric
// `handleOpened`.
//
// Threading model mirrors `Mux`:
//   * a single dispatch thread reads frames and calls `dispatch`; every
//     embedder callback fires from that thread.
//   * `writeChannel` / `channelEof` / `channelClose` may be called from
//     any thread; channels-map and `out_credit` access is `mutex`-
//     guarded, frame writes go through `sendFrameLocked`.

pub const ClientMux = struct {
    alloc: Allocator,
    /// Connection fd. Not owned — the caller closes it.
    fd: posix.fd_t,
    /// Negotiated default / max window (4 KiB units). Set from the
    /// peer's `capabilities` frame via `applyPeerCapabilities`; until
    /// then the protocol defaults stand.
    negotiated_default_window_units: u16 = protocol.default_channel_window_units,
    negotiated_max_window_units: u16 = protocol.max_channel_window_units,
    /// Active channels keyed by channel_id.
    channels: std.AutoHashMapUnmanaged(u32, *Channel) = .empty,
    /// Next client-direction channel id. Client ids always have the
    /// high bit clear; the allocator wraps at the daemon-bit boundary.
    next_client_channel_id: u32 = 1,
    /// Guards `fd` writes, the channels map, and every channel field
    /// mutated outside the dispatch thread (notably `out_credit`).
    mutex: std.Thread.Mutex = .{},
    /// Optional handler for daemon-originated `channel_open` frames.
    /// When null, all inbound opens are rejected with `service_not_supported`.
    on_inbound: ?InboundHandler = null,

    /// Per-channel embedder callbacks. All fire from the dispatch
    /// thread; the embedder is responsible for hopping to its own
    /// executor if needed.
    pub const Callbacks = struct {
        /// The peer accepted the open. `ack` is the service ack bytes
        /// (borrowed — copy if retained); `peer_window_units` is the
        /// outbound credit window the peer granted, in 4 KiB units.
        on_opened: *const fn (ctx: ?*anyopaque, ack: []const u8, peer_window_units: u16) void,
        /// Inbound `channel_data`. `bytes` is borrowed for the call.
        on_data: *const fn (ctx: ?*anyopaque, bytes: []const u8) void,
        /// Additional outbound credit became available (`channel_window`
        /// frame, or the initial grant from `channel_opened`).
        on_credit: *const fn (ctx: ?*anyopaque, credit_bytes: u32) void,
        /// Peer half-closed (`channel_eof`).
        on_eof: *const fn (ctx: ?*anyopaque) void,
        /// Channel torn down. After this returns the channel id is
        /// invalid; the embedder must drop its handle.
        on_close: *const fn (ctx: ?*anyopaque, reason: protocol.ChannelCloseReason, message: []const u8) void,
    };

    /// Handler for daemon-originated `channel_open` frames. If set on
    /// the `ClientMux`, inbound opens are dispatched here instead of
    /// being rejected with `service_not_supported`.
    pub const InboundHandler = struct {
        ctx: ?*anyopaque,
        /// Called once per inbound `channel_open`. The handler must either:
        ///   * Return non-null `Callbacks` — accepting the channel. The mux
        ///     allocates a Channel, registers it, sends `channel_opened(.ok)`,
        ///     and fires `cbs.on_opened`. The `ctx` supplied as the third
        ///     argument becomes the per-channel context passed to every
        ///     subsequent callback.
        ///   * Return null — rejecting the channel. The mux sends
        ///     `channel_opened(.service_not_supported)` and nothing is
        ///     allocated.
        ///
        /// `params` is borrowed for the duration of this call — copy if
        /// retention is needed. Fires on the dispatch thread; MUST NOT block.
        open: *const fn (
            ctx: ?*anyopaque,
            channel_id: u32,
            service: protocol.ChannelService,
            params: []const u8,
            channel_ctx_out: *?*anyopaque,
        ) ?Callbacks,
    };

    pub fn init(alloc: Allocator, fd: posix.fd_t) ClientMux {
        return .{ .alloc = alloc, .fd = fd };
    }

    /// Send our `capabilities` frame to the peer. MUST be called once,
    /// before any `openChannel`, as the very first frame on the mux fd.
    ///
    /// The daemon's `ClientThread.main_` requires `.capabilities` as the
    /// first frame (`daemon.zig:413-414`) — without it the daemon falls
    /// through `else => {}`, closes the connection, and every subsequent
    /// `channel_open` lands on a dead socket. The peer responds with its
    /// own capabilities, which we apply via `applyPeerCapabilities` on
    /// receipt.
    pub fn sendCapabilities(self: *ClientMux) !void {
        const ours = protocol.Capabilities{
            .protocol_version = protocol.protocol_version,
            .services = &.{},
            .default_window = protocol.default_channel_window_units,
            .max_window = protocol.max_channel_window_units,
            .max_payload_kib = protocol.max_payload / 1024,
            .compression_algo = .lz4,
        };
        const encoded = try ours.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrameLocked(.capabilities, encoded);
    }

    /// Read frames from `self.fd` until EOF and dispatch each to the
    /// embedder. Counterpart to `Mux`'s server-side `runMuxMode` loop
    /// (`daemon.zig:476`). Without this reader, `channel_opened`,
    /// `channel_data`, `channel_close`, etc. accumulate in the
    /// socketpair buffer with no consumer — embedders see open frames
    /// land but never receive a response, manifesting as hanging
    /// channels.
    ///
    /// Returns when `self.fd` EOFs (peer closed) or any read/dispatch
    /// error occurs. Callers typically run this on a dedicated thread
    /// spawned right after `sendCapabilities`.
    pub fn runReader(self: *ClientMux) void {
        const rlog = std.log.scoped(.channel_mux);
        while (true) {
            var hbuf: [protocol.header_size]u8 = undefined;
            readAllFd(self.fd, &hbuf) catch return;
            const hdr = protocol.Header.parseFromBuf(&hbuf) catch {
                rlog.warn("client: malformed frame header", .{});
                return;
            };
            if (hdr.len > protocol.max_payload) {
                rlog.warn("client: oversized frame len={d}", .{hdr.len});
                return;
            }
            const buf = self.alloc.alloc(u8, hdr.len) catch {
                rlog.warn("client: alloc {d} bytes for frame failed", .{hdr.len});
                return;
            };
            defer self.alloc.free(buf);
            readAllFd(self.fd, buf) catch return;
            self.dispatch(hdr.kind, buf) catch |err| {
                rlog.warn("client: dispatch error: {}", .{err});
                return;
            };
        }
    }

    fn readAllFd(fd: posix.fd_t, buf: []u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = posix.read(fd, buf[off..]) catch |err| return err;
            if (n == 0) return error.UnexpectedEOF;
            off += n;
        }
    }

    pub fn deinit(self: *ClientMux) void {
        // Fire on_close for every channel that's still live so the
        // embedder can release its handles, then free.
        //
        // An embedder `on_close` callback may itself call back into the
        // mux and close a sibling channel (`channelClose`), mutating
        // `self.channels` mid-iteration. Snapshot the channel pointers
        // and clear the map up front — mirroring `Mux.deinit` — so any
        // re-entrant `channelClose` becomes a safe no-op and every
        // pointer is owned exactly once for teardown.
        if (self.channels.count() != 0) {
            const snapshot = self.alloc.alloc(*Channel, self.channels.count()) catch {
                // Allocation failure during teardown — best-effort
                // in-place close. Only runs under genuine OOM.
                var it = self.channels.iterator();
                while (it.next()) |entry| {
                    const ch = entry.value_ptr.*;
                    ch.closing = true;
                    ch.close_signal.set();
                    ch.credit_signal.set();
                    if (ch.client_callbacks) |cb| {
                        cb.on_close(ch.client_ctx, .daemon_shutdown, "");
                    }
                    self.alloc.destroy(ch);
                }
                self.channels.deinit(self.alloc);
                return;
            };
            defer self.alloc.free(snapshot);
            var it = self.channels.iterator();
            var i: usize = 0;
            while (it.next()) |entry| : (i += 1) snapshot[i] = entry.value_ptr.*;
            self.channels.clearRetainingCapacity();

            // Signal every channel first, then fire callbacks + free.
            for (snapshot) |ch| {
                ch.closing = true;
                ch.close_signal.set();
                ch.credit_signal.set();
            }
            for (snapshot) |ch| {
                if (ch.client_callbacks) |cb| {
                    cb.on_close(ch.client_ctx, .daemon_shutdown, "");
                }
                self.alloc.destroy(ch);
            }
        }
        self.channels.deinit(self.alloc);
    }

    /// Record negotiated window limits from the peer's `capabilities`
    /// frame. Takes the smaller of the two for safety, matching
    /// `Mux.handshake`.
    pub fn applyPeerCapabilities(self: *ClientMux, peer: protocol.Capabilities) void {
        if (peer.default_window > 0 and
            peer.default_window < self.negotiated_default_window_units)
        {
            self.negotiated_default_window_units = peer.default_window;
        }
        if (peer.max_window > 0 and peer.max_window < self.negotiated_max_window_units) {
            self.negotiated_max_window_units = peer.max_window;
        }
    }

    fn sendFrameLocked(
        self: *ClientMux,
        kind: protocol.Kind,
        payload: []const u8,
    ) !void {
        try shared.sendFrameFd(self.fd, kind, 0, payload);
    }

    fn sendFrame(self: *ClientMux, kind: protocol.Kind, payload: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sendFrameLocked(kind, payload);
    }

    /// Open a channel toward the peer. Allocates a client-direction
    /// channel id, registers the channel, sends `channel_open`, and
    /// returns the id. Best-effort: does not block for the peer's
    /// `channel_opened` ack. Outbound credit starts at 0 — the embedder
    /// must wait for `on_opened` / `on_credit` before `writeChannel`
    /// will accept bytes.
    pub fn openChannel(
        self: *ClientMux,
        service: protocol.ChannelService,
        flags: protocol.ChannelOpenFlags,
        initial_window_units: u16,
        params: []const u8,
        callbacks: Callbacks,
        ctx: ?*anyopaque,
    ) !u32 {
        const channel_id = try self.allocClientChannelId();

        const requested_units: u16 = if (initial_window_units == 0)
            self.negotiated_default_window_units
        else
            @min(initial_window_units, self.negotiated_max_window_units);
        const window_bytes: usize = @as(usize, requested_units) * 4 * 1024;

        const ch = try self.alloc.create(Channel);
        errdefer self.alloc.destroy(ch);
        ch.* = .{
            .id = channel_id,
            .service_id = @intFromEnum(service),
            .origin = .local,
            .service_state = null,
            .vtable = null,
            .client_callbacks = callbacks,
            .client_ctx = ctx,
            // Pre-ack: no outbound credit until `channel_opened`. The
            // embedder's `ghostty_channel_write` contract returns 0
            // when credit is 0 and waits for `on_credit`.
            // TODO(0.5-RTT): allow speculative pre-ack writes for
            // browser_proxy.
            .out_credit = 0,
            .in_credit = window_bytes,
            .initial_window_bytes = window_bytes,
            .in_unacked = 0,
            .flags = flags,
        };
        ch.assertBackendInvariant();
        self.mutex.lock();
        const put_err = self.channels.put(self.alloc, channel_id, ch);
        self.mutex.unlock();
        try put_err;

        const open = protocol.ChannelOpen{
            .channel_id = channel_id,
            .service = service,
            .flags = flags,
            .initial_window = requested_units,
            .service_params = params,
        };
        const encoded = open.encode(self.alloc) catch |err| switch (err) {
            error.OutOfMemory => {
                self.mutex.lock();
                _ = self.channels.remove(channel_id);
                self.mutex.unlock();
                self.alloc.destroy(ch);
                return error.OutOfMemory;
            },
        };
        defer self.alloc.free(encoded);
        self.sendFrame(.channel_open, encoded) catch |err| {
            log.warn("client: failed to send channel_open: {}", .{err});
        };
        return channel_id;
    }

    /// Allocate the next client-direction channel id. Caller must NOT
    /// hold `mutex`. Monotonic, wraps at the daemon-bit boundary, skips
    /// ids already in `channels`.
    fn allocClientChannelId(self: *ClientMux) error{ResourceExhausted}!u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var probes: usize = self.channels.count() + 1;
        while (probes > 0) : (probes -= 1) {
            const candidate = self.next_client_channel_id;
            // Client ids must keep the high bit clear; wrap back to 1.
            self.next_client_channel_id =
                if (candidate >= protocol.channel_id_daemon_bit - 1)
                    1
                else
                    candidate + 1;
            if (!self.channels.contains(candidate)) return candidate;
        }
        return error.ResourceExhausted;
    }

    /// Dispatch a channel/capabilities frame. Mirrors `Mux.dispatch`.
    pub fn dispatch(
        self: *ClientMux,
        kind: protocol.Kind,
        payload: []const u8,
    ) !void {
        switch (kind) {
            .channel_opened => try self.handleOpened(payload),
            .channel_data => try self.handleData(payload),
            .channel_window => try self.handleWindow(payload),
            .channel_eof => try self.handleEof(payload),
            .channel_close => try self.handleClose(payload),
            .channel_control => self.handleControl(payload),
            .channel_open => try self.handleInboundOpen(payload),
            .capabilities => {
                log.debug("client: late capabilities frame, ignoring", .{});
            },
            else => unreachable, // caller must filter
        }
    }

    fn handleOpened(self: *ClientMux, payload: []const u8) !void {
        const opened = protocol.ChannelOpened.parse(payload) catch {
            log.warn("client: malformed channel_opened frame", .{});
            return;
        };
        self.mutex.lock();
        const ch = self.channels.get(opened.channel_id) orelse {
            self.mutex.unlock();
            log.debug(
                "client: channel_opened for unknown channel_id={d} — discarding",
                .{opened.channel_id},
            );
            return;
        };
        const cb = ch.client_callbacks orelse {
            self.mutex.unlock();
            return;
        };
        if (opened.status != .ok) {
            // Peer rejected the open. Remove + notify the embedder.
            ch.closing = true;
            _ = self.channels.remove(opened.channel_id);
            self.mutex.unlock();
            ch.close_signal.set();
            ch.credit_signal.set();
            cb.on_close(ch.client_ctx, .peer_reset, "peer rejected open");
            self.alloc.destroy(ch);
            return;
        }
        // Record the negotiated flags + outbound window.
        ch.flags = opened.flags;
        const credit_units = opened.peer_window;
        if (credit_units > 0) {
            ch.out_credit = @as(usize, credit_units) * 4 * 1024;
        }
        self.mutex.unlock();

        // Fire on_opened, then the initial credit grant. Both run on
        // the dispatch thread; `service_ack` is borrowed from `payload`
        // which outlives this call.
        cb.on_opened(ch.client_ctx, opened.service_ack, credit_units);
        if (credit_units > 0) {
            ch.credit_signal.set();
            cb.on_credit(ch.client_ctx, @as(u32, credit_units) * 4 * 1024);
        }
    }

    fn handleData(self: *ClientMux, payload: []const u8) !void {
        const data = protocol.ChannelData.parse(payload) catch {
            log.warn("client: malformed channel_data frame", .{});
            return;
        };
        self.mutex.lock();
        const ch = self.channels.get(data.channel_id) orelse {
            self.mutex.unlock();
            log.debug(
                "client: channel_data for unknown channel_id={d} — discarding",
                .{data.channel_id},
            );
            return;
        };
        const cb = ch.client_callbacks orelse {
            self.mutex.unlock();
            return;
        };
        if (data.bytes.len > ch.in_credit) {
            log.warn("client: channel_id={d} window violation: sent {d}, credit {d}", .{
                ch.id, data.bytes.len, ch.in_credit,
            });
            self.mutex.unlock();
            _ = self.closeByIdInternal(data.channel_id, .peer_reset, "window violation", true);
            return;
        }
        ch.in_credit -= data.bytes.len;
        ch.in_unacked += data.bytes.len;
        self.mutex.unlock();

        cb.on_data(ch.client_ctx, data.bytes);

        // Replenish the inbound credit window eagerly, same 25%
        // threshold as the daemon side.
        self.mutex.lock();
        const should_replenish = ch.in_unacked >= ch.initial_window_bytes / 4;
        if (should_replenish) {
            const credit_to_grant: u32 = @intCast(ch.in_unacked);
            ch.in_credit += ch.in_unacked;
            ch.in_unacked = 0;
            const win = protocol.ChannelWindow{
                .channel_id = ch.id,
                .credit_bytes = credit_to_grant,
            };
            const win_bytes = win.encode();
            self.sendFrameLocked(.channel_window, &win_bytes) catch |err| {
                log.warn("client: failed to send channel_window: {}", .{err});
            };
        }
        self.mutex.unlock();
    }

    fn handleWindow(self: *ClientMux, payload: []const u8) !void {
        const win = protocol.ChannelWindow.parse(payload) catch {
            log.warn("client: malformed channel_window frame", .{});
            return;
        };
        self.mutex.lock();
        const ch = self.channels.get(win.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        const cb = ch.client_callbacks orelse {
            self.mutex.unlock();
            return;
        };
        ch.out_credit = std.math.add(usize, ch.out_credit, win.credit_bytes) catch
            std.math.maxInt(usize);
        self.mutex.unlock();
        ch.credit_signal.set();
        cb.on_credit(ch.client_ctx, win.credit_bytes);
    }

    fn handleEof(self: *ClientMux, payload: []const u8) !void {
        const eof = protocol.ChannelEof.parse(payload) catch return;
        self.mutex.lock();
        const ch = self.channels.get(eof.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        if (ch.remote_eof) {
            self.mutex.unlock();
            return; // duplicate
        }
        ch.remote_eof = true;
        const cb = ch.client_callbacks;
        self.mutex.unlock();
        if (cb) |c| c.on_eof(ch.client_ctx);
    }

    fn handleClose(self: *ClientMux, payload: []const u8) !void {
        const close = protocol.ChannelClose.parse(payload) catch return;
        self.mutex.lock();
        const ch = self.channels.get(close.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        ch.closing = true;
        _ = self.channels.remove(close.channel_id);
        const cb = ch.client_callbacks;
        self.mutex.unlock();
        ch.close_signal.set();
        ch.credit_signal.set();
        if (cb) |c| c.on_close(ch.client_ctx, close.reason, close.message);
        self.alloc.destroy(ch);
    }

    fn handleControl(_: *ClientMux, payload: []const u8) void {
        const ctrl = protocol.ChannelControl.parse(payload) catch return;
        // The client-side channel model has no service vtable, so there
        // is no per-op handler. Control ops that the embedder cares
        // about (port_listener status, etc.) are a future addition;
        // until then, log and drop.
        log.debug("client: ignoring channel_control op={d} channel_id={d}", .{
            ctrl.op, ctrl.channel_id,
        });
    }

    /// Inbound `channel_open` on the client side. Daemon-originated
    /// channels (e.g. port_listener accepts) arrive this way. If
    /// `on_inbound` is set and the handler accepts, a Channel is
    /// allocated and registered; otherwise the open is rejected with
    /// `service_not_supported`.
    fn handleInboundOpen(self: *ClientMux, payload: []const u8) !void {
        const open = protocol.ChannelOpen.parse(payload) catch {
            log.warn("client: malformed channel_open frame", .{});
            return;
        };

        // Reject duplicate channel ids.
        self.mutex.lock();
        const duplicate = self.channels.contains(open.channel_id);
        self.mutex.unlock();
        if (duplicate) {
            log.warn("client: duplicate inbound channel_id={x}", .{open.channel_id});
            try self.sendInboundOpened(open.channel_id, .invalid_request, null, null);
            return;
        }

        const handler = self.on_inbound orelse {
            log.debug(
                "client: rejecting daemon-originated channel_open id={x} service={d} (no handler)",
                .{ open.channel_id, @intFromEnum(open.service) },
            );
            try self.sendInboundOpened(open.channel_id, .service_not_supported, null, null);
            return;
        };

        // Resolve window for the inbound channel.
        const requested_units = if (open.initial_window == 0)
            self.negotiated_default_window_units
        else
            @min(open.initial_window, self.negotiated_max_window_units);
        const window_bytes: usize = @as(usize, requested_units) * 4 * 1024;

        // Offer the open to the handler. Handler returns null to reject.
        var channel_ctx: ?*anyopaque = null;
        const cbs_opt = handler.open(
            handler.ctx,
            open.channel_id,
            open.service,
            open.service_params,
            &channel_ctx,
        );
        const cbs = cbs_opt orelse {
            log.debug(
                "client: handler rejected daemon-originated channel_open id={x}",
                .{open.channel_id},
            );
            try self.sendInboundOpened(open.channel_id, .service_not_supported, null, null);
            return;
        };

        // Handler accepted — allocate and register the channel.
        const ch = try self.alloc.create(Channel);
        ch.* = .{
            .id = open.channel_id,
            .service_id = @intFromEnum(open.service),
            .origin = .remote,
            .service_state = null,
            .vtable = null,
            .client_callbacks = cbs,
            .client_ctx = channel_ctx,
            // Inbound: we grant the daemon an outbound window (in_credit)
            // and start with zero outbound credit ourselves until the
            // daemon sees our channel_opened and grants a window back via
            // on_opened (peer_window).
            .out_credit = 0,
            .in_credit = window_bytes,
            .initial_window_bytes = window_bytes,
            .in_unacked = 0,
            .flags = open.flags,
        };
        ch.assertBackendInvariant();
        errdefer self.alloc.destroy(ch);
        self.mutex.lock();
        const put_err = self.channels.put(self.alloc, open.channel_id, ch);
        self.mutex.unlock();
        try put_err;

        // Acknowledge acceptance to the daemon.
        try self.sendInboundOpened(open.channel_id, .ok, ch.flags, requested_units);

        // Fire on_opened with empty ack and the window we just granted.
        cbs.on_opened(channel_ctx, "", requested_units);
    }

    /// Send a `channel_opened` reply for a daemon-initiated open. Helper
    /// shared between the accept and reject paths.
    fn sendInboundOpened(
        self: *ClientMux,
        channel_id: u32,
        status: protocol.ChannelOpenStatus,
        flags: ?protocol.ChannelOpenFlags,
        peer_window: ?u16,
    ) !void {
        const opened = protocol.ChannelOpened{
            .channel_id = channel_id,
            .status = status,
            .flags = flags orelse .{},
            .peer_window = peer_window orelse 0,
        };
        const encoded = try opened.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrame(.channel_opened, encoded);
    }

    /// Write up to `bytes.len` bytes as one or more `channel_data`
    /// frames, respecting the outbound credit window. Returns the
    /// number of bytes accepted. Returns 0 if the channel is closing,
    /// has sent EOF, or currently has no credit — the embedder waits
    /// for `on_credit` and retries. Discipline matches
    /// `Mux.sendChannelData`: lock once, check, encode + send under the
    /// lock, unlock.
    pub fn writeChannel(self: *ClientMux, channel_id: u32, bytes: []const u8) !usize {
        if (bytes.len == 0) return 0;
        const max_data = protocol.max_payload - protocol.ChannelData.fixed_size;

        self.mutex.lock();
        const ch = self.channels.get(channel_id) orelse {
            self.mutex.unlock();
            return error.UnknownChannel;
        };
        if (ch.closing or ch.local_eof) {
            self.mutex.unlock();
            return 0;
        }
        if (ch.out_credit == 0) {
            ch.credit_signal.reset();
            self.mutex.unlock();
            return 0;
        }
        const to_send = @min(@min(bytes.len, ch.out_credit), max_data);
        ch.out_credit -= to_send;
        const frame = protocol.ChannelData{ .channel_id = channel_id, .bytes = bytes[0..to_send] };
        const encoded = try frame.encode(self.alloc);
        defer self.alloc.free(encoded);
        try self.sendFrameLocked(.channel_data, encoded);
        self.mutex.unlock();
        return to_send;
    }

    /// Send `channel_eof` for the given channel. Idempotent.
    pub fn channelEof(self: *ClientMux, channel_id: u32) !void {
        self.mutex.lock();
        const ch = self.channels.get(channel_id) orelse {
            self.mutex.unlock();
            return error.UnknownChannel;
        };
        if (ch.local_eof or ch.closing) {
            self.mutex.unlock();
            return;
        }
        ch.local_eof = true;
        const eof_bytes = (protocol.ChannelEof{ .channel_id = channel_id }).encode();
        try self.sendFrameLocked(.channel_eof, &eof_bytes);
        self.mutex.unlock();
    }

    /// Send `channel_close` and tear down the channel locally. The
    /// embedder's `on_close` callback is NOT fired — the embedder
    /// initiated this teardown and already knows. Returns
    /// `error.UnknownChannel` if the id is not (or no longer) live.
    pub fn channelClose(
        self: *ClientMux,
        channel_id: u32,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
    ) !void {
        if (!self.closeByIdInternal(channel_id, reason, message, false)) {
            return error.UnknownChannel;
        }
    }

    /// Shared teardown for client-initiated close (`channelClose`) and
    /// protocol-violation close (`handleData`). Resolves `channel_id`,
    /// claims the teardown, sends `channel_close`, removes + frees the
    /// channel. Returns `false` if the id is unknown or already closing.
    ///
    /// Only the `channel_id` crosses the lock boundary — the lookup,
    /// the `closing` claim, and the map removal all happen inside one
    /// critical section, so a `*Channel` is never held past a point
    /// where another thread could free it. Safe to call from any
    /// thread, which `channelClose` requires (the embedder may close a
    /// channel concurrently with the dispatch thread).
    ///
    /// `fire_on_close` controls whether the embedder's `on_close` runs:
    /// true for involuntary teardown (window violation), false for
    /// embedder-requested close (the embedder already knows).
    fn closeByIdInternal(
        self: *ClientMux,
        channel_id: u32,
        reason: protocol.ChannelCloseReason,
        message: []const u8,
        fire_on_close: bool,
    ) bool {
        self.mutex.lock();
        const ch = self.channels.get(channel_id) orelse {
            self.mutex.unlock();
            return false;
        };
        if (ch.closing) {
            self.mutex.unlock();
            return false;
        }
        ch.closing = true;
        const cb = ch.client_callbacks;
        const ctx = ch.client_ctx;
        const frame = protocol.ChannelClose{
            .channel_id = channel_id,
            .reason = reason,
            .message = message,
        };
        if (frame.encode(self.alloc)) |encoded| {
            defer self.alloc.free(encoded);
            self.sendFrameLocked(.channel_close, encoded) catch |err| {
                log.warn("client: failed to send channel_close: {}", .{err});
            };
        } else |err| {
            log.warn("client: failed to encode channel_close: {}", .{err});
        }
        _ = self.channels.remove(channel_id);
        self.mutex.unlock();

        ch.close_signal.set();
        ch.credit_signal.set();
        if (fire_on_close) {
            if (cb) |c| c.on_close(ctx, reason, message);
        }
        self.alloc.destroy(ch);
        return true;
    }
};

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

/// Trivial echo service used in tests. Echoes any inbound data back
/// to the peer as a control op (so we don't have to manage outbound
/// channel_data credits in the test).
const echo_service_id: u8 = 100;

fn echoOpen(
    _: ?*anyopaque,
    _: *Mux,
    _: u32,
    _: []const u8,
    _: []u8,
) ServiceError!Service.OpenResult {
    return .{};
}

fn echoOnData(_: ?*anyopaque, _: []const u8) ServiceError!void {}
fn echoOnControl(_: ?*anyopaque, _: u8, _: []const u8) ServiceError!void {}
fn echoOnEof(_: ?*anyopaque) void {}
fn echoOnClose(_: ?*anyopaque, _: protocol.ChannelCloseReason, _: []const u8) void {}

const echo_vtable: Service.VTable = .{
    .open = echoOpen,
    .on_data = echoOnData,
    .on_control = echoOnControl,
    .on_eof = echoOnEof,
    .on_close = echoOnClose,
};

/// Helper: spin up a connected socketpair, build a Mux on one end,
/// return both fds + the mux + registry on the heap (so pointers
/// between fields stay valid across the return).
const SocketPair = struct {
    a: posix.fd_t,
    b: posix.fd_t,
    alloc: Allocator,
    registry: *Registry,
    mux: Mux,

    fn init(alloc: Allocator) !SocketPair {
        // std.posix doesn't expose a wrapped socketpair, so we call the
        // C extern directly. On macOS and Linux the signature is the
        // same: (domain, type, protocol, &fd[2]) -> 0 on success.
        var fds: [2]posix.fd_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc != 0) return error.SocketPairFailed;
        // Heap-allocate the Registry so its address is stable while
        // Mux holds a `*const Registry` reference to it.
        const reg = try alloc.create(Registry);
        reg.* = Registry.init(alloc);
        const mux = Mux.init(alloc, fds[0], reg);
        return .{
            .a = fds[0],
            .b = fds[1],
            .alloc = alloc,
            .registry = reg,
            .mux = mux,
        };
    }

    fn deinit(self: *SocketPair) void {
        self.mux.deinit();
        self.registry.deinit();
        self.alloc.destroy(self.registry);
        posix.close(self.a);
        posix.close(self.b);
    }
};

fn readFrameAlloc(alloc: Allocator, fd: posix.fd_t) !struct {
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
    off = 0;
    while (off < payload.len) {
        const n = try posix.read(fd, payload[off..]);
        if (n == 0) {
            alloc.free(payload);
            return error.UnexpectedEof;
        }
        off += n;
    }
    return .{ .header = header, .payload = payload };
}

test "mux capability handshake — empty registry" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    // Client (b-side) sends its capabilities.
    const client_caps = protocol.Capabilities{
        .protocol_version = protocol.protocol_version,
        .services = &.{},
        .default_window = protocol.default_channel_window_units,
        .max_window = protocol.max_channel_window_units,
        .max_payload_kib = protocol.max_payload / 1024,
        .compression_algo = .lz4,
    };
    const client_caps_buf = try client_caps.encode(testing.allocator);
    defer testing.allocator.free(client_caps_buf);
    try shared.sendFrameFd(pair.b, .capabilities, 0, client_caps_buf);

    // Daemon (a-side) handshakes against the received frame.
    const frame = try readFrameAlloc(testing.allocator, pair.a);
    defer testing.allocator.free(frame.payload);
    try testing.expectEqual(protocol.Kind.capabilities, frame.header.kind);
    const peer = try pair.mux.handshake(frame.payload);
    defer testing.allocator.free(peer.services);

    // Daemon should have replied with its own capabilities (empty
    // service list since registry has no services).
    const reply = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(reply.payload);
    try testing.expectEqual(protocol.Kind.capabilities, reply.header.kind);
    const parsed = try protocol.Capabilities.parse(testing.allocator, reply.payload);
    defer testing.allocator.free(parsed.services);
    try testing.expectEqual(@as(usize, 0), parsed.services.len);
    try testing.expectEqual(protocol.protocol_version, parsed.protocol_version);
}

test "mux rejects channel_open for unknown service" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    // Client sends channel_open for a service that's not registered.
    const open = protocol.ChannelOpen{
        .channel_id = 42,
        .service = .tcp_connect, // not in our empty registry
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);

    // Drive the dispatch directly (no handshake needed for this test).
    try pair.mux.dispatch(.channel_open, open_buf);

    // Daemon should have replied with channel_opened, status=service_not_supported.
    const reply = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(reply.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, reply.header.kind);
    const opened = try protocol.ChannelOpened.parse(reply.payload);
    try testing.expectEqual(@as(u32, 42), opened.channel_id);
    try testing.expectEqual(protocol.ChannelOpenStatus.service_not_supported, opened.status);

    // The channel should NOT have been recorded.
    try testing.expect(!pair.mux.channels.contains(42));
}

test "mux accepts channel_open for a registered service and tracks it" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    const open = protocol.ChannelOpen{
        .channel_id = 7,
        .service = @enumFromInt(echo_service_id),
        .initial_window = 8, // 8 × 4 KiB = 32 KiB
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);

    const reply = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(reply.payload);
    const opened = try protocol.ChannelOpened.parse(reply.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    try testing.expectEqual(@as(u32, 7), opened.channel_id);
    try testing.expectEqual(@as(u16, 8), opened.peer_window);

    try testing.expect(pair.mux.channels.contains(7));
    const ch = pair.mux.channels.get(7).?;
    try testing.expectEqual(@as(usize, 8 * 4 * 1024), ch.in_credit);
    try testing.expectEqual(@as(usize, 8 * 4 * 1024), ch.out_credit);
}

test "mux rejects duplicate channel_id" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    const open = protocol.ChannelOpen{
        .channel_id = 1,
        .service = @enumFromInt(echo_service_id),
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);

    try pair.mux.dispatch(.channel_open, open_buf);
    // Consume the first opened-OK reply.
    const r1 = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(r1.payload);

    // Same id again.
    try pair.mux.dispatch(.channel_open, open_buf);
    const r2 = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(r2.payload);
    const dup = try protocol.ChannelOpened.parse(r2.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.invalid_request, dup.status);
}

test "mux channel_data window violation closes the channel" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    // Open a channel with a tiny window: 1 × 4 KiB = 4 KiB.
    const open = protocol.ChannelOpen{
        .channel_id = 9,
        .service = @enumFromInt(echo_service_id),
        .initial_window = 1,
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);
    const r1 = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(r1.payload);

    // Send 4097 bytes (1 byte over the 4 KiB window) — must trigger
    // close with reason=peer_reset.
    const big = try testing.allocator.alloc(u8, 4097);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    const data = protocol.ChannelData{ .channel_id = 9, .bytes = big };
    const data_buf = try data.encode(testing.allocator);
    defer testing.allocator.free(data_buf);
    try pair.mux.dispatch(.channel_data, data_buf);

    const close_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(close_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_close, close_frame.header.kind);
    const close = try protocol.ChannelClose.parse(close_frame.payload);
    try testing.expectEqual(@as(u32, 9), close.channel_id);
    try testing.expectEqual(protocol.ChannelCloseReason.peer_reset, close.reason);

    try testing.expect(!pair.mux.channels.contains(9));
}

test "mux ignores channel_data for unknown channel" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    const data = protocol.ChannelData{ .channel_id = 999, .bytes = "ignored" };
    const data_buf = try data.encode(testing.allocator);
    defer testing.allocator.free(data_buf);
    try pair.mux.dispatch(.channel_data, data_buf);

    // No outbound frame should have been written. Verify via a
    // non-blocking read using poll(timeout=0).
    var pollfds = [1]posix.pollfd{
        .{ .fd = pair.b, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = try posix.poll(&pollfds, 0);
    try testing.expectEqual(@as(usize, 0), ready);
}

// =========================================================================
// Daemon-originated channel tests (openChannelFromDaemon + handleOpened)
// =========================================================================

test "openChannelFromDaemon allocates a daemon-direction id and sends channel_open" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    const params = "hello-params";
    const id = try pair.mux.openChannelFromDaemon(echo_service_id, params, params, 8);

    // The id must carry the daemon-direction high bit.
    try testing.expect((id & protocol.channel_id_daemon_bit) != 0);
    // The channel must be registered with origin = local.
    try testing.expect(pair.mux.channels.contains(id));
    const ch = pair.mux.channels.get(id).?;
    try testing.expectEqual(ChannelOrigin.local, ch.origin);

    // A channel_open frame must have appeared on the wire.
    const frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(frame.payload);
    try testing.expectEqual(protocol.Kind.channel_open, frame.header.kind);
    const open = try protocol.ChannelOpen.parse(frame.payload);
    try testing.expectEqual(id, open.channel_id);
    try testing.expect((open.channel_id & protocol.channel_id_daemon_bit) != 0);
    try testing.expectEqual(@as(u8, echo_service_id), @intFromEnum(open.service));
    try testing.expectEqualStrings(params, open.service_params);
}

test "openChannelFromDaemon rejects unregistered service" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try testing.expectError(
        error.ServiceNotRegistered,
        pair.mux.openChannelFromDaemon(200, "", "", 0),
    );
}

test "handleOpened records peer_window on a daemon-originated channel" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    const id = try pair.mux.openChannelFromDaemon(echo_service_id, "", "", 8);
    // Drain the channel_open frame.
    const open_frame = try readFrameAlloc(testing.allocator, pair.b);
    testing.allocator.free(open_frame.payload);

    // Peer acks with a different window than we advertised.
    const opened = protocol.ChannelOpened{
        .channel_id = id,
        .status = .ok,
        .peer_window = 32, // 32 × 4 KiB = 128 KiB
    };
    const opened_buf = try opened.encode(testing.allocator);
    defer testing.allocator.free(opened_buf);
    try pair.mux.dispatch(.channel_opened, opened_buf);

    // out_credit must now reflect the peer's authoritative grant.
    const ch = pair.mux.channels.get(id).?;
    try testing.expectEqual(@as(usize, 32 * 4 * 1024), ch.out_credit);
}

test "handleOpened with status != ok tears down the daemon-originated channel" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    const id = try pair.mux.openChannelFromDaemon(echo_service_id, "", "", 8);
    const open_frame = try readFrameAlloc(testing.allocator, pair.b);
    testing.allocator.free(open_frame.payload);

    // Peer rejects the open.
    const opened = protocol.ChannelOpened{
        .channel_id = id,
        .status = .service_error,
    };
    const opened_buf = try opened.encode(testing.allocator);
    defer testing.allocator.free(opened_buf);
    try pair.mux.dispatch(.channel_opened, opened_buf);

    // The local channel must be gone, and a channel_close frame should
    // have been emitted to the peer.
    try testing.expect(!pair.mux.channels.contains(id));
    const close_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(close_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_close, close_frame.header.kind);
    const close = try protocol.ChannelClose.parse(close_frame.payload);
    try testing.expectEqual(id, close.channel_id);
    try testing.expectEqual(protocol.ChannelCloseReason.peer_reset, close.reason);
}

test "handleOpened ignores channel_opened for a peer-opened channel" {
    var pair = try SocketPair.init(testing.allocator);
    defer pair.deinit();

    try pair.registry.register(.{
        .id = echo_service_id,
        .name = "echo",
        .vtable = &echo_vtable,
    });

    // Peer opens a channel (origin = remote).
    const open = protocol.ChannelOpen{
        .channel_id = 5,
        .service = @enumFromInt(echo_service_id),
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);
    const opened_reply = try readFrameAlloc(testing.allocator, pair.b);
    testing.allocator.free(opened_reply.payload);

    const before = pair.mux.channels.get(5).?.out_credit;

    // A stray channel_opened for that id must be ignored, not applied.
    const stray = protocol.ChannelOpened{
        .channel_id = 5,
        .status = .ok,
        .peer_window = 999,
    };
    const stray_buf = try stray.encode(testing.allocator);
    defer testing.allocator.free(stray_buf);
    try pair.mux.dispatch(.channel_opened, stray_buf);

    try testing.expectEqual(before, pair.mux.channels.get(5).?.out_credit);
}

// =========================================================================
// ClientMux tests
// =========================================================================

/// Echo service that copies inbound channel_data straight back out as
/// channel_data on the same channel. Used to exercise ClientMux against
/// a real daemon-side Mux.
const RoundtripState = struct {
    mux: *Mux,
    channel: ?*Channel = null,
};

fn rtOpen(
    _: ?*anyopaque,
    mux: *Mux,
    _: u32,
    _: []const u8,
    _: []u8,
) ServiceError!Service.OpenResult {
    const state = try mux.alloc.create(RoundtripState);
    state.* = .{ .mux = mux };
    return .{ .state = state };
}

fn rtOnOpened(state_ptr: ?*anyopaque, ch: *Channel) void {
    const state: *RoundtripState = @ptrCast(@alignCast(state_ptr orelse return));
    state.channel = ch;
}

fn rtOnData(state_ptr: ?*anyopaque, bytes: []const u8) ServiceError!void {
    const state: *RoundtripState = @ptrCast(@alignCast(state_ptr orelse return));
    const ch = state.channel orelse return;
    // Echo the bytes back, looping until the whole slice is sent.
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

fn rtOnControl(_: ?*anyopaque, _: u8, _: []const u8) ServiceError!void {}
fn rtOnEof(_: ?*anyopaque) void {}
fn rtOnClose(state_ptr: ?*anyopaque, _: protocol.ChannelCloseReason, _: []const u8) void {
    const state: *RoundtripState = @ptrCast(@alignCast(state_ptr orelse return));
    state.mux.alloc.destroy(state);
}

const roundtrip_vtable: Service.VTable = .{
    .open = rtOpen,
    .on_opened = rtOnOpened,
    .on_data = rtOnData,
    .on_control = rtOnControl,
    .on_eof = rtOnEof,
    .on_close = rtOnClose,
};

const roundtrip_service_id: u8 = 101;

/// Test harness pairing a daemon `Mux` and a `ClientMux` over a
/// socketpair, with a background thread pumping the daemon's dispatch.
const DaemonClientPair = struct {
    a: posix.fd_t,
    b: posix.fd_t,
    alloc: Allocator,
    registry: *Registry,
    mux: *Mux,
    client: *ClientMux,
    daemon_thread: ?std.Thread = null,
    daemon_stop: std.atomic.Value(bool) = .init(false),

    fn init(alloc: Allocator) !*DaemonClientPair {
        var fds: [2]posix.fd_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc != 0) return error.SocketPairFailed;

        const reg = try alloc.create(Registry);
        reg.* = Registry.init(alloc);
        const mux = try alloc.create(Mux);
        mux.* = Mux.init(alloc, fds[0], reg);
        const client = try alloc.create(ClientMux);
        client.* = ClientMux.init(alloc, fds[1]);

        const self = try alloc.create(DaemonClientPair);
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

    /// Start a background thread that reads frames off the daemon fd
    /// and feeds them to `mux.dispatch`. Exits on EOF or stop flag.
    fn startDaemonPump(self: *DaemonClientPair) !void {
        self.daemon_thread = try std.Thread.spawn(.{}, daemonPump, .{self});
    }

    fn daemonPump(self: *DaemonClientPair) void {
        while (!self.daemon_stop.load(.acquire)) {
            const frame = readFrameAlloc(self.alloc, self.a) catch return;
            defer self.alloc.free(frame.payload);
            self.mux.dispatch(frame.header.kind, frame.payload) catch return;
        }
    }

    fn deinit(self: *DaemonClientPair) void {
        self.daemon_stop.store(true, .release);
        // Break the daemon pump out of a blocking read.
        posix.shutdown(self.a, .both) catch {};
        if (self.daemon_thread) |t| t.join();
        self.client.deinit();
        self.mux.deinit();
        self.registry.deinit();
        posix.close(self.a);
        posix.close(self.b);
        self.alloc.destroy(self.client);
        self.alloc.destroy(self.mux);
        self.alloc.destroy(self.registry);
        self.alloc.destroy(self);
    }
};

/// Callback context for ClientMux tests — records every callback.
const ClientObserver = struct {
    mutex: std.Thread.Mutex = .{},
    opened: bool = false,
    opened_window: u16 = 0,
    data: std.ArrayListUnmanaged(u8) = .empty,
    credit_total: u64 = 0,
    eof: bool = false,
    closed: bool = false,
    close_reason: protocol.ChannelCloseReason = .normal,
    alloc: Allocator,

    fn deinit(self: *ClientObserver) void {
        self.data.deinit(self.alloc);
    }

    fn onOpened(ctx: ?*anyopaque, _: []const u8, peer_window_units: u16) void {
        const self: *ClientObserver = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.opened = true;
        self.opened_window = peer_window_units;
    }
    fn onData(ctx: ?*anyopaque, bytes: []const u8) void {
        const self: *ClientObserver = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.data.appendSlice(self.alloc, bytes) catch {};
    }
    fn onCredit(ctx: ?*anyopaque, credit_bytes: u32) void {
        const self: *ClientObserver = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.credit_total += credit_bytes;
    }
    fn onEof(ctx: ?*anyopaque) void {
        const self: *ClientObserver = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.eof = true;
    }
    fn onClose(ctx: ?*anyopaque, reason: protocol.ChannelCloseReason, _: []const u8) void {
        const self: *ClientObserver = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.close_reason = reason;
    }

    fn callbacks() ClientMux.Callbacks {
        return .{
            .on_opened = onOpened,
            .on_data = onData,
            .on_credit = onCredit,
            .on_eof = onEof,
            .on_close = onClose,
        };
    }
};

test "ClientMux roundtrip: open, write, echo back, close" {
    const pair = try DaemonClientPair.init(testing.allocator);
    defer pair.deinit();
    try pair.registry.register(.{
        .id = roundtrip_service_id,
        .name = "roundtrip",
        .vtable = &roundtrip_vtable,
    });
    try pair.startDaemonPump();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    const id = try pair.client.openChannel(
        @enumFromInt(roundtrip_service_id),
        .{},
        8,
        "",
        ClientObserver.callbacks(),
        &observer,
    );

    // The client must dispatch the daemon's channel_opened reply.
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, opened_frame.header.kind);
    try pair.client.dispatch(opened_frame.header.kind, opened_frame.payload);
    try testing.expect(observer.opened);

    // Write bytes; the daemon echo service bounces them back.
    const greeting = "hello over the mux";
    var written: usize = 0;
    while (written < greeting.len) {
        const n = try pair.client.writeChannel(id, greeting[written..]);
        written += n;
    }

    // Read echoed channel_data frames off the client fd and dispatch
    // them until the observer has the full payload.
    while (true) {
        observer.mutex.lock();
        const have = observer.data.items.len;
        observer.mutex.unlock();
        if (have >= greeting.len) break;
        const frame = try readFrameAlloc(testing.allocator, pair.b);
        defer testing.allocator.free(frame.payload);
        try pair.client.dispatch(frame.header.kind, frame.payload);
    }
    try testing.expectEqualStrings(greeting, observer.data.items);

    // Clean close from the client side.
    try pair.client.channelClose(id, .normal, "");
    try testing.expect(!pair.client.channels.contains(id));

    // A second close of the same id is a safe no-op that reports the
    // channel is gone — the id-keyed teardown resolves + claims under
    // one lock, so it cannot act on a freed Channel.
    try testing.expectError(error.UnknownChannel, pair.client.channelClose(id, .normal, ""));
}

test "ClientMux channelClose on an unknown channel reports UnknownChannel" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var client = ClientMux.init(testing.allocator, fds[1]);
    defer client.deinit();

    try testing.expectError(
        error.UnknownChannel,
        client.channelClose(12345, .normal, ""),
    );
}

test "ClientMux window symmetry: tiny window drives channel_window updates" {
    const pair = try DaemonClientPair.init(testing.allocator);
    defer pair.deinit();
    try pair.registry.register(.{
        .id = roundtrip_service_id,
        .name = "roundtrip",
        .vtable = &roundtrip_vtable,
    });
    try pair.startDaemonPump();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    // Open with a 1 × 4 KiB window.
    const id = try pair.client.openChannel(
        @enumFromInt(roundtrip_service_id),
        .{},
        1,
        "",
        ClientObserver.callbacks(),
        &observer,
    );
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try pair.client.dispatch(opened_frame.header.kind, opened_frame.payload);
    // Initial credit grant equals the 4 KiB window.
    try testing.expectEqual(@as(u64, 4 * 1024), observer.credit_total);

    // Push 6 KiB through — enough to cross the daemon's 25% replenish
    // threshold and force a channel_window update back to the client.
    const payload = try testing.allocator.alloc(u8, 6 * 1024);
    defer testing.allocator.free(payload);
    @memset(payload, 'z');

    var written: usize = 0;
    var collected: usize = 0;
    while (collected < payload.len) {
        if (written < payload.len) {
            const n = try pair.client.writeChannel(id, payload[written..]);
            written += n;
        }
        // Drain frames the daemon sent us (echoed data + window grants).
        var pollfds = [1]posix.pollfd{
            .{ .fd = pair.b, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = try posix.poll(&pollfds, 50);
        if (ready > 0) {
            const frame = try readFrameAlloc(testing.allocator, pair.b);
            defer testing.allocator.free(frame.payload);
            if (frame.header.kind == .channel_data) {
                const dd = try protocol.ChannelData.parse(frame.payload);
                collected += dd.bytes.len;
            }
            try pair.client.dispatch(frame.header.kind, frame.payload);
        }
    }

    // The client must have received more credit than the initial 4 KiB
    // window — i.e. at least one channel_window frame was applied.
    try testing.expect(observer.credit_total > 4 * 1024);
}

test "ClientMux peer rejection fires on_close(peer_reset)" {
    const pair = try DaemonClientPair.init(testing.allocator);
    defer pair.deinit();
    // Intentionally do NOT register the service.
    try pair.startDaemonPump();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    const id = try pair.client.openChannel(
        .tcp_connect, // not registered on the daemon side
        .{},
        8,
        "",
        ClientObserver.callbacks(),
        &observer,
    );

    // Daemon replies with channel_opened status=service_not_supported.
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try pair.client.dispatch(opened_frame.header.kind, opened_frame.payload);

    try testing.expect(observer.closed);
    try testing.expectEqual(protocol.ChannelCloseReason.peer_reset, observer.close_reason);
    try testing.expect(!pair.client.channels.contains(id));
}

test "ClientMux pre-ack write returns 0 until channel_opened arrives" {
    const pair = try DaemonClientPair.init(testing.allocator);
    defer pair.deinit();
    try pair.registry.register(.{
        .id = roundtrip_service_id,
        .name = "roundtrip",
        .vtable = &roundtrip_vtable,
    });
    try pair.startDaemonPump();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    const id = try pair.client.openChannel(
        @enumFromInt(roundtrip_service_id),
        .{},
        8,
        "",
        ClientObserver.callbacks(),
        &observer,
    );

    // Before processing the channel_opened reply there is no outbound
    // credit — a write must be refused (returns 0).
    const pre = try pair.client.writeChannel(id, "data");
    try testing.expectEqual(@as(usize, 0), pre);

    // Process the daemon's channel_opened, then retry.
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try pair.client.dispatch(opened_frame.header.kind, opened_frame.payload);

    const post = try pair.client.writeChannel(id, "data");
    try testing.expect(post > 0);
}

test "ClientMux rejects daemon-originated channel_open" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var client = ClientMux.init(testing.allocator, fds[1]);
    defer client.deinit();

    // Synthesize a daemon-originated channel_open arriving at the client.
    const open = protocol.ChannelOpen{
        .channel_id = protocol.channel_id_daemon_bit | 7,
        .service = .tcp_connect,
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try client.dispatch(.channel_open, open_buf);

    // The client must have replied with channel_opened,
    // status=service_not_supported, and registered nothing.
    const reply = try readFrameAlloc(testing.allocator, fds[0]);
    defer testing.allocator.free(reply.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, reply.header.kind);
    const opened = try protocol.ChannelOpened.parse(reply.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.service_not_supported, opened.status);
    try testing.expectEqual(open.channel_id, opened.channel_id);
    try testing.expect(!client.channels.contains(open.channel_id));
}

test "ClientMux channel id allocation skips the daemon-direction range" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var client = ClientMux.init(testing.allocator, fds[1]);
    defer client.deinit();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    // Every allocated id must keep the high bit clear.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const id = try client.openChannel(
            .tcp_connect,
            .{},
            1,
            "",
            ClientObserver.callbacks(),
            &observer,
        );
        try testing.expect((id & protocol.channel_id_daemon_bit) == 0);
        // Drain the channel_open frame the client emitted.
        const frame = try readFrameAlloc(testing.allocator, fds[0]);
        testing.allocator.free(frame.payload);
    }
}

// =========================================================================
// InboundHandler tests (Phase 6D Part 1)
// =========================================================================

test "ClientMux InboundHandler: accepts daemon-originated channel and fires on_opened" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var client = ClientMux.init(testing.allocator, fds[1]);
    defer client.deinit();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    const Handler = struct {
        obs: *ClientObserver,

        fn open(
            ctx: ?*anyopaque,
            _: u32,
            _: protocol.ChannelService,
            _: []const u8,
            ch_ctx: *?*anyopaque,
        ) ?ClientMux.Callbacks {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            ch_ctx.* = self.obs;
            return ClientObserver.callbacks();
        }
    };
    var handler = Handler{ .obs = &observer };
    client.on_inbound = .{
        .ctx = &handler,
        .open = Handler.open,
    };

    // Synthesize a daemon-originated channel_open arriving at the client.
    const daemon_channel_id = protocol.channel_id_daemon_bit | 42;
    const open = protocol.ChannelOpen{
        .channel_id = daemon_channel_id,
        .service = .port_listener,
        .initial_window = 4,
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try client.dispatch(.channel_open, open_buf);

    // The client must have replied with channel_opened status=ok.
    const reply = try readFrameAlloc(testing.allocator, fds[0]);
    defer testing.allocator.free(reply.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, reply.header.kind);
    const opened = try protocol.ChannelOpened.parse(reply.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    try testing.expectEqual(daemon_channel_id, opened.channel_id);

    // The channel must have been registered.
    try testing.expect(client.channels.contains(daemon_channel_id));

    // on_opened must have fired.
    try testing.expect(observer.opened);
}

test "ClientMux InboundHandler: handler returning null sends service_not_supported" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var client = ClientMux.init(testing.allocator, fds[1]);
    defer client.deinit();

    const Handler = struct {
        fn open(
            _: ?*anyopaque,
            _: u32,
            _: protocol.ChannelService,
            _: []const u8,
            _: *?*anyopaque,
        ) ?ClientMux.Callbacks {
            return null; // always reject
        }
    };
    client.on_inbound = .{ .ctx = null, .open = Handler.open };

    const daemon_channel_id = protocol.channel_id_daemon_bit | 7;
    const open = protocol.ChannelOpen{
        .channel_id = daemon_channel_id,
        .service = .tcp_connect,
    };
    const open_buf = try open.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try client.dispatch(.channel_open, open_buf);

    const reply = try readFrameAlloc(testing.allocator, fds[0]);
    defer testing.allocator.free(reply.payload);
    const opened_reply = try protocol.ChannelOpened.parse(reply.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.service_not_supported, opened_reply.status);
    try testing.expect(!client.channels.contains(daemon_channel_id));
}

test "ClientMux InboundHandler: inbound channel receives subsequent data" {
    // Use raw socketpair fds so we can drive both sides manually with no
    // background pump (avoids a race on pair.a between the pump thread and
    // our manual readFrameAlloc calls).
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const reg = try testing.allocator.create(Registry);
    reg.* = Registry.init(testing.allocator);
    defer {
        reg.deinit();
        testing.allocator.destroy(reg);
    }
    try reg.register(.{
        .id = roundtrip_service_id,
        .name = "roundtrip",
        .vtable = &roundtrip_vtable,
    });
    var daemon_mux = Mux.init(testing.allocator, fds[0], reg);
    defer daemon_mux.deinit();
    var client_mux = ClientMux.init(testing.allocator, fds[1]);
    defer client_mux.deinit();

    var observer: ClientObserver = .{ .alloc = testing.allocator };
    defer observer.deinit();

    const Handler = struct {
        obs: *ClientObserver,

        fn open(
            ctx: ?*anyopaque,
            _: u32,
            _: protocol.ChannelService,
            _: []const u8,
            ch_ctx: *?*anyopaque,
        ) ?ClientMux.Callbacks {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            ch_ctx.* = self.obs;
            return ClientObserver.callbacks();
        }
    };
    var handler = Handler{ .obs = &observer };
    client_mux.on_inbound = .{ .ctx = &handler, .open = Handler.open };

    // Daemon originates a channel toward the client. `openChannelFromDaemon`
    // runs the roundtrip service's `open`, allocates a daemon-direction id,
    // and sends `channel_open` to fds[1] (client side).
    const id = try daemon_mux.openChannelFromDaemon(roundtrip_service_id, "", "", 4);

    // Route the `channel_open` frame to the client mux.
    const open_frame = try readFrameAlloc(testing.allocator, fds[1]);
    defer testing.allocator.free(open_frame.payload);
    try client_mux.dispatch(open_frame.header.kind, open_frame.payload);

    // Route the `channel_opened` reply to the daemon mux (updates out_credit).
    const opened_frame = try readFrameAlloc(testing.allocator, fds[0]);
    defer testing.allocator.free(opened_frame.payload);
    try daemon_mux.dispatch(opened_frame.header.kind, opened_frame.payload);

    // Client channel must be registered; on_opened must have fired.
    try testing.expect(client_mux.channels.contains(id));
    try testing.expect(observer.opened);

    // Daemon sends data to the client channel.
    const ch = daemon_mux.channels.get(id).?;
    const sent = try daemon_mux.sendChannelData(ch, "hello-inbound");
    try testing.expectEqual(@as(usize, "hello-inbound".len), sent);

    // Route the `channel_data` frame to the client mux.
    const data_frame = try readFrameAlloc(testing.allocator, fds[1]);
    defer testing.allocator.free(data_frame.payload);
    try client_mux.dispatch(data_frame.header.kind, data_frame.payload);

    try testing.expectEqualStrings("hello-inbound", observer.data.items);
}
