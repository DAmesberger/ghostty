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

/// Per-channel state owned by the mux. Pointers into here are stable
/// for the channel's lifetime (i.e. until `Service.on_close` returns).
pub const Channel = struct {
    id: u32,
    service_id: u8,
    /// Per-service state returned by `Service.open`. Null for stateless
    /// services.
    service_state: ?*anyopaque,
    /// Vtable for fast dispatch (cached from the service entry).
    vtable: *const Service.VTable,
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
        // Tear down any channels that didn't close cleanly. Signal
        // pumps first so on_close can join them.
        if (self.channels.count() != 0) {
            var it = self.channels.iterator();
            while (it.next()) |entry| {
                const ch = entry.value_ptr.*;
                ch.closing = true;
                ch.close_signal.set();
                ch.credit_signal.set();
                ch.vtable.on_close(ch.service_state, .daemon_shutdown, "");
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
            .channel_opened => {
                // The daemon does not accept channel-opened from the
                // peer in this phase — daemon-originated channels
                // (e.g. port_listener accepts) are a 6A.3 feature.
                log.debug("ignoring channel_opened from peer", .{});
            },
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
            .service_state = result.state,
            .vtable = service.vtable,
            .out_credit = window_bytes,
            .in_credit = window_bytes,
            .initial_window_bytes = window_bytes,
            .in_unacked = 0,
            .flags = result.flags,
        };
        errdefer {
            ch.vtable.on_close(ch.service_state, .normal, "");
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

    fn handleData(self: *Mux, payload: []const u8) !void {
        const data = protocol.ChannelData.parse(payload) catch {
            log.warn("malformed channel_data frame", .{});
            return;
        };
        self.mutex.lock();
        const ch = self.channels.get(data.channel_id) orelse {
            self.mutex.unlock();
            log.debug("channel_data for unknown channel_id={d} — discarding", .{data.channel_id});
            return;
        };

        // Flow-control: peer is sending against the credit we granted.
        // Drop + close if they exceed it.
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
        ch.vtable.on_data(ch.service_state, data.bytes) catch |err| {
            const reason: protocol.ChannelCloseReason = switch (err) {
                error.PolicyDenied => .policy_denied,
                else => .service_error,
            };
            try self.closeChannel(ch, reason, @errorName(err));
            return;
        };

        // Replenish the credit window eagerly.
        self.mutex.lock();
        const should_replenish = ch.in_unacked >= ch.initial_window_bytes / 4;
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
        self.mutex.lock();
        const ch = self.channels.get(win.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        // Saturating-add to prevent overflow on misbehaving peers.
        ch.out_credit = std.math.add(usize, ch.out_credit, win.credit_bytes) catch
            std.math.maxInt(usize);
        self.mutex.unlock();
        // Wake any pump threads parked in waitForCredit.
        ch.credit_signal.set();
    }

    fn handleEof(self: *Mux, payload: []const u8) !void {
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
        self.mutex.unlock();
        ch.vtable.on_eof(ch.service_state);
    }

    fn handleClose(self: *Mux, payload: []const u8) !void {
        const close = protocol.ChannelClose.parse(payload) catch return;
        self.mutex.lock();
        const ch = self.channels.get(close.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        // Mark + signal first so any pump thread parked on credit or
        // waiting on close exits before we call on_close (which must
        // join the pump).
        ch.closing = true;
        self.mutex.unlock();
        ch.close_signal.set();
        ch.credit_signal.set();
        // Call on_close outside the mutex — it joins pump threads
        // which may currently be blocked acquiring the mutex.
        ch.vtable.on_close(ch.service_state, close.reason, close.message);
        self.mutex.lock();
        _ = self.channels.remove(close.channel_id);
        self.mutex.unlock();
        self.alloc.destroy(ch);
    }

    fn handleControl(self: *Mux, payload: []const u8) !void {
        const ctrl = protocol.ChannelControl.parse(payload) catch return;
        self.mutex.lock();
        const ch = self.channels.get(ctrl.channel_id) orelse {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        ch.vtable.on_control(ch.service_state, ctrl.op, ctrl.op_payload) catch |err| {
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
        const id = ch.id;
        // Mark + signal first so the service's pump threads can exit
        // before `on_close` tries to join them.
        self.mutex.lock();
        ch.closing = true;
        self.mutex.unlock();
        ch.close_signal.set();
        ch.credit_signal.set();
        // on_close outside the mutex — pump threads may be blocked
        // acquiring it.
        ch.vtable.on_close(ch.service_state, reason, message);

        // Send the close frame. Best-effort — if the peer is gone the
        // outer loop will tear everything down anyway.
        const close = protocol.ChannelClose{
            .channel_id = id,
            .reason = reason,
            .message = message,
        };
        const encoded = close.encode(self.alloc) catch return;
        defer self.alloc.free(encoded);
        self.sendFrame(.channel_close, encoded) catch |err| {
            log.warn("failed to send channel_close: {}", .{err});
        };

        self.mutex.lock();
        _ = self.channels.remove(id);
        self.mutex.unlock();
        self.alloc.destroy(ch);
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
        self.mutex.unlock();

        // Wake any other pumps for the same channel (defensive).
        ch.close_signal.set();
        ch.credit_signal.set();
        self.alloc.destroy(ch);
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
