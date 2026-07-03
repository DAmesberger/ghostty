//! Channel service registry and the service interface types for the channel
//! multiplexer. Split out of `channel_mux.zig`; see that file's module doc
//! comment for the overall design. `channel_mux.zig` re-exports these.

const std = @import("std");
const Allocator = std.mem.Allocator;

const protocol = @import("protocol.zig");

const Mux = @import("mux.zig").Mux;
const Channel = @import("channel.zig").Channel;

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
