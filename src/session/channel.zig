//! The multiplexed `Channel` and its origin enum. Split out of
//! `channel_mux.zig`; see that file's module doc comment for the design.
//! `channel_mux.zig` re-exports these.

const std = @import("std");

const protocol = @import("protocol.zig");

const Service = @import("registry.zig").Service;
const ClientMux = @import("client_mux.zig").ClientMux;

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
