//! Embedder-side (client) per-connection multiplexer. Split out of
//! `channel_mux.zig`; see that file's module doc comment for the design.
//! `channel_mux.zig` re-exports `ClientMux`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("protocol.zig");
const shared = @import("shared.zig");

const log = std.log.scoped(.channel_mux);

const Channel = @import("channel.zig").Channel;

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
