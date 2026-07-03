//! Daemon-side per-connection multiplexer. Split out of `channel_mux.zig`;
//! see that file's module doc comment for the overall design.
//! `channel_mux.zig` re-exports `Mux`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("protocol.zig");
const shared = @import("shared.zig");

const log = std.log.scoped(.channel_mux);

const Registry = @import("registry.zig").Registry;
const Service = @import("registry.zig").Service;
const OpenChannelError = @import("registry.zig").OpenChannelError;
const Channel = @import("channel.zig").Channel;

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
