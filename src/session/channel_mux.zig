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

// This file is a thin facade. The channel multiplexer implementation lives
// in flat sibling modules; re-export every public symbol so external
// importers doing `@import("channel_mux.zig").Foo` keep resolving unchanged.
pub const Registry = @import("registry.zig").Registry;
pub const Service = @import("registry.zig").Service;
pub const ServiceError = @import("registry.zig").ServiceError;
pub const OpenChannelError = @import("registry.zig").OpenChannelError;
pub const ChannelOrigin = @import("channel.zig").ChannelOrigin;
pub const Channel = @import("channel.zig").Channel;
pub const Mux = @import("mux.zig").Mux;
pub const ClientMux = @import("client_mux.zig").ClientMux;

// Pull the sibling modules into the test binary so any inline tests they
// grow keep running. The tests below exercise the re-exported types
// end-to-end across both the daemon `Mux` and the embedder `ClientMux`.
test {
    _ = @import("registry.zig");
    _ = @import("channel.zig");
    _ = @import("mux.zig");
    _ = @import("client_mux.zig");
}

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
