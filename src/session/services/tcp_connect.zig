//! tcp_connect channel service.
//!
//! Provides outbound TCP connections to a remote `host:port` over the
//! channel mux. Every channel maps 1:1 to an upstream TCP socket. The
//! service spawns a per-channel pump thread that reads from the TCP
//! socket and emits `channel_data` frames respecting the channel's
//! outbound credit window. Inbound `channel_data` is written
//! synchronously to the TCP socket from the dispatch thread (which is
//! acceptable because the socket has its own kernel buffer; if the
//! peer is slow we'll back-pressure the daemon's read loop, which is
//! exactly the desired behaviour).
//!
//! Replaces cmux's `KindTCPOpen` family (kinds 30-33).
//!
//! Open params layout:
//!   [2]   host_len  u16 LE
//!   [N]   host      UTF-8 bytes (≤ 253 chars per DNS spec)
//!   [2]   port      u16 LE
//!
//! Opened service_ack: empty (the channel works the moment ok is
//! reported; resolved address details are not exposed today).

const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");

const log = std.log.scoped(.tcp_connect_service);

/// Service id for `tcp_connect`. Must match
/// `protocol.ChannelService.tcp_connect`.
pub const service_id: u8 = @intFromEnum(protocol.ChannelService.tcp_connect);

/// Read buffer size for the upstream → channel pump. 16 KiB is a
/// good sweet spot — large enough to amortise the per-frame overhead,
/// small enough that a single read doesn't starve other channels.
const pump_read_chunk_size = 16 * 1024;

/// Connect timeout for the upstream dial. The mux dispatch thread
/// blocks for up to this long during channel open; if the upstream is
/// unreachable we want to fail fast rather than tying up the daemon.
const connect_timeout_ms = 10_000;

/// How long the pump thread waits for outbound credit before checking
/// the close signal again. 1 second strikes a balance between not
/// busy-looping and not delaying shutdown noticeably.
const credit_wait_timeout_ns: u64 = 1 * std.time.ns_per_s;

/// Maximum host length we accept in open params. Slightly under the
/// 253-char DNS spec; anything larger is almost certainly garbage.
const max_host_len: usize = 255;

/// Per-channel service state.
const TcpState = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    /// Set during open(); cleared during on_close after the pump joins.
    tcp_fd: posix.fd_t,
    /// Pump thread reading from tcp_fd into channel_data frames. Null
    /// only briefly before on_close joins it.
    pump_thread: ?std.Thread = null,
    /// Cached *Channel pointer for the pump. Valid until on_close
    /// returns. Set by the mux right after open() succeeds — see
    /// `attachChannel` below.
    channel: ?*channel_mux.Channel = null,
    /// Set by `attachChannel` to unblock the pump's initial wait.
    /// The pump spawns inside open() but the *Channel doesn't exist
    /// until the mux finishes registering it after open() returns; the
    /// pump waits on this event before touching `channel`.
    channel_attached: std.Thread.ResetEvent = .{},
};

/// Register the service in a daemon's channel-mux registry. Called
/// once at daemon startup.
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "tcp_connect",
        .vtable = &vtable,
    });
}

pub const vtable: channel_mux.Service.VTable = .{
    .open = open,
    .on_opened = onOpened,
    .on_data = onData,
    .on_control = onControl,
    .on_eof = onEof,
    .on_close = onClose,
};

/// Called by the mux right after `open` succeeds and the *Channel
/// pointer becomes stable. Hands the pointer to the pump and wakes it.
fn onOpened(state_ptr: ?*anyopaque, ch: *channel_mux.Channel) void {
    const state: *TcpState = @ptrCast(@alignCast(state_ptr orelse return));
    state.channel = ch;
    state.channel_attached.set();
}

fn open(
    _: ?*anyopaque,
    mux: *channel_mux.Mux,
    channel_id: u32,
    params: []const u8,
    _: []u8,
) channel_mux.ServiceError!channel_mux.Service.OpenResult {
    // Parse params: host_len(2) + host + port(2).
    if (params.len < 4) {
        log.warn("tcp_connect: open params too short ({d} bytes)", .{params.len});
        return error.InvalidRequest;
    }
    const host_len = std.mem.readInt(u16, params[0..2], .little);
    if (host_len > max_host_len) {
        log.warn("tcp_connect: host_len={d} exceeds limit", .{host_len});
        return error.InvalidRequest;
    }
    const min_params_len = 2 + @as(usize, host_len) + 2;
    if (params.len < min_params_len) {
        log.warn("tcp_connect: params truncated (need {d}, got {d})", .{ min_params_len, params.len });
        return error.InvalidRequest;
    }
    const host = params[2 .. 2 + host_len];
    const port = std.mem.readInt(u16, params[2 + host_len ..][0..2], .little);

    // Resolve + dial. We do this synchronously on the dispatch
    // thread. DNS can take ≤ a few seconds; this gates daemon
    // throughput briefly. If this turns into a real problem we can
    // move the dial to a worker thread and reply with status=ok early,
    // but that adds significant complexity — defer until we have data.
    const tcp_fd = dialTcp(mux.alloc, host, port) catch |err| {
        log.warn("tcp_connect: dial {s}:{d} failed: {}", .{ host, port, err });
        return error.ServiceError;
    };
    errdefer posix.close(tcp_fd);

    // Disable Nagle. Browser proxy + interactive port forwards want
    // low latency far more than they want byte coalescing.
    setTcpNoDelay(tcp_fd) catch |err| {
        log.warn("tcp_connect: TCP_NODELAY failed: {}", .{err});
    };

    // Allocate per-channel state.
    const state = try mux.alloc.create(TcpState);
    errdefer mux.alloc.destroy(state);
    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .tcp_fd = tcp_fd,
    };

    // Spawn the pump. The pump waits on channel_attached before doing
    // anything else, so we can spawn it before the mux has registered
    // the channel.
    state.pump_thread = std.Thread.spawn(.{}, pumpMain, .{state}) catch |err| {
        log.warn("tcp_connect: pump spawn failed: {}", .{err});
        return error.ResourceExhausted;
    };

    // The mux registers the channel in its map AFTER this function
    // returns. We need to attach the *Channel pointer to the state
    // once that happens. Since the mux doesn't have a post-open hook
    // yet, we stash a function pointer + state in OpenResult.ack...
    // actually that's a hack. Cleaner: the pump fetches the *Channel
    // itself via mux.getChannel(channel_id) on first iteration.
    return .{ .state = state };
}

fn onData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    const state: *TcpState = @ptrCast(@alignCast(state_ptr orelse return));
    // Write to the TCP socket. Blocking writes here are fine — the
    // socket has a kernel send buffer, and if it's full we naturally
    // back-pressure the daemon's read loop.
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(state.tcp_fd, bytes[off..]) catch |err| {
            log.warn("tcp_connect: write to upstream failed: {}", .{err});
            return error.ServiceError;
        };
        if (n == 0) return error.ServiceError;
        off += n;
    }
}

fn onControl(_: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    // No control ops defined for tcp_connect yet (stats is a future
    // op=1). Silently ignore unknown ops rather than failing the
    // channel — forward compatibility.
    log.debug("tcp_connect: ignoring unknown control op={d}", .{op});
}

fn onEof(state_ptr: ?*anyopaque) void {
    const state: *TcpState = @ptrCast(@alignCast(state_ptr orelse return));
    // Peer half-closed: stop sending bytes upstream by shutting down
    // the write side. The upstream may continue sending to us.
    posix.shutdown(state.tcp_fd, .send) catch |err| {
        log.debug("tcp_connect: shutdown(send) failed: {}", .{err});
    };
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *TcpState = @ptrCast(@alignCast(state_ptr orelse return));

    // Break the pump out of any blocking posix.read. The pump's loop
    // also observes `channel.close_signal` (set by the mux before
    // calling on_close), so this is belt-and-braces.
    posix.shutdown(state.tcp_fd, .both) catch |err| {
        log.debug("tcp_connect: shutdown(both) failed: {}", .{err});
    };

    // Also signal channel_attached in case the pump was waiting on
    // it (e.g. open() returned but the mux is tearing the channel
    // down before attaching).
    state.channel_attached.set();

    if (state.pump_thread) |t| {
        t.join();
        state.pump_thread = null;
    }

    posix.close(state.tcp_fd);
    state.alloc.destroy(state);
}

// =========================================================================
// Pump thread
// =========================================================================

fn pumpMain(state: *TcpState) void {
    pumpLoop(state) catch |err| {
        log.warn("tcp_connect pump exiting on error: {}", .{err});
    };
}

fn pumpLoop(state: *TcpState) !void {
    // Wait until the mux finishes registering the channel and we have
    // a stable *Channel pointer to work with. Bounded wait — if
    // attachment never happens (channel was closed before registry),
    // the close_signal still flips and we wake up.
    state.channel_attached.wait();
    var ch = state.mux.getChannel(state.channel_id) orelse return;

    var buf: [pump_read_chunk_size]u8 = undefined;
    while (!ch.close_signal.isSet()) {
        const n = posix.read(state.tcp_fd, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.ConnectionResetByPeer => {
                state.mux.requestClose(ch, .service_error, "upstream RST") catch {};
                return;
            },
            else => {
                state.mux.requestClose(ch, .service_error, @errorName(err)) catch {};
                return;
            },
        };
        if (n == 0) {
            // Upstream EOF. Tell the peer; the channel can still
            // carry inbound data (peer → upstream) until close.
            state.mux.sendChannelEof(ch) catch {};
            return;
        }

        var off: usize = 0;
        while (off < n) {
            if (ch.close_signal.isSet()) return;
            const sent = state.mux.sendChannelData(ch, buf[off..n]) catch |err| {
                log.warn("tcp_connect pump: sendChannelData failed: {}", .{err});
                return;
            };
            if (sent == 0) {
                _ = state.mux.waitForCredit(ch, credit_wait_timeout_ns);
                continue;
            }
            off += sent;
        }
    }
}

// =========================================================================
// Socket helpers
// =========================================================================

fn dialTcp(alloc: Allocator, host: []const u8, port: u16) !posix.fd_t {
    // std.net.tcpConnectToHost does DNS + connect synchronously but
    // doesn't expose a timeout. For an MVP we accept the OS default
    // (typically ~75s on macOS); applying connect_timeout_ms properly
    // requires non-blocking connect + select/poll which is more code
    // than the v1 service warrants. TODO: revisit when we hit a
    // hanging-dial pain point.
    _ = connect_timeout_ms;

    // std.net.Stream is a no-RAII handle wrapper, so we can grab the
    // fd and let the wrapper fall out of scope without closing.
    const stream = try std.net.tcpConnectToHost(alloc, host, port);
    return stream.handle;
}

fn setTcpNoDelay(fd: posix.fd_t) !void {
    // std.posix.TCP is `void` on iOS, so NODELAY is unavailable there.
    if (comptime builtin.os.tag == .ios) return;
    const yes: c_int = 1;
    try posix.setsockopt(
        fd,
        posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&yes),
    );
}

// =========================================================================
// Open params encoding helper (for clients/tests)
// =========================================================================

/// Encode tcp_connect open params for a host+port. Caller owns the
/// returned slice.
pub fn encodeOpenParams(alloc: Allocator, host: []const u8, port: u16) ![]u8 {
    if (host.len > max_host_len) return error.HostTooLong;
    const total = 2 + host.len + 2;
    const buf = try alloc.alloc(u8, total);
    std.mem.writeInt(u16, buf[0..2], @intCast(host.len), .little);
    @memcpy(buf[2 .. 2 + host.len], host);
    std.mem.writeInt(u16, buf[2 + host.len ..][0..2], port, .little);
    return buf;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "tcp_connect encodeOpenParams roundtrip" {
    const buf = try encodeOpenParams(testing.allocator, "localhost", 8080);
    defer testing.allocator.free(buf);
    try testing.expectEqual(@as(usize, 2 + 9 + 2), buf.len);
    const host_len = std.mem.readInt(u16, buf[0..2], .little);
    try testing.expectEqual(@as(u16, 9), host_len);
    try testing.expectEqualStrings("localhost", buf[2..11]);
    const port = std.mem.readInt(u16, buf[11..13], .little);
    try testing.expectEqual(@as(u16, 8080), port);
}

test "tcp_connect encodeOpenParams rejects oversized host" {
    var huge: [300]u8 = undefined;
    @memset(&huge, 'x');
    try testing.expectError(error.HostTooLong, encodeOpenParams(testing.allocator, &huge, 80));
}

// =========================================================================
// End-to-end integration test
// =========================================================================
//
// Stands up a real TCP echo server on localhost:0, opens a tcp_connect
// channel to it through a Mux running on a socketpair, verifies bytes
// round-trip in both directions, then closes cleanly.

const EchoServer = struct {
    listener_fd: posix.fd_t,
    port: u16,
    accept_thread: std.Thread,
    /// Set to true by the test when it wants the accept thread to
    /// stop blocking and exit (used for clean shutdown).
    stop_requested: std.atomic.Value(bool) = .init(false),

    fn start(alloc: Allocator) !*EchoServer {
        const server = try alloc.create(EchoServer);
        errdefer alloc.destroy(server);

        // Bind a TCP listener on localhost:0.
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        var addr = std.net.Address.parseIp("127.0.0.1", 0) catch unreachable;
        var addr_len: posix.socklen_t = addr.getOsSockLen();
        try posix.bind(fd, &addr.any, addr_len);
        try posix.listen(fd, 4);

        // Read back the bound port.
        try posix.getsockname(fd, &addr.any, &addr_len);
        const port = addr.getPort();

        server.* = .{
            .listener_fd = fd,
            .port = port,
            .accept_thread = undefined,
        };
        server.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{server});
        return server;
    }

    fn acceptLoop(self: *EchoServer) void {
        // Accept exactly one connection (sufficient for tests).
        var peer_addr: posix.sockaddr.in = undefined;
        var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer_addr));
        const peer = posix.accept(self.listener_fd, @ptrCast(&peer_addr), &peer_len, 0) catch return;
        defer posix.close(peer);

        var buf: [4096]u8 = undefined;
        while (!self.stop_requested.load(.acquire)) {
            const n = posix.read(peer, &buf) catch return;
            if (n == 0) return; // EOF
            // Echo back. Best-effort write.
            var off: usize = 0;
            while (off < n) {
                const w = posix.write(peer, buf[off..n]) catch return;
                if (w == 0) return;
                off += w;
            }
        }
    }

    fn stop(self: *EchoServer, alloc: Allocator) void {
        self.stop_requested.store(true, .release);
        // Closing the listener will not wake the accept that already
        // returned (we accept exactly once); we rely on the test
        // having driven the channel close which triggers EOF on the
        // accepted socket, ending the echo loop. As a safety net we
        // also shutdown the listener.
        posix.shutdown(self.listener_fd, .both) catch {};
        posix.close(self.listener_fd);
        self.accept_thread.join();
        alloc.destroy(self);
    }
};

const HeapMux = struct {
    a: posix.fd_t,
    b: posix.fd_t,
    alloc: Allocator,
    registry: *channel_mux.Registry,
    mux: channel_mux.Mux,

    fn init(alloc: Allocator) !HeapMux {
        var fds: [2]posix.fd_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc != 0) return error.SocketPairFailed;
        const reg = try alloc.create(channel_mux.Registry);
        reg.* = channel_mux.Registry.init(alloc);
        const mux = channel_mux.Mux.init(alloc, fds[0], reg);
        return .{ .a = fds[0], .b = fds[1], .alloc = alloc, .registry = reg, .mux = mux };
    }

    fn deinit(self: *HeapMux) void {
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
    var hbuf: [protocol.header_size]u8 = undefined;
    var off: usize = 0;
    while (off < hbuf.len) {
        const n = try posix.read(fd, hbuf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
    const header = try protocol.Header.parseFromBuf(&hbuf);
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

test "tcp_connect end-to-end: open, echo bytes, close" {
    var pair = try HeapMux.init(testing.allocator);
    defer pair.deinit();
    try register(pair.registry);

    var server = try EchoServer.start(testing.allocator);
    defer server.stop(testing.allocator);

    // Open the channel.
    const params = try encodeOpenParams(testing.allocator, "127.0.0.1", server.port);
    defer testing.allocator.free(params);
    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .tcp_connect,
        .initial_window = 8, // 8 × 4 KiB = 32 KiB window
        .service_params = params,
    };
    const open_buf = try open_frame.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);

    // Read the channel_opened reply.
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, opened_frame.header.kind);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    try testing.expectEqual(@as(u32, 1), opened.channel_id);

    // Send some bytes to be echoed.
    const greeting = "hello, world";
    const data = protocol.ChannelData{ .channel_id = 1, .bytes = greeting };
    const data_buf = try data.encode(testing.allocator);
    defer testing.allocator.free(data_buf);
    try pair.mux.dispatch(.channel_data, data_buf);

    // Read frames from the mux's outbound side until we've seen the
    // full echoed payload. The pump may emit multiple channel_data
    // frames, and may also interleave a channel_window update (if we
    // were sending enough to cross the 25% threshold — we aren't,
    // but be defensive).
    var collected = std.ArrayList(u8).empty;
    defer collected.deinit(testing.allocator);
    while (collected.items.len < greeting.len) {
        const frame = try readFrameAlloc(testing.allocator, pair.b);
        defer testing.allocator.free(frame.payload);
        switch (frame.header.kind) {
            .channel_data => {
                const dd = try protocol.ChannelData.parse(frame.payload);
                try testing.expectEqual(@as(u32, 1), dd.channel_id);
                try collected.appendSlice(testing.allocator, dd.bytes);
            },
            .channel_window => {}, // ignore — may be emitted by the daemon side
            else => return error.UnexpectedFrame,
        }
    }
    try testing.expectEqualStrings(greeting, collected.items);

    // Send channel_close from the peer side; daemon should tear
    // down the channel cleanly.
    const close = protocol.ChannelClose{
        .channel_id = 1,
        .reason = .normal,
        .message = "",
    };
    const close_buf = try close.encode(testing.allocator);
    defer testing.allocator.free(close_buf);
    try pair.mux.dispatch(.channel_close, close_buf);

    // Channel must be gone from the registry.
    pair.mux.mutex.lock();
    const present = pair.mux.channels.contains(1);
    pair.mux.mutex.unlock();
    try testing.expect(!present);
}
