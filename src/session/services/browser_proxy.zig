//! browser_proxy channel service.
//!
//! Forwards opaque byte streams to an upstream `host:port`, structurally
//! identical to `tcp_connect`: one channel = one upstream TCP socket,
//! one pump thread reads from the socket and emits `channel_data`
//! frames, inbound `channel_data` is written synchronously back to the
//! socket. The daemon does NOT parse HTTP — it just pumps bytes.
//!
//! Why a separate service from `tcp_connect`:
//!   * Lets the daemon audit and policy browser traffic independently
//!     (DNS allowlists, connection caps, request logging).
//!   * Carries an `upstream_kind` byte and free-form `request_metadata`
//!     so future policy hooks have something to inspect without
//!     parsing the wire format itself.
//!
//! Open params layout:
//!   [1]   upstream_kind     u8     // 0 = direct host:port,
//!                                  // 1 = http_connect_target,
//!                                  // 2 = socks5_target
//!   [2]   host_len          u16 LE
//!   [N]   host              UTF-8 bytes (≤ 253 chars per DNS spec)
//!   [2]   port              u16 LE
//!   [M]   request_metadata  UTF-8 bytes (optional; may be empty —
//!                                       logged on the daemon side, not
//!                                       interpreted)
//!
//! Opened service_ack: empty.
//!
//! Defaults:
//!   * Compression: OFF (HTTP responses are typically already gzipped).
//!   * TCP_NODELAY: ON (interactive browser traffic is latency-sensitive).
//!
//! Control ops (reserved for future use, ignored for v1):
//!   * op=1 keep_alive_hint — peer says "don't reap this idle channel".

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");

const log = std.log.scoped(.browser_proxy_service);

/// Service id for `browser_proxy`. Must match
/// `protocol.ChannelService.browser_proxy`.
pub const service_id: u8 = @intFromEnum(protocol.ChannelService.browser_proxy);

/// Read buffer size for the upstream → channel pump. 16 KiB matches
/// the tcp_connect chunk size — large enough to amortise per-frame
/// overhead, small enough that one read doesn't starve other channels.
const pump_read_chunk_size = 16 * 1024;

/// How long the pump thread waits for outbound credit before re-checking
/// the close signal. 1 s balances responsiveness with not busy-looping.
const credit_wait_timeout_ns: u64 = 1 * std.time.ns_per_s;

/// Maximum host length we accept in open params. Slightly above the
/// 253-char DNS spec; anything larger is almost certainly garbage.
const max_host_len: usize = 255;

/// Cap on request_metadata bytes accepted in open params. Logged only,
/// so we don't need much — but bound it to prevent unbounded memory
/// growth from a misbehaving peer.
const max_metadata_len: usize = 8 * 1024;

/// `upstream_kind` byte values. Currently informational — the daemon
/// pumps bytes the same way regardless. Future policy hooks (DNS
/// allowlist, per-kind caps) can inspect this without parsing the
/// stream.
pub const UpstreamKind = enum(u8) {
    /// Plain host:port — opener does TLS / HTTP itself.
    direct = 0,
    /// Target of an HTTP CONNECT tunnel.
    http_connect_target = 1,
    /// SOCKS5 endpoint hint.
    socks5_target = 2,
    _,
};

/// Per-channel service state.
const State = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    upstream_kind: UpstreamKind,
    /// Set during open(); closed during on_close after the pump joins.
    tcp_fd: posix.fd_t,
    /// Pump thread reading from tcp_fd into channel_data frames. Null
    /// only briefly before on_close joins it.
    pump_thread: ?std.Thread = null,
    /// Cached *Channel pointer for the pump. Valid until on_close
    /// returns. Set by `onOpened` once the mux has registered the
    /// channel.
    channel: ?*channel_mux.Channel = null,
    /// Set by `onOpened` to unblock the pump's initial wait. The pump
    /// spawns inside open() before the *Channel exists; it waits on
    /// this event before touching `channel`.
    channel_attached: std.Thread.ResetEvent = .{},
};

/// Register the service in a daemon's channel-mux registry. Called
/// once at daemon startup.
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "browser_proxy",
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

fn onOpened(state_ptr: ?*anyopaque, ch: *channel_mux.Channel) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
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
    const parsed = parseOpenParams(params) catch |err| {
        log.warn("browser_proxy: open params invalid: {}", .{err});
        return error.InvalidRequest;
    };

    // Resolve + dial synchronously on the dispatch thread. Same
    // trade-off as tcp_connect: DNS can briefly gate daemon throughput
    // but the alternative (async dial + later channel_opened reply)
    // adds significant complexity.
    const tcp_fd = dialTcp(mux.alloc, parsed.host, parsed.port) catch |err| {
        log.warn("browser_proxy[{s}]: dial {s}:{d} failed: {}", .{
            kindTag(parsed.upstream_kind), parsed.host, parsed.port, err,
        });
        return error.ServiceError;
    };
    errdefer posix.close(tcp_fd);

    // Browser traffic is interactive — disable Nagle.
    setTcpNoDelay(tcp_fd) catch |err| {
        log.warn("browser_proxy: TCP_NODELAY failed: {}", .{err});
    };

    if (parsed.request_metadata.len > 0) {
        log.debug("browser_proxy[{s}] {s}:{d} metadata: {d} bytes", .{
            kindTag(parsed.upstream_kind),
            parsed.host,
            parsed.port,
            parsed.request_metadata.len,
        });
    }

    const state = try mux.alloc.create(State);
    errdefer mux.alloc.destroy(state);
    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .upstream_kind = parsed.upstream_kind,
        .tcp_fd = tcp_fd,
    };

    state.pump_thread = std.Thread.spawn(.{}, pumpMain, .{state}) catch |err| {
        log.warn("browser_proxy: pump spawn failed: {}", .{err});
        return error.ResourceExhausted;
    };

    // Compression is OFF by default — leave flags empty.
    return .{ .state = state };
}

fn onData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(state.tcp_fd, bytes[off..]) catch |err| {
            log.warn("browser_proxy: write to upstream failed: {}", .{err});
            return error.ServiceError;
        };
        if (n == 0) return error.ServiceError;
        off += n;
    }
}

fn onControl(_: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    // op=1 keep_alive_hint is reserved but not yet acted on (no idle
    // reaper exists). All other ops are silently ignored for forward
    // compatibility.
    log.debug("browser_proxy: ignoring control op={d}", .{op});
}

fn onEof(state_ptr: ?*anyopaque) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    // Peer half-closed: stop sending bytes upstream but keep reading
    // from it.
    posix.shutdown(state.tcp_fd, .send) catch |err| {
        log.debug("browser_proxy: shutdown(send) failed: {}", .{err});
    };
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));

    // Break the pump out of any blocking posix.read. The pump's loop
    // also observes `channel.close_signal`, so this is belt-and-braces.
    posix.shutdown(state.tcp_fd, .both) catch |err| {
        log.debug("browser_proxy: shutdown(both) failed: {}", .{err});
    };

    // Defensive: unblock the pump if it was still waiting for attach
    // (e.g. open() returned but the mux is tearing the channel down
    // before invoking on_opened).
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

fn pumpMain(state: *State) void {
    pumpLoop(state) catch |err| {
        log.warn("browser_proxy pump exiting on error: {}", .{err});
    };
}

fn pumpLoop(state: *State) !void {
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
                log.warn("browser_proxy pump: sendChannelData failed: {}", .{err});
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
    const stream = try std.net.tcpConnectToHost(alloc, host, port);
    return stream.handle;
}

fn setTcpNoDelay(fd: posix.fd_t) !void {
    const yes: c_int = 1;
    try posix.setsockopt(
        fd,
        posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&yes),
    );
}

fn kindTag(kind: UpstreamKind) []const u8 {
    return switch (kind) {
        .direct => "direct",
        .http_connect_target => "http_connect",
        .socks5_target => "socks5",
        _ => "unknown",
    };
}

// =========================================================================
// Open params encoding / parsing
// =========================================================================

const ParsedParams = struct {
    upstream_kind: UpstreamKind,
    host: []const u8,
    port: u16,
    request_metadata: []const u8,
};

fn parseOpenParams(params: []const u8) !ParsedParams {
    // upstream_kind(1) + host_len(2) + port(2) = 5 minimum bytes.
    if (params.len < 5) return error.TooShort;
    const upstream_kind: UpstreamKind = @enumFromInt(params[0]);
    const host_len = std.mem.readInt(u16, params[1..3], .little);
    if (host_len > max_host_len) return error.HostTooLong;
    const min_len: usize = 1 + 2 + @as(usize, host_len) + 2;
    if (params.len < min_len) return error.Truncated;
    const host = params[3 .. 3 + host_len];
    const port = std.mem.readInt(u16, params[3 + host_len ..][0..2], .little);
    const metadata = params[3 + host_len + 2 ..];
    if (metadata.len > max_metadata_len) return error.MetadataTooLong;
    return .{
        .upstream_kind = upstream_kind,
        .host = host,
        .port = port,
        .request_metadata = metadata,
    };
}

/// Encode browser_proxy open params. Caller owns the returned slice.
pub fn encodeOpenParams(
    alloc: Allocator,
    upstream_kind: UpstreamKind,
    host: []const u8,
    port: u16,
    request_metadata: []const u8,
) ![]u8 {
    if (host.len > max_host_len) return error.HostTooLong;
    if (request_metadata.len > max_metadata_len) return error.MetadataTooLong;
    const total = 1 + 2 + host.len + 2 + request_metadata.len;
    const buf = try alloc.alloc(u8, total);
    buf[0] = @intFromEnum(upstream_kind);
    std.mem.writeInt(u16, buf[1..3], @intCast(host.len), .little);
    @memcpy(buf[3 .. 3 + host.len], host);
    std.mem.writeInt(u16, buf[3 + host.len ..][0..2], port, .little);
    @memcpy(buf[3 + host.len + 2 ..], request_metadata);
    return buf;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "browser_proxy encodeOpenParams roundtrip — direct, no metadata" {
    const buf = try encodeOpenParams(testing.allocator, .direct, "example.com", 443, "");
    defer testing.allocator.free(buf);
    const parsed = try parseOpenParams(buf);
    try testing.expectEqual(UpstreamKind.direct, parsed.upstream_kind);
    try testing.expectEqualStrings("example.com", parsed.host);
    try testing.expectEqual(@as(u16, 443), parsed.port);
    try testing.expectEqual(@as(usize, 0), parsed.request_metadata.len);
}

test "browser_proxy encodeOpenParams roundtrip — http_connect_target with metadata" {
    const meta = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const buf = try encodeOpenParams(
        testing.allocator,
        .http_connect_target,
        "proxy.internal",
        8080,
        meta,
    );
    defer testing.allocator.free(buf);
    const parsed = try parseOpenParams(buf);
    try testing.expectEqual(UpstreamKind.http_connect_target, parsed.upstream_kind);
    try testing.expectEqualStrings("proxy.internal", parsed.host);
    try testing.expectEqual(@as(u16, 8080), parsed.port);
    try testing.expectEqualStrings(meta, parsed.request_metadata);
}

test "browser_proxy encodeOpenParams roundtrip — socks5_target" {
    const buf = try encodeOpenParams(testing.allocator, .socks5_target, "10.0.0.1", 1080, "");
    defer testing.allocator.free(buf);
    const parsed = try parseOpenParams(buf);
    try testing.expectEqual(UpstreamKind.socks5_target, parsed.upstream_kind);
    try testing.expectEqualStrings("10.0.0.1", parsed.host);
    try testing.expectEqual(@as(u16, 1080), parsed.port);
}

test "browser_proxy encodeOpenParams rejects oversized host" {
    var huge: [300]u8 = undefined;
    @memset(&huge, 'x');
    try testing.expectError(
        error.HostTooLong,
        encodeOpenParams(testing.allocator, .direct, &huge, 80, ""),
    );
}

test "browser_proxy encodeOpenParams rejects oversized metadata" {
    const big = try testing.allocator.alloc(u8, max_metadata_len + 1);
    defer testing.allocator.free(big);
    @memset(big, 'm');
    try testing.expectError(
        error.MetadataTooLong,
        encodeOpenParams(testing.allocator, .direct, "h", 80, big),
    );
}

test "browser_proxy parseOpenParams rejects truncated input" {
    // Just upstream_kind, no host_len.
    const tiny = [_]u8{0};
    try testing.expectError(error.TooShort, parseOpenParams(&tiny));

    // upstream_kind + host_len=10 but only 4 bytes of host follow.
    var truncated: [3 + 4]u8 = undefined;
    truncated[0] = 0;
    std.mem.writeInt(u16, truncated[1..3], 10, .little);
    @memset(truncated[3..], 'x');
    try testing.expectError(error.Truncated, parseOpenParams(&truncated));
}

// =========================================================================
// End-to-end integration test
// =========================================================================
//
// Stands up a real TCP echo server on localhost:0, opens a browser_proxy
// channel to it through a Mux running on a socketpair, verifies bytes
// round-trip in both directions, then closes cleanly.

const EchoServer = struct {
    listener_fd: posix.fd_t,
    port: u16,
    accept_thread: std.Thread,
    stop_requested: std.atomic.Value(bool) = .init(false),

    fn start(alloc: Allocator) !*EchoServer {
        const server = try alloc.create(EchoServer);
        errdefer alloc.destroy(server);

        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        var addr = std.net.Address.parseIp("127.0.0.1", 0) catch unreachable;
        var addr_len: posix.socklen_t = addr.getOsSockLen();
        try posix.bind(fd, &addr.any, addr_len);
        try posix.listen(fd, 4);
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
        var peer_addr: posix.sockaddr.in = undefined;
        var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer_addr));
        const peer = posix.accept(self.listener_fd, @ptrCast(&peer_addr), &peer_len, 0) catch return;
        defer posix.close(peer);

        var buf: [4096]u8 = undefined;
        while (!self.stop_requested.load(.acquire)) {
            const n = posix.read(peer, &buf) catch return;
            if (n == 0) return;
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

test "browser_proxy end-to-end: open, echo bytes, close" {
    var pair = try HeapMux.init(testing.allocator);
    defer pair.deinit();
    try register(pair.registry);

    var server = try EchoServer.start(testing.allocator);
    defer server.stop(testing.allocator);

    // Open the channel.
    const params = try encodeOpenParams(
        testing.allocator,
        .direct,
        "127.0.0.1",
        server.port,
        "",
    );
    defer testing.allocator.free(params);
    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .browser_proxy,
        .initial_window = 8, // 8 × 4 KiB = 32 KiB
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
    // Compression must NOT have been negotiated by default.
    try testing.expectEqual(false, opened.flags.compression);

    // Send some bytes to be echoed.
    const greeting = "GET / HTTP/1.0\r\n\r\n";
    const data = protocol.ChannelData{ .channel_id = 1, .bytes = greeting };
    const data_buf = try data.encode(testing.allocator);
    defer testing.allocator.free(data_buf);
    try pair.mux.dispatch(.channel_data, data_buf);

    // Collect echoed bytes from the daemon-side mux output.
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
            .channel_window => {}, // ignore replenish updates
            else => return error.UnexpectedFrame,
        }
    }
    try testing.expectEqualStrings(greeting, collected.items);

    // Tear the channel down from the peer side.
    const close = protocol.ChannelClose{
        .channel_id = 1,
        .reason = .normal,
        .message = "",
    };
    const close_buf = try close.encode(testing.allocator);
    defer testing.allocator.free(close_buf);
    try pair.mux.dispatch(.channel_close, close_buf);

    pair.mux.mutex.lock();
    const present = pair.mux.channels.contains(1);
    pair.mux.mutex.unlock();
    try testing.expect(!present);
}
