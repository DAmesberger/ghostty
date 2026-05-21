//! port_listener channel service.
//!
//! Binds a TCP listening socket on the daemon and, for each inbound
//! connection it accepts, spawns a daemon-originated child channel that
//! carries that connection's bytes back to the peer. This is the
//! reverse-forward primitive: the peer asks the daemon to listen on a
//! port, and every connection to that port surfaces on the peer as a
//! new channel.
//!
//! The listener channel itself carries NO `channel_data` frames — it is
//! purely a control channel. Bytes flow on the child channels.
//!
//! Open params layout:
//!   [1]   mode           u8     (0 = remote_listen, 1 = local_listen)
//!   [2]   bind_port      u16 LE (0 = auto-assign)
//!   [2]   bind_host_len  u16 LE
//!   [N]   bind_host      UTF-8  (e.g. "127.0.0.1" or "0.0.0.0")
//!
//! Opened service_ack layout:
//!   [2]   actual_port      u16 LE
//!   [2]   actual_host_len  u16 LE
//!   [N]   actual_host      UTF-8
//!
//! Child channel (one per accepted connection): opened from the daemon
//! side via `Mux.openChannelFromDaemon` against the internal
//! `tcp_accepted` service. Its on-the-wire `service_params` are:
//!   [16]  parent_listener_uuid
//!   [N]   peer_addr   (6 bytes AF_INET: port + IPv4, or
//!                      18 bytes AF_INET6: port + IPv6)
//!
//! Control ops on the listener channel:
//!   op=1  pause   (client -> daemon): stop accepting until resume
//!   op=2  resume  (client -> daemon): resume accepting
//!   op=3  status  (daemon -> client): [8] accepted u64 LE | [8] active u64 LE

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");
const shared = @import("../shared.zig");
const tcp_accepted = @import("tcp_accepted.zig");

const log = std.log.scoped(.port_listener_service);

/// Service id for `port_listener`. Matches
/// `protocol.ChannelService.port_listener`.
pub const service_id: u8 = @intFromEnum(protocol.ChannelService.port_listener);

/// Listener bind mode.
const Mode = enum(u8) {
    /// The daemon binds the socket; connections to it surface on the
    /// peer. This is the only mode implemented for v1.
    remote_listen = 0,
    /// Reserved: the peer binds the socket. Unused for v1.
    local_listen = 1,
};

/// Control opcodes on the listener channel.
const op_pause: u8 = 1;
const op_resume: u8 = 2;
const op_status: u8 = 3;

/// Initial credit window (in 4 KiB units) advertised on each child
/// channel. 64 units = 256 KiB, a reasonable per-connection buffer.
const child_window_units: u16 = 64;

/// `listen` backlog for the bound socket.
const listen_backlog: u31 = 64;

/// Per-channel service state for an active listener.
const ListenerState = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    /// UUID identifying this listener, embedded in every child
    /// channel's wire params so the peer can correlate children to
    /// their parent listener.
    uuid: shared.Uuid,
    /// The bound listening socket. Owned by this service from `open`
    /// until `on_close` returns.
    listener_fd: posix.fd_t,
    /// Accept thread. Null only briefly before `on_close` joins it.
    accept_thread: ?std.Thread = null,
    /// Set true by `on_close` to make the accept loop exit. The loop
    /// is also broken out of a blocking `accept` by `shutdown`.
    stop_requested: std.atomic.Value(bool) = .init(false),
    /// Pause flag toggled by control ops. While true the accept loop
    /// still calls `accept` (so the socket's backlog drains) but
    /// immediately closes accepted sockets without spawning a channel.
    paused: std.atomic.Value(bool) = .init(false),
    /// Total connections accepted over the listener's lifetime.
    accepted_count: std.atomic.Value(u64) = .init(0),
    /// Guards `children`.
    children_mutex: std.Thread.Mutex = .{},
    /// Channel ids of every child spawned by this listener. Appended by
    /// the accept thread; drained by `on_close`. Ids of children that
    /// closed on their own are left in the list — `closeChannelById` is
    /// a no-op for unknown ids, so stale entries are harmless.
    children: std.ArrayListUnmanaged(u32) = .empty,
};

/// Register the service in a daemon's channel-mux registry. Called once
/// at daemon startup (by `daemon.zig`, lead-owned wiring).
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "port_listener",
        .vtable = &vtable,
    });
}

pub const vtable: channel_mux.Service.VTable = .{
    .open = open,
    .on_data = onData,
    .on_control = onControl,
    .on_eof = onEof,
    .on_close = onClose,
};

fn open(
    _: ?*anyopaque,
    mux: *channel_mux.Mux,
    channel_id: u32,
    params: []const u8,
    ack_buf: []u8,
) channel_mux.ServiceError!channel_mux.Service.OpenResult {
    const req = parseOpenParams(params) catch return error.InvalidRequest;
    if (req.mode != .remote_listen) {
        log.warn("port_listener: mode {} unsupported", .{req.mode});
        return error.InvalidRequest;
    }

    // Bind the listening socket.
    const bound = bindListener(req.bind_host, req.bind_port) catch |err| {
        log.warn("port_listener: bind {s}:{d} failed: {}", .{
            req.bind_host, req.bind_port, err,
        });
        return error.ServiceError;
    };
    errdefer posix.close(bound.fd);

    const state = try mux.alloc.create(ListenerState);
    errdefer mux.alloc.destroy(state);
    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .uuid = shared.generateUuid(),
        .listener_fd = bound.fd,
    };

    state.accept_thread = std.Thread.spawn(.{}, acceptMain, .{state}) catch |err| {
        log.warn("port_listener: accept thread spawn failed: {}", .{err});
        return error.ResourceExhausted;
    };

    // Encode the service ack: actual bound host + port.
    const ack = encodeAck(ack_buf, bound.host[0..bound.host_len], bound.port) catch
        return error.ServiceError;

    return .{ .state = state, .ack = ack };
}

fn onData(_: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    // The listener channel carries no data frames. A peer sending data
    // is a protocol misuse; drop it rather than failing the channel.
    log.debug("port_listener: discarding {d} unexpected data bytes", .{bytes.len});
}

fn onControl(state_ptr: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    const state: *ListenerState = @ptrCast(@alignCast(state_ptr orelse return));
    switch (op) {
        op_pause => {
            state.paused.store(true, .release);
            log.debug("port_listener: paused channel_id={d}", .{state.channel_id});
        },
        op_resume => {
            state.paused.store(false, .release);
            log.debug("port_listener: resumed channel_id={d}", .{state.channel_id});
        },
        op_status => sendStatus(state) catch |err| {
            log.warn("port_listener: status send failed: {}", .{err});
        },
        else => log.debug("port_listener: ignoring unknown control op={d}", .{op}),
    }
}

fn onEof(_: ?*anyopaque) void {
    // Peer half-close on a control channel is meaningless; ignore.
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *ListenerState = @ptrCast(@alignCast(state_ptr orelse return));

    // Stop the accept loop: flag it, then break it out of a blocking
    // `accept` by shutting the listener down.
    state.stop_requested.store(true, .release);
    posix.shutdown(state.listener_fd, .both) catch |err| {
        log.debug("port_listener: shutdown(listener) failed: {}", .{err});
    };
    if (state.accept_thread) |t| {
        t.join();
        state.accept_thread = null;
    }
    posix.close(state.listener_fd);

    // Tear down every child channel. `closeChannelById` runs the full
    // close path (joins each child's pump) and is a no-op for ids whose
    // channel already closed, so stale ids in the list are harmless.
    state.children_mutex.lock();
    for (state.children.items) |child_id| {
        state.mux.closeChannelById(child_id, .normal, "listener closed");
    }
    state.children.deinit(state.alloc);
    state.children_mutex.unlock();

    state.alloc.destroy(state);
}

// =========================================================================
// Accept thread
// =========================================================================

fn acceptMain(state: *ListenerState) void {
    acceptLoop(state) catch |err| {
        log.warn("port_listener accept loop exiting on error: {}", .{err});
    };
}

fn acceptLoop(state: *ListenerState) !void {
    // The listener socket is non-blocking; we `poll` with a short
    // timeout so the stop flag is checked regularly. This avoids
    // depending on `shutdown` to break a blocked `accept`, which is not
    // portable (notably unreliable on macOS).
    while (!state.stop_requested.load(.acquire)) {
        var pollfds = [1]posix.pollfd{
            .{ .fd = state.listener_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = try posix.poll(&pollfds, 200);
        if (ready == 0) continue; // timeout — re-check the stop flag

        var addr: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(@TypeOf(addr));
        const conn_fd = posix.accept(
            state.listener_fd,
            @ptrCast(&addr),
            &addr_len,
            0,
        ) catch |err| switch (err) {
            // No connection actually pending (e.g. the client reset
            // between `poll` and `accept`) — loop and re-poll.
            error.WouldBlock, error.ConnectionAborted, error.ConnectionResetByPeer => continue,
            // The listener was closed under us — exit.
            error.SocketNotListening, error.FileDescriptorNotASocket => return,
            else => return err,
        };

        // Re-check the stop flag: `on_close` may have run while we were
        // in `accept`.
        if (state.stop_requested.load(.acquire)) {
            posix.close(conn_fd);
            return;
        }

        _ = state.accepted_count.fetchAdd(1, .monotonic);

        // While paused, drain the backlog but drop the connection.
        if (state.paused.load(.acquire)) {
            posix.close(conn_fd);
            continue;
        }

        spawnChild(state, conn_fd, &addr) catch |err| {
            // On any failure to hand the socket to a child channel we
            // must close it here — ownership never transferred.
            log.warn("port_listener: spawnChild failed: {}", .{err});
            posix.close(conn_fd);
        };
    }
}

/// Hand an accepted socket to a new daemon-originated `tcp_accepted`
/// child channel. On success the fd's ownership has transferred to the
/// child service; on error the caller must close it.
fn spawnChild(
    state: *ListenerState,
    conn_fd: posix.fd_t,
    addr: *const posix.sockaddr.storage,
) !void {
    // Daemon-local open params for tcp_accepted: just the fd.
    const service_params = try tcp_accepted.encodeOpenParams(state.alloc, conn_fd);
    defer state.alloc.free(service_params);

    // Wire params: parent uuid + peer address.
    const wire_params = try encodeChildWireParams(state.alloc, state.uuid, addr);
    defer state.alloc.free(wire_params);

    const child_id = state.mux.openChannelFromDaemon(
        tcp_accepted.service_id,
        wire_params,
        service_params,
        child_window_units,
    ) catch |err| {
        // The error tells us whether `tcp_accepted.open` ran, which
        // determines fd ownership (see `OpenChannelError` docs):
        switch (err) {
            // `open` never ran — we still own conn_fd; surface the
            // error so `acceptLoop` closes it.
            error.ServiceNotRegistered, error.ChannelIdsExhausted => return err,
            // `open` ran and failed — `tcp_accepted.open`'s errdefer
            // already closed conn_fd. Return without closing (avoids a
            // double close) and without surfacing the error.
            error.InvalidRequest,
            error.ServiceError,
            error.PolicyDenied,
            error.ResourceExhausted,
            error.OutOfMemory,
            => {
                log.warn("port_listener: child open rejected: {}", .{err});
                return;
            },
        }
    };

    state.children_mutex.lock();
    state.children.append(state.alloc, child_id) catch {
        // We could not record the child id for later teardown. The
        // channel still exists and works; it just won't be force-closed
        // on listener teardown (it will be reaped by Mux.deinit). Log
        // and carry on rather than killing a healthy connection.
        log.warn("port_listener: failed to track child id={x}", .{child_id});
    };
    state.children_mutex.unlock();
}

// =========================================================================
// Status
// =========================================================================

fn sendStatus(state: *ListenerState) !void {
    const ch = state.mux.getChannel(state.channel_id) orelse return;

    state.children_mutex.lock();
    var active: u64 = 0;
    for (state.children.items) |child_id| {
        if (state.mux.getChannel(child_id) != null) active += 1;
    }
    state.children_mutex.unlock();

    var payload: [16]u8 = undefined;
    std.mem.writeInt(u64, payload[0..8], state.accepted_count.load(.monotonic), .little);
    std.mem.writeInt(u64, payload[8..16], active, .little);

    const ctrl = protocol.ChannelControl{
        .channel_id = ch.id,
        .op = op_status,
        .op_payload = &payload,
    };
    const encoded = try ctrl.encode(state.mux.alloc);
    defer state.mux.alloc.free(encoded);
    try state.mux.sendFrame(.channel_control, encoded);
}

// =========================================================================
// Param + address codecs
// =========================================================================

const OpenRequest = struct {
    mode: Mode,
    bind_port: u16,
    bind_host: []const u8,
};

fn parseOpenParams(params: []const u8) !OpenRequest {
    // mode(1) + bind_port(2) + bind_host_len(2) = 5 fixed bytes.
    if (params.len < 5) return error.InvalidParams;
    const mode: Mode = std.meta.intToEnum(Mode, params[0]) catch return error.InvalidParams;
    const bind_port = std.mem.readInt(u16, params[1..3], .little);
    const host_len = std.mem.readInt(u16, params[3..5], .little);
    if (params.len < 5 + @as(usize, host_len)) return error.InvalidParams;
    return .{
        .mode = mode,
        .bind_port = bind_port,
        .bind_host = params[5 .. 5 + host_len],
    };
}

/// Encode `port_listener` open params. Caller owns the returned slice.
/// Exposed for clients and tests.
pub fn encodeOpenParams(
    alloc: Allocator,
    mode_byte: u8,
    bind_port: u16,
    bind_host: []const u8,
) ![]u8 {
    const buf = try alloc.alloc(u8, 5 + bind_host.len);
    buf[0] = mode_byte;
    std.mem.writeInt(u16, buf[1..3], bind_port, .little);
    std.mem.writeInt(u16, buf[3..5], @intCast(bind_host.len), .little);
    @memcpy(buf[5..], bind_host);
    return buf;
}

/// Encode the opened service_ack into `buf`. Returns the populated
/// sub-slice. `buf` must be at least `4 + host.len` bytes.
fn encodeAck(buf: []u8, host: []const u8, port: u16) ![]const u8 {
    const total = 4 + host.len;
    if (buf.len < total) return error.AckBufferTooSmall;
    std.mem.writeInt(u16, buf[0..2], port, .little);
    std.mem.writeInt(u16, buf[2..4], @intCast(host.len), .little);
    @memcpy(buf[4..total], host);
    return buf[0..total];
}

/// Parsed `port_listener` opened service_ack. Exposed for tests.
pub const Ack = struct {
    port: u16,
    host: []const u8,
};

/// Parse a `port_listener` opened service_ack. `host` borrows from
/// `ack`. Exposed for clients and tests.
pub fn parseAck(ack: []const u8) !Ack {
    if (ack.len < 4) return error.InvalidAck;
    const port = std.mem.readInt(u16, ack[0..2], .little);
    const host_len = std.mem.readInt(u16, ack[2..4], .little);
    if (ack.len < 4 + @as(usize, host_len)) return error.InvalidAck;
    return .{ .port = port, .host = ack[4 .. 4 + host_len] };
}

/// Encode a child channel's wire `service_params`:
///   [16] parent_uuid | [N] peer_addr
/// where peer_addr is 6 bytes for IPv4 (port + addr) or 18 bytes for
/// IPv6. Caller owns the returned slice.
fn encodeChildWireParams(
    alloc: Allocator,
    uuid: shared.Uuid,
    addr: *const posix.sockaddr.storage,
) ![]u8 {
    const family = addr.family;
    switch (family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
            const buf = try alloc.alloc(u8, 16 + 6);
            @memcpy(buf[0..16], &uuid);
            // `sin_port` and `sin_addr` are already in network byte
            // order; the wire format wants AF_INET form, i.e. network
            // order — so copy the raw bytes verbatim, no conversion.
            @memcpy(buf[16..18], std.mem.asBytes(&in.port)[0..2]);
            @memcpy(buf[18..22], std.mem.asBytes(&in.addr)[0..4]);
            return buf;
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            const buf = try alloc.alloc(u8, 16 + 18);
            @memcpy(buf[0..16], &uuid);
            @memcpy(buf[16..18], std.mem.asBytes(&in6.port)[0..2]);
            @memcpy(buf[18..34], &in6.addr);
            return buf;
        },
        else => return error.UnsupportedAddressFamily,
    }
}

// =========================================================================
// Socket helpers
// =========================================================================

const BoundListener = struct {
    fd: posix.fd_t,
    port: u16,
    /// Echo of the requested bind host (the human-readable address the
    /// caller asked for, not a reverse-resolved name).
    host: [256]u8,
    host_len: u8,
};

fn bindListener(host: []const u8, port: u16) !BoundListener {
    var addr = try std.net.Address.parseIp(host, port);
    // Non-blocking so the accept loop can `poll` with a timeout and
    // observe the stop flag without depending on `shutdown` to break a
    // blocked `accept`.
    const fd = try posix.socket(
        addr.any.family,
        posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
        posix.IPPROTO.TCP,
    );
    errdefer posix.close(fd);

    // SO_REUSEADDR so a quick listener restart on the same port does
    // not trip over TIME_WAIT.
    const yes: c_int = 1;
    posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.REUSEADDR,
        std.mem.asBytes(&yes),
    ) catch |err| {
        log.warn("port_listener: SO_REUSEADDR failed: {}", .{err});
    };

    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    try posix.listen(fd, listen_backlog);

    // Read back the actual bound port (relevant when port == 0).
    var bound_addr = addr;
    var bound_len: posix.socklen_t = bound_addr.getOsSockLen();
    try posix.getsockname(fd, &bound_addr.any, &bound_len);

    var result: BoundListener = .{
        .fd = fd,
        .port = bound_addr.getPort(),
        .host = undefined,
        .host_len = 0,
    };
    const copy_len = @min(host.len, result.host.len);
    @memcpy(result.host[0..copy_len], host[0..copy_len]);
    result.host_len = @intCast(copy_len);
    return result;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "port_listener encodeOpenParams / parseOpenParams roundtrip" {
    const buf = try encodeOpenParams(testing.allocator, 0, 8080, "127.0.0.1");
    defer testing.allocator.free(buf);
    const req = try parseOpenParams(buf);
    try testing.expectEqual(Mode.remote_listen, req.mode);
    try testing.expectEqual(@as(u16, 8080), req.bind_port);
    try testing.expectEqualStrings("127.0.0.1", req.bind_host);
}

test "port_listener parseOpenParams rejects truncated host" {
    // Claims a 9-byte host but supplies only 3.
    var buf: [8]u8 = .{ 0, 0x90, 0x1f, 9, 0, 'a', 'b', 'c' };
    try testing.expectError(error.InvalidParams, parseOpenParams(&buf));
}

test "port_listener ack roundtrip" {
    var buf: [64]u8 = undefined;
    const ack = try encodeAck(&buf, "0.0.0.0", 54321);
    const parsed = try parseAck(ack);
    try testing.expectEqual(@as(u16, 54321), parsed.port);
    try testing.expectEqualStrings("0.0.0.0", parsed.host);
}

test "port_listener encodeChildWireParams IPv4" {
    // `sockaddr.in` stores port + addr in network byte order; build
    // them so the in-memory bytes are the network-order bytes.
    const addr_in: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 4242),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = .{0} ** 8,
    };
    var storage: posix.sockaddr.storage = undefined;
    @memcpy(std.mem.asBytes(&storage)[0..@sizeOf(posix.sockaddr.in)], std.mem.asBytes(&addr_in));

    const uuid: shared.Uuid = .{1} ** 16;
    const wire = try encodeChildWireParams(testing.allocator, uuid, &storage);
    defer testing.allocator.free(wire);

    try testing.expectEqual(@as(usize, 22), wire.len);
    try testing.expectEqualSlices(u8, &uuid, wire[0..16]);
    const port = std.mem.readInt(u16, wire[16..18], .big);
    try testing.expectEqual(@as(u16, 4242), port);
    try testing.expectEqualSlices(u8, &[4]u8{ 127, 0, 0, 1 }, wire[18..22]);
}

// =========================================================================
// End-to-end integration test
// =========================================================================
//
// Opens a `port_listener` channel against a `Mux` running over a
// socketpair, learns the auto-assigned port from the opened ack,
// connects a TCP client to it, sends bytes, and verifies they surface
// as `channel_data` on a daemon-originated child channel on the mux's
// outbound side. Exercises `port_listener` + `tcp_accepted` +
// `Mux.openChannelFromDaemon` together.

/// Read exactly `buf.len` bytes from `fd`, failing with
/// `error.ReadTimeout` if no data arrives within ~5s. The timeout keeps
/// a stalled test from hanging the whole suite.
fn readExactTimeout(fd: posix.fd_t, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        var pollfds = [1]posix.pollfd{
            .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = try posix.poll(&pollfds, 5000);
        if (ready == 0) return error.ReadTimeout;
        const n = try posix.read(fd, buf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

fn readFrameAlloc(alloc: Allocator, fd: posix.fd_t) !struct {
    header: protocol.Header,
    payload: []u8,
} {
    var hbuf: [protocol.header_size]u8 = undefined;
    try readExactTimeout(fd, &hbuf);
    const header = try protocol.Header.parseFromBuf(&hbuf);
    const payload = try alloc.alloc(u8, header.len);
    errdefer alloc.free(payload);
    try readExactTimeout(fd, payload);
    return .{ .header = header, .payload = payload };
}

test "port_listener end-to-end: bind, accept, child channel carries bytes" {
    const alloc = testing.allocator;

    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const reg = try alloc.create(channel_mux.Registry);
    defer alloc.destroy(reg);
    reg.* = channel_mux.Registry.init(alloc);
    defer reg.deinit();
    try register(reg);
    try tcp_accepted.register(reg);

    var mux = channel_mux.Mux.init(alloc, fds[0], reg);
    defer mux.deinit();

    // Open a port_listener channel: auto-assign a port on 127.0.0.1.
    const params = try encodeOpenParams(alloc, 0, 0, "127.0.0.1");
    defer alloc.free(params);
    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .port_listener,
        .initial_window = 8,
        .service_params = params,
    };
    const open_buf = try open_frame.encode(alloc);
    defer alloc.free(open_buf);
    try mux.dispatch(.channel_open, open_buf);

    // Read the channel_opened reply and learn the bound port.
    const opened_frame = try readFrameAlloc(alloc, fds[1]);
    defer alloc.free(opened_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, opened_frame.header.kind);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    const ack = try parseAck(opened.service_ack);
    try testing.expect(ack.port != 0);
    try testing.expectEqualStrings("127.0.0.1", ack.host);

    // Connect a TCP client to the listener.
    const client_addr = try std.net.Address.parseIp("127.0.0.1", ack.port);
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(client_fd);
    try posix.connect(client_fd, &client_addr.any, client_addr.getOsSockLen());

    // The accept loop should spawn a daemon-originated child channel:
    // first a channel_open frame, then channel_data once we send bytes.
    const probe = "ping through the tunnel";
    var sent: usize = 0;
    while (sent < probe.len) {
        sent += try posix.write(client_fd, probe[sent..]);
    }

    // Collect frames off the mux's outbound side. We expect a child
    // channel_open (daemon-direction id) followed by channel_data
    // carrying our probe bytes.
    var child_id: ?u32 = null;
    var collected = std.ArrayListUnmanaged(u8).empty;
    defer collected.deinit(alloc);
    var guard: usize = 0;
    while (collected.items.len < probe.len and guard < 64) : (guard += 1) {
        const frame = try readFrameAlloc(alloc, fds[1]);
        defer alloc.free(frame.payload);
        switch (frame.header.kind) {
            .channel_open => {
                const co = try protocol.ChannelOpen.parse(frame.payload);
                try testing.expect((co.channel_id & protocol.channel_id_daemon_bit) != 0);
                // Wire params: parent uuid (16) + IPv4 peer addr (6).
                try testing.expectEqual(@as(usize, 22), co.service_params.len);
                child_id = co.channel_id;
            },
            .channel_data => {
                const cd = try protocol.ChannelData.parse(frame.payload);
                try testing.expect(child_id != null);
                try testing.expectEqual(child_id.?, cd.channel_id);
                try collected.appendSlice(alloc, cd.bytes);
            },
            .channel_window => {},
            else => return error.UnexpectedFrame,
        }
    }
    try testing.expectEqualStrings(probe, collected.items);

    // Tear the listener down; mux.deinit() (deferred) will close the
    // listener channel, which stops the accept thread and force-closes
    // the child channel.
    const close = protocol.ChannelClose{ .channel_id = 1, .reason = .normal };
    const close_buf = try close.encode(alloc);
    defer alloc.free(close_buf);
    try mux.dispatch(.channel_close, close_buf);
    try testing.expect(!mux.channels.contains(1));
}

test "port_listener rejects an unsupported bind mode" {
    const alloc = testing.allocator;
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const reg = try alloc.create(channel_mux.Registry);
    defer alloc.destroy(reg);
    reg.* = channel_mux.Registry.init(alloc);
    defer reg.deinit();
    try register(reg);

    var mux = channel_mux.Mux.init(alloc, fds[0], reg);
    defer mux.deinit();

    // mode = 1 (local_listen) is unsupported in v1.
    const params = try encodeOpenParams(alloc, 1, 0, "127.0.0.1");
    defer alloc.free(params);
    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .port_listener,
        .service_params = params,
    };
    const open_buf = try open_frame.encode(alloc);
    defer alloc.free(open_buf);
    try mux.dispatch(.channel_open, open_buf);

    const opened_frame = try readFrameAlloc(alloc, fds[1]);
    defer alloc.free(opened_frame.payload);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.invalid_request, opened.status);
    try testing.expect(!mux.channels.contains(1));
}

test "port_listener closes the accepted socket when child open fails" {
    const alloc = testing.allocator;
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    // Register port_listener but NOT tcp_accepted — so every child
    // open fails with error.ServiceNotRegistered and the accept loop
    // must close the accepted socket itself.
    const reg = try alloc.create(channel_mux.Registry);
    defer alloc.destroy(reg);
    reg.* = channel_mux.Registry.init(alloc);
    defer reg.deinit();
    try register(reg);

    var mux = channel_mux.Mux.init(alloc, fds[0], reg);
    defer mux.deinit();

    const params = try encodeOpenParams(alloc, 0, 0, "127.0.0.1");
    defer alloc.free(params);
    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .port_listener,
        .service_params = params,
    };
    const open_buf = try open_frame.encode(alloc);
    defer alloc.free(open_buf);
    try mux.dispatch(.channel_open, open_buf);

    const opened_frame = try readFrameAlloc(alloc, fds[1]);
    defer alloc.free(opened_frame.payload);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    const ack = try parseAck(opened.service_ack);

    // Connect; the accept loop accepts then fails to spawn a child and
    // must close the socket. The client side observes EOF.
    const client_addr = try std.net.Address.parseIp("127.0.0.1", ack.port);
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(client_fd);
    try posix.connect(client_fd, &client_addr.any, client_addr.getOsSockLen());

    // The daemon-side accepted socket must be closed by the accept
    // loop, which the client observes as EOF (read returns 0).
    var buf: [16]u8 = undefined;
    var pollfds = [1]posix.pollfd{
        .{ .fd = client_fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = try posix.poll(&pollfds, 5000);
    try testing.expect(ready > 0);
    const n = try posix.read(client_fd, &buf);
    try testing.expectEqual(@as(usize, 0), n);

    const close = protocol.ChannelClose{ .channel_id = 1, .reason = .normal };
    const close_buf = try close.encode(alloc);
    defer alloc.free(close_buf);
    try mux.dispatch(.channel_close, close_buf);
}
