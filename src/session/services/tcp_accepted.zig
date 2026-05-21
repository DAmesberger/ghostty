//! tcp_accepted channel service (daemon-internal).
//!
//! The opener-side counterpart of `tcp_connect`, used exclusively for
//! the child channels that `port_listener` spawns on each inbound TCP
//! accept. Where `tcp_connect.open` dials a *new* upstream socket,
//! `tcp_accepted.open` adopts an *already-accepted* socket fd handed to
//! it out-of-band through `service_open_params`.
//!
//! This service is daemon-internal: it is registered in the daemon's
//! channel-mux `Registry` (so daemon-originated `channel_open` frames
//! can resolve it and so it is advertised in the `capabilities` frame),
//! but it is NOT a member of `protocol.ChannelService` — the wire id is
//! a reserved value above the spec-defined range. Clients that want to
//! receive these channels need a matching client-side service; that is
//! a later-phase concern (see ClientMux's daemon-originated-open stub).
//!
//! Once the channel exists the byte-pump is identical to `tcp_connect`:
//! a per-channel pump thread reads the socket into `channel_data`
//! frames respecting outbound credit, and inbound `channel_data` is
//! written synchronously to the socket.
//!
//! service_open_params layout (daemon-local, never on the wire):
//!   [4]  fd  i32 LE   — the accepted socket fd, already owned by us

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");

const log = std.log.scoped(.tcp_accepted_service);

/// Reserved wire service id for `tcp_accepted`. Deliberately outside
/// `protocol.ChannelService`'s spec-defined range (0-5, 255) — this is
/// a daemon-internal service, not a spec service. 6 is the first free
/// slot above the defined ids.
pub const service_id: u8 = 6;

/// Read buffer size for the socket -> channel pump. Matches
/// `tcp_connect`.
const pump_read_chunk_size = 16 * 1024;

/// How long the pump waits for outbound credit before re-checking the
/// close signal. Matches `tcp_connect`.
const credit_wait_timeout_ns: u64 = 1 * std.time.ns_per_s;

/// Per-channel service state. Mirrors `tcp_connect`'s `TcpState` minus
/// the dial — the fd is supplied ready-to-use.
const AcceptedState = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    /// The accepted socket. Owned by this service from `open` until
    /// `on_close` returns.
    tcp_fd: posix.fd_t,
    pump_thread: ?std.Thread = null,
    channel: ?*channel_mux.Channel = null,
    channel_attached: std.Thread.ResetEvent = .{},
};

/// Register the service in a daemon's channel-mux registry. Called once
/// at daemon startup (by `daemon.zig`, lead-owned wiring).
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "tcp_accepted",
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

/// Encode the daemon-local open params for a given accepted fd. Used by
/// `port_listener` (and tests). Caller owns the returned slice.
pub fn encodeOpenParams(alloc: Allocator, fd: posix.fd_t) ![]u8 {
    const buf = try alloc.alloc(u8, 4);
    std.mem.writeInt(i32, buf[0..4], @intCast(fd), .little);
    return buf;
}

fn onOpened(state_ptr: ?*anyopaque, ch: *channel_mux.Channel) void {
    const state: *AcceptedState = @ptrCast(@alignCast(state_ptr orelse return));
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
    if (params.len < 4) {
        log.warn("tcp_accepted: open params too short ({d} bytes)", .{params.len});
        return error.InvalidRequest;
    }
    const fd: posix.fd_t = @intCast(std.mem.readInt(i32, params[0..4], .little));

    // The fd is already ours. From here we own it: any error past this
    // point must close it (errdefer below) so the accept loop never
    // leaks the socket.
    errdefer posix.close(fd);

    // Disable Nagle — interactive forwards want latency over coalescing.
    setTcpNoDelay(fd) catch |err| {
        log.warn("tcp_accepted: TCP_NODELAY failed: {}", .{err});
    };

    const state = try mux.alloc.create(AcceptedState);
    errdefer mux.alloc.destroy(state);
    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .tcp_fd = fd,
    };

    state.pump_thread = std.Thread.spawn(.{}, pumpMain, .{state}) catch |err| {
        log.warn("tcp_accepted: pump spawn failed: {}", .{err});
        return error.ResourceExhausted;
    };

    return .{ .state = state };
}

fn onData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    const state: *AcceptedState = @ptrCast(@alignCast(state_ptr orelse return));
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(state.tcp_fd, bytes[off..]) catch |err| {
            log.warn("tcp_accepted: write to socket failed: {}", .{err});
            return error.ServiceError;
        };
        if (n == 0) return error.ServiceError;
        off += n;
    }
}

fn onControl(_: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    log.debug("tcp_accepted: ignoring unknown control op={d}", .{op});
}

fn onEof(state_ptr: ?*anyopaque) void {
    const state: *AcceptedState = @ptrCast(@alignCast(state_ptr orelse return));
    posix.shutdown(state.tcp_fd, .send) catch |err| {
        log.debug("tcp_accepted: shutdown(send) failed: {}", .{err});
    };
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *AcceptedState = @ptrCast(@alignCast(state_ptr orelse return));

    // Break the pump out of any blocking posix.read.
    posix.shutdown(state.tcp_fd, .both) catch |err| {
        log.debug("tcp_accepted: shutdown(both) failed: {}", .{err});
    };
    // Unblock the pump if it was still waiting on channel attachment.
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

fn pumpMain(state: *AcceptedState) void {
    pumpLoop(state) catch |err| {
        log.warn("tcp_accepted pump exiting on error: {}", .{err});
    };
}

fn pumpLoop(state: *AcceptedState) !void {
    state.channel_attached.wait();
    const ch = state.mux.getChannel(state.channel_id) orelse return;

    var buf: [pump_read_chunk_size]u8 = undefined;
    while (!ch.close_signal.isSet()) {
        const n = posix.read(state.tcp_fd, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            // Socket died (RST / other read error). Unlike tcp_connect,
            // this pump does NOT call `requestClose` to tear the channel
            // down: a `tcp_accepted` channel may be closed concurrently
            // by its parent `port_listener` via `closeChannelById`, and
            // two destroy paths would double-free. Instead the pump
            // signals EOF best-effort and exits; the channel is reaped
            // by the peer's `channel_close`, the parent listener's
            // teardown, or `Mux.deinit` — each a single-owner full
            // close path.
            else => {
                state.mux.sendChannelEof(ch) catch {};
                return;
            },
        };
        if (n == 0) {
            // Upstream EOF.
            state.mux.sendChannelEof(ch) catch {};
            return;
        }

        var off: usize = 0;
        while (off < n) {
            if (ch.close_signal.isSet()) return;
            const sent = state.mux.sendChannelData(ch, buf[off..n]) catch |err| {
                log.warn("tcp_accepted pump: sendChannelData failed: {}", .{err});
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

fn setTcpNoDelay(fd: posix.fd_t) !void {
    const yes: c_int = 1;
    try posix.setsockopt(
        fd,
        posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&yes),
    );
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "tcp_accepted encodeOpenParams roundtrip" {
    const buf = try encodeOpenParams(testing.allocator, 42);
    defer testing.allocator.free(buf);
    try testing.expectEqual(@as(usize, 4), buf.len);
    const fd = std.mem.readInt(i32, buf[0..4], .little);
    try testing.expectEqual(@as(i32, 42), fd);
}
