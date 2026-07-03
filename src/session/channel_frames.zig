const std = @import("std");
const Allocator = std.mem.Allocator;

const frame = @import("frame.zig");
const max_payload = frame.max_payload;
const Kind = frame.Kind;
const writeFrame = frame.writeFrame;
const readHeader = frame.readHeader;
const readPayloadAlloc = frame.readPayloadAlloc;

// =========================================================================
// Generic multiplexed channels (kinds 30-36)
// =========================================================================
//
// All channel frames carry their channel_id as the first 4 bytes of the
// payload. The 8-byte frame header's `target` field is reserved (must be 0)
// for channel frames so the existing terminal-surface multiplexer on
// `target` does not collide with channel multiplexing.
//
// Direction convention: opener picks the channel_id; daemon-originated
// channels (e.g. an inbound TCP accept on a port_listener service) set the
// high bit (`channel_id & 0x8000_0000 != 0`). This avoids a central
// allocator across both directions and matches SSH channel-direction
// semantics.

/// Default initial credit window for a new channel, in 4 KiB units.
/// 1 MiB. Opener may declare smaller for memory-bounded services.
pub const default_channel_window_units: u16 = 256;

/// Hard upper bound on per-channel window in 4 KiB units (16 MiB).
/// Used to bound per-channel inbound buffering.
pub const max_channel_window_units: u16 = 4096;

/// Channel id value used for "no channel" / invalid. Both 0 and the
/// daemon-direction marker bit are valid; only this sentinel is reserved
/// for explicit "unset" sentinels in fields that can omit a channel id.
pub const invalid_channel_id: u32 = std.math.maxInt(u32);

/// Bit on `channel_id` indicating the channel was opened by the daemon
/// side (as opposed to the client side). See direction convention above.
pub const channel_id_daemon_bit: u32 = 0x8000_0000;

/// Service identifier for `ChannelOpen`. Matches the registry on the
/// daemon side. Values 0 and 255 are reserved (invalid sentinel and
/// `custom` escape hatch respectively).
pub const ChannelService = enum(u8) {
    invalid = 0,
    tcp_connect = 1,
    port_listener = 2,
    file_transfer = 3,
    browser_proxy = 4,
    process_exec = 5,
    /// Reverse control bridge. The daemon listens on a remote-side unix
    /// socket (path injected into the remote shell via the embedder's
    /// configured socket-path env var, default `CMUX_SOCKET_PATH`) and
    /// forwards each framed CLI request received there back to the client
    /// over a daemon-originated channel of this service. The client runs the
    /// request through its in-process socket dispatcher (notify /
    /// notify_target / report_*) and writes the response back. Wire id 7 —
    /// the first free slot above the spec-defined services and below the
    /// `tcp_accepted` daemon-internal id (which uses the reserved-range
    /// value, see services/tcp_accepted.zig). The value is an on-wire
    /// contract with deployed peers; keep it stable.
    control_bridge = 7,
    custom = 255,
    _,
};

/// Flags for ChannelOpen / ChannelOpened, packed into the `flags` byte
/// inside the payload (separate from the header's `Flags` byte).
pub const ChannelOpenFlags = packed struct(u8) {
    /// Opener can decompress inbound data (and asks daemon to compress).
    /// Daemon echoes this bit in `ChannelOpened.flags` to commit. When
    /// both sides set it, individual `channel_data` frames opt in via
    /// the header `Flags.compressed` bit on a per-frame basis.
    compression: bool = false,
    /// Channel will not carry upstream (opener → peer) data. Hint for
    /// services like file downloads that pre-allocate buffers.
    unidirectional_download: bool = false,
    _reserved: u6 = 0,
};

/// Status code returned in ChannelOpened. 0 = ok; nonzero = error and
/// the channel is dead (no further frames will be sent for this id).
pub const ChannelOpenStatus = enum(u8) {
    ok = 0,
    /// Service id was not advertised in the peer's Capabilities.
    service_not_supported = 1,
    /// Service-level error (e.g. TCP dial failed, file path denied).
    service_error = 2,
    /// Too many concurrent channels; opener should back off.
    resource_exhausted = 3,
    /// Malformed open request (bad params, invalid window, etc.).
    invalid_request = 4,
    /// Peer policy rejected the open (sandboxing, auth, etc.).
    policy_denied = 5,
    _,
};

/// Reason for ChannelClose. Both sides may close unilaterally; any
/// further frames carrying the channel id are discarded.
pub const ChannelCloseReason = enum(u8) {
    normal = 0,
    /// The peer violated the protocol (e.g. window overrun).
    peer_reset = 1,
    /// Service raised an error (e.g. TCP connection dropped).
    service_error = 2,
    /// Policy / sandbox decision.
    policy_denied = 3,
    /// No traffic for too long (stall watchdog).
    idle_timeout = 4,
    /// Daemon is shutting down; all channels on this connection close.
    daemon_shutdown = 5,
    _,
};

/// Payload for `channel_open` (kind 30):
///   [4]  channel_id     u32 LE (opener-chosen; high bit set if daemon-origin)
///   [1]  service_id     u8
///   [1]  flags          u8 (ChannelOpenFlags bitfield)
///   [2]  initial_window u16 LE (4 KiB units; 0 = use default_channel_window_units)
///   [2]  reserved       u16 LE (must be 0)
///   [N]  service_params bytes (service-defined; may be empty)
pub const ChannelOpen = struct {
    channel_id: u32,
    service: ChannelService,
    flags: ChannelOpenFlags = .{},
    initial_window: u16 = 0,
    service_params: []const u8 = "",

    /// Fixed bytes: channel_id(4) + service_id(1) + flags(1) + initial_window(2) + reserved(2).
    pub const fixed_size: usize = 4 + 1 + 1 + 2 + 2;

    pub fn encode(self: ChannelOpen, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.service_params.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.service);
        buf[5] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[6..8], self.initial_window, .little);
        std.mem.writeInt(u16, buf[8..10], 0, .little);
        @memcpy(buf[fixed_size..], self.service_params);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelOpen {
        if (payload.len < fixed_size) return error.InvalidChannelOpenPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .service = @enumFromInt(payload[4]),
            .flags = @bitCast(payload[5]),
            .initial_window = std.mem.readInt(u16, payload[6..8], .little),
            .service_params = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_opened` (kind 31):
///   [4]  channel_id  u32 LE (echoes the opener's id)
///   [1]  status      u8 (ChannelOpenStatus)
///   [1]  flags       u8 (negotiated ChannelOpenFlags — bits opener AND daemon set)
///   [2]  peer_window u16 LE (4 KiB units the daemon grants the opener)
///   [2]  reserved    u16 LE
///   [N]  service_ack bytes (service-defined; error message on failure)
pub const ChannelOpened = struct {
    channel_id: u32,
    status: ChannelOpenStatus,
    flags: ChannelOpenFlags = .{},
    peer_window: u16 = 0,
    service_ack: []const u8 = "",

    pub const fixed_size: usize = 4 + 1 + 1 + 2 + 2;

    pub fn encode(self: ChannelOpened, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.service_ack.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.status);
        buf[5] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[6..8], self.peer_window, .little);
        std.mem.writeInt(u16, buf[8..10], 0, .little);
        @memcpy(buf[fixed_size..], self.service_ack);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelOpened {
        if (payload.len < fixed_size) return error.InvalidChannelOpenedPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .status = @enumFromInt(payload[4]),
            .flags = @bitCast(payload[5]),
            .peer_window = std.mem.readInt(u16, payload[6..8], .little),
            .service_ack = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_data` (kind 32):
///   [4]  channel_id u32 LE
///   [N]  bytes      (raw data; LZ4 via header `Flags.compressed`)
pub const ChannelData = struct {
    channel_id: u32,
    bytes: []const u8,

    pub const fixed_size: usize = 4;

    pub fn encode(self: ChannelData, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.bytes.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        @memcpy(buf[fixed_size..], self.bytes);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelData {
        if (payload.len < fixed_size) return error.InvalidChannelDataPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .bytes = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_window` (kind 33):
///   [4]  channel_id   u32 LE
///   [4]  credit_bytes u32 LE (additional outbound credit, in bytes, cumulative)
pub const ChannelWindow = struct {
    channel_id: u32,
    credit_bytes: u32,

    pub const size: usize = 8;

    pub fn encode(self: ChannelWindow) [size]u8 {
        var buf: [size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        std.mem.writeInt(u32, buf[4..8], self.credit_bytes, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelWindow {
        if (payload.len < size) return error.InvalidChannelWindowPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .credit_bytes = std.mem.readInt(u32, payload[4..8], .little),
        };
    }
};

/// Payload for `channel_eof` (kind 34):
///   [4]  channel_id u32 LE
///
/// "Sender will send no more `channel_data` frames on this channel." The
/// peer may still send (full-duplex half-close). After both sides EOF,
/// either side may send Close.
pub const ChannelEof = struct {
    channel_id: u32,

    pub const size: usize = 4;

    pub fn encode(self: ChannelEof) [size]u8 {
        var buf: [size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelEof {
        if (payload.len < size) return error.InvalidChannelEofPayload;
        return .{ .channel_id = std.mem.readInt(u32, payload[0..4], .little) };
    }
};

/// Payload for `channel_close` (kind 35):
///   [4]  channel_id u32 LE
///   [1]  reason     u8 (ChannelCloseReason)
///   [N]  message    UTF-8 bytes (may be empty)
///
/// Unilateral and final; any further frames carrying this id are
/// discarded by the receiver.
pub const ChannelClose = struct {
    channel_id: u32,
    reason: ChannelCloseReason,
    message: []const u8 = "",

    pub const fixed_size: usize = 4 + 1;

    pub fn encode(self: ChannelClose, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.message.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.reason);
        @memcpy(buf[fixed_size..], self.message);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelClose {
        if (payload.len < fixed_size) return error.InvalidChannelClosePayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .reason = @enumFromInt(payload[4]),
            .message = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_control` (kind 36):
///   [4]  channel_id u32 LE
///   [1]  op         u8 (service-defined opcode)
///   [N]  op_payload bytes (service-defined; may be empty)
///
/// Ordered with `channel_data` on the same channel. Used for service-
/// specific signals like file-transfer progress, port-listener
/// pause/resume, TCP RST instead of FIN, etc.
pub const ChannelControl = struct {
    channel_id: u32,
    op: u8,
    op_payload: []const u8 = "",

    pub const fixed_size: usize = 4 + 1;

    pub fn encode(self: ChannelControl, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.op_payload.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = self.op;
        @memcpy(buf[fixed_size..], self.op_payload);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelControl {
        if (payload.len < fixed_size) return error.InvalidChannelControlPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .op = payload[4],
            .op_payload = payload[fixed_size..],
        };
    }
};

// =========================================================================
// Channel tests (Phase 6A.1 codec scaffold)
// =========================================================================

test "channel_open encode/parse roundtrip" {
    const testing = std.testing;
    const params = "host\x00\x50\x00"; // arbitrary opaque service params
    const open = ChannelOpen{
        .channel_id = 0x1234_5678,
        .service = .tcp_connect,
        .flags = .{ .compression = true },
        .initial_window = 128,
        .service_params = params,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelOpen.fixed_size + params.len, encoded.len);

    const parsed = try ChannelOpen.parse(encoded);
    try testing.expectEqual(@as(u32, 0x1234_5678), parsed.channel_id);
    try testing.expectEqual(ChannelService.tcp_connect, parsed.service);
    try testing.expect(parsed.flags.compression);
    try testing.expect(!parsed.flags.unidirectional_download);
    try testing.expectEqual(@as(u16, 128), parsed.initial_window);
    try testing.expectEqualSlices(u8, params, parsed.service_params);
}

test "channel_open encodes empty service_params" {
    const testing = std.testing;
    const open = ChannelOpen{
        .channel_id = 1,
        .service = .browser_proxy,
        .initial_window = 0,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelOpen.fixed_size, encoded.len);
    const parsed = try ChannelOpen.parse(encoded);
    try testing.expectEqual(@as(usize, 0), parsed.service_params.len);
    try testing.expectEqual(ChannelService.browser_proxy, parsed.service);
}

test "channel_open with daemon-direction high bit" {
    const testing = std.testing;
    const open = ChannelOpen{
        .channel_id = channel_id_daemon_bit | 7,
        .service = .tcp_connect,
        .initial_window = default_channel_window_units,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    const parsed = try ChannelOpen.parse(encoded);
    try testing.expect((parsed.channel_id & channel_id_daemon_bit) != 0);
    try testing.expectEqual(@as(u32, 7), parsed.channel_id & ~channel_id_daemon_bit);
}

test "channel_open rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidChannelOpenPayload, ChannelOpen.parse(&short));
}

test "channel_opened encode/parse roundtrip" {
    const testing = std.testing;
    const ack = "remote_port=8080";
    const opened = ChannelOpened{
        .channel_id = 0xDEAD_BEEF,
        .status = .ok,
        .flags = .{ .compression = true },
        .peer_window = 256,
        .service_ack = ack,
    };
    const encoded = try opened.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelOpened.parse(encoded);
    try testing.expectEqual(@as(u32, 0xDEAD_BEEF), parsed.channel_id);
    try testing.expectEqual(ChannelOpenStatus.ok, parsed.status);
    try testing.expect(parsed.flags.compression);
    try testing.expectEqual(@as(u16, 256), parsed.peer_window);
    try testing.expectEqualStrings(ack, parsed.service_ack);
}

test "channel_opened carries error message on failure" {
    const testing = std.testing;
    const msg = "dial failed: connection refused";
    const opened = ChannelOpened{
        .channel_id = 1,
        .status = .service_error,
        .service_ack = msg,
    };
    const encoded = try opened.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    const parsed = try ChannelOpened.parse(encoded);
    try testing.expectEqual(ChannelOpenStatus.service_error, parsed.status);
    try testing.expectEqualStrings(msg, parsed.service_ack);
}

test "channel_data encode/parse — empty payload" {
    const testing = std.testing;
    const data = ChannelData{ .channel_id = 42, .bytes = "" };
    const encoded = try data.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelData.fixed_size, encoded.len);
    const parsed = try ChannelData.parse(encoded);
    try testing.expectEqual(@as(u32, 42), parsed.channel_id);
    try testing.expectEqual(@as(usize, 0), parsed.bytes.len);
}

test "channel_data encode/parse — payload at max_payload boundary" {
    const testing = std.testing;
    // ChannelData payload = channel_id(4) + bytes. The header `len` field
    // caps the total frame payload at `max_payload`, so the data slice
    // can be up to max_payload - 4 bytes long. Pick a realistic large
    // size that still fits.
    const big = try testing.allocator.alloc(u8, max_payload - ChannelData.fixed_size);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);

    const data = ChannelData{ .channel_id = 1, .bytes = big };
    const encoded = try data.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(usize, max_payload), encoded.len);

    const parsed = try ChannelData.parse(encoded);
    try testing.expectEqual(@as(u32, 1), parsed.channel_id);
    try testing.expectEqualSlices(u8, big, parsed.bytes);
}

test "channel_window encode/parse roundtrip" {
    const testing = std.testing;
    const win = ChannelWindow{ .channel_id = 99, .credit_bytes = 65_536 };
    const encoded = win.encode();
    try testing.expectEqual(ChannelWindow.size, encoded.len);
    const parsed = try ChannelWindow.parse(&encoded);
    try testing.expectEqual(@as(u32, 99), parsed.channel_id);
    try testing.expectEqual(@as(u32, 65_536), parsed.credit_bytes);
}

test "channel_window rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidChannelWindowPayload, ChannelWindow.parse(&short));
}

test "channel_eof encode/parse roundtrip" {
    const testing = std.testing;
    const eof = ChannelEof{ .channel_id = 5 };
    const encoded = eof.encode();
    try testing.expectEqual(ChannelEof.size, encoded.len);
    const parsed = try ChannelEof.parse(&encoded);
    try testing.expectEqual(@as(u32, 5), parsed.channel_id);
}

test "channel_close encode/parse — with message" {
    const testing = std.testing;
    const msg = "window violation";
    const close = ChannelClose{
        .channel_id = 7,
        .reason = .peer_reset,
        .message = msg,
    };
    const encoded = try close.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelClose.parse(encoded);
    try testing.expectEqual(@as(u32, 7), parsed.channel_id);
    try testing.expectEqual(ChannelCloseReason.peer_reset, parsed.reason);
    try testing.expectEqualStrings(msg, parsed.message);
}

test "channel_close encode/parse — empty message" {
    const testing = std.testing;
    const close = ChannelClose{ .channel_id = 8, .reason = .normal };
    const encoded = try close.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelClose.fixed_size, encoded.len);
    const parsed = try ChannelClose.parse(encoded);
    try testing.expectEqual(ChannelCloseReason.normal, parsed.reason);
    try testing.expectEqual(@as(usize, 0), parsed.message.len);
}

test "channel_control encode/parse roundtrip" {
    const testing = std.testing;
    const op_payload = "progress=512";
    const ctrl = ChannelControl{
        .channel_id = 11,
        .op = 1,
        .op_payload = op_payload,
    };
    const encoded = try ctrl.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelControl.parse(encoded);
    try testing.expectEqual(@as(u32, 11), parsed.channel_id);
    try testing.expectEqual(@as(u8, 1), parsed.op);
    try testing.expectEqualStrings(op_payload, parsed.op_payload);
}

test "channel frames roundtrip through writeFrame / readHeader" {
    // Ensures the new kinds work end-to-end with the existing frame I/O
    // helpers — no behavior change to the frame layer.
    const testing = std.testing;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);

    const win = ChannelWindow{ .channel_id = 17, .credit_bytes = 4096 };
    const win_bytes = win.encode();
    try writeFrame(buf.writer(testing.allocator), .channel_window, 0, &win_bytes);

    var stream = std.io.fixedBufferStream(buf.items);
    const header = try readHeader(stream.reader());
    try testing.expectEqual(Kind.channel_window, header.kind);
    try testing.expectEqual(@as(u16, 0), header.target); // channel_id lives in payload
    try testing.expectEqual(@as(u32, ChannelWindow.size), header.len);

    const payload = try readPayloadAlloc(testing.allocator, stream.reader(), header);
    defer testing.allocator.free(payload);
    const parsed = try ChannelWindow.parse(payload);
    try testing.expectEqual(@as(u32, 17), parsed.channel_id);
    try testing.expectEqual(@as(u32, 4096), parsed.credit_bytes);
}
