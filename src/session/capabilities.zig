const std = @import("std");
const Allocator = std.mem.Allocator;

const frame = @import("frame.zig");
const protocol_version = frame.protocol_version;
const max_payload = frame.max_payload;

const channel_frames = @import("channel_frames.zig");
const ChannelService = channel_frames.ChannelService;
const default_channel_window_units = channel_frames.default_channel_window_units;
const max_channel_window_units = channel_frames.max_channel_window_units;

// =========================================================================
// Capabilities frame (kind 27)
// =========================================================================
//
// Sent by both daemon and client immediately after the banner exchange, so
// each side can negotiate which channel services / features the other
// supports. The effective set is the intersection. Channels whose service
// id is not advertised in the peer's Capabilities frame are rejected at
// open time with status=service_not_supported.

/// Identifies a single channel service in a Capabilities frame.
pub const CapabilityService = struct {
    /// Service id (matches ChannelOpen.service_id below).
    id: u8,
    /// Human-readable service name, e.g. "tcp_connect", "browser_proxy".
    /// Used for diagnostics and as the lookup key for the `custom` service.
    name: []const u8,
};

/// Compression algorithm identifier for per-channel compression negotiation.
/// 0 = none, 1 = LZ4 (currently the only supported algo). Future algos may
/// add values without bumping the protocol version, gated by the
/// Capabilities exchange.
pub const CompressionAlgo = enum(u8) {
    none = 0,
    lz4 = 1,
    _,
};

/// Payload for `capabilities` (kind 27):
///   [2]   protocol_version u16 LE
///   [4]   feature_bits     u32 LE
///   [2]   service_count    u16 LE
///   per service:
///     [1] service_id       u8
///     [2] name_len         u16 LE
///     [N] name bytes (UTF-8)
///   [2]   default_window   u16 LE (in 4 KiB units; 0 = use protocol default)
///   [2]   max_window       u16 LE (in 4 KiB units; cap on opener-requested window)
///   [2]   max_payload      u16 LE (in KiB; e.g. 256 for the current 256 KiB cap)
///   [1]   compression_algo u8
pub const Capabilities = struct {
    protocol_version: u16,
    feature_bits: u32 = 0,
    services: []const CapabilityService,
    default_window: u16 = 0,
    max_window: u16 = 0,
    max_payload_kib: u16 = 0,
    compression_algo: CompressionAlgo = .lz4,

    /// Fixed-size bytes excluding the variable services list:
    /// protocol_version(2) + feature_bits(4) + service_count(2) +
    /// default_window(2) + max_window(2) + max_payload(2) + compression_algo(1).
    pub const fixed_size: usize = 2 + 4 + 2 + 2 + 2 + 2 + 1;

    /// Per-service fixed bytes (excluding name): id(1) + name_len(2).
    pub const service_fixed_size: usize = 1 + 2;

    pub fn encode(self: Capabilities, alloc: Allocator) ![]u8 {
        var total: usize = fixed_size;
        for (self.services) |s| {
            total += service_fixed_size + s.name.len;
        }
        const buf = try alloc.alloc(u8, total);
        var off: usize = 0;
        std.mem.writeInt(u16, buf[off..][0..2], self.protocol_version, .little);
        off += 2;
        std.mem.writeInt(u32, buf[off..][0..4], self.feature_bits, .little);
        off += 4;
        std.mem.writeInt(u16, buf[off..][0..2], @intCast(self.services.len), .little);
        off += 2;
        for (self.services) |s| {
            buf[off] = s.id;
            off += 1;
            std.mem.writeInt(u16, buf[off..][0..2], @intCast(s.name.len), .little);
            off += 2;
            @memcpy(buf[off..][0..s.name.len], s.name);
            off += s.name.len;
        }
        std.mem.writeInt(u16, buf[off..][0..2], self.default_window, .little);
        off += 2;
        std.mem.writeInt(u16, buf[off..][0..2], self.max_window, .little);
        off += 2;
        std.mem.writeInt(u16, buf[off..][0..2], self.max_payload_kib, .little);
        off += 2;
        buf[off] = @intFromEnum(self.compression_algo);
        return buf;
    }

    /// Parses the header + services list into a borrowed view. The returned
    /// `services` slice points into a freshly-allocated array owned by the
    /// caller (free via `alloc.free`); each `service.name` borrows from
    /// `payload`.
    pub fn parse(alloc: Allocator, payload: []const u8) !Capabilities {
        // Minimum without any services: fixed_size, with service_count = 0.
        if (payload.len < fixed_size) return error.InvalidCapabilitiesPayload;
        var off: usize = 0;
        const protocol_v = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const feature_bits = std.mem.readInt(u32, payload[off..][0..4], .little);
        off += 4;
        const service_count = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;

        const services = try alloc.alloc(CapabilityService, service_count);
        errdefer alloc.free(services);

        for (0..service_count) |i| {
            if (off + service_fixed_size > payload.len) return error.InvalidCapabilitiesPayload;
            const id = payload[off];
            off += 1;
            const name_len = std.mem.readInt(u16, payload[off..][0..2], .little);
            off += 2;
            if (name_len > payload.len - off) return error.InvalidCapabilitiesPayload;
            services[i] = .{ .id = id, .name = payload[off..][0..name_len] };
            off += name_len;
        }

        // Trailing fixed fields: default_window(2) + max_window(2) +
        // max_payload(2) + compression_algo(1) = 7 bytes.
        if (payload.len - off < 7) return error.InvalidCapabilitiesPayload;
        const default_window = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const max_window = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const max_payload_kib = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const compression_algo: CompressionAlgo = @enumFromInt(payload[off]);

        return .{
            .protocol_version = protocol_v,
            .feature_bits = feature_bits,
            .services = services,
            .default_window = default_window,
            .max_window = max_window,
            .max_payload_kib = max_payload_kib,
            .compression_algo = compression_algo,
        };
    }
};

// =========================================================================
// Capabilities tests (Phase 6A.1 codec scaffold)
// =========================================================================

test "capabilities encode/parse — empty services list" {
    const testing = std.testing;
    const caps = Capabilities{
        .protocol_version = protocol_version,
        .services = &.{},
        .default_window = default_channel_window_units,
        .max_window = max_channel_window_units,
        .max_payload_kib = max_payload / 1024,
        .compression_algo = .lz4,
    };
    const encoded = try caps.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(Capabilities.fixed_size, encoded.len);

    const parsed = try Capabilities.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed.services);
    try testing.expectEqual(@as(u16, protocol_version), parsed.protocol_version);
    try testing.expectEqual(@as(u32, 0), parsed.feature_bits);
    try testing.expectEqual(@as(usize, 0), parsed.services.len);
    try testing.expectEqual(default_channel_window_units, parsed.default_window);
    try testing.expectEqual(max_channel_window_units, parsed.max_window);
    try testing.expectEqual(@as(u16, max_payload / 1024), parsed.max_payload_kib);
    try testing.expectEqual(CompressionAlgo.lz4, parsed.compression_algo);
}

test "capabilities encode/parse — full service catalog" {
    const testing = std.testing;
    const services = [_]CapabilityService{
        .{ .id = @intFromEnum(ChannelService.tcp_connect), .name = "tcp_connect" },
        .{ .id = @intFromEnum(ChannelService.port_listener), .name = "port_listener" },
        .{ .id = @intFromEnum(ChannelService.file_transfer), .name = "file_transfer" },
        .{ .id = @intFromEnum(ChannelService.browser_proxy), .name = "browser_proxy" },
        .{ .id = @intFromEnum(ChannelService.process_exec), .name = "process_exec" },
        .{ .id = @intFromEnum(ChannelService.custom), .name = "custom" },
    };
    const caps = Capabilities{
        .protocol_version = protocol_version,
        .feature_bits = 0b101,
        .services = &services,
        .default_window = default_channel_window_units,
        .max_window = max_channel_window_units,
        .max_payload_kib = 256,
        .compression_algo = .lz4,
    };
    const encoded = try caps.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Capabilities.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed.services);
    try testing.expectEqual(@as(usize, services.len), parsed.services.len);
    try testing.expectEqual(@as(u32, 0b101), parsed.feature_bits);
    for (services, parsed.services) |orig, got| {
        try testing.expectEqual(orig.id, got.id);
        try testing.expectEqualStrings(orig.name, got.name);
    }
}

test "capabilities rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidCapabilitiesPayload, Capabilities.parse(testing.allocator, &short));
}

test "capabilities rejects truncated service name" {
    const testing = std.testing;
    // Manually craft: protocol_version=1, feature_bits=0, service_count=1,
    // service_id=1, name_len=10 — but supply only 2 bytes of name.
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &.{ 1, 0 }); // protocol_version
    try buf.appendSlice(testing.allocator, &.{ 0, 0, 0, 0 }); // feature_bits
    try buf.appendSlice(testing.allocator, &.{ 1, 0 }); // service_count = 1
    try buf.appendSlice(testing.allocator, &.{1}); // service_id = 1
    try buf.appendSlice(testing.allocator, &.{ 10, 0 }); // name_len = 10
    try buf.appendSlice(testing.allocator, "ab"); // only 2 bytes of name
    try testing.expectError(error.InvalidCapabilitiesPayload, Capabilities.parse(testing.allocator, buf.items));
}
