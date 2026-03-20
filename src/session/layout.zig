//! Layout serialization for multi-surface session groups.
//!
//! Binary format (little-endian):
//!   [2] version
//!   [2] node_count
//!   [2] zoomed_handle (0xFFFF = none)
//!   per node:
//!     [1] tag: 0=leaf, 1=split
//!     leaf:  [16] surface_id (UUID, binary)
//!     split: [1] direction (0=horiz, 1=vert), [2] ratio (f16 bits), [2] left_idx, [2] right_idx
//!
//! Leaf nodes are 17 bytes (tag + UUID). Split nodes are 8 bytes.
//! A 4-surface tree (3 splits + 4 leaves) is 6 + 3*8 + 4*17 = 98 bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

const layout_version: u16 = 1;
const no_zoomed: u16 = 0xFFFF;

pub const Uuid = shared.Uuid;

pub const Direction = enum(u8) {
    horizontal = 0,
    vertical = 1,
};

pub const NodeInfo = union(enum) {
    leaf: Leaf,
    split: Split,

    pub const Leaf = struct {
        surface_id: Uuid,
    };

    pub const Split = struct {
        direction: Direction,
        ratio: f16,
        left: u16,
        right: u16,
    };
};

pub const LayoutInfo = struct {
    nodes: []NodeInfo,
    zoomed: ?u16,

    pub fn deinit(self: *LayoutInfo, alloc: Allocator) void {
        alloc.free(self.nodes);
    }
};

pub fn serialize(alloc: Allocator, info: LayoutInfo) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // Header
    var header: [6]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], layout_version, .little);
    std.mem.writeInt(u16, header[2..4], @intCast(info.nodes.len), .little);
    std.mem.writeInt(u16, header[4..6], info.zoomed orelse no_zoomed, .little);
    try buf.appendSlice(alloc, &header);

    // Nodes
    for (info.nodes) |node| {
        switch (node) {
            .leaf => |l| {
                try buf.append(alloc, 0); // tag
                try buf.appendSlice(alloc, &l.surface_id);
            },
            .split => |s| {
                var node_buf: [8]u8 = undefined;
                node_buf[0] = 1; // tag
                node_buf[1] = @intFromEnum(s.direction);
                std.mem.writeInt(u16, node_buf[2..4], @bitCast(s.ratio), .little);
                std.mem.writeInt(u16, node_buf[4..6], s.left, .little);
                std.mem.writeInt(u16, node_buf[6..8], s.right, .little);
                try buf.appendSlice(alloc, &node_buf);
            },
        }
    }

    return buf.toOwnedSlice(alloc);
}

pub fn deserialize(alloc: Allocator, blob: []const u8) !LayoutInfo {
    if (blob.len < 6) return error.InvalidLayout;

    const version = std.mem.readInt(u16, blob[0..2], .little);
    if (version != layout_version) return error.UnsupportedLayoutVersion;

    const node_count = std.mem.readInt(u16, blob[2..4], .little);
    const zoomed_raw = std.mem.readInt(u16, blob[4..6], .little);
    const zoomed: ?u16 = if (zoomed_raw == no_zoomed) null else zoomed_raw;

    const nodes = try alloc.alloc(NodeInfo, node_count);
    errdefer alloc.free(nodes);

    var offset: usize = 6;
    for (0..node_count) |i| {
        if (offset >= blob.len) return error.InvalidLayout;
        const tag = blob[offset];
        offset += 1;

        switch (tag) {
            0 => { // leaf: 16-byte UUID
                if (offset + 16 > blob.len) return error.InvalidLayout;
                nodes[i] = .{ .leaf = .{ .surface_id = blob[offset..][0..16].* } };
                offset += 16;
            },
            1 => { // split
                if (offset + 7 > blob.len) return error.InvalidLayout;
                const dir_byte = blob[offset];
                offset += 1;
                const ratio_bits = std.mem.readInt(u16, blob[offset..][0..2], .little);
                offset += 2;
                const left = std.mem.readInt(u16, blob[offset..][0..2], .little);
                offset += 2;
                const right = std.mem.readInt(u16, blob[offset..][0..2], .little);
                offset += 2;
                nodes[i] = .{ .split = .{
                    .direction = std.meta.intToEnum(Direction, dir_byte) catch return error.InvalidLayout,
                    .ratio = @bitCast(ratio_bits),
                    .left = left,
                    .right = right,
                } };
            },
            else => return error.InvalidLayout,
        }
    }

    return .{
        .nodes = nodes,
        .zoomed = zoomed,
    };
}

test "roundtrip single leaf" {
    const alloc = std.testing.allocator;

    const uuid = shared.generateUuid();
    const info: LayoutInfo = .{
        .nodes = @constCast(&[_]NodeInfo{
            .{ .leaf = .{ .surface_id = uuid } },
        }),
        .zoomed = null,
    };

    const blob = try serialize(alloc, info);
    defer alloc.free(blob);

    // Header(6) + leaf(1 tag + 16 uuid) = 23 bytes
    try std.testing.expectEqual(@as(usize, 23), blob.len);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed.nodes.len);
    try std.testing.expectEqual(@as(?u16, null), parsed.zoomed);
    try std.testing.expectEqualSlices(u8, &uuid, &parsed.nodes[0].leaf.surface_id);
}

test "roundtrip split tree" {
    const alloc = std.testing.allocator;

    const uuid_a: Uuid = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const uuid_b: Uuid = .{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

    const info: LayoutInfo = .{
        .nodes = @constCast(&[_]NodeInfo{
            .{ .split = .{ .direction = .horizontal, .ratio = @as(f16, 0.5), .left = 1, .right = 2 } },
            .{ .leaf = .{ .surface_id = uuid_a } },
            .{ .leaf = .{ .surface_id = uuid_b } },
        }),
        .zoomed = null,
    };

    const blob = try serialize(alloc, info);
    defer alloc.free(blob);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 3), parsed.nodes.len);
    try std.testing.expectEqual(Direction.horizontal, parsed.nodes[0].split.direction);
    try std.testing.expect(parsed.nodes[0].split.ratio == @as(f16, 0.5));
    try std.testing.expectEqual(@as(u16, 1), parsed.nodes[0].split.left);
    try std.testing.expectEqual(@as(u16, 2), parsed.nodes[0].split.right);
    try std.testing.expectEqualSlices(u8, &uuid_a, &parsed.nodes[1].leaf.surface_id);
    try std.testing.expectEqualSlices(u8, &uuid_b, &parsed.nodes[2].leaf.surface_id);
}

test "roundtrip with zoomed" {
    const alloc = std.testing.allocator;

    const uuid_a: Uuid = .{0xaa} ** 16;
    const uuid_b: Uuid = .{0xbb} ** 16;

    const info: LayoutInfo = .{
        .nodes = @constCast(&[_]NodeInfo{
            .{ .split = .{ .direction = .vertical, .ratio = @as(f16, 0.3), .left = 1, .right = 2 } },
            .{ .leaf = .{ .surface_id = uuid_a } },
            .{ .leaf = .{ .surface_id = uuid_b } },
        }),
        .zoomed = 1,
    };

    const blob = try serialize(alloc, info);
    defer alloc.free(blob);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(?u16, 1), parsed.zoomed);
}

test "compact size" {
    const alloc = std.testing.allocator;

    // 4-surface tree: 3 splits + 4 leaves
    const info: LayoutInfo = .{
        .nodes = @constCast(&[_]NodeInfo{
            .{ .split = .{ .direction = .horizontal, .ratio = @as(f16, 0.5), .left = 1, .right = 2 } },
            .{ .split = .{ .direction = .vertical, .ratio = @as(f16, 0.5), .left = 3, .right = 4 } },
            .{ .split = .{ .direction = .vertical, .ratio = @as(f16, 0.5), .left = 5, .right = 6 } },
            .{ .leaf = .{ .surface_id = .{0x01} ** 16 } },
            .{ .leaf = .{ .surface_id = .{0x02} ** 16 } },
            .{ .leaf = .{ .surface_id = .{0x03} ** 16 } },
            .{ .leaf = .{ .surface_id = .{0x04} ** 16 } },
        }),
        .zoomed = null,
    };

    const blob = try serialize(alloc, info);
    defer alloc.free(blob);

    // Header: 6 bytes
    // 3 splits: 3 * 8 = 24 bytes
    // 4 leaves: 4 * 17 = 68 bytes
    // Total: 98 bytes
    try std.testing.expectEqual(@as(usize, 98), blob.len);
}

test "invalid blob" {
    const alloc = std.testing.allocator;

    // Too short
    try std.testing.expectError(error.InvalidLayout, deserialize(alloc, ""));
    try std.testing.expectError(error.InvalidLayout, deserialize(alloc, &.{ 0, 0 }));

    // Wrong version
    var bad_version: [6]u8 = undefined;
    std.mem.writeInt(u16, bad_version[0..2], 99, .little);
    std.mem.writeInt(u16, bad_version[2..4], 0, .little);
    std.mem.writeInt(u16, bad_version[4..6], 0xFFFF, .little);
    try std.testing.expectError(error.UnsupportedLayoutVersion, deserialize(alloc, &bad_version));
}
