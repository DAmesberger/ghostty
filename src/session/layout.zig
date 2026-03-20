//! Layout serialization for multi-tab, multi-surface session groups.
//!
//! Binary format v1 (little-endian):
//!   [2] version = 1
//!   [2] tab_count
//!   per tab:
//!     [2] node_count
//!     [2] zoomed_handle (0xFFFF = none)
//!     [2] title_len (0 = no override)
//!     [title_len] title_override bytes (UTF-8)
//!     per node:
//!       [1] tag: 0=leaf, 1=split
//!       leaf:  [16] surface_id (UUID, binary)
//!       split: [1] direction (0=horiz, 1=vert), [2] ratio (f16 bits), [2] left_idx, [2] right_idx

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

pub const TabInfo = struct {
    nodes: []NodeInfo,
    zoomed: ?u16,
    title_override: ?[]const u8,
};

pub const WindowLayout = struct {
    tabs: []TabInfo,

    pub fn deinit(self: *WindowLayout, alloc: Allocator) void {
        for (self.tabs) |*tab| {
            alloc.free(tab.nodes);
            if (tab.title_override) |t| alloc.free(t);
        }
        alloc.free(self.tabs);
    }
};

pub fn serialize(alloc: Allocator, layout: WindowLayout) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // Global header: version + tab_count
    var header: [4]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], layout_version, .little);
    std.mem.writeInt(u16, header[2..4], @intCast(layout.tabs.len), .little);
    try buf.appendSlice(alloc, &header);

    // Per-tab
    for (layout.tabs) |tab| {
        // Tab header: node_count + zoomed + title_len
        var tab_header: [6]u8 = undefined;
        std.mem.writeInt(u16, tab_header[0..2], @intCast(tab.nodes.len), .little);
        std.mem.writeInt(u16, tab_header[2..4], tab.zoomed orelse no_zoomed, .little);
        const title_len: u16 = if (tab.title_override) |t| @intCast(t.len) else 0;
        std.mem.writeInt(u16, tab_header[4..6], title_len, .little);
        try buf.appendSlice(alloc, &tab_header);

        // Title bytes
        if (tab.title_override) |t| {
            try buf.appendSlice(alloc, t);
        }

        // Nodes
        for (tab.nodes) |node| {
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
    }

    return buf.toOwnedSlice(alloc);
}

pub fn deserialize(alloc: Allocator, blob: []const u8) !WindowLayout {
    if (blob.len < 4) return error.InvalidLayout;

    const version = std.mem.readInt(u16, blob[0..2], .little);
    if (version != layout_version) return error.UnsupportedLayoutVersion;

    const tab_count = std.mem.readInt(u16, blob[2..4], .little);

    const tabs = try alloc.alloc(TabInfo, tab_count);
    errdefer {
        for (tabs[0..tab_count]) |*tab| {
            if (@intFromPtr(tab.nodes.ptr) != 0 and tab.nodes.len > 0) alloc.free(tab.nodes);
            if (tab.title_override) |t| alloc.free(t);
        }
        alloc.free(tabs);
    }

    var offset: usize = 4;

    for (0..tab_count) |tab_i| {
        if (offset + 6 > blob.len) return error.InvalidLayout;

        const node_count = std.mem.readInt(u16, blob[offset..][0..2], .little);
        offset += 2;
        const zoomed_raw = std.mem.readInt(u16, blob[offset..][0..2], .little);
        offset += 2;
        const title_len = std.mem.readInt(u16, blob[offset..][0..2], .little);
        offset += 2;

        const zoomed: ?u16 = if (zoomed_raw == no_zoomed) null else zoomed_raw;

        // Title
        const title_override: ?[]const u8 = if (title_len > 0) blk: {
            if (offset + title_len > blob.len) return error.InvalidLayout;
            const title = try alloc.dupe(u8, blob[offset..][0..title_len]);
            offset += title_len;
            break :blk title;
        } else null;
        errdefer if (title_override) |t| alloc.free(t);

        // Nodes
        const nodes = try alloc.alloc(NodeInfo, node_count);
        errdefer alloc.free(nodes);

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

        tabs[tab_i] = .{
            .nodes = nodes,
            .zoomed = zoomed,
            .title_override = title_override,
        };
    }

    return .{ .tabs = tabs };
}

test "roundtrip single tab single leaf" {
    const alloc = std.testing.allocator;

    const uuid = shared.generateUuid();
    const layout: WindowLayout = .{
        .tabs = @constCast(&[_]TabInfo{
            .{
                .nodes = @constCast(&[_]NodeInfo{
                    .{ .leaf = .{ .surface_id = uuid } },
                }),
                .zoomed = null,
                .title_override = null,
            },
        }),
    };

    const blob = try serialize(alloc, layout);
    defer alloc.free(blob);

    // Header(4) + tab_header(6) + leaf(1 tag + 16 uuid) = 27 bytes
    try std.testing.expectEqual(@as(usize, 27), blob.len);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed.tabs.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.tabs[0].nodes.len);
    try std.testing.expectEqual(@as(?u16, null), parsed.tabs[0].zoomed);
    try std.testing.expect(parsed.tabs[0].title_override == null);
    try std.testing.expectEqualSlices(u8, &uuid, &parsed.tabs[0].nodes[0].leaf.surface_id);
}

test "roundtrip multi-tab with titles and splits" {
    const alloc = std.testing.allocator;

    const uuid_a: Uuid = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const uuid_b: Uuid = .{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    const uuid_c: Uuid = .{0xcc} ** 16;

    const layout: WindowLayout = .{
        .tabs = @constCast(&[_]TabInfo{
            .{
                .nodes = @constCast(&[_]NodeInfo{
                    .{ .split = .{ .direction = .horizontal, .ratio = @as(f16, 0.5), .left = 1, .right = 2 } },
                    .{ .leaf = .{ .surface_id = uuid_a } },
                    .{ .leaf = .{ .surface_id = uuid_b } },
                }),
                .zoomed = null,
                .title_override = "Tab One",
            },
            .{
                .nodes = @constCast(&[_]NodeInfo{
                    .{ .leaf = .{ .surface_id = uuid_c } },
                }),
                .zoomed = null,
                .title_override = null,
            },
        }),
    };

    const blob = try serialize(alloc, layout);
    defer alloc.free(blob);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.tabs.len);

    // Tab 0: split with 2 leaves and a title
    try std.testing.expectEqual(@as(usize, 3), parsed.tabs[0].nodes.len);
    try std.testing.expectEqual(@as(?u16, null), parsed.tabs[0].zoomed);
    try std.testing.expectEqualStrings("Tab One", parsed.tabs[0].title_override.?);
    try std.testing.expectEqual(Direction.horizontal, parsed.tabs[0].nodes[0].split.direction);
    try std.testing.expectEqualSlices(u8, &uuid_a, &parsed.tabs[0].nodes[1].leaf.surface_id);
    try std.testing.expectEqualSlices(u8, &uuid_b, &parsed.tabs[0].nodes[2].leaf.surface_id);

    // Tab 1: single leaf, no title
    try std.testing.expectEqual(@as(usize, 1), parsed.tabs[1].nodes.len);
    try std.testing.expect(parsed.tabs[1].title_override == null);
    try std.testing.expectEqualSlices(u8, &uuid_c, &parsed.tabs[1].nodes[0].leaf.surface_id);
}

test "roundtrip with zoomed" {
    const alloc = std.testing.allocator;

    const uuid_a: Uuid = .{0xaa} ** 16;
    const uuid_b: Uuid = .{0xbb} ** 16;

    const layout: WindowLayout = .{
        .tabs = @constCast(&[_]TabInfo{
            .{
                .nodes = @constCast(&[_]NodeInfo{
                    .{ .split = .{ .direction = .vertical, .ratio = @as(f16, 0.3), .left = 1, .right = 2 } },
                    .{ .leaf = .{ .surface_id = uuid_a } },
                    .{ .leaf = .{ .surface_id = uuid_b } },
                }),
                .zoomed = 1,
                .title_override = null,
            },
        }),
    };

    const blob = try serialize(alloc, layout);
    defer alloc.free(blob);

    var parsed = try deserialize(alloc, blob);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(?u16, 1), parsed.tabs[0].zoomed);
}

test "compact size multi-tab" {
    const alloc = std.testing.allocator;

    // 2 tabs: tab0 has 4-surface tree (3 splits + 4 leaves), tab1 has 1 leaf
    const layout: WindowLayout = .{
        .tabs = @constCast(&[_]TabInfo{
            .{
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
                .title_override = null,
            },
            .{
                .nodes = @constCast(&[_]NodeInfo{
                    .{ .leaf = .{ .surface_id = .{0x05} ** 16 } },
                }),
                .zoomed = null,
                .title_override = "ssh",
            },
        }),
    };

    const blob = try serialize(alloc, layout);
    defer alloc.free(blob);

    // Global header: 4 bytes
    // Tab 0: tab_header(6) + 3 splits(3*8=24) + 4 leaves(4*17=68) = 98
    // Tab 1: tab_header(6) + title("ssh"=3) + 1 leaf(17) = 26
    // Total: 4 + 98 + 26 = 128
    try std.testing.expectEqual(@as(usize, 128), blob.len);
}

test "invalid blob" {
    const alloc = std.testing.allocator;

    // Too short
    try std.testing.expectError(error.InvalidLayout, deserialize(alloc, ""));
    try std.testing.expectError(error.InvalidLayout, deserialize(alloc, &.{ 0, 0 }));

    // Wrong version
    var bad_version: [4]u8 = undefined;
    std.mem.writeInt(u16, bad_version[0..2], 99, .little);
    std.mem.writeInt(u16, bad_version[2..4], 0, .little);
    try std.testing.expectError(error.UnsupportedLayoutVersion, deserialize(alloc, &bad_version));
}
