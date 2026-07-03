const std = @import("std");
const Allocator = std.mem.Allocator;

const Uuid = @import("shared.zig").Uuid;
const uuid_size = 16;

// =========================================================================
// Multi-viewer: size mode and viewer state
// =========================================================================

pub const SizeMode = enum(u8) {
    smallest_wins = 0,
    leader_wins = 1,
};

pub const ViewerStateReason = enum(u8) {
    welcome = 0, // Sent to a joining viewer with full roster
    join = 1, // A new viewer joined
    leave = 2, // A viewer left
    control_change = 3, // Active controller changed (someone typed)
    size_change = 4, // Effective PTY size changed
    mode_change = 5, // Size mode changed
    name_change = 6, // Session label or color changed
};

/// Single viewer entry within a ViewerState payload.
pub const ViewerEntry = struct {
    id: Uuid,
    label: []const u8,
    is_controller: bool,
    rows: u16,
    cols: u16,
};

/// Payload for `viewer_state` (kind 20).
/// Sent to viewers on roster changes. Includes authoritative session state.
pub const ViewerState = struct {
    reason: ViewerStateReason,
    size_mode: SizeMode,
    controller_id: Uuid,
    effective_rows: u16,
    effective_cols: u16,
    session_color: i8 = -1,
    session_label: []const u8 = "",
    viewers: []const ViewerEntry,

    /// Fixed header: reason(1) + size_mode(1) + controller_id(16) + rows(2) + cols(2) +
    ///   session_color(1) + label_len(2) + viewer_count(2) = 27
    pub const fixed_size = 27;
    /// Per viewer: id(16) + label_len(2) + is_controller(1) + rows(2) + cols(2) = 23 + label
    pub const viewer_fixed_size = 23;

    pub fn encode(self: ViewerState, alloc: Allocator) ![]u8 {
        var total: usize = fixed_size + self.session_label.len;
        for (self.viewers) |v| {
            total += viewer_fixed_size + v.label.len;
        }
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.reason);
        buf[1] = @intFromEnum(self.size_mode);
        @memcpy(buf[2..18], &self.controller_id);
        std.mem.writeInt(u16, buf[18..20], self.effective_rows, .little);
        std.mem.writeInt(u16, buf[20..22], self.effective_cols, .little);
        // Session color + label
        buf[22] = @bitCast(self.session_color);
        std.mem.writeInt(u16, buf[23..25], @intCast(self.session_label.len), .little);
        // Viewer count
        std.mem.writeInt(u16, buf[25..27], @intCast(self.viewers.len), .little);

        // Session label (variable length, before viewer entries)
        var off: usize = fixed_size;
        @memcpy(buf[off..][0..self.session_label.len], self.session_label);
        off += self.session_label.len;

        for (self.viewers) |v| {
            @memcpy(buf[off..][0..uuid_size], &v.id);
            off += uuid_size;
            std.mem.writeInt(u16, buf[off..][0..2], @intCast(v.label.len), .little);
            off += 2;
            buf[off] = if (v.is_controller) 1 else 0;
            off += 1;
            std.mem.writeInt(u16, buf[off..][0..2], v.rows, .little);
            off += 2;
            std.mem.writeInt(u16, buf[off..][0..2], v.cols, .little);
            off += 2;
            @memcpy(buf[off..][0..v.label.len], v.label);
            off += v.label.len;
        }
        return buf;
    }

    pub fn parseHeader(payload: []const u8) !struct {
        reason: ViewerStateReason,
        size_mode: SizeMode,
        controller_id: Uuid,
        effective_rows: u16,
        effective_cols: u16,
        session_color: i8,
        session_label: []const u8,
        viewer_count: u16,
        remaining: []const u8,
    } {
        if (payload.len < fixed_size) return error.InvalidViewerStatePayload;
        const session_color: i8 = @bitCast(payload[22]);
        const label_len = std.mem.readInt(u16, payload[23..25], .little);
        const viewer_count = std.mem.readInt(u16, payload[25..27], .little);
        const label_end = fixed_size + label_len;
        if (payload.len < label_end) return error.InvalidViewerStatePayload;
        // Each viewer needs at least viewer_fixed_size bytes (label is variable on top).
        if (payload.len - label_end < @as(usize, viewer_count) * viewer_fixed_size)
            return error.InvalidViewerStatePayload;
        return .{
            .reason = std.meta.intToEnum(ViewerStateReason, payload[0]) catch return error.InvalidViewerStatePayload,
            .size_mode = std.meta.intToEnum(SizeMode, payload[1]) catch return error.InvalidViewerStatePayload,
            .controller_id = payload[2..18].*,
            .effective_rows = std.mem.readInt(u16, payload[18..20], .little),
            .effective_cols = std.mem.readInt(u16, payload[20..22], .little),
            .session_color = session_color,
            .session_label = payload[fixed_size..label_end],
            .viewer_count = viewer_count,
            .remaining = payload[label_end..],
        };
    }
};

/// Payload for `size_mode_change` (kind 21): single byte.
pub const SizeModeChange = struct {
    mode: SizeMode,

    pub fn encode(self: SizeModeChange) [1]u8 {
        return .{@intFromEnum(self.mode)};
    }

    pub fn parse(payload: []const u8) !SizeModeChange {
        if (payload.len < 1) return error.InvalidSizeModePayload;
        return .{
            .mode = std.meta.intToEnum(SizeMode, payload[0]) catch return error.InvalidSizeModePayload,
        };
    }
};

/// Payload for `session_meta` (kind 26): update session label + color atomically.
pub const SessionMeta = struct {
    group_id: Uuid,
    color: i8,
    label: []const u8,

    pub const min_size = uuid_size + 1 + 2; // group_id(16) + color(1) + label_len(2)

    pub fn encode(self: SessionMeta, alloc: Allocator) ![]u8 {
        const total = min_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        @memcpy(buf[0..uuid_size], &self.group_id);
        buf[uuid_size] = @bitCast(self.color);
        std.mem.writeInt(u16, buf[uuid_size + 1 ..][0..2], @intCast(self.label.len), .little);
        @memcpy(buf[min_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !SessionMeta {
        if (payload.len < min_size) return error.InvalidSessionMetaPayload;
        const label_len = std.mem.readInt(u16, payload[uuid_size + 1 ..][0..2], .little);
        if (payload.len < min_size + label_len) return error.InvalidSessionMetaPayload;
        return .{
            .group_id = payload[0..uuid_size].*,
            .color = @bitCast(payload[uuid_size]),
            .label = payload[min_size..][0..label_len],
        };
    }
};

// =========================================================================
// List response — structured binary (replaces per-entry text frames)
// =========================================================================

pub const ListStatus = enum(u8) {
    detached = 0,
    attached = 1,
    dead = 2,
};

/// Single entry in a list_response.
pub const ListEntry = struct {
    group_id: Uuid,
    status: ListStatus,
    surface_count: u16,
    alive_count: u16,
    created_at: i64,
    label: []const u8,
    /// Session color badge: -1 = none, 0-7 = color index.
    session_color: i8 = -1,
};

/// Payload for `list_response`:
///   [2] entry_count (u16 LE)
///   per entry:
///     [16] group_id
///     [1]  status
///     [2]  surface_count (u16 LE)
///     [2]  alive_count (u16 LE)
///     [8]  created_at (i64 LE)
///     [1]  session_color (i8, -1 = none)
///     [2]  label_len (u16 LE)
///     [label_len] label
pub const ListResponse = struct {
    entries: []const ListEntry,

    pub const entry_header_size = uuid_size + 1 + 2 + 2 + 8 + 1 + 2;

    pub fn encode(self: ListResponse, alloc: Allocator) ![]u8 {
        var total: usize = 2; // entry_count
        for (self.entries) |e| {
            total += entry_header_size + e.label.len;
        }
        const buf = try alloc.alloc(u8, total);
        std.mem.writeInt(u16, buf[0..2], @intCast(self.entries.len), .little);
        var offset: usize = 2;
        for (self.entries) |e| {
            @memcpy(buf[offset..][0..uuid_size], &e.group_id);
            offset += uuid_size;
            buf[offset] = @intFromEnum(e.status);
            offset += 1;
            std.mem.writeInt(u16, buf[offset..][0..2], e.surface_count, .little);
            offset += 2;
            std.mem.writeInt(u16, buf[offset..][0..2], e.alive_count, .little);
            offset += 2;
            std.mem.writeInt(i64, buf[offset..][0..8], e.created_at, .little);
            offset += 8;
            buf[offset] = @bitCast(e.session_color);
            offset += 1;
            const label_len: u16 = @intCast(e.label.len);
            std.mem.writeInt(u16, buf[offset..][0..2], label_len, .little);
            offset += 2;
            @memcpy(buf[offset..][0..e.label.len], e.label);
            offset += e.label.len;
        }
        return buf;
    }

    pub fn parse(alloc: Allocator, payload: []const u8) ![]ListEntry {
        if (payload.len < 2) return error.InvalidListPayload;
        const entry_count = std.mem.readInt(u16, payload[0..2], .little);
        const entries = try alloc.alloc(ListEntry, entry_count);
        errdefer alloc.free(entries);
        var offset: usize = 2;
        for (0..entry_count) |i| {
            if (offset + entry_header_size > payload.len) return error.InvalidListPayload;
            const group_id = payload[offset..][0..uuid_size].*;
            offset += uuid_size;
            const status = std.meta.intToEnum(ListStatus, payload[offset]) catch return error.InvalidListPayload;
            offset += 1;
            const surface_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            const alive_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            const created_at = std.mem.readInt(i64, payload[offset..][0..8], .little);
            offset += 8;
            const session_color: i8 = @bitCast(payload[offset]);
            offset += 1;
            const label_len = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            if (label_len > payload.len - offset) return error.InvalidListPayload;
            entries[i] = .{
                .group_id = group_id,
                .status = status,
                .surface_count = surface_count,
                .alive_count = alive_count,
                .created_at = created_at,
                .session_color = session_color,
                .label = payload[offset..][0..label_len],
            };
            offset += label_len;
        }
        return entries;
    }
};

// =========================================================================
// Tests
// =========================================================================

test "list response encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");

    const entries = [_]ListEntry{
        .{
            .group_id = shared.generateUuid(),
            .status = .attached,
            .surface_count = 3,
            .alive_count = 2,
            .created_at = 1700000000,
            .session_color = 5,
            .label = "my-session",
        },
        .{
            .group_id = shared.generateUuid(),
            .status = .detached,
            .surface_count = 1,
            .alive_count = 1,
            .created_at = 1700001000,
            .session_color = -1,
            .label = "other",
        },
    };

    const resp = ListResponse{ .entries = &entries };
    const encoded = try resp.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ListResponse.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqual(ListStatus.attached, parsed[0].status);
    try testing.expectEqual(@as(u16, 3), parsed[0].surface_count);
    try testing.expectEqual(@as(u16, 2), parsed[0].alive_count);
    try testing.expectEqual(@as(i8, 5), parsed[0].session_color);
    try testing.expectEqualStrings("my-session", parsed[0].label);
    try testing.expectEqual(ListStatus.detached, parsed[1].status);
    try testing.expectEqual(@as(i8, -1), parsed[1].session_color);
    try testing.expectEqualStrings("other", parsed[1].label);
}

test "viewer_state encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const v1_id = shared.generateUuid();
    const v2_id = shared.generateUuid();

    const state = ViewerState{
        .reason = .join,
        .size_mode = .smallest_wins,
        .controller_id = v1_id,
        .effective_rows = 24,
        .effective_cols = 80,
        .viewers = &.{
            .{ .id = v1_id, .label = "user@laptop", .is_controller = true, .rows = 24, .cols = 80 },
            .{ .id = v2_id, .label = "user@desktop", .is_controller = false, .rows = 40, .cols = 120 },
        },
    };
    const encoded = try state.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const hdr = try ViewerState.parseHeader(encoded);
    try testing.expectEqual(ViewerStateReason.join, hdr.reason);
    try testing.expectEqual(SizeMode.smallest_wins, hdr.size_mode);
    try testing.expectEqualSlices(u8, &v1_id, &hdr.controller_id);
    try testing.expectEqual(@as(u16, 24), hdr.effective_rows);
    try testing.expectEqual(@as(u16, 80), hdr.effective_cols);
    try testing.expectEqual(@as(u16, 2), hdr.viewer_count);
}

test "size_mode_change encode/parse" {
    const testing = std.testing;
    const change = SizeModeChange{ .mode = .leader_wins };
    const encoded = change.encode();
    const parsed = try SizeModeChange.parse(&encoded);
    try testing.expectEqual(SizeMode.leader_wins, parsed.mode);
}
