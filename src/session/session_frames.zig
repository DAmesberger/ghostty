const std = @import("std");
const Allocator = std.mem.Allocator;

const Uuid = @import("shared.zig").Uuid;
const zero_uuid = @import("shared.zig").zero_uuid;
const uuid_size = 16;

const Resize = @import("resize_scrollback.zig").Resize;

// =========================================================================
// Open frame — unified session/surface open
// =========================================================================

pub const OpenType = enum(u8) {
    session_new = 0,
    session_attach = 1,
    surface_new = 2,
    surface_attach = 3,
};

/// Payload for `open`:
///   [1]  open_type
///   [16] group_id  (zero = auto-generate)
///   [16] surface_id (zero = auto-generate or first-alive)
///   [8]  resize
///   [4]  max_scrollback (u32 LE, 0 = use daemon default)
///   [1]  compression_enabled (0=no, 1=yes — client supports LZ4)
///   [2]  frame_interval_ms (0=no debounce, default 16; client's preferred rate)
///   [N]  label (remaining bytes, UTF-8, may be empty)
pub const Open = struct {
    open_type: OpenType,
    group_id: Uuid = zero_uuid,
    surface_id: Uuid = zero_uuid,
    resize: Resize,
    max_scrollback: u32 = 0,
    compression_enabled: u8 = 1,
    frame_interval_ms: u16 = 16,
    label: []const u8 = "",

    /// Fixed part: open_type(1) + group_id(16) + surface_id(16) + resize(8) +
    /// max_scrollback(4) + compression_enabled(1) + frame_interval_ms(2) = 48
    const fixed_size = 1 + uuid_size * 2 + 8 + 4 + 1 + 2;
    pub const min_payload_size = fixed_size;

    pub fn encode(self: Open, alloc: Allocator) ![]u8 {
        const total = min_payload_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.open_type);
        @memcpy(buf[1 .. 1 + uuid_size], &self.group_id);
        @memcpy(buf[1 + uuid_size .. 1 + uuid_size * 2], &self.surface_id);
        const resize_bytes = self.resize.bytes();
        @memcpy(buf[1 + uuid_size * 2 .. 1 + uuid_size * 2 + 8], &resize_bytes);
        const scrollback_off = 1 + uuid_size * 2 + 8;
        std.mem.writeInt(u32, buf[scrollback_off..][0..4], self.max_scrollback, .little);
        buf[scrollback_off + 4] = self.compression_enabled;
        std.mem.writeInt(u16, buf[scrollback_off + 5 ..][0..2], self.frame_interval_ms, .little);
        @memcpy(buf[min_payload_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !Open {
        if (payload.len < min_payload_size) return error.InvalidOpenPayload;
        const scrollback_off = 1 + uuid_size * 2 + 8;
        return .{
            .open_type = std.meta.intToEnum(OpenType, payload[0]) catch return error.InvalidOpenPayload,
            .group_id = payload[1..][0..uuid_size].*,
            .surface_id = payload[1 + uuid_size ..][0..uuid_size].*,
            .resize = try Resize.parse(payload[1 + uuid_size * 2 ..][0..8]),
            .max_scrollback = std.mem.readInt(u32, payload[scrollback_off..][0..4], .little),
            .compression_enabled = payload[scrollback_off + 4],
            .frame_interval_ms = std.mem.readInt(u16, payload[scrollback_off + 5 ..][0..2], .little),
            .label = payload[min_payload_size..],
        };
    }
};

// =========================================================================
// Close frame — unified close/detach
// =========================================================================

pub const CloseMode = enum(u8) {
    /// Kill the specific surface's PTY.
    surface = 0,
    /// Detach — keep daemon-side session alive for reattach.
    detach = 1,
    /// Kill all surfaces in the session group.
    session = 2,
};

/// Payload for `close`:
///   [1]  close_mode
///   [16] id (surface UUID for mode=surface, group UUID for mode=session;
///            omittable for mode=detach — parser accepts 1-byte payload)
pub const Close = struct {
    mode: CloseMode,
    id: Uuid = zero_uuid,

    pub fn encode(self: Close, alloc: Allocator) ![]u8 {
        if (self.mode == .detach) {
            const buf = try alloc.alloc(u8, 1);
            buf[0] = @intFromEnum(self.mode);
            return buf;
        }
        const buf = try alloc.alloc(u8, 1 + uuid_size);
        buf[0] = @intFromEnum(self.mode);
        @memcpy(buf[1 .. 1 + uuid_size], &self.id);
        return buf;
    }

    pub fn parse(payload: []const u8) !Close {
        if (payload.len < 1) return error.InvalidClosePayload;
        const mode = std.meta.intToEnum(CloseMode, payload[0]) catch return error.InvalidClosePayload;
        if (mode == .detach) return .{ .mode = .detach };
        if (payload.len < 1 + uuid_size) return error.InvalidClosePayload;
        return .{
            .mode = mode,
            .id = payload[1..][0..uuid_size].*,
        };
    }
};

// =========================================================================
// Rename frame
// =========================================================================

pub const RenameScope = enum(u8) {
    group = 0,
    surface = 1,
};

/// Payload for `rename`:
///   [1]  scope (0=group, 1=surface)
///   [16] UUID
///   [N]  label (remaining bytes)
pub const Rename = struct {
    scope: RenameScope,
    id: Uuid,
    label: []const u8,

    pub const min_payload_size = 1 + uuid_size;

    pub fn encode(self: Rename, alloc: Allocator) ![]u8 {
        const total = min_payload_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.scope);
        @memcpy(buf[1 .. 1 + uuid_size], &self.id);
        @memcpy(buf[min_payload_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !Rename {
        if (payload.len < min_payload_size) return error.InvalidRenamePayload;
        return .{
            .scope = std.meta.intToEnum(RenameScope, payload[0]) catch return error.InvalidRenamePayload,
            .id = payload[1..][0..uuid_size].*,
            .label = payload[min_payload_size..],
        };
    }
};

// =========================================================================
// Opened frame — bundled response (eliminates round-trips on attach)
// =========================================================================

/// Payload for `opened`:
///   [16] group_id
///   [16] surface_id (which daemon surface was attached; zero for new sessions)
///   [4]  caps (u32 LE capability bitmask — bit 0: compression)
///   [4]  history_rows (u32 LE)
///   [2]  label_len (u16 LE)
///   [label_len] session label (daemon-authoritative)
///   [4]  layout_len (u32 LE, 0 = no layout)
///   [layout_len] layout blob
///   [2]  state_count (u16 LE, number of surface state snapshots)
///   per state_count:
///     [16] surface_id
///     [4]  state_len (u32 LE)
///     [state_len] full page snapshot (diff_type=1 data_out format)
pub const Opened = struct {
    group_id: Uuid,
    /// The daemon-side surface_id that was attached.
    surface_id: Uuid = zero_uuid,
    caps: u32 = 0,
    history_rows: u32 = 0,
    /// Daemon-authoritative session label. Set on first open, updated by rename.
    label: []const u8 = "",
    /// Session color (-1 = none, 0-7 = index). Deterministic from group UUID.
    color: i8 = -1,
    layout_blob: ?[]const u8 = null,
    states: []const SurfaceState = &.{},

    pub const SurfaceState = struct {
        surface_id: Uuid,
        data: []const u8,
    };

    /// Capability bits.
    pub const cap_compression: u32 = 1 << 0;

    pub fn encode(self: Opened, alloc: Allocator) ![]u8 {
        const layout_len: u32 = if (self.layout_blob) |b| @intCast(b.len) else 0;
        // uuid*2 + caps(4) + history_rows(4) + label_len(2) + label + color(1) + layout_len(4) + layout + state_count(2)
        var total: usize = uuid_size * 2 + 4 + 4 + 2 + self.label.len + 1 + 4 + layout_len + 2;
        for (self.states) |s| {
            total += uuid_size + 4 + s.data.len;
        }
        const buf = try alloc.alloc(u8, total);
        var offset: usize = 0;

        @memcpy(buf[offset..][0..uuid_size], &self.group_id);
        offset += uuid_size;
        @memcpy(buf[offset..][0..uuid_size], &self.surface_id);
        offset += uuid_size;
        std.mem.writeInt(u32, buf[offset..][0..4], self.caps, .little);
        offset += 4;
        std.mem.writeInt(u32, buf[offset..][0..4], self.history_rows, .little);
        offset += 4;
        // Label
        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(self.label.len), .little);
        offset += 2;
        @memcpy(buf[offset..][0..self.label.len], self.label);
        offset += self.label.len;
        // Color
        buf[offset] = @bitCast(self.color);
        offset += 1;
        std.mem.writeInt(u32, buf[offset..][0..4], layout_len, .little);
        offset += 4;
        if (self.layout_blob) |b| {
            @memcpy(buf[offset..][0..b.len], b);
            offset += b.len;
        }
        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(self.states.len), .little);
        offset += 2;
        for (self.states) |s| {
            @memcpy(buf[offset..][0..uuid_size], &s.surface_id);
            offset += uuid_size;
            std.mem.writeInt(u32, buf[offset..][0..4], @intCast(s.data.len), .little);
            offset += 4;
            @memcpy(buf[offset..][0..s.data.len], s.data);
            offset += s.data.len;
        }
        return buf;
    }

    pub fn parseHeader(payload: []const u8) !struct {
        group_id: Uuid,
        surface_id: Uuid,
        caps: u32,
        history_rows: u32,
        label: []const u8,
        color: i8,
        layout_blob: ?[]const u8,
        state_count: u16,
        remaining: []const u8,
    } {
        // uuid*2 + caps(4) + history_rows(4) + label_len(2) + color(1) + layout_len(4) + state_count(2)
        const min_size = uuid_size * 2 + 4 + 4 + 2 + 1 + 4 + 2;
        if (payload.len < min_size) return error.InvalidOpenedPayload;
        var offset: usize = 0;
        const group_id = payload[0..uuid_size].*;
        offset += uuid_size;
        const surface_id = payload[offset..][0..uuid_size].*;
        offset += uuid_size;
        const caps = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        const history_rows = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        // Label
        const label_len = std.mem.readInt(u16, payload[offset..][0..2], .little);
        offset += 2;
        if (label_len > payload.len - offset) return error.InvalidOpenedPayload;
        const label = payload[offset..][0..label_len];
        offset += label_len;
        // Remaining fixed fields: color(1) + layout_len(4) + state_count(2) = 7
        if (payload.len - offset < 7) return error.InvalidOpenedPayload;
        const color: i8 = @bitCast(payload[offset]);
        offset += 1;
        const layout_len = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        if (payload.len - offset < layout_len) return error.InvalidOpenedPayload;
        const layout_blob: ?[]const u8 = if (layout_len > 0)
            payload[offset..][0..layout_len]
        else
            null;
        offset += layout_len;
        // state_count already covered by the 7-byte check above
        const state_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
        offset += 2;
        return .{
            .group_id = group_id,
            .surface_id = surface_id,
            .caps = caps,
            .history_rows = history_rows,
            .label = label,
            .color = color,
            .layout_blob = layout_blob,
            .state_count = state_count,
            .remaining = payload[offset..],
        };
    }
};

// =========================================================================
// Tests
// =========================================================================

test "open encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const sid = shared.generateUuid();
    const gid = shared.generateUuid();
    const o = Open{
        .open_type = .session_new,
        .group_id = gid,
        .surface_id = sid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .max_scrollback = 10_000_000,
        .label = "test-session",
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Open.parse(encoded);
    try testing.expectEqual(OpenType.session_new, parsed.open_type);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqual(@as(u32, 10_000_000), parsed.max_scrollback);
    try testing.expectEqualStrings("test-session", parsed.label);
}

// Legacy backward-compat test removed — only current format is supported.

test "open attach mode" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const o = Open{
        .open_type = .session_attach,
        .group_id = gid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Open.parse(encoded);
    try testing.expectEqual(OpenType.session_attach, parsed.open_type);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
}

test "close encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const sid = shared.generateUuid();

    // Surface close
    const c1 = Close{ .mode = .surface, .id = sid };
    const e1 = try c1.encode(testing.allocator);
    defer testing.allocator.free(e1);
    const p1 = try Close.parse(e1);
    try testing.expectEqual(CloseMode.surface, p1.mode);
    try testing.expectEqualSlices(u8, &sid, &p1.id);

    // Detach (no UUID)
    const c2 = Close{ .mode = .detach };
    const e2 = try c2.encode(testing.allocator);
    defer testing.allocator.free(e2);
    try testing.expectEqual(@as(usize, 1), e2.len);
    const p2 = try Close.parse(e2);
    try testing.expectEqual(CloseMode.detach, p2.mode);
}

test "rename encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();

    const r = Rename{ .scope = .group, .id = gid, .label = "new-name" };
    const encoded = try r.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Rename.parse(encoded);
    try testing.expectEqual(RenameScope.group, parsed.scope);
    try testing.expectEqualSlices(u8, &gid, &parsed.id);
    try testing.expectEqualStrings("new-name", parsed.label);
}

test "opened encode/parse header" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const sid = shared.generateUuid();

    const layout_data = "fake-layout";
    const o = Opened{
        .group_id = gid,
        .surface_id = sid,
        .caps = Opened.cap_compression,
        .layout_blob = layout_data,
        .states = &.{},
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Opened.parseHeader(encoded);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
    try testing.expectEqual(Opened.cap_compression, parsed.caps);
    try testing.expectEqual(@as(u32, 0), parsed.history_rows);
    try testing.expectEqualStrings("fake-layout", parsed.layout_blob.?);
    try testing.expectEqual(@as(u16, 0), parsed.state_count);
}
