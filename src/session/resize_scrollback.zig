const std = @import("std");
const Allocator = std.mem.Allocator;

// =========================================================================
// Resize (unchanged from v6)
// =========================================================================

pub const Resize = packed struct {
    rows: u16,
    cols: u16,
    width_px: u16,
    height_px: u16,

    pub fn bytes(self: Resize) [8]u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], self.rows, .little);
        std.mem.writeInt(u16, buf[2..4], self.cols, .little);
        std.mem.writeInt(u16, buf[4..6], self.width_px, .little);
        std.mem.writeInt(u16, buf[6..8], self.height_px, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !Resize {
        if (payload.len != 8) return error.InvalidResizePayload;
        return .{
            .rows = std.mem.readInt(u16, payload[0..2], .little),
            .cols = std.mem.readInt(u16, payload[2..4], .little),
            .width_px = std.mem.readInt(u16, payload[4..6], .little),
            .height_px = std.mem.readInt(u16, payload[6..8], .little),
        };
    }
};

// =========================================================================
// Scrollback response (proactive streaming from daemon)
// =========================================================================

/// Payload for `scrollback_response` (binary chunk format):
///   [4]  total_history_rows  (u32 LE: daemon's total history rows, for progress)
///   [4]  chunk_start_row     (u32 LE: absolute row from top of history)
///   [2]  row_count           (u16 LE: rows in this chunk, 0 = done marker)
///   [2]  cols                (u16 LE: column count)
///   [N]  chunk_data          (binary row/style data, serialized by page_diff)
pub const ScrollbackResponse = struct {
    total_history_rows: u32,
    chunk_start_row: u32,
    row_count: u16,
    cols: u16,
    chunk_data: []const u8,

    pub const hdr_size: usize = 12;

    pub fn encode(self: ScrollbackResponse, alloc: Allocator) ![]u8 {
        const total = hdr_size + self.chunk_data.len;
        const buf = try alloc.alloc(u8, total);
        std.mem.writeInt(u32, buf[0..4], self.total_history_rows, .little);
        std.mem.writeInt(u32, buf[4..8], self.chunk_start_row, .little);
        std.mem.writeInt(u16, buf[8..10], self.row_count, .little);
        std.mem.writeInt(u16, buf[10..12], self.cols, .little);
        @memcpy(buf[hdr_size..], self.chunk_data);
        return buf;
    }

    pub fn parse(payload: []const u8) !ScrollbackResponse {
        if (payload.len < hdr_size) return error.InvalidScrollbackResponse;
        return .{
            .total_history_rows = std.mem.readInt(u32, payload[0..4], .little),
            .chunk_start_row = std.mem.readInt(u32, payload[4..8], .little),
            .row_count = std.mem.readInt(u16, payload[8..10], .little),
            .cols = std.mem.readInt(u16, payload[10..12], .little),
            .chunk_data = payload[hdr_size..],
        };
    }
};

// =========================================================================
// Tests
// =========================================================================

test "scrollback_response encode/parse" {
    const testing = std.testing;

    const chunk_data = "fake-binary-chunk";
    const resp = ScrollbackResponse{
        .total_history_rows = 5000,
        .chunk_start_row = 100,
        .row_count = 25,
        .cols = 80,
        .chunk_data = chunk_data,
    };
    const encoded = try resp.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ScrollbackResponse.parse(encoded);
    try testing.expectEqual(@as(u32, 5000), parsed.total_history_rows);
    try testing.expectEqual(@as(u32, 100), parsed.chunk_start_row);
    try testing.expectEqual(@as(u16, 25), parsed.row_count);
    try testing.expectEqual(@as(u16, 80), parsed.cols);
    try testing.expectEqualStrings(chunk_data, parsed.chunk_data);
}

test "scrollback_response rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidScrollbackResponse, ScrollbackResponse.parse(&short));
}
