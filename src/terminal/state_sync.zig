//! Terminal state synchronization for SSH remote sessions.
//!
//! Provides delta extraction and application for efficient terminal state
//! transfer. The helper runs a Terminal instance, extracts dirty rows after
//! processOutput, and sends compact deltas to the client.
//!
//! Delta frame format:
//!   [cursor_x: u16] [cursor_y: u16] [cursor_style: u8] [cols: u16] [rows: u16]
//!   [num_dirty_rows: u16]
//!   for each dirty row:
//!     [row_index: u16] [row_flags: u8] [cells: u64 × cols]
//!   [num_styles: u16]
//!   for each style:
//!     [style_id: u16] [style_data: 16 bytes]
//!
//! Full snapshot uses the same format but includes ALL rows.

const std = @import("std");
const Allocator = std.mem.Allocator;
const page = @import("page.zig");
const style = @import("style.zig");
const Screen = @import("Screen.zig");
const Terminal = @import("Terminal.zig");
const size = @import("size.zig");

const log = std.log.scoped(.state_sync);

/// Header size: cursor_x(2) + cursor_y(2) + cursor_style(1) + cols(2) + rows(2) + num_dirty(2) = 11
const header_size = 11;

/// Per-row overhead: row_index(2) + row_flags(1) = 3
const row_overhead = 3;

/// Per-style size: style_id(2) + 3 colors × 4 bytes + flags(2) = 16
const style_record_size = 16;

/// Extract a delta frame containing only dirty rows from the active screen.
/// Clears dirty flags after extraction.
pub fn extractDelta(alloc: Allocator, t: *Terminal) ![]u8 {
    return extractFrame(alloc, t, false);
}

/// Extract a full snapshot of all rows from the active screen.
pub fn extractFullSnapshot(alloc: Allocator, t: *Terminal) ![]u8 {
    return extractFrame(alloc, t, true);
}

fn extractFrame(alloc: Allocator, t: *Terminal, full: bool) ![]u8 {
    const s: *Screen = t.screens.active;
    const cols = s.pages.cols;
    const rows = s.pages.rows;

    // Pre-allocate a reasonable buffer
    const max_size = header_size + (@as(usize, rows) * (row_overhead + @as(usize, cols) * 8)) + 2 + 256 * style_record_size;
    var buf = try std.ArrayList(u8).initCapacity(alloc, @min(max_size, 256 * 1024));
    errdefer buf.deinit(alloc);

    // Write header
    try appendU16(&buf, alloc, s.cursor.x);
    try appendU16(&buf, alloc, s.cursor.y);
    try buf.append(alloc, @intFromEnum(s.cursor.cursor_style));
    try appendU16(&buf, alloc, cols);
    try appendU16(&buf, alloc, rows);

    // Placeholder for num_dirty_rows
    const dirty_count_offset = buf.items.len;
    try appendU16(&buf, alloc, 0);

    // Collect dirty rows and referenced styles
    var num_dirty: u16 = 0;
    var style_set = std.AutoHashMap(page.StyleId, void).init(alloc);
    defer style_set.deinit();

    var row_it = s.pages.rowIterator(
        .right_down,
        .{ .viewport = .{} },
        null,
    );
    var y: u16 = 0;
    while (row_it.next()) |row_pin| : (y += 1) {
        const p: *page.Page = &row_pin.node.data;
        const rac = row_pin.rowAndCell();
        const row = rac.row;

        // Skip non-dirty rows unless doing full snapshot
        if (!full and !row.dirty and !p.dirty) continue;

        // Clear dirty flag
        row.dirty = false;

        // Write row index
        try appendU16(&buf, alloc, y);

        // Write row flags as a single byte
        const flags: u8 = @as(u8, @intFromBool(row.wrap)) |
            (@as(u8, @intFromBool(row.wrap_continuation)) << 1) |
            (@as(u8, @intFromBool(row.grapheme)) << 2) |
            (@as(u8, @intFromBool(row.styled)) << 3) |
            (@as(u8, @intFromBool(row.hyperlink)) << 4) |
            (@as(u8, @intFromEnum(row.semantic_prompt)) << 5) |
            (@as(u8, @intFromBool(row.kitty_virtual_placeholder)) << 7);
        try buf.append(alloc, flags);

        // Write raw cell data (cols × 8 bytes)
        const page_cells = p.getCells(row);
        const cell_bytes: []const u8 = @as([*]const u8, @ptrCast(page_cells.ptr))[0 .. @as(usize, cols) * 8];
        try buf.appendSlice(alloc, cell_bytes);

        // Track referenced style IDs
        for (page_cells) |cell| {
            if (cell.style_id != 0) {
                try style_set.put(cell.style_id, {});
            }
        }

        num_dirty += 1;
    }

    // Patch num_dirty_rows
    std.mem.writeInt(u16, buf.items[dirty_count_offset..][0..2], num_dirty, .little);

    // Clear page dirty flags
    if (!full) {
        var page_it = s.pages.rowIterator(.right_down, .{ .viewport = .{} }, null);
        while (page_it.next()) |pin| {
            pin.node.data.dirty = false;
        }
    }

    // Write styles
    const num_styles: u16 = @intCast(@min(style_set.count(), std.math.maxInt(u16)));
    try appendU16(&buf, alloc, num_styles);

    var style_it = style_set.keyIterator();
    while (style_it.next()) |id_ptr| {
        const id = id_ptr.*;
        try appendU16(&buf, alloc, id);

        // Look up the style from the current page's style set
        // For simplicity, we serialize a default style if lookup fails
        const s_data = lookupStyle(s, id);
        try serializeStyle(&buf, alloc, s_data);
    }

    return try buf.toOwnedSlice(alloc);
}

/// Apply a delta frame to the terminal's active screen.
pub fn applyDelta(alloc: Allocator, t: *Terminal, payload: []const u8) !void {
    if (payload.len < header_size) return error.InvalidPayload;

    var offset: usize = 0;

    // Read header
    const cursor_x = readU16(payload, &offset);
    const cursor_y = readU16(payload, &offset);
    const cursor_style_byte = payload[offset];
    offset += 1;
    const cols = readU16(payload, &offset);
    const rows = readU16(payload, &offset);
    const num_dirty = readU16(payload, &offset);

    _ = rows; // Used for validation if needed

    const s: *Screen = t.screens.active;

    // Update cursor
    s.cursor.x = @min(cursor_x, s.pages.cols -| 1);
    s.cursor.y = @min(cursor_y, s.pages.rows -| 1);
    s.cursor.cursor_style = std.meta.intToEnum(@TypeOf(s.cursor.cursor_style), cursor_style_byte) catch s.cursor.cursor_style;

    // Apply dirty rows
    const cell_data_size = @as(usize, cols) * 8;
    var i: u16 = 0;
    while (i < num_dirty) : (i += 1) {
        if (offset + row_overhead > payload.len) break;

        const row_index = readU16(payload, &offset);
        const row_flags = payload[offset];
        offset += 1;

        if (offset + cell_data_size > payload.len) break;
        if (row_index >= s.pages.rows) {
            offset += cell_data_size;
            continue;
        }

        // Find the row in the viewport
        const row_pin = findViewportRow(s, row_index) orelse {
            offset += cell_data_size;
            continue;
        };

        const p: *page.Page = &row_pin.node.data;
        const rac = row_pin.rowAndCell();
        const row = rac.row;

        // Update row flags
        row.wrap = (row_flags & 1) != 0;
        row.wrap_continuation = (row_flags & 2) != 0;
        row.grapheme = (row_flags & 4) != 0;
        row.styled = (row_flags & 8) != 0;
        row.hyperlink = (row_flags & 16) != 0;
        row.semantic_prompt = std.meta.intToEnum(page.Row.SemanticPrompt, (row_flags >> 5) & 0x3) catch .none;
        row.kitty_virtual_placeholder = (row_flags & 128) != 0;

        // Copy cell data
        const target_cells = p.getCells(row);
        const src_cols = @min(cols, s.pages.cols);
        const copy_bytes = @as(usize, src_cols) * 8;
        const cell_ptr: [*]u8 = @ptrCast(target_cells.ptr);
        @memcpy(cell_ptr[0..copy_bytes], payload[offset .. offset + copy_bytes]);
        offset += cell_data_size;

        // Mark row dirty for renderer
        row.dirty = true;
    }

    // Read and apply styles
    if (offset + 2 <= payload.len) {
        const num_styles = readU16(payload, &offset);
        _ = alloc;
        var si: u16 = 0;
        while (si < num_styles) : (si += 1) {
            if (offset + style_record_size > payload.len) break;
            // Read style_id and data
            _ = readU16(payload, &offset); // style_id
            offset += style_record_size - 2; // skip style data for now
            // Style application requires the style set which is complex.
            // For the initial implementation, styles are carried in the cell
            // data (style_id). The receiving terminal needs to have matching
            // style IDs, which works when both sides process the same VT stream.
        }
    }

    // Mark page dirty
    if (num_dirty > 0) {
        s.dirty.selection = true; // Trigger renderer redraw
    }
}

/// Apply a full snapshot — reset viewport and apply all rows.
pub fn applyFullSnapshot(alloc: Allocator, t: *Terminal, payload: []const u8) !void {
    // Full snapshot uses the same format as delta but with all rows
    try applyDelta(alloc, t, payload);
}

// -- Helpers --

fn appendU16(buf: *std.ArrayList(u8), alloc: Allocator, val: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, val, .little);
    try buf.appendSlice(alloc, &bytes);
}

fn readU16(data: []const u8, offset: *usize) u16 {
    if (offset.* + 2 > data.len) return 0;
    const val = std.mem.readInt(u16, data[offset.*..][0..2], .little);
    offset.* += 2;
    return val;
}

fn lookupStyle(s: *Screen, id: page.StyleId) style.Style {
    // The style might be on any page in the viewport. Search the current
    // cursor page first, then fall back to default.
    if (s.cursor.page_pin.node.data.styles.get(
        s.cursor.page_pin.node.data.memory,
        id,
    )) |found| {
        return found.*;
    }
    return .{};
}

fn serializeStyle(buf: *std.ArrayList(u8), alloc: Allocator, s: style.Style) !void {
    // Foreground
    try serializeColor(buf, alloc, s.fg_color);
    // Background
    try serializeColor(buf, alloc, s.bg_color);
    // Underline
    try serializeColor(buf, alloc, s.underline_color);
    // Flags (2 bytes)
    const flags_int: u16 = @bitCast(s.flags);
    var fb: [2]u8 = undefined;
    std.mem.writeInt(u16, &fb, flags_int, .little);
    try buf.appendSlice(alloc, &fb);
}

fn serializeColor(buf: *std.ArrayList(u8), alloc: Allocator, c: style.Color) !void {
    switch (c) {
        .none => {
            try buf.appendSlice(alloc, &[_]u8{ 0, 0, 0, 0 });
        },
        .palette => |idx| {
            try buf.appendSlice(alloc, &[_]u8{ 1, idx, 0, 0 });
        },
        .rgb => |rgb| {
            try buf.appendSlice(alloc, &[_]u8{ 2, rgb.r, rgb.g, rgb.b });
        },
    }
}

fn findViewportRow(s: *Screen, row_index: u16) ?@import("PageList.zig").Pin {
    var it = s.pages.rowIterator(.right_down, .{ .viewport = .{} }, null);
    var y: u16 = 0;
    while (it.next()) |pin| : (y += 1) {
        if (y == row_index) return pin;
    }
    return null;
}
