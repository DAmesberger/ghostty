//! Structured page diff engine for SSH remote sessions.
//!
//! Serializes terminal page state as binary diffs instead of raw VT bytes.
//! The daemon's HeadlessStreamHandler already parses all VT from the PTY
//! and updates its page memory. We forward the *output* of the Terminal
//! (page diffs) rather than its *input* (raw VT), so the client applies
//! binary diffs directly to its Terminal's page memory, skipping VT
//! parsing entirely.

const std = @import("std");
const Allocator = std.mem.Allocator;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page = terminal.page;
const style = @import("../terminal/style.zig");

/// Encode row flags byte.
fn encodeRowFlags(row: page.Row) u8 {
    var flags: u8 = 0;
    if (row.wrap) flags |= 0x01;
    if (row.wrap_continuation) flags |= 0x02;
    flags |= @as(u8, @intFromEnum(row.semantic_prompt)) << 2;
    return flags;
}

/// Count the number of non-trailing-empty cells in a row.
/// Trailing empty = codepoint 0, style_id 0, no bg color.
fn countContentCells(cells: []const page.Cell) u16 {
    var last: u16 = 0;
    for (cells, 0..) |cell, i| {
        if (cell.codepoint() != 0 or cell.style_id != 0 or
            cell.content_tag == .bg_color_palette or cell.content_tag == .bg_color_rgb)
        {
            last = @intCast(i + 1);
        }
    }
    return last;
}

/// Serialize a Style into the buffer. Returns bytes written.
/// Public so that scrollback chunk serialization can reuse it.
pub fn serializeStyle(buf: []u8, s: style.Style) usize {
    var offset: usize = 0;
    // Flags (2 bytes)
    const flags_bits: u16 = @bitCast(s.flags);
    std.mem.writeInt(u16, buf[offset..][0..2], flags_bits, .little);
    offset += 2;
    // fg_color
    offset += serializeColor(buf[offset..], s.fg_color);
    // bg_color
    offset += serializeColor(buf[offset..], s.bg_color);
    // underline_color
    offset += serializeColor(buf[offset..], s.underline_color);
    return offset;
}

/// Serialize a Style.Color. Returns bytes written.
fn serializeColor(buf: []u8, color: style.Style.Color) usize {
    switch (color) {
        .none => {
            buf[0] = 0;
            return 1;
        },
        .palette => |idx| {
            buf[0] = 1;
            buf[1] = idx;
            return 2;
        },
        .rgb => |rgb| {
            buf[0] = 2;
            buf[1] = rgb.r;
            buf[2] = rgb.g;
            buf[3] = rgb.b;
            return 4;
        },
    }
}

// =========================================================================
// Scrollback chunk serialization (daemon → client binary transfer)
// =========================================================================

/// Maximum style size in bytes: flags(2) + 3 colors * max 4 bytes each = 14.
const max_style_bytes = 14;

/// Deserialize a Style.Color from the buffer. Returns the color and bytes consumed.
pub fn deserializeColor(buf: []const u8) struct { color: style.Style.Color, len: usize } {
    if (buf.len == 0) return .{ .color = .none, .len = 0 };
    return switch (buf[0]) {
        // palette tag needs 1 tag byte + 1 index byte
        1 => if (buf.len >= 2)
            .{ .color = .{ .palette = buf[1] }, .len = 2 }
        else
            // Truncated: signal malformed chunk with a zero-length sentinel.
            .{ .color = .none, .len = 0 },
        // rgb tag needs 1 tag byte + 3 component bytes
        2 => if (buf.len >= 4)
            .{ .color = .{ .rgb = .{ .r = buf[1], .g = buf[2], .b = buf[3] } }, .len = 4 }
        else
            // Truncated: signal malformed chunk with a zero-length sentinel.
            .{ .color = .none, .len = 0 },
        else => .{ .color = .none, .len = 1 },
    };
}

/// Deserialize a Style from the buffer. Returns the style and bytes consumed.
pub fn deserializeStyle(buf: []const u8) struct { s: style.Style, len: usize } {
    var s: style.Style = .{};
    var offset: usize = 0;
    if (buf.len < 2) return .{ .s = s, .len = 0 };

    s.flags = @bitCast(std.mem.readInt(u16, buf[0..2], .little));
    offset += 2;

    const fg = deserializeColor(buf[offset..]);
    s.fg_color = fg.color;
    offset += fg.len;

    const bg = deserializeColor(buf[offset..]);
    s.bg_color = bg.color;
    offset += bg.len;

    const ul = deserializeColor(buf[offset..]);
    s.underline_color = ul.color;
    offset += ul.len;

    return .{ .s = s, .len = offset };
}

/// Serialize a chunk of scrollback history rows into a binary buffer.
/// Iterates history rows starting at `start_row` (absolute from top of
/// history), serializes up to `max_rows` rows. Returns the serialized
/// data and the number of rows actually serialized.
///
/// The format per row is:
///   [1]  row_flags
///   [2]  cell_count (u16 LE)
///   [cell_count * 8]  raw Cell u64 LE
///   [2]  grapheme_count (u16 LE)
///   per grapheme:
///     [2]  cell_index (u16 LE)
///     [2]  cp_count (u16 LE)
///     [cp_count * 4]  u32 LE codepoints
///
/// After all rows, the style table:
///   [2]  style_count (u16 LE)
///   per style:
///     [2]  style_id (u16 LE)
///     [N]  serialized Style
pub fn serializeScrollbackChunk(
    alloc: Allocator,
    t: *Terminal,
    start_row: u32,
    max_rows: u16,
) !struct { data: []u8, rows_serialized: u16 } {
    const s: *Screen = t.screens.active;

    // Estimate size: generous initial allocation
    const est_per_row = 5 + @as(usize, @intCast(t.cols)) * 8 + 64;
    var buf = try alloc.alloc(u8, @min(
        est_per_row * @as(usize, max_rows) + 4096,
        512 * 1024,
    ));
    errdefer alloc.free(buf);
    var offset: usize = 0;
    var buf_cap = buf.len;

    // Track referenced styles for the style table
    var style_ids_seen = std.AutoArrayHashMap(style.Id, void).init(alloc);
    defer style_ids_seen.deinit();

    // Collect styles per page for later lookup
    const StyleEntry = struct { id: style.Id, page_ptr: *page.Page };
    var style_entries = std.ArrayList(StyleEntry).empty;
    defer style_entries.deinit(alloc);

    var row_it = s.pages.rowIterator(.right_down, .{ .history = .{} }, null);
    var row_idx: u32 = 0;
    var rows_serialized: u16 = 0;

    while (row_it.next()) |row_pin| {
        if (row_idx < start_row) {
            row_idx += 1;
            continue;
        }
        if (rows_serialized >= max_rows) break;

        const p: *page.Page = &row_pin.node.data;
        const rac = row_pin.rowAndCell();
        const row = rac.row;
        const cells = p.getCells(row);
        const cell_count = countContentCells(cells);

        // Count graphemes for this row
        var grapheme_count: u16 = 0;
        var grapheme_bytes: usize = 0;
        for (cells[0..cell_count]) |cell| {
            if (cell.content_tag == .codepoint_grapheme) {
                if (p.lookupGrapheme(&cell)) |extras| {
                    grapheme_count += 1;
                    grapheme_bytes += 4 + extras.len * 4; // cell_index(2) + cp_count(2) + codepoints
                }
            }
        }

        // Ensure buffer has space for this row
        const row_bytes = 1 + 2 + @as(usize, cell_count) * 8 + 2 + grapheme_bytes;
        while (offset + row_bytes > buf_cap) {
            buf_cap = buf_cap * 2;
            buf = try alloc.realloc(buf, buf_cap);
        }

        // Row flags
        buf[offset] = encodeRowFlags(row.*);
        offset += 1;

        // Cell count
        std.mem.writeInt(u16, buf[offset..][0..2], cell_count, .little);
        offset += 2;

        // Raw cell data
        for (cells[0..cell_count]) |cell| {
            const cell_bits: u64 = @bitCast(cell);
            std.mem.writeInt(u64, buf[offset..][0..8], cell_bits, .little);
            offset += 8;

            if (cell.style_id != 0) {
                if (!style_ids_seen.contains(cell.style_id)) {
                    style_ids_seen.put(cell.style_id, {}) catch {};
                    style_entries.append(alloc, .{ .id = cell.style_id, .page_ptr = p }) catch {};
                }
            }
        }

        // Grapheme data
        std.mem.writeInt(u16, buf[offset..][0..2], grapheme_count, .little);
        offset += 2;

        if (grapheme_count > 0) {
            for (cells[0..cell_count], 0..) |cell, ci| {
                if (cell.content_tag == .codepoint_grapheme) {
                    if (p.lookupGrapheme(&cell)) |extras| {
                        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(ci), .little);
                        offset += 2;
                        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(extras.len), .little);
                        offset += 2;
                        for (extras) |cp| {
                            std.mem.writeInt(u32, buf[offset..][0..4], cp, .little);
                            offset += 4;
                        }
                    }
                }
            }
        }

        rows_serialized += 1;
        row_idx += 1;
    }

    // Write style table
    const style_table_est = 2 + style_entries.items.len * (2 + max_style_bytes);
    while (offset + style_table_est > buf_cap) {
        buf_cap = buf_cap * 2;
        buf = try alloc.realloc(buf, buf_cap);
    }

    std.mem.writeInt(u16, buf[offset..][0..2], @intCast(style_entries.items.len), .little);
    offset += 2;

    for (style_entries.items) |entry| {
        std.mem.writeInt(u16, buf[offset..][0..2], entry.id, .little);
        offset += 2;
        const s_ptr = entry.page_ptr.styles.get(entry.page_ptr.memory, entry.id);
        offset += serializeStyle(buf[offset..], s_ptr.*);
    }

    return .{
        .data = try alloc.realloc(buf, offset),
        .rows_serialized = rows_serialized,
    };
}

/// Apply a scrollback chunk to the client's terminal. Writes cell data,
/// styles, and graphemes directly into pre-allocated history pages.
///
/// The client must have called `PageList.prependBlankPages()` before the
/// first chunk to ensure the target rows exist.
pub fn applyScrollbackChunk(
    t: *Terminal,
    chunk_start_row: u32,
    row_count: u16,
    data: []const u8,
) void {
    if (row_count == 0) return;

    const s: *Screen = t.screens.active;
    var offset: usize = 0;

    // First parse the style table at the end. We need to find it by
    // scanning past all rows first.
    var scan_offset: usize = 0;
    for (0..row_count) |_| {
        if (scan_offset >= data.len) return;
        scan_offset += 1; // row_flags
        if (scan_offset + 2 > data.len) return;
        const cell_count = std.mem.readInt(u16, data[scan_offset..][0..2], .little);
        scan_offset += 2;
        scan_offset += @as(usize, cell_count) * 8;
        if (scan_offset + 2 > data.len) return;
        const grapheme_count = std.mem.readInt(u16, data[scan_offset..][0..2], .little);
        scan_offset += 2;
        for (0..grapheme_count) |_| {
            if (scan_offset + 4 > data.len) return;
            scan_offset += 2; // cell_index
            const cp_count = std.mem.readInt(u16, data[scan_offset..][0..2], .little);
            scan_offset += 2;
            scan_offset += @as(usize, cp_count) * 4;
        }
    }

    // Parse style table: server_id → Style (inline arrays, no allocator needed)
    var style_count: u16 = 0;
    var style_table_offset = scan_offset;
    if (style_table_offset + 2 <= data.len) {
        style_count = std.mem.readInt(u16, data[style_table_offset..][0..2], .little);
        style_table_offset += 2;
    }

    // We need a small lookup from server style ID → Style. Since we can't
    // easily use an allocator here, we'll build the mapping as we go and
    // look up styles from the table on demand.
    // Store up to 256 style mappings inline.
    const max_inline_styles = 256;
    var server_ids: [max_inline_styles]style.Id = undefined;
    var server_styles: [max_inline_styles]style.Style = undefined;
    const actual_style_count = @min(style_count, max_inline_styles);

    for (0..actual_style_count) |i| {
        if (style_table_offset + 2 > data.len) break;
        server_ids[i] = std.mem.readInt(u16, data[style_table_offset..][0..2], .little);
        style_table_offset += 2;
        const result = deserializeStyle(data[style_table_offset..]);
        server_styles[i] = result.s;
        style_table_offset += result.len;
    }

    // Now apply rows
    for (0..row_count) |ri| {
        if (offset >= data.len) return;

        const target_row: u32 = chunk_start_row + @as(u32, @intCast(ri));

        // Pin the target history row
        const pin = s.pages.pin(.{ .history = .{
            .x = 0,
            .y = target_row,
        } }) orelse continue;

        const p: *page.Page = &pin.node.data;
        const rac = pin.rowAndCell();
        const row = rac.row;

        // Parse row flags
        const row_flags = data[offset];
        offset += 1;
        row.wrap = (row_flags & 0x01) != 0;
        row.wrap_continuation = (row_flags & 0x02) != 0;
        row.semantic_prompt = @enumFromInt(@as(u2, @truncate(row_flags >> 2)));

        // Parse cell count
        if (offset + 2 > data.len) return;
        const cell_count = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;

        // Write cells
        const page_cells = p.getCells(row);
        const write_count = @min(cell_count, @as(u16, @intCast(page_cells.len)));

        for (0..write_count) |ci| {
            if (offset + 8 > data.len) return;
            const cell_bits = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;

            var cell: page.Cell = @bitCast(cell_bits);

            // Remap style_id from server to client
            if (cell.style_id != 0) {
                const server_id = cell.style_id;
                // Look up server style
                var found_style: ?style.Style = null;
                for (0..actual_style_count) |si| {
                    if (server_ids[si] == server_id) {
                        found_style = server_styles[si];
                        break;
                    }
                }
                if (found_style) |fs| {
                    // Add style to this page and get client-side ID
                    const client_id = p.styles.add(p.memory, fs) catch |err| blk: {
                        switch (err) {
                            error.NeedsRehash => {
                                // Try rehash — but we don't have PageList access here,
                                // so just clear the style on this cell.
                            },
                            error.OutOfMemory => {},
                        }
                        break :blk @as(style.Id, 0);
                    };
                    cell.style_id = client_id;
                    if (client_id != 0) row.styled = true;
                } else {
                    cell.style_id = 0;
                }
            }

            // Clear grapheme tag — we'll re-set it from grapheme data below
            if (cell.content_tag == .codepoint_grapheme) {
                cell.content_tag = .codepoint;
            }

            page_cells[ci] = cell;
        }

        // Skip remaining cells we didn't write (if cell_count > page width)
        if (cell_count > write_count) {
            offset += @as(usize, cell_count - write_count) * 8;
        }

        // Parse grapheme data
        if (offset + 2 > data.len) return;
        const grapheme_count = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;

        for (0..grapheme_count) |_| {
            if (offset + 4 > data.len) return;
            const cell_index = std.mem.readInt(u16, data[offset..][0..2], .little);
            offset += 2;
            const cp_count = std.mem.readInt(u16, data[offset..][0..2], .little);
            offset += 2;

            if (cell_index < page_cells.len and cp_count > 0) {
                // Read codepoints
                var cps_buf: [32]u21 = undefined;
                const actual_cp = @min(cp_count, 32);
                for (0..actual_cp) |cpi| {
                    if (offset + 4 > data.len) return;
                    const raw_cp = std.mem.readInt(u32, data[offset..][0..4], .little);
                    cps_buf[cpi] = std.math.cast(u21, raw_cp) orelse 0xFFFD; // replacement char
                    offset += 4;
                }
                // Skip any excess codepoints
                if (cp_count > actual_cp) {
                    offset += @as(usize, cp_count - actual_cp) * 4;
                }

                // Set graphemes on the cell
                p.setGraphemes(row, &page_cells[cell_index], cps_buf[0..actual_cp]) catch {
                    // Grapheme alloc full — skip this grapheme
                };
                row.grapheme = true;
            } else {
                // Skip codepoint data
                offset += @as(usize, cp_count) * 4;
            }
        }

        // Mark row dirty for renderer
        row.dirty = true;
    }
}
