//! Pure Terminal-viewport -> VT escape-sequence serialization.
//!
//! Split out of `remote_session.zig` (which re-exports it). This module holds
//! the reconnect/snapshot serialization: it walks a `*Terminal` viewport and
//! emits VT escape sequences (cells, SGR styles, charsets, modes, cursor) into
//! a writer. It carries no session/threading state — it takes only
//! `(alloc, *Terminal)` plus a writer — so it is reused by `persist.zig` and
//! `daemon_core.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page = terminal.page;

/// Serialize the Terminal's viewport as VT escape sequences.
/// Public so `session/persist.zig` can reuse it for daemon-side scrollback
/// persistence (the reload path repaints this through the same parser).
pub fn serializeViewportAsVT(alloc: Allocator, t: *Terminal) ![]u8 {
    const s: *Screen = t.screens.active;

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    // Reset client state: clear screen, reset attributes, home cursor
    try w.writeAll("\x1b[0m\x1b[H\x1b[2J");

    // If the daemon is on the alternate screen (a full-screen TUI: vim, less,
    // an agent TUI, etc.), switch the client to the alt screen NOW, BEFORE
    // painting cells. `t.screens.active` is the alt screen in that case, so its
    // cells must land on the client's alt screen. Emitting ?1049h AFTER the
    // paint (as before) entered a freshly-cleared alt screen and wiped the
    // just-painted content -> blank reconnect for every TUI.
    const on_alt = t.modes.get(.alt_screen) or t.modes.get(.alt_screen_save_cursor_clear_enter);
    if (on_alt) try w.writeAll("\x1b[?1049h");

    var cur_style: terminal.Style = .{};

    var row_it = s.pages.rowIterator(.right_down, .{ .viewport = .{} }, null);
    var y: u16 = 0;
    while (row_it.next()) |row_pin| : (y += 1) {
        try w.print("\x1b[{d};1H", .{@as(u32, y) + 1});

        const p: *page.Page = &row_pin.node.data;
        const rac = row_pin.rowAndCell();
        const row = rac.row;
        const page_cells = p.getCells(row);

        var last_content: u16 = 0;
        for (page_cells, 0..) |cell, x| {
            if (cell.codepoint() != 0 or cell.style_id != 0 or
                cell.content_tag == .bg_color_palette or cell.content_tag == .bg_color_rgb)
            {
                last_content = @intCast(x + 1);
            }
        }

        for (page_cells[0..last_content]) |cell| {
            if (cell.wide == .spacer_tail) continue;
            if (cell.wide == .spacer_head) continue;

            const cell_style: terminal.Style = if (cell.style_id != 0)
                p.styles.get(p.memory, cell.style_id).*
            else
                .{};

            if (!cell_style.eql(cur_style)) {
                try emitSGR(w, cell_style);
                cur_style = cell_style;
            }

            const cp = cell.codepoint();
            if (cp == 0) {
                try w.writeByte(' ');
            } else if (cell.content_tag == .codepoint_grapheme) {
                var cp_buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(cp, &cp_buf) catch 0;
                if (len > 0) try w.writeAll(cp_buf[0..len]);
                if (p.lookupGrapheme(&cell)) |extras| {
                    for (extras) |extra_cp| {
                        const elen = std.unicode.utf8Encode(extra_cp, &cp_buf) catch 0;
                        if (elen > 0) try w.writeAll(cp_buf[0..elen]);
                    }
                }
            } else {
                var cp_buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(cp, &cp_buf) catch 0;
                if (len > 0) try w.writeAll(cp_buf[0..len]);
            }
        }
    }

    if (!cur_style.eql(.{})) {
        try w.writeAll("\x1b[0m");
    }

    // --------------------------------------------------------------------
    // Non-default terminal state (modes / charsets / scroll region).
    //
    // The leading "\x1b[0m\x1b[H\x1b[2J" plus the client's fullReset() (driven
    // by the snapshot_begin sentinel) put the client at power-on defaults, so
    // here we only emit DEVIATIONS from the default to keep the snapshot small.
    //
    // Covered (read from the daemon Terminal — terminal/modes.zig + the
    // Terminal/Screen fields):
    //   - DECAWM wraparound          (?7, default ON  -> emit RESET when off)
    //   - insert mode                (4,  default off -> emit SET when on)
    //   - origin mode                (?6, default off -> emit SET when on)
    //   - DECCKM cursor keys         (?1, default off)
    //   - reverse video / colors     (?5, default off)
    //   - bracketed paste            (?2004, default off)
    //   - mouse tracking modes       (?9 / ?1000 / ?1002 / ?1003)
    //   - mouse report format        (?1005 / ?1006 / ?1015 / ?1016)
    //   - focus reporting            (?1004)
    //   - SCS G0 / G1 charset        (ESC ( x / ESC ) x)
    //   - DECSTBM scroll region      (CSI top;bottom r)
    //   - cursor visibility/style/blink and alt-screen (emitted below, as
    //     before).
    //
    // NOT covered: OSC 0/2 window title. The daemon's core Terminal does not
    // store the window title (it is OSC-driven and tracked by the embedder /
    // StreamHandler, not by terminalpkg.Terminal), so there is no
    // authoritative title on terminal_instance to serialize here.
    //
    // Emit structural modes that do NOT move the cursor first; cursor-moving
    // state (DECSTBM, origin) is emitted just before the final cursor CUP so
    // positioning stays correct.

    // DECAWM wraparound: default ON.
    if (!t.modes.get(.wraparound)) try w.writeAll("\x1b[?7l");
    // Insert mode (IRM): default off.
    if (t.modes.get(.insert)) try w.writeAll("\x1b[4h");
    // DECCKM application cursor keys: default off.
    if (t.modes.get(.cursor_keys)) try w.writeAll("\x1b[?1h");
    // Reverse video (DECSCNM): default off.
    if (t.modes.get(.reverse_colors)) try w.writeAll("\x1b[?5h");
    // Bracketed paste: default off.
    if (t.modes.get(.bracketed_paste)) try w.writeAll("\x1b[?2004h");
    // Mouse tracking: default off (emit each enabled tracking mode).
    if (t.modes.get(.mouse_event_x10)) try w.writeAll("\x1b[?9h");
    if (t.modes.get(.mouse_event_normal)) try w.writeAll("\x1b[?1000h");
    if (t.modes.get(.mouse_event_button)) try w.writeAll("\x1b[?1002h");
    if (t.modes.get(.mouse_event_any)) try w.writeAll("\x1b[?1003h");
    // Mouse report format: default off.
    if (t.modes.get(.mouse_format_utf8)) try w.writeAll("\x1b[?1005h");
    if (t.modes.get(.mouse_format_sgr)) try w.writeAll("\x1b[?1006h");
    if (t.modes.get(.mouse_format_urxvt)) try w.writeAll("\x1b[?1015h");
    if (t.modes.get(.mouse_format_sgr_pixels)) try w.writeAll("\x1b[?1016h");
    // Focus reporting: default off.
    if (t.modes.get(.focus_event)) try w.writeAll("\x1b[?1004h");

    // SCS G0/G1 charset designation. Default for both is UTF-8 (no SCS).
    // Map the Charset enum to its final designator byte. utf8 is the
    // default and emits nothing.
    try emitCharsetSCS(w, '(', s.charset.charsets.g0);
    try emitCharsetSCS(w, ')', s.charset.charsets.g1);

    // DECSTBM scroll region. Default is the full screen (top=0,
    // bottom=rows-1). Only emit when it deviates. Note: DECSTBM homes the
    // cursor on the client, so this must precede the final cursor CUP.
    const sr = t.scrolling_region;
    const sr_is_default = sr.top == 0 and sr.bottom == t.rows -| 1;
    if (!sr_is_default) {
        try w.print("\x1b[{d};{d}r", .{
            @as(u32, sr.top) + 1,
            @as(u32, sr.bottom) + 1,
        });
    }

    // Origin mode (DECOM): default off. When set on the client it homes the
    // cursor and makes the subsequent CUP relative to the scroll region, so
    // emit it before the final CUP and translate the cursor coordinates into
    // origin space.
    const origin = t.modes.get(.origin);
    if (origin) try w.writeAll("\x1b[?6h");

    // Final cursor position. In origin mode CUP is relative to the scroll
    // region's top/left; otherwise it is absolute screen coordinates.
    if (origin) {
        const rel_y = @as(u32, s.cursor.y) -| @as(u32, sr.top);
        const rel_x = @as(u32, s.cursor.x) -| @as(u32, sr.left);
        try w.print("\x1b[{d};{d}H", .{ rel_y + 1, rel_x + 1 });
    } else {
        try w.print("\x1b[{d};{d}H", .{
            @as(u32, s.cursor.y) + 1,
            @as(u32, s.cursor.x) + 1,
        });
    }

    if (!t.modes.get(.cursor_visible)) {
        try w.writeAll("\x1b[?25l");
    }

    const blink = t.modes.get(.cursor_blinking);
    const cs: u8 = switch (s.cursor.cursor_style) {
        .block => if (blink) 1 else 2,
        .underline => if (blink) 3 else 4,
        .bar => if (blink) 5 else 6,
        .block_hollow => if (blink) 1 else 2,
    };
    if (cs != 1) {
        try w.print("\x1b[{d} q", .{cs});
    }

    // (Alt-screen switch is emitted EARLY, before the cell paint — see `on_alt`
    // above. Emitting it here, after the paint, wiped the content.)

    return buf.toOwnedSlice(alloc);
}

/// Emit an SCS (Select Character Set) designation for a single G-slot.
/// `slot_byte` is '(' for G0 or ')' for G1. The default charset is UTF-8,
/// which requires no SCS sequence, so this emits nothing for utf8.
fn emitCharsetSCS(w: anytype, slot_byte: u8, cs: terminal.Charset) !void {
    const final: u8 = switch (cs) {
        .utf8 => return, // default; nothing to emit
        .ascii => 'B',
        .british => 'A',
        .dec_special => '0',
    };
    try w.print("\x1b{c}{c}", .{ slot_byte, final });
}

fn emitSGR(w: anytype, s: terminal.Style) !void {
    try w.writeAll("\x1b[0");
    if (s.flags.bold) try w.writeAll(";1");
    if (s.flags.faint) try w.writeAll(";2");
    if (s.flags.italic) try w.writeAll(";3");
    switch (s.flags.underline) {
        .none => {},
        .single => try w.writeAll(";4"),
        .double => try w.writeAll(";21"),
        .curly => try w.writeAll(";4:3"),
        .dotted => try w.writeAll(";4:4"),
        .dashed => try w.writeAll(";4:5"),
    }
    if (s.flags.blink) try w.writeAll(";5");
    if (s.flags.inverse) try w.writeAll(";7");
    if (s.flags.invisible) try w.writeAll(";8");
    if (s.flags.strikethrough) try w.writeAll(";9");
    if (s.flags.overline) try w.writeAll(";53");
    try emitColorSGR(w, s.fg_color, 30);
    try emitColorSGR(w, s.bg_color, 40);
    switch (s.underline_color) {
        .none => {},
        .palette => |idx| try w.print(";58;5;{d}", .{idx}),
        .rgb => |rgb| try w.print(";58;2;{d};{d};{d}", .{ rgb.r, rgb.g, rgb.b }),
    }
    try w.writeByte('m');
}

fn emitColorSGR(w: anytype, color: terminal.Style.Color, base: u8) !void {
    switch (color) {
        .none => {},
        .palette => |idx| {
            if (idx < 8) {
                try w.print(";{d}", .{base + idx});
            } else if (idx < 16) {
                try w.print(";{d}", .{base + 60 + idx - 8});
            } else {
                try w.print(";{d};5;{d}", .{ base + 8, idx });
            }
        },
        .rgb => |rgb| {
            try w.print(";{d};2;{d};{d};{d}", .{ base + 8, rgb.r, rgb.g, rgb.b });
        },
    }
}
