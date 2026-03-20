//! A lightweight Stream handler that drives a Terminal without any
//! renderer, surface, or mailbox dependencies. Designed for headless
//! operation in the remote session daemon where we need to process VT
//! sequences and update Terminal state but have no GUI.
//!
//! Write-back responses (DA, DSR, etc.) are collected in a buffer that
//! the caller can drain and send to the PTY.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const terminal = @import("../terminal/main.zig");
const terminfo = @import("../terminfo/main.zig");
const build_config = @import("../build_config.zig");

const log = std.log.scoped(.headless_handler);

pub const HeadlessHandler = struct {
    alloc: Allocator,
    terminal: *terminal.Terminal,
    /// File descriptor for writing responses back to the PTY.
    /// Used for DA, DSR, XTVERSION, and other query responses.
    pty_fd: posix.fd_t,

    // Minimal config
    enquiry_response: []const u8 = "",
    default_cursor_style: terminal.CursorStyle = .block,
    default_cursor_blink: ?bool = null,
    default_cursor: bool = true,

    // DCS/APC state
    apc: terminal.apc.Handler = .{},
    dcs: terminal.dcs.Handler = .{},

    pub const Stream = terminal.Stream(HeadlessHandler);

    pub fn deinit(self: *HeadlessHandler) void {
        self.apc.deinit();
        self.dcs.deinit();
    }

    pub fn vt(
        self: *HeadlessHandler,
        comptime action: Stream.Action.Tag,
        value: Stream.Action.Value(action),
    ) void {
        self.vtFallible(action, value) catch |err| {
            log.warn("error handling VT action action={} err={}", .{ action, err });
        };
    }

    inline fn vtFallible(
        self: *HeadlessHandler,
        comptime action: Stream.Action.Tag,
        value: Stream.Action.Value(action),
    ) !void {
        switch (action) {
            // -- Direct Terminal calls (hot path) --
            .print => {
                @branchHint(.likely);
                try self.terminal.print(value.cp);
            },
            .print_repeat => try self.terminal.printRepeat(value),
            .backspace => self.terminal.backspace(),
            .carriage_return => {
                @branchHint(.likely);
                self.terminal.carriageReturn();
            },
            .linefeed => {
                @branchHint(.likely);
                try self.terminal.index();
            },
            .cursor_pos => {
                @branchHint(.likely);
                self.terminal.setCursorPos(value.row, value.col);
            },
            .set_attribute => {
                @branchHint(.likely);
                switch (value) {
                    .unknown => {},
                    else => {
                        self.terminal.setAttribute(value) catch |err| {
                            log.warn("error setting attribute {}: {}", .{ value, err });
                        };
                    },
                }
            },

            // -- Cursor movement --
            .cursor_up => self.terminal.cursorUp(value.value),
            .cursor_down => self.terminal.cursorDown(value.value),
            .cursor_left => self.terminal.cursorLeft(value.value),
            .cursor_right => self.terminal.cursorRight(value.value),
            .cursor_col => self.terminal.setCursorPos(self.terminal.screens.active.cursor.y + 1, value.value),
            .cursor_row => self.terminal.setCursorPos(value.value, self.terminal.screens.active.cursor.x + 1),
            .cursor_col_relative => self.terminal.setCursorPos(
                self.terminal.screens.active.cursor.y + 1,
                self.terminal.screens.active.cursor.x + 1 +| value.value,
            ),
            .cursor_row_relative => self.terminal.setCursorPos(
                self.terminal.screens.active.cursor.y + 1 +| value.value,
                self.terminal.screens.active.cursor.x + 1,
            ),
            .cursor_style => try self.setCursorStyle(value),
            .save_cursor => self.terminal.saveCursor(),
            .restore_cursor => self.terminal.restoreCursor(),

            // -- Erase operations --
            .erase_display_below => self.terminal.eraseDisplay(.below, value),
            .erase_display_above => self.terminal.eraseDisplay(.above, value),
            .erase_display_complete => {
                self.terminal.scrollViewport(.{ .bottom = {} });
                self.terminal.eraseDisplay(.complete, value);
            },
            .erase_display_scrollback => self.terminal.eraseDisplay(.scrollback, value),
            .erase_display_scroll_complete => self.terminal.eraseDisplay(.scroll_complete, value),
            .erase_line_right => self.terminal.eraseLine(.right, value),
            .erase_line_left => self.terminal.eraseLine(.left, value),
            .erase_line_complete => self.terminal.eraseLine(.complete, value),
            .erase_line_right_unless_pending_wrap => self.terminal.eraseLine(.right_unless_pending_wrap, value),
            .erase_chars => self.terminal.eraseChars(value),
            .delete_chars => self.terminal.deleteChars(value),

            // -- Line/char manipulation --
            .insert_lines => self.terminal.insertLines(value),
            .insert_blanks => self.terminal.insertBlanks(value),
            .delete_lines => self.terminal.deleteLines(value),
            .scroll_up => try self.terminal.scrollUp(value),
            .scroll_down => self.terminal.scrollDown(value),

            // -- Tabs --
            .horizontal_tab => self.horizontalTab(value),
            .horizontal_tab_back => self.horizontalTabBack(value),
            .tab_clear_current => self.terminal.tabClear(.current),
            .tab_clear_all => self.terminal.tabClear(.all),
            .tab_set => self.terminal.tabSet(),
            .tab_reset => self.terminal.tabReset(),

            // -- Index/movement --
            .index => try self.terminal.index(),
            .next_line => {
                try self.terminal.index();
                self.terminal.carriageReturn();
            },
            .reverse_index => self.terminal.reverseIndex(),

            // -- Modes --
            .set_mode => try self.setMode(value.mode, true),
            .reset_mode => try self.setMode(value.mode, false),
            .save_mode => self.terminal.modes.save(value.mode),
            .restore_mode => {
                const v = self.terminal.modes.restore(value.mode);
                try self.setMode(value.mode, v);
            },

            // -- Margins --
            .top_and_bottom_margin => self.terminal.setTopAndBottomMargin(value.top_left, value.bottom_right),
            .left_and_right_margin => self.terminal.setLeftAndRightMargin(value.top_left, value.bottom_right),
            .left_and_right_margin_ambiguous => {
                if (self.terminal.modes.get(.enable_left_and_right_margin)) {
                    self.terminal.setLeftAndRightMargin(0, 0);
                } else {
                    self.terminal.saveCursor();
                }
            },

            // -- Charset --
            .invoke_charset => self.terminal.invokeCharset(value.bank, value.charset, value.locking),
            .configure_charset => self.terminal.configureCharset(value.slot, value.charset),

            // -- Kitty keyboard --
            .kitty_keyboard_push => self.terminal.screens.active.kitty_keyboard.push(value.flags),
            .kitty_keyboard_pop => self.terminal.screens.active.kitty_keyboard.pop(@intCast(value)),
            .kitty_keyboard_set => self.terminal.screens.active.kitty_keyboard.set(.set, value.flags),
            .kitty_keyboard_set_or => self.terminal.screens.active.kitty_keyboard.set(.@"or", value.flags),
            .kitty_keyboard_set_not => self.terminal.screens.active.kitty_keyboard.set(.not, value.flags),

            // -- Protection modes --
            .protected_mode_off => self.terminal.setProtectedMode(.off),
            .protected_mode_iso => self.terminal.setProtectedMode(.iso),
            .protected_mode_dec => self.terminal.setProtectedMode(.dec),

            // -- Mouse --
            .mouse_shift_capture => self.terminal.flags.mouse_shift_capture = if (value) .true else .false,

            // -- Hyperlinks --
            .start_hyperlink => try self.terminal.screens.active.startHyperlink(value.uri, value.id),
            .end_hyperlink => self.terminal.screens.active.endHyperlink(),

            // -- Misc terminal state --
            .active_status_display => self.terminal.status_display = value,
            .decaln => try self.terminal.decaln(),
            .full_reset => self.terminal.fullReset(),
            .semantic_prompt => try self.terminal.semanticPrompt(value),
            .modify_key_format => {
                self.terminal.flags.modify_other_keys_2 = false;
                switch (value) {
                    .other_keys_numeric => self.terminal.flags.modify_other_keys_2 = true,
                    else => {},
                }
            },

            // -- Write-back responses (need PTY fd) --
            .enquiry => self.writePty(self.enquiry_response),
            .device_attributes => try self.deviceAttributes(value),
            .device_status => try self.deviceStatusReport(value.request),
            .xtversion => try self.reportXtversion(),
            .request_mode => try self.requestMode(value.mode),
            .request_mode_unknown => try self.requestModeUnknown(value.mode, value.ansi),
            .kitty_keyboard_query => try self.queryKittyKeyboard(),
            .size_report => {}, // No surface to measure pixel size
            .kitty_color_report => try self.kittyColorReport(value),
            .color_operation => try self.colorOperation(value.op, &value.requests, value.terminator),
            .clipboard_contents => {}, // No clipboard in headless

            // -- DCS/APC --
            .dcs_hook => try self.dcsHook(value),
            .dcs_put => try self.dcsPut(value),
            .dcs_unhook => try self.dcsUnhook(),
            .apc_start => self.apc.start(),
            .apc_end => try self.apcEnd(),
            .apc_put => self.apc.feed(self.alloc, value),

            // -- Stub (UI-only, no-op in headless) --
            .bell,
            .window_title,
            .report_pwd,
            .show_desktop_notification,
            .progress_report,
            .mouse_shape,
            .title_push,
            .title_pop,
            => {},
        }
    }

    // -- Private helpers --

    fn writePty(self: *HeadlessHandler, data: []const u8) void {
        if (data.len == 0) return;
        _ = posix.write(self.pty_fd, data) catch |err| {
            log.warn("pty write failed: {}", .{err});
        };
    }

    fn writePtyBuf(self: *HeadlessHandler, data: []const u8, len: usize) void {
        if (len == 0) return;
        _ = posix.write(self.pty_fd, data[0..len]) catch |err| {
            log.warn("pty write failed: {}", .{err});
        };
    }

    inline fn horizontalTab(self: *HeadlessHandler, count: u16) void {
        for (0..count) |_| {
            const x = self.terminal.screens.active.cursor.x;
            self.terminal.horizontalTab();
            if (x == self.terminal.screens.active.cursor.x) break;
        }
    }

    inline fn horizontalTabBack(self: *HeadlessHandler, count: u16) void {
        for (0..count) |_| {
            const x = self.terminal.screens.active.cursor.x;
            self.terminal.horizontalTabBack();
            if (x == self.terminal.screens.active.cursor.x) break;
        }
    }

    fn setCursorStyle(self: *HeadlessHandler, style: terminal.CursorStyleReq) !void {
        self.default_cursor = false;
        switch (style) {
            .default => {
                self.default_cursor = true;
                self.terminal.screens.active.cursor.cursor_style = self.default_cursor_style;
                self.terminal.modes.set(.cursor_blinking, self.default_cursor_blink orelse true);
            },
            .blinking_block => {
                self.terminal.screens.active.cursor.cursor_style = .block;
                self.terminal.modes.set(.cursor_blinking, true);
            },
            .steady_block => {
                self.terminal.screens.active.cursor.cursor_style = .block;
                self.terminal.modes.set(.cursor_blinking, false);
            },
            .blinking_underline => {
                self.terminal.screens.active.cursor.cursor_style = .underline;
                self.terminal.modes.set(.cursor_blinking, true);
            },
            .steady_underline => {
                self.terminal.screens.active.cursor.cursor_style = .underline;
                self.terminal.modes.set(.cursor_blinking, false);
            },
            .blinking_bar => {
                self.terminal.screens.active.cursor.cursor_style = .bar;
                self.terminal.modes.set(.cursor_blinking, true);
            },
            .steady_bar => {
                self.terminal.screens.active.cursor.cursor_style = .bar;
                self.terminal.modes.set(.cursor_blinking, false);
            },
        }
    }

    fn setMode(self: *HeadlessHandler, mode: terminal.Mode, enabled: bool) !void {
        if (mode == .cursor_blinking and self.default_cursor_blink != null) return;

        self.terminal.modes.set(mode, enabled);

        switch (mode) {
            .origin => self.terminal.setCursorPos(1, 1),
            .enable_left_and_right_margin => if (!enabled) {
                self.terminal.scrolling_region.left = 0;
                self.terminal.scrolling_region.right = self.terminal.cols - 1;
            },
            .alt_screen_legacy => try self.terminal.switchScreenMode(.@"47", enabled),
            .alt_screen => try self.terminal.switchScreenMode(.@"1047", enabled),
            .alt_screen_save_cursor_clear_enter => try self.terminal.switchScreenMode(.@"1049", enabled),
            .save_cursor => if (enabled) self.terminal.saveCursor() else self.terminal.restoreCursor(),
            .@"132_column" => try self.terminal.deccolm(
                self.alloc,
                if (enabled) .@"132_cols" else .@"80_cols",
            ),
            // Mouse modes: update terminal state only (no surface notification)
            .mouse_event_x10 => self.terminal.flags.mouse_event = if (enabled) .x10 else .none,
            .mouse_event_normal => self.terminal.flags.mouse_event = if (enabled) .normal else .none,
            .mouse_event_button => self.terminal.flags.mouse_event = if (enabled) .button else .none,
            .mouse_event_any => self.terminal.flags.mouse_event = if (enabled) .any else .none,
            .mouse_format_utf8 => self.terminal.flags.mouse_format = if (enabled) .utf8 else .x10,
            .mouse_format_sgr => self.terminal.flags.mouse_format = if (enabled) .sgr else .x10,
            .mouse_format_urxvt => self.terminal.flags.mouse_format = if (enabled) .urxvt else .x10,
            .mouse_format_sgr_pixels => self.terminal.flags.mouse_format = if (enabled) .sgr_pixels else .x10,
            .reverse_colors => self.terminal.flags.dirty.reverse_colors = true,
            else => {},
        }
    }

    // -- Write-back response methods --

    fn deviceAttributes(self: *HeadlessHandler, req: terminal.DeviceAttributeReq) !void {
        switch (req) {
            .primary => self.writePty("\x1B[?62;22c"),
            .secondary => self.writePty("\x1B[>1;10;0c"),
            else => {},
        }
    }

    fn deviceStatusReport(self: *HeadlessHandler, req: terminal.device_status.Request) !void {
        switch (req) {
            .operating_status => self.writePty("\x1B[0n"),
            .cursor_position => {
                var pos_x: usize = undefined;
                var pos_y: usize = undefined;
                if (self.terminal.modes.get(.origin)) {
                    pos_x = self.terminal.screens.active.cursor.x -| self.terminal.scrolling_region.left;
                    pos_y = self.terminal.screens.active.cursor.y -| self.terminal.scrolling_region.top;
                } else {
                    pos_x = self.terminal.screens.active.cursor.x;
                    pos_y = self.terminal.screens.active.cursor.y;
                }

                var buf: [32]u8 = undefined;
                const resp = try std.fmt.bufPrint(&buf, "\x1B[{};{}R", .{ pos_y + 1, pos_x + 1 });
                self.writePty(resp);
            },
            .color_scheme => {}, // No surface to query
        }
    }

    fn reportXtversion(self: *HeadlessHandler) !void {
        var buf: [288]u8 = undefined;
        const resp = try std.fmt.bufPrint(&buf, "\x1BP>|{s} {s}\x1B\\", .{
            "ghostty",
            build_config.version_string,
        });
        self.writePty(resp);
    }

    fn requestMode(self: *HeadlessHandler, mode: terminal.Mode) !void {
        const tag: terminal.modes.ModeTag = @bitCast(@intFromEnum(mode));
        const code: u8 = if (self.terminal.modes.get(mode)) 1 else 2;
        var buf: [32]u8 = undefined;
        const resp = try std.fmt.bufPrint(&buf, "\x1B[{s}{};{}$y", .{
            if (tag.ansi) "" else "?",
            tag.value,
            code,
        });
        self.writePty(resp);
    }

    fn requestModeUnknown(self: *HeadlessHandler, mode_raw: u16, ansi: bool) !void {
        var buf: [32]u8 = undefined;
        const resp = try std.fmt.bufPrint(&buf, "\x1B[{s}{};0$y", .{
            if (ansi) "" else "?",
            mode_raw,
        });
        self.writePty(resp);
    }

    fn queryKittyKeyboard(self: *HeadlessHandler) !void {
        var buf: [32]u8 = undefined;
        const resp = try std.fmt.bufPrint(&buf, "\x1b[?{}u", .{
            self.terminal.screens.active.kitty_keyboard.current().int(),
        });
        self.writePty(resp);
    }

    fn kittyColorReport(self: *HeadlessHandler, request: terminal.kitty.color.OSC) !void {
        // Process sets and resets (state changes) but skip query responses
        // since we have no surface colors to report.
        for (request.list.items) |item| {
            switch (item) {
                .set => |v| switch (v.key) {
                    .palette => |palette| {
                        self.terminal.flags.dirty.palette = true;
                        self.terminal.colors.palette.set(palette, v.color);
                    },
                    .special => |special| switch (special) {
                        .foreground => self.terminal.colors.foreground.set(v.color),
                        .background => self.terminal.colors.background.set(v.color),
                        .cursor => self.terminal.colors.cursor.set(v.color),
                        else => {},
                    },
                },
                .reset => |key| switch (key) {
                    .palette => |palette| {
                        self.terminal.flags.dirty.palette = true;
                        self.terminal.colors.palette.reset(palette);
                    },
                    .special => |special| switch (special) {
                        .foreground => self.terminal.colors.foreground.reset(),
                        .background => self.terminal.colors.background.reset(),
                        .cursor => self.terminal.colors.cursor.reset(),
                        else => {},
                    },
                },
                .query => {},
            }
        }
    }

    fn colorOperation(
        self: *HeadlessHandler,
        op: terminal.osc.color.Operation,
        requests: *const terminal.osc.color.List,
        terminator: terminal.osc.Terminator,
    ) !void {
        _ = op;
        _ = terminator;
        if (requests.count() == 0) return;

        var it = requests.constIterator(0);
        while (it.next()) |req| {
            switch (req.*) {
                .set => |set| switch (set.target) {
                    .palette => |i| {
                        self.terminal.flags.dirty.palette = true;
                        self.terminal.colors.palette.set(i, set.color);
                    },
                    .dynamic => |dynamic| switch (dynamic) {
                        .foreground => self.terminal.colors.foreground.set(set.color),
                        .background => self.terminal.colors.background.set(set.color),
                        .cursor => self.terminal.colors.cursor.set(set.color),
                        else => {},
                    },
                    .special => {},
                },
                .reset => |target| switch (target) {
                    .palette => |i| {
                        self.terminal.flags.dirty.palette = true;
                        self.terminal.colors.palette.reset(i);
                    },
                    .dynamic => |dynamic| switch (dynamic) {
                        .foreground => self.terminal.colors.foreground.reset(),
                        .background => self.terminal.colors.background.reset(),
                        .cursor => self.terminal.colors.cursor.reset(),
                        else => {},
                    },
                    .special => {},
                },
                .reset_palette => {
                    const mask = &self.terminal.colors.palette.mask;
                    var mask_it = mask.iterator(.{});
                    while (mask_it.next()) |i| {
                        self.terminal.flags.dirty.palette = true;
                        self.terminal.colors.palette.reset(@intCast(i));
                    }
                    mask.* = .initEmpty();
                },
                .reset_special => {},
                .query => {}, // No color report in headless
            }
        }
    }

    // -- DCS/APC --

    inline fn dcsHook(self: *HeadlessHandler, dcs: terminal.DCS) !void {
        var cmd = self.dcs.hook(self.alloc, dcs) orelse return;
        defer cmd.deinit();
        try self.dcsCommand(&cmd);
    }

    inline fn dcsPut(self: *HeadlessHandler, byte: u8) !void {
        var cmd = self.dcs.put(byte) orelse return;
        defer cmd.deinit();
        try self.dcsCommand(&cmd);
    }

    inline fn dcsUnhook(self: *HeadlessHandler) !void {
        var cmd = self.dcs.unhook() orelse return;
        defer cmd.deinit();
        try self.dcsCommand(&cmd);
    }

    fn dcsCommand(self: *HeadlessHandler, cmd: *terminal.dcs.Command) !void {
        switch (cmd.*) {
            .tmux => {}, // No tmux control mode in headless
            .xtgettcap => |*gettcap| {
                const map = comptime terminfo.ghostty.xtgettcapMap();
                while (gettcap.next()) |key| {
                    const response = map.get(key) orelse continue;
                    self.writePty(response);
                }
            },
            .decrqss => |decrqss| {
                var response: [128]u8 = undefined;
                var stream = std.io.fixedBufferStream(&response);
                const writer = stream.writer();

                const prefix_fmt = "\x1bP{d}$r";
                const prefix_len = std.fmt.comptimePrint(prefix_fmt, .{0}).len;
                stream.pos = prefix_len;

                switch (decrqss) {
                    .none => {},
                    .sgr => {
                        const buf = try self.terminal.printAttributes(stream.buffer[stream.pos..]);
                        stream.pos += buf.len;
                        try writer.writeByte('m');
                    },
                    .decscusr => {
                        const blink = self.terminal.modes.get(.cursor_blinking);
                        const s: u8 = switch (self.terminal.screens.active.cursor.cursor_style) {
                            .block => if (blink) 1 else 2,
                            .underline => if (blink) 3 else 4,
                            .bar => if (blink) 5 else 6,
                            .block_hollow => if (blink) 1 else 2,
                        };
                        try writer.print("{d} q", .{s});
                    },
                    .decstbm => {
                        try writer.print("{d};{d}r", .{
                            self.terminal.scrolling_region.top + 1,
                            self.terminal.scrolling_region.bottom + 1,
                        });
                    },
                    .decslrm => {
                        if (self.terminal.modes.get(.enable_left_and_right_margin)) {
                            try writer.print("{d};{d}s", .{
                                self.terminal.scrolling_region.left + 1,
                                self.terminal.scrolling_region.right + 1,
                            });
                        }
                    },
                }

                const valid = stream.pos > prefix_len;
                try writer.writeAll("\x1b\\");
                _ = try std.fmt.bufPrint(response[0..prefix_len], prefix_fmt, .{@intFromBool(valid)});
                self.writePty(response[0..stream.pos]);
            },
        }
    }

    fn apcEnd(self: *HeadlessHandler) !void {
        var cmd = self.apc.end() orelse return;
        defer cmd.deinit(self.alloc);

        switch (cmd) {
            .kitty => |*kitty_cmd| {
                if (self.terminal.kittyGraphics(self.alloc, kitty_cmd)) |resp| {
                    var buf: [1024]u8 = undefined;
                    var writer: std.Io.Writer = .fixed(&buf);
                    try resp.encode(&writer);
                    const final = writer.buffered();
                    if (final.len > 2) {
                        self.writePty(final);
                    }
                }
            },
        }
    }
};
