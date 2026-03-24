//! RemoteSession: the headless ghostty terminal for remote sessions.
//!
//! The daemon owns a full Terminal instance that is the source of truth
//! for terminal state. PTY output is fed through HeadlessStreamHandler
//! to keep this Terminal up to date. Raw PTY bytes are forwarded to the
//! attached client as .data_out frames — the client's own VT parser
//! handles rendering independently.
//!
//! On reconnect, the daemon's Terminal viewport is serialized as VT
//! escape sequences and sent as a .data_out frame, allowing the new
//! client to rebuild the screen naturally via processOutput.
//!
//! Threading model:
//!   - readerMain thread: reads PTY → feeds Terminal → forwards raw bytes
//!   - ClientThread (from daemon): calls attachAndServe which reads client frames
//!   - The `mutex` protects: terminal_instance, viewers, controller_id, alive.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page = terminal.page;
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;
const page_diff = @import("page_diff.zig");
const session = @import("../session.zig");
const ptypkg = @import("../pty.zig");
const Pty = ptypkg.Pty;
const Command = @import("../Command.zig");

const log = std.log.scoped(.remote_session);

pub const Uuid = session.shared.Uuid;

pub const RemoteSession = struct {
    alloc: Allocator,
    id: []u8,
    label: []u8,
    surface_id: Uuid,
    pty: Pty,
    command: Command,
    terminal_instance: Terminal,
    stream: HeadlessHandler.Stream,

    /// Optional back-reference to the owning SessionGroup.
    /// Set when the session belongs to a multi-surface group.
    /// Used by attachAndServe to store layout blobs.
    group: ?*SessionGroup = null,

    /// Protects: terminal_instance, viewers, controller_id, alive.
    /// Both readerMain and attachAndServe must hold this when accessing
    /// any of these fields.
    mutex: std.Thread.Mutex = .{},

    /// Connected viewers. Multiple clients can view the same surface.
    viewers: std.ArrayList(ViewerSlot),
    /// UUID of the viewer who last sent input (active controller).
    /// Used for UI display and leader-wins size mode.
    controller_id: Uuid = session.shared.zero_uuid,
    /// Size negotiation mode for this surface.
    size_mode: session.protocol.SizeMode = .smallest_wins,

    created_at: i64,
    alive: bool = true,
    /// Set to true when the client sends close(surface) (permanent close, not detach).
    closed: bool = false,
    reader_thread: std.Thread = undefined,

    pub const SessionGroup = @import("helper.zig").SessionGroup;

    pub const ViewerSlot = struct {
        fd: posix.fd_t,
        target: u16,
        viewer_id: Uuid,
        label: []const u8,
        rows: u16,
        cols: u16,
    };

    /// Number of rows to serialize per scrollback chunk. Targets ~64KB.
    const scrollback_chunk_rows: u16 = 90;

    /// Count the number of scrollback history rows in this session's terminal.
    /// Must be called with mutex held.
    pub fn computeHistoryRows(self: *RemoteSession) u32 {
        const s: *Screen = self.terminal_instance.screens.active;
        var total: u32 = 0;
        var row_it = s.pages.rowIterator(.right_down, .{ .history = .{} }, null);
        while (row_it.next()) |_| {
            total += 1;
        }
        return total;
    }

    /// Find a viewer by fd. Must be called with mutex held.
    pub fn findViewer(self: *RemoteSession, fd: posix.fd_t) ?*ViewerSlot {
        for (self.viewers.items) |*v| {
            if (v.fd == fd) return v;
        }
        return null;
    }

    /// Remove a viewer by fd. Must be called with mutex held.
    fn removeViewer(self: *RemoteSession, fd: posix.fd_t) void {
        var i: usize = 0;
        while (i < self.viewers.items.len) {
            if (self.viewers.items[i].fd == fd) {
                _ = self.viewers.swapRemove(i);
                return;
            }
            i += 1;
        }
    }

    /// Recalculate and apply PTY size based on all viewers and current mode.
    /// Must be called with mutex held.
    fn recalculateSize(self: *RemoteSession) void {
        if (self.viewers.items.len == 0) return;
        switch (self.size_mode) {
            .smallest_wins => {
                var rows: u16 = std.math.maxInt(u16);
                var cols: u16 = std.math.maxInt(u16);
                for (self.viewers.items) |v| {
                    rows = @min(rows, v.rows);
                    cols = @min(cols, v.cols);
                }
                self.pty.setSize(.{
                    .ws_row = rows,
                    .ws_col = cols,
                    .ws_xpixel = 0,
                    .ws_ypixel = 0,
                }) catch {};
            },
            .leader_wins => {
                // Leader is whoever has control (controller_id).
                for (self.viewers.items) |v| {
                    if (std.mem.eql(u8, &v.viewer_id, &self.controller_id)) {
                        self.pty.setSize(.{
                            .ws_row = v.rows,
                            .ws_col = v.cols,
                            .ws_xpixel = 0,
                            .ws_ypixel = 0,
                        }) catch {};
                        return;
                    }
                }
                // No controller found — use first viewer's size.
                self.pty.setSize(.{
                    .ws_row = self.viewers.items[0].rows,
                    .ws_col = self.viewers.items[0].cols,
                    .ws_xpixel = 0,
                    .ws_ypixel = 0,
                }) catch {};
            },
        }
    }

    pub fn deinit(self: *RemoteSession) void {
        self.viewers.deinit(self.alloc);
        self.stream.handler.deinit();
        self.terminal_instance.deinit(self.alloc);
        closeFd(self.pty.master);
        self.alloc.free(self.command.path);
        self.alloc.free(self.command.args);
        self.alloc.free(self.id);
        self.alloc.free(self.label);
        self.alloc.destroy(self);
    }

    pub fn kill(self: *RemoteSession) void {
        if (self.command.pid) |pid| _ = posix.kill(pid, posix.SIG.TERM) catch {};
    }

    /// Reader thread: reads PTY output, feeds the headless Terminal,
    /// and forwards raw bytes to the attached client as .data_out frames.
    pub fn readerMain(self: *RemoteSession) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = posix.read(self.pty.master, &buf) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => break,
            };
            if (n == 0) break;

            self.mutex.lock();

            // Feed headless terminal (the source of truth for this session)
            self.stream.nextSlice(buf[0..n]);

            // Forward raw bytes to all attached viewers
            // TODO: Replace with structured page diffs (Phase 4)
            for (self.viewers.items) |viewer| {
                sendFrameFd(viewer.fd, .data_out, viewer.target, buf[0..n]) catch {};
            }

            self.mutex.unlock();
        }

        self.mutex.lock();
        self.alive = false;
        for (self.viewers.items) |viewer| {
            sendFrameFd(viewer.fd, .eof, viewer.target, "") catch {};
        }
        self.mutex.unlock();
        _ = self.command.wait(false) catch {};
    }

    /// Attach a client and begin serving.
    pub fn attachAndServe(
        self: *RemoteSession,
        fd: posix.fd_t,
        target: u16,
        resize: session.protocol.Resize,
    ) !void {
        // Generate a viewer ID for this connection.
        const viewer_id = session.shared.generateUuid();

        self.mutex.lock();

        // Add viewer to list — multi-viewer: no rejection.
        self.viewers.append(self.alloc, .{
            .fd = fd,
            .target = target,
            .viewer_id = viewer_id,
            .label = "", // TODO: pass from Open frame
            .rows = resize.rows,
            .cols = resize.cols,
        }) catch {
            self.mutex.unlock();
            return error.OutOfMemory;
        };

        // First viewer gets implicit control.
        if (self.viewers.items.len == 1) {
            self.controller_id = viewer_id;
        }

        // Recalculate PTY size based on all viewers.
        self.recalculateSize();

        // Generate and send VT snapshot BEFORE enabling live forwarding
        const vt_snapshot = serializeViewportAsVT(self.alloc, &self.terminal_instance) catch |err| {
            self.removeViewer(fd);
            self.mutex.unlock();
            return err;
        };
        defer self.alloc.free(vt_snapshot);

        // Capture history state for background streaming
        const total_history = self.computeHistoryRows();
        const cols = self.terminal_instance.cols;

        if (vt_snapshot.len > 0) {
            sendFrameFd(fd, .data_out, target, vt_snapshot) catch |err| {
                self.removeViewer(fd);
                self.mutex.unlock();
                return err;
            };
        }

        self.mutex.unlock();

        var history_sent: u32 = 0;

        // Frame read loop with interleaved scrollback streaming.
        // Uses a read buffer and non-blocking check for client frames.
        var frame_buf = std.ArrayList(u8).empty;
        defer frame_buf.deinit(self.alloc);

        while (true) {
            // Process any complete frames from the buffer first
            if (self.processClientFrames(&frame_buf)) break;

            // If scrollback streaming is not done, check if we can send a chunk.
            // Use poll with timeout=0 to check for pending input without blocking.
            if (history_sent < total_history) {
                var pollfds = [1]posix.pollfd{
                    .{ .fd = fd, .events = posix.POLL.IN, .revents = undefined },
                };
                const poll_result = posix.poll(&pollfds, 0) catch 0;

                if (poll_result == 0) {
                    // No pending input — send next scrollback chunk
                    self.sendScrollbackChunk(fd, target, total_history, &history_sent, cols);
                    continue;
                }
                // Fall through to read pending data
            }

            // Block waiting for client input
            var read_buf: [4096]u8 = undefined;
            const n = posix.read(fd, &read_buf) catch break;
            if (n == 0) break;
            frame_buf.appendSlice(self.alloc, read_buf[0..n]) catch break;
        }

        self.mutex.lock();
        self.removeViewer(fd);
        // If the disconnected viewer was the controller, clear it.
        if (std.mem.eql(u8, &self.controller_id, &viewer_id)) {
            self.controller_id = session.shared.zero_uuid;
        }
        self.recalculateSize();
        self.mutex.unlock();
    }

    /// Send one scrollback chunk to the client.
    fn sendScrollbackChunk(
        self: *RemoteSession,
        fd: posix.fd_t,
        target: u16,
        total_history: u32,
        history_sent: *u32,
        cols: u16,
    ) void {
        self.mutex.lock();
        const chunk = page_diff.serializeScrollbackChunk(
            self.alloc,
            &self.terminal_instance,
            history_sent.*,
            scrollback_chunk_rows,
        ) catch {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        defer self.alloc.free(chunk.data);

        if (chunk.rows_serialized == 0) {
            // Send done marker
            history_sent.* = total_history;
            const done_resp = session.protocol.ScrollbackResponse{
                .total_history_rows = total_history,
                .chunk_start_row = history_sent.*,
                .row_count = 0,
                .cols = cols,
                .chunk_data = "",
            };
            const done_payload = done_resp.encode(self.alloc) catch return;
            defer self.alloc.free(done_payload);
            sendFrameFd(fd, .scrollback_response, target, done_payload) catch {};
            return;
        }

        const resp = session.protocol.ScrollbackResponse{
            .total_history_rows = total_history,
            .chunk_start_row = history_sent.*,
            .row_count = chunk.rows_serialized,
            .cols = cols,
            .chunk_data = chunk.data,
        };
        const resp_payload = resp.encode(self.alloc) catch return;
        defer self.alloc.free(resp_payload);
        sendFrameFd(fd, .scrollback_response, target, resp_payload) catch {};

        history_sent.* += chunk.rows_serialized;

        // If we just finished, send done marker
        if (history_sent.* >= total_history) {
            const done_resp = session.protocol.ScrollbackResponse{
                .total_history_rows = total_history,
                .chunk_start_row = history_sent.*,
                .row_count = 0,
                .cols = cols,
                .chunk_data = "",
            };
            const done_payload = done_resp.encode(self.alloc) catch return;
            defer self.alloc.free(done_payload);
            sendFrameFd(fd, .scrollback_response, target, done_payload) catch {};
        }
    }

    /// Process complete frames from the client input buffer.
    /// Returns true if the connection should be closed.
    fn processClientFrames(
        self: *RemoteSession,
        frame_buf: *std.ArrayList(u8),
    ) bool {
        while (frame_buf.items.len >= session.protocol.header_size) {
            const header = session.protocol.Header.parseFromBuf(
                frame_buf.items[0..session.protocol.header_size],
            ) catch {
                shiftBuf(frame_buf, session.protocol.header_size);
                continue;
            };
            const total = session.protocol.header_size + header.len;
            if (frame_buf.items.len < total) break;

            if (header.len > session.protocol.max_payload) {
                shiftBuf(frame_buf, total);
                continue;
            }

            const kind = header.kind;
            const payload = frame_buf.items[session.protocol.header_size..total];

            switch (kind) {
                .data_in => _ = posix.write(self.pty.master, payload) catch |err| {
                    log.warn("session write failed id={s} err={}", .{ self.id, err });
                    shiftBuf(frame_buf, total);
                    return true;
                },
                .resize => {
                    const parsed = session.protocol.Resize.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        return true;
                    };
                    // width_px and height_px are allowed to be 0 ("unknown"), used
                    // during reconnect and by terminals that don't report pixel size.
                    if (parsed.rows == 0 or parsed.cols == 0 or
                        parsed.rows > 10000 or parsed.cols > 10000 or
                        parsed.width_px > 100000 or parsed.height_px > 100000)
                    {
                        log.warn("invalid resize values: {}x{} ({}x{} px)", .{
                            parsed.cols, parsed.rows, parsed.width_px, parsed.height_px,
                        });
                    } else {
                        self.pty.setSize(.{
                            .ws_row = parsed.rows,
                            .ws_col = parsed.cols,
                            .ws_xpixel = parsed.width_px,
                            .ws_ypixel = parsed.height_px,
                        }) catch {};
                    }
                },
                .layout => {
                    if (payload.len <= 64 * 1024) {
                        if (self.group) |group| {
                            group.updateLayout(self.alloc, payload);
                        }
                    }
                },
                .close => {
                    const close_data = session.protocol.Close.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        return true;
                    };
                    switch (close_data.mode) {
                        .surface, .session => {
                            self.closed = true;
                            shiftBuf(frame_buf, total);
                            return true;
                        },
                        .detach => {
                            shiftBuf(frame_buf, total);
                            return true;
                        },
                    }
                },
                else => {},
            }

            shiftBuf(frame_buf, total);
        }
        return false;
    }

    const shiftBuf = session.shared.shiftBuffer;
};

/// Serialize the Terminal's viewport as VT escape sequences.
fn serializeViewportAsVT(alloc: Allocator, t: *Terminal) ![]u8 {
    const s: *Screen = t.screens.active;

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    // Reset client state: clear screen, reset attributes, home cursor
    try w.writeAll("\x1b[0m\x1b[H\x1b[2J");

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

    try w.print("\x1b[{d};{d}H", .{
        @as(u32, s.cursor.y) + 1,
        @as(u32, s.cursor.x) + 1,
    });

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

    if (t.modes.get(.alt_screen) or t.modes.get(.alt_screen_save_cursor_clear_enter)) {
        try w.writeAll("\x1b[?1049h");
    }

    return buf.toOwnedSlice(alloc);
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

fn sendFrameFd(fd: posix.fd_t, kind: session.protocol.Kind, target: u16, payload: []const u8) !void {
    var file: std.fs.File = .{ .handle = fd };
    var wbuf: [1024]u8 = undefined;
    var writer_ = file.writerStreaming(&wbuf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, kind, target, payload);
    try writer.flush();
}

fn closeFd(fd: posix.fd_t) void {
    posix.close(fd);
}
