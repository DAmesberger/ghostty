//! RemoteSession: the headless ghostty terminal for remote sessions.
//!
//! The daemon owns a full Terminal instance that is the source of truth
//! for terminal state. PTY output is fed through HeadlessStreamHandler
//! to keep this Terminal up to date. Raw PTY bytes are simultaneously
//! forwarded to the attached client as .stdout frames — the client's
//! own VT parser handles rendering independently.
//!
//! On reconnect, the daemon's Terminal viewport is serialized as VT
//! escape sequences and sent as a .state_full frame, allowing the new
//! client to rebuild the screen naturally via processOutput.
//!
//! Threading model:
//!   - readerMain thread: reads PTY → feeds Terminal → forwards raw bytes
//!   - ClientThread (from daemon): calls attachAndServe which reads client frames
//!   - The `mutex` protects: terminal_instance, attached_fd, attached_target, alive.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page = terminal.page;
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;
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
    /// Used by attachAndServe to store layout_update blobs.
    group: ?*SessionGroup = null,

    /// Protects: terminal_instance, attached_fd, attached_target, alive.
    /// Both readerMain and attachAndServe must hold this when accessing
    /// any of these fields.
    mutex: std.Thread.Mutex = .{},
    attached_fd: ?posix.fd_t = null,
    attached_target: u16 = 0,

    created_at: i64,
    alive: bool = true,
    /// Set to true when the client sends surface_close (permanent close, not detach).
    closed: bool = false,
    reader_thread: std.Thread = undefined,

    pub const SessionGroup = @import("helper.zig").SessionGroup;

    pub fn deinit(self: *RemoteSession) void {
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
    /// and forwards raw bytes to the attached client as .stdout frames.
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

            // Forward raw bytes to attached client
            if (self.attached_fd) |fd| {
                sendFrameFd(fd, .stdout, self.attached_target, buf[0..n]) catch {
                    self.attached_fd = null;
                };
            }

            self.mutex.unlock();
        }

        self.mutex.lock();
        self.alive = false;
        if (self.attached_fd) |fd| {
            sendFrameFd(fd, .eof, self.attached_target, "") catch {};
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
        self.mutex.lock();

        if (self.attached_fd != null) {
            self.mutex.unlock();
            return error.SessionAlreadyAttached;
        }

        // Resize PTY so the shell adjusts its output
        self.pty.setSize(.{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.width_px,
            .ws_ypixel = resize.height_px,
        }) catch |err| {
            log.warn("pty resize failed: {}", .{err});
        };

        // Generate and send VT snapshot BEFORE enabling live forwarding
        const vt_snapshot = serializeViewportAsVT(self.alloc, &self.terminal_instance) catch |err| {
            self.mutex.unlock();
            return err;
        };
        defer self.alloc.free(vt_snapshot);

        if (vt_snapshot.len > 0) {
            sendFrameFd(fd, .state_full, target, vt_snapshot) catch |err| {
                self.mutex.unlock();
                return err;
            };
        }

        // NOW enable live forwarding — readerMain will start sending .stdout
        self.attached_fd = fd;
        self.attached_target = target;
        self.mutex.unlock();

        // Frame read loop: handle client input (runs WITHOUT mutex)
        var file: std.fs.File = .{ .handle = fd };
        var reader_buf: [1024]u8 = undefined;
        var reader_ = file.readerStreaming(&reader_buf);
        const reader = &reader_.interface;

        while (true) {
            const header = session.protocol.readHeader(reader) catch break;
            const payload = session.protocol.readPayloadAlloc(self.alloc, reader, header) catch break;
            defer self.alloc.free(payload);

            switch (header.kind) {
                .stdin => _ = posix.write(self.pty.master, payload) catch |err| {
                    log.warn("session write failed id={s} err={}", .{ self.id, err });
                    break;
                },
                .resize => {
                    const parsed = session.protocol.Resize.parse(payload) catch break;
                    // Validate resize values — reject unreasonable sizes
                    if (parsed.rows == 0 or parsed.cols == 0 or
                        parsed.rows > 10000 or parsed.cols > 10000 or
                        parsed.width_px > 100000 or parsed.height_px > 100000)
                    {
                        log.warn("invalid resize values: {}x{} ({}x{} px)", .{
                            parsed.cols, parsed.rows, parsed.width_px, parsed.height_px,
                        });
                        continue; // Skip invalid resize, don't break connection
                    }
                    self.pty.setSize(.{
                        .ws_row = parsed.rows,
                        .ws_col = parsed.cols,
                        .ws_xpixel = parsed.width_px,
                        .ws_ypixel = parsed.height_px,
                    }) catch {};
                },
                .layout_update => {
                    // Validate layout blob size
                    if (payload.len > session.protocol.max_payload or payload.len > 64 * 1024) {
                        log.warn("layout_update too large: {d} bytes", .{payload.len});
                        continue;
                    }
                    // Store layout blob in the owning group (opaque, for reconnect)
                    if (self.group) |group| {
                        group.updateLayout(self.alloc, payload);
                    }
                },
                .surface_close => {
                    self.closed = true;
                    break;
                },
                .detach => break,
                else => {},
            }
        }

        self.mutex.lock();
        if (self.attached_fd == fd) self.attached_fd = null;
        self.mutex.unlock();
    }
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
