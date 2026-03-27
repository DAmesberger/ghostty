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

    pub const SessionGroup = @import("daemon.zig").SessionGroup;

    pub const ViewerSlot = struct {
        fd: posix.fd_t,
        target: u16,
        viewer_id: Uuid,
        label: []const u8,
        rows: u16,
        cols: u16,
        compression_enabled: bool = false,
    };

    /// Number of rows to serialize per scrollback chunk. Targets ~64KB.
    const scrollback_chunk_rows: u16 = 90;

    /// Count the number of scrollback history rows in this session's terminal.
    /// Must be called with mutex held.
    pub fn computeHistoryRows(self: *RemoteSession) u32 {
        const s: *Screen = self.terminal_instance.screens.active;
        const total = s.pages.total_rows;
        const viewport = s.pages.rows;
        return @intCast(if (total > viewport) total - viewport else 0);
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
                const removed = self.viewers.swapRemove(i);
                freeViewerLabel(self.alloc, removed.label);
                return;
            }
            i += 1;
        }
    }

    /// Free a heap-allocated viewer label.
    fn freeViewerLabel(alloc: Allocator, label: []const u8) void {
        if (label.len > 0) alloc.free(@constCast(label));
    }

    /// Recalculate and apply PTY size based on all viewers and current mode.
    /// Must be called with mutex held.
    fn recalculateSize(self: *RemoteSession) void {
        if (self.viewers.items.len == 0) return;
        var rows: u16 = undefined;
        var cols: u16 = undefined;
        switch (self.size_mode) {
            .smallest_wins => {
                rows = std.math.maxInt(u16);
                cols = std.math.maxInt(u16);
                for (self.viewers.items) |v| {
                    rows = @min(rows, v.rows);
                    cols = @min(cols, v.cols);
                }
            },
            .leader_wins => {
                // Leader is whoever has control (controller_id).
                const leader = for (self.viewers.items) |v| {
                    if (std.mem.eql(u8, &v.viewer_id, &self.controller_id)) break v;
                } else self.viewers.items[0];
                rows = leader.rows;
                cols = leader.cols;
            },
        }
        self.pty.setSize(.{
            .ws_row = rows,
            .ws_col = cols,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        }) catch {};
    }

    /// Force-disconnect a viewer by UUID. Must be called with mutex held.
    /// If viewer_id is zero_uuid, kick all viewers EXCEPT the one on `sender_fd`.
    pub fn kickViewer(self: *RemoteSession, viewer_id: Uuid, sender_fd: posix.fd_t) void {
        if (session.shared.isZeroUuid(viewer_id)) {
            // Kick all others — iterate backward since we're removing.
            var i: usize = self.viewers.items.len;
            while (i > 0) {
                i -= 1;
                if (self.viewers.items[i].fd != sender_fd) {
                    sendFrameFd(self.viewers.items[i].fd, .eof, self.viewers.items[i].target, "") catch {};
                    _ = self.viewers.swapRemove(i);
                }
            }
            self.controller_id = session.shared.zero_uuid;
            self.recalculateSize();
            if (self.viewers.items.len > 0) {
                self.broadcastViewerState(.leave);
            }
            return;
        }

        for (self.viewers.items) |viewer| {
            if (std.mem.eql(u8, &viewer.viewer_id, &viewer_id)) {
                sendFrameFd(viewer.fd, .eof, viewer.target, "") catch {};
                self.removeViewer(viewer.fd);
                if (std.mem.eql(u8, &self.controller_id, &viewer_id)) {
                    self.controller_id = session.shared.zero_uuid;
                }
                self.recalculateSize();
                if (self.viewers.items.len > 0) {
                    self.broadcastViewerState(.leave);
                }
                return;
            }
        }
    }

    /// Broadcast viewer state. If `group_label_override` is provided, use it
    /// instead of reading from self.group (avoids re-locking group.mutex when
    /// caller already holds it, e.g., from .rename handler).
    pub fn broadcastViewerState(self: *RemoteSession, reason: session.protocol.ViewerStateReason) void {
        self.broadcastViewerStateWithLabel(reason, null, -1);
    }

    /// Broadcast with explicit label/color (caller provides them from under group.mutex).
    pub fn broadcastViewerStateWithLabel(
        self: *RemoteSession,
        reason: session.protocol.ViewerStateReason,
        label_override: ?[]const u8,
        color_override: i8,
    ) void {
        // Build viewer entries from current state.
        var entries_buf: [64]session.protocol.ViewerEntry = undefined;
        const count = @min(self.viewers.items.len, entries_buf.len);
        for (self.viewers.items[0..count], 0..) |v, i| {
            entries_buf[i] = .{
                .id = v.viewer_id,
                .label = v.label,
                .is_controller = std.mem.eql(u8, &v.viewer_id, &self.controller_id),
                .rows = v.rows,
                .cols = v.cols,
            };
        }

        // Get effective PTY size from terminal instance (always up to date).
        const eff_rows = self.terminal_instance.rows;
        const eff_cols = self.terminal_instance.cols;

        // Get session label and color. If caller provided an override (when
        // group.mutex is already held), use it. Otherwise read from group
        // under its mutex.
        var label_buf: [256]u8 = undefined;
        var group_label: []const u8 = label_override orelse "";
        var group_color: i8 = color_override;
        if (label_override == null) {
            if (self.group) |g| {
                g.mutex.lock();
                const len = @min(g.label.len, label_buf.len);
                @memcpy(label_buf[0..len], g.label[0..len]);
                group_label = label_buf[0..len];
                group_color = g.color;
                g.mutex.unlock();
            }
        }

        const state = session.protocol.ViewerState{
            .reason = reason,
            .size_mode = self.size_mode,
            .controller_id = self.controller_id,
            .effective_rows = eff_rows,
            .effective_cols = eff_cols,
            .session_color = group_color,
            .session_label = group_label,
            .viewers = entries_buf[0..count],
        };

        const payload = state.encode(self.alloc) catch return;
        defer self.alloc.free(payload);

        for (self.viewers.items) |viewer| {
            sendFrameFd(viewer.fd, .viewer_state, viewer.target, payload) catch {};
        }
    }

    fn updateGroupMeta(self: *RemoteSession, label: ?[]const u8, color: ?i8) bool {
        const group = self.group orelse return true;
        return group.updateLabel(self.alloc, label, color);
    }

    pub fn deinit(self: *RemoteSession) void {
        for (self.viewers.items) |v| freeViewerLabel(self.alloc, v.label);
        self.viewers.deinit(self.alloc);
        self.stream.handler.deinit();
        self.terminal_instance.deinit(self.alloc);
        posix.close(self.pty.master);
        self.alloc.free(self.command.path);
        self.alloc.free(self.command.args);
        self.alloc.free(self.id);
        self.alloc.free(self.label);
        self.alloc.destroy(self);
    }

    pub fn kill(self: *RemoteSession) void {
        if (self.command.pid) |pid| _ = posix.kill(pid, posix.SIG.TERM) catch {};
    }

    /// Frame interval for output batching (nanoseconds).
    const frame_interval_ns: u64 = 16 * std.time.ns_per_ms;
    /// Soft threshold for flushing early.
    const flush_threshold: usize = 128 * 1024;

    /// Reader thread: reads PTY output, feeds the headless Terminal,
    /// and forwards accumulated bytes to viewers at the frame rate.
    pub fn readerMain(self: *RemoteSession) void {
        var read_buf: [65536]u8 = undefined;
        var accum = std.ArrayList(u8).empty;
        defer accum.deinit(self.alloc);
        var last_flush = std.time.nanoTimestamp();

        while (true) {
            // Poll PTY for data with frame-interval timeout.
            const now_ts = std.time.nanoTimestamp();
            const elapsed: u64 = @intCast(@max(0, now_ts - last_flush));
            const remaining_ms: i32 = if (elapsed >= frame_interval_ns)
                0
            else
                @intCast((frame_interval_ns - elapsed) / std.time.ns_per_ms);

            var pollfds = [1]posix.pollfd{
                .{ .fd = self.pty.master, .events = posix.POLL.IN, .revents = undefined },
            };
            const poll_result = posix.poll(&pollfds, remaining_ms) catch break;

            if (poll_result > 0 and (pollfds[0].revents & posix.POLL.IN != 0)) {
                const n = posix.read(self.pty.master, &read_buf) catch |err| switch (err) {
                    error.WouldBlock => continue,
                    else => break,
                };
                if (n == 0) break;

                self.mutex.lock();
                self.stream.nextSlice(read_buf[0..n]);
                self.mutex.unlock();

                accum.appendSlice(self.alloc, read_buf[0..n]) catch break;

                // Keep accumulating if below threshold and within frame interval.
                const flush_now = std.time.nanoTimestamp();
                const since_flush: u64 = @intCast(@max(0, flush_now - last_flush));
                if (accum.items.len < flush_threshold and since_flush < frame_interval_ns) {
                    continue;
                }
            } else if (poll_result > 0 and (pollfds[0].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0)) {
                break;
            }

            if (accum.items.len > 0) {
                self.flushToViewers(accum.items);
                accum.clearRetainingCapacity();
                last_flush = std.time.nanoTimestamp();
            }
        }

        // Flush remaining.
        if (accum.items.len > 0) {
            self.flushToViewers(accum.items);
        }

        self.mutex.lock();
        self.alive = false;
        for (self.viewers.items) |viewer| {
            sendFrameFd(viewer.fd, .eof, viewer.target, "") catch {};
        }
        self.mutex.unlock();
        _ = self.command.wait(false) catch {};
    }

    /// Send accumulated data to all viewers, using compression if all support it.
    fn flushToViewers(self: *RemoteSession, data: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const use_compression = session.shared.allViewersSupportsCompression(self.viewers.items);
        for (self.viewers.items) |viewer| {
            if (use_compression) {
                session.shared.sendFrameFdCompressed(
                    viewer.fd,
                    .data_out,
                    viewer.target,
                    data,
                    self.alloc,
                ) catch {};
            } else {
                sendFrameFd(viewer.fd, .data_out, viewer.target, data) catch {};
            }
        }
    }

    /// Attach a client and begin serving.
    pub fn attachAndServe(
        self: *RemoteSession,
        fd: posix.fd_t,
        target: u16,
        open_data: session.protocol.Open,
    ) !void {
        // Generate a viewer ID for this connection.
        const viewer_id = session.shared.generateUuid();

        self.mutex.lock();

        // Add viewer to list — multi-viewer: no rejection.
        // Copy the label string — open_data.label is a slice into the
        // caller's payload buffer which may be freed after this returns.
        const viewer_label = self.alloc.dupe(u8, open_data.label) catch {
            self.mutex.unlock();
            return error.OutOfMemory;
        };
        self.viewers.append(self.alloc, .{
            .fd = fd,
            .target = target,
            .viewer_id = viewer_id,
            .label = viewer_label,
            .rows = open_data.resize.rows,
            .cols = open_data.resize.cols,
            .compression_enabled = open_data.compression_enabled != 0,
        }) catch {
            self.alloc.free(viewer_label);
            self.mutex.unlock();
            return error.OutOfMemory;
        };

        // First viewer gets implicit control.
        if (self.viewers.items.len == 1) {
            self.controller_id = viewer_id;
        }

        // Recalculate PTY size based on all viewers.
        self.recalculateSize();

        // Notify all viewers (including the new one) about the roster.
        self.broadcastViewerState(if (self.viewers.items.len == 1) .welcome else .join);

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
            if (self.processClientFrames(&frame_buf, fd)) break;

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
        if (self.viewers.items.len > 0) {
            self.broadcastViewerState(.leave);
        }
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
            history_sent.* = total_history;
            self.sendScrollbackDone(fd, target, total_history, history_sent.*, cols);
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

        if (history_sent.* >= total_history) {
            self.sendScrollbackDone(fd, target, total_history, history_sent.*, cols);
        }
    }

    /// Process complete frames from a viewer's input buffer.
    fn sendScrollbackDone(self: *RemoteSession, fd: posix.fd_t, target: u16, total_history: u32, chunk_start: u32, cols: u16) void {
        const done_resp = session.protocol.ScrollbackResponse{
            .total_history_rows = total_history,
            .chunk_start_row = chunk_start,
            .row_count = 0,
            .cols = cols,
            .chunk_data = "",
        };
        const done_payload = done_resp.encode(self.alloc) catch return;
        defer self.alloc.free(done_payload);
        sendFrameFd(fd, .scrollback_response, target, done_payload) catch {};
    }

    /// Returns true if the connection should be closed.
    fn processClientFrames(
        self: *RemoteSession,
        frame_buf: *std.ArrayList(u8),
        viewer_fd: posix.fd_t,
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
                .data_in => {
                    // Implicit control: typing = instant takeover.
                    self.mutex.lock();
                    if (self.findViewer(viewer_fd)) |viewer| {
                        if (!std.mem.eql(u8, &self.controller_id, &viewer.viewer_id)) {
                            self.controller_id = viewer.viewer_id;
                            self.broadcastViewerState(.control_change);
                            if (self.size_mode == .leader_wins) self.recalculateSize();
                        }
                    }
                    self.mutex.unlock();
                    _ = posix.write(self.pty.master, payload) catch |err| {
                        log.warn("session write failed id={s} err={}", .{ self.id, err });
                        shiftBuf(frame_buf, total);
                        return true;
                    };
                },
                .resize => {
                    const parsed = session.protocol.Resize.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        return true;
                    };
                    if (parsed.rows == 0 or parsed.cols == 0 or
                        parsed.rows > 10000 or parsed.cols > 10000 or
                        parsed.width_px > 100000 or parsed.height_px > 100000)
                    {
                        log.warn("invalid resize values: {}x{} ({}x{} px)", .{
                            parsed.cols, parsed.rows, parsed.width_px, parsed.height_px,
                        });
                    } else {
                        // Update per-viewer size and recalculate negotiated size.
                        self.mutex.lock();
                        if (self.findViewer(viewer_fd)) |viewer| {
                            viewer.rows = parsed.rows;
                            viewer.cols = parsed.cols;
                        }
                        self.recalculateSize();
                        self.mutex.unlock();
                    }
                },
                .size_mode_change => {
                    const change = session.protocol.SizeModeChange.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        continue;
                    };
                    self.mutex.lock();
                    self.size_mode = change.mode;
                    self.recalculateSize();
                    self.broadcastViewerState(.mode_change);
                    self.mutex.unlock();
                },
                .kick_viewer => {
                    if (payload.len >= session.protocol.uuid_size) {
                        const target_id_bytes = payload[0..session.protocol.uuid_size];
                        self.mutex.lock();
                        self.kickViewer(target_id_bytes.*, viewer_fd);
                        self.mutex.unlock();
                    }
                },
                .rename => {
                    const rename_data = session.protocol.Rename.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        continue;
                    };
                    if (rename_data.scope == .group) {
                        if (!self.updateGroupMeta(rename_data.label, null)) {
                            shiftBuf(frame_buf, total);
                            continue;
                        }
                    }
                },
                .session_meta => {
                    const meta = session.protocol.SessionMeta.parse(payload) catch {
                        shiftBuf(frame_buf, total);
                        continue;
                    };
                    const label = if (meta.label.len > 0) meta.label else null;
                    if (!self.updateGroupMeta(label, meta.color)) {
                        shiftBuf(frame_buf, total);
                        continue;
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

const sendFrameFd = session.shared.sendFrameFd;

