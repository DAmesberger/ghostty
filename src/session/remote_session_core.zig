//! RemoteSession core: the headless ghostty terminal struct + its full method
//! surface for remote sessions.
//!
//! Split out of `remote_session.zig` (which re-exports it). This module owns
//! the `RemoteSession` struct and its entire method surface: viewer roster,
//! size negotiation, reader/flush thread, attachAndServe, scrollback streaming,
//! client-frame dispatch, and refcount lifecycle. It calls into
//! `remote_vt_serialize` for the reconnect snapshot.
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
const remote_vt_serialize = @import("remote_vt_serialize.zig");
const serializeViewportAsVT = remote_vt_serialize.serializeViewportAsVT;

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

    /// Reference count for safe teardown across threads. References are held by:
    /// the group map (the initial 1, dropped when the surface is removed from
    /// `group.surfaces`), the reader thread (dropped when `readerMain` returns),
    /// each in-flight open/attach handler serving a viewer (dropped when it
    /// finishes), and the checkpoint thread while it snapshots off the group
    /// lock. `deinit` runs exactly once — on the final `release` — so a
    /// closed/removed surface is never freed while a thread still touches it,
    /// and never double-freed against `SessionGroup.deinit`.
    refs: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    /// Monotonically-increasing counter bumped under `mutex` in `readerMain`
    /// whenever PTY output is fed into the terminal. The daemon's checkpoint
    /// thread compares this against `checkpointed_seq` to skip surfaces that
    /// have not changed since their last on-disk snapshot (cmux scrollback
    /// persistence). Cheap: one u64 increment under the already-held mutex.
    dirty_seq: u64 = 0,
    /// Last `dirty_seq` value persisted to disk. Read/written ONLY by the
    /// checkpoint thread (no mutex needed for this field itself).
    checkpointed_seq: u64 = 0,
    /// The max_scrollback cap (bytes) this surface's terminal was created
    /// with. Recorded in the on-disk snapshot so reload rebuilds under the
    /// same bound. Set once at creation; never mutated.
    max_scrollback: u32 = 0,

    /// cmux execve self-handoff (Phase 2, GATED): back-pointer to the daemon's
    /// shared `ReexecControl`. When non-null AND `in_progress` is set, the
    /// reader thread drains then PARKS (no PTY reads, no eof, no command.wait)
    /// so the PTY master can be carried across an execve. null (default) ⇒ the
    /// reader behaves exactly as before. Set in `createSurfaceInner`/`adoptSurface`.
    reexec: ?*ReexecControl = null,

    pub const SessionGroup = @import("daemon.zig").SessionGroup;
    pub const ReexecControl = @import("daemon.zig").ReexecControl;

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

    /// Acquire a reference. The caller must already hold a live reference or the
    /// lock (`group.mutex`) that keeps this surface in `group.surfaces`, so the
    /// count cannot be racing to zero underneath the increment.
    pub fn retain(self: *RemoteSession) void {
        _ = self.refs.fetchAdd(1, .acq_rel);
    }

    /// Release a reference. The final release `deinit`s the surface. After
    /// calling this the caller must not touch `self` again.
    pub fn release(self: *RemoteSession) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) self.deinit();
    }

    /// Frame interval for output batching (nanoseconds).
    const frame_interval_ns: u64 = 16 * std.time.ns_per_ms;
    /// Soft threshold for flushing early.
    const flush_threshold: usize = 128 * 1024;

    /// Reader thread: reads PTY output, feeds the headless Terminal,
    /// and forwards accumulated bytes to viewers at the frame rate.
    pub fn readerMain(self: *RemoteSession) void {
        // Capture these now: the final `self.release()` may free `self`, and the
        // deferred cleanup below runs AFTER it, so it must not dereference
        // `self`. `alloc` is a value and `reexec` points into the daemon (both
        // outlive the session), so the deferred uses stay valid post-free.
        const alloc = self.alloc;
        const reexec = self.reexec;

        var read_buf: [65536]u8 = undefined;
        var accum = std.ArrayList(u8).empty;
        defer accum.deinit(alloc);
        var last_flush = std.time.nanoTimestamp();

        // cmux execve self-handoff (GATED): count this thread as a live,
        // un-parked reader so `handleReexec` can wait for active_readers==0
        // before clearing CLOEXEC + execve. The function-scope defer balances
        // the add on eventual exit; the park branch below sub/adds around the
        // park so the count reflects "currently reading" at all times.
        if (reexec) |rc| _ = rc.active_readers.fetchAdd(1, .acq_rel);
        defer if (reexec) |rc| {
            _ = rc.active_readers.fetchSub(1, .acq_rel);
        };

        while (true) {
            // cmux execve self-handoff: when a handoff is in progress, drain any
            // buffered PTY output into the terminal ONE last time, then PARK —
            // do NOT exit, mark eof, or wait the child. On a successful execve
            // this thread vanishes with the old image (the new image's fresh
            // reader resumes the inherited master); on ABORT, in_progress clears
            // and we resume the normal loop with no respawn needed.
            if (self.reexec) |rc| {
                if (rc.in_progress.load(.acquire)) {
                    while (true) {
                        var dpoll = [1]posix.pollfd{
                            .{ .fd = self.pty.master, .events = posix.POLL.IN, .revents = undefined },
                        };
                        const dr = posix.poll(&dpoll, 0) catch break;
                        if (dr <= 0 or (dpoll[0].revents & posix.POLL.IN) == 0) break;
                        const n = posix.read(self.pty.master, &read_buf) catch break;
                        if (n == 0) break;
                        self.mutex.lock();
                        self.stream.nextSlice(read_buf[0..n]);
                        self.dirty_seq +%= 1;
                        self.mutex.unlock();
                    }
                    _ = rc.active_readers.fetchSub(1, .acq_rel);
                    while (rc.in_progress.load(.acquire)) std.Thread.sleep(2 * std.time.ns_per_ms);
                    _ = rc.active_readers.fetchAdd(1, .acq_rel);
                    continue;
                }
            }

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
                // cmux scrollback persistence: mark the terminal dirty so the
                // daemon's checkpoint thread knows this surface changed. Free
                // relative to VT parsing; under the already-held mutex.
                self.dirty_seq +%= 1;
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
            }
            // Always reset the frame timer — without this, once the PTY is idle
            // for >16ms, remaining_ms stays 0 and poll() never blocks.
            last_flush = std.time.nanoTimestamp();
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

        // Drop the reader thread's reference. This is the LAST access to `self`:
        // if the surface was already removed from its group and no viewer still
        // holds a reference, this frees it. The deferred cleanup above only
        // touches the captured `alloc`/`reexec`, never `self`.
        self.release();
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
            // Snapshot boundary sentinel: emit snapshot_begin for this target
            // IMMEDIATELY before the full-viewport data_out, under the same
            // mutex so the client sees them in order. The client resets the
            // target's terminal + VT parser on snapshot_begin so the snapshot
            // below lands on a clean baseline (no desync). Zero-byte payload.
            sendFrameFd(fd, .snapshot_begin, target, &.{}) catch |err| {
                self.removeViewer(fd);
                self.mutex.unlock();
                return err;
            };
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
            // Terminate scrollback streaming on persistent error to prevent
            // attachAndServe from spinning in a poll(fd, 0) busy loop.
            history_sent.* = total_history;
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

const sendFrameFd = session.shared.sendFrameFd;
