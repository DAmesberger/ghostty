//! Inbound frame path for the SSH connection manager: `processFrames` parses
//! the multiplexed protocol stream off the shared channel and `dispatchFrame`
//! applies each frame (data_out, snapshot, opened, scrollback, layout,
//! viewer_state, ...) to the matching surface. Split out of
//! `SshConnectionManager.zig`. `processFrames` is `pub` so the SSH thread can
//! drive it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const page_diff = session.page_diff;
const ssh = session.ssh;
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");
const config = @import("../config.zig").Config;

const log = std.log.scoped(.ssh_connection_manager);

const types = @import("ssh_conn_types.zig");
const Uuid = types.Uuid;
const SurfaceSlot = types.SurfaceSlot;
const Session = types.Session;
const WriteRequest = types.WriteRequest;
const EntryState = types.EntryState;
const Entry = types.Entry;

const sessions = @import("ssh_conn_sessions.zig");
const findSurfaceAcrossSessions = sessions.findSurfaceAcrossSessions;
const findSurfaceSlotPtr = sessions.findSurfaceSlotPtr;
const moveSurfaceToSession = sessions.moveSurfaceToSession;
const updateSurfaceIdLocked = sessions.updateSurfaceIdLocked;

const shiftBuffer = session.shared.shiftBuffer;


pub fn processFrames(frame_buf: *std.ArrayList(u8), entry: *Entry) void {
    while (frame_buf.items.len >= session.protocol.header_size) {
        const header = session.protocol.Header.parseFromBuf(
            frame_buf.items[0..session.protocol.header_size],
        ) catch {
            shiftBuffer(frame_buf, session.protocol.header_size);
            continue;
        };
        const kind = header.kind;
        const frame_target = header.target;
        // Defense-in-depth: a header whose len exceeds max_payload is a desync
        // (the frame format has no sync marker, so a garbage byte can parse as
        // a plausible kind with a bogus 4-byte len). Trusting it would either
        // stall forever waiting for gigabytes (the `break` below) or over-
        // consume real output. Treat it as a desync — drop one byte and rescan.
        if (header.len > session.protocol.max_payload) {
            shiftBuffer(frame_buf, 1);
            continue;
        }
        const total = session.protocol.header_size + header.len;
        if (frame_buf.items.len < total) break;

        var payload = frame_buf.items[session.protocol.header_size..total];

        // Decompress if flags indicate compression.
        var decompressed: ?[]u8 = null;
        defer if (decompressed) |d| entry.alloc.free(d);
        if (header.flags.compressed) {
            decompressed = session.shared.decompressPayload(entry.alloc, payload) catch {
                log.warn("decompression failed for {s} frame", .{@tagName(kind)});
                shiftBuffer(frame_buf, total);
                continue;
            };
            payload = decompressed.?;
        }

        // Handle pong: update timestamp, don't dispatch to surfaces
        if (kind == .pong) {
            entry.last_keepalive_received = std.time.nanoTimestamp();
            entry.keepalive_active = true;
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Collect list_response frames into the query buffer
        if (kind == .list_response) {
            entry.session_list.mutex.lock();
            if (entry.session_list.active) {
                entry.session_list.buf.appendSlice(entry.alloc, payload) catch {};
                entry.session_list.buf.append(entry.alloc, '\n') catch {};
                entry.session_list.cond.signal();
            }
            entry.session_list.mutex.unlock();
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Hold surfaces_mutex during dispatch to prevent use-after-free
        // on surface io pointers (unregisterSurface acquires the same lock).
        entry.surfaces_mutex.lock();
        if (frame_target == 0) {
            // Broadcast to all surfaces across all sessions
            var sit = entry.sessions.iterator();
            while (sit.next()) |kv| {
                for (kv.value_ptr.*.surfaces.items) |s| {
                    dispatchFrame(entry, kind, s, payload);
                }
            }
        } else {
            if (findSurfaceAcrossSessions(entry, frame_target)) |s| {
                dispatchFrame(entry, kind, s, payload);
            }
        }
        entry.surfaces_mutex.unlock();

        shiftBuffer(frame_buf, total);
    }
}

fn dispatchFrame(entry: *Entry, kind: session.protocol.Kind, s: SurfaceSlot, payload: []const u8) void {
    switch (kind) {
        .snapshot_begin => {
            // The daemon is about to send a full-viewport snapshot for this
            // target. Mark the surface so the NEXT data_out resets the
            // terminal + VT parser to a clean baseline before applying the
            // snapshot. We persist this on the slot (not the by-value `s`
            // copy) so it survives to the following frame. Caller holds
            // surfaces_mutex, so findSurfaceSlotPtr is safe here.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                slot.pending_snapshot_reset = true;
            }
        },
        .data_out => {
            // If a snapshot_begin preceded this data_out, reset the terminal
            // and VT parsing state to a clean baseline first so the snapshot
            // lands on a known-empty terminal (no desync). resetForSnapshot
            // acquires renderer_state.mutex itself, so it must run before we
            // take any lock here. Clear the flag so subsequent live data_out
            // frames are applied normally.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                if (slot.pending_snapshot_reset) {
                    slot.pending_snapshot_reset = false;
                    s.io.resetForSnapshot();
                }
            }
            // Suppress write-back responses (DA, DSR, OSC colors, etc.) during
            // remote data processing. The daemon already responded to queries.
            s.io.terminal_stream.handler.suppress_responses = true;
            defer s.io.terminal_stream.handler.suppress_responses = false;
            @call(.always_inline, termio.Termio.processOutput, .{ s.io, payload });
        },
        .opened => {
            // Parse the bundled opened response
            const parsed = session.protocol.Opened.parseHeader(payload) catch {
                log.warn("opened: invalid payload", .{});
                return;
            };
            log.info("remote session opened history_rows={d} label='{s}' (len={d})", .{ parsed.history_rows, parsed.label, parsed.label.len });

            // Move surface to the correct session and update surface_id.
            // surfaces_mutex is held by caller.
            moveSurfaceToSession(entry, s.target_id, parsed.group_id);
            updateSurfaceIdLocked(entry, s.target_id, parsed.surface_id);

            // Send IDs to GTK thread via mailbox so it can update ssh_ctx
            // without racing this (SSH) thread. All GTK-thread readers see
            // the update before any subsequent messages (data_out,
            // layout_restore) because the mailbox is FIFO.
            var opened_msg: apprt.surface.Message = .{
                .remote_opened = .{
                    .group_id = parsed.group_id,
                    .surface_id = parsed.surface_id,
                },
            };
            // Copy daemon-authoritative session label.
            const ol = parsed.label;
            const ol_len = @min(ol.len, 64);
            @memcpy(opened_msg.remote_opened.label[0..ol_len], ol[0..ol_len]);
            opened_msg.remote_opened.label_len = @intCast(ol_len);
            opened_msg.remote_opened.color = parsed.color;
            _ = s.surface_mailbox.push(opened_msg, .{ .forever = {} });

            // NOTE: blank history pages for scrollback restore are NOT
            // prepended here. The daemon sends `opened` BEFORE the
            // `snapshot_begin`+`data_out` pair, and that `data_out` runs
            // `resetForSnapshot()` → `terminal.fullReset()` →
            // `Screen.reset()` → `pages.reset()`, which DROPS every page —
            // including any we prepended here. The following
            // `scrollback_response` chunks would then land on a terminal with
            // no history rows and scramble the screen. So the prepend is
            // deferred to the `.scrollback_response` handler below, which runs
            // AFTER the snapshot reset, on a clean terminal. (`history_rows`
            // is re-derived there from `total_history_rows`.)

            // If layout blob is included, send it to surface for tree recreation.
            // Bundle group_id/surface_id in the message to avoid a race:
            // the GTK thread must not read these from the Remote backend
            // since we just wrote them on this (SSH) thread.
            if (parsed.layout_blob) |layout_blob| {
                log.info("received layout blob in opened response len={d}", .{layout_blob.len});
                const blob_copy = std.heap.page_allocator.dupe(u8, layout_blob) catch {
                    log.err("failed to allocate layout blob", .{});
                    return;
                };
                _ = s.surface_mailbox.push(.{
                    .layout_restore = .{
                        .blob = blob_copy.ptr,
                        .len = @intCast(blob_copy.len),
                        .group_id = parsed.group_id,
                        .surface_id = parsed.surface_id,
                    },
                }, .{ .forever = {} });
            }
        },
        .scrollback_response => {
            // Parse scrollback chunk header
            const resp = session.protocol.ScrollbackResponse.parse(payload) catch {
                log.warn("scrollback_response: invalid payload", .{});
                return;
            };

            // row_count == 0 is the done marker
            if (resp.row_count == 0) {
                log.info("scrollback restore complete ({d} history rows)", .{resp.total_history_rows});
                _ = s.surface_mailbox.push(.{
                    .scrollback_progress = .{
                        .received = resp.total_history_rows,
                        .total = resp.total_history_rows,
                    },
                }, .{ .forever = {} });
                return;
            }

            // Apply the chunk to the client's terminal
            s.io.renderer_state.mutex.lock();
            defer s.io.renderer_state.mutex.unlock();
            const t = s.io.renderer_state.terminal;

            // Pre-allocate the blank history pages on the FIRST chunk, here —
            // AFTER the snapshot's `data_out` already ran `fullReset()`. Doing
            // this in the `.opened` handler instead places the blank pages
            // BEFORE that reset, which drops them and scrambles the restored
            // screen (see the note in the `.opened` handler). Guard with
            // `history_prepended` (reset per-surface on reconnect in
            // `reopenSurfaces`) so we prepend exactly once per attach.
            // `surfaces_mutex` is held by the caller, so findSurfaceSlotPtr is
            // safe.
            if (findSurfaceSlotPtr(entry, s.target_id)) |slot| {
                if (!slot.history_prepended and resp.total_history_rows > 0) {
                    t.screens.active.pages.prependBlankPages(resp.total_history_rows) catch |err| {
                        log.warn("failed to prepend history pages: {}", .{err});
                    };
                    slot.history_prepended = true;
                }
            }

            page_diff.applyScrollbackChunk(
                t,
                resp.chunk_start_row,
                resp.row_count,
                resp.chunk_data,
            );

            // Notify surface of progress
            const received = resp.chunk_start_row + resp.row_count;
            _ = s.surface_mailbox.push(.{
                .scrollback_progress = .{
                    .received = received,
                    .total = resp.total_history_rows,
                },
            }, .{ .forever = {} });
        },
        .layout => {
            log.info("received layout blob len={d}", .{payload.len});
            // page_allocator is used intentionally: this blob crosses thread
            // boundaries via the surface mailbox. The receiver (GTK thread)
            // frees it and does not have access to entry.alloc.
            const blob_copy = std.heap.page_allocator.dupe(u8, payload) catch {
                log.err("failed to allocate layout blob", .{});
                return;
            };
            _ = s.surface_mailbox.push(.{
                .layout_restore = .{
                    .blob = blob_copy.ptr,
                    .len = @intCast(blob_copy.len),
                },
            }, .{ .forever = {} });
        },
        .viewer_state => {
            const hdr = session.protocol.ViewerState.parseHeader(payload) catch {
                log.warn("viewer_state: invalid payload", .{});
                return;
            };
            log.info("viewer_state: reason={s} viewers={d} label='{s}' (len={d})", .{
                @tagName(hdr.reason),
                hdr.viewer_count,
                hdr.session_label,
                hdr.session_label.len,
            });

            var msg: apprt.surface.Message = .{
                .viewer_state = .{
                    .reason = hdr.reason,
                    .size_mode = hdr.size_mode,
                    .controller_id = hdr.controller_id,
                    .effective_rows = hdr.effective_rows,
                    .effective_cols = hdr.effective_cols,
                    .viewer_count = hdr.viewer_count,
                    .session_color = hdr.session_color,
                },
            };

            // Copy session label into fixed buffer.
            const sl = hdr.session_label;
            const sl_len = @min(sl.len, 64);
            @memcpy(msg.viewer_state.session_label[0..sl_len], sl[0..sl_len]);
            msg.viewer_state.session_label_len = @intCast(sl_len);

            // Parse viewer entries from remaining payload.
            var remaining = hdr.remaining;
            const count = @min(hdr.viewer_count, 8); // Cap at inline roster size
            for (0..count) |i| {
                const uuid_end = session.protocol.uuid_size;
                if (remaining.len < session.protocol.ViewerState.viewer_fixed_size) break;
                // Skip UUID (16 bytes)
                remaining = remaining[uuid_end..];
                const label_len = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                const is_ctrl = remaining[0] != 0;
                remaining = remaining[1..];
                const rows = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                const cols = std.mem.readInt(u16, remaining[0..2], .little);
                remaining = remaining[2..];
                // Read label
                const actual_label_len = @min(label_len, 64);
                if (remaining.len < label_len) break;
                var vi: apprt.surface.Message.ViewerInfo = .{
                    .is_controller = is_ctrl,
                    .rows = rows,
                    .cols = cols,
                    .label_len = @intCast(actual_label_len),
                };
                @memcpy(vi.label[0..actual_label_len], remaining[0..actual_label_len]);
                remaining = remaining[label_len..];
                msg.viewer_state.viewers[i] = vi;
            }

            _ = s.surface_mailbox.push(msg, .{ .forever = {} });
        },
        .info => log.info("remote info: {s}", .{payload}),
        .err => log.err("remote error: {s}", .{payload}),
        .eof => {
            log.info("remote session EOF target={d}", .{s.target_id});
            _ = s.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        },
        else => {},
    }
}
