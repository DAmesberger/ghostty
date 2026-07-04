//! Daemon-side scrollback codec: the GTSB `.term` on-disk format.
//!
//! Split out of `persist.zig` (pure code motion); `persist.zig` re-exports
//! every public symbol here so existing `persist.Symbol` importers keep
//! resolving. This module owns capturing a headless `terminal.Terminal` to
//! an owned `Snapshot`, (de)serializing that Snapshot to/from the flat
//! `.term` file body, and rebuilding a Terminal on reload. See the header of
//! `persist.zig` for the full on-disk `.term` format description.

const std = @import("std");
const Allocator = std.mem.Allocator;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page_diff = @import("page_diff.zig");
const remote_session = @import("remote_session.zig");
const shared = @import("shared.zig");
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;

pub const magic_term = [4]u8{ 'G', 'T', 'S', 'B' };

/// Bump when the .term layout OR the page_diff chunk/Cell layout changes.
/// Independent of `meta_format_version`. A mismatch is treated as "no
/// persisted scrollback" (reload falls back to a fresh surface).
pub const term_format_version: u16 = 1;

/// Rows per scrollback chunk. Must match the live wire path so reload is
/// byte-identical to the client reconstruct path.
const scrollback_chunk_rows: u16 = 90;

/// Hard ceiling on the scrollback bytes we will write to disk, independent
/// of max_scrollback. Newest rows are kept (oldest dropped) if exceeded.
pub const max_scrollback_file_bytes: usize = 16 * 1024 * 1024;

/// Reference to one serialized scrollback chunk within the scrollback section.
pub const ChunkRef = struct {
    start_row: u32,
    row_count: u16,
    byte_off: u32,
    byte_len: u32,
};

/// A captured terminal snapshot. Owns `viewport`, `scrollback`, and
/// `chunk_index`. Call `deinit` to free.
pub const Snapshot = struct {
    cols: u16,
    rows: u16,
    max_scrollback: u32,
    history_rows: u32,
    viewport: []u8,
    scrollback: []u8,
    chunk_index: []ChunkRef,

    pub fn deinit(self: *Snapshot, alloc: Allocator) void {
        alloc.free(self.viewport);
        alloc.free(self.scrollback);
        alloc.free(self.chunk_index);
        self.* = undefined;
    }
};

/// Count scrollback history rows in a terminal (rows above the viewport).
/// Free function so `capture` can call it without a `*RemoteSession`.
pub fn historyRows(t: *Terminal) u32 {
    const s: *Screen = t.screens.active;
    const total = s.pages.total_rows;
    const viewport = s.pages.rows;
    return @intCast(if (total > viewport) total - viewport else 0);
}

/// Serialize a Terminal into an owned Snapshot using the EXISTING
/// serializers. MUST be called with the owning session's mutex held
/// (it reads the live terminal_instance).
///
/// `max_scrollback` is recorded in the snapshot so reload can rebuild the
/// Terminal under the same cap.
pub fn capture(alloc: Allocator, t: *Terminal, max_scrollback: u32) !Snapshot {
    const viewport = try remote_session.serializeViewportAsVT(alloc, t);
    errdefer alloc.free(viewport);

    const total_history = historyRows(t);

    var scrollback: std.ArrayList(u8) = .empty;
    errdefer scrollback.deinit(alloc);
    var chunks: std.ArrayList(ChunkRef) = .empty;
    errdefer chunks.deinit(alloc);

    var start_row: u32 = 0;
    while (start_row < total_history) {
        const chunk = try page_diff.serializeScrollbackChunk(
            alloc,
            t,
            start_row,
            scrollback_chunk_rows,
        );
        defer alloc.free(chunk.data);
        if (chunk.rows_serialized == 0) break;

        const byte_off: u32 = @intCast(scrollback.items.len);
        try scrollback.appendSlice(alloc, chunk.data);
        try chunks.append(alloc, .{
            .start_row = start_row,
            .row_count = chunk.rows_serialized,
            .byte_off = byte_off,
            .byte_len = @intCast(chunk.data.len),
        });
        start_row += chunk.rows_serialized;
    }

    // Hard byte ceiling: drop oldest chunks (keep newest scrollback) if the
    // serialized section exceeds the file cap. The kept rows still apply
    // correctly because each ChunkRef carries its absolute start_row.
    var chunk_slice = try chunks.toOwnedSlice(alloc);
    errdefer alloc.free(chunk_slice);
    var scrollback_slice = try scrollback.toOwnedSlice(alloc);
    errdefer alloc.free(scrollback_slice);
    var serialized_history = start_row;

    if (scrollback_slice.len > max_scrollback_file_bytes) {
        // Find the first chunk whose tail fits within the cap from the end.
        var keep_from: usize = 0;
        var i: usize = chunk_slice.len;
        var kept_bytes: usize = 0;
        while (i > 0) {
            i -= 1;
            const c = chunk_slice[i];
            if (kept_bytes + c.byte_len > max_scrollback_file_bytes) {
                keep_from = i + 1;
                break;
            }
            kept_bytes += c.byte_len;
        }
        if (keep_from < chunk_slice.len) {
            const drop_off = chunk_slice[keep_from].byte_off;
            const new_len = scrollback_slice.len - drop_off;
            std.mem.copyForwards(u8, scrollback_slice[0..new_len], scrollback_slice[drop_off..]);
            scrollback_slice = try alloc.realloc(scrollback_slice, new_len);
            // Rebase kept chunks so byte_off is relative to the trimmed buffer.
            const kept = chunk_slice[keep_from..];
            std.mem.copyForwards(ChunkRef, chunk_slice[0..kept.len], kept);
            for (chunk_slice[0..kept.len]) |*c| c.byte_off -= drop_off;
            chunk_slice = try alloc.realloc(chunk_slice, kept.len);
            // history_rows reflects the oldest kept row's start so reload
            // prepends exactly the right number of rows.
            serialized_history = total_history - chunk_slice[0].start_row;
            // Rebase start_row to 0-based for the trimmed history.
            const base = chunk_slice[0].start_row;
            for (chunk_slice) |*c| c.start_row -= base;
        } else {
            // Even a single chunk exceeds the cap — drop scrollback entirely.
            alloc.free(scrollback_slice);
            alloc.free(chunk_slice);
            scrollback_slice = try alloc.alloc(u8, 0);
            chunk_slice = try alloc.alloc(ChunkRef, 0);
            serialized_history = 0;
        }
    }

    return .{
        .cols = t.cols,
        .rows = t.rows,
        .max_scrollback = max_scrollback,
        .history_rows = serialized_history,
        .viewport = viewport,
        .scrollback = scrollback_slice,
        .chunk_index = chunk_slice,
    };
}

const header_fixed_len = 4 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 4;
const chunk_ref_disk_len = 4 + 2 + 2 + 4 + 4; // start_row, row_count, pad, byte_off, byte_len

/// Serialize a Snapshot to a flat owned byte buffer (the .term file body).
/// LZ4-compresses the viewport+scrollback payload when beneficial.
pub fn encodeSnapshot(alloc: Allocator, snap: Snapshot) ![]u8 {
    // Build the raw payload (viewport then scrollback) first.
    const payload_len = snap.viewport.len + snap.scrollback.len;
    var payload = try alloc.alloc(u8, payload_len);
    defer alloc.free(payload);
    @memcpy(payload[0..snap.viewport.len], snap.viewport);
    @memcpy(payload[snap.viewport.len..], snap.scrollback);

    const compressed = shared.compressPayload(alloc, payload, 1);
    defer if (compressed) |comp| alloc.free(comp);
    const body: []const u8 = if (compressed) |comp| comp else payload;
    const flags: u16 = if (compressed != null) 0x0001 else 0x0000;

    const index_len = snap.chunk_index.len * chunk_ref_disk_len;
    var out = try alloc.alloc(u8, header_fixed_len + index_len + body.len);
    errdefer alloc.free(out);
    var off: usize = 0;

    @memcpy(out[off..][0..4], &magic_term);
    off += 4;
    std.mem.writeInt(u16, out[off..][0..2], term_format_version, .little);
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], flags, .little);
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], snap.cols, .little);
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], snap.rows, .little);
    off += 2;
    std.mem.writeInt(u32, out[off..][0..4], snap.max_scrollback, .little);
    off += 4;
    std.mem.writeInt(u32, out[off..][0..4], snap.history_rows, .little);
    off += 4;
    std.mem.writeInt(u32, out[off..][0..4], @intCast(snap.chunk_index.len), .little);
    off += 4;
    std.mem.writeInt(u32, out[off..][0..4], @intCast(snap.viewport.len), .little);
    off += 4;
    std.mem.writeInt(u32, out[off..][0..4], @intCast(snap.scrollback.len), .little);
    off += 4;

    for (snap.chunk_index) |cref| {
        std.mem.writeInt(u32, out[off..][0..4], cref.start_row, .little);
        off += 4;
        std.mem.writeInt(u16, out[off..][0..2], cref.row_count, .little);
        off += 2;
        std.mem.writeInt(u16, out[off..][0..2], 0, .little); // pad
        off += 2;
        std.mem.writeInt(u32, out[off..][0..4], cref.byte_off, .little);
        off += 4;
        std.mem.writeInt(u32, out[off..][0..4], cref.byte_len, .little);
        off += 4;
    }

    @memcpy(out[off..][0..body.len], body);
    off += body.len;
    std.debug.assert(off == out.len);
    return out;
}

/// Decode a .term file body into an owned Snapshot. Returns null on any
/// validation failure (bad magic, version mismatch, short/torn file) so
/// callers fall back to a fresh surface.
pub fn decodeSnapshot(alloc: Allocator, data: []const u8) !?Snapshot {
    if (data.len < header_fixed_len) return null;
    var off: usize = 0;
    if (!std.mem.eql(u8, data[0..4], &magic_term)) return null;
    off += 4;
    const ver = std.mem.readInt(u16, data[off..][0..2], .little);
    off += 2;
    if (ver != term_format_version) return null;
    const flags = std.mem.readInt(u16, data[off..][0..2], .little);
    off += 2;
    const cols = std.mem.readInt(u16, data[off..][0..2], .little);
    off += 2;
    const rows = std.mem.readInt(u16, data[off..][0..2], .little);
    off += 2;
    const max_scrollback = std.mem.readInt(u32, data[off..][0..4], .little);
    off += 4;
    const history_rows = std.mem.readInt(u32, data[off..][0..4], .little);
    off += 4;
    const chunk_count = std.mem.readInt(u32, data[off..][0..4], .little);
    off += 4;
    const viewport_len = std.mem.readInt(u32, data[off..][0..4], .little);
    off += 4;
    const scrollback_len = std.mem.readInt(u32, data[off..][0..4], .little);
    off += 4;

    const index_len = @as(usize, chunk_count) * chunk_ref_disk_len;
    if (data.len < off + index_len) return null;

    var chunk_index = try alloc.alloc(ChunkRef, chunk_count);
    errdefer alloc.free(chunk_index);
    for (0..chunk_count) |i| {
        const start_row = std.mem.readInt(u32, data[off..][0..4], .little);
        off += 4;
        const row_count = std.mem.readInt(u16, data[off..][0..2], .little);
        off += 2;
        off += 2; // pad
        const byte_off = std.mem.readInt(u32, data[off..][0..4], .little);
        off += 4;
        const byte_len = std.mem.readInt(u32, data[off..][0..4], .little);
        off += 4;
        // Validate the chunk's byte range lies fully within the scrollback
        // section. Widen to u64 so byte_off + byte_len can't wrap a u32; a
        // range that overflows or overruns scrollback_len means a torn/corrupt
        // file → no persisted state (caller falls back to a fresh surface).
        const chunk_end: u64 = @as(u64, byte_off) + @as(u64, byte_len);
        if (byte_off > chunk_end or chunk_end > @as(u64, scrollback_len)) {
            alloc.free(chunk_index);
            return null;
        }
        chunk_index[i] = .{
            .start_row = start_row,
            .row_count = row_count,
            .byte_off = byte_off,
            .byte_len = byte_len,
        };
    }

    const body = data[off..];
    const payload: []u8 = if (flags & 0x0001 != 0)
        shared.decompressPayload(alloc, body) catch {
            alloc.free(chunk_index);
            return null;
        }
    else
        try alloc.dupe(u8, body);
    errdefer alloc.free(payload);

    if (payload.len < @as(usize, viewport_len) + @as(usize, scrollback_len)) {
        alloc.free(payload);
        alloc.free(chunk_index);
        return null;
    }

    const viewport = try alloc.dupe(u8, payload[0..viewport_len]);
    errdefer alloc.free(viewport);
    const scrollback = try alloc.dupe(u8, payload[viewport_len..][0..scrollback_len]);
    alloc.free(payload);

    return .{
        .cols = cols,
        .rows = rows,
        .max_scrollback = max_scrollback,
        .history_rows = history_rows,
        .viewport = viewport,
        .scrollback = scrollback,
        .chunk_index = chunk_index,
    };
}

/// Rebuild a Terminal from a Snapshot. Caller owns the returned Terminal
/// and must `deinit` it. `cols`/`rows` come from the live attach request
/// (passed in) so the reconstructed terminal matches the new PTY size; the
/// snapshot's own cols/rows are used as a fallback only when the request
/// values are zero.
pub fn restore(
    alloc: Allocator,
    snap: Snapshot,
    cols: u16,
    rows: u16,
) !Terminal {
    const use_cols = if (cols > 0) cols else snap.cols;
    const use_rows = if (rows > 0) rows else snap.rows;

    var t = try Terminal.init(alloc, .{
        .cols = use_cols,
        .rows = use_rows,
        .max_scrollback = if (snap.max_scrollback > 0) snap.max_scrollback else 10_000_000,
    });
    errdefer t.deinit(alloc);

    // 1) Replay viewport VT through a throwaway HeadlessHandler.Stream so the
    //    active screen matches the pre-restart viewport (same parser the live
    //    PTY uses). pty_fd = -1: viewport replay never writes back to a PTY.
    if (snap.viewport.len > 0) {
        var stream: HeadlessHandler.Stream = .init(.{
            .alloc = alloc,
            .terminal = &t,
            .pty_fd = -1,
        });
        defer stream.deinit();
        stream.nextSlice(snap.viewport);
    }

    // 2) Prepend blank history rows, then apply each scrollback chunk in
    //    place — mirroring the client reconstruct path exactly.
    if (snap.history_rows > 0 and snap.chunk_index.len > 0) {
        // Bound history_rows BEFORE allocating: a corrupt u32 (up to ~4B)
        // would make prependBlankPages allocate unbounded memory (one page per
        // ~rows_per_page rows). Every serialized scrollback row occupies
        // several bytes, so a legitimate snapshot can never have more history
        // rows than scrollback bytes; anything larger is corrupt → fall back
        // to a fresh surface (never a crash) instead of allocating.
        if (snap.history_rows > snap.scrollback.len) return error.CorruptSnapshot;
        try t.screens.active.pages.prependBlankPages(snap.history_rows);
        for (snap.chunk_index) |cref| {
            // Checked/widened arithmetic: cref.byte_off + cref.byte_len are u32
            // and can wrap. Compute in u64 and require the range lie fully
            // within the scrollback buffer (byte_off <= end AND end <= len)
            // before slicing; a torn/corrupt range → fresh surface.
            const end: u64 = @as(u64, cref.byte_off) + @as(u64, cref.byte_len);
            if (cref.byte_off > end or end > snap.scrollback.len) return error.CorruptSnapshot;
            page_diff.applyScrollbackChunk(
                &t,
                cref.start_row,
                cref.row_count,
                snap.scrollback[cref.byte_off..@intCast(end)],
            );
        }
    }

    return t;
}
