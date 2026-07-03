//! Daemon-side scrollback persistence (cmux first cut).
//!
//! Pure (de)serialization helpers for snapshotting a headless
//! `terminal.Terminal` to disk and rebuilding it on the next daemon
//! generation. No daemon types live here so this module stays
//! independently unit-testable.
//!
//! WHAT THIS DOES (and does NOT do)
//! --------------------------------
//! The remote daemon (`daemon.zig`) is a headless terminal emulator: each
//! surface owns a full `terminal.Terminal` whose scrollback lives entirely
//! in memory. Nothing about that state survives a daemon restart today.
//! This module lets the daemon checkpoint a surface's scrollback + viewport
//! to a per-surface file under `<stateDir>/state/<group_hex>/<surface_hex>.term`
//! and reload it lazily when a client re-attaches after a restart.
//!
//! We restore SCROLLBACK, not the live process: a reloaded surface gets a
//! fresh shell. The restored viewport shows the pre-restart screen, then a
//! new shell prompt appears below.
//!
//! ON-DISK FORMAT (.term file, all integers little-endian)
//! -------------------------------------------------------
//!   magic        [4]  "GTSB"  (Ghostty Terminal ScrollBack)
//!   version      [2]  = term_format_version
//!   flags        [2]  bit0: compressed (LZ4, via shared.compressPayload framing)
//!   cols         [2]
//!   rows         [2]
//!   max_scrollback [4]   (bytes — the cap this snapshot was taken under)
//!   history_rows [4]     (count of scrollback rows serialized)
//!   chunk_count  [4]     (number of scrollback chunk refs that follow)
//!   viewport_len [4]     (byte length of the viewport-VT section, post-decompress)
//!   scrollback_len [4]   (byte length of the scrollback section, post-decompress)
//!   --- chunk index ---  chunk_count * ChunkRef (start_row u32, row_count u16,
//!                        pad u16, byte_off u32, byte_len u32)
//!   --- payload ---      if flags.compressed: one LZ4 blob (shared framing)
//!                        decompressing to [viewport_section ++ scrollback_section];
//!                        else the two sections concatenated raw.
//!
//! The scrollback section is the exact concatenation of the chunks that
//! `page_diff.serializeScrollbackChunk` produces for the live wire path, so
//! reload replays them through `page_diff.applyScrollbackChunk` identically
//! to `SshConnectionManager`'s client reconstruct path. The viewport section
//! is `remote_session.serializeViewportAsVT` output, repainted on reload by
//! feeding it back through the daemon's own `HeadlessHandler.Stream`.
//!
//! FORMAT DRIFT COUPLING (read before changing the chunk format)
//! ------------------------------------------------------------
//! `serializeScrollbackChunk` / `applyScrollbackChunk` encode each `Cell` as
//! a raw packed `u64` (`page_diff.zig`). The on-disk format is therefore
//! IMPLICITLY tied to ghostty's `Cell` struct layout: a `Cell` change
//! silently invalidates old blobs. Mitigation: bump `term_format_version`
//! whenever the chunk format (or `Cell` layout) changes. A mismatched
//! version, bad magic, or short/torn file is treated as "no persisted
//! state" — reload falls back to a fresh surface; never a crash, never
//! garbage. (TODO(cmux): embed a Cell-layout hash in the header so even an
//! unbumped version can be rejected — deferred per design §5.)

const std = @import("std");
const Allocator = std.mem.Allocator;
const terminal = @import("../terminal/main.zig");
const Terminal = terminal.Terminal;
const Screen = terminal.Screen;
const page_diff = @import("page_diff.zig");
const remote_session = @import("remote_session.zig");
const shared = @import("shared.zig");
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;

const log = std.log.scoped(.ssh_persist);

pub const magic_term = [4]u8{ 'G', 'T', 'S', 'B' };
pub const magic_group = [4]u8{ 'G', 'T', 'G', 'M' };

/// Bump when the GTGM (group.meta) layout changes. Independent of term churn,
/// so a scrollback-format bump never drops the session list / names / layout.
/// A mismatch is treated as "no persisted metadata".
pub const meta_format_version: u16 = 1;

/// Bump when the .term layout OR the page_diff chunk/Cell layout changes.
/// Independent of `meta_format_version`. A mismatch is treated as "no
/// persisted scrollback" (reload falls back to a fresh surface).
pub const term_format_version: u16 = 1;

/// Rows per scrollback chunk. Must match the live wire path so reload is
/// byte-identical to the client reconstruct path.
const scrollback_chunk_rows: u16 = 90;

/// Hard ceiling on the scrollback bytes we will write to disk, independent
/// of max_scrollback. Newest rows are kept (oldest dropped) if exceeded.
const max_scrollback_file_bytes: usize = 16 * 1024 * 1024;

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

// =========================================================================
// File I/O (atomic tmp + rename)
// =========================================================================

/// Write a Snapshot to `<dir_path>/<surface_hex>.term` atomically.
/// Creates `dir_path` (mode 0700) if needed. Writes to a `.tmp` sibling and
/// renames over the final path (POSIX atomic same-dir rename).
pub fn writeTermFile(
    alloc: Allocator,
    dir_path: []const u8,
    surface_hex: []const u8,
    snap: Snapshot,
) !void {
    std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    chmod0700(dir_path);

    const body = try encodeSnapshot(alloc, snap);
    defer alloc.free(body);

    const final_path = try std.fmt.allocPrint(alloc, "{s}/{s}.term", .{ dir_path, surface_hex });
    defer alloc.free(final_path);
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}/{s}.term.tmp", .{ dir_path, surface_hex });
    defer alloc.free(tmp_path);

    {
        var file = try std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600, .truncate = true });
        defer file.close();
        try file.writeAll(body);
    }
    try std.fs.cwd().rename(tmp_path, final_path);
}

/// Read + decode `<dir_path>/<surface_hex>.term`. Returns null on missing,
/// torn, bad-magic, or version-mismatch file.
pub fn readTermFile(
    alloc: Allocator,
    dir_path: []const u8,
    surface_hex: []const u8,
) !?Snapshot {
    const final_path = try std.fmt.allocPrint(alloc, "{s}/{s}.term", .{ dir_path, surface_hex });
    defer alloc.free(final_path);

    const data = std.fs.cwd().readFileAlloc(alloc, final_path, max_scrollback_file_bytes + 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return null, // any read error → treat as no state
    };
    defer alloc.free(data);

    return decodeSnapshot(alloc, data);
}

/// Delete a single surface's .term file. Best-effort.
pub fn deleteTermFile(alloc: Allocator, dir_path: []const u8, surface_hex: []const u8) void {
    const final_path = std.fmt.allocPrint(alloc, "{s}/{s}.term", .{ dir_path, surface_hex }) catch return;
    defer alloc.free(final_path);
    std.fs.cwd().deleteFile(final_path) catch {};
}

/// Delete an entire group's persisted state directory. Best-effort.
pub fn deleteGroupDir(dir_path: []const u8) void {
    std.fs.cwd().deleteTree(dir_path) catch {};
}

// =========================================================================
// group.meta (label / color / created_at / layout_blob)
// =========================================================================

/// Group metadata persisted alongside surfaces so the session list + tab
/// layout survive a restart.
pub const GroupMeta = struct {
    color: i8,
    created_at: i64,
    label: []u8,
    layout_blob: ?[]u8,

    pub fn deinit(self: *GroupMeta, alloc: Allocator) void {
        alloc.free(self.label);
        if (self.layout_blob) |b| alloc.free(b);
        self.* = undefined;
    }
};

/// Write `<dir_path>/group.meta` atomically.
pub fn writeGroupMeta(
    alloc: Allocator,
    dir_path: []const u8,
    color: i8,
    created_at: i64,
    label: []const u8,
    layout_blob: ?[]const u8,
) !void {
    std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    chmod0700(dir_path);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    try buf.appendSlice(alloc, &magic_group);
    var hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &hdr, meta_format_version, .little);
    try buf.appendSlice(alloc, &hdr);
    try buf.append(alloc, @bitCast(color));
    var ts: [8]u8 = undefined;
    std.mem.writeInt(i64, &ts, created_at, .little);
    try buf.appendSlice(alloc, &ts);
    try appendLenPrefixed(alloc, &buf, label);
    try appendLenPrefixed(alloc, &buf, layout_blob orelse &.{});

    const final_path = try std.fmt.allocPrint(alloc, "{s}/group.meta", .{dir_path});
    defer alloc.free(final_path);
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}/group.meta.tmp", .{dir_path});
    defer alloc.free(tmp_path);
    {
        var file = try std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600, .truncate = true });
        defer file.close();
        try file.writeAll(buf.items);
    }
    try std.fs.cwd().rename(tmp_path, final_path);
}

/// Read `<dir_path>/group.meta`. Returns null on missing/torn/bad file.
pub fn readGroupMeta(alloc: Allocator, dir_path: []const u8) !?GroupMeta {
    const final_path = try std.fmt.allocPrint(alloc, "{s}/group.meta", .{dir_path});
    defer alloc.free(final_path);
    const data = std.fs.cwd().readFileAlloc(alloc, final_path, 256 * 1024) catch return null;
    defer alloc.free(data);

    var off: usize = 0;
    if (data.len < 4 + 2 + 1 + 8) return null;
    if (!std.mem.eql(u8, data[0..4], &magic_group)) return null;
    off += 4;
    const ver = std.mem.readInt(u16, data[off..][0..2], .little);
    off += 2;
    if (ver != meta_format_version) return null;
    const color: i8 = @bitCast(data[off]);
    off += 1;
    const created_at = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;

    const label = readLenPrefixed(alloc, data, &off) orelse return null;
    errdefer alloc.free(label);
    const layout_raw = readLenPrefixed(alloc, data, &off) orelse {
        alloc.free(label);
        return null;
    };
    const layout_blob: ?[]u8 = if (layout_raw.len > 0) layout_raw else blk: {
        alloc.free(layout_raw);
        break :blk null;
    };

    return .{
        .color = color,
        .created_at = created_at,
        .label = label,
        .layout_blob = layout_blob,
    };
}

fn appendLenPrefixed(alloc: Allocator, buf: *std.ArrayList(u8), data: []const u8) !void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(data.len), .little);
    try buf.appendSlice(alloc, &lb);
    try buf.appendSlice(alloc, data);
}

fn readLenPrefixed(alloc: Allocator, data: []const u8, off: *usize) ?[]u8 {
    if (off.* + 4 > data.len) return null;
    const len = std.mem.readInt(u32, data[off.*..][0..4], .little);
    off.* += 4;
    if (off.* + len > data.len) return null;
    const out = alloc.dupe(u8, data[off.*..][0..len]) catch return null;
    off.* += len;
    return out;
}

fn chmod0700(dir_path: []const u8) void {
    var dir = std.fs.cwd().openDir(dir_path, .{}) catch return;
    defer dir.close();
    dir.chmod(0o700) catch {};
}

// =========================================================================
// Startup scan / enumerate / TTL sweep
//
// Pure filesystem-walk helpers (no daemon types) the daemon calls once on
// boot to repopulate `--list` / the session chooser / the tab layout from
// on-disk state BEFORE any client attaches. Mirrors the reload-on-attach
// path but for visibility only: nothing here spawns a shell or rebuilds a
// Terminal — it just reports which groups + surfaces exist on disk.
// =========================================================================

/// Metadata for one persisted group discovered by `scanPersistedGroups`.
/// Owns `label`, `layout_blob`, and `surface_ids`. Call `deinit` to free.
pub const PersistedGroupInfo = struct {
    group_id: shared.Uuid,
    color: i8,
    created_at: i64,
    label: []u8,
    layout_blob: ?[]u8,
    /// Surface ids discovered as `<surface_hex>.term` files in the group dir.
    surface_ids: []shared.Uuid,

    pub fn deinit(self: *PersistedGroupInfo, alloc: Allocator) void {
        alloc.free(self.label);
        if (self.layout_blob) |b| alloc.free(b);
        alloc.free(self.surface_ids);
        self.* = undefined;
    }
};

/// Enumerate the surface ids persisted under `group_dir` by parsing the
/// `<surface_hex>.term` filenames. Accepts ONLY names of the exact shape
/// `[0-9a-f]{32}.term`; `group.meta`, `*.term.tmp`, `*.tmp`, and any name
/// whose stem is not a 32-char lowercase-hex UUID are skipped. A missing
/// directory yields an empty slice (not an error). Caller owns the result.
pub fn listSurfaceIds(alloc: Allocator, group_dir: []const u8) ![]shared.Uuid {
    var dir = std.fs.cwd().openDir(group_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return alloc.alloc(shared.Uuid, 0),
        else => return err,
    };
    defer dir.close();

    var ids: std.ArrayList(shared.Uuid) = .empty;
    errdefer ids.deinit(alloc);

    const suffix = ".term";
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, suffix)) continue; // skips *.term.tmp/*.tmp/group.meta
        const stem = entry.name[0 .. entry.name.len - suffix.len];
        if (stem.len != 32) continue;
        const uuid = shared.parseUuid(stem) catch continue; // non-hex stem
        try ids.append(alloc, uuid);
    }

    return ids.toOwnedSlice(alloc);
}

/// Scan `<persist_root>/<group_hex>/` for every persisted group. Per dir:
/// parse the 32-hex dir name (skip if unparseable), `readGroupMeta` (skip
/// the dir if it returns null — missing/torn/version-mismatch metadata),
/// then `listSurfaceIds`. Each group is wrapped so one corrupt group never
/// aborts the whole scan. A missing root yields an empty slice. Caller owns
/// the result (free each via `PersistedGroupInfo.deinit`, then the slice).
pub fn scanPersistedGroups(alloc: Allocator, persist_root: []const u8) ![]PersistedGroupInfo {
    var dir = std.fs.cwd().openDir(persist_root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return alloc.alloc(PersistedGroupInfo, 0),
        else => return err,
    };
    defer dir.close();

    var infos: std.ArrayList(PersistedGroupInfo) = .empty;
    errdefer {
        for (infos.items) |*gi| gi.deinit(alloc);
        infos.deinit(alloc);
    }

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name.len != 32) continue;
        const group_id = shared.parseUuid(entry.name) catch continue;

        const group_dir = std.fs.path.join(alloc, &.{ persist_root, entry.name }) catch continue;
        defer alloc.free(group_dir);

        var meta = (readGroupMeta(alloc, group_dir) catch continue) orelse continue;
        // On success, `meta.label` + `meta.layout_blob` ownership transfers
        // into the appended info; only free `meta` on a failure below.
        const surface_ids = listSurfaceIds(alloc, group_dir) catch {
            meta.deinit(alloc);
            continue;
        };

        infos.append(alloc, .{
            .group_id = group_id,
            .color = meta.color,
            .created_at = meta.created_at,
            .label = meta.label,
            .layout_blob = meta.layout_blob,
            .surface_ids = surface_ids,
        }) catch {
            meta.deinit(alloc);
            alloc.free(surface_ids);
            continue;
        };
    }

    return infos.toOwnedSlice(alloc);
}

/// Best-effort TTL sweep: `deleteTree` any group dir whose `group.meta`
/// mtime is older than `ttl_secs`. Runs BEFORE `scanPersistedGroups` on
/// boot so abandoned state can't accumulate forever. Never errors out — any
/// per-dir failure is skipped. Victim names are collected first, then
/// deleted, so we never mutate the directory mid-iteration. A non-positive
/// `ttl_secs` disables the sweep.
pub fn sweepExpiredGroups(alloc: Allocator, persist_root: []const u8, ttl_secs: i64) void {
    if (ttl_secs <= 0) return;
    var dir = std.fs.cwd().openDir(persist_root, .{ .iterate = true }) catch return;
    defer dir.close();

    const now = std.time.timestamp();

    var victims: std.ArrayList([]u8) = .empty;
    defer {
        for (victims.items) |v| alloc.free(v);
        victims.deinit(alloc);
    }

    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name.len != 32) continue;
        _ = shared.parseUuid(entry.name) catch continue;

        const meta_rel = std.fs.path.join(alloc, &.{ entry.name, "group.meta" }) catch continue;
        defer alloc.free(meta_rel);
        const st = dir.statFile(meta_rel) catch continue;
        const mtime_secs: i64 = @intCast(@divFloor(st.mtime, std.time.ns_per_s));
        if (now - mtime_secs <= ttl_secs) continue;

        const name_copy = alloc.dupe(u8, entry.name) catch continue;
        victims.append(alloc, name_copy) catch {
            alloc.free(name_copy);
            continue;
        };
    }

    for (victims.items) |name| {
        dir.deleteTree(name) catch {};
    }
}

// =========================================================================
// Re-exec handoff manifest (cmux Phase 2 — GATED execve self-handoff)
//
// Written by the OLD daemon image immediately before `execve` and read by the
// NEW daemon image immediately on boot. It records the inherited (CLOEXEC-
// cleared) fd numbers for the listener + each alive PTY master, plus the
// minimum per-surface state needed to re-wire the emulator without forking a
// new shell. The fds themselves survive `execve` because their FD_CLOEXEC bit
// was cleared; the manifest just tells the successor what those fd NUMBERS map
// to.
//
// On-disk layout (`<stateDir>/reexec.manifest`, mode 0600, atomic tmp+rename+
// fsync). The STABLE PREFIX is parseable by EVERY future version so a
// successor that does not recognise the body version can still close the
// carried fds and fall through to a clean fresh start (== today's behavior):
//
//   STABLE PREFIX
//     magic            [4]   "GTRX"
//     version          [2]   reexec_manifest_version
//     writer_pid       [4]   i32   (== the execve'ing pid; preserved across execve)
//     nonce            [16]        (also passed via GHOSTTY_DAEMON_REEXEC, hex)
//     carried_fd_count [4]   u32
//     carried_fds      [n]   i32   (FLAT: listener_fd then every alive master fd)
//   VERSIONED BODY (only when version == reexec_manifest_version)
//     listener_fd      [4]   i32
//     ctl_sock: len[2] + bytes  (control_bridge_socket_path; len 0 = none)
//     ctl_tok:  len[2] + bytes  (control_bridge_token;       len 0 = none)
//     surface_count    [4]   u32
//       group_id       [16]
//       surface_id     [16]
//       pty_master_fd  [4]   i32
//       child_pid      [4]   i32
//       cols rows xpix ypix [2 each] u16
//       max_scrollback [4]   u32
//       size_mode      [1]   u8
//       label:    len[2] + bytes
//       viewport: len[4] + bytes  (VERSION-STABLE serializeViewportAsVT bytes)
// =========================================================================

pub const magic_reexec = [4]u8{ 'G', 'T', 'R', 'X' };

/// Bump when the re-exec manifest BODY layout changes. The STABLE PREFIX is
/// frozen forever so any successor can close carried fds and fall through.
pub const reexec_manifest_version: u16 = 1;

/// One alive surface to re-adopt across an execve handoff.
pub const ReexecSurface = struct {
    group_id: shared.Uuid,
    surface_id: shared.Uuid,
    pty_master_fd: i32,
    child_pid: i32,
    cols: u16,
    rows: u16,
    xpix: u16,
    ypix: u16,
    max_scrollback: u32,
    size_mode: u8,
    /// Owned. Per-surface label (may be empty).
    label: []u8,
    /// Owned. Version-stable viewport VT (may be empty → blank restore).
    viewport: []u8,
};

pub const ReexecManifest = struct {
    version: u16,
    writer_pid: i32,
    nonce: [16]u8,
    /// Lowercase-hex of `nonce`, for comparison against GHOSTTY_DAEMON_REEXEC.
    nonce_hex: [32]u8,
    /// Owned. FLAT carried fd list (listener first, then each alive master).
    /// Always populated from the stable prefix even on a version mismatch so
    /// the successor can close every carried fd before a fresh start.
    carried_fds: []i32,
    /// Body fields (valid only when `version == reexec_manifest_version`).
    listener_fd: i32,
    ctl_sock: ?[]u8,
    ctl_tok: ?[]u8,
    surfaces: []ReexecSurface,

    /// True when the body was parsed (version matched) and adoption is possible.
    pub fn bodyValid(self: *const ReexecManifest) bool {
        return self.version == reexec_manifest_version;
    }

    pub fn deinit(self: *ReexecManifest, alloc: Allocator) void {
        alloc.free(self.carried_fds);
        if (self.ctl_sock) |s| alloc.free(s);
        if (self.ctl_tok) |t| alloc.free(t);
        for (self.surfaces) |*s| {
            alloc.free(s.label);
            alloc.free(s.viewport);
        }
        alloc.free(self.surfaces);
        self.* = undefined;
    }
};

/// Input the OLD daemon hands to `writeReexecManifest`. Borrows everything —
/// the writer only serializes; the daemon retains ownership and frees.
pub const ReexecManifestIn = struct {
    writer_pid: i32,
    nonce: [16]u8,
    listener_fd: i32,
    ctl_sock: ?[]const u8,
    ctl_tok: ?[]const u8,
    surfaces: []const ReexecSurface,
};

fn manifestPath(alloc: Allocator, state_dir: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}/reexec.manifest", .{state_dir});
}

/// Serialize + atomically write the manifest to `<state_dir>/reexec.manifest`
/// (same-dir tmp + fsync + rename, mode 0600). Returns on the first error so
/// the caller can ABORT (re-set CLOEXEC, un-park readers) and fall back.
pub fn writeReexecManifest(
    alloc: Allocator,
    state_dir: []const u8,
    in: ReexecManifestIn,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // ---- STABLE PREFIX ----
    try buf.appendSlice(alloc, &magic_reexec);
    try appendU16(alloc, &buf, reexec_manifest_version);
    try appendI32(alloc, &buf, in.writer_pid);
    try buf.appendSlice(alloc, &in.nonce);
    // carried_fds = listener + each surface master, FLAT.
    const carried_count: u32 = @intCast(1 + in.surfaces.len);
    try appendU32(alloc, &buf, carried_count);
    try appendI32(alloc, &buf, in.listener_fd);
    for (in.surfaces) |s| try appendI32(alloc, &buf, s.pty_master_fd);

    // ---- VERSIONED BODY ----
    try appendI32(alloc, &buf, in.listener_fd);
    try appendLen16(alloc, &buf, in.ctl_sock orelse &.{});
    try appendLen16(alloc, &buf, in.ctl_tok orelse &.{});
    try appendU32(alloc, &buf, @intCast(in.surfaces.len));
    for (in.surfaces) |s| {
        try buf.appendSlice(alloc, &s.group_id);
        try buf.appendSlice(alloc, &s.surface_id);
        try appendI32(alloc, &buf, s.pty_master_fd);
        try appendI32(alloc, &buf, s.child_pid);
        try appendU16(alloc, &buf, s.cols);
        try appendU16(alloc, &buf, s.rows);
        try appendU16(alloc, &buf, s.xpix);
        try appendU16(alloc, &buf, s.ypix);
        try appendU32(alloc, &buf, s.max_scrollback);
        try buf.append(alloc, s.size_mode);
        try appendLen16(alloc, &buf, s.label);
        try appendLen32(alloc, &buf, s.viewport);
    }

    const final_path = try manifestPath(alloc, state_dir);
    defer alloc.free(final_path);
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{final_path});
    defer alloc.free(tmp_path);

    {
        // O_EXCL|O_NOFOLLOW semantics: createFile with exclusive=true refuses an
        // existing/symlink target. Best-effort cleanup of a stale tmp first.
        std.fs.cwd().deleteFile(tmp_path) catch {};
        var file = try std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600, .truncate = true, .exclusive = true });
        defer file.close();
        try file.writeAll(buf.items);
        std.posix.fsync(file.handle) catch {};
    }
    try std.fs.cwd().rename(tmp_path, final_path);
}

const ReexecBody = struct {
    listener_fd: i32,
    ctl_sock: ?[]u8,
    ctl_tok: ?[]u8,
    surfaces: []ReexecSurface,
};

/// Parse the versioned body. Uses errdefer so ANY torn-body failure frees all
/// partial allocations and propagates an error — the caller then degrades to a
/// prefix-only manifest (close carried fds, fresh start). `data`/`off` are the
/// remainder after the stable prefix.
fn parseReexecBody(alloc: Allocator, data: []const u8, off_in: usize) !ReexecBody {
    var off = off_in;
    const listener_fd = readI32(data, &off) orelse return error.Truncated;
    const ctl_sock = try readLen16Owned(alloc, data, &off);
    errdefer if (ctl_sock) |s| alloc.free(s);
    const ctl_tok = try readLen16Owned(alloc, data, &off);
    errdefer if (ctl_tok) |t| alloc.free(t);
    const surface_count = readU32(data, &off) orelse return error.Truncated;
    if (surface_count > 4096) return error.Truncated;

    var surfaces: std.ArrayList(ReexecSurface) = .empty;
    errdefer {
        for (surfaces.items) |*s| {
            alloc.free(s.label);
            alloc.free(s.viewport);
        }
        surfaces.deinit(alloc);
    }
    var i: usize = 0;
    while (i < surface_count) : (i += 1) {
        if (off + 16 + 16 + 4 + 4 + 8 + 4 + 1 > data.len) return error.Truncated;
        var gid: shared.Uuid = undefined;
        @memcpy(&gid, data[off .. off + 16]);
        off += 16;
        var sid: shared.Uuid = undefined;
        @memcpy(&sid, data[off .. off + 16]);
        off += 16;
        const master_fd = readI32(data, &off).?;
        const child_pid = readI32(data, &off).?;
        const cols = readU16(data, &off).?;
        const rows = readU16(data, &off).?;
        const xpix = readU16(data, &off).?;
        const ypix = readU16(data, &off).?;
        const max_sb = readU32(data, &off).?;
        const sm = data[off];
        off += 1;
        const label = (try readLen16Owned(alloc, data, &off)) orelse try alloc.alloc(u8, 0);
        errdefer alloc.free(label);
        const viewport = (try readLen32Owned(alloc, data, &off)) orelse try alloc.alloc(u8, 0);
        errdefer alloc.free(viewport);
        try surfaces.append(alloc, .{
            .group_id = gid,
            .surface_id = sid,
            .pty_master_fd = master_fd,
            .child_pid = child_pid,
            .cols = cols,
            .rows = rows,
            .xpix = xpix,
            .ypix = ypix,
            .max_scrollback = max_sb,
            .size_mode = sm,
            .label = label,
            .viewport = viewport,
        });
    }

    return .{
        .listener_fd = listener_fd,
        .ctl_sock = ctl_sock,
        .ctl_tok = ctl_tok,
        .surfaces = try surfaces.toOwnedSlice(alloc),
    };
}

/// Read + decode `<state_dir>/reexec.manifest`. Returns null on missing/bad-
/// magic/torn-prefix file. On a body version-mismatch OR torn body, the STABLE
/// PREFIX is still returned (surfaces empty, listener_fd = -1) so the caller
/// can close every carried fd and fall through to a fresh start. Caller owns
/// the result (free via `deinit`).
pub fn readReexecManifest(alloc: Allocator, state_dir: []const u8) !?ReexecManifest {
    const final_path = try manifestPath(alloc, state_dir);
    defer alloc.free(final_path);
    const data = std.fs.cwd().readFileAlloc(alloc, final_path, 64 * 1024 * 1024) catch return null;
    defer alloc.free(data);

    var off: usize = 0;
    // Stable prefix — if THIS is unparseable we cannot even close carried fds.
    if (data.len < 4 + 2 + 4 + 16 + 4) return null;
    if (!std.mem.eql(u8, data[0..4], &magic_reexec)) return null;
    off = 4;
    const version = readU16(data, &off) orelse return null;
    const writer_pid = readI32(data, &off) orelse return null;
    var nonce: [16]u8 = undefined;
    @memcpy(&nonce, data[off .. off + 16]);
    off += 16;
    const carried_count = readU32(data, &off) orelse return null;
    if (carried_count > 4096) return null; // sanity bound
    const carried = alloc.alloc(i32, carried_count) catch return null;
    var carried_ok = false;
    defer if (!carried_ok) alloc.free(carried);
    for (0..carried_count) |i| {
        carried[i] = readI32(data, &off) orelse return null;
    }
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);

    // Prefix-only result (version mismatch OR torn body): caller closes the
    // carried fds and starts fresh. carried ownership transfers to the result.
    const prefixOnly = struct {
        fn build(a: Allocator, v: u16, wp: i32, n: [16]u8, nh: [32]u8, c: []i32) ?ReexecManifest {
            const empty = a.alloc(ReexecSurface, 0) catch {
                a.free(c);
                return null;
            };
            return .{
                .version = v,
                .writer_pid = wp,
                .nonce = n,
                .nonce_hex = nh,
                .carried_fds = c,
                .listener_fd = -1,
                .ctl_sock = null,
                .ctl_tok = null,
                .surfaces = empty,
            };
        }
    };

    if (version != reexec_manifest_version) {
        carried_ok = true;
        return prefixOnly.build(alloc, version, writer_pid, nonce, nonce_hex, carried);
    }

    const body = parseReexecBody(alloc, data, off) catch {
        carried_ok = true;
        return prefixOnly.build(alloc, version, writer_pid, nonce, nonce_hex, carried);
    };
    carried_ok = true;
    return .{
        .version = version,
        .writer_pid = writer_pid,
        .nonce = nonce,
        .nonce_hex = nonce_hex,
        .carried_fds = carried,
        .listener_fd = body.listener_fd,
        .ctl_sock = body.ctl_sock,
        .ctl_tok = body.ctl_tok,
        .surfaces = body.surfaces,
    };
}

/// Best-effort delete of the manifest (successor removes it after reading).
pub fn deleteReexecManifest(alloc: Allocator, state_dir: []const u8) void {
    const final_path = manifestPath(alloc, state_dir) catch return;
    defer alloc.free(final_path);
    std.fs.cwd().deleteFile(final_path) catch {};
}

// ---- little-endian scratch helpers (manifest only) ----
fn appendU16(alloc: Allocator, buf: *std.ArrayList(u8), v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try buf.appendSlice(alloc, &b);
}
fn appendU32(alloc: Allocator, buf: *std.ArrayList(u8), v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try buf.appendSlice(alloc, &b);
}
fn appendI32(alloc: Allocator, buf: *std.ArrayList(u8), v: i32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(i32, &b, v, .little);
    try buf.appendSlice(alloc, &b);
}
fn appendLen16(alloc: Allocator, buf: *std.ArrayList(u8), data: []const u8) !void {
    try appendU16(alloc, buf, @intCast(data.len));
    try buf.appendSlice(alloc, data);
}
fn appendLen32(alloc: Allocator, buf: *std.ArrayList(u8), data: []const u8) !void {
    try appendU32(alloc, buf, @intCast(data.len));
    try buf.appendSlice(alloc, data);
}
fn readU16(data: []const u8, off: *usize) ?u16 {
    if (off.* + 2 > data.len) return null;
    const v = std.mem.readInt(u16, data[off.*..][0..2], .little);
    off.* += 2;
    return v;
}
fn readU32(data: []const u8, off: *usize) ?u32 {
    if (off.* + 4 > data.len) return null;
    const v = std.mem.readInt(u32, data[off.*..][0..4], .little);
    off.* += 4;
    return v;
}
fn readI32(data: []const u8, off: *usize) ?i32 {
    if (off.* + 4 > data.len) return null;
    const v = std.mem.readInt(i32, data[off.*..][0..4], .little);
    off.* += 4;
    return v;
}
/// Read a u16-length-prefixed blob; null length-prefix → error; empty → null.
fn readLen16Owned(alloc: Allocator, data: []const u8, off: *usize) !?[]u8 {
    const len = readU16(data, off) orelse return error.Truncated;
    if (off.* + len > data.len) return error.Truncated;
    if (len == 0) return null;
    const out = try alloc.dupe(u8, data[off.*..][0..len]);
    off.* += len;
    return out;
}
fn readLen32Owned(alloc: Allocator, data: []const u8, off: *usize) !?[]u8 {
    const len = readU32(data, off) orelse return error.Truncated;
    if (off.* + len > data.len) return error.Truncated;
    if (len == 0) return null;
    const out = try alloc.dupe(u8, data[off.*..][0..len]);
    off.* += len;
    return out;
}

// =========================================================================
// Tests (pure, no daemon/socket dependency)
// =========================================================================

test "term snapshot encode/decode roundtrip (uncompressed small)" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var snap: Snapshot = .{
        .cols = 80,
        .rows = 24,
        .max_scrollback = 100_000,
        .history_rows = 2,
        .viewport = try alloc.dupe(u8, "hi"), // < 64 bytes → not compressed
        .scrollback = try alloc.dupe(u8, "sb"),
        .chunk_index = try alloc.dupe(ChunkRef, &.{
            .{ .start_row = 0, .row_count = 2, .byte_off = 0, .byte_len = 2 },
        }),
    };
    defer snap.deinit(alloc);

    const body = try encodeSnapshot(alloc, snap);
    defer alloc.free(body);

    var decoded = (try decodeSnapshot(alloc, body)).?;
    defer decoded.deinit(alloc);

    try testing.expectEqual(@as(u16, 80), decoded.cols);
    try testing.expectEqual(@as(u16, 24), decoded.rows);
    try testing.expectEqual(@as(u32, 100_000), decoded.max_scrollback);
    try testing.expectEqual(@as(u32, 2), decoded.history_rows);
    try testing.expectEqualStrings("hi", decoded.viewport);
    try testing.expectEqualStrings("sb", decoded.scrollback);
    try testing.expectEqual(@as(usize, 1), decoded.chunk_index.len);
    try testing.expectEqual(@as(u16, 2), decoded.chunk_index[0].row_count);
}

test "term snapshot roundtrip compressed (large repetitive payload)" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const vp = "\x1b[0m\x1b[H\x1b[2J" ++ ("xterm-ghostty " ** 64);
    const sb = "row-data-" ** 128;

    var snap: Snapshot = .{
        .cols = 120,
        .rows = 40,
        .max_scrollback = 1_000_000,
        .history_rows = 5,
        .viewport = try alloc.dupe(u8, vp),
        .scrollback = try alloc.dupe(u8, sb),
        .chunk_index = try alloc.dupe(ChunkRef, &.{
            .{ .start_row = 0, .row_count = 5, .byte_off = 0, .byte_len = @intCast(sb.len) },
        }),
    };
    defer snap.deinit(alloc);

    const body = try encodeSnapshot(alloc, snap);
    defer alloc.free(body);

    var decoded = (try decodeSnapshot(alloc, body)).?;
    defer decoded.deinit(alloc);
    try testing.expectEqualStrings(vp, decoded.viewport);
    try testing.expectEqualStrings(sb, decoded.scrollback);
}

test "decodeSnapshot rejects bad magic / short / version mismatch" {
    const testing = std.testing;
    const alloc = testing.allocator;

    try testing.expect((try decodeSnapshot(alloc, "")) == null);
    try testing.expect((try decodeSnapshot(alloc, "GTSB")) == null); // too short
    try testing.expect((try decodeSnapshot(alloc, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")) == null);

    // Valid-shaped header but wrong version.
    var snap: Snapshot = .{
        .cols = 1,
        .rows = 1,
        .max_scrollback = 0,
        .history_rows = 0,
        .viewport = try alloc.dupe(u8, ""),
        .scrollback = try alloc.dupe(u8, ""),
        .chunk_index = try alloc.dupe(ChunkRef, &.{}),
    };
    defer snap.deinit(alloc);
    const body = try encodeSnapshot(alloc, snap);
    defer alloc.free(body);
    var mutable = try alloc.dupe(u8, body);
    defer alloc.free(mutable);
    // Bump version byte at offset 4.
    mutable[4] = 0xFF;
    mutable[5] = 0xFF;
    try testing.expect((try decodeSnapshot(alloc, mutable)) == null);
}

test "group.meta write/read roundtrip via tmp dir" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir_path);

    try writeGroupMeta(alloc, dir_path, 3, 1234567, "my-session", "layout-bytes");

    var meta = (try readGroupMeta(alloc, dir_path)).?;
    defer meta.deinit(alloc);
    try testing.expectEqual(@as(i8, 3), meta.color);
    try testing.expectEqual(@as(i64, 1234567), meta.created_at);
    try testing.expectEqualStrings("my-session", meta.label);
    try testing.expect(meta.layout_blob != null);
    try testing.expectEqualStrings("layout-bytes", meta.layout_blob.?);
}

test "writeTermFile then readTermFile roundtrip via tmp dir" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const dir_path = try std.fmt.allocPrint(alloc, "{s}/grp", .{base});
    defer alloc.free(dir_path);

    var snap: Snapshot = .{
        .cols = 80,
        .rows = 24,
        .max_scrollback = 50_000,
        .history_rows = 1,
        .viewport = try alloc.dupe(u8, "viewport-content"),
        .scrollback = try alloc.dupe(u8, "scrollback-content"),
        .chunk_index = try alloc.dupe(ChunkRef, &.{
            .{ .start_row = 0, .row_count = 1, .byte_off = 0, .byte_len = 18 },
        }),
    };
    defer snap.deinit(alloc);

    try writeTermFile(alloc, dir_path, "abcd", snap);

    var got = (try readTermFile(alloc, dir_path, "abcd")).?;
    defer got.deinit(alloc);
    try testing.expectEqualStrings("viewport-content", got.viewport);
    try testing.expectEqualStrings("scrollback-content", got.scrollback);

    // Missing file → null, not error.
    try testing.expect((try readTermFile(alloc, dir_path, "nope")) == null);
}

// -------------------------------------------------------------------------
// Startup scan / enumerate / TTL sweep tests
// -------------------------------------------------------------------------

/// Write a minimal (empty viewport/scrollback) `.term` for `sid` under `dir`.
fn testWriteEmptyTerm(alloc: Allocator, dir: []const u8, sid: shared.Uuid) !void {
    var snap: Snapshot = .{
        .cols = 80,
        .rows = 24,
        .max_scrollback = 1000,
        .history_rows = 0,
        .viewport = try alloc.dupe(u8, ""),
        .scrollback = try alloc.dupe(u8, ""),
        .chunk_index = try alloc.dupe(ChunkRef, &.{}),
    };
    defer snap.deinit(alloc);
    const hex = shared.formatUuid(sid);
    try writeTermFile(alloc, dir, &hex, snap);
}

fn testFindInfo(infos: []PersistedGroupInfo, id: shared.Uuid) ?*PersistedGroupInfo {
    for (infos) |*gi| {
        if (std.mem.eql(u8, &gi.group_id, &id)) return gi;
    }
    return null;
}

fn testHasSurface(ids: []const shared.Uuid, id: shared.Uuid) bool {
    for (ids) |s| {
        if (std.mem.eql(u8, &s, &id)) return true;
    }
    return false;
}

test "scanPersistedGroups enumerates groups + surfaces from real writers" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(root);

    var g1: shared.Uuid = .{0} ** 16;
    g1[0] = 0x11;
    g1[15] = 0xA1;
    var g2: shared.Uuid = .{0} ** 16;
    g2[0] = 0x22;
    g2[15] = 0xB2;

    const g1_hex = shared.formatUuid(g1);
    const g2_hex = shared.formatUuid(g2);
    const g1_dir = try std.fs.path.join(alloc, &.{ root, &g1_hex });
    defer alloc.free(g1_dir);
    const g2_dir = try std.fs.path.join(alloc, &.{ root, &g2_hex });
    defer alloc.free(g2_dir);

    try writeGroupMeta(alloc, g1_dir, 3, 1111, "alpha", "layoutA");
    try writeGroupMeta(alloc, g2_dir, 5, 2222, "beta", null);

    // 2 surfaces in g1, 3 in g2.
    var s1a: shared.Uuid = .{0} ** 16;
    s1a[0] = 0x01;
    var s1b: shared.Uuid = .{0} ** 16;
    s1b[0] = 0x02;
    var s2a: shared.Uuid = .{0} ** 16;
    s2a[0] = 0x03;
    var s2b: shared.Uuid = .{0} ** 16;
    s2b[0] = 0x04;
    var s2c: shared.Uuid = .{0} ** 16;
    s2c[0] = 0x05;
    try testWriteEmptyTerm(alloc, g1_dir, s1a);
    try testWriteEmptyTerm(alloc, g1_dir, s1b);
    try testWriteEmptyTerm(alloc, g2_dir, s2a);
    try testWriteEmptyTerm(alloc, g2_dir, s2b);
    try testWriteEmptyTerm(alloc, g2_dir, s2c);

    const infos = try scanPersistedGroups(alloc, root);
    defer {
        for (infos) |*gi| gi.deinit(alloc);
        alloc.free(infos);
    }

    try testing.expectEqual(@as(usize, 2), infos.len);

    const info1 = testFindInfo(infos, g1) orelse return error.Group1Missing;
    try testing.expectEqual(@as(i8, 3), info1.color);
    try testing.expectEqual(@as(i64, 1111), info1.created_at);
    try testing.expectEqualStrings("alpha", info1.label);
    try testing.expect(info1.layout_blob != null);
    try testing.expectEqualStrings("layoutA", info1.layout_blob.?);
    try testing.expectEqual(@as(usize, 2), info1.surface_ids.len);
    try testing.expect(testHasSurface(info1.surface_ids, s1a));
    try testing.expect(testHasSurface(info1.surface_ids, s1b));

    const info2 = testFindInfo(infos, g2) orelse return error.Group2Missing;
    try testing.expectEqual(@as(i8, 5), info2.color);
    try testing.expectEqual(@as(i64, 2222), info2.created_at);
    try testing.expectEqualStrings("beta", info2.label);
    try testing.expect(info2.layout_blob == null);
    try testing.expectEqual(@as(usize, 3), info2.surface_ids.len);
    try testing.expect(testHasSurface(info2.surface_ids, s2a));
    try testing.expect(testHasSurface(info2.surface_ids, s2b));
    try testing.expect(testHasSurface(info2.surface_ids, s2c));
}

test "scanPersistedGroups tolerates corrupt group + junk surface files" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(root);

    var good: shared.Uuid = .{0} ** 16;
    good[0] = 0xAA;
    const good_hex = shared.formatUuid(good);
    const good_dir = try std.fs.path.join(alloc, &.{ root, &good_hex });
    defer alloc.free(good_dir);
    try writeGroupMeta(alloc, good_dir, 1, 7, "good", null);
    var sg: shared.Uuid = .{0} ** 16;
    sg[0] = 0x77;
    try testWriteEmptyTerm(alloc, good_dir, sg);
    // Junk files that listSurfaceIds must ignore.
    {
        var d = try std.fs.cwd().openDir(good_dir, .{});
        defer d.close();
        try d.writeFile(.{ .sub_path = "notahex.term", .data = "junk" });
        try d.writeFile(.{ .sub_path = "deadbeef.term.tmp", .data = "junk" });
    }

    // A second dir with a CORRUPT group.meta (bad magic) — must be skipped.
    var bad: shared.Uuid = .{0} ** 16;
    bad[0] = 0xBB;
    const bad_hex = shared.formatUuid(bad);
    const bad_dir = try std.fs.path.join(alloc, &.{ root, &bad_hex });
    defer alloc.free(bad_dir);
    try std.fs.cwd().makePath(bad_dir);
    {
        var d = try std.fs.cwd().openDir(bad_dir, .{});
        defer d.close();
        try d.writeFile(.{ .sub_path = "group.meta", .data = "XXXXnotavalidmetafile" });
    }

    const infos = try scanPersistedGroups(alloc, root);
    defer {
        for (infos) |*gi| gi.deinit(alloc);
        alloc.free(infos);
    }

    try testing.expectEqual(@as(usize, 1), infos.len);
    const gi = testFindInfo(infos, good) orelse return error.GoodGroupMissing;
    try testing.expectEqualStrings("good", gi.label);
    try testing.expectEqual(@as(usize, 1), gi.surface_ids.len);
    try testing.expect(testHasSurface(gi.surface_ids, sg));
}

test "sweepExpiredGroups deletes stale groups, keeps fresh ones" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(root);

    var stale: shared.Uuid = .{0} ** 16;
    stale[0] = 0x10;
    const stale_hex = shared.formatUuid(stale);
    const stale_dir = try std.fs.path.join(alloc, &.{ root, &stale_hex });
    defer alloc.free(stale_dir);
    try writeGroupMeta(alloc, stale_dir, 1, 1, "stale", null);

    var fresh: shared.Uuid = .{0} ** 16;
    fresh[0] = 0x20;
    const fresh_hex = shared.formatUuid(fresh);
    const fresh_dir = try std.fs.path.join(alloc, &.{ root, &fresh_hex });
    defer alloc.free(fresh_dir);
    try writeGroupMeta(alloc, fresh_dir, 1, 1, "fresh", null);

    // Back-date the stale group's group.meta mtime by ~100 days.
    {
        const stale_meta = try std.fs.path.join(alloc, &.{ stale_dir, "group.meta" });
        defer alloc.free(stale_meta);
        var f = try std.fs.cwd().openFile(stale_meta, .{ .mode = .read_write });
        defer f.close();
        const past_ns: i128 = @as(i128, std.time.timestamp() - 100 * 24 * 3600) * std.time.ns_per_s;
        try f.updateTimes(past_ns, past_ns);
    }

    // TTL = 7 days. Stale (100 days old) is swept; fresh survives.
    sweepExpiredGroups(alloc, root, 7 * 24 * 3600);

    const stale_gone = if (std.fs.cwd().access(stale_dir, .{})) |_| false else |err| err == error.FileNotFound;
    try testing.expect(stale_gone);
    try std.fs.cwd().access(fresh_dir, .{}); // still present (no error)
}

test "metadata survives a term-format-version bump (split version constants)" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(root);

    var g: shared.Uuid = .{0} ** 16;
    g[0] = 0x33;
    const g_hex = shared.formatUuid(g);
    const g_dir = try std.fs.path.join(alloc, &.{ root, &g_hex });
    defer alloc.free(g_dir);
    try writeGroupMeta(alloc, g_dir, 2, 99, "survivor", "layoutZ");

    // Write a `.term` whose version field is a FUTURE term_format_version
    // (simulating a scrollback-format bump the running daemon predates).
    var sid: shared.Uuid = .{0} ** 16;
    sid[0] = 0x44;
    const sid_hex = shared.formatUuid(sid);
    {
        var snap: Snapshot = .{
            .cols = 80,
            .rows = 24,
            .max_scrollback = 1000,
            .history_rows = 0,
            .viewport = try alloc.dupe(u8, ""),
            .scrollback = try alloc.dupe(u8, ""),
            .chunk_index = try alloc.dupe(ChunkRef, &.{}),
        };
        defer snap.deinit(alloc);
        const body = try encodeSnapshot(alloc, snap);
        defer alloc.free(body);
        // Bump the version field (offset 4..6) past term_format_version.
        std.mem.writeInt(u16, body[4..6], term_format_version +% 1, .little);
        const term_path = try std.fmt.allocPrint(alloc, "{s}/{s}.term", .{ g_dir, &sid_hex });
        defer alloc.free(term_path);
        try std.fs.cwd().writeFile(.{ .sub_path = term_path, .data = body });
    }

    // group.meta still decodes (meta_format_version unaffected by term bump).
    var meta = (try readGroupMeta(alloc, g_dir)).?;
    defer meta.deinit(alloc);
    try testing.expectEqualStrings("survivor", meta.label);
    try testing.expectEqual(@as(i8, 2), meta.color);

    // The bumped-version .term is rejected by decodeSnapshot (scrollback dropped).
    try testing.expect((try readTermFile(alloc, g_dir, &sid_hex)) == null);

    // ...but the session + surface still appear in the startup scan, so
    // `--list` / the chooser / the layout survive a scrollback-format bump.
    const infos = try scanPersistedGroups(alloc, root);
    defer {
        for (infos) |*gi| gi.deinit(alloc);
        alloc.free(infos);
    }
    const gi = testFindInfo(infos, g) orelse return error.SurvivorMissing;
    try testing.expectEqualStrings("survivor", gi.label);
    try testing.expect(gi.layout_blob != null);
    try testing.expectEqualStrings("layoutZ", gi.layout_blob.?);
    try testing.expectEqual(@as(usize, 1), gi.surface_ids.len);
    try testing.expect(testHasSurface(gi.surface_ids, sid));
}
