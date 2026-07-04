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
//!
//! MODULE SPLIT (pure code motion): the GTSB `.term` scrollback codec now
//! lives in `persist_scrollback.zig` and the GTRX re-exec handoff manifest
//! in `persist_reexec.zig`. This file re-exports their public symbols so
//! existing `persist.Symbol` importers keep resolving, and itself keeps the
//! group.meta metadata, the startup scan / TTL sweep, and the `.term`
//! file-I/O helpers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

const log = std.log.scoped(.ssh_persist);

// Re-exported from the split-out scrollback codec (persist_scrollback.zig) so
// external `persist.Symbol` importers and the kept code below resolve.
pub const magic_term = @import("persist_scrollback.zig").magic_term;
pub const term_format_version = @import("persist_scrollback.zig").term_format_version;
pub const max_scrollback_file_bytes = @import("persist_scrollback.zig").max_scrollback_file_bytes;
pub const ChunkRef = @import("persist_scrollback.zig").ChunkRef;
pub const Snapshot = @import("persist_scrollback.zig").Snapshot;
pub const historyRows = @import("persist_scrollback.zig").historyRows;
pub const capture = @import("persist_scrollback.zig").capture;
pub const encodeSnapshot = @import("persist_scrollback.zig").encodeSnapshot;
pub const decodeSnapshot = @import("persist_scrollback.zig").decodeSnapshot;
pub const restore = @import("persist_scrollback.zig").restore;

// Re-exported from the split-out re-exec manifest codec (persist_reexec.zig).
pub const magic_reexec = @import("persist_reexec.zig").magic_reexec;
pub const reexec_manifest_version = @import("persist_reexec.zig").reexec_manifest_version;
pub const ReexecSurface = @import("persist_reexec.zig").ReexecSurface;
pub const ReexecManifest = @import("persist_reexec.zig").ReexecManifest;
pub const ReexecManifestIn = @import("persist_reexec.zig").ReexecManifestIn;
pub const writeReexecManifest = @import("persist_reexec.zig").writeReexecManifest;
pub const readReexecManifest = @import("persist_reexec.zig").readReexecManifest;
pub const deleteReexecManifest = @import("persist_reexec.zig").deleteReexecManifest;

pub const magic_group = [4]u8{ 'G', 'T', 'G', 'M' };

/// Bump when the GTGM (group.meta) layout changes. Independent of term churn,
/// so a scrollback-format bump never drops the session list / names / layout.
/// A mismatch is treated as "no persisted metadata".
pub const meta_format_version: u16 = 1;

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

// Pull the split-out siblings into the test binary so their inline tests
// (if any) stay discoverable alongside the facade's own kept tests.
test {
    _ = @import("persist_scrollback.zig");
    _ = @import("persist_reexec.zig");
}
