//! Re-exec handoff manifest: the GTRX execve self-handoff manifest codec.
//!
//! Split out of `persist.zig` (pure code motion); `persist.zig` re-exports
//! the public symbols here so existing `persist.Symbol` importers keep
//! resolving. Written by the OLD daemon image immediately before `execve`
//! and read by the NEW daemon image on boot to re-adopt inherited fds and
//! surfaces without forking a new shell. The detailed on-disk layout is
//! documented in the section comment below.

const std = @import("std");
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

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
