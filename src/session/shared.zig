const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const internal_os = @import("../os/main.zig");

pub const state_subdir = "ghostty/remote-session";
pub const remote_binary_name = "ghostty";
pub const remote_daemon_binary_name = "ghostty-daemon";
/// The CLI subcommand used to invoke the remote session modes.
pub const remote_subcommand = "+ssh-session";

/// Base URL for downloading pre-built daemon binaries from CI releases.
pub const release_base_url = "https://github.com/DAmesberger/ghostty/releases/download";

const posix = std.posix;
const protocol = @import("../session.zig").protocol;

/// Write a single protocol frame to a file descriptor.
/// This is the canonical frame-send function — use this everywhere
/// instead of duplicating frame write logic.
///
/// Writes header + payload as two sequential writeAll calls (the OS
/// will coalesce into one TCP segment for small frames via Nagle or
/// cork). For the common case this is 2 syscalls total, which is
/// better than the previous streaming approach that split large
/// payloads into many 1KB writes.
pub fn sendFrameFd(fd: posix.fd_t, kind: protocol.Kind, target: u16, payload: []const u8) !void {
    try sendFrameFile(.{ .handle = fd }, kind, .{}, target, payload);
}

pub fn sendFrameFile(file: std.fs.File, kind: protocol.Kind, flags: protocol.Flags, target: u16, payload: []const u8) !void {
    if (payload.len > protocol.max_payload) return error.PayloadTooLarge;
    const header = (protocol.Header{
        .kind = kind,
        .flags = flags,
        .target = target,
        .len = @intCast(payload.len),
    }).encodeToBuf();
    try file.writeAll(&header);
    if (payload.len > 0) try file.writeAll(payload);
}

const lz4 = @import("lz4.zig");

/// Compress payload data using LZ4 block format. Returns compressed data
/// with a 4-byte LE original length prefix (caller owns).
/// Returns null if compression doesn't reduce size or data is too small.
pub fn compressPayload(alloc: Allocator, data: []const u8, level: u8) ?[]u8 {
    if (level == 0 or data.len < 64) return null;

    const compressed = lz4.compress(alloc, data) orelse return null;
    defer alloc.free(compressed);

    // Prepend original length (4 bytes LE) so decompressor knows the output size.
    const result = alloc.alloc(u8, 4 + compressed.len) catch return null;
    std.mem.writeInt(u32, result[0..4], @intCast(data.len), .little);
    @memcpy(result[4..], compressed);
    return result;
}

/// Decompress LZ4-compressed payload. The first 4 bytes are the original
/// uncompressed length (LE). Returns decompressed data (caller owns).
pub fn decompressPayload(alloc: Allocator, data: []const u8) ![]u8 {
    if (data.len < 4) return error.InvalidLz4Data;
    const orig_len = std.mem.readInt(u32, data[0..4], .little);
    // The 4-byte length prefix is attacker-controllable on the wire and in
    // persisted state, so validate it BEFORE lz4.decompress allocates a
    // buffer of that size. A decompressed payload can never legitimately
    // exceed a single protocol frame (max_payload = 256 KiB); reject anything
    // larger so a forged prefix can't force a multi-GiB allocation.
    if (orig_len > protocol.max_payload) return error.Lz4PayloadTooLarge;
    return lz4.decompress(alloc, data[4..], orig_len);
}

/// Write a protocol frame with LZ4 compression if beneficial.
/// Falls back to uncompressed if compression doesn't reduce size.
pub fn sendFrameFdCompressed(
    fd: posix.fd_t,
    kind: protocol.Kind,
    target: u16,
    payload: []const u8,
    alloc: Allocator,
) !void {
    if (compressPayload(alloc, payload, 1)) |compressed| {
        defer alloc.free(compressed);
        const header = (protocol.Header{
            .kind = kind,
            .flags = .{ .compressed = true },
            .target = target,
            .len = @intCast(compressed.len),
        }).encodeToBuf();
        var file: std.fs.File = .{ .handle = fd };
        try file.writeAll(&header);
        try file.writeAll(compressed);
    } else {
        try sendFrameFd(fd, kind, target, payload);
    }
}

/// Check if all viewers support compression.
pub fn allViewersSupportsCompression(viewers: []const @import("remote_session.zig").RemoteSession.ViewerSlot) bool {
    for (viewers) |v| {
        if (!v.compression_enabled) return false;
    }
    return viewers.len > 0;
}

/// Zero-fill a buffer before freeing it, preventing sensitive data
/// (passwords, keys) from lingering in deallocated memory.
///
/// Uses std.crypto.secureZero (volatile pointer barrier) so the compiler
/// cannot treat the zero-fill as a dead store before deallocation.
/// Calls rawFree directly to avoid Allocator.free's debug undefined-fill
/// clobbering the zeros.
pub fn secureZeroAndFree(alloc: Allocator, buf: []const u8) void {
    const mutable: []u8 = @constCast(buf);
    std.crypto.secureZero(u8, mutable);
    alloc.rawFree(mutable, .fromByteUnits(@alignOf(u8)), @returnAddress());
}

test "secureZeroAndFree zeroes buffer before free" {
    // RecordingAllocator snapshots buffer contents just before forwarding
    // free() to the backing allocator.  If the compiler elided the secure
    // zero the snapshot would still contain the original non-zero pattern.
    const RecordingAllocator = struct {
        backing: Allocator,
        snapshot: [256]u8 = undefined,
        snapshot_len: usize = 0,

        fn vtFree(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const copy_len = @min(buf.len, self.snapshot.len);
            @memcpy(self.snapshot[0..copy_len], buf[0..copy_len]);
            self.snapshot_len = copy_len;
            self.backing.rawFree(buf, alignment, ret_addr);
        }

        fn vtAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawAlloc(len, alignment, ret_addr);
        }

        fn vtResize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawResize(buf, alignment, new_len, ret_addr);
        }

        fn vtRemap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawRemap(buf, alignment, new_len, ret_addr);
        }

        fn allocator(self: *@This()) Allocator {
            return .{ .ptr = self, .vtable = &.{
                .alloc = vtAlloc,
                .resize = vtResize,
                .remap = vtRemap,
                .free = vtFree,
            } };
        }
    };

    const testing = std.testing;
    var rec = RecordingAllocator{ .backing = testing.allocator };
    const a = rec.allocator();

    const len = 32;
    const secret_pattern: u8 = 0xAB;
    const buf = try a.alloc(u8, len);
    @memset(buf, secret_pattern);

    secureZeroAndFree(a, buf);

    // All bytes in the snapshot must be zero — not the original 0xAB pattern.
    try testing.expectEqual(len, rec.snapshot_len);
    for (rec.snapshot[0..rec.snapshot_len]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

pub const ControlCommand = enum {
    detach,
    reconnect,
};

pub fn stateDir(alloc: Allocator) ![]const u8 {
    return try internal_os.xdg.state(alloc, .{ .subdir = state_subdir });
}

pub fn registryPath(alloc: Allocator) ![]const u8 {
    const dir = try stateDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, "registry" });
}

pub fn sessionDir(alloc: Allocator) ![]const u8 {
    const dir = try stateDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, "sessions" });
}

pub fn socketPath(alloc: Allocator) ![]const u8 {
    const dir = try stateDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, "daemon.sock" });
}

/// Root directory for daemon-side scrollback persistence (cmux first cut):
/// `<stateDir>/state`. Each group gets a `<group_hex>/` subdir holding one
/// `<surface_hex>.term` file per surface plus a `group.meta` file.
pub fn persistDir(alloc: Allocator) ![]u8 {
    const dir = try stateDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, "state" });
}

/// Per-group persistence directory: `<stateDir>/state/<group_hex>`.
pub fn groupPersistDir(alloc: Allocator, persist_root: []const u8, group: Uuid) ![]u8 {
    const hex = formatUuid(group);
    return try std.fs.path.join(alloc, &.{ persist_root, &hex });
}

/// Build the remote install directory path, platform-aware.
/// - macOS (Darwin): ~/Library/Application Support/com.ghostty/bin
/// - Linux/FreeBSD:  ~/.local/state/ghostty/bin (XDG_STATE_HOME default)
pub fn remoteInstallDir(alloc: Allocator, remote_home: []const u8, remote_os: []const u8) ![]const u8 {
    const suffix = if (std.mem.eql(u8, remote_os, "Darwin"))
        "Library/Application Support/com.ghostty/bin"
    else
        ".local/state/ghostty/bin";
    return try std.fs.path.join(alloc, &.{ remote_home, suffix });
}

pub fn remoteInstallPath(alloc: Allocator, remote_home: []const u8, remote_os: []const u8) ![]const u8 {
    const dir = try remoteInstallDir(alloc, remote_home, remote_os);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, remote_binary_name });
}

pub fn remoteDaemonInstallPath(alloc: Allocator, remote_home: []const u8, remote_os: []const u8) ![]const u8 {
    const dir = try remoteInstallDir(alloc, remote_home, remote_os);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, remote_daemon_binary_name });
}

/// Normalize raw `uname -s` output to the OS name used in release artifacts.
pub fn normalizeOs(uname_s: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(uname_s, "Darwin")) return "macos";
    if (std.ascii.eqlIgnoreCase(uname_s, "Linux")) return "linux";
    // Pass through as-is for unrecognized values (e.g. FreeBSD).
    return uname_s;
}

/// Normalize raw `uname -m` output to the arch name used in release artifacts.
pub fn normalizeArch(uname_m: []const u8) []const u8 {
    if (std.mem.eql(u8, uname_m, "arm64")) return "aarch64";
    if (std.mem.eql(u8, uname_m, "x86_64")) return "x86_64";
    if (std.mem.eql(u8, uname_m, "aarch64")) return "aarch64";
    return uname_m;
}

/// A parsed and validated SSH connection target.
/// Returned slices point into the original input string.
pub const ParsedSshTarget = struct {
    /// The target host segment (user@host or user@host:port).
    target: []const u8,
    /// Comma-separated jump host chain, or null if direct connection.
    jump: ?[]const u8,
};

/// Validate a single SSH host segment: `user@host` or `user@host:port`.
/// No spaces allowed. Must have a `@` separating non-empty user and host.
/// Returns a human-readable error message, or null if valid.
pub fn validateHostSegment(segment: []const u8) ?[]const u8 {
    if (segment.len == 0) return "empty host segment";

    // No spaces allowed in a segment
    if (std.mem.indexOf(u8, segment, " ") != null) return "spaces not allowed in host segment";

    // Must contain exactly one @
    const at_pos = std.mem.indexOf(u8, segment, "@") orelse return "missing @ — use user@host";
    const user = segment[0..at_pos];
    const host_port = segment[at_pos + 1 ..];

    if (user.len == 0) return "missing username before @";
    if (host_port.len == 0) return "missing hostname after @";

    // Validate user: alphanumeric, dash, underscore, dot
    for (user) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') {
            return "invalid character in username";
        }
    }

    // Split host:port if colon present
    var host = host_port;
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        const port_str = host_port[colon + 1 ..];
        if (port_str.len > 0) {
            _ = std.fmt.parseInt(u16, port_str, 10) catch return "invalid port number";
        }
        host = host_port[0..colon];
    }

    if (host.len == 0) return "missing hostname";

    // Validate host: alphanumeric, dash, dot, brackets/colon (IPv6)
    for (host) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '.' and
            ch != '[' and ch != ']' and ch != ':')
        {
            return "invalid character in hostname";
        }
    }

    return null; // Valid
}

/// Parse and validate a full SSH target string.
///
/// Format: `user@host[:port] [via jump1@host1,jump2@host2,...]`
///
/// 1. Split on ` via ` → left is target, right is jump chain
/// 2. Split jump chain on `,` → individual jump host segments
/// 3. Validate each segment with `validateHostSegment` (no spaces, has @, valid chars)
///
/// Returns a human-readable error message, or null if valid.
pub fn validateSshTarget(raw: []const u8) ?[]const u8 {
    const parsed = parseSshTarget(raw);

    if (parsed.target.len == 0) return "target is empty";

    if (validateHostSegment(parsed.target)) |err| {
        return err;
    }

    if (parsed.jump) |jump| {
        var it = std.mem.splitScalar(u8, jump, ',');
        while (it.next()) |hop| {
            const trimmed = std.mem.trim(u8, hop, " \t");
            if (validateHostSegment(trimmed)) |err| {
                return err;
            }
        }
    }

    return null;
}

/// Parse an SSH target string, splitting on ` via ` for jump hosts.
/// Does NOT validate — call `validateSshTarget` first for user input.
/// Used internally where the format is already known-good (e.g., from config).
pub fn parseSshTarget(raw: []const u8) ParsedSshTarget {
    if (std.mem.indexOf(u8, raw, " via ")) |idx| {
        const target = std.mem.trim(u8, raw[0..idx], " \t\r\n");
        const jump = std.mem.trim(u8, raw[idx + 5 ..], " \t\r\n");
        return .{
            .target = target,
            .jump = if (jump.len > 0) jump else null,
        };
    }
    return .{ .target = std.mem.trim(u8, raw, " \t\r\n"), .jump = null };
}

/// Format a target + optional jump back into the canonical "via" string.
/// Caller owns the returned memory.
pub fn formatSshTarget(alloc: Allocator, target: []const u8, jump: ?[]const u8) ![]const u8 {
    if (jump) |j| {
        return try std.fmt.allocPrint(alloc, "{s} via {s}", .{ target, j });
    }
    return try alloc.dupe(u8, target);
}

/// Construct the full download URL for a daemon binary release asset.
/// Caller owns the returned string.
pub fn daemonDownloadUrl(
    alloc: Allocator,
    proto_version: u16,
    os: []const u8,
    arch: []const u8,
) ![]const u8 {
    return try std.fmt.allocPrint(
        alloc,
        "{s}/ghostty-daemon-v{d}/ghostty-daemon-{s}-{s}",
        .{ release_base_url, proto_version, os, arch },
    );
}

pub fn sanitizeLabelAlloc(alloc: Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return try alloc.dupe(u8, "session");

    var out = try alloc.alloc(u8, trimmed.len);
    for (trimmed, 0..) |c, i| {
        out[i] = switch (c) {
            'a'...'z',
            'A'...'Z',
            '0'...'9',
            '-',
            '_',
            '.',
            => c,
            else => '-',
        };
    }

    return out;
}

pub fn generateSessionId(alloc: Allocator) ![]u8 {
    var random_bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const random_hex = std.fmt.bytesToHex(random_bytes, .lower);
    return try std.fmt.allocPrint(
        alloc,
        "{d}-{s}",
        .{ std.time.timestamp(), random_hex[0..] },
    );
}

/// 128-bit UUID used for group_id and surface_id in multi-surface sessions.
/// Transmitted as 16 raw bytes on the wire for efficiency.
pub const Uuid = [16]u8;

/// Generate a random v4 UUID.
pub fn generateUuid() Uuid {
    var uuid: Uuid = undefined;
    std.crypto.random.bytes(&uuid);
    // Set version 4 (bits 48-51)
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    // Set variant 1 (bits 64-65)
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    return uuid;
}

/// Format a UUID as a hex string (32 lowercase hex chars, no dashes).
pub fn formatUuid(uuid: Uuid) [32]u8 {
    return std.fmt.bytesToHex(uuid, .lower);
}

/// Format a UUID as a standard dashed string (36 chars: 8-4-4-4-12).
pub fn formatUuidDashed(uuid: Uuid) [36]u8 {
    const hex = std.fmt.bytesToHex(uuid, .lower);
    var out: [36]u8 = undefined;
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
    return out;
}

/// Parse a UUID from a 32-char hex string (no dashes).
pub fn parseUuid(hex: []const u8) !Uuid {
    if (hex.len != 32) return error.InvalidUuid;
    var uuid: Uuid = undefined;
    for (0..16) |i| {
        uuid[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidUuid;
    }
    return uuid;
}

/// Parse a UUID from a 36-char dashed string (8-4-4-4-12).
pub fn parseUuidDashed(s: []const u8) !Uuid {
    if (s.len != 36) return error.InvalidUuid;
    if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') return error.InvalidUuid;
    // Strip dashes and parse as hex
    var hex: [32]u8 = undefined;
    @memcpy(hex[0..8], s[0..8]);
    @memcpy(hex[8..12], s[9..13]);
    @memcpy(hex[12..16], s[14..18]);
    @memcpy(hex[16..20], s[19..23]);
    @memcpy(hex[20..32], s[24..36]);
    return parseUuid(&hex);
}

/// The zero UUID, used as a sentinel for "no ID".
pub const zero_uuid: Uuid = .{0} ** 16;

/// Check if a UUID is the zero sentinel.
pub fn isZeroUuid(uuid: Uuid) bool {
    return std.mem.eql(u8, &uuid, &zero_uuid);
}

/// Word lists for generating human-readable session names.
/// 64 adjectives × 64 nouns = 4096 unique combinations.
const adjectives = [64][]const u8{
    "bold", "calm", "cool", "dark", "deep", "fair", "fast", "fine",
    "free", "glad", "gold", "good", "gray", "grim", "keen", "kind",
    "late", "lean", "live", "lone", "lost", "mild", "near", "neat",
    "next", "pale", "pure", "rare", "rich", "safe", "slim", "slow",
    "soft", "sure", "tall", "thin", "true", "vast", "warm", "weak",
    "wide", "wild", "wise", "blue", "cold", "dear", "easy", "even",
    "flat", "full", "half", "hard", "high", "just", "last", "long",
    "loud", "main", "more", "much", "nice", "open", "real", "same",
};

const nouns = [64][]const u8{
    "arch", "bark", "bell", "bird", "bolt", "bone", "cape", "cave",
    "claw", "coin", "cone", "cove", "crow", "dawn", "deer", "dove",
    "drum", "dune", "dust", "echo", "edge", "fern", "fish", "fawn",
    "frog", "gate", "glow", "hare", "hawk", "hill", "iris", "jade",
    "lake", "lark", "leaf", "lily", "lynx", "mesa", "mint", "moon",
    "moss", "moth", "nest", "nova", "opal", "orca", "palm", "peak",
    "pine", "pond", "rain", "reed", "reef", "rose", "sage", "seal",
    "snow", "star", "swan", "tarn", "tide", "vine", "wave", "wolf",
};

/// Generate a human-readable session name deterministically from a UUID.
/// Returns an "adjective-noun" string like "bold-hawk" or "calm-reef".
pub fn generateReadableName(alloc: Allocator, uuid: Uuid) ![]u8 {
    const adj_idx = uuid[0] & 0x3F;
    const noun_idx = uuid[1] & 0x3F;
    return try std.fmt.allocPrint(alloc, "{s}-{s}", .{ adjectives[adj_idx], nouns[noun_idx] });
}

/// Unified SSH connection context that bundles all SSH properties into a
/// single value type. Replaces threading individual optional fields through
/// multiple layers (ssh_target, ssh-session, _ssh-group-id, _ssh-surface-id,
/// reconnect config).
pub const SshConnectionContext = struct {
    target: []const u8,
    jump: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    label: ?[]const u8 = null,
    group_id: Uuid = zero_uuid,
    surface_id: Uuid = zero_uuid,
    reconnect_attempts: u32 = 5,
    reconnect_backoff: SshReconnectBackoff = .exponential,
    reconnect_interval_ms: u32 = 1000,

    pub const SshReconnectBackoff = @import("../config.zig").Config.SshReconnectBackoff;

    /// Construct from config fields. Returns null if ssh-target is not set.
    /// The ssh-target field supports "via" syntax: "user@host via jump".
    pub fn fromConfig(config: anytype) ?SshConnectionContext {
        const raw_target = config.@"ssh-target" orelse return null;
        const parsed = parseSshTarget(raw_target);

        const group_id = if (config.@"_ssh-group-id") |gid_hex|
            parseUuid(gid_hex) catch zero_uuid
        else
            zero_uuid;

        const surface_id = if (config.@"_ssh-surface-id") |sid_hex|
            parseUuid(sid_hex) catch zero_uuid
        else
            zero_uuid;

        return .{
            .target = parsed.target,
            .jump = parsed.jump,
            .session_id = config.@"ssh-session",
            .label = config.@"_ssh-label",
            .group_id = group_id,
            .surface_id = surface_id,
            .reconnect_attempts = config.@"ssh-reconnect-attempts",
            .reconnect_backoff = config.@"ssh-reconnect-backoff",
            .reconnect_interval_ms = config.@"ssh-reconnect-interval",
        };
    }

    /// Apply this context's properties to a config, allocating strings
    /// in the config's arena. Encodes jump host into "via" syntax.
    pub fn applyToConfig(self: SshConnectionContext, config: anytype) !void {
        const alloc = config.arenaAlloc();
        config.@"ssh-target" = try formatSshTarget(alloc, self.target, self.jump);
        if (self.session_id) |s| {
            config.@"ssh-session" = try alloc.dupe(u8, s);
        }
        if (!isZeroUuid(self.group_id)) {
            const hex = formatUuid(self.group_id);
            config.@"_ssh-group-id" = try alloc.dupe(u8, &hex);
        }
        if (!isZeroUuid(self.surface_id)) {
            const hex = formatUuid(self.surface_id);
            config.@"_ssh-surface-id" = try alloc.dupe(u8, &hex);
        }
        if (self.label) |label| {
            config.@"_ssh-label" = try alloc.dupe(u8, label);
        }
        config.@"ssh-reconnect-attempts" = self.reconnect_attempts;
        config.@"ssh-reconnect-backoff" = self.reconnect_backoff;
        config.@"ssh-reconnect-interval" = self.reconnect_interval_ms;
    }

    /// Deep copy all owned strings.
    pub fn dupe(self: SshConnectionContext, alloc: Allocator) !SshConnectionContext {
        return .{
            .target = try alloc.dupe(u8, self.target),
            .jump = if (self.jump) |j| try alloc.dupe(u8, j) else null,
            .session_id = if (self.session_id) |s| try alloc.dupe(u8, s) else null,
            .label = if (self.label) |l| try alloc.dupe(u8, l) else null,
            .group_id = self.group_id,
            .surface_id = self.surface_id,
            .reconnect_attempts = self.reconnect_attempts,
            .reconnect_backoff = self.reconnect_backoff,
            .reconnect_interval_ms = self.reconnect_interval_ms,
        };
    }

    /// Returns a context for spawning a new surface (tab/split) that inherits
    /// connection parameters and group from this context but gets fresh IDs.
    pub fn forNewSurface(self: SshConnectionContext) SshConnectionContext {
        return .{
            .target = self.target,
            .jump = self.jump,
            .group_id = self.group_id,
            .reconnect_attempts = self.reconnect_attempts,
            .reconnect_backoff = self.reconnect_backoff,
            .reconnect_interval_ms = self.reconnect_interval_ms,
        };
    }

    /// Free owned string copies.
    pub fn deinit(self: *SshConnectionContext, alloc: Allocator) void {
        alloc.free(self.target);
        if (self.jump) |j| alloc.free(j);
        if (self.session_id) |s| alloc.free(s);
        if (self.label) |l| alloc.free(l);
        self.* = undefined;
    }
};

/// Thread-safe authentication state for interactive password prompts.
/// Shared between the SSH thread (waits on cond) and the UI thread
/// (signals password/cancel).
pub const AuthState = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    /// Password provided by the UI thread. null = not yet provided.
    password: ?[]const u8 = null,
    /// True if the user cancelled the password prompt.
    cancelled: bool = false,
};

/// Thread-safe decision state for the interactive remote-daemon update
/// confirmation gate. Shared between the SSH thread (which blocks on
/// `cond` after broadcasting `.update_confirmation_required`) and the
/// UI thread (which signals the user's decision). Mirrors `AuthState`.
///
/// The gate fires when a content-hash-mismatched daemon upload would
/// restart a remote daemon that is ALREADY RUNNING with live sessions.
/// The user picks "Update & restart" (proceed with upload + force
/// restart, killing sessions) or "Keep current" (reuse the running
/// protocol-compatible daemon, no kill). The decision flows back here.
pub const UpdateState = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    /// True once the UI thread has recorded a decision. The SSH thread
    /// blocks on `cond` until this flips.
    decided: bool = false,
    /// Meaningful only when `decided` is true. true = update & restart
    /// (proceed to upload), false = keep current (reuse running daemon).
    approved: bool = false,
};

/// Shift an ArrayList buffer forward, discarding the first `amount` bytes.
/// Used by protocol frame parsers to consume processed data.
pub fn shiftBuffer(buf: *std.ArrayList(u8), amount: usize) void {
    if (amount >= buf.items.len) {
        buf.shrinkRetainingCapacity(0);
    } else {
        std.mem.copyForwards(u8, buf.items, buf.items[amount..]);
        buf.shrinkRetainingCapacity(buf.items.len - amount);
    }
}

pub const Platform = struct {
    os: []const u8,
    arch: []const u8,
};

pub fn localPlatform() Platform {
    return .{
        .os = @tagName(builtin.os.tag),
        .arch = @tagName(builtin.cpu.arch),
    };
}

test "generate readable name" {
    const testing = std.testing;

    // A deterministic UUID should always produce the same name.
    const uuid: Uuid = .{ 0x02, 0x05, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0 };
    const name = try generateReadableName(testing.allocator, uuid);
    defer testing.allocator.free(name);

    // adj index 0x02 & 0x3F = 2 → "cool", noun index 0x05 & 0x3F = 5 → "bone"
    try testing.expectEqualStrings("cool-bone", name);
}

test "lz4 compress/decompress roundtrip via shared API" {
    const testing = std.testing;
    // Repetitive data (like VT sequences) should compress well.
    const input = "\x1b[38;2;255;128;0m" ** 100 ++ "Hello, World! " ** 50;

    const compressed = compressPayload(testing.allocator, input, 3) orelse
        return error.CompressionFailed;
    defer testing.allocator.free(compressed);

    // Verify it actually compressed (4-byte header + compressed data < input).
    try testing.expect(compressed.len < input.len);

    // Decompress and verify roundtrip.
    const decompressed = try decompressPayload(testing.allocator, compressed);
    defer testing.allocator.free(decompressed);
    try testing.expectEqualSlices(u8, input, decompressed);
}

test "compressPayload returns null for tiny data" {
    const result = compressPayload(std.testing.allocator, "hi", 3);
    try std.testing.expect(result == null);
}

test "sanitize label" {
    const testing = std.testing;

    const value = try sanitizeLabelAlloc(testing.allocator, "hello world");
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("hello-world", value);
}

test "SshConnectionContext round-trips label through config" {
    const testing = std.testing;
    const Config = @import("../config.zig").Config;

    var config = try Config.default(testing.allocator);
    defer config.deinit();

    const ctx_in: SshConnectionContext = .{
        .target = "user@host",
        .session_id = "deadbeefdeadbeefdeadbeefdeadbeef",
        .label = "my-workspace-title",
    };
    try ctx_in.applyToConfig(&config);

    // The label must be persisted to the dedicated config field, NOT
    // left null (the bug) or conflated with the session_id hex.
    try testing.expect(config.@"_ssh-label" != null);
    try testing.expectEqualStrings("my-workspace-title", config.@"_ssh-label".?);

    const ctx_out = SshConnectionContext.fromConfig(&config) orelse
        return error.FromConfigReturnedNull;
    try testing.expect(ctx_out.label != null);
    try testing.expectEqualStrings("my-workspace-title", ctx_out.label.?);

    // Regression guard: the recovered label must be the human title,
    // never the hex session_id that used to leak through.
    try testing.expect(!std.mem.eql(u8, ctx_out.label.?, ctx_out.session_id.?));
}

test "SshConnectionContext omits label config when unlabeled" {
    const testing = std.testing;
    const Config = @import("../config.zig").Config;

    var config = try Config.default(testing.allocator);
    defer config.deinit();

    // No label set → daemon-generated-name (bare-ghostty) contract:
    // applyToConfig must leave _ssh-label null so fromConfig yields a
    // null label and Remote.zig sends "" (daemon generateReadableName).
    const ctx_in: SshConnectionContext = .{ .target = "user@host" };
    try ctx_in.applyToConfig(&config);
    try testing.expect(config.@"_ssh-label" == null);

    const ctx_out = SshConnectionContext.fromConfig(&config) orelse
        return error.FromConfigReturnedNull;
    try testing.expect(ctx_out.label == null);
}

test "normalizeOs" {
    const testing = std.testing;
    try testing.expectEqualStrings("macos", normalizeOs("Darwin"));
    try testing.expectEqualStrings("macos", normalizeOs("darwin"));
    try testing.expectEqualStrings("linux", normalizeOs("Linux"));
    try testing.expectEqualStrings("linux", normalizeOs("linux"));
    try testing.expectEqualStrings("FreeBSD", normalizeOs("FreeBSD"));
}

test "normalizeArch" {
    const testing = std.testing;
    try testing.expectEqualStrings("aarch64", normalizeArch("arm64"));
    try testing.expectEqualStrings("aarch64", normalizeArch("aarch64"));
    try testing.expectEqualStrings("x86_64", normalizeArch("x86_64"));
}

test "daemonDownloadUrl" {
    const testing = std.testing;
    const url = try daemonDownloadUrl(testing.allocator, 1, "linux", "x86_64");
    defer testing.allocator.free(url);
    try testing.expectEqualStrings(
        "https://github.com/DAmesberger/ghostty/releases/download/ghostty-daemon-v1/ghostty-daemon-linux-x86_64",
        url,
    );
}

test "remoteDaemonInstallPath" {
    const testing = std.testing;
    const path = try remoteDaemonInstallPath(testing.allocator, "/home/user", "Linux");
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("/home/user/.local/state/ghostty/bin/ghostty-daemon", path);
}

test "parseSshTarget simple" {
    const result = parseSshTarget("user@host");
    try std.testing.expectEqualStrings("user@host", result.target);
    try std.testing.expect(result.jump == null);
}

test "parseSshTarget with via" {
    const result = parseSshTarget("user@host via bastion@gw");
    try std.testing.expectEqualStrings("user@host", result.target);
    try std.testing.expectEqualStrings("bastion@gw", result.jump.?);
}

test "parseSshTarget with multi-hop via" {
    const result = parseSshTarget("user@host via hop1,hop2");
    try std.testing.expectEqualStrings("user@host", result.target);
    try std.testing.expectEqualStrings("hop1,hop2", result.jump.?);
}

test "parseSshTarget with extra whitespace" {
    const result = parseSshTarget("  user@host  via  bastion  ");
    try std.testing.expectEqualStrings("user@host", result.target);
    try std.testing.expectEqualStrings("bastion", result.jump.?);
}

test "parseSshTarget empty via" {
    const result = parseSshTarget("user@host via ");
    try std.testing.expectEqualStrings("user@host", result.target);
    try std.testing.expect(result.jump == null);
}

test "formatSshTarget without jump" {
    const s = try formatSshTarget(std.testing.allocator, "user@host", null);
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("user@host", s);
}

test "formatSshTarget with jump" {
    const s = try formatSshTarget(std.testing.allocator, "user@host", "bastion");
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("user@host via bastion", s);
}

test "validateSshTarget valid" {
    try std.testing.expect(validateSshTarget("user@host") == null);
    try std.testing.expect(validateSshTarget("user@host:22") == null);
    try std.testing.expect(validateSshTarget("user@host via jump@bastion") == null);
    try std.testing.expect(validateSshTarget("user@host via hop1@a,hop2@b") == null);
    try std.testing.expect(validateSshTarget("root@192.168.1.1:2222") == null);
}

test "validateSshTarget invalid" {
    try std.testing.expect(validateSshTarget("") != null);
    try std.testing.expect(validateSshTarget("hostonly") != null);
    try std.testing.expect(validateSshTarget("@host") != null);
    try std.testing.expect(validateSshTarget("user@") != null);
    try std.testing.expect(validateSshTarget("user@host:abc") != null);
    try std.testing.expect(validateSshTarget("user@host via notvalid") != null);
}

test "validateSshTarget trailing via is treated as no jump" {
    // "user@host via " trims to empty jump → equivalent to "user@host"
    try std.testing.expect(validateSshTarget("user@host via ") == null);
}
