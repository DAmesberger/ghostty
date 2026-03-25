const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const internal_os = @import("../os/main.zig");

pub const state_subdir = "ghostty/remote-session";
pub const remote_binary_name = "ghostty";
pub const remote_headless_binary_name = "ghostty-headless";
/// The CLI subcommand used to invoke the remote session modes.
pub const remote_subcommand = "+ssh-session";

/// Base URL for downloading pre-built headless binaries from CI releases.
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
    if (payload.len > protocol.max_payload) return error.PayloadTooLarge;
    const header = (protocol.Header{
        .kind = kind,
        .target = target,
        .len = @intCast(payload.len),
    }).encodeToBuf();
    var file: std.fs.File = .{ .handle = fd };
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

pub fn remoteHeadlessInstallPath(alloc: Allocator, remote_home: []const u8, remote_os: []const u8) ![]const u8 {
    const dir = try remoteInstallDir(alloc, remote_home, remote_os);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, remote_headless_binary_name });
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

/// Parsed SSH target with optional jump host chain.
/// Returned slices point into the original input string.
pub const ParsedSshTarget = struct {
    target: []const u8,
    jump: ?[]const u8,
};

/// Parse an SSH target string that optionally contains a " via " jump host
/// specifier.  Examples:
///   "user@host"                → .{ .target = "user@host", .jump = null }
///   "user@host via bastion"    → .{ .target = "user@host", .jump = "bastion" }
///   "user@host via h1,h2"     → .{ .target = "user@host", .jump = "h1,h2" }
pub fn parseSshTarget(raw: []const u8) ParsedSshTarget {
    // Search before trimming so trailing " via " edge cases work.
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

/// Construct the full download URL for a headless binary release asset.
/// Caller owns the returned string.
pub fn headlessDownloadUrl(
    alloc: Allocator,
    proto_version: u16,
    os: []const u8,
    arch: []const u8,
) ![]const u8 {
    return try std.fmt.allocPrint(
        alloc,
        "{s}/ghostty-headless-v{d}/ghostty-headless-{s}-{s}",
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

test "headlessDownloadUrl" {
    const testing = std.testing;
    const url = try headlessDownloadUrl(testing.allocator, 1, "linux", "x86_64");
    defer testing.allocator.free(url);
    try testing.expectEqualStrings(
        "https://github.com/DAmesberger/ghostty/releases/download/ghostty-headless-v1/ghostty-headless-linux-x86_64",
        url,
    );
}

test "remoteHeadlessInstallPath" {
    const testing = std.testing;
    const path = try remoteHeadlessInstallPath(testing.allocator, "/home/user", "Linux");
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("/home/user/.local/state/ghostty/bin/ghostty-headless", path);
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
