const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const internal_os = @import("../os/main.zig");

pub const helper_subdir = "ghostty/remote-session";
pub const remote_binary_name = "ghostty";
/// The CLI subcommand used to invoke the remote helper modes.
pub const remote_subcommand = "+ssh-session";

pub const ControlCommand = enum {
    detach,
    reconnect,
};

pub fn controlSequence(comptime cmd: ControlCommand) []const u8 {
    return switch (cmd) {
        .detach => "\x1bP9999;ghostty-session-control;detach\x1b\\",
        .reconnect => "\x1bP9999;ghostty-session-control;reconnect\x1b\\",
    };
}

pub fn stateDir(alloc: Allocator) ![]const u8 {
    return try internal_os.xdg.state(alloc, .{ .subdir = helper_subdir });
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

test "sanitize label" {
    const testing = std.testing;

    const value = try sanitizeLabelAlloc(testing.allocator, "hello world");
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("hello-world", value);
}
