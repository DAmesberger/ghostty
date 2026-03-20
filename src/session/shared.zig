const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const internal_os = @import("../os/main.zig");

pub const helper_subdir = "ghostty/remote-session";
pub const helper_binary_name = "ghostty-session-helper";

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

/// Fixed remote install paths under /tmp. This avoids depending on any
/// particular remote user's home directory or XDG configuration.
pub const remote_dir = "/tmp/ghostty-remote-session/bin";
pub const remote_path = remote_dir ++ "/" ++ helper_binary_name;

pub fn remoteInstallDir(alloc: Allocator) ![]const u8 {
    return try alloc.dupe(u8, remote_dir);
}

pub fn remoteInstallPath(alloc: Allocator) ![]const u8 {
    return try alloc.dupe(u8, remote_path);
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

test "sanitize label" {
    const testing = std.testing;

    const value = try sanitizeLabelAlloc(testing.allocator, "hello world");
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("hello-world", value);
}
