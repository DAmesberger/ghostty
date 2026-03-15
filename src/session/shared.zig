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

pub fn remoteInstallDir(alloc: Allocator) ![]const u8 {
    const dir = try stateDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, "bin" });
}

pub fn remoteInstallPath(alloc: Allocator) ![]const u8 {
    const dir = try remoteInstallDir(alloc);
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, helper_binary_name });
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
