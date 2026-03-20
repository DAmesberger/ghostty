//! Minimal parser for OpenSSH config format.
//! Extracts Host/HostName/User/Port from ~/.ssh/config for the SSH
//! connection picker. Skips wildcard hosts and Match blocks.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const SshHost = struct {
    alias: []const u8, // "myserver" from Host myserver
    hostname: []const u8, // "192.168.1.100" from HostName, defaults to alias
    user: ?[]const u8, // "admin" from User, null if not specified
    port: u16, // from Port, defaults to 22
};

/// Parse ~/.ssh/config and return a list of SSH hosts.
/// Caller owns the returned slice and all strings within it.
pub fn parseConfig(alloc: Allocator) ![]SshHost {
    const home = std.posix.getenv("HOME") orelse return &.{};

    const path = try std.fmt.allocPrint(alloc, "{s}/.ssh/config", .{home});
    defer alloc.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return &.{};
    defer file.close();

    const content = file.readToEndAlloc(alloc, 1024 * 1024) catch return &.{};
    defer alloc.free(content);

    return parseContent(alloc, content);
}

/// Parse SSH config content from a string. Useful for testing.
pub fn parseContent(alloc: Allocator, content: []const u8) ![]SshHost {
    var hosts: std.ArrayListUnmanaged(SshHost) = .empty;
    errdefer {
        for (hosts.items) |h| freeHost(alloc, h);
        hosts.deinit(alloc);
    }

    // Pending host block state.
    var pending_aliases: std.ArrayListUnmanaged([]const u8) = .empty;
    defer pending_aliases.deinit(alloc);

    var pending_hostname: ?[]const u8 = null;
    var pending_user: ?[]const u8 = null;
    var pending_port: u16 = 22;
    var in_match: bool = false;

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        // Strip trailing \r for Windows-style line endings.
        const line_trimmed = std.mem.trimRight(u8, raw_line, "\r");
        const line = std.mem.trim(u8, line_trimmed, " \t");

        // Skip empty lines and comments.
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        const kv = splitKeyValue(line) orelse continue;
        const key = kv.key;
        const value = kv.value;

        if (std.ascii.eqlIgnoreCase(key, "Host")) {
            // Flush the previous host block.
            try flushPending(alloc, &hosts, &pending_aliases, pending_hostname, pending_user, pending_port);
            pending_hostname = null;
            pending_user = null;
            pending_port = 22;
            in_match = false;

            // Parse aliases -- may be space-separated.
            var alias_iter = std.mem.tokenizeAny(u8, value, " \t");
            while (alias_iter.next()) |alias| {
                // Skip wildcard aliases.
                if (std.mem.indexOfAny(u8, alias, "*?") != null) continue;
                const alias_copy = try alloc.dupe(u8, alias);
                errdefer alloc.free(alias_copy);
                try pending_aliases.append(alloc, alias_copy);
            }
        } else if (std.ascii.eqlIgnoreCase(key, "Match")) {
            // Flush and enter match-skip mode.
            try flushPending(alloc, &hosts, &pending_aliases, pending_hostname, pending_user, pending_port);
            pending_hostname = null;
            pending_user = null;
            pending_port = 22;
            in_match = true;
        } else if (!in_match and pending_aliases.items.len > 0) {
            // Inside a Host block -- collect relevant keys.
            if (std.ascii.eqlIgnoreCase(key, "HostName")) {
                if (pending_hostname) |old| alloc.free(old);
                pending_hostname = try alloc.dupe(u8, value);
            } else if (std.ascii.eqlIgnoreCase(key, "User")) {
                if (pending_user) |old| alloc.free(old);
                pending_user = try alloc.dupe(u8, value);
            } else if (std.ascii.eqlIgnoreCase(key, "Port")) {
                pending_port = std.fmt.parseInt(u16, value, 10) catch 22;
            }
        }
    }

    // Flush last block.
    try flushPending(alloc, &hosts, &pending_aliases, pending_hostname, pending_user, pending_port);

    return hosts.toOwnedSlice(alloc);
}

/// Split a config line into key and value.
/// Handles both `Key value` and `Key=value` syntax.
fn splitKeyValue(line: []const u8) ?struct { key: []const u8, value: []const u8 } {
    // Find the boundary between key and value: first whitespace or '='.
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (line[i] == '=' or line[i] == ' ' or line[i] == '\t') break;
    }
    if (i == 0 or i == line.len) return null;

    const key = line[0..i];

    // Skip the separator (whitespace and/or '=').
    var j = i;
    while (j < line.len and (line[j] == ' ' or line[j] == '\t' or line[j] == '=')) : (j += 1) {}
    if (j == line.len) return null;

    const value = std.mem.trimRight(u8, line[j..], " \t");
    if (value.len == 0) return null;

    return .{ .key = key, .value = value };
}

/// Flush the currently accumulated host block into the hosts list.
fn flushPending(
    alloc: Allocator,
    hosts: *std.ArrayListUnmanaged(SshHost),
    pending_aliases: *std.ArrayListUnmanaged([]const u8),
    pending_hostname: ?[]const u8,
    pending_user: ?[]const u8,
    pending_port: u16,
) !void {
    defer {
        // We have taken ownership of the alias strings (or freed them on error),
        // so just clear the list.
        pending_aliases.clearRetainingCapacity();
    }

    if (pending_aliases.items.len == 0) {
        // Nothing to flush, but free any dangling hostname/user.
        if (pending_hostname) |h| alloc.free(h);
        if (pending_user) |u| alloc.free(u);
        return;
    }

    // For each alias, create a separate SshHost.
    for (pending_aliases.items, 0..) |alias, idx| {
        const is_last = idx == pending_aliases.items.len - 1;

        const hostname_copy = if (pending_hostname) |hn|
            if (is_last) hn else try alloc.dupe(u8, hn)
        else
            try alloc.dupe(u8, alias);

        errdefer alloc.free(hostname_copy);

        const user_copy: ?[]const u8 = if (pending_user) |u|
            if (is_last) u else try alloc.dupe(u8, u)
        else
            null;

        errdefer if (user_copy) |uc| alloc.free(uc);

        try hosts.append(alloc, .{
            .alias = alias,
            .hostname = hostname_copy,
            .user = user_copy,
            .port = pending_port,
        });
    }
}

fn freeHost(alloc: Allocator, host: SshHost) void {
    // hostname might point to same allocation as alias when hostname == alias,
    // but we always dupe, so they are separate allocations.
    alloc.free(host.alias);
    alloc.free(host.hostname);
    if (host.user) |u| alloc.free(u);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "basic host with all fields" {
    const input =
        \\Host myserver
        \\    HostName 192.168.1.100
        \\    User admin
        \\    Port 2222
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 1), hosts.len);
    try std.testing.expectEqualStrings("myserver", hosts[0].alias);
    try std.testing.expectEqualStrings("192.168.1.100", hosts[0].hostname);
    try std.testing.expectEqualStrings("admin", hosts[0].user.?);
    try std.testing.expectEqual(@as(u16, 2222), hosts[0].port);
}

test "host with defaults" {
    const input =
        \\Host simple
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 1), hosts.len);
    try std.testing.expectEqualStrings("simple", hosts[0].alias);
    // hostname defaults to alias
    try std.testing.expectEqualStrings("simple", hosts[0].hostname);
    try std.testing.expect(hosts[0].user == null);
    try std.testing.expectEqual(@as(u16, 22), hosts[0].port);
}

test "multiple aliases on one Host line" {
    const input =
        \\Host dev staging
        \\    HostName dev.example.com
        \\    User deploy
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 2), hosts.len);

    try std.testing.expectEqualStrings("dev", hosts[0].alias);
    try std.testing.expectEqualStrings("dev.example.com", hosts[0].hostname);
    try std.testing.expectEqualStrings("deploy", hosts[0].user.?);

    try std.testing.expectEqualStrings("staging", hosts[1].alias);
    try std.testing.expectEqualStrings("dev.example.com", hosts[1].hostname);
    try std.testing.expectEqualStrings("deploy", hosts[1].user.?);
}

test "skip wildcard hosts" {
    const input =
        \\Host *
        \\    ServerAliveInterval 60
        \\
        \\Host myserver
        \\    HostName 10.0.0.1
        \\
        \\Host test-?
        \\    HostName test.local
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 1), hosts.len);
    try std.testing.expectEqualStrings("myserver", hosts[0].alias);
}

test "skip Match blocks" {
    const input =
        \\Host before
        \\    HostName before.example.com
        \\
        \\Match host *.internal
        \\    ProxyJump bastion
        \\
        \\Host after
        \\    HostName after.example.com
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 2), hosts.len);
    try std.testing.expectEqualStrings("before", hosts[0].alias);
    try std.testing.expectEqualStrings("after", hosts[1].alias);
}

test "comments and empty lines" {
    const input =
        \\# This is a comment
        \\
        \\Host myhost
        \\    # Another comment
        \\    HostName example.com
        \\
        \\    User testuser
        \\
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 1), hosts.len);
    try std.testing.expectEqualStrings("myhost", hosts[0].alias);
    try std.testing.expectEqualStrings("example.com", hosts[0].hostname);
    try std.testing.expectEqualStrings("testuser", hosts[0].user.?);
    try std.testing.expectEqual(@as(u16, 22), hosts[0].port);
}

test "Key=value syntax" {
    const input =
        \\Host equalshost
        \\    HostName=equals.example.com
        \\    User=equser
        \\    Port=3022
    ;
    const hosts = try parseContent(std.testing.allocator, input);
    defer {
        for (hosts) |h| freeHost(std.testing.allocator, h);
        std.testing.allocator.free(hosts);
    }

    try std.testing.expectEqual(@as(usize, 1), hosts.len);
    try std.testing.expectEqualStrings("equalshost", hosts[0].alias);
    try std.testing.expectEqualStrings("equals.example.com", hosts[0].hostname);
    try std.testing.expectEqualStrings("equser", hosts[0].user.?);
    try std.testing.expectEqual(@as(u16, 3022), hosts[0].port);
}
