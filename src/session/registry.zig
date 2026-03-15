const std = @import("std");
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

pub const Status = enum {
    attached,
    detached,
    disconnected,
    dead,
};

pub const Entry = struct {
    ssh_target: []const u8,
    session_id: []const u8,
    label: []const u8,
    status: Status,
    created_at: i64,
    last_seen_at: i64,

    pub fn parse(line: []const u8) ?Entry {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) return null;

        var it = std.mem.splitScalar(u8, trimmed, '|');
        const ssh_target = it.next() orelse return null;
        const session_id = it.next() orelse return null;
        const label = it.next() orelse return null;
        const status_raw = it.next() orelse return null;
        const created_raw = it.next() orelse return null;
        const last_seen_raw = it.next() orelse return null;

        return .{
            .ssh_target = ssh_target,
            .session_id = session_id,
            .label = label,
            .status = std.meta.stringToEnum(Status, status_raw) orelse return null,
            .created_at = std.fmt.parseInt(i64, created_raw, 10) catch return null,
            .last_seen_at = std.fmt.parseInt(i64, last_seen_raw, 10) catch return null,
        };
    }

    pub fn clone(self: Entry, alloc: Allocator) !Entry {
        return .{
            .ssh_target = try alloc.dupe(u8, self.ssh_target),
            .session_id = try alloc.dupe(u8, self.session_id),
            .label = try alloc.dupe(u8, self.label),
            .status = self.status,
            .created_at = self.created_at,
            .last_seen_at = self.last_seen_at,
        };
    }

    pub fn format(self: Entry, writer: anytype) !void {
        try writer.print(
            "{s}|{s}|{s}|{t}|{d}|{d}\n",
            .{
                self.ssh_target,
                self.session_id,
                self.label,
                self.status,
                self.created_at,
                self.last_seen_at,
            },
        );
    }
};

pub const Map = std.StringHashMap(Entry);

pub fn defaultPath(alloc: Allocator) ![]const u8 {
    return try shared.registryPath(alloc);
}

pub fn load(alloc: Allocator, path: []const u8) !Map {
    var map: Map = .init(alloc);
    errdefer deinit(alloc, &map);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return map,
        else => return err,
    };
    defer file.close();

    const data = try file.readToEndAlloc(alloc, 1024 * 1024);
    defer alloc.free(data);

    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        const parsed = Entry.parse(line) orelse continue;
        const entry = try parsed.clone(alloc);
        const gop = try map.getOrPut(entry.session_id);
        if (gop.found_existing) {
            alloc.free(entry.ssh_target);
            alloc.free(entry.session_id);
            alloc.free(entry.label);
            continue;
        }
        gop.key_ptr.* = entry.session_id;
        gop.value_ptr.* = entry;
    }

    return map;
}

pub fn save(path: []const u8, map: *const Map) !void {
    if (std.fs.path.dirname(path)) |dir| try std.fs.cwd().makePath(dir);
    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();

    var buf: [1024]u8 = undefined;
    var writer_ = file.writer(&buf);
    const writer = &writer_.interface;

    var it = map.iterator();
    while (it.next()) |kv| try kv.value_ptr.format(writer);
    try writer.flush();
}

pub fn upsert(path: []const u8, alloc: Allocator, entry: Entry) !void {
    var map = try load(alloc, path);
    defer deinit(alloc, &map);

    if (map.fetchRemove(entry.session_id)) |removed| {
        alloc.free(removed.value.ssh_target);
        alloc.free(removed.value.session_id);
        alloc.free(removed.value.label);
    }

    const cloned = try entry.clone(alloc);
    try map.put(cloned.session_id, cloned);
    try save(path, &map);
}

pub fn deinit(alloc: Allocator, map: *Map) void {
    var it = map.iterator();
    while (it.next()) |kv| {
        alloc.free(kv.value_ptr.ssh_target);
        alloc.free(kv.value_ptr.session_id);
        alloc.free(kv.value_ptr.label);
    }
    map.deinit();
}

test "entry roundtrip" {
    const testing = std.testing;

    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);
    var writer = list.writer(testing.allocator);

    const entry: Entry = .{
        .ssh_target = "dev@example.com",
        .session_id = "abc",
        .label = "demo",
        .status = .attached,
        .created_at = 1,
        .last_seen_at = 2,
    };

    try entry.format(&writer);
    const parsed = Entry.parse(list.items) orelse return error.TestExpectedEqual;
    try testing.expectEqualStrings(entry.ssh_target, parsed.ssh_target);
    try testing.expectEqual(entry.status, parsed.status);
}
