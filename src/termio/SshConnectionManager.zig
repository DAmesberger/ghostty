//! Shared SSH connection pool keyed by (ssh_target, jump).
//! Multiple surfaces (tabs/splits) to the same host share one TCP connection
//! and SSH session, each getting their own SSH channel.
const SshConnectionManager = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("../session.zig");
const ssh = session.ssh;

mutex: std.Thread.Mutex = .{},
connections: std.StringArrayHashMap(Entry),
alloc: Allocator,

pub const Entry = struct {
    ctx: session.client.SshContext,
    helper_path: []const u8,
    ref_count: u32,
};

pub fn init(alloc: Allocator) SshConnectionManager {
    return .{
        .connections = std.StringArrayHashMap(Entry).init(alloc),
        .alloc = alloc,
    };
}

pub fn deinit(self: *SshConnectionManager) void {
    var it = self.connections.iterator();
    while (it.next()) |entry| {
        self.alloc.free(entry.key_ptr.*);
        self.alloc.free(entry.value_ptr.helper_path);
        entry.value_ptr.ctx.deinit();
    }
    self.connections.deinit();
}

/// Build the lookup key from ssh_target + optional jump.
fn makeKey(alloc: Allocator, ssh_target: []const u8, jump: ?[]const u8) ![]u8 {
    if (jump) |j| {
        return std.fmt.allocPrint(alloc, "{s}|{s}", .{ ssh_target, j });
    }
    return alloc.dupe(u8, ssh_target);
}

/// Acquire a connection entry. If one already exists for this target+jump,
/// increments the ref count and returns it. Otherwise creates a new entry
/// with ref_count=1. The SSH connection itself is lazily established.
pub fn acquire(
    self: *SshConnectionManager,
    ssh_target: []const u8,
    jump: ?[]const u8,
) !*Entry {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = try makeKey(self.alloc, ssh_target, jump);

    if (self.connections.getPtr(key)) |entry| {
        self.alloc.free(key);
        entry.ref_count += 1;
        return entry;
    }

    const entry: Entry = .{
        .ctx = .{
            .alloc = self.alloc,
            .ssh_target = ssh_target,
            .jump = jump,
        },
        .helper_path = &.{},
        .ref_count = 1,
    };
    try self.connections.put(key, entry);
    return self.connections.getPtr(key).?;
}

/// Release a reference. When ref_count reaches 0, clean up the connection.
pub fn release(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    if (self.connections.getPtr(key)) |entry| {
        if (entry.ref_count > 1) {
            entry.ref_count -= 1;
            return;
        }
        // Last reference — clean up
        if (entry.helper_path.len > 0) self.alloc.free(entry.helper_path);
        entry.ctx.deinit();
        // Remove the entry and free the stored key
        const removed = self.connections.fetchOrderedRemove(key);
        if (removed) |r| self.alloc.free(r.key);
    }
}
