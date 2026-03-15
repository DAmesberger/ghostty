const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn selfExePathAlloc(alloc: Allocator) ![]const u8 {
    return try std.fs.selfExePathAlloc(alloc);
}

pub fn spawnGhosttyWithCommand(
    alloc: Allocator,
    command_args: []const []const u8,
) !void {
    const exe = try selfExePathAlloc(alloc);
    defer alloc.free(exe);

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);
    try argv.appendSlice(alloc, &.{ exe, "-e", exe });
    for (command_args) |arg| try argv.append(alloc, arg);

    var child = std.process.Child.init(argv.items, alloc);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
}
