const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const proxy = @import("../session/proxy.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// SSH destination that owns the remote session.
    ssh: []const u8 = "",

    /// Optional SSH jump host (ProxyJump). Routes the connection through
    /// an intermediate SSH host.
    jump: ?[]const u8 = null,

    /// Existing remote session identifier to attach to. If omitted, a fresh
    /// session is created.
    session: ?[]const u8 = null,

    /// Optional label to use when creating a fresh remote session.
    label: ?[]const u8 = null,

    pub fn deinit(self: *Options) void {
        if (self._arena) |a| a.deinit();
        self.* = undefined;
    }

    /// Enables `-h` and `--help` to work.
    pub fn help(self: Options) !void {
        _ = self;
        return Action.help_error;
    }
};

/// Internal action used by `+session-connect` and `+session-attach` to run the
/// local proxy process for an attached remote session.
///
/// This is not intended for direct interactive use and may change without
/// notice.
pub fn run(alloc: Allocator) !u8 {
    var opts: Options = .{};
    {
        var iter = try args.argsIterator(alloc);
        defer iter.deinit();
        args.parse(Options, alloc, &opts, &iter) catch |err| switch (err) {
            error.ActionHelpRequested => return err,
            else => {
                std.debug.print("error parsing args: {}\n", .{err});
                return 1;
            },
        };
    }
    defer opts.deinit();

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    const rc = try proxy.run(alloc, .{
        .ssh = opts.ssh,
        .jump = opts.jump,
        .session = opts.session,
        .label = opts.label,
    }, stderr);
    try stderr.flush();
    return rc;
}
