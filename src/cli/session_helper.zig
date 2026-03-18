const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const helper = @import("../session/helper.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// Start the remote helper as a background daemon and return immediately.
    daemonize: bool = false,

    /// Run the remote helper in daemon mode.
    daemon: bool = false,

    /// List the sessions known to the remote helper.
    list: bool = false,

    /// Attach the helper to stdio for an interactive session transport.
    @"stdio-attach": bool = false,

    /// Kill the specified remote session id.
    kill: ?[]const u8 = null,

    /// Remote session identifier to operate on.
    session: ?[]const u8 = null,

    /// Create a new remote session.
    new: bool = false,

    /// Optional label to associate with a newly created session.
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

/// Internal action that runs the remote helper process for Ghostty-managed
/// remote sessions.
///
/// This action is invoked over SSH by the local Ghostty client. It is not a
/// stable user-facing interface and is documented here only so generated help
/// and reference output can describe its role accurately.
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

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer_ = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer_.interface;
    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    const rc = try helper.run(alloc, .{
        .daemonize = opts.daemonize,
        .daemon = opts.daemon,
        .list = opts.list,
        .@"stdio-attach" = opts.@"stdio-attach",
        .kill = opts.kill,
        .session = opts.session,
        .new = opts.new,
        .label = opts.label,
    }, stdout, stderr);
    try stdout.flush();
    try stderr.flush();
    return rc;
}
