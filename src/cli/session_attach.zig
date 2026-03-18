const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// SSH destination that owns the remote session.
    ssh: []const u8 = "",

    /// Remote session identifier to attach to. Use `ghostty +session-list`
    /// to discover available values.
    session: []const u8 = "",

    /// Optional SSH jump host (ProxyJump). Routes the connection through
    /// an intermediate SSH host.
    jump: ?[]const u8 = null,

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

/// The `session-attach` command attaches to an existing remote session.
///
/// This runs directly in the current terminal (no new window).
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

    // Validate required args
    if (opts.ssh.len == 0) {
        try stderr.writeAll("Error: --ssh is required\n");
        try stderr.flush();
        return 1;
    }
    if (opts.session.len == 0) {
        try stderr.writeAll("Error: --session is required\n");
        try stderr.flush();
        return 1;
    }

    try stderr.print("Attaching to session {s} on {s}...\n", .{ opts.session, opts.ssh });
    try stderr.flush();

    const rc = try session.proxy.run(alloc, .{
        .ssh = opts.ssh,
        .jump = opts.jump,
        .session = opts.session,
        .label = null,
    }, stderr);

    try stderr.flush();
    return rc;
}
