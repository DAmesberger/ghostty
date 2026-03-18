const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// SSH destination to connect to. This uses the same target syntax as
    /// the system `ssh` command.
    ssh: []const u8 = "",

    /// Optional SSH jump host (ProxyJump). Routes the connection through
    /// an intermediate SSH host.
    jump: ?[]const u8 = null,

    /// Optional human-readable label to associate with the created remote
    /// session.
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

/// The `session-connect` command establishes a remote Ghostty session.
///
/// This runs directly in the current terminal (no new window), connecting
/// to the remote host and establishing the session. Password prompts will
/// appear in this terminal.
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

    // Validate that ssh is not empty
    if (opts.ssh.len == 0) {
        try stderr.writeAll("Error: --ssh is required\n");
        try stderr.flush();
        return 1;
    }

    try stderr.print("Connecting to {s}...\n", .{opts.ssh});
    try stderr.writeAll("(You may be prompted for SSH passwords)\n\n");
    try stderr.flush();

    const rc = try session.proxy.run(alloc, .{
        .ssh = opts.ssh,
        .jump = opts.jump,
        .session = null, // Create new session
        .label = opts.label,
    }, stderr);

    try stderr.flush();
    return rc;
}
