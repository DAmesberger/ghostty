const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// SSH destination that owns the target remote session.
    ssh: []const u8 = "",

    /// Remote session identifier to terminate. Use `ghostty +session-list`
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

/// The `session-kill` command terminates a Ghostty-managed remote session on
/// an SSH target.
///
/// This ends the remote session and removes it from the remote helper's
/// active session set.
///
/// Use `ghostty +session-list --ssh <target>` to discover session ids before
/// invoking this command.
///
/// Flags:
///
///   * `--ssh`: SSH destination that owns the session.
///
///   * `--session`: remote session identifier to terminate.
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

    if (opts.ssh.len == 0) {
        std.debug.print("Error: --ssh is required\n", .{});
        return 1;
    }
    if (opts.session.len == 0) {
        std.debug.print("Error: --session is required\n", .{});
        return 1;
    }

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = opts.ssh,
        .jump = opts.jump,
    };
    defer ctx.deinit();

    const helper_result = try session.client.ensureRemoteHelper(alloc, &ctx, stderr, null);
    const helper_path = helper_result.path;
    defer alloc.free(helper_path);
    try session.client.ensureRemoteDaemon(alloc, &ctx, helper_path, helper_result.uploaded);

    const cmd = try std.fmt.allocPrint(
        alloc,
        "{s} " ++ session.shared.remote_subcommand ++ " --kill={s}",
        .{ helper_path, opts.session },
    );
    defer alloc.free(cmd);

    const result = try session.client.runRemoteCapture(alloc, &ctx, cmd);
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.exit_code != 0) {
        try stderr.print("Error: remote command failed with exit code: {d}\n", .{result.exit_code});
        if (result.stderr.len > 0) {
            try stderr.print("Remote stderr: {s}\n", .{result.stderr});
        }
        try stderr.flush();
        return 1;
    }

    try std.fs.File.stdout().writeAll(result.stdout);
    return 0;
}
