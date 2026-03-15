const std = @import("std");
const Allocator = std.mem.Allocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    /// SSH destination that owns the target remote session.
    ssh: []const u8,

    /// Remote session identifier to terminate. Use `ghostty +session-list`
    /// to discover available values.
    session: []const u8,

    pub fn deinit(self: *Options) void {
        _ = self;
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
    var opts: Options = undefined;
    {
        var iter = try args.argsIterator(alloc);
        defer iter.deinit();
        try args.parse(Options, alloc, &opts, &iter);
    }
    defer opts.deinit();

    const helper_path = try session.client.ensureRemoteHelper(alloc, opts.ssh);
    defer alloc.free(helper_path);
    try session.client.ensureRemoteDaemon(alloc, opts.ssh, helper_path);

    const result = try session.client.runRemoteCapture(
        alloc,
        opts.ssh,
        &.{ helper_path, "+session-helper", "--kill", opts.session },
    );
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    try std.fs.File.stdout().writeAll(result.stdout);
    return switch (result.term) {
        .Exited => |code| if (code == 0) 0 else 1,
        else => 1,
    };
}
