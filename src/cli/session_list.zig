const std = @import("std");
const Allocator = std.mem.Allocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    /// SSH destination whose Ghostty-managed remote sessions should be listed.
    ssh: []const u8,

    pub fn deinit(self: *Options) void {
        _ = self;
    }

    /// Enables `-h` and `--help` to work.
    pub fn help(self: Options) !void {
        _ = self;
        return Action.help_error;
    }
};

/// The `session-list` command lists the Ghostty-managed remote sessions
/// currently available on an SSH target.
///
/// This queries the remote Ghostty helper and prints the known session ids,
/// labels, and state. The resulting session ids can be passed to
/// `ghostty +session-attach` or `ghostty +session-kill`.
///
/// Flags:
///
///   * `--ssh`: SSH destination whose sessions should be listed.
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
        &.{ helper_path, "+session-helper", "--list" },
    );
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    try std.fs.File.stdout().writeAll(result.stdout);
    return switch (result.term) {
        .Exited => |code| if (code == 0) 0 else 1,
        else => 1,
    };
}
