const std = @import("std");
const Allocator = std.mem.Allocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const common = @import("session_common.zig");

pub const Options = struct {
    /// SSH destination to connect to. This uses the same target syntax as
    /// the system `ssh` command.
    ssh: []const u8,

    /// Optional human-readable label to associate with the created remote
    /// session.
    label: ?[]const u8 = null,

    pub fn deinit(self: *Options) void {
        _ = self;
    }

    /// Enables `-h` and `--help` to work.
    pub fn help(self: Options) !void {
        _ = self;
        return Action.help_error;
    }
};

/// The `session-connect` command opens a new Ghostty window attached to a
/// freshly created Ghostty-managed remote session on an SSH target.
///
/// This is the direct-connect entrypoint for remote sessions. Ghostty will
/// ensure the remote helper is available, start the remote daemon if needed,
/// create a new session, and attach the new window to it.
///
/// To reconnect to a detached session later, use `ghostty +session-list` to
/// discover the session id and `ghostty +session-attach` to open it again.
///
/// Flags:
///
///   * `--ssh`: SSH destination to connect to.
///
///   * `--label`: optional human-readable label stored with the session.
pub fn run(alloc: Allocator) !u8 {
    var opts: Options = undefined;
    {
        var iter = try args.argsIterator(alloc);
        defer iter.deinit();
        try args.parse(Options, alloc, &opts, &iter);
    }
    defer opts.deinit();

    var proxy_args = std.ArrayList([]const u8).empty;
    defer proxy_args.deinit(alloc);
    try proxy_args.appendSlice(alloc, &.{ "+session-proxy", "--ssh", opts.ssh });
    if (opts.label) |label| {
        try proxy_args.appendSlice(alloc, &.{ "--label", label });
    }

    try common.spawnGhosttyWithCommand(alloc, proxy_args.items);
    return 0;
}
