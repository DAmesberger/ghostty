const std = @import("std");
const Allocator = std.mem.Allocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const common = @import("session_common.zig");

pub const Options = struct {
    /// SSH destination that owns the remote session.
    ssh: []const u8,

    /// Remote session identifier to attach to. Use `ghostty +session-list`
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

/// The `session-attach` command opens a new Ghostty window attached to an
/// existing Ghostty-managed remote session on an SSH target.
///
/// This is used to reconnect to a detached session or to open an additional
/// view onto a known session id.
///
/// Use `ghostty +session-list --ssh <target>` first to see the available
/// session identifiers on a host.
///
/// Flags:
///
///   * `--ssh`: SSH destination that owns the session.
///
///   * `--session`: remote session identifier to attach to.
pub fn run(alloc: Allocator) !u8 {
    var opts: Options = undefined;
    {
        var iter = try args.argsIterator(alloc);
        defer iter.deinit();
        try args.parse(Options, alloc, &opts, &iter);
    }
    defer opts.deinit();

    try common.spawnGhosttyWithCommand(
        alloc,
        &.{ "+session-proxy", "--ssh", opts.ssh, "--session", opts.session },
    );
    return 0;
}
