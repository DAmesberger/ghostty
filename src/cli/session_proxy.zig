const std = @import("std");
const Allocator = std.mem.Allocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const proxy = @import("../session/proxy.zig");

pub const Options = struct {
    /// SSH destination that owns the remote session.
    ssh: []const u8,

    /// Existing remote session identifier to attach to. If omitted, a fresh
    /// session is created.
    session: ?[]const u8 = null,

    /// Optional label to use when creating a fresh remote session.
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

/// Internal action used by `+session-connect` and `+session-attach` to run the
/// local proxy process for an attached remote session.
///
/// This is not intended for direct interactive use and may change without
/// notice.
pub fn run(alloc: Allocator) !u8 {
    var opts: Options = undefined;
    {
        var iter = try args.argsIterator(alloc);
        defer iter.deinit();
        try args.parse(Options, alloc, &opts, &iter);
    }
    defer opts.deinit();

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    const rc = try proxy.run(alloc, .{
        .ssh = opts.ssh,
        .session = opts.session,
        .label = opts.label,
    }, stderr);
    try stderr.flush();
    return rc;
}
