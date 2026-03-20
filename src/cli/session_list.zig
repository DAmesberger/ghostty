const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const session = @import("../session.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// SSH destination whose Ghostty-managed remote sessions should be listed.
    ssh: []const u8 = "",

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
        "{s} " ++ session.shared.remote_subcommand ++ " --list",
        .{helper_path},
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

    // Parse and format the session list with human-readable ages.
    // Raw format from daemon: id|label|status|created_at|attached
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer_ = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer_.interface;

    const now = std.time.timestamp();
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '|');
        const id = fields.next() orelse continue;
        const label = fields.next() orelse "";
        const status = fields.next() orelse "";
        const created_str = fields.next() orelse "";
        const attached = fields.next() orelse "";

        const created_at = std.fmt.parseInt(i64, created_str, 10) catch 0;
        const age_secs: u64 = if (created_at > 0) @intCast(@max(0, now - created_at)) else 0;

        try stdout.print("{s}  {s}  {s}  age: {s}  {s}\n", .{
            id,
            label,
            status,
            formatAge(age_secs),
            attached,
        });
    }
    try stdout.flush();
    return 0;
}

fn formatAge(secs: u64) []const u8 {
    const State = struct {
        var buf: [32]u8 = undefined;
    };
    if (secs < 60) {
        const result = std.fmt.bufPrint(&State.buf, "{d}s", .{secs}) catch "?";
        return result;
    } else if (secs < 3600) {
        const result = std.fmt.bufPrint(&State.buf, "{d}m", .{secs / 60}) catch "?";
        return result;
    } else if (secs < 86400) {
        const result = std.fmt.bufPrint(&State.buf, "{d}h{d}m", .{ secs / 3600, (secs % 3600) / 60 }) catch "?";
        return result;
    } else {
        const result = std.fmt.bufPrint(&State.buf, "{d}d{d}h", .{ secs / 86400, (secs % 86400) / 3600 }) catch "?";
        return result;
    }
}
