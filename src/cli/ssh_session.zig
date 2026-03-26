const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const args = @import("args.zig");
const Action = @import("ghostty.zig").Action;
const helper = @import("../session/helper.zig");
const session = @import("../session.zig");

pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    /// Print the session protocol version and exit.
    @"protocol-version": bool = false,

    /// Start the remote helper as a background daemon and return immediately.
    daemonize: bool = false,

    /// Run the remote helper in daemon mode.
    daemon: bool = false,

    /// Kill any running daemon and exit.
    @"kill-daemon": bool = false,

    /// List the sessions known to the remote helper.
    list: bool = false,

    /// Attach the helper to stdio for an interactive session transport.
    @"stdio-attach": bool = false,

    /// Kill the specified remote session id.
    kill: ?[]const u8 = null,

    /// Rename the specified remote session id. Requires --label.
    rename: ?[]const u8 = null,

    /// Detach all other viewers from the specified remote session id.
    @"detach-others": ?[]const u8 = null,

    /// Remote session identifier to operate on.
    session: ?[]const u8 = null,

    /// Create a new remote session.
    new: bool = false,

    /// Optional label to associate with a newly created session or rename.
    label: ?[]const u8 = null,

    /// SSH target for remote execution. When set, the command connects
    /// to the remote host first and runs itself there. Supports "via"
    /// syntax for jump hosts: "user@host via bastion".
    ssh: []const u8 = "",

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

/// Manage Ghostty remote sessions over SSH.
///
/// When invoked with `--ssh`, the command connects to the remote host,
/// provisions the remote helper binary, and runs the requested operation
/// there. Without `--ssh`, the command runs locally and communicates
/// with the daemon directly (used on the remote host).
///
/// Examples:
///
///   ghostty +ssh-session --list --ssh user@host
///   ghostty +ssh-session --kill=<id> --ssh "user@host via bastion"
///   ghostty +ssh-session --rename=<id> --label=new-name --ssh user@host
///
/// Remote-only subcommands (used by the Ghostty client internally):
///
///   ghostty +ssh-session --daemon
///   ghostty +ssh-session --protocol-version
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

    // If --ssh is provided, dispatch to the remote host.
    if (opts.ssh.len > 0) {
        return runRemote(alloc, opts);
    }

    // Otherwise run locally (remote-side daemon operations).
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer_ = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer_.interface;
    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    const rc = try helper.run(alloc, .{
        .@"protocol-version" = opts.@"protocol-version",
        .daemonize = opts.daemonize,
        .daemon = opts.daemon,
        .@"kill-daemon" = opts.@"kill-daemon",
        .list = opts.list,
        .@"stdio-attach" = opts.@"stdio-attach",
        .kill = opts.kill,
        .rename = opts.rename,
        .@"detach-others" = opts.@"detach-others",
        .session = opts.session,
        .new = opts.new,
        .label = opts.label,
    }, stdout, stderr);
    try stdout.flush();
    try stderr.flush();
    return rc;
}

/// Connect to the remote host via SSH, provision the binary/daemon,
/// and execute the requested subcommand there.
fn runRemote(alloc: Allocator, opts: Options) !u8 {
    // Validate before attempting connection.
    if (session.shared.validateSshTarget(opts.ssh)) |err_msg| {
        std.debug.print("Error: invalid --ssh target: {s}\n", .{err_msg});
        return 1;
    }
    const parsed = session.shared.parseSshTarget(opts.ssh);

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = parsed.target,
        .jump = parsed.jump,
    };
    defer ctx.deinit();

    const provision = try session.client.ensureRemoteGhostty(alloc, &ctx, stderr, null);
    const remote_bin_path = provision.path;
    defer alloc.free(remote_bin_path);
    try session.client.ensureRemoteDaemon(alloc, &ctx, remote_bin_path, provision.provisioned);

    // Build the remote command string.
    const cmd = try buildRemoteCommand(alloc, remote_bin_path, opts);
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

    // For --list, format the output with human-readable ages.
    if (opts.list) {
        try formatListOutput(result.stdout);
    } else {
        try std.fs.File.stdout().writeAll(result.stdout);
    }
    return 0;
}

/// Build the remote +ssh-session command string from the local options.
fn buildRemoteCommand(alloc: Allocator, remote_bin: []const u8, opts: Options) ![]const u8 {
    const subcommand = session.shared.remote_subcommand;

    if (opts.@"kill-daemon") {
        return std.fmt.allocPrint(alloc, "{s} {s} --kill-daemon", .{ remote_bin, subcommand });
    }
    if (opts.list) {
        return std.fmt.allocPrint(alloc, "{s} {s} --list", .{ remote_bin, subcommand });
    }
    if (opts.kill) |id| {
        return std.fmt.allocPrint(alloc, "{s} {s} --kill={s}", .{ remote_bin, subcommand, id });
    }
    if (opts.rename) |id| {
        const label = opts.label orelse return error.MissingLabel;
        return std.fmt.allocPrint(alloc, "{s} {s} --rename={s} --label={s}", .{ remote_bin, subcommand, id, label });
    }
    if (opts.@"detach-others") |id| {
        return std.fmt.allocPrint(alloc, "{s} {s} --detach-others={s}", .{ remote_bin, subcommand, id });
    }
    return error.MissingSubcommand;
}

/// Format the raw daemon list output with human-readable ages.
fn formatListOutput(raw: []const u8) !void {
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer_ = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer_.interface;

    const now = std.time.timestamp();
    var lines = std.mem.splitScalar(u8, raw, '\n');
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
}

fn formatAge(secs: u64) []const u8 {
    const State = struct {
        var buf: [32]u8 = undefined;
    };
    if (secs < 60) {
        return std.fmt.bufPrint(&State.buf, "{d}s", .{secs}) catch "?";
    } else if (secs < 3600) {
        return std.fmt.bufPrint(&State.buf, "{d}m", .{secs / 60}) catch "?";
    } else if (secs < 86400) {
        return std.fmt.bufPrint(&State.buf, "{d}h{d}m", .{ secs / 3600, (secs % 3600) / 60 }) catch "?";
    } else {
        return std.fmt.bufPrint(&State.buf, "{d}d{d}h", .{ secs / 86400, (secs % 86400) / 3600 }) catch "?";
    }
}
