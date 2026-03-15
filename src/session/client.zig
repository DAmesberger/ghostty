const std = @import("std");
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

pub const Error = error{
    RemoteCommandFailed,
    RemotePlatformUnsupported,
    RemoteHelperUploadFailed,
};

pub fn ensureRemoteHelper(
    alloc: Allocator,
    ssh_target: []const u8,
) ![]const u8 {
    const helper_path = try shared.remoteInstallPath(alloc);
    errdefer alloc.free(helper_path);

    if (remoteFileExecutable(alloc, ssh_target, helper_path)) return helper_path;

    const remote_platform = try detectRemotePlatform(alloc, ssh_target);
    defer {
        alloc.free(remote_platform.os);
        alloc.free(remote_platform.arch);
    }
    const local_platform = shared.localPlatform();
    if (!platformMatches(local_platform.os, remote_platform.os) or
        !std.ascii.eqlIgnoreCase(local_platform.arch, remote_platform.arch))
    {
        return error.RemotePlatformUnsupported;
    }

    const install_dir = try shared.remoteInstallDir(alloc);
    defer alloc.free(install_dir);
    try uploadCurrentExecutable(alloc, ssh_target, install_dir, helper_path);
    return helper_path;
}

pub fn ensureRemoteDaemon(
    alloc: Allocator,
    ssh_target: []const u8,
    helper_path: []const u8,
) !void {
    const result = try runRemoteCapture(
        alloc,
        ssh_target,
        &.{ helper_path, "+session-helper", "--daemonize" },
    );
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (!termExitedOk(result.term)) return error.RemoteCommandFailed;
}

pub const Capture = struct {
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,
};

pub fn runRemoteCapture(
    alloc: Allocator,
    ssh_target: []const u8,
    remote_args: []const []const u8,
) !Capture {
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);
    try argv.append(alloc, "ssh");
    try argv.append(alloc, ssh_target);
    for (remote_args) |arg| try argv.append(alloc, arg);

    const result = try std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv.items,
    });

    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .term = result.term,
    };
}

pub fn spawnRemoteAttach(
    alloc: Allocator,
    ssh_target: []const u8,
    helper_path: []const u8,
    session_id: ?[]const u8,
    label: ?[]const u8,
) !std.process.Child {
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);

    try argv.appendSlice(alloc, &.{
        "ssh",
        ssh_target,
        helper_path,
        "+session-helper",
        "--stdio-attach",
    });
    if (session_id) |id| {
        try argv.append(alloc, "--session");
        try argv.append(alloc, id);
    } else {
        try argv.append(alloc, "--new");
    }
    if (label) |value| {
        try argv.append(alloc, "--label");
        try argv.append(alloc, value);
    }

    var child = std.process.Child.init(argv.items, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    return child;
}

fn remoteFileExecutable(
    alloc: Allocator,
    ssh_target: []const u8,
    path: []const u8,
) bool {
    const shell = std.fmt.allocPrint(alloc, "test -x '{s}'", .{path}) catch return false;
    defer alloc.free(shell);

    const result = runRemoteCapture(alloc, ssh_target, &.{ "sh", "-lc", shell }) catch return false;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    return termExitedOk(result.term);
}

fn detectRemotePlatform(
    alloc: Allocator,
    ssh_target: []const u8,
) !shared.Platform {
    const result = try runRemoteCapture(alloc, ssh_target, &.{ "sh", "-lc", "uname -s && uname -m" });
    defer alloc.free(result.stderr);
    errdefer alloc.free(result.stdout);

    if (!termExitedOk(result.term)) return error.RemoteCommandFailed;

    var it = std.mem.splitScalar(u8, std.mem.trim(u8, result.stdout, " \t\r\n"), '\n');
    const os = it.next() orelse return error.RemoteCommandFailed;
    const arch = it.next() orelse return error.RemoteCommandFailed;

    const platform: shared.Platform = .{
        .os = try std.ascii.allocLowerString(alloc, os),
        .arch = try alloc.dupe(u8, std.mem.trim(u8, arch, " \t\r\n")),
    };
    alloc.free(result.stdout);
    return platform;
}

fn uploadCurrentExecutable(
    alloc: Allocator,
    ssh_target: []const u8,
    install_dir: []const u8,
    install_path: []const u8,
) !void {
    const exe_path = try std.fs.selfExePathAlloc(alloc);
    defer alloc.free(exe_path);

    const file = try std.fs.openFileAbsolute(exe_path, .{});
    defer file.close();

    const shell = try std.fmt.allocPrint(
        alloc,
        "mkdir -p '{s}' && cat > '{s}' && chmod 700 '{s}'",
        .{ install_dir, install_path, install_path },
    );
    defer alloc.free(shell);

    var child = std.process.Child.init(
        &.{ "ssh", ssh_target, "sh", "-lc", shell },
        alloc,
    );
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const child_stdin = child.stdin.?;
    var writer_buf: [1024]u8 = undefined;
    var writer_ = child_stdin.writer(&writer_buf);
    const writer = &writer_.interface;
    try pumpFileToWriter(file, writer);
    try writer.flush();
    child_stdin.close();
    const term = try child.wait();
    if (!termExitedOk(term)) return error.RemoteHelperUploadFailed;
}

fn pumpFileToWriter(file: std.fs.File, writer: *std.Io.Writer) !void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) return;
        try writer.writeAll(buf[0..n]);
    }
}

fn platformMatches(local_os: []const u8, remote_os: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(local_os, remote_os)) return true;
    if (std.mem.eql(u8, local_os, "macos") and std.mem.eql(u8, remote_os, "darwin")) return true;
    return false;
}

fn termExitedOk(term: std.process.Child.Term) bool {
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

test "platform matches darwin" {
    const testing = std.testing;
    try testing.expect(platformMatches("macos", "darwin"));
}
