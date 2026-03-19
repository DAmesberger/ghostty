const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const protocol = @import("protocol.zig");
const ssh = @import("ssh.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.session_client);

pub const Error = error{
    RemoteCommandFailed,
    RemotePlatformUnsupported,
    RemoteHelperUploadFailed,
    RemoteAuthRequired,
    RemoteCheckFailed,
};

/// Native SSH connection context backed by libssh2. The session stays
/// open across all operations — no ControlMaster or subprocess needed.
pub const SshContext = struct {
    alloc: Allocator,
    ssh_target: []const u8,
    jump: ?[]const u8,
    session: ?ssh.SshSession = null,
    /// If we connected through a jump host, this holds the jump session.
    /// The target session's .jump field references it, but we keep the
    /// jump session alive here for the duration of the context.
    jump_session: ?ssh.SshSession = null,

    pub fn deinit(self: *SshContext) void {
        if (self.session) |*s| {
            s.close();
            self.session = null;
        }
        // The jump session is cleaned up via the target session's jump
        // state, so we just nil the pointer here.
        self.jump_session = null;
    }

    /// Establish the SSH connection and authenticate.
    /// Tries agent/key auth first; falls back to password prompt on stderr.
    pub fn connect(self: *SshContext, stderr: *std.Io.Writer) !void {
        if (self.session != null) return;

        ssh.globalInit();
        const target = try ssh.SshTarget.parse(self.ssh_target);

        if (self.jump) |jump_str| {
            const jump = try ssh.SshTarget.parse(jump_str);

            // Connect and authenticate to the jump host
            var jump_sess = ssh.SshSession.connect(self.alloc, jump.host, jump.port) catch {
                try stderr.print("Failed to connect to jump host {s}\n", .{jump_str});
                try stderr.flush();
                return error.RemoteAuthRequired;
            };
            // Once tunnel() succeeds, target_sess.close() owns the jump
            // resources (session, socket, channel). Only close independently
            // if we fail before that point.
            var jump_needs_close = true;
            errdefer if (jump_needs_close) jump_sess.close();

            jump_sess.authAuto(jump.user) catch {
                try stderr.print("Password for {s}: ", .{jump_str});
                try stderr.flush();
                const pass = readPassword(self.alloc) catch |err| {
                    try stderr.print("Failed to read password: {}\n", .{err});
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
                defer self.alloc.free(pass);
                jump_sess.authPassword(jump.user, pass) catch {
                    try stderr.writeAll("Authentication failed for jump host.\n");
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
                try stderr.writeAll("Jump host password auth OK.\n");
                try stderr.flush();
            };

            try stderr.writeAll("Opening tunnel...\n");
            try stderr.flush();

            // Tunnel through jump to target and authenticate
            var target_sess = jump_sess.tunnel(target.host, target.port) catch |err| {
                try stderr.print("Failed to tunnel to {s} via {s}: {}\n", .{ self.ssh_target, jump_str, err });
                try stderr.flush();
                return error.RemoteAuthRequired;
            };
            jump_needs_close = false; // target_sess now owns jump resources
            errdefer target_sess.close();

            target_sess.authAuto(target.user) catch {
                try stderr.print("Password for {s}: ", .{self.ssh_target});
                try stderr.flush();
                const pass = readPassword(self.alloc) catch |err| {
                    try stderr.print("Failed to read password: {}\n", .{err});
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
                defer self.alloc.free(pass);
                target_sess.authPassword(target.user, pass) catch {
                    try stderr.writeAll("Authentication failed for target host.\n");
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
            };

            self.jump_session = jump_sess;
            self.session = target_sess;
        } else {
            var sess = ssh.SshSession.connect(self.alloc, target.host, target.port) catch {
                try stderr.print("Failed to connect to {s}\n", .{self.ssh_target});
                try stderr.flush();
                return error.RemoteAuthRequired;
            };
            errdefer sess.close();

            sess.authAuto(target.user) catch {
                try stderr.print("Password for {s}: ", .{self.ssh_target});
                try stderr.flush();
                const pass = readPassword(self.alloc) catch |err| {
                    try stderr.print("Failed to read password: {}\n", .{err});
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
                defer self.alloc.free(pass);
                sess.authPassword(target.user, pass) catch {
                    try stderr.writeAll("Authentication failed.\n");
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
            };

            self.session = sess;
        }
    }
};

/// Ensure the remote helper binary exists on the target host with a
/// compatible protocol version.
pub fn ensureRemoteHelper(
    alloc: Allocator,
    ctx: *SshContext,
    stderr: *std.Io.Writer,
) ![]const u8 {
    const helper_path = try shared.remoteInstallPath(alloc);
    errdefer alloc.free(helper_path);

    // Establish SSH connection
    try ctx.connect(stderr);
    var sess = &ctx.session.?;

    // Probe: run the helper's --version flag. If the binary is missing,
    // wrong arch, or a different protocol version, we re-upload.
    const version_cmd = try std.fmt.allocPrint(
        alloc,
        "{s} +session-helper --version",
        .{helper_path},
    );
    defer alloc.free(version_cmd);

    const result = sess.exec(version_cmd) catch {
        try uploadHelper(alloc, sess, helper_path, stderr);
        return helper_path;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.exit_code != 0) {
        try uploadHelper(alloc, sess, helper_path, stderr);
        return helper_path;
    }

    // Parse "GHOSTTY_SESSION_PROTOCOL <version>\n"
    const prefix = "GHOSTTY_SESSION_PROTOCOL ";
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, prefix)) {
        try stderr.writeAll("Remote helper version unrecognized, re-uploading...\n");
        try stderr.flush();
        try uploadHelper(alloc, sess, helper_path, stderr);
        return helper_path;
    }

    const ver_str = trimmed[prefix.len..];
    const remote_version = std.fmt.parseInt(u16, ver_str, 10) catch {
        try uploadHelper(alloc, sess, helper_path, stderr);
        return helper_path;
    };

    if (remote_version != protocol.protocol_version) {
        try stderr.writeAll("Remote helper protocol version mismatch, re-uploading...\n");
        try stderr.flush();
        try uploadHelper(alloc, sess, helper_path, stderr);
    }

    return helper_path;
}

/// Launch the remote session daemon via the helper's --daemonize flag.
/// With the double-fork daemonization, this returns promptly.
pub fn ensureRemoteDaemon(
    alloc: Allocator,
    ctx: *const SshContext,
    helper_path: []const u8,
) !void {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    {
        const dbg = std.fs.File.stderr();
        var b: [80]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "[ensureRemoteDaemon] sock={d}\n", .{sess.sock}) catch "";
        dbg.writeAll(m) catch {};
    }
    const cmd = try std.fmt.allocPrint(
        alloc,
        "{s} +session-helper --daemonize",
        .{helper_path},
    );
    defer alloc.free(cmd);

    const result = try sess.exec(cmd);
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (result.exit_code != 0) return error.RemoteCommandFailed;
}

pub const Capture = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: c_int,
};

/// Execute a command on the remote host and capture its output.
pub fn runRemoteCapture(
    alloc: Allocator,
    ctx: *const SshContext,
    remote_cmd: []const u8,
) !Capture {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    const result = try sess.exec(remote_cmd);
    _ = alloc;
    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .exit_code = result.exit_code,
    };
}

/// Build a remote command string from separate arguments.
pub fn buildRemoteCommand(
    alloc: Allocator,
    args: []const []const u8,
) ![]const u8 {
    var cmd = std.ArrayList(u8).empty;
    defer cmd.deinit(alloc);
    for (args, 0..) |arg, i| {
        if (i > 0) try cmd.append(alloc, ' ');
        try cmd.appendSlice(alloc, arg);
    }
    return try cmd.toOwnedSlice(alloc);
}

/// Open a channel to the remote helper's stdio-attach mode.
/// Returns a Channel that provides read/write directly — no subprocess.
pub fn openRemoteAttach(
    alloc: Allocator,
    ctx: *const SshContext,
    helper_path: []const u8,
    session_id: ?[]const u8,
    label: ?[]const u8,
) !ssh.Channel {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    const dbg = std.fs.File.stderr();
    {
        var b: [120]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "[openRemoteAttach] sock={d} session_ptr={d}\n", .{ sess.sock, @intFromPtr(sess.session) }) catch "";
        dbg.writeAll(m) catch {};
    }
    var channel = try sess.openChannel();
    errdefer channel.close();

    // Build the command
    var cmd = std.ArrayList(u8).empty;
    defer cmd.deinit(alloc);
    try cmd.appendSlice(alloc, helper_path);
    try cmd.appendSlice(alloc, " +session-helper --stdio-attach");
    if (session_id) |id| {
        try cmd.appendSlice(alloc, " --session=");
        try cmd.appendSlice(alloc, id);
    } else {
        try cmd.appendSlice(alloc, " --new");
    }
    if (label) |value| {
        try cmd.appendSlice(alloc, " --label=");
        try cmd.appendSlice(alloc, value);
    }
    const cmd_str = try cmd.toOwnedSlice(alloc);
    defer alloc.free(cmd_str);

    dbg.writeAll("[openRemoteAttach] cmd: ") catch {};
    dbg.writeAll(cmd_str) catch {};
    dbg.writeAll("\n") catch {};

    try channel.exec(cmd_str);
    return channel;
}

// -- Internal helpers --

fn uploadHelper(
    alloc: Allocator,
    sess: *ssh.SshSession,
    helper_path: []const u8,
    stderr: *std.Io.Writer,
) !void {
    try stderr.writeAll("\nSetting up Ghostty helper on remote host...\n");
    try stderr.flush();

    const exe_path = try std.fs.selfExePathAlloc(alloc);
    defer alloc.free(exe_path);

    const install_dir = try shared.remoteInstallDir(alloc);
    defer alloc.free(install_dir);

    // Create the install directory
    const mkdir_cmd = try std.fmt.allocPrint(alloc, "mkdir -p '{s}'", .{install_dir});
    defer alloc.free(mkdir_cmd);
    const mkdir_result = try sess.exec(mkdir_cmd);
    defer alloc.free(mkdir_result.stdout);
    defer alloc.free(mkdir_result.stderr);

    // Check platform
    const uname_result = try sess.exec("uname -s && uname -m");
    defer alloc.free(uname_result.stdout);
    defer alloc.free(uname_result.stderr);

    if (uname_result.exit_code == 0) {
        var it = std.mem.splitScalar(u8, std.mem.trim(u8, uname_result.stdout, " \t\r\n"), '\n');
        const remote_os = it.next() orelse "";
        const remote_arch = it.next() orelse "";
        const local = shared.localPlatform();
        if (!platformMatches(local.os, remote_os) or
            !std.ascii.eqlIgnoreCase(local.arch, remote_arch))
        {
            try stderr.writeAll("Warning: remote platform may not match local binary.\n");
            try stderr.flush();
        }
    }

    // Upload via SCP to a temp file, then move into place to avoid
    // "Text file busy" when replacing a running binary.
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{helper_path});
    defer alloc.free(tmp_path);

    const file = try std.fs.openFileAbsolute(exe_path, .{});
    defer file.close();
    const stat = try file.stat();

    try stderr.print("Uploading binary ({d} KB)... ", .{stat.size / 1024});
    try stderr.flush();

    try sess.upload(exe_path, tmp_path, 0o700);

    try stderr.writeAll("Done.\n");
    try stderr.flush();

    // Move into final location
    const mv_cmd = try std.fmt.allocPrint(
        alloc,
        "mv -f '{s}' '{s}' && test -x '{s}' && echo GHOSTTY_SETUP_SUCCESS",
        .{ tmp_path, helper_path, helper_path },
    );
    defer alloc.free(mv_cmd);
    const mv_result = try sess.exec(mv_cmd);
    defer alloc.free(mv_result.stdout);
    defer alloc.free(mv_result.stderr);

    if (std.mem.indexOf(u8, mv_result.stdout, "GHOSTTY_SETUP_SUCCESS") == null) {
        try stderr.writeAll("Setup failed: could not install helper binary.\n");
        try stderr.flush();
        return error.RemoteHelperUploadFailed;
    }

    try stderr.writeAll("Helper installed successfully.\n");
    try stderr.flush();
}

fn platformMatches(local_os: []const u8, remote_os: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(local_os, remote_os)) return true;
    if (std.mem.eql(u8, local_os, "macos") and std.mem.eql(u8, remote_os, "darwin")) return true;
    return false;
}

/// Read a password from stdin with echo disabled.
fn readPassword(alloc: Allocator) ![]u8 {
    if (comptime builtin.os.tag == .windows) return error.RemoteAuthRequired;

    // Disable echo
    var old_termios: c.struct_termios = undefined;
    const has_termios = c.tcgetattr(posix.STDIN_FILENO, &old_termios) == 0;
    if (has_termios) {
        var new_termios = old_termios;
        new_termios.c_lflag &= @bitCast(~@as(c_uint, c.ECHO));
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &new_termios);
    }
    defer if (has_termios) {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &old_termios);
        // Print newline after password entry
        _ = posix.write(posix.STDERR_FILENO, "\n") catch {};
    };

    // Read until newline
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);
    var byte: [1]u8 = undefined;
    while (true) {
        const n = posix.read(posix.STDIN_FILENO, &byte) catch break;
        if (n == 0) break;
        if (byte[0] == '\n' or byte[0] == '\r') break;
        try buf.append(alloc, byte[0]);
    }

    return try buf.toOwnedSlice(alloc);
}

test "platform matches darwin" {
    const testing = std.testing;
    try testing.expect(platformMatches("macos", "darwin"));
}

test "platform matches case insensitive" {
    const testing = std.testing;
    try testing.expect(platformMatches("linux", "Linux"));
    try testing.expect(!platformMatches("linux", "darwin"));
}

test "version output format matches parser expectation" {
    // The helper outputs "GHOSTTY_SESSION_PROTOCOL <version>\n"
    // and the client parses it with this prefix. Verify they agree.
    const version_output = std.fmt.comptimePrint(
        "GHOSTTY_SESSION_PROTOCOL {d}\n",
        .{protocol.protocol_version},
    );
    const prefix = "GHOSTTY_SESSION_PROTOCOL ";
    const trimmed = std.mem.trim(u8, version_output, " \t\r\n");
    try std.testing.expect(std.mem.startsWith(u8, trimmed, prefix));
    const ver_str = trimmed[prefix.len..];
    const parsed = try std.fmt.parseInt(u16, ver_str, 10);
    try std.testing.expectEqual(protocol.protocol_version, parsed);
}
