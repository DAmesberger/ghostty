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

/// Zero-fill a buffer before freeing it, preventing sensitive data
/// (passwords, keys) from lingering in deallocated memory.
fn secureZeroAndFree(alloc: Allocator, buf: []u8) void {
    @memset(buf, 0);
    alloc.free(buf);
}

pub const Error = error{
    RemoteCommandFailed,
    RemotePlatformUnsupported,
    RemoteHelperUploadFailed,
    RemoteAuthRequired,
    RemoteCheckFailed,
};

pub const ConnectResult = enum {
    success,
    password_required_target,
    password_required_jump,
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
                defer secureZeroAndFree(self.alloc, pass);
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
                defer secureZeroAndFree(self.alloc, pass);
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
                defer secureZeroAndFree(self.alloc, pass);
                sess.authPassword(target.user, pass) catch {
                    try stderr.writeAll("Authentication failed.\n");
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
            };

            self.session = sess;
        }
    }

    /// Like connect() but returns password_required instead of reading stdin.
    /// Designed for GUI-based authentication: if a password is needed and not
    /// provided, returns which host needs it so the caller can prompt the user
    /// and call again with the password.
    ///
    /// If `password` is non-null, it's used for the host indicated by `for_jump`:
    /// - `for_jump == true` → password is applied to the jump host
    /// - `for_jump == false` → password is applied to the target host
    ///
    /// Between calls, partially-established state (`self.jump_session`,
    /// `self.session`) is preserved, so reconnection steps are skipped on retry.
    pub fn connectWithAuth(
        self: *SshContext,
        stderr: *std.Io.Writer,
        password: ?[]const u8,
        for_jump: bool,
    ) !ConnectResult {
        if (self.session != null) return .success;

        ssh.globalInit();
        const target = try ssh.SshTarget.parse(self.ssh_target);

        if (self.jump) |jump_str| {
            const jump = try ssh.SshTarget.parse(jump_str);

            // --- Jump host connection & auth ---
            if (self.jump_session == null) {
                var jump_sess = ssh.SshSession.connect(self.alloc, jump.host, jump.port) catch {
                    try stderr.print("Failed to connect to jump host {s}\n", .{jump_str});
                    try stderr.flush();
                    return error.RemoteAuthRequired;
                };
                var jump_needs_close = true;
                errdefer if (jump_needs_close) jump_sess.close();

                jump_sess.authAuto(jump.user) catch {
                    if (for_jump) {
                        if (password) |pass| {
                            jump_sess.authPassword(jump.user, pass) catch {
                                try stderr.writeAll("Authentication failed for jump host.\n");
                                try stderr.flush();
                                return error.RemoteAuthRequired;
                            };
                            try stderr.writeAll("Jump host password auth OK.\n");
                            try stderr.flush();
                        } else {
                            // Password needed but not provided — close and ask caller.
                            return .password_required_jump;
                        }
                    } else {
                        // We weren't given a password for the jump host.
                        return .password_required_jump;
                    }
                };

                jump_needs_close = false;
                self.jump_session = jump_sess;
            }

            // --- Tunnel to target ---
            try stderr.writeAll("Opening tunnel...\n");
            try stderr.flush();

            var target_sess = self.jump_session.?.tunnel(target.host, target.port) catch |err| {
                try stderr.print("Failed to tunnel to {s} via {s}: {}\n", .{ self.ssh_target, jump_str, err });
                try stderr.flush();
                return error.RemoteAuthRequired;
            };
            errdefer target_sess.close();

            // --- Target auth ---
            target_sess.authAuto(target.user) catch {
                if (!for_jump) {
                    if (password) |pass| {
                        target_sess.authPassword(target.user, pass) catch {
                            try stderr.writeAll("Authentication failed for target host.\n");
                            try stderr.flush();
                            return error.RemoteAuthRequired;
                        };
                    } else {
                        return .password_required_target;
                    }
                } else {
                    // Password was for jump host, not target — ask caller for target password.
                    return .password_required_target;
                }
            };

            self.session = target_sess;
            return .success;
        } else {
            // --- Direct connection (no jump host) ---
            var sess = ssh.SshSession.connect(self.alloc, target.host, target.port) catch {
                try stderr.print("Failed to connect to {s}\n", .{self.ssh_target});
                try stderr.flush();
                return error.RemoteAuthRequired;
            };
            errdefer sess.close();

            sess.authAuto(target.user) catch {
                if (password) |pass| {
                    sess.authPassword(target.user, pass) catch {
                        try stderr.writeAll("Authentication failed.\n");
                        try stderr.flush();
                        return error.RemoteAuthRequired;
                    };
                } else {
                    return .password_required_target;
                }
            };

            self.session = sess;
            return .success;
        }
    }
};

pub const Mailbox = @import("../apprt.zig").surface.Mailbox;

/// Ensure the remote helper binary exists on the target host with a
/// compatible protocol version.
pub fn ensureRemoteHelper(
    alloc: Allocator,
    ctx: *SshContext,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
) ![]const u8 {
    // Establish SSH connection
    try ctx.connect(stderr);
    var sess = &ctx.session.?;

    // Resolve the remote HOME directory for secure path construction
    const remote_home = try resolveRemoteHome(alloc, sess);
    defer alloc.free(remote_home);

    const helper_path = try shared.remoteInstallPath(alloc, remote_home);
    errdefer alloc.free(helper_path);

    // Probe: run the helper's --version flag. If the binary is missing,
    // wrong arch, or a different protocol version, we re-upload.
    const version_cmd = try std.fmt.allocPrint(
        alloc,
        "{s} +session-helper --protocol-version",
        .{helper_path},
    );
    defer alloc.free(version_cmd);

    const result = sess.exec(version_cmd) catch {
        try uploadHelper(alloc, sess, helper_path, remote_home, stderr, mailbox);
        return helper_path;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.exit_code != 0) {
        try uploadHelper(alloc, sess, helper_path, remote_home, stderr, mailbox);
        return helper_path;
    }

    // Parse "GHOSTTY_SESSION_PROTOCOL <version>\n"
    const prefix = "GHOSTTY_SESSION_PROTOCOL ";
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, prefix)) {
        try stderr.writeAll("Remote helper version unrecognized, re-uploading...\n");
        try stderr.flush();
        try uploadHelper(alloc, sess, helper_path, remote_home, stderr, mailbox);
        return helper_path;
    }

    const ver_str = trimmed[prefix.len..];
    const remote_version = std.fmt.parseInt(u16, ver_str, 10) catch {
        try uploadHelper(alloc, sess, helper_path, remote_home, stderr, mailbox);
        return helper_path;
    };

    if (remote_version != protocol.protocol_version) {
        try stderr.writeAll("Remote helper protocol version mismatch, re-uploading...\n");
        try stderr.flush();
        try uploadHelper(alloc, sess, helper_path, remote_home, stderr, mailbox);
    }

    return helper_path;
}

/// Launch the remote session daemon via the helper's --daemonize flag.
/// If `force_restart` is true, kills any existing daemon first (used
/// when the helper binary was re-uploaded with a new protocol version).
pub fn ensureRemoteDaemon(
    alloc: Allocator,
    ctx: *const SshContext,
    helper_path: []const u8,
    force_restart: bool,
) !void {
    var sess = ctx.session orelse return error.RemoteCommandFailed;

    if (force_restart) {
        // Kill any existing daemon — the old one may be running old code
        // in memory even after the binary was re-uploaded.
        const kill_cmd = try std.fmt.allocPrint(
            alloc,
            "{s} +session-helper --kill-daemon",
            .{helper_path},
        );
        defer alloc.free(kill_cmd);
        const kill_result = sess.exec(kill_cmd) catch null;
        if (kill_result) |r| {
            alloc.free(r.stdout);
            alloc.free(r.stderr);
        }
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
/// Each argument is shell-escaped to prevent injection attacks.
pub fn buildRemoteCommand(
    alloc: Allocator,
    args: []const []const u8,
) ![]const u8 {
    var cmd = std.ArrayList(u8).empty;
    defer cmd.deinit(alloc);
    for (args, 0..) |arg, i| {
        if (i > 0) try cmd.append(alloc, ' ');
        const escaped = try shellEscape(alloc, arg);
        defer alloc.free(escaped);
        try cmd.appendSlice(alloc, escaped);
    }
    return try cmd.toOwnedSlice(alloc);
}

/// Shell-escape a string for safe use in SSH commands.
/// Wraps the string in single quotes, escaping any embedded single quotes
/// using the '\'' technique (end quote, literal quote, restart quote).
fn shellEscape(alloc: Allocator, s: []const u8) ![]u8 {
    // Count single quotes to determine output size
    var sq_count: usize = 0;
    for (s) |ch| {
        if (ch == '\'') sq_count += 1;
    }

    // Output: ' + content + '
    // Each embedded ' becomes '\'' (4 chars instead of 1)
    const out_len = 2 + s.len + sq_count * 3;
    var out = try alloc.alloc(u8, out_len);
    var i: usize = 0;
    out[i] = '\'';
    i += 1;
    for (s) |ch| {
        if (ch == '\'') {
            out[i] = '\'';
            out[i + 1] = '\\';
            out[i + 2] = '\'';
            out[i + 3] = '\'';
            i += 4;
        } else {
            out[i] = ch;
            i += 1;
        }
    }
    out[i] = '\'';
    return out[0 .. i + 1];
}

/// Open a multiplexed channel to the remote helper's stdio-attach mode.
/// Returns a Channel shared by all sessions to this host. Session creation
/// happens via session_open frames, not CLI args.
pub fn openMultiplexChannel(
    alloc: Allocator,
    ctx: *const SshContext,
    helper_path: []const u8,
) !ssh.Channel {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    var channel = try sess.openChannel();
    errdefer channel.close();

    const cmd = try std.fmt.allocPrint(alloc, "{s} +session-helper --stdio-attach", .{helper_path});
    defer alloc.free(cmd);

    try channel.exec(cmd);
    return channel;
}

// -- Internal helpers --

fn uploadHelper(
    alloc: Allocator,
    sess: *ssh.SshSession,
    helper_path: []const u8,
    remote_home: []const u8,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
) !void {
    try stderr.writeAll("\nSetting up Ghostty helper on remote host...\n");
    try stderr.flush();

    const exe_path = try std.fs.selfExePathAlloc(alloc);
    defer alloc.free(exe_path);

    const install_dir = try shared.remoteInstallDir(alloc, remote_home);
    defer alloc.free(install_dir);

    // Create the install directory and set restrictive permissions
    const mkdir_cmd = try std.fmt.allocPrint(alloc, "mkdir -p '{s}' && chmod 700 '{s}'", .{ install_dir, install_dir });
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
    const total_bytes: u64 = stat.size;

    try stderr.print("Uploading binary ({d} KB)... ", .{total_bytes / 1024});
    try stderr.flush();

    // Notify via mailbox of upload start
    pushConnectionState(mailbox, .{ .uploading = .{ .bytes_sent = 0, .total_bytes = total_bytes } });

    const ProgressCtx = struct {
        mbox: ?*Mailbox,
        total: u64,

        pub fn onProgress(ctx: @This(), bytes_sent: u64) void {
            pushConnectionState(ctx.mbox, .{ .uploading = .{
                .bytes_sent = bytes_sent,
                .total_bytes = ctx.total,
            } });
        }
    };
    try sess.upload(exe_path, tmp_path, 0o700, ProgressCtx{ .mbox = mailbox, .total = total_bytes });

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

fn pushConnectionState(mailbox: ?*Mailbox, state: protocol.ConnectionState) void {
    if (mailbox) |m| {
        _ = m.push(.{ .connection_state = state }, .{ .forever = {} });
    }
}

/// Resolve the remote user's HOME directory by executing a command on the
/// remote host. This is needed to construct secure per-user install paths
/// for SCP uploads (shell variable expansion doesn't work in SCP paths).
fn resolveRemoteHome(alloc: Allocator, sess: *ssh.SshSession) ![]const u8 {
    const result = try sess.exec("printf '%s' \"$HOME\"");
    defer alloc.free(result.stderr);

    if (result.exit_code != 0 or result.stdout.len == 0) {
        alloc.free(result.stdout);
        return error.RemoteCommandFailed;
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        alloc.free(result.stdout);
        return error.RemoteCommandFailed;
    }

    // If the trimmed result is the same slice as stdout, return it directly.
    // Otherwise, dupe the trimmed portion and free the original.
    if (trimmed.ptr == result.stdout.ptr and trimmed.len == result.stdout.len) {
        return result.stdout;
    }
    const home = try alloc.dupe(u8, trimmed);
    alloc.free(result.stdout);
    return home;
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
