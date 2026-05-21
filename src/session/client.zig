const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const protocol = @import("protocol.zig");
const ssh = @import("ssh.zig");

/// Connection-pool manager type imported lazily — `attachRemoteSurface`
/// needs the `Entry` pointer + the manager's mutex/alloc to mirror the
/// behavior previously living inline in `termio/Remote.zig:setupConnection`.
/// The cycle (session → termio → session) is fine: Zig's @import graph
/// resolves declarations on demand, and `client.zig`'s use is opaque
/// pointers + field reads, no struct-layout reentry.
const SshConnectionManager = @import("../termio/SshConnectionManager.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.session_client);

const secureZeroAndFree = shared.secureZeroAndFree;

pub const Error = error{
    RemoteCommandFailed,
    RemotePlatformUnsupported,
    RemoteUploadFailed,
    RemoteDownloadFailed,
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
    /// If we connected through a jump host, this holds the last
    /// authenticated session in the chain. For multi-hop, this is
    /// the furthest hop reached so far.
    jump_session: ?ssh.SshSession = null,
    /// Index of the next jump hop to connect (0-based). Used to resume
    /// multi-hop chains after a password prompt.
    jump_hop_index: u8 = 0,

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
    /// Delegates to connectWithAuth(), reading passwords from stdin when needed.
    pub fn connect(self: *SshContext, stderr: *std.Io.Writer) !void {
        var for_jump: bool = false;
        var password: ?[]const u8 = null;
        while (true) {
            defer {
                if (password) |pw| secureZeroAndFree(self.alloc, @constCast(pw));
                password = null;
            }
            const result = try self.connectWithAuth(stderr, password, for_jump);
            switch (result) {
                .success => return,
                .password_required_jump => {
                    for_jump = true;
                    try stderr.print("Password for {s}: ", .{self.jump orelse "jump host"});
                    try stderr.flush();
                    password = readPassword(self.alloc) catch |err| {
                        try stderr.print("Failed to read password: {}\n", .{err});
                        try stderr.flush();
                        return error.RemoteAuthRequired;
                    };
                },
                .password_required_target => {
                    for_jump = false;
                    try stderr.print("Password for {s}: ", .{self.ssh_target});
                    try stderr.flush();
                    password = readPassword(self.alloc) catch |err| {
                        try stderr.print("Failed to read password: {}\n", .{err});
                        try stderr.flush();
                        return error.RemoteAuthRequired;
                    };
                },
            }
        }
    }

    /// Like connect() but returns password_required instead of reading stdin.
    /// Designed for GUI-based authentication: if a password is needed and not
    /// provided, returns which host needs it so the caller can prompt the user
    /// and call again with the password.
    ///
    /// If `password` is non-null, it's used for the host indicated by `for_jump`:
    /// - `for_jump == true` → password is applied to the current jump hop
    /// - `for_jump == false` → password is applied to the target host
    ///
    /// Between calls, partially-established state (`self.jump_session`,
    /// `self.jump_hop_index`) is preserved, so completed hops are skipped on retry.
    /// Supports multi-hop jump chains: `hop1@h1,hop2@h2`.
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
            // Iterate through comma-separated jump hosts for multi-hop chaining.
            var hops = std.mem.splitScalar(u8, jump_str, ',');
            var hop_index: u8 = 0;

            // Skip already-connected hops (from previous password retry).
            while (hop_index < self.jump_hop_index) : (hop_index += 1) {
                _ = hops.next();
            }

            // Connect and authenticate each remaining hop.
            while (hops.next()) |hop_raw| {
                const hop_trimmed = std.mem.trim(u8, hop_raw, " \t");
                const hop = try ssh.SshTarget.parse(hop_trimmed);
                const is_pw_target = for_jump and hop_index == self.jump_hop_index;

                if (self.jump_session) |*prev| {
                    try stderr.print("Tunneling to {s}...\n", .{hop_trimmed});
                    try stderr.flush();
                    var sess = prev.tunnel(hop.host, hop.port) catch |err| {
                        try stderr.print("Failed to tunnel to {s}: {}\n", .{ hop_trimmed, err });
                        try stderr.flush();
                        return err;
                    };
                    errdefer sess.close();

                    if (try authenticateSession(&sess, hop.user, if (is_pw_target) password else null, is_pw_target, stderr, hop_trimmed)) |_| {
                        self.jump_hop_index = hop_index;
                        return .password_required_jump;
                    }
                    self.jump_session = sess;
                } else {
                    // First hop — direct TCP connection.
                    var sess = ssh.SshSession.connect(self.alloc, hop.host, hop.port) catch |err| {
                        try stderr.print("Failed to connect to {s}: {}\n", .{ hop_trimmed, err });
                        try stderr.flush();
                        return err;
                    };
                    errdefer sess.close();

                    if (try authenticateSession(&sess, hop.user, if (is_pw_target) password else null, is_pw_target, stderr, hop_trimmed)) |_| {
                        self.jump_hop_index = hop_index;
                        return .password_required_jump;
                    }
                    self.jump_session = sess;
                }

                hop_index += 1;
                self.jump_hop_index = hop_index;
            }

            // Tunnel from last hop to target.
            try stderr.writeAll("Opening tunnel to target...\n");
            try stderr.flush();
            var target_sess = self.jump_session.?.tunnel(target.host, target.port) catch |err| {
                try stderr.print("Failed to tunnel to {s}: {}\n", .{ self.ssh_target, err });
                try stderr.flush();
                return err;
            };
            errdefer target_sess.close();

            if (try authenticateSession(&target_sess, target.user, if (!for_jump) password else null, !for_jump, stderr, self.ssh_target)) |_| {
                return .password_required_target;
            }

            self.session = target_sess;
            return .success;
        } else {
            // Direct connection (no jump host).
            var sess = ssh.SshSession.connect(self.alloc, target.host, target.port) catch |err| {
                try stderr.print("Failed to connect to {s}: {}\n", .{ self.ssh_target, err });
                try stderr.flush();
                return err;
            };
            errdefer sess.close();

            if (try authenticateSession(&sess, target.user, password, password != null, stderr, self.ssh_target)) |_| {
                return .password_required_target;
            }

            self.session = sess;
            return .success;
        }
    }

    /// Authenticate a session via agent/key, falling back to password if provided.
    /// Returns null on success, or a ConnectResult placeholder if password is needed.
    fn authenticateSession(
        sess: *ssh.SshSession,
        user: []const u8,
        password: ?[]const u8,
        is_password_target: bool,
        stderr: *std.Io.Writer,
        host_label: []const u8,
    ) !?ConnectResult {
        sess.authAuto(user) catch {
            if (is_password_target) {
                if (password) |pass| {
                    sess.authPassword(user, pass) catch {
                        try stderr.print("Authentication failed for {s}.\n", .{host_label});
                        try stderr.flush();
                        return error.SshAuthFailed;
                    };
                    return null; // password auth succeeded
                }
            }
            // Password needed but not provided for this host.
            return .password_required_jump;
        };
        return null; // authAuto succeeded
    }
};

pub const Mailbox = @import("../apprt.zig").surface.Mailbox;

/// Result of provisioning a ghostty binary on the remote host.
pub const ProvisionResult = struct {
    path: []const u8,
    provisioned: bool,
};

/// Ensure a compatible ghostty-daemon exists on the remote host.
///
/// Resolution order:
///   1. `ghostty` in remote PATH with matching protocol version → use it
///   2. Same arch → upload local ghostty-daemon (from same dir as this binary) if available
///   3. Download ghostty-daemon from GitHub CI release for target OS/arch
pub fn ensureRemoteGhostty(
    alloc: Allocator,
    ctx: *SshContext,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
) !ProvisionResult {
    // Establish SSH connection
    try ctx.connect(stderr);
    var sess = &ctx.session.?;

    // Resolve remote HOME, OS, and arch in a single SSH round trip
    const remote_info = try resolveRemoteInfo(alloc, sess);
    defer alloc.free(remote_info.home);
    defer alloc.free(remote_info.os);
    defer alloc.free(remote_info.arch);
    const remote_home = remote_info.home;
    const remote_os = remote_info.os;
    const remote_arch = remote_info.arch;

    // 1. Check if ghostty in PATH on the remote has the right protocol version.
    const path_check = sess.exec("ghostty " ++ shared.remote_subcommand ++ " --protocol-version") catch null;
    if (path_check) |pc| {
        defer alloc.free(pc.stdout);
        defer alloc.free(pc.stderr);
        if (pc.exit_code == 0) {
            if (parseProtocolVersion(pc.stdout)) |ver| {
                if (ver == protocol.protocol_version) {
                    return .{ .path = try alloc.dupe(u8, "ghostty"), .provisioned = false };
                }
            }
        }
    }

    // Also check if a previously deployed ghostty-daemon exists with matching version.
    const daemon_path = try shared.remoteDaemonInstallPath(alloc, remote_home, remote_os);
    defer alloc.free(daemon_path);

    if (try probeDeployedBinary(alloc, sess, daemon_path)) {
        return .{ .path = try alloc.dupe(u8, daemon_path), .provisioned = false };
    }

    // Need to provision — install as ghostty-daemon.
    const dest = try alloc.dupe(u8, daemon_path);
    errdefer alloc.free(dest);

    // 2. Same architecture → try uploading local ghostty-daemon binary.
    const local = shared.localPlatform();
    const arch_matches = platformMatches(local.os, remote_os) and
        std.ascii.eqlIgnoreCase(local.arch, remote_arch);

    if (arch_matches) {
        if (try findLocalDaemon(alloc)) |local_daemon| {
            defer alloc.free(local_daemon);

            if (uploadGhostty(alloc, sess, dest, local_daemon, remote_home, remote_os, stderr, mailbox, .local_daemon)) {
                return .{ .path = dest, .provisioned = true };
            } else |_| {
                // Local daemon upload failed (e.g., file not found) — fall through to download.
            }
        }
    }

    // 3. Download ghostty-daemon from GitHub CI release.
    const norm_os = shared.normalizeOs(remote_os);
    const norm_arch = shared.normalizeArch(remote_arch);

    try stderr.print(
        "Downloading ghostty-daemon for {s}/{s}...\n",
        .{ norm_os, norm_arch },
    );
    try stderr.flush();

    try downloadAndInstallDaemon(alloc, sess, dest, remote_home, remote_os, norm_os, norm_arch, stderr, mailbox);
    return .{ .path = dest, .provisioned = true };
}

/// Find a locally-built daemon binary adjacent to the current exe.
/// Returns the path if found, null otherwise. Caller owns returned memory.
fn findLocalDaemon(alloc: Allocator) !?[]const u8 {
    const exe_path = std.fs.selfExePathAlloc(alloc) catch return null;
    defer alloc.free(exe_path);

    const dir = std.fs.path.dirname(exe_path) orelse return null;
    return try std.fs.path.join(alloc, &.{ dir, "ghostty-daemon" });
}

/// Check if a deployed binary at the given path has a compatible protocol version.
/// Returns true if the binary exists and its protocol version matches the local one.
fn probeDeployedBinary(
    alloc: Allocator,
    sess: *ssh.SshSession,
    binary_path: []const u8,
) !bool {
    const version_cmd = try std.fmt.allocPrint(
        alloc,
        "{s} " ++ shared.remote_subcommand ++ " --protocol-version",
        .{binary_path},
    );
    defer alloc.free(version_cmd);

    const result = sess.exec(version_cmd) catch return false;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.exit_code != 0) return false;

    const remote_version = parseProtocolVersion(result.stdout) orelse return false;
    if (remote_version != protocol.protocol_version) {
        log.info("remote binary at {s} has protocol v{d}, need v{d}", .{
            binary_path, remote_version, protocol.protocol_version,
        });
        return false;
    }

    return true;
}

/// Download a pre-built daemon binary from GitHub releases and install
/// it on the remote host. Tries downloading directly on the remote first
/// (most efficient), then falls back to local download + SCP upload.
fn downloadAndInstallDaemon(
    alloc: Allocator,
    sess: *ssh.SshSession,
    remote_dest_path: []const u8,
    remote_home: []const u8,
    remote_os: []const u8,
    norm_os: []const u8,
    norm_arch: []const u8,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
) !void {
    const url = try shared.daemonDownloadUrl(alloc, protocol.protocol_version, norm_os, norm_arch);
    defer alloc.free(url);

    const install_dir = try shared.remoteInstallDir(alloc, remote_home, remote_os);
    defer alloc.free(install_dir);

    try ensureRemoteDir(alloc, sess, install_dir);

    const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{remote_dest_path});
    defer alloc.free(tmp_path);

    // Strategy 1: Download directly on remote (avoids double transfer)
    const remote_dl_cmd = try std.fmt.allocPrint(
        alloc,
        "curl -fsSL -o '{s}' '{s}' && chmod 700 '{s}' && mv -f '{s}' '{s}'",
        .{ tmp_path, url, tmp_path, tmp_path, remote_dest_path },
    );
    defer alloc.free(remote_dl_cmd);

    pushConnectionState(mailbox, .downloading);

    const dl_result = sess.exec(remote_dl_cmd) catch null;
    const remote_dl_ok = if (dl_result) |r| blk: {
        defer alloc.free(r.stdout);
        defer alloc.free(r.stderr);
        break :blk r.exit_code == 0;
    } else false;

    if (!remote_dl_ok) {
        // Strategy 2: Download locally then upload via SCP
        try stderr.writeAll("Remote download failed, downloading locally and uploading via SCP...\n");
        try stderr.flush();

        try downloadAndUploadLocal(alloc, sess, remote_dest_path, tmp_path, url, stderr, mailbox);
    }

    // Verify the installed binary works
    const verify_cmd = try std.fmt.allocPrint(
        alloc,
        "{s} " ++ shared.remote_subcommand ++ " --protocol-version",
        .{remote_dest_path},
    );
    defer alloc.free(verify_cmd);

    const verify = sess.exec(verify_cmd) catch {
        try stderr.writeAll("Failed to verify downloaded daemon binary.\n");
        try stderr.flush();
        return error.RemoteDownloadFailed;
    };
    defer alloc.free(verify.stdout);
    defer alloc.free(verify.stderr);

    if (verify.exit_code != 0) {
        try stderr.print("Daemon binary failed to execute (exit={d}).\n", .{verify.exit_code});
        try stderr.flush();
        return error.RemoteDownloadFailed;
    }

    const ver = parseProtocolVersion(verify.stdout) orelse {
        try stderr.writeAll("Daemon binary did not report protocol version.\n");
        try stderr.flush();
        return error.RemoteDownloadFailed;
    };

    if (ver != protocol.protocol_version) {
        try stderr.print(
            "Downloaded binary has protocol version {d}, expected {d}. " ++
                "Please ensure the CI release matches your local build.\n",
            .{ ver, protocol.protocol_version },
        );
        try stderr.flush();
        return error.RemoteDownloadFailed;
    }

    try stderr.writeAll("Daemon binary installed successfully.\n");
    try stderr.flush();
}

/// Download a file locally using curl/wget, then upload via SCP.
fn downloadAndUploadLocal(
    alloc: Allocator,
    sess: *ssh.SshSession,
    remote_dest_path: []const u8,
    remote_tmp_path: []const u8,
    url: []const u8,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
) !void {
    // Create a temporary local file
    const local_tmp = "/tmp/ghostty-daemon-download";

    // Try curl first, then wget
    const curl_argv = [_][]const u8{ "curl", "-fsSL", "-o", local_tmp, url };
    const wget_argv = [_][]const u8{ "wget", "-q", "-O", local_tmp, url };

    var local_dl_ok = false;
    for ([_][]const []const u8{ &curl_argv, &wget_argv }) |argv| {
        var child = std.process.Child.init(argv, alloc);
        child.stderr_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        _ = child.spawnAndWait() catch continue;
        local_dl_ok = true;
        break;
    }

    if (!local_dl_ok) {
        try stderr.writeAll("Failed to download daemon binary: neither curl nor wget available locally.\n");
        try stderr.flush();
        return error.RemoteDownloadFailed;
    }

    defer std.fs.deleteFileAbsolute(local_tmp) catch {};

    // Upload via SCP
    const stat = blk: {
        const f = std.fs.openFileAbsolute(local_tmp, .{}) catch {
            try stderr.writeAll("Failed to open locally downloaded binary.\n");
            try stderr.flush();
            return error.RemoteDownloadFailed;
        };
        defer f.close();
        break :blk f.stat() catch {
            try stderr.writeAll("Failed to stat locally downloaded binary.\n");
            try stderr.flush();
            return error.RemoteDownloadFailed;
        };
    };

    const total_bytes: u64 = stat.size;
    try stderr.print("Uploading daemon binary ({d} KB)... ", .{total_bytes / 1024});
    try stderr.flush();

    pushConnectionState(mailbox, .{ .uploading = .{ .bytes_sent = 0, .total_bytes = total_bytes, .source = .github } });
    try sess.upload(local_tmp, remote_tmp_path, 0o700, UploadProgressCtx{ .mbox = mailbox, .total = total_bytes, .src = .github });

    try stderr.writeAll("Done.\n");
    try stderr.flush();

    try moveAndVerifyRemoteBinary(alloc, sess, remote_tmp_path, remote_dest_path);
}

fn parseProtocolVersion(stdout: []const u8) ?u16 {
    const prefix = "GHOSTTY_SESSION_PROTOCOL ";
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    return std.fmt.parseInt(u16, trimmed[prefix.len..], 10) catch null;
}

const RemoteInfo = struct {
    home: []const u8,
    os: []const u8,
    arch: []const u8,
};

/// Resolve HOME, OS, and arch in a single SSH round trip.
fn resolveRemoteInfo(alloc: Allocator, sess: *ssh.SshSession) !RemoteInfo {
    const result = try sess.exec("printf '%s\\n' \"$HOME\" \"$(uname -s)\" \"$(uname -m)\"");
    defer alloc.free(result.stderr);
    defer alloc.free(result.stdout);

    if (result.exit_code != 0 or result.stdout.len == 0) {
        return error.RemoteCommandFailed;
    }

    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, result.stdout, " \t\r\n"), '\n');

    const home_raw = lines.next() orelse return error.RemoteCommandFailed;
    const home = std.mem.trim(u8, home_raw, " \t\r");
    if (home.len == 0) return error.RemoteCommandFailed;

    const os_raw = lines.next() orelse "Linux";
    const arch_raw = lines.next() orelse "x86_64";

    const home_owned = try alloc.dupe(u8, home);
    errdefer alloc.free(home_owned);
    const os_owned = try alloc.dupe(u8, std.mem.trim(u8, os_raw, " \t\r"));
    errdefer alloc.free(os_owned);
    const arch_owned = try alloc.dupe(u8, std.mem.trim(u8, arch_raw, " \t\r"));

    return .{ .home = home_owned, .os = os_owned, .arch = arch_owned };
}

/// Launch the remote session daemon via ghostty's --daemonize flag.
/// If `force_restart` is true, kills any existing daemon first (used
/// when the binary was re-provisioned with a new protocol version).
pub fn ensureRemoteDaemon(
    alloc: Allocator,
    ctx: *const SshContext,
    remote_bin_path: []const u8,
    force_restart: bool,
) !void {
    var sess = ctx.session orelse return error.RemoteCommandFailed;

    if (force_restart) {
        // Kill any existing daemon — the old one may be running old code
        // in memory even after the binary was re-uploaded.
        const kill_cmd = try std.fmt.allocPrint(
            alloc,
            "{s} " ++ shared.remote_subcommand ++ " --kill-daemon",
            .{remote_bin_path},
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
        "{s} " ++ shared.remote_subcommand ++ " --daemonize",
        .{remote_bin_path},
    );
    defer alloc.free(cmd);

    const result = try sess.exec(cmd);
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (result.exit_code != 0) {
        log.warn("daemon start failed (exit={d}): stdout={s} stderr={s}", .{
            result.exit_code, result.stdout, result.stderr,
        });
        return error.RemoteCommandFailed;
    }
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

/// Create a directory on the remote host with restrictive permissions.
fn ensureRemoteDir(alloc: Allocator, sess: *ssh.SshSession, dir: []const u8) !void {
    const cmd = try std.fmt.allocPrint(alloc, "mkdir -p '{s}' && chmod 700 '{s}'", .{ dir, dir });
    defer alloc.free(cmd);
    const result = try sess.exec(cmd);
    alloc.free(result.stdout);
    alloc.free(result.stderr);
}

/// Move a temp file to its final location and verify it's executable.
fn moveAndVerifyRemoteBinary(alloc: Allocator, sess: *ssh.SshSession, tmp_path: []const u8, dest_path: []const u8) !void {
    const cmd = try std.fmt.allocPrint(
        alloc,
        "mv -f '{s}' '{s}' && test -x '{s}' && echo GHOSTTY_SETUP_SUCCESS",
        .{ tmp_path, dest_path, dest_path },
    );
    defer alloc.free(cmd);
    const result = try sess.exec(cmd);
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (std.mem.indexOf(u8, result.stdout, "GHOSTTY_SETUP_SUCCESS") == null) {
        return error.RemoteUploadFailed;
    }
}

/// Open a multiplexed channel to the remote ghostty's stdio-attach mode.
/// Returns a Channel shared by all sessions to this host. Session creation
/// happens via open frames, not CLI args.
pub fn openMultiplexChannel(
    alloc: Allocator,
    ctx: *const SshContext,
    remote_bin_path: []const u8,
) !ssh.Channel {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    var channel = try sess.openChannel();
    errdefer channel.close();

    const cmd = try std.fmt.allocPrint(alloc, "{s} " ++ shared.remote_subcommand ++ " --stdio-attach", .{remote_bin_path});
    defer alloc.free(cmd);

    try channel.exec(cmd);
    return channel;
}

/// Knobs threaded into `attachRemoteSurface` so callers (terminal
/// surfaces via `termio/Remote.zig`, the libghostty C API via
/// `apprt/embedded/ssh_capi.zig`) can override defaults without
/// reaching into the connection-pool Entry. Mirrors the fields
/// previously read off `Remote.ssh_ctx` + `Remote.scrollback_limit`.
pub const AttachConfig = struct {
    /// Number of automatic reconnect attempts after an unexpected
    /// drop. 0 disables auto-reconnect entirely; callers should
    /// drive `requestReconnect` manually if desired.
    max_reconnect_attempts: u32,
    /// Backoff strategy for the reconnect interval.
    reconnect_backoff: @import("../config.zig").Config.SshReconnectBackoff,
    /// Initial reconnect interval in milliseconds.
    reconnect_interval_ms: u32,
    /// Client-side scrollback retention requested from the daemon.
    scrollback_limit: u32,
};

/// Establish the SSH connection on an `SshConnectionManager.Entry`,
/// provision/ensure the remote `ghostty-daemon`, open the multiplexed
/// channel, stamp the Entry's reconnect/scrollback config, and spawn
/// the dedicated SSH I/O thread. Used by both the GTK terminal-
/// surface path (`termio/Remote.zig`) and the libghostty C API
/// (`apprt/embedded/ssh_capi.zig`) so the two callers share an
/// identical setup sequence.
///
/// State transitions are broadcast via the Entry-level
/// `broadcastConnectionState` fan-out (visible to BOTH the per-
/// surface mailbox path and the generic SshListener registry).
/// Additionally, when a non-null `mailbox` is supplied it receives
/// every transition directly — preserved for backward compatibility
/// with the GTK overlay code that today reads its own surface
/// mailbox during connection setup (before the surface is registered
/// on the Entry, so the broadcast fan-out wouldn't reach it).
///
/// Returns on success; the caller is responsible for the post-setup
/// steps (allocateTarget / registerSurface / sending the Open frame
/// / final CONNECTED broadcast). The caller is also responsible for
/// transitioning the Entry's `conn_state` atomic.
///
/// NOTE: this function BLOCKS — it performs the full SSH handshake,
/// possible interactive password prompts via the Entry's auth_state
/// condition variable, and the binary provisioning round-trips.
/// Callers that must remain non-blocking (e.g. the C API) MUST spawn
/// a worker thread.
pub fn attachRemoteSurface(
    alloc: Allocator,
    manager: *SshConnectionManager,
    entry: *SshConnectionManager.Entry,
    mailbox: ?*Mailbox,
    cfg: AttachConfig,
) !void {
    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    // Password authentication loop: use connectWithAuth so passwords
    // come from the GUI overlay (or any other on-state consumer)
    // instead of stdin.
    var for_jump: bool = false;
    while (true) {
        const result = entry.ctx.connectWithAuth(stderr, entry.auth_state.password, for_jump) catch |err| {
            const reason: protocol.ConnectionState.FailReason = switch (err) {
                error.SshConnectFailed, error.SshHandshakeFailed => .timeout,
                error.SshAuthFailed => .auth_failed,
                else => .unknown,
            };
            pushAttachState(mailbox, entry, .{ .failed = reason });
            return err;
        };

        // Zero and free the previous password after use
        if (entry.auth_state.password) |pw| {
            @memset(@constCast(pw), 0);
            entry.alloc.free(pw);
            entry.auth_state.password = null;
        }

        switch (result) {
            .success => break,
            .password_required_jump, .password_required_target => {
                for_jump = (result == .password_required_jump);

                // Surface a password prompt to all listeners + the
                // calling mailbox.
                var prompt: protocol.ConnectionState.PasswordPrompt = .{
                    .is_jump = for_jump,
                    .auth_state = @ptrCast(&entry.auth_state),
                };
                const host_name = if (for_jump) (entry.ctx.jump orelse "jump host") else entry.ctx.ssh_target;
                prompt.setHost(host_name);
                pushAttachState(mailbox, entry, .{ .password_required = prompt });

                // Wait for someone (GUI overlay, C API embedder via
                // submit_password) to provide a password OR cancel.
                entry.auth_state.mutex.lock();
                while (entry.auth_state.password == null and !entry.auth_state.cancelled) {
                    entry.auth_state.cond.wait(&entry.auth_state.mutex);
                }

                if (entry.auth_state.cancelled) {
                    entry.auth_state.mutex.unlock();
                    pushAttachState(mailbox, entry, .{ .failed = .auth_failed });
                    return error.RemoteAuthRequired;
                }
                entry.auth_state.mutex.unlock();
                // Loop back to retry connectWithAuth with the new password.
            },
        }
    }

    const provision = ensureRemoteGhostty(alloc, &entry.ctx, stderr, mailbox) catch |err| {
        pushAttachState(mailbox, entry, .{ .failed = .helper_failed });
        return err;
    };
    const remote_bin_path = provision.path;

    // Only force-restart the daemon if the binary was re-provisioned
    // (version mismatch). Otherwise reuse the running daemon to
    // preserve existing sessions.
    ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, provision.provisioned) catch |err| {
        alloc.free(remote_bin_path);
        pushAttachState(mailbox, entry, .{ .failed = .helper_failed });
        return err;
    };

    entry.surfaces_mutex.lock();
    if (entry.remote_bin_path.len > 0) manager.alloc.free(entry.remote_bin_path);
    entry.remote_bin_path = remote_bin_path;
    entry.surfaces_mutex.unlock();

    // Copy remote_bin_path for use below so we don't read the field
    // after releasing the lock (the reconnect thread could modify it).
    const remote_bin_path_local = alloc.dupe(u8, remote_bin_path) catch return error.OutOfMemory;
    defer alloc.free(remote_bin_path_local);

    const channel = openMultiplexChannel(
        alloc,
        &entry.ctx,
        remote_bin_path_local,
    ) catch |err| {
        pushAttachState(mailbox, entry, .{ .failed = .unknown });
        return err;
    };

    // Switch to non-blocking for the SSH thread
    var sess = &entry.ctx.session.?;
    sess.setBlocking(0);

    manager.mutex.lock();
    entry.channel = channel;
    manager.mutex.unlock();

    // Stamp reconnect config + scrollback limit so the per-Entry SSH
    // thread (and any reconnect attempt) honors the caller's policy.
    entry.max_reconnect_attempts = cfg.max_reconnect_attempts;
    entry.reconnect_backoff = cfg.reconnect_backoff;
    entry.reconnect_interval_ms = cfg.reconnect_interval_ms;
    entry.scrollback_limit = cfg.scrollback_limit;

    // Pipes used by the SSH thread for quit / write-wakeup /
    // reconnect-request IPC.
    entry.quit_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.quit_pipe[0]);
        posix.close(entry.quit_pipe[1]);
    }
    entry.write_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.write_pipe[0]);
        posix.close(entry.write_pipe[1]);
    }
    entry.reconnect_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.reconnect_pipe[0]);
        posix.close(entry.reconnect_pipe[1]);
    }

    // Spawn the dedicated SSH I/O thread.
    entry.ssh_thread = try std.Thread.spawn(.{}, SshConnectionManager.sshThreadMain, .{entry});
    entry.ssh_thread.?.setName("ssh-io") catch {};
}

/// Push a state through BOTH the per-surface mailbox (if non-null)
/// AND the Entry's broadcast fan-out (which reaches every other
/// surface registered on the Entry + every libghostty C API
/// listener). During first-surface setup the Entry has zero
/// registered surfaces, so `broadcastConnectionState` does NOT
/// duplicate the `mailbox` push to the caller's surface; the
/// listener-side fan-out is the only consumer that observes the
/// transition twice would be problematic for, and listeners only
/// see this state via the broadcast path (not the mailbox).
fn pushAttachState(
    mailbox: ?*Mailbox,
    entry: *SshConnectionManager.Entry,
    state: protocol.ConnectionState,
) void {
    pushConnectionState(mailbox, state);
    SshConnectionManager.broadcastConnectionState(entry, state);
}

// -- Internal --

/// Upload a local binary to the remote host via SCP.
/// `local_binary_path` is the path to the binary on the local machine.
/// `remote_dest_path` is the full path on the remote where it will be installed.
fn uploadGhostty(
    alloc: Allocator,
    sess: *ssh.SshSession,
    remote_dest_path: []const u8,
    local_binary_path: []const u8,
    remote_home: []const u8,
    remote_os: []const u8,
    stderr: *std.Io.Writer,
    mailbox: ?*Mailbox,
    source: protocol.ConnectionState.ProvisionSource,
) !void {
    const install_dir = try shared.remoteInstallDir(alloc, remote_home, remote_os);
    defer alloc.free(install_dir);

    try ensureRemoteDir(alloc, sess, install_dir);

    // Upload via SCP to a temp file, then move into place to avoid
    // "Text file busy" when replacing a running binary.
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{remote_dest_path});
    defer alloc.free(tmp_path);

    const file = try std.fs.openFileAbsolute(local_binary_path, .{});
    defer file.close();
    const stat = try file.stat();
    const total_bytes: u64 = stat.size;

    try stderr.print("Uploading binary ({d} KB)... ", .{total_bytes / 1024});
    try stderr.flush();

    // Notify via mailbox of upload start
    pushConnectionState(mailbox, .{ .uploading = .{ .bytes_sent = 0, .total_bytes = total_bytes, .source = source } });

    try sess.upload(local_binary_path, tmp_path, 0o700, UploadProgressCtx{ .mbox = mailbox, .total = total_bytes, .src = source });

    try stderr.writeAll("Done.\n");
    try stderr.flush();

    try moveAndVerifyRemoteBinary(alloc, sess, tmp_path, remote_dest_path);

    try stderr.writeAll("Ghostty installed successfully.\n");
    try stderr.flush();
}

const UploadProgressCtx = struct {
    mbox: ?*Mailbox,
    total: u64,
    src: protocol.ConnectionState.ProvisionSource,

    pub fn onProgress(ctx: @This(), bytes_sent: u64) void {
        pushConnectionState(ctx.mbox, .{ .uploading = .{
            .bytes_sent = bytes_sent,
            .total_bytes = ctx.total,
            .source = ctx.src,
        } });
    }
};

fn pushConnectionState(mailbox: ?*Mailbox, state: protocol.ConnectionState) void {
    if (mailbox) |m| {
        _ = m.push(.{ .connection_state = state }, .{ .forever = {} });
    }
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
        new_termios.c_lflag &= ~@as(@TypeOf(new_termios.c_lflag), c.ECHO);
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
    // Remote ghostty outputs "GHOSTTY_SESSION_PROTOCOL <version>\n"
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
