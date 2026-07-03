const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const protocol = @import("protocol.zig");
const ssh = @import("ssh.zig");
const control_bridge_config = @import("control_bridge_config.zig");

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

/// libssh2 transport-level keepalive interval, in seconds.
///
/// This must be comfortably below the remote sshd's idle-disconnect window.
/// A direct sshd configured with the classic `ClientAliveInterval=5` /
/// `ClientAliveCountMax=3` disconnects an unresponsive transport at 15s.
/// Emitting a transport keepalive every 5s resets that timer well before
/// the 3-miss teardown, so the SSH transport stays alive even when the
/// cmux session-protocol channel ping/pong (which only the daemon answers)
/// is not enough to satisfy sshd's ClientAlive handshake.
pub const transport_keepalive_interval_s: u32 = 5;

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
    /// Optional fd polled by tcpConnect alongside the connect socket so an
    /// in-flight connect aborts promptly on surface teardown. -1 = no cancel.
    /// Set from the Entry's cancel_pipe[0] in SshConnectionManager.acquire.
    cancel_fd: posix.fd_t = -1,

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
                    var sess = ssh.SshSession.connect(self.alloc, hop.host, hop.port, self.cancel_fd) catch |err| {
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
            // Enable transport-level keepalive so the CLIENT keeps the SSH
            // transport alive (resets sshd's ClientAlive/idle timer). The
            // session-protocol channel ping/pong only keeps the daemon alive.
            self.session.?.keepaliveConfig(true, transport_keepalive_interval_s);
            return .success;
        } else {
            // Direct connection (no jump host).
            var sess = ssh.SshSession.connect(self.alloc, target.host, target.port, self.cancel_fd) catch |err| {
                try stderr.print("Failed to connect to {s}: {}\n", .{ self.ssh_target, err });
                try stderr.flush();
                return err;
            };
            errdefer sess.close();

            if (try authenticateSession(&sess, target.user, password, password != null, stderr, self.ssh_target)) |_| {
                return .password_required_target;
            }

            self.session = sess;
            // Enable transport-level keepalive (see jump-host branch above).
            self.session.?.keepaliveConfig(true, transport_keepalive_interval_s);
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
    /// cmux execve self-handoff (Phase 2, GATED): when set, `ensureRemoteDaemon`
    /// asks the RUNNING (old) daemon to execve-replace itself with the binary at
    /// this absolute path instead of `--kill-daemon` + `--daemonize`, preserving
    /// live shells. Non-null ONLY when the client gate is on AND the running
    /// daemon answered `REEXEC 1`. Owned; freed by the caller.
    reexec_target: ?[]const u8 = null,
};

/// cmux execve self-handoff client gate (default OFF). Enabled by setting
/// `GHOSTTY_SSH_REEXEC=1` in the cmux process environment. When off, the client
/// never injects the daemon-side flag and never prefers the execve path, so the
/// daemon answers `REEXEC 0` and every update uses today's kill+restart.
fn clientReexecGateOn() bool {
    const v = posix.getenv("GHOSTTY_SSH_REEXEC") orelse return false;
    return std.mem.eql(u8, v, "1");
}

/// Probe the RUNNING daemon (via the just-uploaded `bin_path` as a CLI client)
/// for execve-handoff capability. Returns an owned dup of `bin_path` to use as
/// the reexec target iff the client gate is on AND the daemon prints exactly
/// `REEXEC 1`; otherwise null (caller falls back to kill+restart).
fn probeReexecTarget(alloc: Allocator, sess: anytype, bin_path: []const u8) ?[]const u8 {
    if (!clientReexecGateOn()) return null;
    const cmd = std.fmt.allocPrint(
        alloc,
        "{s} " ++ shared.remote_subcommand ++ " --query-reexec",
        .{bin_path},
    ) catch return null;
    defer alloc.free(cmd);
    const r = sess.exec(cmd) catch return null;
    defer alloc.free(r.stdout);
    defer alloc.free(r.stderr);
    if (r.exit_code != 0) return null;
    const trimmed = std.mem.trim(u8, r.stdout, " \t\r\n");
    if (!std.mem.eql(u8, trimmed, "REEXEC 1")) return null;
    return alloc.dupe(u8, bin_path) catch null;
}

/// Outcome of the interactive remote-daemon update-confirmation gate.
pub const UpdateDecision = enum {
    /// User chose "Update & restart": proceed with upload + force-restart.
    update,
    /// User chose "Keep current": reuse the running daemon, no kill.
    keep_current,
    /// No interactive embedder was available to answer the prompt
    /// (GTK picker / CLI / null entry). Caller picks a safe default per
    /// context (reuse for optional, disconnect for mandatory).
    no_decider,
};

/// Surface the update-confirmation gate to the embedder and BLOCK until
/// the user decides. Mirrors the password-required async gate: emit a
/// `.update_confirmation_required` state carrying a pointer to the
/// Entry's shared `update_state`, then wait on its condition variable
/// until the C-API submit (or GTK handler) records `decided`.
///
/// Returns `.no_decider` immediately when there is no `entry` (no
/// listener fan-out / no C-API submit path) so the caller falls back to
/// a safe default rather than blocking forever.
fn confirmDaemonUpdate(
    mailbox: ?*Mailbox,
    entry: ?*SshConnectionManager.Entry,
    host: []const u8,
    session_count: u32,
    is_mandatory: bool,
) UpdateDecision {
    const e = entry orelse return .no_decider;

    // Reset the gate state before publishing the prompt so a stale
    // decision from a prior gate can't satisfy this wait.
    e.update_state.mutex.lock();
    e.update_state.decided = false;
    e.update_state.approved = false;
    e.update_state.mutex.unlock();

    var conf: protocol.ConnectionState.UpdateConfirmation = .{
        .update_state = @ptrCast(&e.update_state),
        .is_mandatory = is_mandatory,
        .session_count = session_count,
    };
    conf.setHost(host);
    pushAttachState(mailbox, e, .{ .update_confirmation_required = conf });

    // Block until the embedder records a decision (C-API
    // submit_update_decision / GTK handler).
    e.update_state.mutex.lock();
    while (!e.update_state.decided) {
        e.update_state.cond.wait(&e.update_state.mutex);
    }
    const approved = e.update_state.approved;
    e.update_state.mutex.unlock();

    return if (approved) .update else .keep_current;
}

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
    /// When non-null, provisioning progress (`.downloading` / `.uploading`)
    /// is broadcast to this Entry's state listeners so the app's overlay
    /// can render the upload. Callers without an Entry (GTK picker, CLI)
    /// pass `null` and provisioning stays mailbox-only as before.
    entry: ?*SshConnectionManager.Entry,
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
        // Protocol matches. If we ALSO have a local daemon adjacent
        // to this exe (development build), require a content-hash
        // match too. Bumps that don't bump `protocol_version` (e.g.
        // the daemon isSocketOurs inode fix, keepalive default
        // tweaks, debugging tweaks) leave protocol_version steady
        // but DO change the binary, and a stale remote silently
        // breaks the user's session. The check is best-effort:
        // skipped silently if `sha256sum` is unavailable on the
        // remote or the local binary can't be hashed.
        const hash_decision = remoteBinaryMatchesLocalHash(alloc, sess, daemon_path, remote_os, remote_arch) catch null;
        if (hash_decision == null or hash_decision == true) {
            return .{ .path = try alloc.dupe(u8, daemon_path), .provisioned = false };
        }
        log.info(
            "remote binary at {s} content-hash differs from local — update needed",
            .{daemon_path},
        );

        // Content-hash mismatch but protocol is COMPATIBLE. If a daemon
        // is already running with live sessions, uploading + force-
        // restarting would kill them. Gate behind a user confirmation
        // (mirrors the password-required async gate). If the user keeps
        // the current daemon, reuse it (provisioned=false ⇒ no kill);
        // the running daemon speaks a compatible protocol so the session
        // survives.
        if (probeRunningDaemonSessionCount(alloc, sess, daemon_path)) |session_count| {
            const decision = confirmDaemonUpdate(
                mailbox,
                entry,
                ctx.ssh_target,
                session_count,
                false, // not mandatory — protocol is compatible
            );
            switch (decision) {
                .keep_current => {
                    log.info("user declined daemon update — reusing running daemon at {s}", .{daemon_path});
                    return .{ .path = try alloc.dupe(u8, daemon_path), .provisioned = false };
                },
                .update => {
                    log.info("user approved daemon update — re-uploading {s}", .{daemon_path});
                    // Fall through to the upload path below (provisioned=true).
                },
                .no_decider => {
                    // No interactive embedder (GTK picker / CLI). Preserve
                    // live sessions by default: reuse the running daemon.
                    log.info("no decider for daemon update gate — reusing running daemon at {s}", .{daemon_path});
                    return .{ .path = try alloc.dupe(u8, daemon_path), .provisioned = false };
                },
            }
        }
        // No daemon running (or zero sessions) — upload silently.
        // Fall through to the upload path below.
    } else {
        // Either no deployed binary, or one whose protocol version is
        // INCOMPATIBLE. If a daemon is running from that stale binary it
        // speaks an unusable protocol, so the update is MANDATORY. We
        // still warn (declining = disconnect, since there's no
        // compatible daemon to reuse). A fresh remote with no running
        // daemon uploads silently as before.
        if (probeRunningDaemonSessionCount(alloc, sess, daemon_path)) |session_count| {
            const decision = confirmDaemonUpdate(
                mailbox,
                entry,
                ctx.ssh_target,
                session_count,
                true, // mandatory — incompatible protocol
            );
            switch (decision) {
                .update => {
                    log.info("user approved mandatory daemon update", .{});
                    // Fall through to the upload path below.
                },
                .keep_current, .no_decider => {
                    // Mandatory update declined (or no decider): the
                    // running daemon is protocol-incompatible and cannot
                    // be reused, so abort the connection rather than
                    // silently force-restarting.
                    log.info("mandatory daemon update declined — disconnecting", .{});
                    return error.RemoteUpdateDeclined;
                },
            }
        }
    }

    // Need to provision — install as ghostty-daemon.
    const dest = try alloc.dupe(u8, daemon_path);
    errdefer alloc.free(dest);

    // 2. Try uploading a locally-available daemon binary for the
    //    remote target. `findLocalDaemon` resolves to a target-tagged
    //    or generic bundled binary (or an env-var override) — see its
    //    docstring for the resolution order. We no longer gate on
    //    `arch_matches`: if the bundle contains a binary specifically
    //    named `ghostty-daemon-<os>-<arch>` for the remote, the cmux
    //    host's own arch is irrelevant (cross-platform deploy is the
    //    whole point of the tagged slot). If it returns only the
    //    legacy untagged `ghostty-daemon`, uploadGhostty's
    //    architecture-verification step will catch a mismatch and we
    //    fall through to the GitHub download path.
    if (try findLocalDaemon(alloc, remote_os, remote_arch)) |local_daemon| {
        defer alloc.free(local_daemon);

        if (uploadGhostty(alloc, sess, dest, local_daemon, remote_home, remote_os, stderr, mailbox, .local_daemon, entry)) {
            // cmux execve self-handoff: while the OLD daemon is still running,
            // probe whether it can hand off in-place to the just-uploaded binary.
            return .{ .path = dest, .provisioned = true, .reexec_target = probeReexecTarget(alloc, sess, dest) };
        } else |_| {
            // Local daemon upload failed (e.g., file not found, or
            // arch mismatch on the legacy untagged path) — fall
            // through to download.
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

    try downloadAndInstallDaemon(alloc, sess, dest, remote_home, remote_os, norm_os, norm_arch, stderr, mailbox, entry);
    // cmux execve self-handoff: probe the running daemon for in-place handoff.
    return .{ .path = dest, .provisioned = true, .reexec_target = probeReexecTarget(alloc, sess, dest) };
}

/// Find a bundled-or-built daemon binary suitable for the given
/// remote target.
///
/// Resolution order (returns the first that actually exists on disk):
///
///   1. `<exe-dir>/../Resources/ghostty-daemon-<os>-<arch>` — a
///      target-tagged binary bundled into the app at build time
///      (e.g. `ghostty-daemon-linux-x86_64`). This is the right
///      slot for cross-platform deploy where the cmux host arch
///      differs from the remote arch.
///   2. `<exe-dir>/../Resources/ghostty-daemon` — an untagged
///      bundled binary. Used when the bundle ships a single daemon
///      built for the same target as the host (the common
///      release-app shape).
///   3. `<exe-dir>/ghostty-daemon` — adjacent to the running exe,
///      same shape as the legacy bundling. Preserved for backwards
///      compatibility.
///   4. `GHOSTTY_DAEMON_PATH` env var — ultimate override for
///      pointing at an arbitrary daemon binary on the host
///      filesystem (e.g. a freshly-built `zig-out/bin/ghostty-daemon`
///      during dev iteration). Lowest priority so a bundled binary
///      always wins; the env var is the explicit "I know what I'm
///      doing" escape hatch.
///
/// Returns null if none of those paths point at a regular file.
/// Caller owns returned memory.
fn findLocalDaemon(
    alloc: Allocator,
    remote_os: []const u8,
    remote_arch: []const u8,
) !?[]const u8 {
    const exe_path = std.fs.selfExePathAlloc(alloc) catch null;
    defer if (exe_path) |p| alloc.free(p);

    const exe_dir = if (exe_path) |p| std.fs.path.dirname(p) else null;
    const resources_dir = if (exe_dir) |d|
        try std.fs.path.join(alloc, &.{ d, "..", "Resources" })
    else
        null;
    defer if (resources_dir) |r| alloc.free(r);

    const norm_os = shared.normalizeOs(remote_os);
    const norm_arch = shared.normalizeArch(remote_arch);
    const tagged_name = try std.fmt.allocPrint(
        alloc,
        "ghostty-daemon-{s}-{s}",
        .{ norm_os, norm_arch },
    );
    defer alloc.free(tagged_name);

    // 1. Resources/ghostty-daemon-<os>-<arch>
    if (resources_dir) |r| {
        const tagged = try std.fs.path.join(alloc, &.{ r, tagged_name });
        if (fileExists(tagged)) return tagged;
        alloc.free(tagged);
    }
    // 2. Resources/ghostty-daemon
    if (resources_dir) |r| {
        const generic = try std.fs.path.join(alloc, &.{ r, "ghostty-daemon" });
        if (fileExists(generic)) return generic;
        alloc.free(generic);
    }
    // 3. <exe-dir>/ghostty-daemon
    if (exe_dir) |d| {
        const adjacent = try std.fs.path.join(alloc, &.{ d, "ghostty-daemon" });
        if (fileExists(adjacent)) return adjacent;
        alloc.free(adjacent);
    }
    // 4. Env var escape hatch
    if (std.posix.getenv("GHOSTTY_DAEMON_PATH")) |env_path| {
        if (env_path.len > 0 and fileExists(env_path)) {
            return try alloc.dupe(u8, env_path);
        }
    }

    return null;
}

/// True if `path` points at an existing regular file. Used to gate
/// the candidate slots in `findLocalDaemon` so callers see "this
/// binary really exists" semantics.
fn fileExists(path: []const u8) bool {
    const f = std.fs.openFileAbsolute(path, .{}) catch return false;
    f.close();
    return true;
}

/// Compare the SHA256 of `remote_path` on the remote against the local
/// daemon binary adjacent to this exe (`findLocalDaemon`).
///
/// Returns:
///   * `true`  — both hashes computed and they match
///   * `false` — both hashes computed and they differ (remote is stale)
///   * `null`  — couldn't compute one side (no local daemon, no
///               `sha256sum` on remote, exec error, etc). Caller treats
///               null as "unknown" and skips the re-upload trigger.
///
/// We use the remote's `sha256sum` rather than asking the daemon to
/// hash itself: the daemon's binary may be the wrong version or even
/// crash on startup, and we want a check that works in those cases too.
fn remoteBinaryMatchesLocalHash(
    alloc: Allocator,
    sess: *ssh.SshSession,
    remote_path: []const u8,
    remote_os: []const u8,
    remote_arch: []const u8,
) !?bool {
    // 1. Need a local daemon for the target to compare against.
    const local_path = (try findLocalDaemon(alloc, remote_os, remote_arch)) orelse return null;
    defer alloc.free(local_path);

    // 2. Hash the local binary.
    const local_hex = computeLocalSha256(alloc, local_path) catch return null;
    defer alloc.free(local_hex);

    // 3. Get the remote hash. We try `sha256sum` (GNU coreutils — Linux
    //    default) and `shasum -a 256` (macOS / BSD). If neither is on
    //    PATH, the check returns null (unknown).
    var remote_hex_buf: [64]u8 = undefined;
    const remote_hex = blk: {
        const cmd_a = try std.fmt.allocPrint(
            alloc,
            "sha256sum '{s}' 2>/dev/null | head -c 64",
            .{remote_path},
        );
        defer alloc.free(cmd_a);
        if (sess.exec(cmd_a)) |result| {
            defer alloc.free(result.stdout);
            defer alloc.free(result.stderr);
            if (result.exit_code == 0 and result.stdout.len >= 64) {
                @memcpy(remote_hex_buf[0..], result.stdout[0..64]);
                break :blk remote_hex_buf[0..];
            }
        } else |_| {}

        const cmd_b = try std.fmt.allocPrint(
            alloc,
            "shasum -a 256 '{s}' 2>/dev/null | head -c 64",
            .{remote_path},
        );
        defer alloc.free(cmd_b);
        if (sess.exec(cmd_b)) |result| {
            defer alloc.free(result.stdout);
            defer alloc.free(result.stderr);
            if (result.exit_code == 0 and result.stdout.len >= 64) {
                @memcpy(remote_hex_buf[0..], result.stdout[0..64]);
                break :blk remote_hex_buf[0..];
            }
        } else |_| {}

        return null; // No usable hash tool on remote.
    };

    return std.ascii.eqlIgnoreCase(local_hex, remote_hex);
}

/// Compute the SHA256 of a local file and return the hex-encoded
/// digest. Caller owns the returned slice.
fn computeLocalSha256(alloc: Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    const hex = try alloc.alloc(u8, 64);
    const charset = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        hex[i * 2] = charset[(b >> 4) & 0x0f];
        hex[i * 2 + 1] = charset[b & 0x0f];
    }
    return hex;
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

/// Best-effort probe of a RUNNING remote daemon: returns the number of
/// live sessions currently registered with the daemon, or `null` if the
/// daemon is not running / unreachable.
///
/// Uses `<binary> +ssh-session --list`, which connects to the daemon's
/// unix socket and prints one line per session (see `daemon.listSessions`
/// — each session is `gid|label|N surfaces (M alive)|created|status`).
/// If the daemon isn't running, the socket connect fails and `--list`
/// prints nothing, so an empty result is treated as "no running daemon"
/// (return null) and the caller proceeds without prompting.
///
/// This deliberately gates the session-killing update prompt: a hash
/// mismatch on a remote with NO running daemon is uploaded silently as
/// before (no sessions to lose); a mismatch on a remote WITH live
/// sessions surfaces the confirmation gate.
fn probeRunningDaemonSessionCount(
    alloc: Allocator,
    sess: *ssh.SshSession,
    binary_path: []const u8,
) ?u32 {
    const list_cmd = std.fmt.allocPrint(
        alloc,
        "{s} " ++ shared.remote_subcommand ++ " --list",
        .{binary_path},
    ) catch return null;
    defer alloc.free(list_cmd);

    const result = sess.exec(list_cmd) catch return null;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.exit_code != 0) return null;

    // Count non-empty lines. Empty output ⇒ daemon not running (the
    // socket connect failed and listSessions returned early) OR the
    // daemon is up with zero sessions; either way there is nothing to
    // protect, so treat both as "no running daemon" (null).
    var count: u32 = 0;
    var it = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        count += 1;
    }
    if (count == 0) return null;
    return count;
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
    entry: ?*SshConnectionManager.Entry,
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

    pushProvisionState(mailbox, entry, .downloading);

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

        try downloadAndUploadLocal(alloc, sess, remote_dest_path, tmp_path, url, stderr, mailbox, entry);
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
    entry: ?*SshConnectionManager.Entry,
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

    var last_pct: u8 = 0;
    pushProvisionState(mailbox, entry, .{ .uploading = .{ .bytes_sent = 0, .total_bytes = total_bytes, .source = .github } });
    try sess.upload(local_tmp, remote_tmp_path, 0o700, UploadProgressCtx{ .mbox = mailbox, .total = total_bytes, .src = .github, .entry = entry, .last_pct = &last_pct });

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

/// Build an inline env-var prefix for the remote daemon launch command that
/// carries an embedder-supplied control shim, sourced from THIS process's
/// environment (the embedder, e.g. cmux, sets `GHOSTTY_REMOTE_SHIM_*` before
/// opening connections). The forked remote daemon inherits these vars and
/// installs the shim on the session PATH (see `daemon.installEmbedderShim`).
/// Returns an empty string when no shim is configured, so non-embedder callers
/// (and the GTK/CLI paths) are unaffected. Caller owns the returned slice.
fn buildShimEnvPrefix(alloc: Allocator) ![]u8 {
    const name = posix.getenv(control_bridge_config.env_shim_name) orelse
        return alloc.dupe(u8, "");
    const body = posix.getenv(control_bridge_config.env_shim_body_b64) orelse
        return alloc.dupe(u8, "");
    if (name.len == 0 or body.len == 0) return alloc.dupe(u8, "");
    const mode = posix.getenv(control_bridge_config.env_shim_mode) orelse "755";

    // Values are single-quoted for the remote shell. The body is base64 (safe
    // chars only); guard the embedder-controlled name/mode against a quote that
    // would break the inline quoting (the daemon also validates the name).
    if (std.mem.indexOfScalar(u8, name, '\'') != null or
        std.mem.indexOfScalar(u8, mode, '\'') != null)
    {
        return alloc.dupe(u8, "");
    }

    return std.fmt.allocPrint(
        alloc,
        "{s}='{s}' {s}='{s}' {s}='{s}' ",
        .{
            control_bridge_config.env_shim_name,     name,
            control_bridge_config.env_shim_body_b64, body,
            control_bridge_config.env_shim_mode,     mode,
        },
    );
}

/// Launch the remote session daemon via ghostty's --daemonize flag.
/// If `force_restart` is true, kills any existing daemon first (used
/// when the binary was re-provisioned with a new protocol version).
///
/// cmux execve self-handoff (Phase 2, GATED): when `reexec_target` is non-null
/// (client gate on AND running daemon answered `REEXEC 1`), first ask the
/// running daemon to execve-replace itself with that binary — preserving live
/// shells. The `--kill-daemon` step is then skipped on a successful handoff,
/// but the trailing `--daemonize` net ALWAYS runs: on a healthy handoff it is a
/// no-op (the carried listener answers `canConnect`); on a successor that
/// crashed during adoption it is the only recovery (fork fresh = today).
pub fn ensureRemoteDaemon(
    alloc: Allocator,
    ctx: *const SshContext,
    remote_bin_path: []const u8,
    force_restart: bool,
    reexec_target: ?[]const u8,
) !void {
    var sess = ctx.session orelse return error.RemoteCommandFailed;

    var reexec_ok = false;
    if (reexec_target) |newbin| {
        const reexec_cmd = try std.fmt.allocPrint(
            alloc,
            "{s} " ++ shared.remote_subcommand ++ " --reexec {s}",
            .{ remote_bin_path, newbin },
        );
        defer alloc.free(reexec_cmd);
        const r = sess.exec(reexec_cmd) catch null;
        if (r) |res| {
            defer alloc.free(res.stdout);
            defer alloc.free(res.stderr);
            // exit 0 = EOF without a preceding `.err` (handoff launched).
            reexec_ok = res.exit_code == 0;
        }
        log.info("reexec handoff requested newbin={s} ok={}", .{ newbin, reexec_ok });
    }

    if (!reexec_ok and force_restart) {
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

    // Prefix the launch with any embedder control-shim env (empty when none),
    // so the forked daemon inherits + installs the shim on the session PATH.
    const shim_prefix = try buildShimEnvPrefix(alloc);
    defer alloc.free(shim_prefix);

    // When the client gate is on, birth new daemons reexec-capable so the NEXT
    // update can hand off in-place. Ungated daemons answer `REEXEC 0`.
    const reexec_prefix: []const u8 = if (clientReexecGateOn()) "GHOSTTY_SSH_REEXEC=1 " else "";

    const cmd = try std.fmt.allocPrint(
        alloc,
        "{s}{s}{s} " ++ shared.remote_subcommand ++ " --daemonize",
        .{ reexec_prefix, shim_prefix, remote_bin_path },
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

/// Open a second SSH channel dedicated to ClientMux traffic
/// (browser_proxy / port_listener / tcp_connect / tcp_accepted).
///
/// Distinct from `openMultiplexChannel` (the terminal-frame demuxer)
/// because the multiplex process drops every `.channel_*` frame on the
/// floor — its switch statement only handles `.open` / `.close` /
/// `.data_in` / etc. and falls through `else => {}` for ClientMux
/// frames. This mode (`--mux-attach`) is a pure stdio↔unix-socket
/// pump that hands every byte straight to the main daemon's
/// `ClientThread`, which already dispatches `.channel_*` frames
/// against the `channel_registry`.
///
/// Caller must have already ensured the main daemon is running
/// (`ensureRemoteDaemon` → `--daemonize`) so the unix socket exists
/// when this exec connects.
pub fn openClientMuxChannel(
    alloc: Allocator,
    ctx: *const SshContext,
    remote_bin_path: []const u8,
) !ssh.Channel {
    var sess = ctx.session orelse return error.RemoteCommandFailed;
    var channel = try sess.openChannel();
    errdefer channel.close();

    const cmd = try std.fmt.allocPrint(alloc, "{s} " ++ shared.remote_subcommand ++ " --mux-attach", .{remote_bin_path});
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
    /// Upper bound on a single reconnect sleep after backoff growth,
    /// in milliseconds. 0 means "leave the Entry default in place"
    /// (legacy 30 000 ms).
    reconnect_max_interval_ms: u32 = 0,
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
/// The pre-setup CONNECTING state is emitted by the CALLER, not by
/// this helper: the GTK path pushes it onto the mailbox at
/// `termio/Remote.zig:threadEnter` before invoking `setupConnection`,
/// and the libghostty C API path emits it synchronously inside
/// `ghostty_ssh_open` before returning the handle. The helper picks
/// up from there with UPLOADING / SETUP / PASSWORD_REQUIRED / FAILED
/// transitions as the underlying SSH flow progresses.
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

    const provision = ensureRemoteGhostty(alloc, &entry.ctx, stderr, mailbox, entry) catch |err| {
        pushAttachState(mailbox, entry, .{ .failed = .helper_failed });
        return err;
    };
    const remote_bin_path = provision.path;
    // cmux execve self-handoff: the reexec target (when present) is only needed
    // for the ensureRemoteDaemon call below; free it on every path afterward.
    defer if (provision.reexec_target) |rt| alloc.free(rt);

    // Only force-restart the daemon if the binary was re-provisioned
    // (version mismatch). Otherwise reuse the running daemon to
    // preserve existing sessions. When a reexec target is set, prefer an
    // in-place execve handoff (preserves live shells across the update).
    ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, provision.provisioned, provision.reexec_target) catch |err| {
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
    if (cfg.reconnect_max_interval_ms != 0) {
        entry.reconnect_max_interval_ms = cfg.reconnect_max_interval_ms;
    }
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
    entry: ?*SshConnectionManager.Entry,
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

    // Notify via mailbox (+ broadcast to listeners) of upload start.
    var last_pct: u8 = 0;
    pushProvisionState(mailbox, entry, .{ .uploading = .{ .bytes_sent = 0, .total_bytes = total_bytes, .source = source } });

    try sess.upload(local_binary_path, tmp_path, 0o700, UploadProgressCtx{ .mbox = mailbox, .total = total_bytes, .src = source, .entry = entry, .last_pct = &last_pct });

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
    /// When non-null, upload progress is ALSO broadcast to the Entry's
    /// state listeners (so the app's provisioning overlay — which observes
    /// the listener path, not the per-surface mailbox — can render it).
    entry: ?*SshConnectionManager.Entry = null,
    /// Throttle pointer for the broadcast: holds the last whole-percent
    /// value broadcast. A multi-MB upload fires `onProgress` per chunk
    /// (hundreds/thousands of times); broadcasting each one would re-render
    /// the overlay on every chunk. We broadcast only on a whole-percent
    /// change, capping the listener traffic at ~100 updates per upload.
    last_pct: ?*u8 = null,

    pub fn onProgress(ctx: @This(), bytes_sent: u64) void {
        const state: protocol.ConnectionState = .{ .uploading = .{
            .bytes_sent = bytes_sent,
            .total_bytes = ctx.total,
            .source = ctx.src,
        } };
        pushConnectionState(ctx.mbox, state);
        if (ctx.entry) |e| {
            const pct: u8 = if (ctx.total == 0)
                100
            else
                @intCast(@min(@as(u64, 100), bytes_sent * 100 / ctx.total));
            if (ctx.last_pct) |lp| {
                if (pct == lp.*) return;
                lp.* = pct;
            }
            SshConnectionManager.broadcastConnectionState(e, state);
        }
    }
};

fn pushConnectionState(mailbox: ?*Mailbox, state: protocol.ConnectionState) void {
    if (mailbox) |m| {
        _ = m.push(.{ .connection_state = state }, .{ .forever = {} });
    }
}

/// Push a provisioning state (`.downloading` / `.uploading`) to the
/// per-surface mailbox AND, when an Entry is available, broadcast it to
/// the Entry's state listeners. The app's provisioning overlay observes
/// the listener path (see `pushAttachState`'s docstring), so without the
/// broadcast a daemon upload/download is invisible to the overlay — the
/// workspace just shows a silent `connecting` hang for the upload's
/// duration. Mirrors `pushAttachState` but kept separate so callers that
/// have no Entry (the GTK picker / CLI provisioning paths) pass `null`.
fn pushProvisionState(
    mailbox: ?*Mailbox,
    entry: ?*SshConnectionManager.Entry,
    state: protocol.ConnectionState,
) void {
    pushConnectionState(mailbox, state);
    if (entry) |e| SshConnectionManager.broadcastConnectionState(e, state);
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
