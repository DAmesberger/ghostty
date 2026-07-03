const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const protocol = @import("protocol.zig");
const ssh = @import("ssh.zig");
const SshConnectionManager = @import("../termio/SshConnectionManager.zig");

const log = std.log.scoped(.session_client);

const connection = @import("connection.zig");
const SshContext = connection.SshContext;

const shim = @import("shim.zig");
const buildShimEnvPrefix = shim.buildShimEnvPrefix;

const notify = @import("notify.zig");
const Mailbox = notify.Mailbox;
const UploadProgressCtx = notify.UploadProgressCtx;
const pushAttachState = notify.pushAttachState;
const pushProvisionState = notify.pushProvisionState;

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

fn platformMatches(local_os: []const u8, remote_os: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(local_os, remote_os)) return true;
    if (std.mem.eql(u8, local_os, "macos") and std.mem.eql(u8, remote_os, "darwin")) return true;
    return false;
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
