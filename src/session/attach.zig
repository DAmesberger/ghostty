const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const protocol = @import("protocol.zig");
const ssh = @import("ssh.zig");
const SshConnectionManager = @import("../termio/SshConnectionManager.zig");

const connection = @import("connection.zig");
const SshContext = connection.SshContext;

const notify = @import("notify.zig");
const Mailbox = notify.Mailbox;
const pushAttachState = notify.pushAttachState;

const provision_mod = @import("provision.zig");
const ensureRemoteGhostty = provision_mod.ensureRemoteGhostty;
const ensureRemoteDaemon = provision_mod.ensureRemoteDaemon;

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
