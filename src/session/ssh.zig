const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const ssh2 = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("libssh2.h");
});

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("arpa/inet.h");
    @cInclude("fcntl.h");
    @cInclude("netdb.h");
    @cInclude("netinet/in.h");
    @cInclude("poll.h");
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
});

const shared = @import("shared.zig");

const log = std.log.scoped(.session_ssh);

/// POSIX EAGAIN as a negative value — this is what libssh2's transport layer
/// expects custom send/recv callbacks to return for "try again".
/// (-11 on Linux, -35 on macOS)
const posix_EAGAIN: isize = -@as(isize, @intFromEnum(std.posix.E.AGAIN));

pub const Error = error{
    SshInitFailed,
    SshHandshakeFailed,
    SshAuthFailed,
    SshChannelOpenFailed,
    SshChannelExecFailed,
    SshScpSendFailed,
    SshConnectFailed,
    SshDisconnected,
    SshAgentFailed,
    SshHostKeyMismatch,
};

pub const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: c_int,
};

/// High-level SSH session wrapping libssh2.
pub const SshSession = struct {
    alloc: Allocator,
    session: *ssh2.LIBSSH2_SESSION,
    sock: posix.fd_t,
    /// For jump host connections, this holds the tunnel channel and
    /// the intermediate session/socket.
    jump: ?JumpState = null,

    const JumpState = struct {
        jump_session: *ssh2.LIBSSH2_SESSION,
        jump_sock: posix.fd_t,
        tunnel_channel: *ssh2.LIBSSH2_CHANNEL,
    };

    /// Connect to a host via TCP and perform SSH handshake.
    /// Times out after 30 seconds to avoid hanging indefinitely.
    pub fn connect(alloc: Allocator, host: []const u8, port: u16) !SshSession {
        const sock = try tcpConnect(host, port);
        errdefer posix.close(sock);

        const session = sessionInit() orelse return error.SshInitFailed;
        errdefer _ = ssh2.libssh2_session_free(session);

        try performHandshake(session, sock, session, sock);

        try verifyHostKey(alloc, session, host, port);

        return .{
            .alloc = alloc,
            .session = session,
            .sock = sock,
        };
    }

    /// Open a direct-tcpip tunnel through this (already authenticated)
    /// session to a target host, then perform a second SSH handshake
    /// through the tunnel. The caller must authenticate the returned
    /// session separately.
    pub fn tunnel(
        self: *SshSession,
        target_host: []const u8,
        target_port: u16,
    ) !SshSession {
        const target_host_z = try self.alloc.dupeZ(u8, target_host);
        defer self.alloc.free(target_host_z);

        const tunnel_ch = channelDirectTcpip(
            self.session,
            target_host_z.ptr,
            @intCast(target_port),
        ) orelse return error.SshChannelOpenFailed;

        // Set jump session to non-blocking so the custom transport
        // callbacks can return EAGAIN instead of blocking.
        ssh2.libssh2_session_set_blocking(self.session, 0);

        // Allocate tunnel state on the heap so it outlives this function.
        // The inner session's custom callbacks reference it via abstract ptr.
        const state = try self.alloc.create(TunnelState);
        state.* = .{ .channel = tunnel_ch, .jump_session = self.session };

        const inner = sessionInit() orelse return error.SshInitFailed;
        errdefer _ = ssh2.libssh2_session_free(inner);

        // Wire custom send/recv callbacks through the tunnel channel.
        // This replaces the socketpair+bridge approach — no extra fds,
        // no background thread, no risk of fd leaks.
        const abstract = ssh2.libssh2_session_abstract(inner);
        abstract.* = @ptrCast(state);
        _ = ssh2.libssh2_session_callback_set(inner, ssh2.LIBSSH2_CALLBACK_RECV, @constCast(@ptrCast(&tunnelRecv)));
        _ = ssh2.libssh2_session_callback_set(inner, ssh2.LIBSSH2_CALLBACK_SEND, @constCast(@ptrCast(&tunnelSend)));

        // Use a dummy fd — custom callbacks handle all I/O. We can't
        // reuse the jump session's socket because libssh2 sets socket
        // options on it which would interfere with the jump session.
        const dummy_fd = c.open("/dev/null", c.O_RDWR);
        if (dummy_fd < 0) return error.SshConnectFailed;

        performHandshake(inner, dummy_fd, self.session, self.sock) catch {
            _ = c.close(dummy_fd);
            return error.SshHandshakeFailed;
        };

        try verifyHostKey(self.alloc, inner, target_host, target_port);

        return .{
            .alloc = self.alloc,
            .session = inner,
            .sock = dummy_fd,
            .jump = .{
                .jump_session = self.session,
                .jump_sock = self.sock,
                .tunnel_channel = tunnel_ch,
            },
        };
    }

    /// Authenticate using the SSH agent.
    pub fn authAgent(self: *SshSession, username: []const u8) !void {
        const user_z = try self.alloc.dupeZ(u8, username);
        defer self.alloc.free(user_z);

        const agent = ssh2.libssh2_agent_init(self.session) orelse return error.SshAgentFailed;
        defer ssh2.libssh2_agent_free(agent);

        if (ssh2.libssh2_agent_connect(agent) != 0) {
            logSshError(self.session, "[auth] agent connect error: ");
            return error.SshAgentFailed;
        }
        defer _ = ssh2.libssh2_agent_disconnect(agent);

        if (ssh2.libssh2_agent_list_identities(agent) != 0) return error.SshAgentFailed;

        var prev: ?*ssh2.struct_libssh2_agent_publickey = null;
        var identity: ?*ssh2.struct_libssh2_agent_publickey = null;
        while (ssh2.libssh2_agent_get_identity(agent, &identity, prev) == 0) {
            if (identity == null) break;
            if (ssh2.libssh2_agent_userauth(agent, user_z.ptr, identity) == 0) {
                return; // Success
            }
            prev = identity;
        }
        return error.SshAuthFailed;
    }

    /// Authenticate with a password.
    pub fn authPassword(self: *SshSession, username: []const u8, password: []const u8) !void {
        const user_z = try self.alloc.dupeZ(u8, username);
        defer self.alloc.free(user_z);
        const pass_z = try self.alloc.dupeZ(u8, password);
        defer shared.secureZeroAndFree(self.alloc, pass_z);

        if (userauthPassword(
            self.session,
            user_z.ptr,
            @intCast(username.len),
            pass_z.ptr,
            @intCast(password.len),
        ) != 0) {
            return error.SshAuthFailed;
        }
    }

    /// Authenticate with a public/private key pair.
    pub fn authPublicKey(
        self: *SshSession,
        username: []const u8,
        pubkey_path: ?[]const u8,
        privkey_path: []const u8,
        passphrase: ?[]const u8,
    ) !void {
        const user_z = try self.alloc.dupeZ(u8, username);
        defer self.alloc.free(user_z);
        const priv_z = try self.alloc.dupeZ(u8, privkey_path);
        defer self.alloc.free(priv_z);

        var pub_z: ?[:0]const u8 = null;
        defer if (pub_z) |p| self.alloc.free(p);
        if (pubkey_path) |p| pub_z = try self.alloc.dupeZ(u8, p);

        var pass_z: ?[:0]const u8 = null;
        defer if (pass_z) |p| shared.secureZeroAndFree(self.alloc, p);
        if (passphrase) |p| pass_z = try self.alloc.dupeZ(u8, p);

        const rc = ssh2.libssh2_userauth_publickey_fromfile(
            self.session,
            user_z.ptr,
            if (pub_z) |p| p.ptr else null,
            priv_z.ptr,
            if (pass_z) |p| p.ptr else null,
        );
        if (rc != 0) {
            logSshError(self.session, "[auth] pubkey error: ");
            return error.SshAuthFailed;
        }
    }

    /// Try authentication methods in order: agent, then common key files.
    /// Returns an error only if all methods fail.
    pub fn authAuto(self: *SshSession, username: []const u8) !void {
        const dbg = std.fs.File.stderr();
        // Try SSH agent first
        if (self.authAgent(username)) {
            dbg.writeAll("[auth] agent OK\n") catch {};
            return;
        } else |_| {
            dbg.writeAll("[auth] agent failed\n") catch {};
        }

        // Try common private key locations
        const home = posix.getenv("HOME") orelse return error.SshAuthFailed;
        const key_names = [_][]const u8{
            "id_ed25519",
            "id_ecdsa",
            "id_rsa",
            "id_ecdsa_sk",
            "id_ed25519_sk",
        };

        for (&key_names) |name| {
            const priv_path = std.fs.path.join(self.alloc, &.{ home, ".ssh", name }) catch continue;
            defer self.alloc.free(priv_path);

            // Check if the key file exists
            std.fs.accessAbsolute(priv_path, .{}) catch continue;

            // Also try with the .pub companion
            const pub_file = std.fmt.allocPrint(self.alloc, "{s}.pub", .{priv_path}) catch continue;
            defer self.alloc.free(pub_file);
            const has_pub = if (std.fs.accessAbsolute(pub_file, .{})) true else |_| false;

            dbg.writeAll("[auth] trying key ") catch {};
            dbg.writeAll(priv_path) catch {};
            dbg.writeAll(if (has_pub) " (with .pub)\n" else " (no .pub)\n") catch {};

            if (self.authPublicKey(
                username,
                if (has_pub) pub_file else null,
                priv_path,
                null,
            )) {
                dbg.writeAll("[auth] key OK\n") catch {};
                return;
            } else |_| {
                dbg.writeAll("[auth] key failed\n") catch {};
            }
        }

        return error.SshAuthFailed;
    }

    /// Execute a command and capture its output.
    /// Uses non-blocking reads to drain stdout and stderr simultaneously,
    /// avoiding deadlocks when both streams have data (especially through
    /// tunneled connections).
    pub fn exec(self: *SshSession, command: []const u8) !ExecResult {
        var channel = try self.openChannel();
        defer channel.close();

        try channel.exec(command);

        // Switch to non-blocking so we can read stdout and stderr
        // in the same loop without deadlocking.
        const was_blocking = ssh2.libssh2_session_get_blocking(self.session);
        ssh2.libssh2_session_set_blocking(self.session, 0);

        var stdout_buf = std.ArrayList(u8).empty;
        defer stdout_buf.deinit(self.alloc);
        var stderr_buf = std.ArrayList(u8).empty;
        defer stderr_buf.deinit(self.alloc);

        var buf: [4096]u8 = undefined;

        while (true) {
            var did_work = false;

            // Read stdout (non-blocking)
            const out_rc = channelRead(channel.inner, &buf, buf.len);
            if (out_rc > 0) {
                try stdout_buf.appendSlice(self.alloc, buf[0..@intCast(out_rc)]);
                did_work = true;
            } else if (out_rc < 0 and out_rc != ssh2.LIBSSH2_ERROR_EAGAIN) {
                break;
            }

            // Read stderr (non-blocking)
            const err_rc = channelReadStderr(channel.inner, &buf, buf.len);
            if (err_rc > 0) {
                try stderr_buf.appendSlice(self.alloc, buf[0..@intCast(err_rc)]);
                did_work = true;
            } else if (err_rc < 0 and err_rc != ssh2.LIBSSH2_ERROR_EAGAIN) {
                break;
            }

            if (ssh2.libssh2_channel_eof(channel.inner) != 0) break;

            if (!did_work) waitsocket(self.session, self.getPollSocket());
        }

        // Restore original blocking mode
        ssh2.libssh2_session_set_blocking(self.session, was_blocking);

        const exit_code = ssh2.libssh2_channel_get_exit_status(channel.inner);

        return .{
            .stdout = try stdout_buf.toOwnedSlice(self.alloc),
            .stderr = try stderr_buf.toOwnedSlice(self.alloc),
            .exit_code = exit_code,
        };
    }

    /// Upload a local file to the remote host via SCP.
    /// Uses non-blocking mode with proper polling so it works through
    /// tunneled connections without busy-spinning.
    pub fn upload(
        self: *SshSession,
        local_path: []const u8,
        remote_path: []const u8,
        mode: u32,
        progress_ctx: anytype,
    ) !void {
        const file = try std.fs.openFileAbsolute(local_path, .{});
        defer file.close();

        const stat = try file.stat();
        const file_size: usize = @intCast(stat.size);

        const remote_z = try self.alloc.dupeZ(u8, remote_path);
        defer self.alloc.free(remote_z);

        const was_blocking = ssh2.libssh2_session_get_blocking(self.session);
        ssh2.libssh2_session_set_blocking(self.session, 0);

        // Open SCP channel (may return EAGAIN through tunnel)
        const scp_channel = while (true) {
            const ch = ssh2.libssh2_scp_send64(
                self.session,
                remote_z.ptr,
                @intCast(mode),
                @intCast(file_size),
                0,
                0,
            );
            if (ch) |channel| break channel;
            const err = ssh2.libssh2_session_last_errno(self.session);
            if (err == ssh2.LIBSSH2_ERROR_EAGAIN) {
                waitsocket(self.session, self.getPollSocket());
                continue;
            }
            ssh2.libssh2_session_set_blocking(self.session, was_blocking);
            return error.SshScpSendFailed;
        };
        defer _ = ssh2.libssh2_channel_free(scp_channel);

        var remaining: usize = file_size;
        var total_written: usize = 0;
        var buf: [64 * 1024]u8 = undefined;
        while (remaining > 0) {
            const to_read = @min(remaining, buf.len);
            const n = try file.read(buf[0..to_read]);
            if (n == 0) break;

            var written: usize = 0;
            while (written < n) {
                const rc = channelWrite(scp_channel, buf[written..n].ptr, n - written);
                if (rc == ssh2.LIBSSH2_ERROR_EAGAIN or rc == 0) {
                    waitsocket(self.session, self.getPollSocket());
                    continue;
                }
                if (rc < 0) {
                    ssh2.libssh2_session_set_blocking(self.session, was_blocking);
                    return error.SshDisconnected;
                }
                written += @intCast(rc);
                total_written += @intCast(rc);
            }
            remaining -= n;

            // Report progress if callback provided
            if (comptime @typeInfo(@TypeOf(progress_ctx)) == .@"struct") {
                progress_ctx.onProgress(total_written);
            }
        }

        // Send EOF and wait for close (handle EAGAIN)
        while (ssh2.libssh2_channel_send_eof(scp_channel) == ssh2.LIBSSH2_ERROR_EAGAIN)
            waitsocket(self.session, self.getPollSocket());
        while (ssh2.libssh2_channel_wait_eof(scp_channel) == ssh2.LIBSSH2_ERROR_EAGAIN)
            waitsocket(self.session, self.getPollSocket());
        while (ssh2.libssh2_channel_wait_closed(scp_channel) == ssh2.LIBSSH2_ERROR_EAGAIN)
            waitsocket(self.session, self.getPollSocket());

        ssh2.libssh2_session_set_blocking(self.session, was_blocking);
    }

    /// Open a new SSH channel. Uses non-blocking polling internally
    /// so it works through tunneled connections.
    pub fn openChannel(self: *SshSession) !Channel {
        const was_blocking = ssh2.libssh2_session_get_blocking(self.session);
        ssh2.libssh2_session_set_blocking(self.session, 0);
        defer ssh2.libssh2_session_set_blocking(self.session, was_blocking);

        const dbg = std.fs.File.stderr();
        var iterations: u32 = 0;
        while (true) {
            iterations += 1;
            const ch = channelOpenSession(self.session);
            if (ch) |channel| {
                var b2: [80]u8 = undefined;
                const m2 = std.fmt.bufPrint(&b2, "[ssh] openChannel OK after {d} iters\n", .{iterations}) catch "";
                dbg.writeAll(m2) catch {};
                return .{ .inner = channel, .alloc = self.alloc, .ssh_session = self.session, .sock = self.getPollSocket() };
            }
            const err = ssh2.libssh2_session_last_errno(self.session);
            if (err == ssh2.LIBSSH2_ERROR_EAGAIN) {
                if (iterations == 1 or iterations % 200 == 0) {
                    const dir = ssh2.libssh2_session_block_directions(self.session);
                    var b3: [100]u8 = undefined;
                    const m3 = std.fmt.bufPrint(&b3, "[ssh] openChannel EAGAIN iter={d} dir={d}\n", .{ iterations, dir }) catch "";
                    dbg.writeAll(m3) catch {};
                }
                waitsocket(self.session, self.getPollSocket());
                continue;
            }
            var b4: [80]u8 = undefined;
            const m4 = std.fmt.bufPrint(&b4, "[ssh] openChannel FAILED err={d}\n", .{err}) catch "";
            dbg.writeAll(m4) catch {};
            return error.SshChannelOpenFailed;
        }
    }

    /// Get the underlying socket fd. For tunneled sessions this returns
    /// the dummy fd (used by libssh2 for setsockopt/fcntl). Use
    /// `getPollSocket()` for the fd you should actually poll on.
    pub fn getSocket(self: *const SshSession) posix.fd_t {
        return self.sock;
    }

    /// Get the socket fd suitable for polling. For tunneled sessions
    /// this returns the jump host's real TCP socket; for direct
    /// sessions it returns `self.sock`.
    pub fn getPollSocket(self: *const SshSession) posix.fd_t {
        if (self.jump) |j| return j.jump_sock;
        return self.sock;
    }

    /// Returns true if libssh2 needs to send data to the network.
    /// Useful for setting POLLOUT on the SSH socket after a non-blocking
    /// operation returns EAGAIN.
    pub fn needsWrite(self: *SshSession) bool {
        const sess_handle = if (self.jump) |j| j.jump_session else self.session;
        const dir = ssh2.libssh2_session_block_directions(sess_handle);
        return (dir & ssh2.LIBSSH2_SESSION_BLOCK_OUTBOUND) != 0;
    }

    /// Set session blocking mode. 0 = non-blocking, 1 = blocking.
    pub fn setBlocking(self: *SshSession, blocking: c_int) void {
        ssh2.libssh2_session_set_blocking(self.session, blocking);
    }

    /// Poll the SSH transport with a short timeout to process pending
    /// network data. For tunneled sessions this polls the jump host's
    /// real socket. Call this before non-blocking reads to ensure
    /// libssh2 has processed incoming packets.
    pub fn pollTransport(self: *SshSession, timeout_ms: c_int) void {
        // For tunneled sessions, poll the jump session's transport
        if (self.jump) |j| {
            waitsocketTimeout(j.jump_session, j.jump_sock, timeout_ms);
        } else {
            waitsocketTimeout(self.session, self.sock, timeout_ms);
        }
    }

    /// Disconnect and free all resources.
    pub fn close(self: *SshSession) void {
        // Free the TunnelState stored in the inner session's abstract pointer
        // (allocated by tunnel() for custom send/recv callbacks).
        if (self.jump != null) {
            const abstract = ssh2.libssh2_session_abstract(self.session);
            if (abstract.*) |ptr| {
                const state: *TunnelState = @ptrCast(@alignCast(ptr));
                self.alloc.destroy(state);
            }
        }

        _ = ssh2.libssh2_session_disconnect(self.session, "Normal shutdown");
        _ = ssh2.libssh2_session_free(self.session);
        posix.close(self.sock);

        if (self.jump) |j| {
            _ = ssh2.libssh2_channel_free(j.tunnel_channel);
            _ = ssh2.libssh2_session_disconnect(j.jump_session, "Normal shutdown");
            _ = ssh2.libssh2_session_free(j.jump_session);
            posix.close(j.jump_sock);
        }
    }
};

/// An SSH channel for executing commands or transferring data.
pub const Channel = struct {
    inner: *ssh2.LIBSSH2_CHANNEL,
    alloc: Allocator,
    ssh_session: *ssh2.LIBSSH2_SESSION,
    sock: posix.fd_t,

    /// Execute a command on this channel. Uses non-blocking polling
    /// internally so it works through tunneled connections.
    pub fn exec(self: *Channel, command: []const u8) !void {
        const cmd_z = try self.alloc.dupeZ(u8, command);
        defer self.alloc.free(cmd_z);

        const was_blocking = ssh2.libssh2_session_get_blocking(self.ssh_session);
        ssh2.libssh2_session_set_blocking(self.ssh_session, 0);
        defer ssh2.libssh2_session_set_blocking(self.ssh_session, was_blocking);

        while (true) {
            const rc = channelExec(self.inner, cmd_z.ptr, @intCast(command.len));
            if (rc == 0) return;
            if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) {
                waitsocket(self.ssh_session, self.sock);
                continue;
            }
            return error.SshChannelExecFailed;
        }
    }

    /// Request a PTY on this channel.
    pub fn requestPty(self: *Channel, term: []const u8, width: u32, height: u32) !void {
        const term_z = try self.alloc.dupeZ(u8, term);
        defer self.alloc.free(term_z);

        if (ssh2.libssh2_channel_request_pty_ex(
            self.inner,
            term_z.ptr,
            @intCast(term.len),
            null,
            0,
            @intCast(width),
            @intCast(height),
            0,
            0,
        ) != 0) {
            return error.SshChannelExecFailed;
        }
    }

    /// Read from stdout (blocking).
    pub fn read(self: *Channel, buf: []u8) !usize {
        const rc = channelRead(self.inner, buf.ptr, buf.len);
        if (rc < 0) return error.SshDisconnected;
        return @intCast(rc);
    }

    /// Non-blocking read from stdout. Returns bytes read, 0 if no data
    /// available (EAGAIN), or negative on error. Caller must ensure
    /// the session is in non-blocking mode.
    pub fn readNonBlock(self: *Channel, buf: []u8) isize {
        return channelRead(self.inner, buf.ptr, buf.len);
    }

    /// Read from stderr.
    pub fn readStderr(self: *Channel, buf: []u8) !usize {
        const rc = channelReadStderr(self.inner, buf.ptr, buf.len);
        if (rc < 0) return error.SshDisconnected;
        return @intCast(rc);
    }

    /// Non-blocking read from stderr. Returns bytes read, 0 if no data
    /// available (EAGAIN), or negative on error.
    pub fn readStderrNonBlock(self: *Channel, buf: []u8) isize {
        return channelReadStderr(self.inner, buf.ptr, buf.len);
    }

    /// Write data to the channel. Handles EAGAIN by retrying.
    pub fn write(self: *Channel, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const rc = channelWrite(self.inner, data[written..].ptr, data.len - written);
            if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) {
                waitsocket(self.ssh_session, self.sock);
                continue;
            }
            if (rc < 0) return error.SshDisconnected;
            written += @intCast(rc);
        }
    }

    /// Check if the remote end has sent EOF.
    pub fn eof(self: *Channel) bool {
        return ssh2.libssh2_channel_eof(self.inner) != 0;
    }

    /// Close the channel and free resources.
    pub fn close(self: *Channel) void {
        _ = ssh2.libssh2_channel_close(self.inner);
        _ = ssh2.libssh2_channel_free(self.inner);
    }
};

/// State for a tunneled SSH session. The inner session's custom
/// send/recv callbacks use this to route data through the tunnel channel.
const TunnelState = struct {
    channel: *ssh2.LIBSSH2_CHANNEL,
    jump_session: *ssh2.LIBSSH2_SESSION,
};

/// Custom recv callback: reads from the tunnel channel instead of a socket.
fn tunnelRecv(
    _: ssh2.libssh2_socket_t,
    buffer: [*c]u8,
    length: usize,
    _: c_int,
    abstract: *?*anyopaque,
) callconv(.c) isize {
    const ptr = abstract.* orelse {
        std.fs.File.stderr().writeAll("[tunnelRecv] abstract is null!\n") catch {};
        return -1;
    };
    const state: *TunnelState = @ptrCast(@alignCast(ptr));
    const rc = channelRead(state.channel, @ptrCast(buffer), length);
    if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) return posix_EAGAIN;
    if (rc <= 0) {
        const dbg = std.fs.File.stderr();
        var b: [60]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "[tunnelRecv] rc={d} len={d}\n", .{ rc, length }) catch "";
        dbg.writeAll(m) catch {};
    }
    return rc;
}

/// Custom send callback: writes to the tunnel channel instead of a socket.
fn tunnelSend(
    _: ssh2.libssh2_socket_t,
    buffer: [*c]const u8,
    length: usize,
    _: c_int,
    abstract: *?*anyopaque,
) callconv(.c) isize {
    const ptr = abstract.* orelse {
        std.fs.File.stderr().writeAll("[tunnelSend] abstract is null!\n") catch {};
        return -1;
    };
    const state: *TunnelState = @ptrCast(@alignCast(ptr));
    const rc = channelWrite(state.channel, @ptrCast(buffer), length);
    if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) return posix_EAGAIN;
    if (rc < 0) {
        const dbg = std.fs.File.stderr();
        var b: [60]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "[tunnelSend] rc={d} len={d}\n", .{ rc, length }) catch "";
        dbg.writeAll(m) catch {};
    }
    return rc;
}

// -- Helpers --

/// Verify the server's host key against the local known_hosts file.
/// Uses TOFU (Trust On First Use): unknown keys are auto-accepted and
/// written to known_hosts with a warning. Mismatched keys are rejected
/// to prevent MITM attacks.
fn verifyHostKey(
    alloc: Allocator,
    session: *ssh2.LIBSSH2_SESSION,
    host: []const u8,
    port: u16,
) !void {
    // Get the server's host key
    var key_len: usize = 0;
    var key_type: c_int = 0;
    const host_key = ssh2.libssh2_session_hostkey(session, &key_len, &key_type);
    if (host_key == null or key_len == 0) {
        log.warn("could not retrieve server host key", .{});
        return;
    }

    // Initialize known hosts handle
    const kh = ssh2.libssh2_knownhost_init(session) orelse {
        log.warn("failed to init known hosts handle", .{});
        return;
    };
    defer ssh2.libssh2_knownhost_free(kh);

    // Build path to ~/.ssh/known_hosts
    const home = posix.getenv("HOME") orelse {
        log.warn("HOME not set, skipping host key verification", .{});
        return;
    };
    const known_hosts_path = std.fs.path.join(alloc, &.{ home, ".ssh", "known_hosts" }) catch {
        log.warn("failed to build known_hosts path", .{});
        return;
    };
    defer alloc.free(known_hosts_path);
    const kh_path_z = alloc.dupeZ(u8, known_hosts_path) catch {
        log.warn("failed to allocate known_hosts path", .{});
        return;
    };
    defer alloc.free(kh_path_z);

    // Read existing known hosts (ignore errors — file may not exist yet)
    _ = ssh2.libssh2_knownhost_readfile(kh, kh_path_z.ptr, ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    // Map libssh2 key type to knownhost key type constant
    const kh_key_type: c_int = switch (key_type) {
        ssh2.LIBSSH2_HOSTKEY_TYPE_RSA => ssh2.LIBSSH2_KNOWNHOST_KEY_SSHRSA,
        ssh2.LIBSSH2_HOSTKEY_TYPE_DSS => ssh2.LIBSSH2_KNOWNHOST_KEY_SSHDSS,
        ssh2.LIBSSH2_HOSTKEY_TYPE_ECDSA_256 => ssh2.LIBSSH2_KNOWNHOST_KEY_ECDSA_256,
        ssh2.LIBSSH2_HOSTKEY_TYPE_ECDSA_384 => ssh2.LIBSSH2_KNOWNHOST_KEY_ECDSA_384,
        ssh2.LIBSSH2_HOSTKEY_TYPE_ECDSA_521 => ssh2.LIBSSH2_KNOWNHOST_KEY_ECDSA_521,
        ssh2.LIBSSH2_HOSTKEY_TYPE_ED25519 => ssh2.LIBSSH2_KNOWNHOST_KEY_ED25519,
        else => ssh2.LIBSSH2_KNOWNHOST_KEY_UNKNOWN,
    };

    const typemask = ssh2.LIBSSH2_KNOWNHOST_TYPE_PLAIN |
        ssh2.LIBSSH2_KNOWNHOST_KEYENC_RAW |
        kh_key_type;

    // Null-terminate host for C API
    const host_z = alloc.dupeZ(u8, host) catch {
        log.warn("failed to allocate host string for verification", .{});
        return;
    };
    defer alloc.free(host_z);

    // Check the key against known hosts
    var kh_entry: ?*ssh2.struct_libssh2_knownhost = null;
    const check_result = ssh2.libssh2_knownhost_checkp(
        kh,
        host_z.ptr,
        @intCast(port),
        host_key,
        key_len,
        typemask,
        &kh_entry,
    );

    switch (check_result) {
        ssh2.LIBSSH2_KNOWNHOST_CHECK_MATCH => {
            // Host key matches — trusted host
            log.info("host key verified for {s}", .{host});
        },
        ssh2.LIBSSH2_KNOWNHOST_CHECK_MISMATCH => {
            // Key changed — potential MITM attack
            log.err("HOST KEY MISMATCH for {s}:{d} — possible MITM attack! " ++
                "Remove the old key from known_hosts to connect.", .{ host, port });
            return error.SshHostKeyMismatch;
        },
        ssh2.LIBSSH2_KNOWNHOST_CHECK_NOTFOUND => {
            // TOFU: auto-accept and write the key
            log.warn("host key for {s}:{d} not found in known_hosts — " ++
                "auto-accepting (TOFU). Verify the key fingerprint manually " ++
                "for critical connections.", .{ host, port });

            _ = ssh2.libssh2_knownhost_addc(
                kh,
                host_z.ptr,
                null, // salt (not used for plain type)
                host_key,
                key_len,
                null, // comment
                0, // comment len
                typemask,
                null, // store (we don't need the entry back)
            );

            // Ensure ~/.ssh directory exists
            const ssh_dir = std.fs.path.join(alloc, &.{ home, ".ssh" }) catch return;
            defer alloc.free(ssh_dir);
            std.fs.makeDirAbsolute(ssh_dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return,
            };

            // Write updated known_hosts file
            _ = ssh2.libssh2_knownhost_writefile(kh, kh_path_z.ptr, ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        },
        else => {
            // LIBSSH2_KNOWNHOST_CHECK_FAILURE or other
            log.warn("host key check failed for {s} (result={d})", .{ host, check_result });
        },
    }
}

/// Perform SSH handshake in non-blocking mode with a 30s timeout.
/// `hs_session`/`hs_fd` are the session and fd to handshake.
/// `poll_session`/`poll_sock` are used for waitsocket polling (may
/// differ for tunneled sessions where the poll socket is the jump host's).
fn performHandshake(
    hs_session: *ssh2.LIBSSH2_SESSION,
    hs_fd: posix.fd_t,
    poll_session: *ssh2.LIBSSH2_SESSION,
    poll_sock: posix.fd_t,
) !void {
    ssh2.libssh2_session_set_blocking(hs_session, 0);
    const deadline = std.time.nanoTimestamp() + 30 * std.time.ns_per_s;
    while (true) {
        if (std.time.nanoTimestamp() > deadline) return error.SshHandshakeFailed;
        const rc = ssh2.libssh2_session_handshake(hs_session, hs_fd);
        if (rc == 0) break;
        if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) {
            waitsocketTimeout(poll_session, poll_sock, 100);
            continue;
        }
        return error.SshHandshakeFailed;
    }
    ssh2.libssh2_session_set_blocking(hs_session, 1);
}

/// Log the last libssh2 session error to stderr with a prefix.
fn logSshError(session: *ssh2.LIBSSH2_SESSION, prefix: []const u8) void {
    var errmsg: [*c]u8 = null;
    var errmsg_len: c_int = 0;
    _ = ssh2.libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
    if (errmsg != null and errmsg_len > 0) {
        const dbg = std.fs.File.stderr();
        dbg.writeAll(prefix) catch {};
        dbg.writeAll(errmsg[0..@intCast(errmsg_len)]) catch {};
        dbg.writeAll("\n") catch {};
    }
}

/// TCP connect timeout in milliseconds.
const tcp_connect_timeout_ms = 30_000;

fn tcpConnect(host: []const u8, port: u16) !posix.fd_t {
    const host_z = try std.heap.page_allocator.dupeZ(u8, host);
    defer std.heap.page_allocator.free(host_z);

    var port_buf: [6]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;
    const port_z = try std.heap.page_allocator.dupeZ(u8, port_str);
    defer std.heap.page_allocator.free(port_z);

    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_UNSPEC;
    hints.ai_socktype = c.SOCK_STREAM;

    var result: ?*c.struct_addrinfo = null;
    if (c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &result) != 0) {
        return error.SshConnectFailed;
    }
    defer c.freeaddrinfo(result);

    var addr = result;
    while (addr) |a| : (addr = a.ai_next) {
        const sock = c.socket(a.ai_family, a.ai_socktype, a.ai_protocol);
        if (sock < 0) continue;

        // Set non-blocking for connect with timeout.
        const flags = c.fcntl(sock, c.F_GETFL, @as(c_int, 0));
        _ = c.fcntl(sock, c.F_SETFL, flags | c.O_NONBLOCK);

        const rc = c.connect(sock, a.ai_addr, a.ai_addrlen);
        if (rc == 0) {
            // Connected immediately — restore blocking mode.
            _ = c.fcntl(sock, c.F_SETFL, flags);
            return sock;
        }

        if (std.c._errno().* != @as(c_int, @intFromEnum(posix.E.INPROGRESS))) {
            _ = c.close(sock);
            continue;
        }

        // Wait for connect to complete with timeout.
        var fds = [1]c.struct_pollfd{.{ .fd = sock, .events = c.POLLOUT, .revents = 0 }};
        const poll_rc = c.poll(&fds, 1, tcp_connect_timeout_ms);
        if (poll_rc <= 0) {
            _ = c.close(sock);
            continue;
        }

        // Check if connect actually succeeded.
        var so_err: c_int = 0;
        var so_len: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(sock, c.SOL_SOCKET, c.SO_ERROR, @ptrCast(&so_err), &so_len) != 0 or so_err != 0) {
            _ = c.close(sock);
            continue;
        }

        // Restore blocking mode.
        _ = c.fcntl(sock, c.F_SETFL, flags);
        return sock;
    }

    return error.SshConnectFailed;
}

/// Wait for the socket to become ready in the direction libssh2 needs.
/// Uses `libssh2_session_block_directions` on the given session to poll
/// the exact condition. For tunneled sessions, callers should pass the
/// *inner* session — its block directions correctly reflect the TCP
/// socket's needs because BLOCK_INBOUND is set when tunnelRecv got
/// EAGAIN (TCP needs POLLIN) and BLOCK_OUTBOUND when tunnelSend got
/// EAGAIN (TCP needs POLLOUT).
fn waitsocket(sess: *ssh2.LIBSSH2_SESSION, sock: posix.fd_t) void {
    waitsocketTimeout(sess, sock, 100);
}

fn waitsocketTimeout(sess: *ssh2.LIBSSH2_SESSION, sock: posix.fd_t, timeout_ms: c_int) void {
    const dir = ssh2.libssh2_session_block_directions(sess);
    var events: c_short = 0;
    if (dir & ssh2.LIBSSH2_SESSION_BLOCK_INBOUND != 0) events |= c.POLLIN;
    if (dir & ssh2.LIBSSH2_SESSION_BLOCK_OUTBOUND != 0) events |= c.POLLOUT;
    if (events == 0) events = c.POLLIN | c.POLLOUT;
    var fds = [1]c.struct_pollfd{.{ .fd = sock, .events = events, .revents = 0 }};
    _ = c.poll(&fds, 1, timeout_ms);
}

// -- Wrappers for libssh2 macros that Zig's @cImport can't translate --
// These macros pass NULL as typed function pointers which Zig's C
// translation cannot handle. We call the _ex variants directly.

fn sessionInit() ?*ssh2.LIBSSH2_SESSION {
    return ssh2.libssh2_session_init_ex(null, null, null, null);
}

fn userauthPassword(
    session: *ssh2.LIBSSH2_SESSION,
    user: [*:0]const u8,
    user_len: c_uint,
    pass: [*:0]const u8,
    pass_len: c_uint,
) c_int {
    return ssh2.libssh2_userauth_password_ex(
        session,
        user,
        user_len,
        pass,
        pass_len,
        null,
    );
}

fn channelOpenSession(session: *ssh2.LIBSSH2_SESSION) ?*ssh2.LIBSSH2_CHANNEL {
    return ssh2.libssh2_channel_open_ex(
        session,
        "session",
        7,
        ssh2.LIBSSH2_CHANNEL_WINDOW_DEFAULT,
        ssh2.LIBSSH2_CHANNEL_PACKET_DEFAULT,
        null,
        0,
    );
}

fn channelDirectTcpip(
    session: *ssh2.LIBSSH2_SESSION,
    host: [*:0]const u8,
    port: c_int,
) ?*ssh2.LIBSSH2_CHANNEL {
    return ssh2.libssh2_channel_direct_tcpip_ex(
        session,
        host,
        port,
        "127.0.0.1",
        22,
    );
}

fn channelExec(channel: *ssh2.LIBSSH2_CHANNEL, cmd: [*:0]const u8, cmd_len: c_uint) c_int {
    return ssh2.libssh2_channel_process_startup(
        channel,
        "exec",
        4,
        cmd,
        cmd_len,
    );
}

fn channelRead(channel: *ssh2.LIBSSH2_CHANNEL, buf: [*]u8, len: usize) isize {
    return ssh2.libssh2_channel_read_ex(channel, 0, @ptrCast(buf), len);
}

fn channelReadStderr(channel: *ssh2.LIBSSH2_CHANNEL, buf: [*]u8, len: usize) isize {
    return ssh2.libssh2_channel_read_ex(
        channel,
        ssh2.SSH_EXTENDED_DATA_STDERR,
        @ptrCast(buf),
        len,
    );
}

fn channelWrite(channel: *ssh2.LIBSSH2_CHANNEL, buf: [*]const u8, len: usize) isize {
    return ssh2.libssh2_channel_write_ex(channel, 0, @ptrCast(buf), len);
}

/// Global libssh2 initialization. Must be called once before any use.
pub fn globalInit() void {
    _ = ssh2.libssh2_init(0);
}

/// Global libssh2 cleanup.
pub fn globalDeinit() void {
    ssh2.libssh2_exit();
}

/// Parse a "user@host" or "user@host:port" SSH target string.
pub const SshTarget = struct {
    user: []const u8,
    host: []const u8,
    port: u16,

    pub fn parse(target: []const u8) !SshTarget {
        const at_pos = std.mem.indexOf(u8, target, "@") orelse
            return .{ .user = "root", .host = target, .port = 22 };
        const user = target[0..at_pos];
        const rest = target[at_pos + 1 ..];

        if (std.mem.indexOf(u8, rest, ":")) |colon| {
            const port = std.fmt.parseInt(u16, rest[colon + 1 ..], 10) catch 22;
            return .{ .user = user, .host = rest[0..colon], .port = port };
        }
        return .{ .user = user, .host = rest, .port = 22 };
    }
};

test "SshTarget.parse user@host" {
    const t = try SshTarget.parse("dev@192.168.1.1");
    try std.testing.expectEqualStrings("dev", t.user);
    try std.testing.expectEqualStrings("192.168.1.1", t.host);
    try std.testing.expectEqual(@as(u16, 22), t.port);
}

test "SshTarget.parse user@host:port" {
    const t = try SshTarget.parse("admin@myhost:2222");
    try std.testing.expectEqualStrings("admin", t.user);
    try std.testing.expectEqualStrings("myhost", t.host);
    try std.testing.expectEqual(@as(u16, 2222), t.port);
}

test "SshTarget.parse host only" {
    const t = try SshTarget.parse("example.com");
    try std.testing.expectEqualStrings("root", t.user);
    try std.testing.expectEqualStrings("example.com", t.host);
    try std.testing.expectEqual(@as(u16, 22), t.port);
}

test "SshTarget.parse host:port no user" {
    const t = try SshTarget.parse("example.com:8022");
    // No @, so entire string is treated as host
    try std.testing.expectEqualStrings("root", t.user);
    try std.testing.expectEqualStrings("example.com:8022", t.host);
    try std.testing.expectEqual(@as(u16, 22), t.port);
}
