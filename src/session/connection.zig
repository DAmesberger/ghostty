const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const shared = @import("shared.zig");
const ssh = @import("ssh.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

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
