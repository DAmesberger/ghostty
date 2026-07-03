const std = @import("std");

/// Default keepalive intervals. The client may override these per-Entry
/// (see SshConnectionManager.Entry / Config) for faster disconnect
/// detection on flaky links. The server-side timeout
/// (keepalive_server_timeout_ns) is enforced by the multiplex process
/// and is not currently runtime-configurable from the client.
///
/// Client sends ping at `keepalive_interval_ns`, daemon responds with
/// pong. Halves keepalive traffic vs bidirectional keepalive.
pub const keepalive_interval_ns: i128 = 5 * std.time.ns_per_s;

/// Client considers connection stale if no pong received within this
/// window. With the default interval=5s, two missed pongs ⇒ stale,
/// which surfaces as a `.reconnecting` state broadcast and lets the
/// embedder show its reconnect overlay within ~10s of a dropped link
/// (instead of the previous 45s).
pub const keepalive_stale_ns: i128 = 12 * std.time.ns_per_s;

/// Server closes connection if no ping received within this window.
/// Stays at 60s because changing it would require coordinating both
/// ends of the protocol; the client-side stale (12s) trips first
/// anyway under normal flow.
pub const keepalive_server_timeout_ns: i128 = 60 * std.time.ns_per_s;

/// Connection state reported to surfaces for overlay display.
pub const ConnectionState = union(enum) {
    connecting,
    uploading: UploadProgress,
    downloading,
    setup,
    connected,
    reconnecting: ReconnectInfo,
    stale,
    failed: FailReason,
    disconnected: DisconnectInfo,
    password_required: PasswordPrompt,
    update_confirmation_required: UpdateConfirmation,

    /// Emitted when a remote ghostty-daemon needs a session-killing
    /// update (its binary content hash differs from the local one) AND a
    /// daemon is already running on the remote with live sessions at
    /// risk. The embedder must surface a confirmation prompt and call
    /// `ghostty_ssh_submit_update_decision(decision_token, confirm)` to
    /// resume: confirm=true uploads + force-restarts (ending sessions),
    /// confirm=false reuses the running protocol-compatible daemon. The
    /// SSH setup thread blocks on the shared `update_state` cond until
    /// the decision arrives. Mirrors `PasswordPrompt`.
    pub const UpdateConfirmation = struct {
        /// Typed pointer to the shared UpdateState. The GTK / C-API
        /// handler uses this to record the decision and signal the cond.
        update_state: ?*@import("shared.zig").UpdateState = null,
        /// True when the remote daemon's protocol version is
        /// INCOMPATIBLE (not just a content-hash drift). In that case
        /// the update is mandatory: declining means disconnect, not
        /// "keep current" — there is no usable running daemon to reuse.
        is_mandatory: bool = false,
        /// Best-effort count of live sessions on the remote that an
        /// update would reset. 0 when the count couldn't be determined
        /// (but the daemon was still detected as running).
        session_count: u32 = 0,
        /// The host being updated (e.g. "user@host"). Fixed buffer so it
        /// can safely cross thread boundaries via the mailbox/broadcast.
        host: [128]u8 = .{0} ** 128,
        host_len: u8 = 0,

        pub fn hostSlice(self: *const UpdateConfirmation) []const u8 {
            return self.host[0..self.host_len];
        }

        pub fn setHost(self: *UpdateConfirmation, name: []const u8) void {
            const len = @min(name.len, self.host.len);
            @memcpy(self.host[0..len], name[0..len]);
            self.host_len = @intCast(len);
        }
    };

    pub const PasswordPrompt = struct {
        /// True if the password is for the jump host, false for the target.
        is_jump: bool,
        /// Typed pointer to the shared AuthState for password prompts.
        /// The GTK handler uses this to submit the password.
        auth_state: ?*@import("shared.zig").AuthState = null,
        /// The host being authenticated (e.g., "user@host"). Fixed buffer
        /// so it can safely cross thread boundaries via the mailbox.
        host: [128]u8 = .{0} ** 128,
        host_len: u8 = 0,

        pub fn hostSlice(self: *const PasswordPrompt) []const u8 {
            return self.host[0..self.host_len];
        }

        pub fn setHost(self: *PasswordPrompt, name: []const u8) void {
            const len = @min(name.len, self.host.len);
            @memcpy(self.host[0..len], name[0..len]);
            self.host_len = @intCast(len);
        }
    };

    pub const ProvisionSource = enum(u8) {
        local_daemon, // ghostty-daemon binary next to the local executable
        local_self, // the running ghostty binary itself (same platform)
        github, // downloaded from GitHub releases (cross-platform)
    };

    pub const UploadProgress = struct {
        bytes_sent: u64,
        total_bytes: u64,
        source: ProvisionSource = .local_self,
    };

    pub const ReconnectInfo = struct {
        attempt: u32,
        max_attempts: u32,
        elapsed_ns: i128,
        next_retry_ns: i128,
    };

    pub const DisconnectInfo = struct {
        attempts_made: u32,
        reason: DisconnectReason,
    };

    pub const DisconnectReason = enum(u8) {
        exhausted,
        cancelled,
        disabled,
    };

    pub const FailReason = enum(u8) {
        unknown,
        auth_failed,
        timeout,
        helper_failed,
    };

    /// C ABI representation — this is an internal-only action so we
    /// use void; the GTK handler reads from renderer_state instead.
    pub const C = void;

    pub fn cval(self: ConnectionState) void {
        _ = self;
    }
};
