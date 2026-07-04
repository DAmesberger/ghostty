//! Shared C-ABI extern structs + enums for the libghostty SSH
//! connection + channel-multiplexing surface. Split out of
//! `ssh_capi.zig`; the facade re-exports every public symbol here.
//! These mirror `include/ghostty.h` exactly — any change here MUST be
//! reflected in the header.

const protocol = @import("../../session/protocol.zig");

// `SshCallbacks.on_inbound_channel` references `*ChannelHandle` by
// pointer only (no layout dependency), so this cross-import back into
// the handles sibling is cycle-safe (same pattern as channel_mux).
const ChannelHandle = @import("ssh_capi_handles.zig").ChannelHandle;

// =========================================================================
// C-ABI types. These mirror `include/ghostty.h` exactly. Any change
// here MUST be reflected in the header.
// =========================================================================

/// Mirror of `ghostty_ssh_state_kind_e`.
pub const StateKind = enum(c_int) {
    connecting = 0,
    password_required = 1,
    uploading = 2,
    downloading = 3,
    setup = 4,
    connected = 5,
    reconnecting = 6,
    stale = 7,
    failed = 8,
    disconnected = 9,
    update_confirmation_required = 10,
};

/// Mirror of `ghostty_ssh_provision_source_e`.
pub const ProvisionSource = enum(c_int) {
    local_daemon = 0,
    local_self = 1,
    github = 2,

    pub fn fromZig(src: protocol.ConnectionState.ProvisionSource) ProvisionSource {
        return switch (src) {
            .local_daemon => .local_daemon,
            .local_self => .local_self,
            .github => .github,
        };
    }
};

/// Mirror of `ghostty_ssh_disconnect_reason_e`.
pub const DisconnectReason = enum(c_int) {
    exhausted = 0,
    cancelled = 1,
    disabled = 2,

    pub fn fromZig(r: protocol.ConnectionState.DisconnectReason) DisconnectReason {
        return switch (r) {
            .exhausted => .exhausted,
            .cancelled => .cancelled,
            .disabled => .disabled,
        };
    }
};

/// Mirror of `ghostty_ssh_fail_reason_e`.
pub const FailReason = enum(c_int) {
    unknown = 0,
    auth_failed = 1,
    timeout = 2,
    helper_failed = 3,

    pub fn fromZig(r: protocol.ConnectionState.FailReason) FailReason {
        return switch (r) {
            .unknown => .unknown,
            .auth_failed => .auth_failed,
            .timeout => .timeout,
            .helper_failed => .helper_failed,
        };
    }
};

/// Mirror of `ghostty_channel_service_e`. Values match
/// `protocol.ChannelService` for built-ins; `terminal` is a
/// libghostty-only sugar value (the surface attachment path uses the
/// legacy session frames and doesn't ride channel_* frames).
pub const ChannelService = enum(c_int) {
    invalid = 0,
    tcp_connect = 1,
    port_listener = 2,
    file_transfer = 3,
    browser_proxy = 4,
    process_exec = 5,
    terminal = 6,
    custom = 255,
};

/// Mirror of `ghostty_channel_close_reason_e`. Includes
/// libghostty-synthesized values for transport-level closes.
pub const ChannelCloseReason = enum(c_int) {
    normal = 0,
    peer_reset = 1,
    service_error = 2,
    policy_denied = 3,
    idle_timeout = 4,
    daemon_shutdown = 5,
    transport = 254,
    unknown = 255,

    pub fn fromProtocol(r: protocol.ChannelCloseReason) ChannelCloseReason {
        return switch (r) {
            .normal => .normal,
            .peer_reset => .peer_reset,
            .service_error => .service_error,
            .policy_denied => .policy_denied,
            .idle_timeout => .idle_timeout,
            .daemon_shutdown => .daemon_shutdown,
            _ => .unknown,
        };
    }

    /// Map an embedder-supplied close reason to the wire-protocol
    /// reason for a `channel_close` frame. `transport` and `unknown`
    /// are libghostty-synthesized (no wire representation) and map
    /// to `normal` — an embedder closing a channel "because the
    /// transport dropped" still tells the peer a plain close.
    pub fn toProtocol(self: ChannelCloseReason) protocol.ChannelCloseReason {
        return switch (self) {
            .normal, .transport, .unknown => .normal,
            .peer_reset => .peer_reset,
            .service_error => .service_error,
            .policy_denied => .policy_denied,
            .idle_timeout => .idle_timeout,
            .daemon_shutdown => .daemon_shutdown,
        };
    }
};

/// Mirror of `ghostty_ssh_host_key_policy_e`.
pub const HostKeyPolicy = enum(c_int) {
    strict = 0,
    tofu = 1,
    insecure = 2,
};

/// Mirror of `ghostty_ssh_state_password_t`.
pub const StatePassword = extern struct {
    is_jump: bool,
    host: [*:0]const u8,
    auth_token: u64,
};

/// Mirror of `ghostty_ssh_state_update_confirmation_t`.
pub const StateUpdateConfirmation = extern struct {
    /// Host being updated, NUL-terminated.
    host: [*:0]const u8,
    /// Best-effort count of live sessions an update would reset.
    session_count: u32,
    /// True when declining means disconnect (incompatible protocol),
    /// false when "Keep current" can safely reuse the running daemon.
    is_mandatory: bool,
    /// Opaque token to feed back to submit_update_decision.
    decision_token: u64,
};

/// Mirror of `ghostty_ssh_state_upload_t`.
pub const StateUpload = extern struct {
    bytes_sent: u64,
    total_bytes: u64,
    source: ProvisionSource,
};

/// Mirror of `ghostty_ssh_state_reconnect_t`.
pub const StateReconnect = extern struct {
    attempt: u32,
    max_attempts: u32,
    elapsed_ns: i64,
    next_retry_ns: i64,
};

/// Mirror of `ghostty_ssh_state_disconnect_t`.
pub const StateDisconnect = extern struct {
    attempts_made: u32,
    reason: DisconnectReason,
};

/// Mirror of `ghostty_ssh_state_fail_t`.
pub const StateFail = extern struct {
    reason: FailReason,
    message: ?[*:0]const u8,
};

/// Mirror of `ghostty_ssh_state_t`. C uses an anonymous union; Zig
/// builds the equivalent extern union sized to the largest variant.
pub const State = extern struct {
    kind: StateKind,
    payload: Payload,

    pub const Payload = extern union {
        password: StatePassword,
        upload: StateUpload,
        reconnect: StateReconnect,
        disconnect: StateDisconnect,
        fail: StateFail,
        update_confirmation: StateUpdateConfirmation,
    };
};

/// Mirror of `ghostty_ssh_host_key_t`.
pub const HostKey = extern struct {
    host: [*:0]const u8,
    fingerprint_sha256: [*:0]const u8,
    key_type: [*:0]const u8,
    known_match: bool,
    known_mismatch: bool,
    decision_token: u64,
};

/// Mirror of `ghostty_ssh_config_t`. All pointers are borrowed for the
/// duration of ghostty_ssh_open; the impl copies before returning.
pub const Config = extern struct {
    target: [*:0]const u8,
    jump: ?[*:0]const u8,
    identity_file: ?[*:0]const u8,
    keepalive_interval_ms: u32,
    max_reconnect_attempts: u32,
    reconnect_interval_ms: u32,
    host_key_policy: HostKeyPolicy,
    scrollback_limit_bytes: u32,
    /// Upper bound on a single reconnect backoff sleep, in
    /// milliseconds. Pair with `max_reconnect_attempts = UINT32_MAX`
    /// for "patient but persistent" reconnect: ghostty keeps trying
    /// indefinitely, but never sleeps longer than this between
    /// attempts. Set to 0 to use the legacy 30 s default.
    reconnect_max_interval_ms: u32,
};

/// Mirror of `ghostty_ssh_callbacks_t`.
pub const SshCallbacks = extern struct {
    on_state: ?*const fn (userdata: ?*anyopaque, state: *const State) callconv(.c) void,
    on_host_key: ?*const fn (userdata: ?*anyopaque, hk: *const HostKey) callconv(.c) void,
    on_inbound_channel: ?*const fn (
        userdata: ?*anyopaque,
        channel: ?*ChannelHandle,
        service: ChannelService,
        params: ?*const anyopaque,
        params_len: usize,
    ) callconv(.c) ?*ChannelHandle,
    userdata: ?*anyopaque,
};

/// Mirror of `ghostty_channel_callbacks_t`.
pub const ChannelCallbacks = extern struct {
    on_opened: ?*const fn (
        userdata: ?*anyopaque,
        service_ack: ?*const anyopaque,
        ack_len: usize,
        initial_peer_window: u32,
    ) callconv(.c) void,
    on_data: ?*const fn (
        userdata: ?*anyopaque,
        bytes: ?*const anyopaque,
        len: usize,
    ) callconv(.c) void,
    on_window_credit: ?*const fn (userdata: ?*anyopaque, credit_bytes: u32) callconv(.c) void,
    on_eof: ?*const fn (userdata: ?*anyopaque) callconv(.c) void,
    on_close: ?*const fn (
        userdata: ?*anyopaque,
        reason: ChannelCloseReason,
        message: ?[*:0]const u8,
    ) callconv(.c) void,
    /// A service `channel_control` frame arrived. `op` is the
    /// service-defined opcode; `op_payload`/`op_payload_len` are borrowed
    /// for the callback's duration. Null for services with no
    /// client-visible control ops (e.g. the file_transfer progress/final
    /// frames are the first consumer).
    on_control: ?*const fn (
        userdata: ?*anyopaque,
        op: u8,
        op_payload: ?*const anyopaque,
        op_payload_len: usize,
    ) callconv(.c) void = null,
    userdata: ?*anyopaque,
};

/// Mirror of `ghostty_ssh_session_status_e`.
pub const SessionStatus = enum(c_int) {
    detached = 0,
    attached = 1,
    dead = 2,

    pub fn fromProtocol(s: protocol.ListStatus) SessionStatus {
        return switch (s) {
            .detached => .detached,
            .attached => .attached,
            .dead => .dead,
        };
    }
};

/// Mirror of `ghostty_ssh_session_entry_t`.
pub const SessionEntry = extern struct {
    group_id: [*]const u8, // 16 bytes
    label: [*:0]const u8,
    surface_count: u32,
    created_at_ns: i64,
    status: SessionStatus,
    color: i8,
};
