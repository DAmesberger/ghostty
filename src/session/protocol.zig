const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum payload size for a single frame. The receive buffer grows on
/// demand (256KB → 512KB → 1MB) and never shrinks, so a large full snapshot
/// on a 5K terminal is a one-time allocation cost. The u32 len field
/// supports up to 4GB — no protocol-level limit.
pub const max_payload = 256 * 1024;

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

/// Protocol version for the session wire format. Clean break from v6 —
/// new frame kinds, structured page diffs, flags byte.
pub const protocol_version: u16 = 1;

/// Size of a frame header in bytes.
/// Layout: kind(1) + flags(1) + target(2 LE) + len(4 LE) = 8 bytes.
pub const header_size: usize = 8;

/// Frame flags (byte 1 of header).
pub const Flags = packed struct(u8) {
    /// Payload is LZ4-compressed. When set, the payload starts with a
    /// 4-byte LE original length, followed by LZ4 block data.
    compressed: bool = false,
    _reserved: u7 = 0,
};

/// Frame types. Every kind is a first-class enum variant — no sub-typing.
/// Values 0-127 are spec-defined, 128-255 reserved for future extensions.
pub const Kind = enum(u8) {
    // Data plane (hot path)
    data_in = 1, // stdin: client → daemon (raw bytes to PTY)
    data_out = 2, // stdout: daemon → client (binary page diffs, zstd compressed)

    // Control
    resize = 3, // Terminal resize (8-byte Resize struct)
    ping = 4, // Keepalive request (0-byte payload)
    pong = 5, // Keepalive response (0-byte payload)

    // Session lifecycle
    open = 6, // Unified session/surface open
    opened = 7, // Response: group_id + bundled layout + state snapshots
    close = 8, // Unified close/detach (mode byte in payload)
    eof = 9, // Surface/session ended

    // Layout & metadata
    layout = 10, // Layout blob update (both directions)
    list_request = 11, // Client → daemon: list sessions (0-byte)
    list_response = 12, // Daemon → client: structured session list
    rename = 13, // Client → daemon: rename session or surface
    info = 14, // Daemon → client: info text
    err = 15, // Daemon → client: error text

    // Scrollback
    scrollback_response = 17, // Daemon → client: scrollback history chunk (proactive streaming)

    // Multi-viewer
    viewer_state = 20, // Daemon → viewer(s): roster + session state
    size_mode_change = 21, // Client → daemon: change size negotiation mode
    kick_viewer = 25, // Client → daemon: force-disconnect a viewer
    session_meta = 26, // Client → daemon: update session label + color

    // Capability negotiation (post-banner handshake, both directions)
    capabilities = 27,

    // Generic multiplexed channels (Phase 6A — codec scaffold; not wired yet).
    // Channel-id lives in the payload (u32 LE first 4 bytes), NOT the header's
    // `target` field. `target` is left at 0 by senders for channel frames so
    // the existing surface/viewer multiplexing on `target` does not collide
    // with channel multiplexing.
    channel_open = 30, // Open a service-typed channel
    channel_opened = 31, // Ack with status + initial window
    channel_data = 32, // Raw bytes on a channel (LZ4 via header flag)
    channel_window = 33, // Credit-based flow-control window update
    channel_eof = 34, // Half-close: sender done writing
    channel_close = 35, // Full teardown with reason code
    channel_control = 36, // Service-specific control op
};

pub const Header = struct {
    kind: Kind,
    flags: Flags = .{},
    target: u16 = 0,
    len: u32,

    /// Parse a header from an already-read 8-byte buffer.
    pub fn parseFromBuf(buf: *const [header_size]u8) !Header {
        return .{
            .kind = std.meta.intToEnum(Kind, buf[0]) catch return error.InvalidFrameType,
            .flags = @bitCast(buf[1]),
            .target = std.mem.readInt(u16, buf[2..4], .little),
            .len = std.mem.readInt(u32, buf[4..8], .little),
        };
    }

    /// Encode a header into an 8-byte buffer for writing.
    pub fn encodeToBuf(self: Header) [header_size]u8 {
        var buf: [header_size]u8 = undefined;
        buf[0] = @intFromEnum(self.kind);
        buf[1] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[2..4], self.target, .little);
        std.mem.writeInt(u32, buf[4..8], @intCast(self.len), .little);
        return buf;
    }
};

// =========================================================================
// Open frame — unified session/surface open
// =========================================================================

pub const OpenType = enum(u8) {
    session_new = 0,
    session_attach = 1,
    surface_new = 2,
    surface_attach = 3,
};

pub const Uuid = @import("shared.zig").Uuid;
pub const zero_uuid = @import("shared.zig").zero_uuid;
pub const uuid_size = 16;

/// Payload for `open`:
///   [1]  open_type
///   [16] group_id  (zero = auto-generate)
///   [16] surface_id (zero = auto-generate or first-alive)
///   [8]  resize
///   [4]  max_scrollback (u32 LE, 0 = use daemon default)
///   [1]  compression_enabled (0=no, 1=yes — client supports LZ4)
///   [2]  frame_interval_ms (0=no debounce, default 16; client's preferred rate)
///   [N]  label (remaining bytes, UTF-8, may be empty)
pub const Open = struct {
    open_type: OpenType,
    group_id: Uuid = zero_uuid,
    surface_id: Uuid = zero_uuid,
    resize: Resize,
    max_scrollback: u32 = 0,
    compression_enabled: u8 = 1,
    frame_interval_ms: u16 = 16,
    label: []const u8 = "",

    /// Fixed part: open_type(1) + group_id(16) + surface_id(16) + resize(8) +
    /// max_scrollback(4) + compression_enabled(1) + frame_interval_ms(2) = 48
    const fixed_size = 1 + uuid_size * 2 + 8 + 4 + 1 + 2;
    pub const min_payload_size = fixed_size;

    pub fn encode(self: Open, alloc: Allocator) ![]u8 {
        const total = min_payload_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.open_type);
        @memcpy(buf[1 .. 1 + uuid_size], &self.group_id);
        @memcpy(buf[1 + uuid_size .. 1 + uuid_size * 2], &self.surface_id);
        const resize_bytes = self.resize.bytes();
        @memcpy(buf[1 + uuid_size * 2 .. 1 + uuid_size * 2 + 8], &resize_bytes);
        const scrollback_off = 1 + uuid_size * 2 + 8;
        std.mem.writeInt(u32, buf[scrollback_off..][0..4], self.max_scrollback, .little);
        buf[scrollback_off + 4] = self.compression_enabled;
        std.mem.writeInt(u16, buf[scrollback_off + 5 ..][0..2], self.frame_interval_ms, .little);
        @memcpy(buf[min_payload_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !Open {
        if (payload.len < min_payload_size) return error.InvalidOpenPayload;
        const scrollback_off = 1 + uuid_size * 2 + 8;
        return .{
            .open_type = std.meta.intToEnum(OpenType, payload[0]) catch return error.InvalidOpenPayload,
            .group_id = payload[1..][0..uuid_size].*,
            .surface_id = payload[1 + uuid_size ..][0..uuid_size].*,
            .resize = try Resize.parse(payload[1 + uuid_size * 2 ..][0..8]),
            .max_scrollback = std.mem.readInt(u32, payload[scrollback_off..][0..4], .little),
            .compression_enabled = payload[scrollback_off + 4],
            .frame_interval_ms = std.mem.readInt(u16, payload[scrollback_off + 5 ..][0..2], .little),
            .label = payload[min_payload_size..],
        };
    }
};

// =========================================================================
// Close frame — unified close/detach
// =========================================================================

pub const CloseMode = enum(u8) {
    /// Kill the specific surface's PTY.
    surface = 0,
    /// Detach — keep daemon-side session alive for reattach.
    detach = 1,
    /// Kill all surfaces in the session group.
    session = 2,
};

/// Payload for `close`:
///   [1]  close_mode
///   [16] id (surface UUID for mode=surface, group UUID for mode=session;
///            omittable for mode=detach — parser accepts 1-byte payload)
pub const Close = struct {
    mode: CloseMode,
    id: Uuid = zero_uuid,

    pub fn encode(self: Close, alloc: Allocator) ![]u8 {
        if (self.mode == .detach) {
            const buf = try alloc.alloc(u8, 1);
            buf[0] = @intFromEnum(self.mode);
            return buf;
        }
        const buf = try alloc.alloc(u8, 1 + uuid_size);
        buf[0] = @intFromEnum(self.mode);
        @memcpy(buf[1 .. 1 + uuid_size], &self.id);
        return buf;
    }

    pub fn parse(payload: []const u8) !Close {
        if (payload.len < 1) return error.InvalidClosePayload;
        const mode = std.meta.intToEnum(CloseMode, payload[0]) catch return error.InvalidClosePayload;
        if (mode == .detach) return .{ .mode = .detach };
        if (payload.len < 1 + uuid_size) return error.InvalidClosePayload;
        return .{
            .mode = mode,
            .id = payload[1..][0..uuid_size].*,
        };
    }
};

// =========================================================================
// Rename frame
// =========================================================================

pub const RenameScope = enum(u8) {
    group = 0,
    surface = 1,
};

/// Payload for `rename`:
///   [1]  scope (0=group, 1=surface)
///   [16] UUID
///   [N]  label (remaining bytes)
pub const Rename = struct {
    scope: RenameScope,
    id: Uuid,
    label: []const u8,

    pub const min_payload_size = 1 + uuid_size;

    pub fn encode(self: Rename, alloc: Allocator) ![]u8 {
        const total = min_payload_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.scope);
        @memcpy(buf[1 .. 1 + uuid_size], &self.id);
        @memcpy(buf[min_payload_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !Rename {
        if (payload.len < min_payload_size) return error.InvalidRenamePayload;
        return .{
            .scope = std.meta.intToEnum(RenameScope, payload[0]) catch return error.InvalidRenamePayload,
            .id = payload[1..][0..uuid_size].*,
            .label = payload[min_payload_size..],
        };
    }
};

// =========================================================================
// Multi-viewer: size mode and viewer state
// =========================================================================

pub const SizeMode = enum(u8) {
    smallest_wins = 0,
    leader_wins = 1,
};

pub const ViewerStateReason = enum(u8) {
    welcome = 0, // Sent to a joining viewer with full roster
    join = 1, // A new viewer joined
    leave = 2, // A viewer left
    control_change = 3, // Active controller changed (someone typed)
    size_change = 4, // Effective PTY size changed
    mode_change = 5, // Size mode changed
    name_change = 6, // Session label or color changed
};

/// Single viewer entry within a ViewerState payload.
pub const ViewerEntry = struct {
    id: Uuid,
    label: []const u8,
    is_controller: bool,
    rows: u16,
    cols: u16,
};

/// Payload for `viewer_state` (kind 20).
/// Sent to viewers on roster changes. Includes authoritative session state.
pub const ViewerState = struct {
    reason: ViewerStateReason,
    size_mode: SizeMode,
    controller_id: Uuid,
    effective_rows: u16,
    effective_cols: u16,
    session_color: i8 = -1,
    session_label: []const u8 = "",
    viewers: []const ViewerEntry,

    /// Fixed header: reason(1) + size_mode(1) + controller_id(16) + rows(2) + cols(2) +
    ///   session_color(1) + label_len(2) + viewer_count(2) = 27
    pub const fixed_size = 27;
    /// Per viewer: id(16) + label_len(2) + is_controller(1) + rows(2) + cols(2) = 23 + label
    pub const viewer_fixed_size = 23;

    pub fn encode(self: ViewerState, alloc: Allocator) ![]u8 {
        var total: usize = fixed_size + self.session_label.len;
        for (self.viewers) |v| {
            total += viewer_fixed_size + v.label.len;
        }
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.reason);
        buf[1] = @intFromEnum(self.size_mode);
        @memcpy(buf[2..18], &self.controller_id);
        std.mem.writeInt(u16, buf[18..20], self.effective_rows, .little);
        std.mem.writeInt(u16, buf[20..22], self.effective_cols, .little);
        // Session color + label
        buf[22] = @bitCast(self.session_color);
        std.mem.writeInt(u16, buf[23..25], @intCast(self.session_label.len), .little);
        // Viewer count
        std.mem.writeInt(u16, buf[25..27], @intCast(self.viewers.len), .little);

        // Session label (variable length, before viewer entries)
        var off: usize = fixed_size;
        @memcpy(buf[off..][0..self.session_label.len], self.session_label);
        off += self.session_label.len;

        for (self.viewers) |v| {
            @memcpy(buf[off..][0..uuid_size], &v.id);
            off += uuid_size;
            std.mem.writeInt(u16, buf[off..][0..2], @intCast(v.label.len), .little);
            off += 2;
            buf[off] = if (v.is_controller) 1 else 0;
            off += 1;
            std.mem.writeInt(u16, buf[off..][0..2], v.rows, .little);
            off += 2;
            std.mem.writeInt(u16, buf[off..][0..2], v.cols, .little);
            off += 2;
            @memcpy(buf[off..][0..v.label.len], v.label);
            off += v.label.len;
        }
        return buf;
    }

    pub fn parseHeader(payload: []const u8) !struct {
        reason: ViewerStateReason,
        size_mode: SizeMode,
        controller_id: Uuid,
        effective_rows: u16,
        effective_cols: u16,
        session_color: i8,
        session_label: []const u8,
        viewer_count: u16,
        remaining: []const u8,
    } {
        if (payload.len < fixed_size) return error.InvalidViewerStatePayload;
        const session_color: i8 = @bitCast(payload[22]);
        const label_len = std.mem.readInt(u16, payload[23..25], .little);
        const viewer_count = std.mem.readInt(u16, payload[25..27], .little);
        const label_end = fixed_size + label_len;
        if (payload.len < label_end) return error.InvalidViewerStatePayload;
        // Each viewer needs at least viewer_fixed_size bytes (label is variable on top).
        if (payload.len - label_end < @as(usize, viewer_count) * viewer_fixed_size)
            return error.InvalidViewerStatePayload;
        return .{
            .reason = std.meta.intToEnum(ViewerStateReason, payload[0]) catch return error.InvalidViewerStatePayload,
            .size_mode = std.meta.intToEnum(SizeMode, payload[1]) catch return error.InvalidViewerStatePayload,
            .controller_id = payload[2..18].*,
            .effective_rows = std.mem.readInt(u16, payload[18..20], .little),
            .effective_cols = std.mem.readInt(u16, payload[20..22], .little),
            .session_color = session_color,
            .session_label = payload[fixed_size..label_end],
            .viewer_count = viewer_count,
            .remaining = payload[label_end..],
        };
    }
};

/// Payload for `size_mode_change` (kind 21): single byte.
pub const SizeModeChange = struct {
    mode: SizeMode,

    pub fn encode(self: SizeModeChange) [1]u8 {
        return .{@intFromEnum(self.mode)};
    }

    pub fn parse(payload: []const u8) !SizeModeChange {
        if (payload.len < 1) return error.InvalidSizeModePayload;
        return .{
            .mode = std.meta.intToEnum(SizeMode, payload[0]) catch return error.InvalidSizeModePayload,
        };
    }
};

/// Payload for `session_meta` (kind 26): update session label + color atomically.
pub const SessionMeta = struct {
    group_id: Uuid,
    color: i8,
    label: []const u8,

    pub const min_size = uuid_size + 1 + 2; // group_id(16) + color(1) + label_len(2)

    pub fn encode(self: SessionMeta, alloc: Allocator) ![]u8 {
        const total = min_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        @memcpy(buf[0..uuid_size], &self.group_id);
        buf[uuid_size] = @bitCast(self.color);
        std.mem.writeInt(u16, buf[uuid_size + 1 ..][0..2], @intCast(self.label.len), .little);
        @memcpy(buf[min_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !SessionMeta {
        if (payload.len < min_size) return error.InvalidSessionMetaPayload;
        const label_len = std.mem.readInt(u16, payload[uuid_size + 1 ..][0..2], .little);
        if (payload.len < min_size + label_len) return error.InvalidSessionMetaPayload;
        return .{
            .group_id = payload[0..uuid_size].*,
            .color = @bitCast(payload[uuid_size]),
            .label = payload[min_size..][0..label_len],
        };
    }
};

// =========================================================================
// List response — structured binary (replaces per-entry text frames)
// =========================================================================

pub const ListStatus = enum(u8) {
    detached = 0,
    attached = 1,
    dead = 2,
};

/// Single entry in a list_response.
pub const ListEntry = struct {
    group_id: Uuid,
    status: ListStatus,
    surface_count: u16,
    alive_count: u16,
    created_at: i64,
    label: []const u8,
    /// Session color badge: -1 = none, 0-7 = color index.
    session_color: i8 = -1,
};

/// Payload for `list_response`:
///   [2] entry_count (u16 LE)
///   per entry:
///     [16] group_id
///     [1]  status
///     [2]  surface_count (u16 LE)
///     [2]  alive_count (u16 LE)
///     [8]  created_at (i64 LE)
///     [1]  session_color (i8, -1 = none)
///     [2]  label_len (u16 LE)
///     [label_len] label
pub const ListResponse = struct {
    entries: []const ListEntry,

    pub const entry_header_size = uuid_size + 1 + 2 + 2 + 8 + 1 + 2;

    pub fn encode(self: ListResponse, alloc: Allocator) ![]u8 {
        var total: usize = 2; // entry_count
        for (self.entries) |e| {
            total += entry_header_size + e.label.len;
        }
        const buf = try alloc.alloc(u8, total);
        std.mem.writeInt(u16, buf[0..2], @intCast(self.entries.len), .little);
        var offset: usize = 2;
        for (self.entries) |e| {
            @memcpy(buf[offset..][0..uuid_size], &e.group_id);
            offset += uuid_size;
            buf[offset] = @intFromEnum(e.status);
            offset += 1;
            std.mem.writeInt(u16, buf[offset..][0..2], e.surface_count, .little);
            offset += 2;
            std.mem.writeInt(u16, buf[offset..][0..2], e.alive_count, .little);
            offset += 2;
            std.mem.writeInt(i64, buf[offset..][0..8], e.created_at, .little);
            offset += 8;
            buf[offset] = @bitCast(e.session_color);
            offset += 1;
            const label_len: u16 = @intCast(e.label.len);
            std.mem.writeInt(u16, buf[offset..][0..2], label_len, .little);
            offset += 2;
            @memcpy(buf[offset..][0..e.label.len], e.label);
            offset += e.label.len;
        }
        return buf;
    }

    pub fn parse(alloc: Allocator, payload: []const u8) ![]ListEntry {
        if (payload.len < 2) return error.InvalidListPayload;
        const entry_count = std.mem.readInt(u16, payload[0..2], .little);
        const entries = try alloc.alloc(ListEntry, entry_count);
        errdefer alloc.free(entries);
        var offset: usize = 2;
        for (0..entry_count) |i| {
            if (offset + entry_header_size > payload.len) return error.InvalidListPayload;
            const group_id = payload[offset..][0..uuid_size].*;
            offset += uuid_size;
            const status = std.meta.intToEnum(ListStatus, payload[offset]) catch return error.InvalidListPayload;
            offset += 1;
            const surface_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            const alive_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            const created_at = std.mem.readInt(i64, payload[offset..][0..8], .little);
            offset += 8;
            const session_color: i8 = @bitCast(payload[offset]);
            offset += 1;
            const label_len = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            if (label_len > payload.len - offset) return error.InvalidListPayload;
            entries[i] = .{
                .group_id = group_id,
                .status = status,
                .surface_count = surface_count,
                .alive_count = alive_count,
                .created_at = created_at,
                .session_color = session_color,
                .label = payload[offset..][0..label_len],
            };
            offset += label_len;
        }
        return entries;
    }
};

// =========================================================================
// Opened frame — bundled response (eliminates round-trips on attach)
// =========================================================================

/// Payload for `opened`:
///   [16] group_id
///   [16] surface_id (which daemon surface was attached; zero for new sessions)
///   [4]  caps (u32 LE capability bitmask — bit 0: compression)
///   [4]  history_rows (u32 LE)
///   [2]  label_len (u16 LE)
///   [label_len] session label (daemon-authoritative)
///   [4]  layout_len (u32 LE, 0 = no layout)
///   [layout_len] layout blob
///   [2]  state_count (u16 LE, number of surface state snapshots)
///   per state_count:
///     [16] surface_id
///     [4]  state_len (u32 LE)
///     [state_len] full page snapshot (diff_type=1 data_out format)
pub const Opened = struct {
    group_id: Uuid,
    /// The daemon-side surface_id that was attached.
    surface_id: Uuid = zero_uuid,
    caps: u32 = 0,
    history_rows: u32 = 0,
    /// Daemon-authoritative session label. Set on first open, updated by rename.
    label: []const u8 = "",
    /// Session color (-1 = none, 0-7 = index). Deterministic from group UUID.
    color: i8 = -1,
    layout_blob: ?[]const u8 = null,
    states: []const SurfaceState = &.{},

    pub const SurfaceState = struct {
        surface_id: Uuid,
        data: []const u8,
    };

    /// Capability bits.
    pub const cap_compression: u32 = 1 << 0;

    pub fn encode(self: Opened, alloc: Allocator) ![]u8 {
        const layout_len: u32 = if (self.layout_blob) |b| @intCast(b.len) else 0;
        // uuid*2 + caps(4) + history_rows(4) + label_len(2) + label + color(1) + layout_len(4) + layout + state_count(2)
        var total: usize = uuid_size * 2 + 4 + 4 + 2 + self.label.len + 1 + 4 + layout_len + 2;
        for (self.states) |s| {
            total += uuid_size + 4 + s.data.len;
        }
        const buf = try alloc.alloc(u8, total);
        var offset: usize = 0;

        @memcpy(buf[offset..][0..uuid_size], &self.group_id);
        offset += uuid_size;
        @memcpy(buf[offset..][0..uuid_size], &self.surface_id);
        offset += uuid_size;
        std.mem.writeInt(u32, buf[offset..][0..4], self.caps, .little);
        offset += 4;
        std.mem.writeInt(u32, buf[offset..][0..4], self.history_rows, .little);
        offset += 4;
        // Label
        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(self.label.len), .little);
        offset += 2;
        @memcpy(buf[offset..][0..self.label.len], self.label);
        offset += self.label.len;
        // Color
        buf[offset] = @bitCast(self.color);
        offset += 1;
        std.mem.writeInt(u32, buf[offset..][0..4], layout_len, .little);
        offset += 4;
        if (self.layout_blob) |b| {
            @memcpy(buf[offset..][0..b.len], b);
            offset += b.len;
        }
        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(self.states.len), .little);
        offset += 2;
        for (self.states) |s| {
            @memcpy(buf[offset..][0..uuid_size], &s.surface_id);
            offset += uuid_size;
            std.mem.writeInt(u32, buf[offset..][0..4], @intCast(s.data.len), .little);
            offset += 4;
            @memcpy(buf[offset..][0..s.data.len], s.data);
            offset += s.data.len;
        }
        return buf;
    }

    pub fn parseHeader(payload: []const u8) !struct {
        group_id: Uuid,
        surface_id: Uuid,
        caps: u32,
        history_rows: u32,
        label: []const u8,
        color: i8,
        layout_blob: ?[]const u8,
        state_count: u16,
        remaining: []const u8,
    } {
        // uuid*2 + caps(4) + history_rows(4) + label_len(2) + color(1) + layout_len(4) + state_count(2)
        const min_size = uuid_size * 2 + 4 + 4 + 2 + 1 + 4 + 2;
        if (payload.len < min_size) return error.InvalidOpenedPayload;
        var offset: usize = 0;
        const group_id = payload[0..uuid_size].*;
        offset += uuid_size;
        const surface_id = payload[offset..][0..uuid_size].*;
        offset += uuid_size;
        const caps = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        const history_rows = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        // Label
        const label_len = std.mem.readInt(u16, payload[offset..][0..2], .little);
        offset += 2;
        if (label_len > payload.len - offset) return error.InvalidOpenedPayload;
        const label = payload[offset..][0..label_len];
        offset += label_len;
        // Remaining fixed fields: color(1) + layout_len(4) + state_count(2) = 7
        if (payload.len - offset < 7) return error.InvalidOpenedPayload;
        const color: i8 = @bitCast(payload[offset]);
        offset += 1;
        const layout_len = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        if (payload.len - offset < layout_len) return error.InvalidOpenedPayload;
        const layout_blob: ?[]const u8 = if (layout_len > 0)
            payload[offset..][0..layout_len]
        else
            null;
        offset += layout_len;
        // state_count already covered by the 7-byte check above
        const state_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
        offset += 2;
        return .{
            .group_id = group_id,
            .surface_id = surface_id,
            .caps = caps,
            .history_rows = history_rows,
            .label = label,
            .color = color,
            .layout_blob = layout_blob,
            .state_count = state_count,
            .remaining = payload[offset..],
        };
    }
};

// =========================================================================
// Scrollback response (proactive streaming from daemon)
// =========================================================================

/// Payload for `scrollback_response` (binary chunk format):
///   [4]  total_history_rows  (u32 LE: daemon's total history rows, for progress)
///   [4]  chunk_start_row     (u32 LE: absolute row from top of history)
///   [2]  row_count           (u16 LE: rows in this chunk, 0 = done marker)
///   [2]  cols                (u16 LE: column count)
///   [N]  chunk_data          (binary row/style data, serialized by page_diff)
pub const ScrollbackResponse = struct {
    total_history_rows: u32,
    chunk_start_row: u32,
    row_count: u16,
    cols: u16,
    chunk_data: []const u8,

    pub const hdr_size: usize = 12;

    pub fn encode(self: ScrollbackResponse, alloc: Allocator) ![]u8 {
        const total = hdr_size + self.chunk_data.len;
        const buf = try alloc.alloc(u8, total);
        std.mem.writeInt(u32, buf[0..4], self.total_history_rows, .little);
        std.mem.writeInt(u32, buf[4..8], self.chunk_start_row, .little);
        std.mem.writeInt(u16, buf[8..10], self.row_count, .little);
        std.mem.writeInt(u16, buf[10..12], self.cols, .little);
        @memcpy(buf[hdr_size..], self.chunk_data);
        return buf;
    }

    pub fn parse(payload: []const u8) !ScrollbackResponse {
        if (payload.len < hdr_size) return error.InvalidScrollbackResponse;
        return .{
            .total_history_rows = std.mem.readInt(u32, payload[0..4], .little),
            .chunk_start_row = std.mem.readInt(u32, payload[4..8], .little),
            .row_count = std.mem.readInt(u16, payload[8..10], .little),
            .cols = std.mem.readInt(u16, payload[10..12], .little),
            .chunk_data = payload[hdr_size..],
        };
    }
};

// =========================================================================
// Resize (unchanged from v6)
// =========================================================================

// Compatibility shim for two different Zig reader APIs: older versions expose
// `readNoEof` while newer versions use `readSliceAll`. This dispatches at
// comptime so the protocol code works with both.
fn hasReaderMethod(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .pointer => |ptr| @hasDecl(ptr.child, name),
        else => @hasDecl(T, name),
    };
}

fn readExact(reader: anytype, buffer: []u8) !void {
    const T = @TypeOf(reader);
    if (comptime hasReaderMethod(T, "readSliceAll")) {
        try reader.readSliceAll(buffer);
        return;
    }
    if (comptime hasReaderMethod(T, "readNoEof")) {
        try reader.readNoEof(buffer);
        return;
    }
    @compileError("unsupported reader type");
}

pub const Resize = packed struct {
    rows: u16,
    cols: u16,
    width_px: u16,
    height_px: u16,

    pub fn bytes(self: Resize) [8]u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], self.rows, .little);
        std.mem.writeInt(u16, buf[2..4], self.cols, .little);
        std.mem.writeInt(u16, buf[4..6], self.width_px, .little);
        std.mem.writeInt(u16, buf[6..8], self.height_px, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !Resize {
        if (payload.len != 8) return error.InvalidResizePayload;
        return .{
            .rows = std.mem.readInt(u16, payload[0..2], .little),
            .cols = std.mem.readInt(u16, payload[2..4], .little),
            .width_px = std.mem.readInt(u16, payload[4..6], .little),
            .height_px = std.mem.readInt(u16, payload[6..8], .little),
        };
    }
};

// =========================================================================
// Capabilities frame (kind 27)
// =========================================================================
//
// Sent by both daemon and client immediately after the banner exchange, so
// each side can negotiate which channel services / features the other
// supports. The effective set is the intersection. Channels whose service
// id is not advertised in the peer's Capabilities frame are rejected at
// open time with status=service_not_supported.

/// Identifies a single channel service in a Capabilities frame.
pub const CapabilityService = struct {
    /// Service id (matches ChannelOpen.service_id below).
    id: u8,
    /// Human-readable service name, e.g. "tcp_connect", "browser_proxy".
    /// Used for diagnostics and as the lookup key for the `custom` service.
    name: []const u8,
};

/// Compression algorithm identifier for per-channel compression negotiation.
/// 0 = none, 1 = LZ4 (currently the only supported algo). Future algos may
/// add values without bumping the protocol version, gated by the
/// Capabilities exchange.
pub const CompressionAlgo = enum(u8) {
    none = 0,
    lz4 = 1,
    _,
};

/// Payload for `capabilities` (kind 27):
///   [2]   protocol_version u16 LE
///   [4]   feature_bits     u32 LE
///   [2]   service_count    u16 LE
///   per service:
///     [1] service_id       u8
///     [2] name_len         u16 LE
///     [N] name bytes (UTF-8)
///   [2]   default_window   u16 LE (in 4 KiB units; 0 = use protocol default)
///   [2]   max_window       u16 LE (in 4 KiB units; cap on opener-requested window)
///   [2]   max_payload      u16 LE (in KiB; e.g. 256 for the current 256 KiB cap)
///   [1]   compression_algo u8
pub const Capabilities = struct {
    protocol_version: u16,
    feature_bits: u32 = 0,
    services: []const CapabilityService,
    default_window: u16 = 0,
    max_window: u16 = 0,
    max_payload_kib: u16 = 0,
    compression_algo: CompressionAlgo = .lz4,

    /// Fixed-size bytes excluding the variable services list:
    /// protocol_version(2) + feature_bits(4) + service_count(2) +
    /// default_window(2) + max_window(2) + max_payload(2) + compression_algo(1).
    pub const fixed_size: usize = 2 + 4 + 2 + 2 + 2 + 2 + 1;

    /// Per-service fixed bytes (excluding name): id(1) + name_len(2).
    pub const service_fixed_size: usize = 1 + 2;

    pub fn encode(self: Capabilities, alloc: Allocator) ![]u8 {
        var total: usize = fixed_size;
        for (self.services) |s| {
            total += service_fixed_size + s.name.len;
        }
        const buf = try alloc.alloc(u8, total);
        var off: usize = 0;
        std.mem.writeInt(u16, buf[off..][0..2], self.protocol_version, .little);
        off += 2;
        std.mem.writeInt(u32, buf[off..][0..4], self.feature_bits, .little);
        off += 4;
        std.mem.writeInt(u16, buf[off..][0..2], @intCast(self.services.len), .little);
        off += 2;
        for (self.services) |s| {
            buf[off] = s.id;
            off += 1;
            std.mem.writeInt(u16, buf[off..][0..2], @intCast(s.name.len), .little);
            off += 2;
            @memcpy(buf[off..][0..s.name.len], s.name);
            off += s.name.len;
        }
        std.mem.writeInt(u16, buf[off..][0..2], self.default_window, .little);
        off += 2;
        std.mem.writeInt(u16, buf[off..][0..2], self.max_window, .little);
        off += 2;
        std.mem.writeInt(u16, buf[off..][0..2], self.max_payload_kib, .little);
        off += 2;
        buf[off] = @intFromEnum(self.compression_algo);
        return buf;
    }

    /// Parses the header + services list into a borrowed view. The returned
    /// `services` slice points into a freshly-allocated array owned by the
    /// caller (free via `alloc.free`); each `service.name` borrows from
    /// `payload`.
    pub fn parse(alloc: Allocator, payload: []const u8) !Capabilities {
        // Minimum without any services: fixed_size, with service_count = 0.
        if (payload.len < fixed_size) return error.InvalidCapabilitiesPayload;
        var off: usize = 0;
        const protocol_v = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const feature_bits = std.mem.readInt(u32, payload[off..][0..4], .little);
        off += 4;
        const service_count = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;

        const services = try alloc.alloc(CapabilityService, service_count);
        errdefer alloc.free(services);

        for (0..service_count) |i| {
            if (off + service_fixed_size > payload.len) return error.InvalidCapabilitiesPayload;
            const id = payload[off];
            off += 1;
            const name_len = std.mem.readInt(u16, payload[off..][0..2], .little);
            off += 2;
            if (name_len > payload.len - off) return error.InvalidCapabilitiesPayload;
            services[i] = .{ .id = id, .name = payload[off..][0..name_len] };
            off += name_len;
        }

        // Trailing fixed fields: default_window(2) + max_window(2) +
        // max_payload(2) + compression_algo(1) = 7 bytes.
        if (payload.len - off < 7) return error.InvalidCapabilitiesPayload;
        const default_window = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const max_window = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const max_payload_kib = std.mem.readInt(u16, payload[off..][0..2], .little);
        off += 2;
        const compression_algo: CompressionAlgo = @enumFromInt(payload[off]);

        return .{
            .protocol_version = protocol_v,
            .feature_bits = feature_bits,
            .services = services,
            .default_window = default_window,
            .max_window = max_window,
            .max_payload_kib = max_payload_kib,
            .compression_algo = compression_algo,
        };
    }
};

// =========================================================================
// Generic multiplexed channels (kinds 30-36)
// =========================================================================
//
// All channel frames carry their channel_id as the first 4 bytes of the
// payload. The 8-byte frame header's `target` field is reserved (must be 0)
// for channel frames so the existing terminal-surface multiplexer on
// `target` does not collide with channel multiplexing.
//
// Direction convention: opener picks the channel_id; daemon-originated
// channels (e.g. an inbound TCP accept on a port_listener service) set the
// high bit (`channel_id & 0x8000_0000 != 0`). This avoids a central
// allocator across both directions and matches SSH channel-direction
// semantics.

/// Default initial credit window for a new channel, in 4 KiB units.
/// 1 MiB. Opener may declare smaller for memory-bounded services.
pub const default_channel_window_units: u16 = 256;

/// Hard upper bound on per-channel window in 4 KiB units (16 MiB).
/// Used to bound per-channel inbound buffering.
pub const max_channel_window_units: u16 = 4096;

/// Channel id value used for "no channel" / invalid. Both 0 and the
/// daemon-direction marker bit are valid; only this sentinel is reserved
/// for explicit "unset" sentinels in fields that can omit a channel id.
pub const invalid_channel_id: u32 = std.math.maxInt(u32);

/// Bit on `channel_id` indicating the channel was opened by the daemon
/// side (as opposed to the client side). See direction convention above.
pub const channel_id_daemon_bit: u32 = 0x8000_0000;

/// Service identifier for `ChannelOpen`. Matches the registry on the
/// daemon side. Values 0 and 255 are reserved (invalid sentinel and
/// `custom` escape hatch respectively).
pub const ChannelService = enum(u8) {
    invalid = 0,
    tcp_connect = 1,
    port_listener = 2,
    file_transfer = 3,
    browser_proxy = 4,
    process_exec = 5,
    /// cmux control reverse channel. The daemon listens on a remote-side
    /// unix socket (path injected into the remote shell via
    /// `CMUX_SOCKET_PATH`) and forwards each framed CLI request received
    /// there back to the client over a daemon-originated channel of this
    /// service. The client runs the request through its in-process socket
    /// dispatcher (notify / notify_target / report_*) and writes the
    /// response back. Wire id 7 — the first free slot above the
    /// spec-defined services and below the `tcp_accepted` daemon-internal
    /// id (which uses the reserved-range value, see services/tcp_accepted.zig).
    cmux_control = 7,
    custom = 255,
    _,
};

/// Flags for ChannelOpen / ChannelOpened, packed into the `flags` byte
/// inside the payload (separate from the header's `Flags` byte).
pub const ChannelOpenFlags = packed struct(u8) {
    /// Opener can decompress inbound data (and asks daemon to compress).
    /// Daemon echoes this bit in `ChannelOpened.flags` to commit. When
    /// both sides set it, individual `channel_data` frames opt in via
    /// the header `Flags.compressed` bit on a per-frame basis.
    compression: bool = false,
    /// Channel will not carry upstream (opener → peer) data. Hint for
    /// services like file downloads that pre-allocate buffers.
    unidirectional_download: bool = false,
    _reserved: u6 = 0,
};

/// Status code returned in ChannelOpened. 0 = ok; nonzero = error and
/// the channel is dead (no further frames will be sent for this id).
pub const ChannelOpenStatus = enum(u8) {
    ok = 0,
    /// Service id was not advertised in the peer's Capabilities.
    service_not_supported = 1,
    /// Service-level error (e.g. TCP dial failed, file path denied).
    service_error = 2,
    /// Too many concurrent channels; opener should back off.
    resource_exhausted = 3,
    /// Malformed open request (bad params, invalid window, etc.).
    invalid_request = 4,
    /// Peer policy rejected the open (sandboxing, auth, etc.).
    policy_denied = 5,
    _,
};

/// Reason for ChannelClose. Both sides may close unilaterally; any
/// further frames carrying the channel id are discarded.
pub const ChannelCloseReason = enum(u8) {
    normal = 0,
    /// The peer violated the protocol (e.g. window overrun).
    peer_reset = 1,
    /// Service raised an error (e.g. TCP connection dropped).
    service_error = 2,
    /// Policy / sandbox decision.
    policy_denied = 3,
    /// No traffic for too long (stall watchdog).
    idle_timeout = 4,
    /// Daemon is shutting down; all channels on this connection close.
    daemon_shutdown = 5,
    _,
};

/// Payload for `channel_open` (kind 30):
///   [4]  channel_id     u32 LE (opener-chosen; high bit set if daemon-origin)
///   [1]  service_id     u8
///   [1]  flags          u8 (ChannelOpenFlags bitfield)
///   [2]  initial_window u16 LE (4 KiB units; 0 = use default_channel_window_units)
///   [2]  reserved       u16 LE (must be 0)
///   [N]  service_params bytes (service-defined; may be empty)
pub const ChannelOpen = struct {
    channel_id: u32,
    service: ChannelService,
    flags: ChannelOpenFlags = .{},
    initial_window: u16 = 0,
    service_params: []const u8 = "",

    /// Fixed bytes: channel_id(4) + service_id(1) + flags(1) + initial_window(2) + reserved(2).
    pub const fixed_size: usize = 4 + 1 + 1 + 2 + 2;

    pub fn encode(self: ChannelOpen, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.service_params.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.service);
        buf[5] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[6..8], self.initial_window, .little);
        std.mem.writeInt(u16, buf[8..10], 0, .little);
        @memcpy(buf[fixed_size..], self.service_params);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelOpen {
        if (payload.len < fixed_size) return error.InvalidChannelOpenPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .service = @enumFromInt(payload[4]),
            .flags = @bitCast(payload[5]),
            .initial_window = std.mem.readInt(u16, payload[6..8], .little),
            .service_params = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_opened` (kind 31):
///   [4]  channel_id  u32 LE (echoes the opener's id)
///   [1]  status      u8 (ChannelOpenStatus)
///   [1]  flags       u8 (negotiated ChannelOpenFlags — bits opener AND daemon set)
///   [2]  peer_window u16 LE (4 KiB units the daemon grants the opener)
///   [2]  reserved    u16 LE
///   [N]  service_ack bytes (service-defined; error message on failure)
pub const ChannelOpened = struct {
    channel_id: u32,
    status: ChannelOpenStatus,
    flags: ChannelOpenFlags = .{},
    peer_window: u16 = 0,
    service_ack: []const u8 = "",

    pub const fixed_size: usize = 4 + 1 + 1 + 2 + 2;

    pub fn encode(self: ChannelOpened, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.service_ack.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.status);
        buf[5] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[6..8], self.peer_window, .little);
        std.mem.writeInt(u16, buf[8..10], 0, .little);
        @memcpy(buf[fixed_size..], self.service_ack);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelOpened {
        if (payload.len < fixed_size) return error.InvalidChannelOpenedPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .status = @enumFromInt(payload[4]),
            .flags = @bitCast(payload[5]),
            .peer_window = std.mem.readInt(u16, payload[6..8], .little),
            .service_ack = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_data` (kind 32):
///   [4]  channel_id u32 LE
///   [N]  bytes      (raw data; LZ4 via header `Flags.compressed`)
pub const ChannelData = struct {
    channel_id: u32,
    bytes: []const u8,

    pub const fixed_size: usize = 4;

    pub fn encode(self: ChannelData, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.bytes.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        @memcpy(buf[fixed_size..], self.bytes);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelData {
        if (payload.len < fixed_size) return error.InvalidChannelDataPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .bytes = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_window` (kind 33):
///   [4]  channel_id   u32 LE
///   [4]  credit_bytes u32 LE (additional outbound credit, in bytes, cumulative)
pub const ChannelWindow = struct {
    channel_id: u32,
    credit_bytes: u32,

    pub const size: usize = 8;

    pub fn encode(self: ChannelWindow) [size]u8 {
        var buf: [size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        std.mem.writeInt(u32, buf[4..8], self.credit_bytes, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelWindow {
        if (payload.len < size) return error.InvalidChannelWindowPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .credit_bytes = std.mem.readInt(u32, payload[4..8], .little),
        };
    }
};

/// Payload for `channel_eof` (kind 34):
///   [4]  channel_id u32 LE
///
/// "Sender will send no more `channel_data` frames on this channel." The
/// peer may still send (full-duplex half-close). After both sides EOF,
/// either side may send Close.
pub const ChannelEof = struct {
    channel_id: u32,

    pub const size: usize = 4;

    pub fn encode(self: ChannelEof) [size]u8 {
        var buf: [size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelEof {
        if (payload.len < size) return error.InvalidChannelEofPayload;
        return .{ .channel_id = std.mem.readInt(u32, payload[0..4], .little) };
    }
};

/// Payload for `channel_close` (kind 35):
///   [4]  channel_id u32 LE
///   [1]  reason     u8 (ChannelCloseReason)
///   [N]  message    UTF-8 bytes (may be empty)
///
/// Unilateral and final; any further frames carrying this id are
/// discarded by the receiver.
pub const ChannelClose = struct {
    channel_id: u32,
    reason: ChannelCloseReason,
    message: []const u8 = "",

    pub const fixed_size: usize = 4 + 1;

    pub fn encode(self: ChannelClose, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.message.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = @intFromEnum(self.reason);
        @memcpy(buf[fixed_size..], self.message);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelClose {
        if (payload.len < fixed_size) return error.InvalidChannelClosePayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .reason = @enumFromInt(payload[4]),
            .message = payload[fixed_size..],
        };
    }
};

/// Payload for `channel_control` (kind 36):
///   [4]  channel_id u32 LE
///   [1]  op         u8 (service-defined opcode)
///   [N]  op_payload bytes (service-defined; may be empty)
///
/// Ordered with `channel_data` on the same channel. Used for service-
/// specific signals like file-transfer progress, port-listener
/// pause/resume, TCP RST instead of FIN, etc.
pub const ChannelControl = struct {
    channel_id: u32,
    op: u8,
    op_payload: []const u8 = "",

    pub const fixed_size: usize = 4 + 1;

    pub fn encode(self: ChannelControl, alloc: Allocator) ![]u8 {
        const buf = try alloc.alloc(u8, fixed_size + self.op_payload.len);
        std.mem.writeInt(u32, buf[0..4], self.channel_id, .little);
        buf[4] = self.op;
        @memcpy(buf[fixed_size..], self.op_payload);
        return buf;
    }

    pub fn parse(payload: []const u8) !ChannelControl {
        if (payload.len < fixed_size) return error.InvalidChannelControlPayload;
        return .{
            .channel_id = std.mem.readInt(u32, payload[0..4], .little),
            .op = payload[4],
            .op_payload = payload[fixed_size..],
        };
    }
};

// =========================================================================
// Frame I/O
// =========================================================================

/// Write a frame (8-byte header + payload) to the given writer.
pub fn writeFrame(
    writer: anytype,
    kind: Kind,
    target: u16,
    payload: []const u8,
) !void {
    try writeFrameFlags(writer, kind, .{}, target, payload);
}

/// Write a frame with explicit flags.
pub fn writeFrameFlags(
    writer: anytype,
    kind: Kind,
    flags: Flags,
    target: u16,
    payload: []const u8,
) !void {
    if (payload.len > max_payload) return error.PayloadTooLarge;

    const header = (Header{
        .kind = kind,
        .flags = flags,
        .target = target,
        .len = @intCast(payload.len),
    }).encodeToBuf();
    try writer.writeAll(&header);
    try writer.writeAll(payload);
}

pub fn writeResize(writer: anytype, target: u16, resize: Resize) !void {
    const resize_bytes = resize.bytes();
    try writeFrame(writer, .resize, target, &resize_bytes);
}

pub fn readHeader(reader: anytype) !Header {
    var header: [header_size]u8 = undefined;
    try readExact(reader, &header);
    return Header.parseFromBuf(&header);
}

pub fn readPayloadAlloc(
    alloc: Allocator,
    reader: anytype,
    header: Header,
) ![]u8 {
    if (header.len > max_payload) return error.PayloadTooLarge;
    const payload = try alloc.alloc(u8, header.len);
    errdefer alloc.free(payload);
    try readExact(reader, payload);
    return payload;
}

// =========================================================================
// Tests
// =========================================================================

test "protocol roundtrip" {
    const testing = std.testing;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);

    try writeFrame(buf.writer(testing.allocator), .data_out, 42, "hello");

    var stream = std.io.fixedBufferStream(buf.items);
    const header = try readHeader(stream.reader());
    try testing.expectEqual(.data_out, header.kind);
    try testing.expectEqual(@as(u16, 42), header.target);
    try testing.expectEqual(Flags{}, header.flags);
    const payload = try readPayloadAlloc(testing.allocator, stream.reader(), header);
    defer testing.allocator.free(payload);
    try testing.expectEqualStrings("hello", payload);
}

test "protocol version is 1" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 1), protocol_version);
}

test "header parseFromBuf/encodeToBuf roundtrip" {
    const testing = std.testing;
    const h = Header{
        .kind = .data_out,
        .flags = .{ .compressed = true },
        .target = 42,
        .len = 12345,
    };
    const buf = h.encodeToBuf();
    const parsed = try Header.parseFromBuf(&buf);
    try testing.expectEqual(h.kind, parsed.kind);
    try testing.expect(parsed.flags.compressed);
    try testing.expectEqual(@as(u16, 42), parsed.target);
    try testing.expectEqual(@as(u32, 12345), parsed.len);
}

test "flags roundtrip" {
    const testing = std.testing;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);

    try writeFrameFlags(buf.writer(testing.allocator), .data_out, .{ .compressed = true }, 1, "test");

    var stream = std.io.fixedBufferStream(buf.items);
    const header = try readHeader(stream.reader());
    try testing.expect(header.flags.compressed);
    try testing.expectEqual(.data_out, header.kind);
}

test "open encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const sid = shared.generateUuid();
    const gid = shared.generateUuid();
    const o = Open{
        .open_type = .session_new,
        .group_id = gid,
        .surface_id = sid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .max_scrollback = 10_000_000,
        .label = "test-session",
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Open.parse(encoded);
    try testing.expectEqual(OpenType.session_new, parsed.open_type);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqual(@as(u32, 10_000_000), parsed.max_scrollback);
    try testing.expectEqualStrings("test-session", parsed.label);
}

// Legacy backward-compat test removed — only current format is supported.

test "open attach mode" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const o = Open{
        .open_type = .session_attach,
        .group_id = gid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Open.parse(encoded);
    try testing.expectEqual(OpenType.session_attach, parsed.open_type);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
}

test "close encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const sid = shared.generateUuid();

    // Surface close
    const c1 = Close{ .mode = .surface, .id = sid };
    const e1 = try c1.encode(testing.allocator);
    defer testing.allocator.free(e1);
    const p1 = try Close.parse(e1);
    try testing.expectEqual(CloseMode.surface, p1.mode);
    try testing.expectEqualSlices(u8, &sid, &p1.id);

    // Detach (no UUID)
    const c2 = Close{ .mode = .detach };
    const e2 = try c2.encode(testing.allocator);
    defer testing.allocator.free(e2);
    try testing.expectEqual(@as(usize, 1), e2.len);
    const p2 = try Close.parse(e2);
    try testing.expectEqual(CloseMode.detach, p2.mode);
}

test "list response encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");

    const entries = [_]ListEntry{
        .{
            .group_id = shared.generateUuid(),
            .status = .attached,
            .surface_count = 3,
            .alive_count = 2,
            .created_at = 1700000000,
            .session_color = 5,
            .label = "my-session",
        },
        .{
            .group_id = shared.generateUuid(),
            .status = .detached,
            .surface_count = 1,
            .alive_count = 1,
            .created_at = 1700001000,
            .session_color = -1,
            .label = "other",
        },
    };

    const resp = ListResponse{ .entries = &entries };
    const encoded = try resp.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ListResponse.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqual(ListStatus.attached, parsed[0].status);
    try testing.expectEqual(@as(u16, 3), parsed[0].surface_count);
    try testing.expectEqual(@as(u16, 2), parsed[0].alive_count);
    try testing.expectEqual(@as(i8, 5), parsed[0].session_color);
    try testing.expectEqualStrings("my-session", parsed[0].label);
    try testing.expectEqual(ListStatus.detached, parsed[1].status);
    try testing.expectEqual(@as(i8, -1), parsed[1].session_color);
    try testing.expectEqualStrings("other", parsed[1].label);
}

test "rename encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();

    const r = Rename{ .scope = .group, .id = gid, .label = "new-name" };
    const encoded = try r.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Rename.parse(encoded);
    try testing.expectEqual(RenameScope.group, parsed.scope);
    try testing.expectEqualSlices(u8, &gid, &parsed.id);
    try testing.expectEqualStrings("new-name", parsed.label);
}

test "opened encode/parse header" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const sid = shared.generateUuid();

    const layout_data = "fake-layout";
    const o = Opened{
        .group_id = gid,
        .surface_id = sid,
        .caps = Opened.cap_compression,
        .layout_blob = layout_data,
        .states = &.{},
    };
    const encoded = try o.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Opened.parseHeader(encoded);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
    try testing.expectEqual(Opened.cap_compression, parsed.caps);
    try testing.expectEqual(@as(u32, 0), parsed.history_rows);
    try testing.expectEqualStrings("fake-layout", parsed.layout_blob.?);
    try testing.expectEqual(@as(u16, 0), parsed.state_count);
}

test "scrollback_response encode/parse" {
    const testing = std.testing;

    const chunk_data = "fake-binary-chunk";
    const resp = ScrollbackResponse{
        .total_history_rows = 5000,
        .chunk_start_row = 100,
        .row_count = 25,
        .cols = 80,
        .chunk_data = chunk_data,
    };
    const encoded = try resp.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ScrollbackResponse.parse(encoded);
    try testing.expectEqual(@as(u32, 5000), parsed.total_history_rows);
    try testing.expectEqual(@as(u32, 100), parsed.chunk_start_row);
    try testing.expectEqual(@as(u16, 25), parsed.row_count);
    try testing.expectEqual(@as(u16, 80), parsed.cols);
    try testing.expectEqualStrings(chunk_data, parsed.chunk_data);
}

test "scrollback_response rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidScrollbackResponse, ScrollbackResponse.parse(&short));
}

test "viewer_state encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const v1_id = shared.generateUuid();
    const v2_id = shared.generateUuid();

    const state = ViewerState{
        .reason = .join,
        .size_mode = .smallest_wins,
        .controller_id = v1_id,
        .effective_rows = 24,
        .effective_cols = 80,
        .viewers = &.{
            .{ .id = v1_id, .label = "user@laptop", .is_controller = true, .rows = 24, .cols = 80 },
            .{ .id = v2_id, .label = "user@desktop", .is_controller = false, .rows = 40, .cols = 120 },
        },
    };
    const encoded = try state.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const hdr = try ViewerState.parseHeader(encoded);
    try testing.expectEqual(ViewerStateReason.join, hdr.reason);
    try testing.expectEqual(SizeMode.smallest_wins, hdr.size_mode);
    try testing.expectEqualSlices(u8, &v1_id, &hdr.controller_id);
    try testing.expectEqual(@as(u16, 24), hdr.effective_rows);
    try testing.expectEqual(@as(u16, 80), hdr.effective_cols);
    try testing.expectEqual(@as(u16, 2), hdr.viewer_count);
}

test "size_mode_change encode/parse" {
    const testing = std.testing;
    const change = SizeModeChange{ .mode = .leader_wins };
    const encoded = change.encode();
    const parsed = try SizeModeChange.parse(&encoded);
    try testing.expectEqual(SizeMode.leader_wins, parsed.mode);
}

test "compressed flag in header" {
    const testing = std.testing;
    const flags = Flags{ .compressed = true };
    try testing.expect(flags.compressed);

    const no_comp = Flags{};
    try testing.expect(!no_comp.compressed);

    // Roundtrip through header
    const h = Header{ .kind = .data_out, .flags = flags, .target = 1, .len = 100 };
    const buf = h.encodeToBuf();
    const parsed = try Header.parseFromBuf(&buf);
    try testing.expect(parsed.flags.compressed);
}

// =========================================================================
// Channel & Capabilities tests (Phase 6A.1 codec scaffold)
// =========================================================================

test "capabilities encode/parse — empty services list" {
    const testing = std.testing;
    const caps = Capabilities{
        .protocol_version = protocol_version,
        .services = &.{},
        .default_window = default_channel_window_units,
        .max_window = max_channel_window_units,
        .max_payload_kib = max_payload / 1024,
        .compression_algo = .lz4,
    };
    const encoded = try caps.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(Capabilities.fixed_size, encoded.len);

    const parsed = try Capabilities.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed.services);
    try testing.expectEqual(@as(u16, protocol_version), parsed.protocol_version);
    try testing.expectEqual(@as(u32, 0), parsed.feature_bits);
    try testing.expectEqual(@as(usize, 0), parsed.services.len);
    try testing.expectEqual(default_channel_window_units, parsed.default_window);
    try testing.expectEqual(max_channel_window_units, parsed.max_window);
    try testing.expectEqual(@as(u16, max_payload / 1024), parsed.max_payload_kib);
    try testing.expectEqual(CompressionAlgo.lz4, parsed.compression_algo);
}

test "capabilities encode/parse — full service catalog" {
    const testing = std.testing;
    const services = [_]CapabilityService{
        .{ .id = @intFromEnum(ChannelService.tcp_connect), .name = "tcp_connect" },
        .{ .id = @intFromEnum(ChannelService.port_listener), .name = "port_listener" },
        .{ .id = @intFromEnum(ChannelService.file_transfer), .name = "file_transfer" },
        .{ .id = @intFromEnum(ChannelService.browser_proxy), .name = "browser_proxy" },
        .{ .id = @intFromEnum(ChannelService.process_exec), .name = "process_exec" },
        .{ .id = @intFromEnum(ChannelService.custom), .name = "custom" },
    };
    const caps = Capabilities{
        .protocol_version = protocol_version,
        .feature_bits = 0b101,
        .services = &services,
        .default_window = default_channel_window_units,
        .max_window = max_channel_window_units,
        .max_payload_kib = 256,
        .compression_algo = .lz4,
    };
    const encoded = try caps.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try Capabilities.parse(testing.allocator, encoded);
    defer testing.allocator.free(parsed.services);
    try testing.expectEqual(@as(usize, services.len), parsed.services.len);
    try testing.expectEqual(@as(u32, 0b101), parsed.feature_bits);
    for (services, parsed.services) |orig, got| {
        try testing.expectEqual(orig.id, got.id);
        try testing.expectEqualStrings(orig.name, got.name);
    }
}

test "capabilities rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidCapabilitiesPayload, Capabilities.parse(testing.allocator, &short));
}

test "capabilities rejects truncated service name" {
    const testing = std.testing;
    // Manually craft: protocol_version=1, feature_bits=0, service_count=1,
    // service_id=1, name_len=10 — but supply only 2 bytes of name.
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &.{ 1, 0 }); // protocol_version
    try buf.appendSlice(testing.allocator, &.{ 0, 0, 0, 0 }); // feature_bits
    try buf.appendSlice(testing.allocator, &.{ 1, 0 }); // service_count = 1
    try buf.appendSlice(testing.allocator, &.{1}); // service_id = 1
    try buf.appendSlice(testing.allocator, &.{ 10, 0 }); // name_len = 10
    try buf.appendSlice(testing.allocator, "ab"); // only 2 bytes of name
    try testing.expectError(error.InvalidCapabilitiesPayload, Capabilities.parse(testing.allocator, buf.items));
}

test "channel_open encode/parse roundtrip" {
    const testing = std.testing;
    const params = "host\x00\x50\x00"; // arbitrary opaque service params
    const open = ChannelOpen{
        .channel_id = 0x1234_5678,
        .service = .tcp_connect,
        .flags = .{ .compression = true },
        .initial_window = 128,
        .service_params = params,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelOpen.fixed_size + params.len, encoded.len);

    const parsed = try ChannelOpen.parse(encoded);
    try testing.expectEqual(@as(u32, 0x1234_5678), parsed.channel_id);
    try testing.expectEqual(ChannelService.tcp_connect, parsed.service);
    try testing.expect(parsed.flags.compression);
    try testing.expect(!parsed.flags.unidirectional_download);
    try testing.expectEqual(@as(u16, 128), parsed.initial_window);
    try testing.expectEqualSlices(u8, params, parsed.service_params);
}

test "channel_open encodes empty service_params" {
    const testing = std.testing;
    const open = ChannelOpen{
        .channel_id = 1,
        .service = .browser_proxy,
        .initial_window = 0,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelOpen.fixed_size, encoded.len);
    const parsed = try ChannelOpen.parse(encoded);
    try testing.expectEqual(@as(usize, 0), parsed.service_params.len);
    try testing.expectEqual(ChannelService.browser_proxy, parsed.service);
}

test "channel_open with daemon-direction high bit" {
    const testing = std.testing;
    const open = ChannelOpen{
        .channel_id = channel_id_daemon_bit | 7,
        .service = .tcp_connect,
        .initial_window = default_channel_window_units,
    };
    const encoded = try open.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    const parsed = try ChannelOpen.parse(encoded);
    try testing.expect((parsed.channel_id & channel_id_daemon_bit) != 0);
    try testing.expectEqual(@as(u32, 7), parsed.channel_id & ~channel_id_daemon_bit);
}

test "channel_open rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidChannelOpenPayload, ChannelOpen.parse(&short));
}

test "channel_opened encode/parse roundtrip" {
    const testing = std.testing;
    const ack = "remote_port=8080";
    const opened = ChannelOpened{
        .channel_id = 0xDEAD_BEEF,
        .status = .ok,
        .flags = .{ .compression = true },
        .peer_window = 256,
        .service_ack = ack,
    };
    const encoded = try opened.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelOpened.parse(encoded);
    try testing.expectEqual(@as(u32, 0xDEAD_BEEF), parsed.channel_id);
    try testing.expectEqual(ChannelOpenStatus.ok, parsed.status);
    try testing.expect(parsed.flags.compression);
    try testing.expectEqual(@as(u16, 256), parsed.peer_window);
    try testing.expectEqualStrings(ack, parsed.service_ack);
}

test "channel_opened carries error message on failure" {
    const testing = std.testing;
    const msg = "dial failed: connection refused";
    const opened = ChannelOpened{
        .channel_id = 1,
        .status = .service_error,
        .service_ack = msg,
    };
    const encoded = try opened.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    const parsed = try ChannelOpened.parse(encoded);
    try testing.expectEqual(ChannelOpenStatus.service_error, parsed.status);
    try testing.expectEqualStrings(msg, parsed.service_ack);
}

test "channel_data encode/parse — empty payload" {
    const testing = std.testing;
    const data = ChannelData{ .channel_id = 42, .bytes = "" };
    const encoded = try data.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelData.fixed_size, encoded.len);
    const parsed = try ChannelData.parse(encoded);
    try testing.expectEqual(@as(u32, 42), parsed.channel_id);
    try testing.expectEqual(@as(usize, 0), parsed.bytes.len);
}

test "channel_data encode/parse — payload at max_payload boundary" {
    const testing = std.testing;
    // ChannelData payload = channel_id(4) + bytes. The header `len` field
    // caps the total frame payload at `max_payload`, so the data slice
    // can be up to max_payload - 4 bytes long. Pick a realistic large
    // size that still fits.
    const big = try testing.allocator.alloc(u8, max_payload - ChannelData.fixed_size);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);

    const data = ChannelData{ .channel_id = 1, .bytes = big };
    const encoded = try data.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(usize, max_payload), encoded.len);

    const parsed = try ChannelData.parse(encoded);
    try testing.expectEqual(@as(u32, 1), parsed.channel_id);
    try testing.expectEqualSlices(u8, big, parsed.bytes);
}

test "channel_window encode/parse roundtrip" {
    const testing = std.testing;
    const win = ChannelWindow{ .channel_id = 99, .credit_bytes = 65_536 };
    const encoded = win.encode();
    try testing.expectEqual(ChannelWindow.size, encoded.len);
    const parsed = try ChannelWindow.parse(&encoded);
    try testing.expectEqual(@as(u32, 99), parsed.channel_id);
    try testing.expectEqual(@as(u32, 65_536), parsed.credit_bytes);
}

test "channel_window rejects short payload" {
    const testing = std.testing;
    const short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(error.InvalidChannelWindowPayload, ChannelWindow.parse(&short));
}

test "channel_eof encode/parse roundtrip" {
    const testing = std.testing;
    const eof = ChannelEof{ .channel_id = 5 };
    const encoded = eof.encode();
    try testing.expectEqual(ChannelEof.size, encoded.len);
    const parsed = try ChannelEof.parse(&encoded);
    try testing.expectEqual(@as(u32, 5), parsed.channel_id);
}

test "channel_close encode/parse — with message" {
    const testing = std.testing;
    const msg = "window violation";
    const close = ChannelClose{
        .channel_id = 7,
        .reason = .peer_reset,
        .message = msg,
    };
    const encoded = try close.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelClose.parse(encoded);
    try testing.expectEqual(@as(u32, 7), parsed.channel_id);
    try testing.expectEqual(ChannelCloseReason.peer_reset, parsed.reason);
    try testing.expectEqualStrings(msg, parsed.message);
}

test "channel_close encode/parse — empty message" {
    const testing = std.testing;
    const close = ChannelClose{ .channel_id = 8, .reason = .normal };
    const encoded = try close.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(ChannelClose.fixed_size, encoded.len);
    const parsed = try ChannelClose.parse(encoded);
    try testing.expectEqual(ChannelCloseReason.normal, parsed.reason);
    try testing.expectEqual(@as(usize, 0), parsed.message.len);
}

test "channel_control encode/parse roundtrip" {
    const testing = std.testing;
    const op_payload = "progress=512";
    const ctrl = ChannelControl{
        .channel_id = 11,
        .op = 1,
        .op_payload = op_payload,
    };
    const encoded = try ctrl.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try ChannelControl.parse(encoded);
    try testing.expectEqual(@as(u32, 11), parsed.channel_id);
    try testing.expectEqual(@as(u8, 1), parsed.op);
    try testing.expectEqualStrings(op_payload, parsed.op_payload);
}

test "channel frames roundtrip through writeFrame / readHeader" {
    // Ensures the new kinds work end-to-end with the existing frame I/O
    // helpers — no behavior change to the frame layer.
    const testing = std.testing;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);

    const win = ChannelWindow{ .channel_id = 17, .credit_bytes = 4096 };
    const win_bytes = win.encode();
    try writeFrame(buf.writer(testing.allocator), .channel_window, 0, &win_bytes);

    var stream = std.io.fixedBufferStream(buf.items);
    const header = try readHeader(stream.reader());
    try testing.expectEqual(Kind.channel_window, header.kind);
    try testing.expectEqual(@as(u16, 0), header.target); // channel_id lives in payload
    try testing.expectEqual(@as(u32, ChannelWindow.size), header.len);

    const payload = try readPayloadAlloc(testing.allocator, stream.reader(), header);
    defer testing.allocator.free(payload);
    const parsed = try ChannelWindow.parse(payload);
    try testing.expectEqual(@as(u32, 17), parsed.channel_id);
    try testing.expectEqual(@as(u32, 4096), parsed.credit_bytes);
}
