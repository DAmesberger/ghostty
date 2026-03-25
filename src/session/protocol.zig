const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum payload size for a single frame. The receive buffer grows on
/// demand (256KB → 512KB → 1MB) and never shrinks, so a large full snapshot
/// on a 5K terminal is a one-time allocation cost. The u32 len field
/// supports up to 4GB — no protocol-level limit.
pub const max_payload = 256 * 1024;

/// Keepalive: client sends ping at this interval, daemon responds with pong.
/// Halves keepalive traffic vs bidirectional keepalive.
pub const keepalive_interval_ns: i128 = 15 * std.time.ns_per_s;

/// Client considers connection stale if no pong received within this window.
pub const keepalive_stale_ns: i128 = 45 * std.time.ns_per_s;

/// Server closes connection if no ping received within this window.
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
        local_headless, // ghostty-headless binary next to the local executable
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
/// 15 kinds, values 0-127 used, 128-255 reserved.
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

    /// Old min size (without max_scrollback) for backward compat parsing.
    const legacy_min_payload_size = 1 + uuid_size * 2 + 8;
    /// Size with max_scrollback but without capabilities.
    const v1_min_payload_size = legacy_min_payload_size + 4;
    /// Current min size: v1 + compression(1) + frame_interval(2) = v1 + 3.
    pub const min_payload_size = v1_min_payload_size + 3;

    pub fn encode(self: Open, alloc: Allocator) ![]u8 {
        const total = min_payload_size + self.label.len;
        const buf = try alloc.alloc(u8, total);
        buf[0] = @intFromEnum(self.open_type);
        @memcpy(buf[1 .. 1 + uuid_size], &self.group_id);
        @memcpy(buf[1 + uuid_size .. 1 + uuid_size * 2], &self.surface_id);
        const resize_bytes = self.resize.bytes();
        @memcpy(buf[1 + uuid_size * 2 .. 1 + uuid_size * 2 + 8], &resize_bytes);
        std.mem.writeInt(u32, buf[legacy_min_payload_size..][0..4], self.max_scrollback, .little);
        buf[v1_min_payload_size] = self.compression_enabled;
        std.mem.writeInt(u16, buf[v1_min_payload_size + 1 ..][0..2], self.frame_interval_ms, .little);
        @memcpy(buf[min_payload_size..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !Open {
        if (payload.len < legacy_min_payload_size) return error.InvalidOpenPayload;
        return .{
            .open_type = std.meta.intToEnum(OpenType, payload[0]) catch return error.InvalidOpenPayload,
            .group_id = payload[1..][0..uuid_size].*,
            .surface_id = payload[1 + uuid_size ..][0..uuid_size].*,
            .resize = try Resize.parse(payload[1 + uuid_size * 2 ..][0..8]),
            .max_scrollback = if (payload.len >= v1_min_payload_size)
                std.mem.readInt(u32, payload[legacy_min_payload_size..][0..4], .little)
            else
                0,
            .compression_enabled = if (payload.len >= min_payload_size)
                payload[v1_min_payload_size]
            else
                0,
            .frame_interval_ms = if (payload.len >= min_payload_size)
                std.mem.readInt(u16, payload[v1_min_payload_size + 1 ..][0..2], .little)
            else
                16,
            .label = if (payload.len >= min_payload_size)
                payload[min_payload_size..]
            else if (payload.len >= v1_min_payload_size)
                payload[v1_min_payload_size..]
            else
                payload[legacy_min_payload_size..],
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
};

/// Payload for `list_response`:
///   [2] entry_count (u16 LE)
///   per entry:
///     [16] group_id
///     [1]  status
///     [2]  surface_count (u16 LE)
///     [2]  alive_count (u16 LE)
///     [8]  created_at (i64 LE)
///     [2]  label_len (u16 LE)
///     [label_len] label
pub const ListResponse = struct {
    entries: []const ListEntry,

    pub const entry_header_size = uuid_size + 1 + 2 + 2 + 8 + 2;

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
            const label_len = std.mem.readInt(u16, payload[offset..][0..2], .little);
            offset += 2;
            if (offset + label_len > payload.len) return error.InvalidListPayload;
            entries[i] = .{
                .group_id = group_id,
                .status = status,
                .surface_count = surface_count,
                .alive_count = alive_count,
                .created_at = created_at,
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
///   [4]  layout_len (u32 LE, 0 = no layout)
///   [layout_len] layout blob
///   [2]  state_count (u16 LE, number of surface state snapshots)
///   per state_count:
///     [16] surface_id
///     [4]  state_len (u32 LE)
///     [state_len] full page snapshot (diff_type=1 data_out format)
pub const Opened = struct {
    group_id: Uuid,
    /// The daemon-side surface_id that was attached. For session_attach
    /// this is the surface the daemon picked. For new sessions, this is
    /// the created surface's id. The client must update its local
    /// surface_id to match so layout restore can identify it.
    surface_id: Uuid = zero_uuid,
    caps: u32 = 0,
    /// Number of scrollback history rows available for the attached surface.
    /// The client uses this to pre-allocate blank history pages before
    /// receiving scrollback_response chunks.
    history_rows: u32 = 0,
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
        // uuid*2 + caps(4) + history_rows(4) + layout_len(4) + layout + state_count(2)
        var total: usize = uuid_size * 2 + 4 + 4 + 4 + layout_len + 2;
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
        layout_blob: ?[]const u8,
        state_count: u16,
        remaining: []const u8,
    } {
        // uuid*2 + caps(4) + history_rows(4) + layout_len(4) + state_count(2)
        const min_size = uuid_size * 2 + 4 + 4 + 4 + 2;
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
        const layout_len = std.mem.readInt(u32, payload[offset..][0..4], .little);
        offset += 4;
        if (offset + layout_len > payload.len) return error.InvalidOpenedPayload;
        const layout_blob: ?[]const u8 = if (layout_len > 0)
            payload[offset..][0..layout_len]
        else
            null;
        offset += layout_len;
        if (offset + 2 > payload.len) return error.InvalidOpenedPayload;
        const state_count = std.mem.readInt(u16, payload[offset..][0..2], .little);
        offset += 2;
        return .{
            .group_id = group_id,
            .surface_id = surface_id,
            .caps = caps,
            .history_rows = history_rows,
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

test "open backward compat (short payload without max_scrollback)" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    // Simulate an old-format payload with a short label (< 4 bytes so total < min_payload_size)
    var buf: [Open.legacy_min_payload_size + 2]u8 = undefined;
    buf[0] = @intFromEnum(OpenType.session_new);
    @memcpy(buf[1..][0..uuid_size], &gid);
    @memcpy(buf[1 + uuid_size ..][0..uuid_size], &shared.zero_uuid);
    const resize_bytes = (Resize{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 }).bytes();
    @memcpy(buf[1 + uuid_size * 2 ..][0..8], &resize_bytes);
    @memcpy(buf[Open.legacy_min_payload_size..][0..2], "ab");

    const parsed = try Open.parse(buf[0..Open.legacy_min_payload_size + 2]);
    try testing.expectEqual(OpenType.session_new, parsed.open_type);
    try testing.expectEqual(@as(u32, 0), parsed.max_scrollback); // default when missing
    try testing.expectEqualStrings("ab", parsed.label); // label at legacy offset
}

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
            .label = "my-session",
        },
        .{
            .group_id = shared.generateUuid(),
            .status = .detached,
            .surface_count = 1,
            .alive_count = 1,
            .created_at = 1700001000,
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
    try testing.expectEqualStrings("my-session", parsed[0].label);
    try testing.expectEqual(ListStatus.detached, parsed[1].status);
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
