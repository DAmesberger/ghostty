const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum payload size for a single frame. The receive buffer grows on
/// demand (256KB → 512KB → 1MB) and never shrinks, so a large full snapshot
/// on a 5K terminal is a one-time allocation cost. The u32 len field
/// supports up to 4GB — no protocol-level limit.
pub const max_payload = 256 * 1024;

/// Protocol version for the session wire format. Clean break from v6 —
/// new frame kinds, structured page diffs, flags byte.
// v2: remote control bridge is generic — env vars renamed to
// GHOSTTY_CONTROL_SOCKET/TOKEN and the shim is embedder-supplied at daemon
// launch (no hardcoded cmux shim). Bumped so a new client never reuses a v1
// daemon that injects the old env names / installs the old shim.
pub const protocol_version: u16 = 2;

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

    // 37/38 are reserved for future input_ack / resume frames (not yet
    // wired). snapshot_begin takes the next truly-free value, 39.

    // cmux execve self-handoff (Phase 2, GATED behind GHOSTTY_SSH_REEXEC).
    // These are inert unless both the client local gate is on AND the running
    // daemon advertised the capability. An OLD daemon that receives `reexec_query`
    // (40) does not know the value, so `Header.parseFromBuf` returns
    // error.InvalidFrameType and the connection is dropped — which is exactly
    // why capability discovery goes through the answerable `--query-reexec`
    // probe (its EOF→`REEXEC 0` is deterministic against a pre-feature daemon),
    // never a raw frame to an unknown peer.
    reexec_query = 40, // client → daemon: "can you execve-handoff?" (0-byte payload)
    reexec_caps = 41, // daemon → client: 1-byte {1=yes,0=no}
    reexec = 42, // client → daemon: payload = absolute path of the new binary

    // Snapshot boundary marker (daemon → client). Sent immediately before a
    // full serialized-viewport `data_out` (on attach/reattach), under the
    // same mutex so frame ordering is preserved. The `target` field
    // identifies the surface. On receipt the client resets that surface's
    // terminal + VT parser to a clean baseline so the snapshot lands on a
    // known-empty state with no possibility of desync from leftover partial
    // state. Zero-byte payload.
    //
    // Backward compatibility: an old daemon never emits this frame, so an
    // updated client never resets (unchanged behavior). An old client that
    // does not know value 39 hits `intToEnum`'s else/error path in
    // `Header.parseFromBuf` (error.InvalidFrameType); the daemon only emits
    // it because the client requested an attach, so a pre-snapshot_begin
    // client simply never has a peer that sends it.
    snapshot_begin = 39,
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
// Frame I/O
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

test "protocol version is 2" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 2), protocol_version);
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
