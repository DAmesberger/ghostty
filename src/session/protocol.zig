const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_payload = 128 * 1024;

/// Keepalive interval: how often each side sends a keepalive frame.
pub const keepalive_interval_ns: i128 = 15 * std.time.ns_per_s;

/// Client considers connection stale if no keepalive received within this window.
pub const keepalive_stale_ns: i128 = 45 * std.time.ns_per_s;

/// Server closes connection if no keepalive received within this window.
pub const keepalive_server_timeout_ns: i128 = 60 * std.time.ns_per_s;

/// Connection state reported to surfaces for overlay display.
pub const ConnectionState = union(enum) {
    connecting,
    uploading: UploadProgress,
    setup,
    connected,
    reconnecting: ReconnectInfo,
    stale,
    failed: FailReason,

    pub const UploadProgress = struct {
        bytes_sent: u64,
        total_bytes: u64,
    };

    pub const ReconnectInfo = struct {
        attempt: u32,
        elapsed_ns: i128,
    };

    pub const FailReason = enum(u8) {
        unknown,
        auth_failed,
        timeout,
        helper_failed,
    };
};

/// Protocol version for the session wire format. Increment this when
/// making incompatible changes to the protocol. The remote helper
/// reports this via `+session-helper --version` so the client knows
/// whether to re-upload.
pub const protocol_version: u16 = 3;

/// Size of a frame header in bytes.
pub const header_size: usize = 8;

pub const Kind = enum(u8) {
    stdin = 1,
    stdout = 2,
    resize = 3,
    detach = 4,
    info = 5,
    err = 6,
    eof = 7,
    session_open = 8,
    session_opened = 9,
    session_close = 10,
    keepalive = 11,
    state_full = 12,
    state_delta = 13,
    state_ack = 14,
};

pub const Header = struct {
    kind: Kind,
    reserved: u8 = 0,
    target: u16 = 0,
    len: u32,
};

pub const RenderMode = enum(u8) {
    raw = 0,
    state_sync = 1,
};

/// Payload for session_open: 8-byte resize + 1-byte render_mode + label string.
/// For backward compatibility, if payload is exactly 8 + label (no render_mode byte),
/// we default to .raw.
pub const SessionOpen = struct {
    resize: Resize,
    render_mode: RenderMode = .raw,
    label: []const u8,

    pub fn encode(self: SessionOpen, alloc: Allocator) ![]u8 {
        const resize_bytes = self.resize.bytes();
        var buf = try alloc.alloc(u8, 9 + self.label.len);
        @memcpy(buf[0..8], &resize_bytes);
        buf[8] = @intFromEnum(self.render_mode);
        @memcpy(buf[9..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !SessionOpen {
        if (payload.len < 8) return error.InvalidSessionOpenPayload;
        // Backward compat: old clients send 8-byte resize + label (no render_mode)
        if (payload.len == 8 or payload[8] > 1) {
            return .{
                .resize = try Resize.parse(payload[0..8]),
                .label = payload[8..],
            };
        }
        return .{
            .resize = try Resize.parse(payload[0..8]),
            .render_mode = std.meta.intToEnum(RenderMode, payload[8]) catch .raw,
            .label = payload[9..],
        };
    }
};

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

/// Write a frame (8-byte header) to the given writer.
pub fn writeFrame(
    writer: anytype,
    kind: Kind,
    target: u16,
    payload: []const u8,
) !void {
    if (payload.len > max_payload) return error.PayloadTooLarge;

    var header: [header_size]u8 = undefined;
    header[0] = @intFromEnum(kind);
    header[1] = 0; // reserved
    std.mem.writeInt(u16, header[2..4], target, .little);
    std.mem.writeInt(u32, header[4..8], @intCast(payload.len), .little);
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

    return .{
        .kind = std.meta.intToEnum(Kind, header[0]) catch return error.InvalidFrameType,
        .reserved = header[1],
        .target = std.mem.readInt(u16, header[2..4], .little),
        .len = std.mem.readInt(u32, header[4..8], .little),
    };
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

test "protocol roundtrip" {
    const testing = std.testing;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);

    try writeFrame(buf.writer(testing.allocator), .stdout, 42, "hello");

    var stream = std.io.fixedBufferStream(buf.items);
    const header = try readHeader(stream.reader());
    try testing.expectEqual(.stdout, header.kind);
    try testing.expectEqual(@as(u16, 42), header.target);
    try testing.expectEqual(@as(u8, 0), header.reserved);
    const payload = try readPayloadAlloc(testing.allocator, stream.reader(), header);
    defer testing.allocator.free(payload);
    try testing.expectEqualStrings("hello", payload);
}

test "protocol version is 3" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 3), protocol_version);
}

test "session open encode/parse" {
    const testing = std.testing;
    const so = SessionOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .render_mode = .state_sync,
        .label = "test-session",
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try SessionOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqual(RenderMode.state_sync, parsed.render_mode);
    try testing.expectEqualStrings("test-session", parsed.label);
}

test "session open backward compat parse" {
    const testing = std.testing;
    // Simulate old-format payload: 8-byte resize + label (no render_mode)
    const resize = Resize{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 };
    const resize_bytes = resize.bytes();
    var old_payload: [8 + 7]u8 = undefined;
    @memcpy(old_payload[0..8], &resize_bytes);
    @memcpy(old_payload[8..], "session");

    const parsed = try SessionOpen.parse(&old_payload);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(RenderMode.raw, parsed.render_mode);
    try testing.expectEqualStrings("session", parsed.label);
}
