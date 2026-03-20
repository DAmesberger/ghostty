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
pub const protocol_version: u16 = 5;

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
    session_list_request = 15,
    session_list_entry = 16,
    layout_update = 19,
    layout_restore = 20,
    surface_open = 21,
    surface_close = 22,
};

pub const Header = struct {
    kind: Kind,
    reserved: u8 = 0,
    target: u16 = 0,
    len: u32,
};

pub const OpenMode = enum(u8) {
    new = 0,
    attach = 1,
};

/// Payload for session_open:
///   8-byte resize + 1-byte open_mode + label_or_id string.
pub const SessionOpen = struct {
    resize: Resize,
    mode: OpenMode = .new,
    label_or_id: []const u8,

    pub fn encode(self: SessionOpen, alloc: Allocator) ![]u8 {
        const resize_bytes = self.resize.bytes();
        var buf = try alloc.alloc(u8, 9 + self.label_or_id.len);
        @memcpy(buf[0..8], &resize_bytes);
        buf[8] = @intFromEnum(self.mode);
        @memcpy(buf[9..], self.label_or_id);
        return buf;
    }

    pub fn parse(payload: []const u8) !SessionOpen {
        if (payload.len < 9) return error.InvalidSessionOpenPayload;
        return .{
            .resize = try Resize.parse(payload[0..8]),
            .mode = std.meta.intToEnum(OpenMode, payload[8]) catch .new,
            .label_or_id = payload[9..],
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

test "protocol version is 5" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 5), protocol_version);
}

test "session open encode/parse" {
    const testing = std.testing;
    const so = SessionOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .mode = .new,
        .label_or_id = "test-session",
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try SessionOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqual(OpenMode.new, parsed.mode);
    try testing.expectEqualStrings("test-session", parsed.label_or_id);
}

test "session open attach mode" {
    const testing = std.testing;
    const so = SessionOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .mode = .attach,
        .label_or_id = "abc123",
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try SessionOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(OpenMode.attach, parsed.mode);
    try testing.expectEqualStrings("abc123", parsed.label_or_id);
}
