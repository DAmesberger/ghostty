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
    password_required: PasswordPrompt,

    pub const PasswordPrompt = struct {
        /// True if the password is for the jump host, false for the target.
        is_jump: bool,
        /// Opaque pointer to SshConnectionManager.AuthState.
        /// The GTK handler uses this to submit the password.
        auth_state: ?*anyopaque = null,
    };

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

    /// C ABI representation — this is an internal-only action so we
    /// use void; the GTK handler reads from renderer_state instead.
    pub const C = void;

    pub fn cval(self: ConnectionState) void {
        _ = self;
    }
};

/// Protocol version for the session wire format. Increment this when
/// making incompatible changes to the protocol. The remote helper
/// reports this via `+session-helper --version` so the client knows
/// whether to re-upload.
pub const protocol_version: u16 = 6;

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
    session_rename = 23,
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

pub const Uuid = @import("shared.zig").Uuid;
pub const zero_uuid = @import("shared.zig").zero_uuid;
pub const uuid_size = 16;

/// Payload for session_open:
///   [8]  Resize
///   [1]  OpenMode
///   [16] surface_id (UUID, binary)
///   [16] group_id   (UUID, binary; client-generated for new, lookup key for attach)
///   [N]  label      (remaining bytes; session label for new, label-based lookup for attach)
///
/// Both IDs are generated client-side to avoid round-trip latency.
/// For mode=new: daemon creates a SessionGroup with the given group_id.
/// For mode=attach: daemon finds group by group_id, or by label if group_id is zero.
pub const SessionOpen = struct {
    resize: Resize,
    mode: OpenMode = .new,
    surface_id: Uuid = zero_uuid,
    group_id: Uuid = zero_uuid,
    label: []const u8 = "",

    pub fn encode(self: SessionOpen, alloc: Allocator) ![]u8 {
        const total = 9 + uuid_size * 2 + self.label.len;
        var buf = try alloc.alloc(u8, total);
        const resize_bytes = self.resize.bytes();
        @memcpy(buf[0..8], &resize_bytes);
        buf[8] = @intFromEnum(self.mode);
        @memcpy(buf[9 .. 9 + uuid_size], &self.surface_id);
        @memcpy(buf[9 + uuid_size .. 9 + uuid_size * 2], &self.group_id);
        @memcpy(buf[9 + uuid_size * 2 ..], self.label);
        return buf;
    }

    pub fn parse(payload: []const u8) !SessionOpen {
        if (payload.len < 9 + uuid_size * 2) return error.InvalidSessionOpenPayload;
        return .{
            .resize = try Resize.parse(payload[0..8]),
            .mode = std.meta.intToEnum(OpenMode, payload[8]) catch .new,
            .surface_id = payload[9..][0..uuid_size].*,
            .group_id = payload[9 + uuid_size ..][0..uuid_size].*,
            .label = payload[9 + uuid_size * 2 ..],
        };
    }
};

/// Payload for surface_open:
///   [8]  Resize
///   [1]  OpenMode
///   [16] group_id (UUID, binary)
///   [16] surface_id (UUID, binary)
///
/// Used when adding a surface to an existing session group (e.g. splits).
pub const SurfaceOpen = struct {
    resize: Resize,
    mode: OpenMode = .new,
    group_id: Uuid,
    surface_id: Uuid,

    pub const payload_size = 9 + uuid_size * 2;

    pub fn encode(self: SurfaceOpen, alloc: Allocator) ![]u8 {
        var buf = try alloc.alloc(u8, payload_size);
        const resize_bytes = self.resize.bytes();
        @memcpy(buf[0..8], &resize_bytes);
        buf[8] = @intFromEnum(self.mode);
        @memcpy(buf[9 .. 9 + uuid_size], &self.group_id);
        @memcpy(buf[9 + uuid_size .. 9 + uuid_size * 2], &self.surface_id);
        return buf;
    }

    pub fn parse(payload: []const u8) !SurfaceOpen {
        if (payload.len < payload_size) return error.InvalidSurfaceOpenPayload;
        return .{
            .resize = try Resize.parse(payload[0..8]),
            .mode = std.meta.intToEnum(OpenMode, payload[8]) catch .new,
            .group_id = payload[9..][0..uuid_size].*,
            .surface_id = payload[9 + uuid_size ..][0..uuid_size].*,
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

test "protocol version is 6" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 6), protocol_version);
}

test "session open encode/parse with IDs" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const sid = shared.generateUuid();
    const gid = shared.generateUuid();
    const so = SessionOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .mode = .new,
        .surface_id = sid,
        .group_id = gid,
        .label = "test-session",
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try SessionOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqual(OpenMode.new, parsed.mode);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqualStrings("test-session", parsed.label);
}

test "session open attach mode" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const so = SessionOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .mode = .attach,
        .group_id = gid,
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    const parsed = try SessionOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(OpenMode.attach, parsed.mode);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
}

test "surface open encode/parse" {
    const testing = std.testing;
    const shared = @import("shared.zig");
    const gid = shared.generateUuid();
    const sid = shared.generateUuid();
    const so = SurfaceOpen{
        .resize = .{ .rows = 24, .cols = 80, .width_px = 800, .height_px = 600 },
        .mode = .new,
        .group_id = gid,
        .surface_id = sid,
    };
    const encoded = try so.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    try testing.expectEqual(@as(usize, SurfaceOpen.payload_size), encoded.len);

    const parsed = try SurfaceOpen.parse(encoded);
    try testing.expectEqual(@as(u16, 24), parsed.resize.rows);
    try testing.expectEqual(@as(u16, 80), parsed.resize.cols);
    try testing.expectEqual(OpenMode.new, parsed.mode);
    try testing.expectEqualSlices(u8, &gid, &parsed.group_id);
    try testing.expectEqualSlices(u8, &sid, &parsed.surface_id);
}
