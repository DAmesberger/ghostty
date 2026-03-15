const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_payload = 128 * 1024;

pub const Kind = enum(u8) {
    stdin = 1,
    stdout = 2,
    resize = 3,
    detach = 4,
    info = 5,
    err = 6,
    eof = 7,
};

pub const Header = struct {
    kind: Kind,
    len: u32,
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

pub fn writeFrame(
    writer: anytype,
    kind: Kind,
    payload: []const u8,
) !void {
    if (payload.len > max_payload) return error.PayloadTooLarge;

    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(kind);
    std.mem.writeInt(u32, header[1..5], @intCast(payload.len), .little);
    try writer.writeAll(&header);
    try writer.writeAll(payload);
}

pub fn writeResize(writer: anytype, resize: Resize) !void {
    const bytes = resize.bytes();
    try writeFrame(writer, .resize, &bytes);
}

pub fn readHeader(reader: anytype) !Header {
    var header: [5]u8 = undefined;
    try readExact(reader, &header);

    return .{
        .kind = std.meta.intToEnum(Kind, header[0]) catch return error.InvalidFrameType,
        .len = std.mem.readInt(u32, header[1..5], .little),
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

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(testing.allocator);

    try writeFrame(bytes.writer(testing.allocator), .stdout, "hello");

    var stream = std.io.fixedBufferStream(bytes.items);
    const header = try readHeader(stream.reader());
    try testing.expectEqual(.stdout, header.kind);
    const payload = try readPayloadAlloc(testing.allocator, stream.reader(), header);
    defer testing.allocator.free(payload);
    try testing.expectEqualStrings("hello", payload);
}
