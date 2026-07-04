//! file_transfer open-params wire codec.
//!
//! Parse the direction/mode/path(+upload trailer) blob and the inverse
//! encoders for upload/download open requests.
//!
//! Split out of `file_transfer.zig`, which re-exports the public
//! `encodeUploadParams` / `encodeDownloadParams` encoders and re-imports
//! `parseOpenParams` for its `open()` handler.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const root = @import("file_transfer.zig");
const max_path_len = root.max_path_len;
const Direction = root.Direction;

const ParsedParams = struct {
    direction: Direction,
    mode: u32,
    path: []u8, // owned by alloc
    expected_sha256: [Sha256.digest_length]u8 = [_]u8{0} ** Sha256.digest_length,
    total_size: u64 = 0,
};

pub fn parseOpenParams(alloc: Allocator, params: []const u8) !ParsedParams {
    // Fixed prefix: direction(1) + mode(4) + path_len(2) = 7 bytes.
    if (params.len < 7) return error.TooShort;
    const direction: Direction = @enumFromInt(params[0]);
    const mode = std.mem.readInt(u32, params[1..5], .little);
    const path_len = std.mem.readInt(u16, params[5..7], .little);
    if (path_len == 0 or path_len > max_path_len) return error.InvalidPathLen;

    var off: usize = 7;
    if (params.len < off + path_len) return error.Truncated;
    const path = try alloc.dupe(u8, params[off .. off + path_len]);
    errdefer alloc.free(path);
    off += path_len;

    var parsed: ParsedParams = .{
        .direction = direction,
        .mode = mode,
        .path = path,
    };

    switch (direction) {
        .upload => {
            // Upload trailer: expected_sha256(32) + total_size(8).
            if (params.len < off + Sha256.digest_length + 8) return error.Truncated;
            @memcpy(
                &parsed.expected_sha256,
                params[off .. off + Sha256.digest_length],
            );
            off += Sha256.digest_length;
            parsed.total_size = std.mem.readInt(u64, params[off..][0..8], .little);
        },
        .download => {
            // No trailer for downloads. Anything beyond `path` is
            // ignored (forward-compat).
        },
        else => return error.InvalidDirection,
    }

    return parsed;
}

/// Encode upload open params. Caller owns the returned slice.
pub fn encodeUploadParams(
    alloc: Allocator,
    path: []const u8,
    mode: u32,
    expected_sha256: [Sha256.digest_length]u8,
    total_size: u64,
) ![]u8 {
    if (path.len == 0 or path.len > max_path_len) return error.InvalidPathLen;
    const total = 1 + 4 + 2 + path.len + Sha256.digest_length + 8;
    const buf = try alloc.alloc(u8, total);
    buf[0] = @intFromEnum(Direction.upload);
    std.mem.writeInt(u32, buf[1..5], mode, .little);
    std.mem.writeInt(u16, buf[5..7], @intCast(path.len), .little);
    @memcpy(buf[7 .. 7 + path.len], path);
    @memcpy(
        buf[7 + path.len .. 7 + path.len + Sha256.digest_length],
        &expected_sha256,
    );
    std.mem.writeInt(
        u64,
        buf[7 + path.len + Sha256.digest_length ..][0..8],
        total_size,
        .little,
    );
    return buf;
}

/// Encode download open params. Caller owns the returned slice.
pub fn encodeDownloadParams(alloc: Allocator, path: []const u8) ![]u8 {
    if (path.len == 0 or path.len > max_path_len) return error.InvalidPathLen;
    const total = 1 + 4 + 2 + path.len;
    const buf = try alloc.alloc(u8, total);
    buf[0] = @intFromEnum(Direction.download);
    std.mem.writeInt(u32, buf[1..5], 0, .little); // mode unused
    std.mem.writeInt(u16, buf[5..7], @intCast(path.len), .little);
    @memcpy(buf[7 .. 7 + path.len], path);
    return buf;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "file_transfer encodeUploadParams roundtrip" {
    var sha = [_]u8{0} ** Sha256.digest_length;
    for (0..Sha256.digest_length) |i| sha[i] = @intCast(i);
    const buf = try encodeUploadParams(testing.allocator, "/tmp/foo", 0o644, sha, 1234);
    defer testing.allocator.free(buf);

    const parsed = try parseOpenParams(testing.allocator, buf);
    defer testing.allocator.free(parsed.path);
    try testing.expectEqual(Direction.upload, parsed.direction);
    try testing.expectEqual(@as(u32, 0o644), parsed.mode);
    try testing.expectEqualStrings("/tmp/foo", parsed.path);
    try testing.expectEqualSlices(u8, &sha, &parsed.expected_sha256);
    try testing.expectEqual(@as(u64, 1234), parsed.total_size);
}

test "file_transfer encodeDownloadParams roundtrip" {
    const buf = try encodeDownloadParams(testing.allocator, "/tmp/bar");
    defer testing.allocator.free(buf);

    const parsed = try parseOpenParams(testing.allocator, buf);
    defer testing.allocator.free(parsed.path);
    try testing.expectEqual(Direction.download, parsed.direction);
    try testing.expectEqualStrings("/tmp/bar", parsed.path);
    try testing.expectEqual(@as(u64, 0), parsed.total_size);
}

test "file_transfer parseOpenParams rejects truncated input" {
    // Only the fixed prefix, no path bytes.
    var tiny: [7]u8 = undefined;
    tiny[0] = 0;
    std.mem.writeInt(u32, tiny[1..5], 0, .little);
    std.mem.writeInt(u16, tiny[5..7], 10, .little); // claims 10-byte path
    try testing.expectError(error.Truncated, parseOpenParams(testing.allocator, &tiny));
}

test "file_transfer parseOpenParams rejects zero path_len" {
    var bad: [7]u8 = undefined;
    bad[0] = 0;
    std.mem.writeInt(u32, bad[1..5], 0, .little);
    std.mem.writeInt(u16, bad[5..7], 0, .little);
    try testing.expectError(error.InvalidPathLen, parseOpenParams(testing.allocator, &bad));
}
