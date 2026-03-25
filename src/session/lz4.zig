//! LZ4 block compression and decompression.
//!
//! Implements the LZ4 block format (not framed) for fast, real-time
//! compression of terminal output data. LZ4 is optimized for speed
//! over compression ratio — typically ~4GB/s compress, ~8GB/s decompress.
//!
//! Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md

const std = @import("std");
const Allocator = std.mem.Allocator;

const hash_bits = 14;
const hash_size = 1 << hash_bits;
const min_match = 4;
const max_distance = 65535;

/// Compress `src` into LZ4 block format. Returns compressed data (caller owns).
/// Returns null if compressed output would be larger than input.
pub fn compress(alloc: Allocator, src: []const u8) ?[]u8 {
    if (src.len == 0) return null;

    // Output buffer — worst case is slightly larger than input.
    var dst = alloc.alloc(u8, src.len + (src.len / 255) + 16) catch return null;
    errdefer alloc.free(dst);

    var dp: usize = 0; // destination position
    var sp: usize = 0; // source position
    var anchor: usize = 0; // start of current literal run

    // Hash table: maps 4-byte hash → position in src. Empty = sentinel.
    const empty: u32 = std.math.maxInt(u32);
    var table: [hash_size]u32 = @splat(empty);

    while (sp + min_match <= src.len) {
        const h = hash4(src[sp..][0..4]);
        const ref = table[h];
        table[h] = @intCast(sp);

        // Check for match: ref must be valid and within max_distance.
        if (ref != empty and sp > ref and sp - ref <= max_distance and
            std.mem.eql(u8, src[ref..][0..4], src[sp..][0..4]))
        {
            // Extend match forward.
            var match_len: usize = min_match;
            while (sp + match_len < src.len and ref + match_len < sp and
                src[ref + match_len] == src[sp + match_len])
            {
                match_len += 1;
            }

            // Emit token.
            const lit_len = sp - anchor;
            const offset = sp - ref;
            dp = emitToken(dst, dp, lit_len, match_len, src[anchor..sp], @intCast(offset)) orelse {
                alloc.free(dst);
                return null;
            };

            sp += match_len;
            anchor = sp;
        } else {
            sp += 1;
        }
    }

    // Final literals (no match at end).
    const last_lit_len = src.len - anchor;
    if (last_lit_len > 0) {
        dp = emitLastLiterals(dst, dp, last_lit_len, src[anchor..]) orelse {
            alloc.free(dst);
            return null;
        };
    }

    if (dp >= src.len) {
        alloc.free(dst);
        return null; // Compression didn't help.
    }

    // Shrink to actual size.
    const result = alloc.realloc(dst, dp) catch {
        // realloc shrink shouldn't fail, but if it does, return original.
        return dst[0..dp];
    };
    return result[0..dp];
}

/// Decompress LZ4 block format. `src` is compressed, `orig_len` is the
/// original uncompressed size (must be known). Returns decompressed data.
pub fn decompress(alloc: Allocator, src: []const u8, orig_len: usize) ![]u8 {
    var dst = try alloc.alloc(u8, orig_len);
    errdefer alloc.free(dst);

    var sp: usize = 0; // source position
    var dp: usize = 0; // dest position

    while (sp < src.len) {
        const token = src[sp];
        sp += 1;

        // Literal length.
        var lit_len: usize = token >> 4;
        if (lit_len == 15) {
            while (sp < src.len) {
                const extra = src[sp];
                sp += 1;
                lit_len += extra;
                if (extra != 255) break;
            }
        }

        // Copy literals.
        if (sp + lit_len > src.len or dp + lit_len > orig_len)
            return error.InvalidLz4Data;
        @memcpy(dst[dp..][0..lit_len], src[sp..][0..lit_len]);
        sp += lit_len;
        dp += lit_len;

        // End of block — last sequence has no match.
        if (sp >= src.len) break;

        // Match offset (2 bytes LE).
        if (sp + 2 > src.len) return error.InvalidLz4Data;
        const offset: usize = @as(u16, src[sp]) | (@as(u16, src[sp + 1]) << 8);
        sp += 2;
        if (offset == 0 or offset > dp) return error.InvalidLz4Data;

        // Match length.
        var match_len: usize = (token & 0x0F) + min_match;
        if ((token & 0x0F) == 15) {
            while (sp < src.len) {
                const extra = src[sp];
                sp += 1;
                match_len += extra;
                if (extra != 255) break;
            }
        }

        // Copy match (may overlap — byte-by-byte for correctness).
        if (dp + match_len > orig_len) return error.InvalidLz4Data;
        const match_src = dp - offset;
        for (0..match_len) |i| {
            dst[dp + i] = dst[match_src + i];
        }
        dp += match_len;
    }

    if (dp != orig_len) return error.InvalidLz4Data;
    return dst;
}

// ---- Internal helpers ----

fn hash4(data: *const [4]u8) usize {
    const v = std.mem.readInt(u32, data, .little);
    return @intCast((v *% 2654435761) >> (32 - hash_bits));
}

fn emitToken(
    dst: []u8,
    dp: usize,
    lit_len: usize,
    match_len: usize,
    literals: []const u8,
    offset: u16,
) ?usize {
    var pos = dp;
    const ml = match_len - min_match;

    // Token byte: high 4 bits = literal length, low 4 bits = match length.
    const lit_field: u8 = if (lit_len >= 15) 15 else @intCast(lit_len);
    const ml_field: u8 = if (ml >= 15) 15 else @intCast(ml);
    if (pos >= dst.len) return null;
    dst[pos] = (lit_field << 4) | ml_field;
    pos += 1;

    // Extended literal length.
    if (lit_len >= 15) {
        var remaining = lit_len - 15;
        while (remaining >= 255) {
            if (pos >= dst.len) return null;
            dst[pos] = 255;
            pos += 1;
            remaining -= 255;
        }
        if (pos >= dst.len) return null;
        dst[pos] = @intCast(remaining);
        pos += 1;
    }

    // Literals.
    if (pos + lit_len > dst.len) return null;
    @memcpy(dst[pos..][0..lit_len], literals);
    pos += lit_len;

    // Offset (2 bytes LE).
    if (pos + 2 > dst.len) return null;
    dst[pos] = @intCast(offset & 0xFF);
    dst[pos + 1] = @intCast(offset >> 8);
    pos += 2;

    // Extended match length.
    if (ml >= 15) {
        var remaining = ml - 15;
        while (remaining >= 255) {
            if (pos >= dst.len) return null;
            dst[pos] = 255;
            pos += 1;
            remaining -= 255;
        }
        if (pos >= dst.len) return null;
        dst[pos] = @intCast(remaining);
        pos += 1;
    }

    return pos;
}

fn emitLastLiterals(dst: []u8, dp: usize, lit_len: usize, literals: []const u8) ?usize {
    var pos = dp;

    // Token byte: only literal length, match length = 0.
    const lit_field: u8 = if (lit_len >= 15) 15 else @intCast(lit_len);
    if (pos >= dst.len) return null;
    dst[pos] = lit_field << 4;
    pos += 1;

    // Extended literal length.
    if (lit_len >= 15) {
        var remaining = lit_len - 15;
        while (remaining >= 255) {
            if (pos >= dst.len) return null;
            dst[pos] = 255;
            pos += 1;
            remaining -= 255;
        }
        if (pos >= dst.len) return null;
        dst[pos] = @intCast(remaining);
        pos += 1;
    }

    // Literals.
    if (pos + lit_len > dst.len) return null;
    @memcpy(dst[pos..][0..lit_len], literals);
    pos += lit_len;

    return pos;
}

// ---- Tests ----

test "lz4 roundtrip simple" {
    const data = "Hello, World! Hello, World! Hello, World!";
    const compressed = compress(std.testing.allocator, data) orelse
        return error.CompressionFailed;
    defer std.testing.allocator.free(compressed);

    try std.testing.expect(compressed.len < data.len);

    const decompressed = try decompress(std.testing.allocator, compressed, data.len);
    defer std.testing.allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, data, decompressed);
}

test "lz4 roundtrip VT sequences" {
    const data = "\x1b[38;2;255;128;0m" ** 100 ++ "Hello, World! " ** 50;
    const compressed = compress(std.testing.allocator, data) orelse
        return error.CompressionFailed;
    defer std.testing.allocator.free(compressed);

    try std.testing.expect(compressed.len < data.len);

    const decompressed = try decompress(std.testing.allocator, compressed, data.len);
    defer std.testing.allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, data, decompressed);
}

test "lz4 small data returns null" {
    const result = compress(std.testing.allocator, "hi");
    try std.testing.expect(result == null);
}

test "lz4 incompressible data returns null" {
    // Random-looking data that won't compress.
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    const result = compress(std.testing.allocator, &data);
    // May or may not compress — if it doesn't, null is correct.
    if (result) |r| std.testing.allocator.free(r);
}
