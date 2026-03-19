/// Connection status overlay rendered via z2d.
///
/// Draws a centered semi-transparent box with optional progress bar.
/// Text rendering deferred to use Ghostty's font pipeline.
const ConnectionOverlay = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const z2d = @import("z2d");
const session = @import("../session.zig");
const sizepkg = @import("size.zig");
const Size = sizepkg.Size;
const Image = @import("image.zig").Image;

surface: z2d.Surface,
screen_width: u32,
screen_height: u32,

pub const InitError = Allocator.Error || error{InvalidDimensions};

pub fn init(alloc: Allocator, sz: Size) InitError!ConnectionOverlay {
    const term_size = sz.terminal();
    var sfc = z2d.Surface.initPixel(
        .{ .rgba = .{ .r = 0, .g = 0, .b = 0, .a = 0 } },
        alloc,
        std.math.cast(i32, term_size.width) orelse return error.InvalidDimensions,
        std.math.cast(i32, term_size.height) orelse return error.InvalidDimensions,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidWidth, error.InvalidHeight => return error.InvalidDimensions,
    };
    errdefer sfc.deinit(alloc);

    return .{
        .surface = sfc,
        .screen_width = @intCast(term_size.width),
        .screen_height = @intCast(term_size.height),
    };
}

pub fn deinit(self: *ConnectionOverlay, alloc: Allocator) void {
    self.surface.deinit(alloc);
}

pub fn pendingImage(self: *const ConnectionOverlay) Image.Pending {
    return .{
        .width = @intCast(self.surface.getWidth()),
        .height = @intCast(self.surface.getHeight()),
        .pixel_format = .rgba,
        .data = @ptrCast(self.surface.image_surface_rgba.buf.ptr),
    };
}

pub fn draw(self: *ConnectionOverlay, alloc: Allocator, state: session.protocol.ConnectionState) void {
    self.surface.paintPixel(.{ .rgba = .{ .r = 0, .g = 0, .b = 0, .a = 0 } });

    const box_w: u32 = @max(240, self.screen_width * 5 / 10);
    const box_h: u32 = if (state == .uploading) 48 else 32;
    const box_x: u32 = (self.screen_width -| box_w) / 2;
    const box_y: u32 = (self.screen_height -| box_h) / 2;

    // Background
    fillRect(alloc, &self.surface, box_x, box_y, box_w, box_h, premul(16, 18, 28, 210));
    // Border colored by state
    const border = switch (state) {
        .connecting, .setup => premul(70, 130, 220, 200),
        .uploading => premul(70, 160, 255, 200),
        .reconnecting => premul(220, 150, 40, 200),
        .stale, .failed => premul(220, 60, 50, 200),
        .connected => premul(60, 200, 100, 200),
    };
    strokeRect(alloc, &self.surface, box_x, box_y, box_w, box_h, border);

    // Progress bar for uploading state
    if (state == .uploading) {
        const progress = state.uploading;
        const m: u32 = 16;
        const bar_h: u32 = 10;
        const bar_x = box_x + m;
        const bar_y = box_y + (box_h -| bar_h) / 2;
        const bar_w = box_w -| (m * 2);

        fillRect(alloc, &self.surface, bar_x, bar_y, bar_w, bar_h, premul(40, 44, 60, 200));

        if (progress.total_bytes > 0) {
            const sent = @min(progress.bytes_sent, progress.total_bytes);
            const fill_w: u32 = @intCast(@as(u64, bar_w) * sent / progress.total_bytes);
            if (fill_w > 0) {
                fillRect(alloc, &self.surface, bar_x, bar_y, fill_w, bar_h, premul(80, 160, 255, 230));
            }
        }
    }
}

fn premul(r: u8, g: u8, b: u8, a: u8) z2d.Pixel {
    var rgba: z2d.pixel.RGBA = .{ .r = r, .g = g, .b = b, .a = a };
    return rgba.multiply().asPixel();
}

fn fillRect(alloc: Allocator, sfc: *z2d.Surface, x: u32, y: u32, w: u32, h: u32, color: z2d.Pixel) void {
    var ctx: z2d.Context = .init(alloc, sfc);
    defer ctx.deinit();
    ctx.setAntiAliasingMode(.none);
    const fx: f64 = @floatFromInt(x);
    const fy: f64 = @floatFromInt(y);
    const fw: f64 = @floatFromInt(w);
    const fh: f64 = @floatFromInt(h);
    ctx.moveTo(fx, fy) catch return;
    ctx.lineTo(fx + fw, fy) catch return;
    ctx.lineTo(fx + fw, fy + fh) catch return;
    ctx.lineTo(fx, fy + fh) catch return;
    ctx.closePath() catch return;
    ctx.setSourceToPixel(color);
    ctx.fill() catch return;
}

fn strokeRect(alloc: Allocator, sfc: *z2d.Surface, x: u32, y: u32, w: u32, h: u32, color: z2d.Pixel) void {
    var ctx: z2d.Context = .init(alloc, sfc);
    defer ctx.deinit();
    ctx.setAntiAliasingMode(.none);
    ctx.setHairline(true);
    const fx: f64 = @floatFromInt(x);
    const fy: f64 = @floatFromInt(y);
    const fw: f64 = @floatFromInt(w);
    const fh: f64 = @floatFromInt(h);
    ctx.moveTo(fx, fy) catch return;
    ctx.lineTo(fx + fw, fy) catch return;
    ctx.lineTo(fx + fw, fy + fh) catch return;
    ctx.lineTo(fx, fy + fh) catch return;
    ctx.closePath() catch return;
    ctx.setLineWidth(1);
    ctx.setSourceToPixel(color);
    ctx.stroke() catch return;
}
