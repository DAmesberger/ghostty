const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const ssh = @import("ssh.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("poll.h");
    @cInclude("sys/ioctl.h");
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

/// Atomic flags set by signal handlers and checked by the event loop.
var sigwinch_received: std.atomic.Value(bool) = .init(false);
var shutdown_requested: std.atomic.Value(bool) = .init(false);

fn sigwinchHandler(_: c_int) callconv(.c) void {
    sigwinch_received.store(true, .release);
}

fn shutdownHandler(_: c_int) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

pub const Options = struct {
    ssh: []const u8 = "",
    jump: ?[]const u8 = null,
    session: ?[]const u8 = null,
    label: ?[]const u8 = null,
};

pub fn run(
    alloc: Allocator,
    opts: Options,
    stderr: *std.Io.Writer,
) !u8 {
    if (comptime builtin.os.tag == .windows) {
        try stderr.writeAll("remote session proxy is only implemented on POSIX platforms.\n");
        return 1;
    }

    // Install signal handlers early so Ctrl-C works during setup
    installSignalHandlers();

    try stderr.print("Connecting to {s}...\n", .{opts.ssh});
    try stderr.flush();

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = opts.ssh,
        .jump = opts.jump,
    };
    defer ctx.deinit();

    const helper_path = try session.client.ensureRemoteHelper(alloc, &ctx, stderr);
    defer alloc.free(helper_path);

    try stderr.writeAll("Starting remote daemon...\n");
    try stderr.flush();
    try session.client.ensureRemoteDaemon(alloc, &ctx, helper_path);
    try stderr.writeAll("Daemon ready.\n");
    try stderr.flush();

    const label = opts.label orelse "session";
    var desired_session_id = if (opts.session) |value| try alloc.dupe(u8, value) else null;
    defer if (desired_session_id) |value| alloc.free(value);

    var tty = try RawTTY.enter();
    defer tty.restore();

    while (true) {
        writeStatus("Opening remote session...\r\n");
        var channel = session.client.openRemoteAttach(
            alloc,
            &ctx,
            helper_path,
            desired_session_id,
            label,
        ) catch {
            tty.restore();
            writeStatus("\r\n[failed to open remote channel]\r\n");
            return 1;
        };

        // Switch session to non-blocking for the event loop.
        // libssh2 is NOT thread-safe, so we use a single-threaded
        // event loop instead of separate reader/writer threads.
        var sess = &ctx.session.?;
        sess.setBlocking(0);

        const result = eventLoop(alloc, &channel, sess, opts.ssh, label);

        // Restore blocking mode for cleanup / reconnect
        sess.setBlocking(1);
        channel.close();

        const session_id = if (result.session_id) |v| try alloc.dupe(u8, v) else null;
        defer if (session_id) |v| alloc.free(v);
        if (result.session_id) |v| alloc.free(v);

        if (session_id) |value| {
            if (desired_session_id == null) desired_session_id = try alloc.dupe(u8, value);
            try updateRegistry(alloc, opts.ssh, value, label, result.status);
        }

        switch (result.status) {
            .detached, .dead => return 0,
            .attached => {},
            .disconnected => {
                writeStatus("\r\n[ghostty session disconnected; reconnecting]\r\n");
                std.Thread.sleep(std.time.ns_per_s);
                continue;
            },
        }
    }
}

const EventResult = struct {
    status: session.registry.Status,
    session_id: ?[]u8,
};

/// Single-threaded event loop that multiplexes stdin and the SSH channel.
/// All libssh2 calls happen from this one thread, avoiding thread-safety issues.
fn eventLoop(
    alloc: Allocator,
    channel: *ssh.Channel,
    sess: *ssh.SshSession,
    ssh_target: []const u8,
    label: []const u8,
) EventResult {
    _ = ssh_target;
    _ = label;

    const detach_seq = session.shared.controlSequence(.detach);

    var session_id: ?[]u8 = null;
    var frame_buf = std.ArrayList(u8).empty;
    defer frame_buf.deinit(alloc);

    const ssh_fd = sess.getSocket();

    while (true) {
        // Check signals
        if (shutdown_requested.swap(false, .acquire)) {
            sendDetach(channel) catch {};
            return .{ .status = .detached, .session_id = session_id };
        }
        if (sigwinch_received.swap(false, .acquire)) {
            sendResize(channel) catch {};
        }

        // Poll both stdin and the SSH socket
        var fds = [2]c.struct_pollfd{
            .{ .fd = posix.STDIN_FILENO, .events = c.POLLIN, .revents = 0 },
            .{ .fd = ssh_fd, .events = c.POLLIN, .revents = 0 },
        };
        const pr = c.poll(&fds, 2, 50); // 50ms timeout for signal checks
        if (pr < 0) continue; // interrupted by signal

        // Handle stdin → channel (user input)
        if (fds[0].revents & c.POLLIN != 0) {
            var input_buf: [4096]u8 = undefined;
            const n = posix.read(posix.STDIN_FILENO, &input_buf) catch {
                return .{ .status = .disconnected, .session_id = session_id };
            };
            if (n == 0) return .{ .status = .disconnected, .session_id = session_id };
            const input = input_buf[0..n];

            if (std.mem.eql(u8, input, detach_seq)) {
                sendDetach(channel) catch {};
                return .{ .status = .detached, .session_id = session_id };
            }

            sendInput(channel, input) catch {
                return .{ .status = .disconnected, .session_id = session_id };
            };
        }

        // Handle channel → stdout (remote output)
        // Try reading even if poll didn't flag it — non-blocking mode
        // means libssh2 might have buffered data.
        var read_buf: [4096]u8 = undefined;
        while (true) {
            const rc = channel.readNonBlock(&read_buf);
            if (rc > 0) {
                frame_buf.appendSlice(alloc, read_buf[0..@intCast(rc)]) catch break;
            } else {
                break;
            }
        }

        // Process complete frames from buffer
        while (frame_buf.items.len >= 5) {
            const payload_len = std.mem.readInt(u32, frame_buf.items[1..5], .little);
            const total = 5 + payload_len;
            if (frame_buf.items.len < total) break;

            const kind = std.meta.intToEnum(session.protocol.Kind, frame_buf.items[0]) catch {
                shiftBuffer(&frame_buf, total);
                continue;
            };
            const payload = frame_buf.items[5..total];

            switch (kind) {
                .stdout => std.fs.File.stdout().writeAll(payload) catch {},
                .info => {
                    if (session_id) |old| alloc.free(old);
                    session_id = alloc.dupe(u8, payload) catch null;
                },
                .err => std.fs.File.stderr().writeAll(payload) catch {},
                .eof => {
                    shiftBuffer(&frame_buf, total);
                    return .{ .status = .dead, .session_id = session_id };
                },
                else => {},
            }

            shiftBuffer(&frame_buf, total);
        }
    }
}

fn shiftBuffer(buf: *std.ArrayList(u8), amount: usize) void {
    if (amount >= buf.items.len) {
        buf.shrinkRetainingCapacity(0);
    } else {
        std.mem.copyForwards(u8, buf.items, buf.items[amount..]);
        buf.shrinkRetainingCapacity(buf.items.len - amount);
    }
}

fn sendInput(channel: *ssh.Channel, bytes: []const u8) !void {
    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(session.protocol.Kind.stdin);
    std.mem.writeInt(u32, header[1..5], @intCast(bytes.len), .little);
    try channel.write(&header);
    try channel.write(bytes);
}

fn sendDetach(channel: *ssh.Channel) !void {
    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(session.protocol.Kind.detach);
    std.mem.writeInt(u32, header[1..5], 0, .little);
    try channel.write(&header);
}

fn sendResize(channel: *ssh.Channel) !void {
    const resize = getTerminalSize();
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], resize.rows, .little);
    std.mem.writeInt(u16, payload[2..4], resize.cols, .little);
    std.mem.writeInt(u16, payload[4..6], resize.width_px, .little);
    std.mem.writeInt(u16, payload[6..8], resize.height_px, .little);

    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(session.protocol.Kind.resize);
    std.mem.writeInt(u32, header[1..5], 8, .little);
    try channel.write(&header);
    try channel.write(&payload);
}

fn getTerminalSize() session.protocol.Resize {
    var ws: c.struct_winsize = std.mem.zeroes(c.struct_winsize);
    _ = c.ioctl(posix.STDIN_FILENO, c.TIOCGWINSZ, @intFromPtr(&ws));
    return .{
        .rows = @intCast(ws.ws_row),
        .cols = @intCast(ws.ws_col),
        .width_px = @intCast(ws.ws_xpixel),
        .height_px = @intCast(ws.ws_ypixel),
    };
}

fn installSignalHandlers() void {
    var sa_winch: posix.Sigaction = .{
        .handler = .{ .handler = sigwinchHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.WINCH, &sa_winch, null);

    var sa_shutdown: posix.Sigaction = .{
        .handler = .{ .handler = shutdownHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &sa_shutdown, null);
    posix.sigaction(posix.SIG.HUP, &sa_shutdown, null);
    posix.sigaction(posix.SIG.INT, &sa_shutdown, null);
}

fn updateRegistry(
    alloc: Allocator,
    ssh_target: []const u8,
    session_id: []const u8,
    label: []const u8,
    status: session.registry.Status,
) !void {
    const path = try session.registry.defaultPath(alloc);
    defer alloc.free(path);
    try session.registry.upsert(path, alloc, .{
        .ssh_target = ssh_target,
        .session_id = session_id,
        .label = label,
        .status = status,
        .created_at = std.time.timestamp(),
        .last_seen_at = std.time.timestamp(),
    });
}

fn writeStatus(message: []const u8) void {
    std.fs.File.stdout().writeAll(message) catch {};
}

const RawTTY = struct {
    original: c.struct_termios,

    fn enter() !RawTTY {
        var current: c.struct_termios = undefined;
        if (c.tcgetattr(posix.STDIN_FILENO, &current) != 0) {
            return error.TcGetAttrFailed;
        }
        var raw = current;
        c.cfmakeraw(&raw);
        // Keep ISIG so Ctrl-C generates SIGINT even in raw mode
        raw.c_lflag |= c.ISIG;
        if (c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw) != 0) {
            return error.TcSetAttrFailed;
        }
        return .{ .original = current };
    }

    fn restore(self: *RawTTY) void {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &self.original);
    }
};
