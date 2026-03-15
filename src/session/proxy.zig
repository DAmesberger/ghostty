const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

pub const Options = struct {
    ssh: []const u8,
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

    const helper_path = try session.client.ensureRemoteHelper(alloc, opts.ssh);
    defer alloc.free(helper_path);
    try session.client.ensureRemoteDaemon(alloc, opts.ssh, helper_path);

    const label = opts.label orelse "session";
    var desired_session_id = if (opts.session) |value| try alloc.dupe(u8, value) else null;
    defer if (desired_session_id) |value| alloc.free(value);

    var tty = try RawTTY.enter();
    defer tty.restore();

    while (true) {
        var child = try session.client.spawnRemoteAttach(
            alloc,
            opts.ssh,
            helper_path,
            desired_session_id,
            label,
        );
        defer child.stdin.?.close();
        defer if (child.stdout) |*f| f.close();
        defer if (child.stderr) |*f| f.close();

        var shared: Shared = .{
            .alloc = alloc,
            .ssh_target = opts.ssh,
            .label = label,
        };
        defer if (shared.session_id) |value| alloc.free(value);

        const stdout_thread = try std.Thread.spawn(.{}, readRemoteFrames, .{ &shared, child.stdout.?, child.stderr.? });
        defer stdout_thread.join();

        const control = try inputLoop(&shared, child.stdin.?);

        const term = try child.wait();
        _ = term;
        shared.mutex.lock();
        const result = shared.result;
        const session_id = if (shared.session_id) |v| try alloc.dupe(u8, v) else null;
        shared.mutex.unlock();

        if (session_id) |value| {
            defer alloc.free(value);
            if (desired_session_id == null) desired_session_id = try alloc.dupe(u8, value);
            try updateRegistry(
                alloc,
                opts.ssh,
                value,
                label,
                switch (result) {
                    .attached => .attached,
                    .detached => .detached,
                    .dead => .dead,
                    .disconnected => .disconnected,
                },
            );
        }

        switch (result) {
            .detached, .dead => return 0,
            .attached => {},
            .disconnected => {
                if (control == .reconnect_requested) continue;
                writeStatus("\r\n[ghostty session disconnected; reconnecting]\r\n");
                std.Thread.sleep(std.time.ns_per_s);
                continue;
            },
        }
    }
}

const Shared = struct {
    alloc: Allocator,
    ssh_target: []const u8,
    label: []const u8,
    mutex: std.Thread.Mutex = .{},
    result: Result = .attached,
    session_id: ?[]u8 = null,

    const Result = enum {
        attached,
        detached,
        disconnected,
        dead,
    };
};

const InputResult = enum {
    normal,
    reconnect_requested,
};

fn readRemoteFrames(shared: *Shared, stdout_file: std.fs.File, stderr_file: std.fs.File) void {
    defer {
        shared.mutex.lock();
        if (shared.result == .attached) shared.result = .disconnected;
        shared.mutex.unlock();
    }

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr_writer = &stderr_writer_.interface;

    const stderr_thread = std.Thread.spawn(.{}, copyStream, .{ stderr_file, std.fs.File.stderr() }) catch null;
    defer if (stderr_thread) |thread| thread.join();

    var reader_buf: [1024]u8 = undefined;
    var reader_ = stdout_file.reader(&reader_buf);
    const reader = &reader_.interface;

    while (true) {
        const header = session.protocol.readHeader(reader) catch break;
        const payload = session.protocol.readPayloadAlloc(shared.alloc, reader, header) catch break;
        defer shared.alloc.free(payload);

        switch (header.kind) {
            .stdout => {
                std.fs.File.stdout().writeAll(payload) catch {};
            },
            .info => {
                shared.mutex.lock();
                defer shared.mutex.unlock();
                if (shared.session_id) |existing| shared.alloc.free(existing);
                shared.session_id = shared.alloc.dupe(u8, payload) catch null;
            },
            .err => {
                stderr_writer.writeAll(payload) catch {};
                stderr_writer.flush() catch {};
            },
            .eof => {
                shared.mutex.lock();
                shared.result = .dead;
                shared.mutex.unlock();
                return;
            },
            else => {},
        }
    }
}

fn inputLoop(shared: *Shared, child_stdin: std.fs.File) !InputResult {
    const detach_seq = session.shared.controlSequence(.detach);
    const reconnect_seq = session.shared.controlSequence(.reconnect);

    var buf: [4096]u8 = undefined;
    var stdin_file: std.fs.File = .stdin();

    while (true) {
        const n = try stdin_file.read(&buf);
        if (n == 0) return .normal;
        const input = buf[0..n];

        if (std.mem.eql(u8, input, detach_seq)) {
            try sendDetach(child_stdin);
            shared.mutex.lock();
            shared.result = .detached;
            shared.mutex.unlock();
            return .normal;
        }

        if (std.mem.eql(u8, input, reconnect_seq)) {
            shared.mutex.lock();
            const disconnected = shared.result == .disconnected;
            shared.mutex.unlock();
            if (disconnected) return .reconnect_requested;
            continue;
        }

        shared.mutex.lock();
        const result = shared.result;
        shared.mutex.unlock();
        if (result != .attached) {
            if (result == .disconnected) return .reconnect_requested;
            return .normal;
        }

        try sendInput(child_stdin, input);
    }
}

fn sendInput(file: std.fs.File, bytes: []const u8) !void {
    var writer_buf: [1024]u8 = undefined;
    var writer_ = file.writer(&writer_buf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, .stdin, bytes);
    try writer.flush();
}

fn sendDetach(file: std.fs.File) !void {
    var writer_buf: [1024]u8 = undefined;
    var writer_ = file.writer(&writer_buf);
    const writer = &writer_.interface;
    try session.protocol.writeFrame(writer, .detach, "");
    try writer.flush();
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

fn copyStream(src: std.fs.File, dst: std.fs.File) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = src.read(&buf) catch break;
        if (n == 0) break;
        dst.writeAll(buf[0..n]) catch break;
    }
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
        if (c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw) != 0) {
            return error.TcSetAttrFailed;
        }
        return .{ .original = current };
    }

    fn restore(self: *RawTTY) void {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &self.original);
    }
};
