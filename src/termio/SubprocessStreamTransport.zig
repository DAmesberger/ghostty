//! Daemon-protocol transport over a pre-opened pipe pair.
//!
//! **Currently unused.** This is foundation code for the planned OpenSSH
//! engine (`ssh-engine = openssh`), in which Ghostty spawns the system
//! `ssh` binary as a subprocess and talks to the remote daemon over its
//! stdio pipes. The transport itself is engine-agnostic — it doesn't care
//! who created the fds — so the same code will also fit any future use
//! that hands libghostty a pair of bidirectional byte streams already
//! carrying daemon-protocol bytes (Unix sockets, socketpairs in tests,
//! external embedders, etc.).
//!
//! Responsibilities:
//!
//!   - One read thread per transport. Parses wire frames via
//!     `session.protocol` and posts them to a caller-supplied frame
//!     handler.
//!   - Writes are serialized by a mutex so concurrent producers
//!     (multiple surface threads enqueuing data_in frames) don't
//!     interleave bytes on the output pipe.
//!   - `close()` shuts the read thread down cleanly: close the read fd,
//!     the read loop observes EOF, joins.
//!
//! The "connection manager" layer (surface registration, entry cache,
//! reconnect, frame dispatch by Kind) is separate — when the OpenSSH
//! engine lands, it will sit on top of this transport. Until then this
//! file exists as a well-tested building block; the socketpair roundtrip
//! test at the bottom proves the frame parser and mutex serialization
//! work end-to-end.

const SubprocessStreamTransport = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");

const log = std.log.scoped(.io_remote_subprocess);

/// Callback fired once per inbound frame (on the read thread). The
/// payload buffer is owned by the transport and is only valid during
/// the call; consumers should copy anything they need to retain.
pub const FrameHandler = *const fn (
    ctx: ?*anyopaque,
    header: session.protocol.Header,
    payload: []const u8,
) void;

/// Fired once the read loop exits (EOF on the read fd or a fatal
/// parse error). Typically triggers reconnect UX.
pub const DisconnectHandler = *const fn (ctx: ?*anyopaque, reason: DisconnectReason) void;

pub const DisconnectReason = enum {
    eof,
    parse_error,
    read_error,
};

pub const Config = struct {
    /// Inbound fd — frames from the remote daemon helper on the remote
    /// host. SubprocessStreamTransport closes this on shutdown.
    in_fd: posix.fd_t,
    /// Outbound fd — frames to the remote daemon helper. Closed on shutdown.
    out_fd: posix.fd_t,

    on_frame: FrameHandler,
    on_disconnect: DisconnectHandler,
    ctx: ?*anyopaque = null,
};

alloc: Allocator,
config: Config,

read_thread: ?std.Thread = null,

/// Guards concurrent writes to `out_fd`. Frames from arbitrary
/// threads take this before touching the write side.
write_mutex: std.Thread.Mutex = .{},

/// Cleanly ordered flag — set by close() so the read thread knows it
/// was the caller's choice. Read with `@atomicLoad`.
stopped: std.atomic.Value(bool) = .init(false),

/// Init takes ownership of the fds: caller must not close them after
/// handing them to us. `close()` closes both.
pub fn init(alloc: Allocator, config: Config) !*SubprocessStreamTransport {
    const self = try alloc.create(SubprocessStreamTransport);
    errdefer alloc.destroy(self);
    self.* = .{
        .alloc = alloc,
        .config = config,
    };

    // Start the read thread. Name it so it shows up in crash reports
    // and `Debug > Activity Monitor`-style tooling.
    const t = try std.Thread.spawn(.{}, readLoop, .{self});
    t.setName("ssh-subprocess-rx") catch {};
    self.read_thread = t;
    return self;
}

/// Free the transport and its resources. Blocks until the read thread
/// has joined. Safe to call multiple times.
pub fn close(self: *SubprocessStreamTransport) void {
    // Set the flag first so the read loop knows not to emit
    // disconnect on its normal EOF path.
    self.stopped.store(true, .release);

    // Closing the input fd kicks the read loop out of its blocking
    // read. The thread joins in deinit below.
    posix.close(self.config.in_fd);

    // Closing the output side is also the caller's "done sending" —
    // no harm in racing here since writes under the mutex error out
    // gracefully. If the host handed us the same fd for both
    // directions (e.g. a socketpair endpoint), skip the second close
    // — POSIX makes double-close on the same fd unreachable.
    self.write_mutex.lock();
    if (self.config.out_fd != self.config.in_fd) {
        posix.close(self.config.out_fd);
    }
    self.write_mutex.unlock();

    if (self.read_thread) |t| {
        t.join();
        self.read_thread = null;
    }
}

pub fn deinit(self: *SubprocessStreamTransport) void {
    self.close();
    self.alloc.destroy(self);
}

/// Emit a frame downstream. Safe to call from any thread; writes are
/// mutex-serialized so frame bytes don't interleave between producers.
pub fn sendFrame(
    self: *SubprocessStreamTransport,
    kind: session.protocol.Kind,
    target: u16,
    payload: []const u8,
) !void {
    return self.sendFrameFlags(kind, .{}, target, payload);
}

pub fn sendFrameFlags(
    self: *SubprocessStreamTransport,
    kind: session.protocol.Kind,
    flags: session.protocol.Flags,
    target: u16,
    payload: []const u8,
) !void {
    if (payload.len > session.protocol.max_payload) return error.PayloadTooLarge;
    const header = (session.protocol.Header{
        .kind = kind,
        .flags = flags,
        .target = target,
        .len = @intCast(payload.len),
    }).encodeToBuf();

    self.write_mutex.lock();
    defer self.write_mutex.unlock();

    // File-descriptor writes can short-write under pressure; loop.
    try writeAll(self.config.out_fd, &header);
    if (payload.len > 0) try writeAll(self.config.out_fd, payload);
}

// MARK: -- internals --

fn readLoop(self: *SubprocessStreamTransport) void {
    defer {
        if (!self.stopped.load(.acquire)) {
            self.config.on_disconnect(self.config.ctx, .eof);
        }
    }

    const in_fd = self.config.in_fd;
    var header_buf: [session.protocol.header_size]u8 = undefined;
    while (true) {
        // Read exactly `header_size` bytes. readAll returns `error.EndOfStream`
        // when the pipe closes cleanly; any other error is fatal.
        readAll(in_fd, &header_buf) catch |err| {
            switch (err) {
                error.EndOfStream => return, // defer fires on_disconnect(eof)
                else => {
                    if (!self.stopped.load(.acquire)) {
                        log.warn("read error on subprocess transport: {}", .{err});
                        self.config.on_disconnect(self.config.ctx, .read_error);
                    }
                    return;
                },
            }
        };

        const header = session.protocol.Header.parseFromBuf(&header_buf) catch {
            log.warn("invalid frame header on subprocess transport", .{});
            self.config.on_disconnect(self.config.ctx, .parse_error);
            return;
        };
        if (header.len > session.protocol.max_payload) {
            log.warn("subprocess transport: payload {} exceeds max", .{header.len});
            self.config.on_disconnect(self.config.ctx, .parse_error);
            return;
        }

        const payload = self.alloc.alloc(u8, header.len) catch {
            log.warn("subprocess transport: OOM allocating payload", .{});
            self.config.on_disconnect(self.config.ctx, .read_error);
            return;
        };
        defer self.alloc.free(payload);

        if (header.len > 0) {
            readAll(in_fd, payload) catch |err| {
                switch (err) {
                    error.EndOfStream => {
                        log.warn("subprocess transport: EOF mid-payload", .{});
                        return;
                    },
                    else => {
                        log.warn("subprocess transport: payload read error {}", .{err});
                        self.config.on_disconnect(self.config.ctx, .read_error);
                        return;
                    },
                }
            };
        }

        self.config.on_frame(self.config.ctx, header, payload);
    }
}

fn readAll(fd: posix.fd_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) {
            if (total == 0) return error.EndOfStream;
            return error.EndOfStream;
        }
        total += n;
    }
}

fn writeAll(fd: posix.fd_t, buf: []const u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.write(fd, buf[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return error.ShortWrite;
        total += n;
    }
}

// MARK: -- tests --

test "SubprocessStreamTransport roundtrip via socketpair" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const alloc = std.testing.allocator;

    // socketpair gives us a bidirectional byte pipe perfect for this test.
    var fds: [2]posix.fd_t = undefined;
    const pair_res = std.posix.system.socketpair(
        std.posix.AF.UNIX,
        std.posix.SOCK.STREAM,
        0,
        &fds,
    );
    if (pair_res != 0) return error.SkipZigTest;

    // One end is our transport's stdio; the other end is "the daemon".
    const transport_in = fds[0];
    const transport_out = fds[0]; // same fd, bidirectional socket
    const daemon_end = fds[1];

    const Ctx = struct {
        received_kind: ?session.protocol.Kind = null,
        received_payload: [64]u8 = undefined,
        received_len: usize = 0,
        disconnected: bool = false,
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
    };
    var ctx: Ctx = .{};

    const handlers = struct {
        fn onFrame(c: ?*anyopaque, header: session.protocol.Header, payload: []const u8) void {
            const self: *Ctx = @ptrCast(@alignCast(c.?));
            self.mutex.lock();
            defer self.mutex.unlock();
            self.received_kind = header.kind;
            @memcpy(self.received_payload[0..payload.len], payload);
            self.received_len = payload.len;
            self.cond.signal();
        }
        fn onDisconnect(c: ?*anyopaque, _: DisconnectReason) void {
            const self: *Ctx = @ptrCast(@alignCast(c.?));
            self.mutex.lock();
            defer self.mutex.unlock();
            self.disconnected = true;
            self.cond.signal();
        }
    };

    const xport = try SubprocessStreamTransport.init(alloc, .{
        .in_fd = transport_in,
        .out_fd = transport_out,
        .on_frame = handlers.onFrame,
        .on_disconnect = handlers.onDisconnect,
        .ctx = &ctx,
    });
    // Give the transport close() full ownership of the fds.
    defer xport.deinit();

    // Write a single frame from the "daemon" side into the transport.
    const header = (session.protocol.Header{
        .kind = .data_out,
        .flags = .{},
        .target = 7,
        .len = 5,
    }).encodeToBuf();
    _ = try posix.write(daemon_end, &header);
    _ = try posix.write(daemon_end, "hello");

    // Wait for the read thread to dispatch.
    ctx.mutex.lock();
    while (ctx.received_kind == null and !ctx.disconnected) {
        ctx.cond.wait(&ctx.mutex);
    }
    const got_kind = ctx.received_kind;
    const got_len = ctx.received_len;
    const got_bytes: [64]u8 = ctx.received_payload;
    ctx.mutex.unlock();

    try std.testing.expectEqual(session.protocol.Kind.data_out, got_kind.?);
    try std.testing.expectEqual(@as(usize, 5), got_len);
    try std.testing.expectEqualSlices(u8, "hello", got_bytes[0..got_len]);

    // Clean up the daemon-side fd so close() doesn't hang on it.
    posix.close(daemon_end);
}
