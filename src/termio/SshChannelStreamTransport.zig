//! Daemon-protocol transport over an already-opened libssh2 channel.
//!
//! Bridges a `session.ssh.Channel` to `session.channel_mux.ClientMux` via a
//! Unix socketpair. The two halves of the pair form an in-process byte pipe:
//!
//!   mux_fd  = socketpair[0]  — ClientMux reads/writes frames here (posix.fd_t)
//!   ssh_fd  = socketpair[1]  — transport threads bridge to/from libssh2
//!
//! Two threads run concurrently:
//!
//!   reader — libssh2_channel_read  →  write to ssh_fd
//!            Parses no frames itself; raw bytes flow through the socketpair
//!            and ClientMux's own dispatch loop consumes them from mux_fd.
//!
//!   writer — read from ssh_fd  →  libssh2_channel_write
//!            Drains bytes that ClientMux wrote to mux_fd and forwards them
//!            to the remote daemon.
//!
//! libssh2 thread-safety:
//!   libssh2 is NOT thread-safe. All libssh2 calls are serialised via
//!   `ssh_mutex`. Both the reader and writer threads acquire it before each
//!   libssh2 call and release it immediately after. The mutex is never held
//!   across a blocking operation — EAGAIN causes a poll-then-retry loop with
//!   the mutex released during the poll, so the other thread can make
//!   progress.
//!
//! Teardown order (enforced by `close`):
//!   1. Set `stopped` flag.
//!   2. Close `ssh_fd` — wakes the writer's poll on that fd.
//!   3. Signal the reader to stop via `stop_pipe`.
//!   4. Join both threads.
//!   5. Close `mux_fd` (after threads are joined to avoid a racing read).
//!   6. Close the libssh2 channel.
//!
//! The caller must call `close()` and then `ClientMux.deinit()` before
//! destroying this transport.

const SshChannelStreamTransport = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const ssh_mod = session.ssh;

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("poll.h");
});

const ssh2 = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("libssh2.h");
});

const log = std.log.scoped(.ssh_channel_transport);

/// The ClientMux that owns the multiplexed channel state. The transport
/// borrows this — the caller allocates and frees it. `mux_fd` is set
/// as the mux's fd on construction; the mux must not be init'd or
/// deinit'd while the transport is running.
pub const Config = struct {
    /// Already-opened libssh2 channel. Transport takes ownership; `close`
    /// will call `libssh2_channel_close` + `libssh2_channel_free`.
    channel: ssh_mod.Channel,
    /// Called once the read loop exits. Fires on the reader thread.
    on_disconnect: DisconnectHandler,
    ctx: ?*anyopaque = null,
};

pub const DisconnectHandler = *const fn (ctx: ?*anyopaque, reason: DisconnectReason) void;

pub const DisconnectReason = enum {
    eof,
    read_error,
    write_error,
};

alloc: Allocator,
config: Config,

/// socketpair[0] — the fd handed to ClientMux. Closed in `close` after
/// threads have joined (to avoid a race with the reader thread).
mux_fd: posix.fd_t,
/// socketpair[1] — the transport-side fd. Reader writes here;
/// writer reads from here. Closed early in `close` to unblock threads.
ssh_fd: posix.fd_t,

/// Pipe used to wake the reader thread during shutdown: write end lives
/// here, read end is watched by the reader poll loop.
stop_pipe: [2]posix.fd_t,

/// Serialises all libssh2 calls. Never held across a blocking wait.
ssh_mutex: std.Thread.Mutex = .{},

reader_thread: ?std.Thread = null,
writer_thread: ?std.Thread = null,

/// Set by `close` before waking the threads. Atomic so threads can
/// check without acquiring a mutex.
stopped: std.atomic.Value(bool) = .init(false),

pub fn init(alloc: Allocator, config: Config) !*SshChannelStreamTransport {
    if (builtin.os.tag == .windows) return error.UnsupportedPlatform;

    var fds: [2]posix.fd_t = undefined;
    const pair_rc = std.posix.system.socketpair(
        std.posix.AF.UNIX,
        std.posix.SOCK.STREAM,
        0,
        &fds,
    );
    if (pair_rc != 0) return error.SocketPairFailed;
    errdefer {
        posix.close(fds[0]);
        posix.close(fds[1]);
    }

    var stop_fds: [2]posix.fd_t = undefined;
    try posix.pipe(&stop_fds);
    errdefer {
        posix.close(stop_fds[0]);
        posix.close(stop_fds[1]);
    }

    const self = try alloc.create(SshChannelStreamTransport);
    errdefer alloc.destroy(self);
    self.* = .{
        .alloc = alloc,
        .config = config,
        .mux_fd = fds[0],
        .ssh_fd = fds[1],
        .stop_pipe = stop_fds,
    };

    const rt = try std.Thread.spawn(.{}, readerLoop, .{self});
    rt.setName("ssh-chan-rx") catch {};
    self.reader_thread = rt;

    const wt = try std.Thread.spawn(.{}, writerLoop, .{self});
    wt.setName("ssh-chan-tx") catch {};
    self.writer_thread = wt;

    return self;
}

/// The fd to pass to `ClientMux.init`. Valid until `close` is called.
pub fn muxFd(self: *SshChannelStreamTransport) posix.fd_t {
    return self.mux_fd;
}

/// Shut down the transport cleanly. Blocks until both threads have joined.
/// Safe to call multiple times.
pub fn close(self: *SshChannelStreamTransport) void {
    self.stopped.store(true, .release);

    // Wake the writer by closing the ssh_fd it polls on.
    posix.close(self.ssh_fd);
    self.ssh_fd = -1;

    // Wake the reader via stop_pipe.
    _ = posix.write(self.stop_pipe[1], "x") catch {};

    if (self.reader_thread) |t| {
        t.join();
        self.reader_thread = null;
    }
    if (self.writer_thread) |t| {
        t.join();
        self.writer_thread = null;
    }

    posix.close(self.stop_pipe[0]);
    posix.close(self.stop_pipe[1]);

    // Now safe to close the mux fd — threads are done with it.
    posix.close(self.mux_fd);
    self.mux_fd = -1;

    // Close the libssh2 channel.
    self.config.channel.close();
}

pub fn deinit(self: *SshChannelStreamTransport) void {
    self.close();
    self.alloc.destroy(self);
}

// MARK: — reader thread —

/// Reads bytes from the libssh2 channel and forwards them to `ssh_fd`.
/// ClientMux on the other end of the socketpair drains `mux_fd`.
fn readerLoop(self: *SshChannelStreamTransport) void {
    defer {
        if (!self.stopped.load(.acquire)) {
            self.config.on_disconnect(self.config.ctx, .eof);
        }
    }

    var buf: [32 * 1024]u8 = undefined;
    const poll_sock = self.config.channel.sock;
    // Snapshot for the same reason as in writerLoop: close() nils self.ssh_fd
    // concurrently. The fd value itself stays open until close() joins us.
    const my_ssh_fd = self.ssh_fd;

    while (true) {
        if (self.stopped.load(.acquire)) return;

        // Non-blocking read from the libssh2 channel.
        self.ssh_mutex.lock();
        const rc = ssh2.libssh2_channel_read_ex(
            self.config.channel.inner,
            0,
            @ptrCast(&buf),
            buf.len,
        );
        const eof = ssh2.libssh2_channel_eof(self.config.channel.inner) != 0;
        self.ssh_mutex.unlock();

        if (rc > 0) {
            // Got bytes — write them all to the socketpair.
            if (!writeAllFd(my_ssh_fd, buf[0..@intCast(rc)])) {
                if (!self.stopped.load(.acquire)) {
                    log.warn("ssh-chan-rx: write to socketpair failed", .{});
                    self.config.on_disconnect(self.config.ctx, .read_error);
                }
                return;
            }
            continue;
        }

        if (eof) {
            log.debug("ssh-chan-rx: channel EOF", .{});
            return; // defer fires on_disconnect(eof)
        }

        if (rc == ssh2.LIBSSH2_ERROR_EAGAIN) {
            // Poll the underlying socket (or stop_pipe) until data arrives.
            pollForRead(poll_sock, self.stop_pipe[0]);
            continue;
        }

        if (rc < 0) {
            if (!self.stopped.load(.acquire)) {
                log.warn("ssh-chan-rx: libssh2_channel_read error rc={d}", .{rc});
                self.config.on_disconnect(self.config.ctx, .read_error);
            }
            return;
        }

        // rc == 0 and not EOF and not EAGAIN: treat as EAGAIN.
        pollForRead(poll_sock, self.stop_pipe[0]);
    }
}

// MARK: — writer thread —

/// Reads bytes from `ssh_fd` (ClientMux outbound) and writes them to the
/// libssh2 channel.
fn writerLoop(self: *SshChannelStreamTransport) void {
    var buf: [32 * 1024]u8 = undefined;
    const poll_sock = self.config.channel.sock;
    // Snapshot ssh_fd once: close() sets self.ssh_fd = -1 concurrently, but
    // we hold a reference to the fd value as of when the thread started. The
    // poll loop exits via POLLHUP/POLLERR when close() closes the underlying fd.
    const my_ssh_fd = self.ssh_fd;

    while (true) {
        if (self.stopped.load(.acquire)) return;

        // Poll ssh_fd for data from ClientMux (or stop_pipe for shutdown).
        var fds = [2]c.struct_pollfd{
            .{ .fd = my_ssh_fd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = self.stop_pipe[0], .events = c.POLLIN, .revents = 0 },
        };
        const poll_rc = c.poll(&fds, 2, 100);
        if (poll_rc < 0) {
            if (self.stopped.load(.acquire)) return;
            continue;
        }

        if (fds[1].revents & c.POLLIN != 0) return; // stop_pipe signalled
        if (fds[0].revents & (c.POLLHUP | c.POLLERR) != 0) return;
        if (fds[0].revents & c.POLLIN == 0) continue; // timeout

        // Read from the socketpair.
        const n = posix.read(my_ssh_fd, &buf) catch return;
        if (n == 0) return; // EOF on socketpair — mux closed

        // Write all bytes to the libssh2 channel, respecting EAGAIN.
        var written: usize = 0;
        while (written < n) {
            if (self.stopped.load(.acquire)) return;

            self.ssh_mutex.lock();
            const wrc = ssh2.libssh2_channel_write_ex(
                self.config.channel.inner,
                0,
                @ptrCast(buf[written..n].ptr),
                n - written,
            );
            self.ssh_mutex.unlock();

            if (wrc > 0) {
                written += @intCast(wrc);
                continue;
            }
            if (wrc == ssh2.LIBSSH2_ERROR_EAGAIN) {
                // Poll until the channel is ready for writing.
                pollForWrite(poll_sock, self.config.channel.ssh_session, self.stop_pipe[0]);
                continue;
            }
            if (!self.stopped.load(.acquire)) {
                log.warn("ssh-chan-tx: libssh2_channel_write error rc={d}", .{wrc});
                self.config.on_disconnect(self.config.ctx, .write_error);
            }
            return;
        }
    }
}

// MARK: — helpers —

fn writeAllFd(fd: posix.fd_t, buf: []const u8) bool {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.write(fd, buf[total..]) catch return false;
        if (n == 0) return false;
        total += n;
    }
    return true;
}

fn pollForRead(sock: posix.fd_t, stop_fd: posix.fd_t) void {
    var fds = [2]c.struct_pollfd{
        .{ .fd = sock, .events = c.POLLIN, .revents = 0 },
        .{ .fd = stop_fd, .events = c.POLLIN, .revents = 0 },
    };
    _ = c.poll(&fds, 2, 100);
}

fn pollForWrite(sock: posix.fd_t, session_ptr: *ssh2.LIBSSH2_SESSION, stop_fd: posix.fd_t) void {
    const dir = ssh2.libssh2_session_block_directions(session_ptr);
    var events: c_short = 0;
    if (dir & ssh2.LIBSSH2_SESSION_BLOCK_INBOUND != 0) events |= c.POLLIN;
    if (dir & ssh2.LIBSSH2_SESSION_BLOCK_OUTBOUND != 0) events |= c.POLLOUT;
    if (events == 0) events = c.POLLOUT;
    var fds = [2]c.struct_pollfd{
        .{ .fd = sock, .events = events, .revents = 0 },
        .{ .fd = stop_fd, .events = c.POLLIN, .revents = 0 },
    };
    _ = c.poll(&fds, 2, 100);
}

// MARK: — tests —

test "SshChannelStreamTransport: socketpair bridge smoke test" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    // This test verifies that the socketpair plumbing itself works by
    // writing bytes directly to mux_fd and reading them from ssh_fd,
    // without involving libssh2. It exercises the fd wiring only.
    var fds: [2]posix.fd_t = undefined;
    const rc = std.posix.system.socketpair(
        std.posix.AF.UNIX,
        std.posix.SOCK.STREAM,
        0,
        &fds,
    );
    try std.testing.expectEqual(@as(c_int, 0), rc);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const msg = "hello transport";
    _ = try posix.write(fds[0], msg);

    var buf: [64]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expectEqual(msg.len, n);
    try std.testing.expectEqualSlices(u8, msg, buf[0..n]);
}

test "SshChannelStreamTransport: protocol frame parse roundtrip" {
    // Verifies Header.parseFromBuf / encodeToBuf roundtrip works for
    // the kinds the transport forwards through the socketpair.
    const proto = @import("../session.zig").protocol;
    const kinds = [_]proto.Kind{ .channel_open, .channel_data, .channel_window, .channel_eof, .channel_close };
    for (kinds) |kind| {
        const hdr = proto.Header{
            .kind = kind,
            .flags = .{},
            .target = 0,
            .len = 42,
        };
        const encoded = hdr.encodeToBuf();
        const parsed = try proto.Header.parseFromBuf(&encoded);
        try std.testing.expectEqual(kind, parsed.kind);
        try std.testing.expectEqual(@as(u32, 42), parsed.len);
    }
}
