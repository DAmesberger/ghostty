//! Remote implements the termio backend for SSH remote sessions.
//! It connects to a remote host via libssh2 and communicates with
//! the ghostty session helper using the binary protocol.
//!
//! All libssh2 operations happen on the IO thread to avoid thread-safety
//! issues — libssh2 is NOT thread-safe. A timer polls the SSH channel
//! for incoming data on the same thread that handles writes.
const Remote = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const xev = @import("../global.zig").xev;
const renderer = @import("../renderer.zig");
const terminal = @import("../terminal/main.zig");
const termio = @import("../termio.zig");
const session = @import("../session.zig");
const ssh = session.ssh;
const SshConnectionManager = @import("SshConnectionManager.zig");


const log = std.log.scoped(.io_remote);

/// Poll interval for reading from the SSH channel (milliseconds).
const POLL_INTERVAL_MS = 5;

/// Allocator used to own copied config strings.
alloc: Allocator,

/// The SSH target (e.g. "user@host:port") — owned copy.
ssh_target: []const u8,

/// Optional jump host — owned copy.
jump: ?[]const u8,

/// Label for the remote session — owned copy.
label: ?[]const u8,

/// Session ID for reconnecting to an existing session — owned copy.
session_id: ?[]const u8,

/// Reference to the shared connection manager
connection_manager: *SshConnectionManager,

/// The connection entry from the manager (set during threadEnter)
conn_entry: ?*SshConnectionManager.Entry = null,

/// Initial grid size, stored from initTerminal
grid_size: renderer.GridSize = .{ .columns = 80, .rows = 24 },
screen_size: renderer.ScreenSize = .{ .width = 0, .height = 0 },

/// Pointer to the active channel (set during threadEnter, lives in ThreadData)
active_channel: ?*ssh.Channel = null,

pub fn init(
    alloc: Allocator,
    cfg: Config,
) !Remote {
    // Copy config strings — the config memory is NOT stable after init.
    const ssh_target = try alloc.dupe(u8, cfg.ssh_target);
    errdefer alloc.free(ssh_target);
    const jump = if (cfg.jump) |j| try alloc.dupe(u8, j) else null;
    errdefer if (jump) |j| alloc.free(j);
    const label = if (cfg.label) |l| try alloc.dupe(u8, l) else null;
    errdefer if (label) |l| alloc.free(l);
    const session_id = if (cfg.session_id) |s| try alloc.dupe(u8, s) else null;

    return .{
        .alloc = alloc,
        .ssh_target = ssh_target,
        .jump = jump,
        .label = label,
        .session_id = session_id,
        .connection_manager = cfg.connection_manager,
    };
}

pub fn deinit(self: *Remote) void {
    // Release our reference to the connection
    if (self.conn_entry != null) {
        self.connection_manager.release(self.ssh_target, self.jump);
        self.conn_entry = null;
    }

    // Free owned string copies
    self.alloc.free(self.ssh_target);
    if (self.jump) |j| self.alloc.free(j);
    if (self.label) |l| self.alloc.free(l);
    if (self.session_id) |s| self.alloc.free(s);
}

pub fn initTerminal(self: *Remote, term: *terminal.Terminal) void {
    self.grid_size = .{
        .columns = term.cols,
        .rows = term.rows,
    };
    self.screen_size = .{
        .width = term.width_px,
        .height = term.height_px,
    };
}

pub fn threadEnter(
    self: *Remote,
    alloc: Allocator,
    io: *termio.Termio,
    td: *termio.Termio.ThreadData,
) !void {
    // Show connecting message in terminal
    termio.Termio.processOutput(io, "Connecting to ");
    termio.Termio.processOutput(io, self.ssh_target);
    termio.Termio.processOutput(io, "...\r\n");

    // Acquire a connection from the pool
    const entry = try self.connection_manager.acquire(self.ssh_target, self.jump);
    self.conn_entry = entry;

    // If the SSH context has no session yet, establish the connection.
    {
        self.connection_manager.mutex.lock();
        const needs_connect = entry.ctx.session == null;
        self.connection_manager.mutex.unlock();

        if (needs_connect) {
            // Connect SSH (password prompts go to stderr)
            var stderr_buf: [1024]u8 = undefined;
            var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
            const stderr = &stderr_writer_.interface;

            entry.ctx.connect(stderr) catch |err| {
                const msg = std.fmt.allocPrint(alloc, "SSH connection failed: {}\r\n", .{err}) catch "SSH connection failed\r\n";
                termio.Termio.processOutput(io, msg);
                return err;
            };

            termio.Termio.processOutput(io, "Connected. Setting up remote helper...\r\n");

            // Ensure helper is uploaded
            const helper_path = session.client.ensureRemoteHelper(alloc, &entry.ctx, stderr) catch |err| {
                termio.Termio.processOutput(io, "Failed to set up remote helper.\r\n");
                return err;
            };

            // Ensure daemon is running
            session.client.ensureRemoteDaemon(alloc, &entry.ctx, helper_path) catch |err| {
                alloc.free(helper_path);
                termio.Termio.processOutput(io, "Failed to start remote daemon.\r\n");
                return err;
            };

            self.connection_manager.mutex.lock();
            if (entry.helper_path.len > 0) self.connection_manager.alloc.free(entry.helper_path);
            entry.helper_path = helper_path;
            self.connection_manager.mutex.unlock();
        }
    }

    termio.Termio.processOutput(io, "Opening remote session...\r\n");

    // Open a channel to the remote helper's stdio-attach mode
    var channel = session.client.openRemoteAttach(
        alloc,
        &entry.ctx,
        entry.helper_path,
        self.session_id,
        self.label,
    ) catch |err| {
        termio.Termio.processOutput(io, "Failed to open remote session.\r\n");
        return err;
    };
    errdefer channel.close();

    // Switch to non-blocking for the poll-based event loop
    var sess = &entry.ctx.session.?;
    sess.setBlocking(0);

    // Send initial resize so the remote PTY gets the correct terminal size
    sendResize(&channel, self.grid_size, self.screen_size) catch |err| {
        log.warn("failed to send initial resize: {}", .{err});
    };

    // Create the poll timer
    var poll_timer = try xev.Timer.init();
    errdefer poll_timer.deinit();

    // Store thread data — all pointers are stable from here
    td.backend = .{ .remote = .{
        .channel = channel,
        .session = sess,
        .io = io,
        .poll_timer = poll_timer,
        .frame_buf = std.ArrayList(u8).empty,
    } };

    // Store a pointer to the channel for resize access
    self.active_channel = &td.backend.remote.channel;

    // Start the poll timer on the IO thread's event loop
    td.backend.remote.poll_timer.run(
        td.loop,
        &td.backend.remote.poll_timer_c,
        POLL_INTERVAL_MS,
        termio.Termio.ThreadData,
        td,
        pollTimerCallback,
    );
}

pub fn threadExit(self: *Remote, td: *termio.Termio.ThreadData) void {
    const remote_td = &td.backend.remote;

    // Clear active channel reference before cleanup
    self.active_channel = null;

    // Close the channel
    remote_td.channel.close();

    // Restore blocking mode
    remote_td.session.setBlocking(1);

    // Release the connection reference
    if (self.conn_entry != null) {
        self.connection_manager.release(self.ssh_target, self.jump);
        self.conn_entry = null;
    }
}

pub fn focusGained(
    self: *Remote,
    td: *termio.Termio.ThreadData,
    focused: bool,
) !void {
    _ = self;
    _ = td;
    _ = focused;
}

pub fn resize(
    self: *Remote,
    grid_size: renderer.GridSize,
    screen_size: renderer.ScreenSize,
) !void {
    self.grid_size = grid_size;
    self.screen_size = screen_size;

    // This is called on the IO thread, so channel access is safe
    if (self.active_channel) |channel| {
        sendResize(channel, grid_size, screen_size) catch |err| {
            log.warn("failed to send resize: {}", .{err});
        };
    }
}

pub fn queueWrite(
    self: *Remote,
    alloc: Allocator,
    td: *termio.Termio.ThreadData,
    data: []const u8,
    linefeed: bool,
) !void {
    _ = self;
    _ = alloc;
    const remote_td = &td.backend.remote;

    // Called on the IO thread — channel access is safe
    if (linefeed) {
        var i: usize = 0;
        while (i < data.len) {
            const ch = data[i];
            i += 1;
            if (ch == '\r') {
                sendInput(&remote_td.channel, "\r\n") catch return;
            } else {
                sendInput(&remote_td.channel, data[i - 1 .. i]) catch return;
            }
        }
    } else {
        sendInput(&remote_td.channel, data) catch return;
    }
}

pub fn childExitedAbnormally(
    self: *Remote,
    gpa: Allocator,
    t: *terminal.Terminal,
    exit_code: u32,
    runtime_ms: u64,
) !void {
    _ = gpa;
    _ = exit_code;
    _ = runtime_ms;
    _ = self;

    t.carriageReturn();
    try t.linefeed();
    try t.printString("Remote session disconnected.");
    t.modes.set(.cursor_visible, false);
}

// -- Poll timer callback (runs on IO thread) --

fn pollTimerCallback(
    td_: ?*termio.Termio.ThreadData,
    _: *xev.Loop,
    _: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = r catch |err| switch (err) {
        error.Canceled => return .disarm,
        else => {
            log.warn("poll timer error: {}", .{err});
            return .disarm;
        },
    };

    const td = td_.?;
    const remote_td = &td.backend.remote;
    const io = remote_td.io;

    // Poll the SSH transport so libssh2 processes pending network data.
    // For tunneled sessions this polls the jump host's real socket using
    // libssh2_session_block_directions — without this, non-blocking reads
    // through the tunnel chain never see new data.
    remote_td.session.pollTransport(1);

    // Read all available data from the SSH channel (non-blocking)
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const rc = remote_td.channel.readNonBlock(&read_buf);
        if (rc > 0) {
            remote_td.frame_buf.appendSlice(
                std.heap.page_allocator,
                read_buf[0..@intCast(rc)],
            ) catch break;
        } else {
            break;
        }
    }

    // Detect channel EOF (remote helper exited)
    if (remote_td.channel.eof()) {
        log.info("ssh channel EOF", .{});
        _ = td.surface_mailbox.push(.{
            .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
        }, .{ .forever = {} });
        return .disarm;
    }

    // Process complete protocol frames from buffer.
    // The helper sends an .info frame first, then transparently relays
    // daemon frames (.stdout, .eof, .err).
    while (remote_td.frame_buf.items.len >= 5) {
        const payload_len = std.mem.readInt(u32, remote_td.frame_buf.items[1..5], .little);
        const total = 5 + payload_len;
        if (remote_td.frame_buf.items.len < total) break;

        const kind = std.meta.intToEnum(session.protocol.Kind, remote_td.frame_buf.items[0]) catch {
            shiftBuffer(&remote_td.frame_buf, total);
            continue;
        };
        const payload = remote_td.frame_buf.items[5..total];

        switch (kind) {
            .stdout => {
                @call(.always_inline, termio.Termio.processOutput, .{ io, payload });
            },
            .info => {
                log.info("remote session id: {s}", .{payload});
            },
            .err => {
                log.err("remote error: {s}", .{payload});
            },
            .eof => {
                shiftBuffer(&remote_td.frame_buf, total);
                log.info("remote session EOF", .{});
                _ = td.surface_mailbox.push(.{
                    .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
                }, .{ .forever = {} });
                return .disarm;
            },
            else => {},
        }

        shiftBuffer(&remote_td.frame_buf, total);
    }

    // Re-arm the timer
    remote_td.poll_timer.run(
        td.loop,
        &remote_td.poll_timer_c,
        POLL_INTERVAL_MS,
        termio.Termio.ThreadData,
        td,
        pollTimerCallback,
    );

    return .disarm;
}

// -- Protocol helpers --

fn sendInput(channel: *ssh.Channel, data: []const u8) !void {
    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(session.protocol.Kind.stdin);
    std.mem.writeInt(u32, header[1..5], @intCast(data.len), .little);
    try channel.write(&header);
    try channel.write(data);
}

fn sendResize(channel: *ssh.Channel, grid_size: renderer.GridSize, screen_size: renderer.ScreenSize) !void {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], @intCast(grid_size.rows), .little);
    std.mem.writeInt(u16, payload[2..4], @intCast(grid_size.columns), .little);
    std.mem.writeInt(u16, payload[4..6], @intCast(screen_size.width), .little);
    std.mem.writeInt(u16, payload[6..8], @intCast(screen_size.height), .little);

    var header: [5]u8 = undefined;
    header[0] = @intFromEnum(session.protocol.Kind.resize);
    std.mem.writeInt(u32, header[1..5], 8, .little);
    try channel.write(&header);
    try channel.write(&payload);
}

fn shiftBuffer(buf: *std.ArrayList(u8), amount: usize) void {
    if (amount >= buf.items.len) {
        buf.shrinkRetainingCapacity(0);
    } else {
        std.mem.copyForwards(u8, buf.items, buf.items[amount..]);
        buf.shrinkRetainingCapacity(buf.items.len - amount);
    }
}

// -- Thread data --

pub const ThreadData = struct {
    channel: ssh.Channel,
    session: *ssh.SshSession,
    io: *termio.Termio,
    poll_timer: xev.Timer,
    poll_timer_c: xev.Completion = .{},
    frame_buf: std.ArrayList(u8),

    pub fn deinit(self: *ThreadData, _: Allocator) void {
        self.poll_timer.deinit();
        self.frame_buf.deinit(std.heap.page_allocator);
    }
};

pub const Config = struct {
    ssh_target: []const u8,
    jump: ?[]const u8 = null,
    label: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    connection_manager: *SshConnectionManager,
};
