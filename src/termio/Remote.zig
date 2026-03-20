//! Remote implements the termio backend for SSH remote sessions.
//! It connects to a remote host via libssh2 and communicates with
//! the ghostty session helper using the binary protocol with multiplexed
//! target IDs. Multiple surfaces share one SSH channel per host.
//!
//! All libssh2 operations happen on a dedicated SSH thread per connection
//! (managed by SshConnectionManager). Surfaces enqueue writes via a
//! thread-safe queue and receive frames via direct processOutput calls
//! from the SSH thread — the same pattern as Exec.ReadThread.
const Remote = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const renderer = @import("../renderer.zig");
const terminal = @import("../terminal/main.zig");
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");
const session = @import("../session.zig");
const ssh = session.ssh;
const SshConnectionManager = @import("SshConnectionManager.zig");

const log = std.log.scoped(.io_remote);

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

/// This surface's target ID for multiplexing (assigned during threadEnter)
target_id: u16 = 0,

/// Initial grid size, stored from initTerminal
grid_size: renderer.GridSize = .{ .columns = 80, .rows = 24 },
screen_size: renderer.ScreenSize = .{ .width = 0, .height = 0 },

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
    // Release our reference to the connection (safety net if threadExit wasn't called)
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
    // Show overlay
    _ = td.surface_mailbox.push(.{ .connection_state = .connecting }, .{ .forever = {} });

    // Acquire a connection from the pool
    const entry = try self.connection_manager.acquire(self.ssh_target, self.jump);
    self.conn_entry = entry;
    errdefer {
        self.connection_manager.release(self.ssh_target, self.jump);
        self.conn_entry = null;
    }

    // Connection setup with race prevention via atomic state.
    // First surface transitions uninitialized → connecting → ready.
    // Subsequent surfaces wait until ready or failed.
    const prev = entry.conn_state.cmpxchgStrong(.uninitialized, .connecting, .seq_cst, .seq_cst);
    if (prev == null) {
        // We are the first surface — establish the SSH connection
        self.setupConnection(alloc, &td.surface_mailbox, entry) catch |err| {
            entry.conn_state.store(.failed, .seq_cst);
            return err;
        };
        entry.conn_state.store(.ready, .seq_cst);
    } else {
        // Another surface is connecting or already connected — wait
        while (true) {
            const state = entry.conn_state.load(.seq_cst);
            if (state == .ready) break;
            if (state == .failed) return error.SshConnectionFailed;
            std.Thread.sleep(1_000_000); // 1ms
        }
        if (entry.channel == null) return error.SshConnectionFailed;
    }

    // Allocate a target ID for this surface
    self.target_id = self.connection_manager.allocateTarget(entry);

    // Register surface for frame dispatch from the SSH thread
    SshConnectionManager.registerSurface(entry, self.target_id, io, &td.surface_mailbox);
    errdefer SshConnectionManager.unregisterSurface(entry, self.target_id);

    _ = td.surface_mailbox.push(.{ .connection_state = .setup }, .{ .forever = {} });

    // Send session_open frame via write queue.
    {
        const mode: session.protocol.OpenMode = if (self.session_id != null) .attach else .new;
        const label_or_id = self.session_id orelse (self.label orelse "session");
        const open_payload = (session.protocol.SessionOpen{
            .resize = .{
                .rows = @intCast(self.grid_size.rows),
                .cols = @intCast(self.grid_size.columns),
                .width_px = @intCast(self.screen_size.width),
                .height_px = @intCast(self.screen_size.height),
            },
            .mode = mode,
            .label_or_id = label_or_id,
        }).encode(alloc) catch return error.OutOfMemory;
        defer alloc.free(open_payload);
        SshConnectionManager.enqueueWrite(entry, .session_open, self.target_id, open_payload);
    }

    // Dismiss the connection overlay
    _ = td.surface_mailbox.push(.{ .connection_state = .connected }, .{ .forever = {} });

    // Store minimal thread data — no poll timer, the SSH thread handles reads
    td.backend = .{ .remote = .{
        .entry = entry,
        .target_id = self.target_id,
    } };
}

/// Performs SSH connection setup: connect, upload helper, start daemon,
/// open channel, switch to non-blocking, and spawn the SSH thread.
fn setupConnection(
    self: *Remote,
    alloc: Allocator,
    mailbox: *apprt.surface.Mailbox,
    entry: *SshConnectionManager.Entry,
) !void {
    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    entry.ctx.connect(stderr) catch |err| {
        _ = mailbox.push(.{ .connection_state = .{ .failed = .unknown } }, .{ .forever = {} });
        return err;
    };

    const helper_path = session.client.ensureRemoteHelper(alloc, &entry.ctx, stderr, mailbox) catch |err| {
        _ = mailbox.push(.{ .connection_state = .{ .failed = .helper_failed } }, .{ .forever = {} });
        return err;
    };

    session.client.ensureRemoteDaemon(alloc, &entry.ctx, helper_path, true) catch |err| {
        alloc.free(helper_path);
        _ = mailbox.push(.{ .connection_state = .{ .failed = .helper_failed } }, .{ .forever = {} });
        return err;
    };

    self.connection_manager.mutex.lock();
    if (entry.helper_path.len > 0) self.connection_manager.alloc.free(entry.helper_path);
    entry.helper_path = helper_path;
    self.connection_manager.mutex.unlock();

    const channel = session.client.openMultiplexChannel(
        alloc,
        &entry.ctx,
        entry.helper_path,
    ) catch |err| {
        _ = mailbox.push(.{ .connection_state = .{ .failed = .unknown } }, .{ .forever = {} });
        return err;
    };

    // Switch to non-blocking for the SSH thread
    var sess = &entry.ctx.session.?;
    sess.setBlocking(0);

    self.connection_manager.mutex.lock();
    entry.channel = channel;
    self.connection_manager.mutex.unlock();

    // Create pipes for SSH thread communication
    entry.quit_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.quit_pipe[0]);
        posix.close(entry.quit_pipe[1]);
    }
    entry.write_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.write_pipe[0]);
        posix.close(entry.write_pipe[1]);
    }

    // Spawn the dedicated SSH thread
    entry.ssh_thread = try std.Thread.spawn(.{}, SshConnectionManager.sshThreadMain, .{entry});
    entry.ssh_thread.?.setName("ssh-io") catch {};
}

pub fn threadExit(self: *Remote, td: *termio.Termio.ThreadData) void {
    _ = td;
    const entry = self.conn_entry orelse return;

    // Enqueue session_close frame
    SshConnectionManager.enqueueWrite(entry, .session_close, self.target_id, "");

    // Unregister surface — after this returns, SSH thread won't access our io
    SshConnectionManager.unregisterSurface(entry, self.target_id);

    // Release connection reference (may shut down SSH thread if last ref)
    self.connection_manager.release(self.ssh_target, self.jump);
    self.conn_entry = null;
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

    if (self.conn_entry) |entry| {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u16, payload[0..2], @intCast(grid_size.rows), .little);
        std.mem.writeInt(u16, payload[2..4], @intCast(grid_size.columns), .little);
        std.mem.writeInt(u16, payload[4..6], @intCast(screen_size.width), .little);
        std.mem.writeInt(u16, payload[6..8], @intCast(screen_size.height), .little);
        SshConnectionManager.enqueueWrite(entry, .resize, self.target_id, &payload);
    }
}

pub fn queueWrite(
    self: *Remote,
    alloc: Allocator,
    td: *termio.Termio.ThreadData,
    data: []const u8,
    linefeed: bool,
) !void {
    _ = alloc;
    _ = td;

    const entry = self.conn_entry orelse return;

    if (linefeed) {
        var i: usize = 0;
        while (i < data.len) {
            const byte = data[i];
            i += 1;
            if (byte == '\r') {
                SshConnectionManager.enqueueWrite(entry, .stdin, self.target_id, "\r\n");
            } else {
                SshConnectionManager.enqueueWrite(entry, .stdin, self.target_id, data[i - 1 .. i]);
            }
        }
    } else {
        SshConnectionManager.enqueueWrite(entry, .stdin, self.target_id, data);
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

// -- Thread data --

pub const ThreadData = struct {
    entry: *SshConnectionManager.Entry,
    target_id: u16,

    pub fn deinit(self: *ThreadData, _: Allocator) void {
        _ = self;
        // Nothing to clean up — SSH thread owns the shared resources
    }
};

pub const Config = struct {
    ssh_target: []const u8,
    jump: ?[]const u8 = null,
    label: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    connection_manager: *SshConnectionManager,
};
