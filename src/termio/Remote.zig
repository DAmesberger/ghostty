//! Remote implements the termio backend for SSH remote sessions.
//! It connects to a remote host via libssh2 and communicates with
//! the remote Ghostty instance using the binary protocol with multiplexed
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

const Uuid = session.shared.Uuid;
const SshConnectionContext = session.shared.SshConnectionContext;

/// Allocator used to own copied config strings.
alloc: Allocator,

/// SSH connection context — owns all SSH-related strings.
ssh_ctx: SshConnectionContext,

/// Reference to the shared connection manager
connection_manager: *SshConnectionManager,

/// The connection entry from the manager (set during threadEnter)
conn_entry: ?*SshConnectionManager.Entry = null,

/// This surface's target ID for multiplexing (assigned during threadEnter)
target_id: u16 = 0,

/// True if this surface was created from a layout restore (has a specific
/// surface_id from _ssh-surface-id config). Used to select attach mode
/// in open so the daemon reattaches to the existing PTY.
restoring: bool = false,

/// Set by the detach flow so threadExit skips sending close
/// (which would kill the daemon-side surface we want to keep alive).
detaching: bool = false,

/// Client-side scrollback limit in bytes, sent to the daemon via the Open frame.
scrollback_limit: u32 = 10_000_000,

/// Initial grid size, stored from initTerminal
grid_size: renderer.GridSize = .{ .columns = 80, .rows = 24 },
screen_size: renderer.ScreenSize = .{ .width = 0, .height = 0 },

pub fn init(
    alloc: Allocator,
    cfg: Config,
) !Remote {
    // Deep copy the context — the config memory is NOT stable after init.
    var ssh_ctx = try cfg.ssh_ctx.dupe(alloc);
    errdefer ssh_ctx.deinit(alloc);

    // Surface ID: use the configured one (from layout restore) or generate fresh.
    const restoring = !session.shared.isZeroUuid(ssh_ctx.surface_id);
    if (!restoring) {
        ssh_ctx.surface_id = session.shared.generateUuid();
    }

    return .{
        .alloc = alloc,
        .ssh_ctx = ssh_ctx,
        .restoring = restoring,
        .connection_manager = cfg.connection_manager,
        .scrollback_limit = cfg.scrollback_limit,
    };
}

pub fn deinit(self: *Remote) void {
    // Unblock any password wait if the surface is closing while the
    // authentication loop is blocked on the condition variable.
    if (self.conn_entry) |entry| {
        entry.auth_state.mutex.lock();
        entry.auth_state.cancelled = true;
        entry.auth_state.cond.signal();
        entry.auth_state.mutex.unlock();
    }

    // Release our reference to the connection (safety net if threadExit wasn't called)
    if (self.conn_entry != null) {
        self.connection_manager.release(self.ssh_ctx.target, self.ssh_ctx.jump);
        self.conn_entry = null;
    }

    self.ssh_ctx.deinit(self.alloc);
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

    // Acquire a connection from the pool. Don't set conn_entry yet —
    // other threads (resize, write) use it to enqueue data, and the
    // entry isn't safe to use until the connection is fully established.
    const entry = try self.connection_manager.acquire(self.ssh_ctx.target, self.ssh_ctx.jump);
    errdefer {
        self.connection_manager.release(self.ssh_ctx.target, self.ssh_ctx.jump);
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
        // Hold mutex when verifying channel after state transition
        // to prevent race with reconnect nulling channel
        self.connection_manager.mutex.lock();
        const has_channel = entry.channel != null;
        self.connection_manager.mutex.unlock();
        if (!has_channel) return error.SshConnectionFailed;
    }

    // Connection is fully established — now safe to expose the entry
    // to other threads via conn_entry.
    self.conn_entry = entry;

    // Allocate a target ID for this surface
    self.target_id = self.connection_manager.allocateTarget(entry);

    // Register surface for frame dispatch from the SSH thread
    if (!SshConnectionManager.registerSurface(entry, self.target_id, io, &td.surface_mailbox, self.ssh_ctx.surface_id, self.ssh_ctx.group_id, self.ssh_ctx.label)) {
        _ = td.surface_mailbox.push(.{ .connection_state = .{ .failed = .unknown } }, .{ .forever = {} });
        return error.MaxSurfacesExceeded;
    }
    errdefer SshConnectionManager.unregisterSurface(entry, self.target_id);

    _ = td.surface_mailbox.push(.{ .connection_state = .setup }, .{ .forever = {} });

    // Send unified open frame via write queue.
    {
        const open_resize: session.protocol.Resize = .{
            .rows = @intCast(self.grid_size.rows),
            .cols = @intCast(self.grid_size.columns),
            .width_px = @intCast(self.screen_size.width),
            .height_px = @intCast(self.screen_size.height),
        };

        if (!session.shared.isZeroUuid(self.ssh_ctx.group_id)) {
            // Split/restored surface: join existing group via surface open.
            // Use attach mode if restoring from a layout blob (_ssh-surface-id
            // was set), so the daemon reattaches to the existing PTY.
            const open_type: session.protocol.OpenType = if (self.ssh_ctx.session_id != null or self.restoring) .surface_attach else .surface_new;
            const open_payload = (session.protocol.Open{
                .open_type = open_type,
                .resize = open_resize,
                .group_id = self.ssh_ctx.group_id,
                .surface_id = self.ssh_ctx.surface_id,
                .max_scrollback = self.scrollback_limit,
            }).encode(alloc) catch return error.OutOfMemory;
            defer alloc.free(open_payload);
            SshConnectionManager.enqueueWrite(entry, .open, self.target_id, open_payload);
        } else {
            const open_type: session.protocol.OpenType = if (self.ssh_ctx.session_id != null) .session_attach else .session_new;

            if (open_type == .session_attach) {
                // Attach mode: use the daemon's group_id so child surfaces
                // (from layout restore) send open with the correct
                // group_id that the daemon recognizes.
                if (self.ssh_ctx.session_id) |sid| {
                    self.ssh_ctx.group_id = session.shared.parseUuid(sid) catch
                        session.shared.parseUuidDashed(sid) catch
                        session.shared.generateUuid();
                } else {
                    self.ssh_ctx.group_id = session.shared.generateUuid();
                }
            } else {
                // New session: generate a fresh group_id
                self.ssh_ctx.group_id = session.shared.generateUuid();
            }

            // Update the registered slot so detach/reconnect can find us by group.
            SshConnectionManager.updateSurfaceGroupId(entry, self.target_id, self.ssh_ctx.group_id);

            // Generate a readable session name if no explicit label was provided.
            if (self.ssh_ctx.label == null) {
                self.ssh_ctx.label = session.shared.generateReadableName(self.alloc, self.ssh_ctx.group_id) catch null;
            }

            const label = self.ssh_ctx.label orelse self.ssh_ctx.target;

            const open_payload = (session.protocol.Open{
                .open_type = open_type,
                .resize = open_resize,
                // For attach mode, send zero surface_id so the daemon picks
                // the first alive surface rather than looking up a specific one.
                .surface_id = if (open_type == .session_attach) session.shared.zero_uuid else self.ssh_ctx.surface_id,
                .group_id = self.ssh_ctx.group_id,
                .max_scrollback = self.scrollback_limit,
                .label = if (open_type == .session_attach) (self.ssh_ctx.session_id orelse label) else label,
            }).encode(alloc) catch return error.OutOfMemory;
            defer alloc.free(open_payload);
            SshConnectionManager.enqueueWrite(entry, .open, self.target_id, open_payload);
        }
    }

    // Dismiss the connection overlay
    _ = td.surface_mailbox.push(.{ .connection_state = .connected }, .{ .forever = {} });

    // Store minimal thread data — no poll timer, the SSH thread handles reads
    td.backend = .{ .remote = .{
        .entry = entry,
        .target_id = self.target_id,
    } };
}

/// Performs SSH connection setup: connect, provision ghostty, start daemon,
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

    // Password authentication loop: use connectWithAuth so passwords come
    // from the GUI overlay instead of stdin.
    var for_jump: bool = false;
    while (true) {
        const result = entry.ctx.connectWithAuth(stderr, entry.auth_state.password, for_jump) catch |err| {
            _ = mailbox.push(.{ .connection_state = .{ .failed = .unknown } }, .{ .forever = {} });
            return err;
        };

        // Zero and free the previous password after use (allocated by GTK thread via page_allocator)
        if (entry.auth_state.password) |pw| {
            @memset(@constCast(pw), 0);
            std.heap.page_allocator.free(pw);
            entry.auth_state.password = null;
        }

        switch (result) {
            .success => break,
            .password_required_jump, .password_required_target => {
                for_jump = (result == .password_required_jump);

                // Tell the GTK overlay to show the password prompt
                var prompt: session.protocol.ConnectionState.PasswordPrompt = .{
                    .is_jump = for_jump,
                    .auth_state = @ptrCast(&entry.auth_state),
                };
                const host_name = if (for_jump) (entry.ctx.jump orelse "jump host") else entry.ctx.ssh_target;
                prompt.setHost(host_name);
                _ = mailbox.push(.{ .connection_state = .{
                    .password_required = prompt,
                } }, .{ .forever = {} });

                // Wait for the GTK thread to provide a password
                entry.auth_state.mutex.lock();
                while (entry.auth_state.password == null and !entry.auth_state.cancelled) {
                    entry.auth_state.cond.wait(&entry.auth_state.mutex);
                }

                if (entry.auth_state.cancelled) {
                    entry.auth_state.mutex.unlock();
                    _ = mailbox.push(.{ .connection_state = .{ .failed = .auth_failed } }, .{ .forever = {} });
                    return error.RemoteAuthRequired;
                }
                entry.auth_state.mutex.unlock();
                // Loop back to retry connectWithAuth with the provided password
            },
        }
    }

    const provision = session.client.ensureRemoteGhostty(alloc, &entry.ctx, stderr, mailbox) catch |err| {
        _ = mailbox.push(.{ .connection_state = .{ .failed = .helper_failed } }, .{ .forever = {} });
        return err;
    };
    const remote_bin_path = provision.path;

    // Only force-restart the daemon if the binary was re-provisioned
    // (version mismatch). Otherwise reuse the running daemon to preserve
    // existing sessions.
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, provision.provisioned) catch |err| {
        alloc.free(remote_bin_path);
        _ = mailbox.push(.{ .connection_state = .{ .failed = .helper_failed } }, .{ .forever = {} });
        return err;
    };

    entry.surfaces_mutex.lock();
    if (entry.remote_bin_path.len > 0) self.connection_manager.alloc.free(entry.remote_bin_path);
    entry.remote_bin_path = remote_bin_path;
    entry.surfaces_mutex.unlock();

    // Copy remote_bin_path for use below so we don't read the field after
    // releasing the lock (another thread could modify it).
    const remote_bin_path_local = self.alloc.dupe(u8, remote_bin_path) catch return error.OutOfMemory;
    defer self.alloc.free(remote_bin_path_local);

    const channel = session.client.openMultiplexChannel(
        alloc,
        &entry.ctx,
        remote_bin_path_local,
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

    // Store reconnect config into the entry (first surface only)
    entry.max_reconnect_attempts = self.ssh_ctx.reconnect_attempts;
    entry.reconnect_backoff = self.ssh_ctx.reconnect_backoff;
    entry.reconnect_interval_ms = self.ssh_ctx.reconnect_interval_ms;
    entry.scrollback_limit = self.scrollback_limit;

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
    entry.reconnect_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(entry.reconnect_pipe[0]);
        posix.close(entry.reconnect_pipe[1]);
    }

    // Spawn the dedicated SSH thread
    entry.ssh_thread = try std.Thread.spawn(.{}, SshConnectionManager.sshThreadMain, .{entry});
    entry.ssh_thread.?.setName("ssh-io") catch {};
}

pub fn threadExit(self: *Remote, td: *termio.Termio.ThreadData) void {
    _ = td;
    const entry = self.conn_entry orelse return;

    const has_group = !session.shared.isZeroUuid(self.ssh_ctx.group_id);

    if (self.detaching) {
        // Detach flow: the close(detach) frame was already sent by sendDetach.
        // Don't send close(surface) — the daemon-side surface must stay alive
        // so the session can be reattached later.
    } else if (has_group) {
        // Grouped surface: send close(surface) to kill this surface's PTY.
        if ((session.protocol.Close{
            .mode = .surface,
            .id = self.ssh_ctx.surface_id,
        }).encode(entry.alloc)) |close_payload| {
            defer entry.alloc.free(close_payload);
            SshConnectionManager.enqueueWrite(entry, .close, self.target_id, close_payload);
        } else |_| {
            SshConnectionManager.enqueueWrite(entry, .close, self.target_id, &.{@intFromEnum(session.protocol.CloseMode.surface)});
        }
    } else {
        // Standalone: send close(detach) to keep session alive
        SshConnectionManager.enqueueWrite(entry, .close, self.target_id, &.{@intFromEnum(session.protocol.CloseMode.detach)});
    }

    // Unregister surface from the SSH connection entry.
    SshConnectionManager.unregisterSurface(entry, self.target_id);

    // Release connection reference (may shut down SSH thread if last ref)
    self.connection_manager.release(self.ssh_ctx.target, self.ssh_ctx.jump);
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
                SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, "\r\n");
            } else {
                SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, data[i - 1 .. i]);
            }
        }
    } else {
        SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, data);
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
    ssh_ctx: SshConnectionContext,
    connection_manager: *SshConnectionManager,
    scrollback_limit: u32 = 10_000_000,
};
