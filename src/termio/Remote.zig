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
const Allocator = std.mem.Allocator;
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
        // Verify the connection is still ready — conn_state is atomic,
        // so no mutex needed. This avoids a TOCTOU with the reconnect
        // thread that may null entry.channel between our check and use.
        if (entry.conn_state.load(.acquire) != .ready) return error.SshConnectionFailed;
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
                .label = self.ssh_ctx.target, // Identify this viewer by SSH target
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

            // Send the embedder-provided label (cmux workspace title) if set.
            // Otherwise send "" so the daemon generates a readable adjective-noun
            // name (bare-ghostty mode). The hex session_id is NOT a display name —
            // the daemon already keys the group by group_id (derived above), so we
            // must never send it as the label.
            const label = self.ssh_ctx.label orelse "";

            const open_payload = (session.protocol.Open{
                .open_type = open_type,
                .resize = open_resize,
                .surface_id = if (open_type == .session_attach) session.shared.zero_uuid else self.ssh_ctx.surface_id,
                .group_id = self.ssh_ctx.group_id,
                .max_scrollback = self.scrollback_limit,
                .label = label,
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

/// Performs SSH connection setup: delegates to the shared
/// `session.client.attachRemoteSurface` helper so the libghostty C
/// API path (`apprt/embedded/ssh_capi.zig`) and this terminal-
/// surface path stay in lockstep. State transitions still flow
/// through the calling surface's mailbox AND the Entry's
/// broadcast fan-out (which is a no-op during first-surface setup
/// since no surfaces are registered yet — see helper docstring).
fn setupConnection(
    self: *Remote,
    alloc: Allocator,
    mailbox: *apprt.surface.Mailbox,
    entry: *SshConnectionManager.Entry,
) !void {
    try session.client.attachRemoteSurface(
        alloc,
        self.connection_manager,
        entry,
        mailbox,
        .{
            .max_reconnect_attempts = self.ssh_ctx.reconnect_attempts,
            .reconnect_backoff = self.ssh_ctx.reconnect_backoff,
            .reconnect_interval_ms = self.ssh_ctx.reconnect_interval_ms,
            .scrollback_limit = self.scrollback_limit,
        },
    );
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

/// Abort an in-flight connect/reconnect on surface teardown. Called from
/// the MAIN thread immediately before io_thr.join() (via Backend.requestStop).
///
/// Delegated to the manager so the whole abort runs under the manager mutex —
/// the SAME lock `release()` holds across its entire teardown (including
/// `destroy(entry)`). That serialization is load-bearing: during the INITIAL
/// connect the cancel signal unblocks the IO thread, which then unwinds into
/// `release()` (via threadEnter's errdefer) and frees the Entry. Without the
/// lock, that free could race this abort's field writes (use-after-free).
/// Keying by (target, jump) — not self.conn_entry — is required because
/// conn_entry is still null during the initial connect (it is set only after
/// setupConnection returns).
pub fn requestStop(self: *Remote) void {
    self.connection_manager.abortInFlightConnect(
        self.ssh_ctx.target,
        self.ssh_ctx.jump,
    );
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
        const payload = (session.protocol.Resize{
            .rows = @intCast(grid_size.rows),
            .cols = @intCast(grid_size.columns),
            .width_px = @intCast(screen_size.width),
            .height_px = @intCast(screen_size.height),
        }).bytes();
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
        // Pre-process into a single buffer to avoid per-byte enqueue overhead.
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        for (data) |byte| {
            if (byte == '\r') {
                if (pos + 2 > buf.len) {
                    SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, buf[0..pos]);
                    pos = 0;
                }
                buf[pos] = '\r';
                buf[pos + 1] = '\n';
                pos += 2;
            } else {
                if (pos + 1 > buf.len) {
                    SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, buf[0..pos]);
                    pos = 0;
                }
                buf[pos] = byte;
                pos += 1;
            }
        }
        if (pos > 0) {
            SshConnectionManager.enqueueWrite(entry, .data_in, self.target_id, buf[0..pos]);
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
