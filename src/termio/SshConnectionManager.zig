//! Shared SSH connection pool keyed by (ssh_target, jump).
//! Multiple surfaces (tabs/splits) to the same host share one SSH connection,
//! one SSH channel to the helper process, and multiplexed sessions via target IDs.
//! A dedicated SSH thread per connection exclusively owns all libssh2 calls,
//! since libssh2 is NOT thread-safe. Surfaces communicate via a thread-safe
//! write queue and receive frames via direct processOutput calls.
const SshConnectionManager = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const ssh = session.ssh;
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");

const log = std.log.scoped(.ssh_connection_manager);

pub const MAX_SURFACES: usize = 64;

mutex: std.Thread.Mutex = .{},
connections: std.StringArrayHashMap(Entry),
alloc: Allocator,

pub const Uuid = session.shared.Uuid;

pub const SurfaceSlot = struct {
    target_id: u16,
    io: *termio.Termio,
    surface_mailbox: *apprt.surface.Mailbox,
    /// Stable surface UUID for reconnect (survives target_id changes).
    surface_id: Uuid = session.shared.zero_uuid,
    /// Group UUID this surface belongs to (for reconnect).
    group_id: Uuid = session.shared.zero_uuid,
};

pub const WriteRequest = struct {
    kind: session.protocol.Kind,
    target_id: u16,
    data: []const u8, // owned by page_allocator, freed after send
};

pub const ConnState = enum(u8) {
    uninitialized,
    connecting,
    ready,
    failed,
};

pub const Entry = struct {
    ctx: session.client.SshContext,
    helper_path: []const u8,
    ref_count: u32,
    /// Shared SSH channel to the multiplexed helper process (one per host).
    channel: ?ssh.Channel = null,
    /// Next target ID to assign for multiplexing.
    next_target: u16 = 1,

    // -- SSH thread fields --
    ssh_thread: ?std.Thread = null,
    quit_pipe: [2]posix.fd_t = .{ -1, -1 },
    write_pipe: [2]posix.fd_t = .{ -1, -1 },

    // Registered surfaces for frame dispatch
    surfaces: [MAX_SURFACES]?SurfaceSlot = [_]?SurfaceSlot{null} ** MAX_SURFACES,
    surfaces_mutex: std.Thread.Mutex = .{},

    // Write queue (thread-safe)
    write_queue_mu: std.Thread.Mutex = .{},
    write_queue: std.ArrayList(WriteRequest) = .empty,

    // Connection state for race prevention between surfaces
    conn_state: std.atomic.Value(ConnState) = .{ .raw = .uninitialized },

    // Keepalive tracking (written/read only by the SSH thread)
    last_keepalive_received: i128 = 0,
    /// Set to true after receiving the first keepalive from the remote.
    /// Stale detection is only active when this is true, ensuring backward
    /// compatibility with old helpers that don't support keepalive.
    keepalive_active: bool = false,

    // Reconnect state
    reconnect_count: u32 = 0,
    max_reconnect_time_ns: i128 = 5 * 60 * std.time.ns_per_s, // 5 minutes

    // Authentication state (for password prompts)
    auth_state: AuthState = .{},

    pub const AuthState = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        /// Password provided by the GTK thread. null = not yet provided.
        password: ?[]const u8 = null,
        /// True if the user cancelled the password prompt.
        cancelled: bool = false,
    };
};

pub fn init(alloc: Allocator) SshConnectionManager {
    return .{
        .connections = std.StringArrayHashMap(Entry).init(alloc),
        .alloc = alloc,
    };
}

pub fn deinit(self: *SshConnectionManager) void {
    var it = self.connections.iterator();
    while (it.next()) |entry| {
        self.alloc.free(entry.key_ptr.*);
        if (entry.value_ptr.helper_path.len > 0) self.alloc.free(entry.value_ptr.helper_path);
        if (entry.value_ptr.channel) |*ch| ch.close();
        for (entry.value_ptr.write_queue.items) |req| {
            std.heap.page_allocator.free(req.data);
        }
        entry.value_ptr.write_queue.deinit(std.heap.page_allocator);
        entry.value_ptr.ctx.deinit();
    }
    self.connections.deinit();
}

/// Build the lookup key from ssh_target + optional jump.
fn makeKey(alloc: Allocator, ssh_target: []const u8, jump: ?[]const u8) ![]u8 {
    if (jump) |j| {
        return std.fmt.allocPrint(alloc, "{s}|{s}", .{ ssh_target, j });
    }
    return alloc.dupe(u8, ssh_target);
}

/// Acquire a connection entry. If the entry already exists its ref_count
/// is incremented; otherwise a new entry is created.
pub fn acquire(
    self: *SshConnectionManager,
    ssh_target: []const u8,
    jump: ?[]const u8,
) !*Entry {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = try makeKey(self.alloc, ssh_target, jump);

    if (self.connections.getPtr(key)) |entry| {
        self.alloc.free(key);
        entry.ref_count += 1;
        return entry;
    }

    const entry: Entry = .{
        .ctx = .{
            .alloc = self.alloc,
            .ssh_target = ssh_target,
            .jump = jump,
        },
        .helper_path = &.{},
        .ref_count = 1,
    };
    try self.connections.put(key, entry);
    return self.connections.getPtr(key).?;
}

/// Allocate the next target ID for a session on this entry.
pub fn allocateTarget(self: *SshConnectionManager, entry: *Entry) u16 {
    self.mutex.lock();
    defer self.mutex.unlock();
    const target = entry.next_target;
    entry.next_target +%= 1;
    if (entry.next_target == 0) entry.next_target = 1; // skip 0
    return target;
}

/// Register a surface for frame dispatch from the SSH thread.
/// Returns true on success, false if the maximum number of surfaces
/// has been reached (caller should report error to user).
pub fn registerSurface(
    entry: *Entry,
    target_id: u16,
    io: *termio.Termio,
    mailbox: *apprt.surface.Mailbox,
    surface_id: Uuid,
    group_id: Uuid,
) bool {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.* == null) {
            slot.* = .{
                .target_id = target_id,
                .io = io,
                .surface_mailbox = mailbox,
                .surface_id = surface_id,
                .group_id = group_id,
            };
            return true;
        }
    }
    log.err("max surfaces ({d}) exceeded for SSH connection", .{MAX_SURFACES});
    return false;
}

/// Unregister a surface. After this returns, the SSH thread will not
/// access the surface's io pointer (surfaces_mutex acts as barrier).
pub fn unregisterSurface(entry: *Entry, target_id: u16) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.*) |s| {
            if (s.target_id == target_id) {
                slot.* = null;
                return;
            }
        }
    }
}

/// Enqueue a write request for the SSH thread to send.
/// The data is duplicated internally; the caller retains ownership of the input.
pub fn enqueueWrite(entry: *Entry, kind: session.protocol.Kind, target_id: u16, data: []const u8) void {
    const alloc = std.heap.page_allocator;
    const owned_data = alloc.dupe(u8, data) catch return;

    entry.write_queue_mu.lock();
    entry.write_queue.append(alloc, .{
        .kind = kind,
        .target_id = target_id,
        .data = owned_data,
    }) catch {
        entry.write_queue_mu.unlock();
        alloc.free(owned_data);
        return;
    };
    entry.write_queue_mu.unlock();

    // Wake the SSH thread
    _ = posix.write(entry.write_pipe[1], "w") catch {};
}

/// Release a reference. When ref_count reaches 0, shut down the SSH thread
/// and clean up the connection.
pub fn release(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    if (self.connections.getPtr(key)) |entry| {
        if (entry.ref_count > 1) {
            entry.ref_count -= 1;
            return;
        }

        // Last reference — shut down SSH thread and clean up.
        if (entry.ssh_thread) |thread| {
            _ = posix.write(entry.quit_pipe[1], "q") catch {};
            thread.join();
            // Close write ends (read ends are closed by the thread)
            posix.close(entry.quit_pipe[1]);
            posix.close(entry.write_pipe[1]);
        }

        // Clean up remaining write queue
        for (entry.write_queue.items) |req| {
            std.heap.page_allocator.free(req.data);
        }
        entry.write_queue.deinit(std.heap.page_allocator);

        // Free password if one was provided
        if (entry.auth_state.password) |pw| {
            std.heap.page_allocator.free(pw);
            entry.auth_state.password = null;
        }

        if (entry.helper_path.len > 0) self.alloc.free(entry.helper_path);
        if (entry.channel) |*ch| ch.close();
        entry.ctx.deinit();

        const removed = self.connections.fetchOrderedRemove(key);
        if (removed) |r| self.alloc.free(r.key);
    }
}

// =========================================================================
// SSH thread — exclusively owns all libssh2 calls for one connection.
// Modeled after Exec.ReadThread: blocks in posix.poll when idle, zero CPU.
// =========================================================================

pub fn sshThreadMain(entry: *Entry) void {

    // Close read ends of pipes on exit
    defer posix.close(entry.quit_pipe[0]);
    defer posix.close(entry.write_pipe[0]);

    var sess = &entry.ctx.session.?;
    var channel = &entry.channel.?;
    const ssh_sock = sess.getPollSocket();

    // Set write_pipe read end to non-blocking for drain
    setNonBlocking(entry.write_pipe[0]);

    var pollfds: [3]posix.pollfd = .{
        .{ .fd = ssh_sock, .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.write_pipe[0], .events = posix.POLL.IN, .revents = undefined },
    };

    var frame_buf: std.ArrayList(u8) = .empty;
    defer frame_buf.deinit(std.heap.page_allocator);

    var read_buf: [4096]u8 = undefined;

    // Keepalive state.
    // Stale detection only activates after receiving the first keepalive
    // from the remote (entry.keepalive_active). This ensures backward
    // compatibility with old helpers that don't support keepalive.
    const now_init = std.time.nanoTimestamp();
    var last_keepalive_sent: i128 = now_init;
    entry.last_keepalive_received = now_init;
    entry.keepalive_active = false;

    while (true) {
        // 1. Process SSH transport (needed for tunneled sessions)
        sess.pollTransport(1);

        // 2. Drain reads (non-blocking tight loop)
        while (true) {
            const rc = channel.readNonBlock(&read_buf);
            if (rc > 0) {
                frame_buf.appendSlice(
                    std.heap.page_allocator,
                    read_buf[0..@intCast(rc)],
                ) catch break;
            } else break;
        }

        // Check channel EOF (helper process exited — all sessions dead)
        if (channel.eof()) {
            log.info("ssh channel EOF", .{});
            notifyAllSurfaces(entry);
            return;
        }

        // Process complete protocol frames (updates entry.last_keepalive_received)
        processFrames(&frame_buf, entry);

        // 3. Drain write queue
        {
            entry.write_queue_mu.lock();
            for (entry.write_queue.items) |req| {
                sendFrame(channel, req.kind, req.target_id, req.data) catch |err| {
                    log.warn("ssh write failed: {}", .{err});
                };
                std.heap.page_allocator.free(req.data);
            }
            entry.write_queue.clearRetainingCapacity();
            entry.write_queue_mu.unlock();
        }

        // Drain write pipe notification bytes
        drainPipe(entry.write_pipe[0]);

        // 4. Keepalive: send if interval elapsed, detect stale
        const now = std.time.nanoTimestamp();
        if (now - last_keepalive_sent >= session.protocol.keepalive_interval_ns) {
            var ts_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &ts_buf, @intCast(@as(u128, @bitCast(now)) & 0xFFFFFFFFFFFFFFFF), .little);
            sendFrame(channel, .keepalive, 0, &ts_buf) catch |err| {
                log.warn("keepalive send failed: {}", .{err});
            };
            last_keepalive_sent = now;
        }

        if (entry.keepalive_active and
            now - entry.last_keepalive_received > session.protocol.keepalive_stale_ns)
        {
            log.warn("ssh connection stale (no keepalive for {d}s)", .{
                @as(i64, @intCast(@divFloor(now - entry.last_keepalive_received, std.time.ns_per_s))),
            });
            // Attempt reconnection
            if (attemptReconnect(entry)) {
                // Reconnected — reset keepalive state and continue
                const reconnect_now = std.time.nanoTimestamp();
                last_keepalive_sent = reconnect_now;
                entry.last_keepalive_received = reconnect_now;
                entry.reconnect_count = 0;

                // Update local references (session/channel may have changed)
                sess = &entry.ctx.session.?;
                channel = &entry.channel.?;

                // Notify surfaces that we're back
                broadcastConnectionState(entry, .connected);
                continue;
            } else {
                // Reconnect failed — give up
                notifyAllSurfaces(entry);
                return;
            }
        }

        // 5. Compute poll events based on libssh2 block directions
        pollfds[0].events = posix.POLL.IN;
        if (sess.needsWrite()) pollfds[0].events |= posix.POLL.OUT;

        // 6. Compute poll timeout: wake up in time to send the next keepalive
        const elapsed_since_send = now - last_keepalive_sent;
        const remaining_ns = session.protocol.keepalive_interval_ns - elapsed_since_send;
        const timeout_ms: i32 = if (remaining_ns <= 0)
            1
        else
            @intCast(@min(@as(i128, 15000), @divFloor(remaining_ns, std.time.ns_per_ms)));

        // 7. Block in poll until next event or timeout
        _ = posix.poll(&pollfds, timeout_ms) catch |err| {
            log.warn("poll failed: {}", .{err});
            return;
        };

        // 8. Check quit pipe
        if (pollfds[1].revents & posix.POLL.IN != 0) {
            log.info("ssh thread got quit signal", .{});
            return;
        }
    }
}

fn notifyAllSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (entry.surfaces) |slot| {
        if (slot) |s| {
            _ = s.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        }
    }
}

fn broadcastConnectionState(entry: *Entry, state: session.protocol.ConnectionState) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (entry.surfaces) |slot| {
        if (slot) |s| {
            _ = s.surface_mailbox.push(.{ .connection_state = state }, .{ .forever = {} });
        }
    }
}

/// Attempt to reconnect the SSH connection with exponential backoff.
/// Returns true if reconnection succeeded, false if we should give up.
fn attemptReconnect(entry: *Entry) bool {
    const reconnect_start = std.time.nanoTimestamp();
    var backoff_ms: u64 = 1000; // Start at 1s

    broadcastConnectionState(entry, .{ .reconnecting = .{
        .attempt = 0,
        .elapsed_ns = 0,
    } });

    // Close old channel
    if (entry.channel) |*ch| {
        ch.close();
        entry.channel = null;
    }

    var attempt: u32 = 0;
    while (true) {
        attempt += 1;
        const elapsed = std.time.nanoTimestamp() - reconnect_start;

        // Check timeout
        if (elapsed > entry.max_reconnect_time_ns) {
            log.warn("reconnect timeout after {d} attempts", .{attempt});
            broadcastConnectionState(entry, .{ .failed = .timeout });
            return false;
        }

        broadcastConnectionState(entry, .{ .reconnecting = .{
            .attempt = attempt,
            .elapsed_ns = elapsed,
        } });

        log.info("reconnect attempt {d} (backoff {d}ms)", .{ attempt, backoff_ms });

        // Close old session state
        entry.ctx.deinit();
        entry.ctx.session = null;
        entry.ctx.jump_session = null;

        // Try to reconnect
        var stderr_buf: [256]u8 = undefined;
        var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer_.interface;

        entry.ctx.connect(stderr) catch {
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            backoff_ms = @min(backoff_ms * 2, 30_000);
            continue;
        };

        // Try to open multiplexed channel (with daemon restart fallback)
        const new_channel = tryOpenChannel(entry) orelse {
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            backoff_ms = @min(backoff_ms * 2, 30_000);
            continue;
        };

        // Switch to non-blocking
        var sess = &entry.ctx.session.?;
        sess.setBlocking(0);
        entry.channel = new_channel;

        // Re-open sessions for registered surfaces using their stable IDs.
        // For grouped sessions, only send session_open(attach) for the first
        // surface — the daemon will reply with layout_restore, and the UI
        // layer will re-open individual surfaces with correct sizes.
        // For non-grouped surfaces, send session_open(attach) individually.
        entry.surfaces_mutex.lock();
        var group_sent = std.AutoArrayHashMap(session.shared.Uuid, void).init(std.heap.page_allocator);
        defer group_sent.deinit();
        for (entry.surfaces) |slot| {
            if (slot) |s| {
                if (!session.shared.isZeroUuid(s.group_id)) {
                    // Only send one session_open(attach) per group
                    if (group_sent.contains(s.group_id)) continue;
                    group_sent.put(s.group_id, {}) catch continue;

                    const open_payload = (session.protocol.SessionOpen{
                        .resize = .{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 },
                        .mode = .attach,
                        .surface_id = s.surface_id,
                        .group_id = s.group_id,
                        .label = "reconnected",
                    }).encode(std.heap.page_allocator) catch continue;
                    defer std.heap.page_allocator.free(open_payload);
                    sendFrame(&entry.channel.?, .session_open, s.target_id, open_payload) catch {
                        log.warn("reconnect: failed to re-open group for target={d}", .{s.target_id});
                        _ = s.surface_mailbox.push(.{
                            .child_exited = .{ .exit_code = 1, .runtime_ms = 0 },
                        }, .{ .forever = {} });
                    };
                } else {
                    // Standalone surface: use session_open(attach) with surface_id
                    const open_payload = (session.protocol.SessionOpen{
                        .resize = .{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 },
                        .mode = .attach,
                        .surface_id = s.surface_id,
                        .group_id = s.group_id,
                        .label = "reconnected",
                    }).encode(std.heap.page_allocator) catch continue;
                    defer std.heap.page_allocator.free(open_payload);
                    sendFrame(&entry.channel.?, .session_open, s.target_id, open_payload) catch {
                        log.warn("reconnect: failed to re-open surface target={d}", .{s.target_id});
                        _ = s.surface_mailbox.push(.{
                            .child_exited = .{ .exit_code = 1, .runtime_ms = 0 },
                        }, .{ .forever = {} });
                    };
                }
            }
        }
        entry.surfaces_mutex.unlock();

        log.info("reconnected after {d} attempts", .{attempt});
        return true;
    }
}

/// Try to open a multiplexed channel, restarting the daemon if needed.
/// Copies helper_path under surfaces_mutex to avoid racing with setupConnection.
fn tryOpenChannel(entry: *Entry) ?ssh.Channel {
    const alloc = std.heap.page_allocator;

    // Copy helper_path under mutex — setupConnection writes it from another thread.
    entry.surfaces_mutex.lock();
    const helper_path = alloc.dupe(u8, entry.helper_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(helper_path);

    // First attempt
    if (session.client.openMultiplexChannel(alloc, &entry.ctx, helper_path)) |ch| {
        return ch;
    } else |_| {}

    // Helper might be dead — restart daemon and retry
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, helper_path, true) catch return null;

    return session.client.openMultiplexChannel(alloc, &entry.ctx, helper_path) catch null;
}

fn notifyAllSurfacesStale(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (entry.surfaces) |slot| {
        if (slot) |s| {
            _ = s.surface_mailbox.push(.{
                .connection_state = .stale,
            }, .{ .forever = {} });
        }
    }
}

fn processFrames(frame_buf: *std.ArrayList(u8), entry: *Entry) void {
    while (frame_buf.items.len >= session.protocol.header_size) {
        const kind_byte = frame_buf.items[0];
        const frame_target = std.mem.readInt(u16, frame_buf.items[2..4], .little);
        const payload_len = std.mem.readInt(u32, frame_buf.items[4..8], .little);
        const total = session.protocol.header_size + payload_len;
        if (frame_buf.items.len < total) break;

        const kind = std.meta.intToEnum(session.protocol.Kind, kind_byte) catch {
            shiftBuffer(frame_buf, total);
            continue;
        };
        const payload = frame_buf.items[session.protocol.header_size..total];

        // Handle keepalive: update timestamp, don't dispatch to surfaces
        if (kind == .keepalive) {
            entry.last_keepalive_received = std.time.nanoTimestamp();
            entry.keepalive_active = true;
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Hold surfaces_mutex during dispatch to prevent use-after-free
        // on surface io pointers (unregisterSurface acquires the same lock).
        entry.surfaces_mutex.lock();
        if (frame_target == 0) {
            // Broadcast to all surfaces
            for (entry.surfaces) |slot| {
                if (slot) |s| dispatchFrame(kind, s, payload);
            }
        } else {
            if (findSurface(entry, frame_target)) |s| {
                dispatchFrame(kind, s, payload);
            }
        }
        entry.surfaces_mutex.unlock();

        shiftBuffer(frame_buf, total);
    }
}

fn dispatchFrame(kind: session.protocol.Kind, slot: SurfaceSlot, payload: []const u8) void {
    switch (kind) {
        .stdout, .state_full => {
            @call(.always_inline, termio.Termio.processOutput, .{ slot.io, payload });
        },
        .session_opened => {
            log.info("remote session opened id={s}", .{payload});
        },
        .layout_restore => {
            log.info("received layout_restore blob len={d}", .{payload.len});
            // Copy blob to heap and send to surface for tree recreation
            const blob_copy = std.heap.page_allocator.dupe(u8, payload) catch {
                log.err("failed to allocate layout_restore blob", .{});
                return;
            };
            _ = slot.surface_mailbox.push(.{
                .layout_restore = .{
                    .blob = blob_copy.ptr,
                    .len = @intCast(blob_copy.len),
                },
            }, .{ .forever = {} });
        },
        .info => log.info("remote info: {s}", .{payload}),
        .err => log.err("remote error: {s}", .{payload}),
        .eof => {
            log.info("remote session EOF target={d}", .{slot.target_id});
            _ = slot.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        },
        else => {},
    }
}

fn findSurface(entry: *const Entry, target_id: u16) ?SurfaceSlot {
    for (entry.surfaces) |slot| {
        if (slot) |s| {
            if (s.target_id == target_id) return s;
        }
    }
    return null;
}

// -- Protocol helpers --

fn sendFrame(channel: *ssh.Channel, kind: session.protocol.Kind, target: u16, data: []const u8) !void {
    var header: [session.protocol.header_size]u8 = undefined;
    header[0] = @intFromEnum(kind);
    header[1] = 0; // reserved
    std.mem.writeInt(u16, header[2..4], target, .little);
    std.mem.writeInt(u32, header[4..8], @intCast(data.len), .little);
    try channel.write(&header);
    if (data.len > 0) try channel.write(data);
}

fn shiftBuffer(buf: *std.ArrayList(u8), amount: usize) void {
    if (amount >= buf.items.len) {
        buf.shrinkRetainingCapacity(0);
    } else {
        std.mem.copyForwards(u8, buf.items, buf.items[amount..]);
        buf.shrinkRetainingCapacity(buf.items.len - amount);
    }
}

fn setNonBlocking(fd: posix.fd_t) void {
    const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    _ = posix.fcntl(fd, posix.F.SETFL, flags | @as(usize, @as(u32, @bitCast(posix.O{ .NONBLOCK = true })))) catch {};
}

fn drainPipe(fd: posix.fd_t) void {
    var buf: [64]u8 = undefined;
    while (true) {
        _ = posix.read(fd, &buf) catch return;
    }
}
