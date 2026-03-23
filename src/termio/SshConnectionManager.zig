//! Shared SSH connection pool keyed by (ssh_target, jump).
//! Multiple surfaces (tabs/splits) to the same host share one SSH connection,
//! one SSH channel to the remote ghostty process, and multiplexed sessions via target IDs.
//! A dedicated SSH thread per connection exclusively owns all libssh2 calls,
//! since libssh2 is NOT thread-safe. Surfaces communicate via a thread-safe
//! write queue and receive frames via direct processOutput calls.
const SshConnectionManager = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const session = @import("../session.zig");
const page_diff = session.page_diff;
const ssh = session.ssh;
const termio = @import("../termio.zig");
const apprt = @import("../apprt.zig");
const config = @import("../config.zig").Config;

const log = std.log.scoped(.ssh_connection_manager);

pub const max_surfaces: usize = 64;

mutex: std.Thread.Mutex = .{},
/// Entries are heap-allocated so that pointers remain stable across
/// hash map growth and ordered removal (which shifts internal arrays).
connections: std.StringArrayHashMap(*Entry),
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
    /// Current tab/session label, synced from title changes. Used on reconnect.
    label: ?[]const u8 = null,
};

pub const WriteRequest = struct {
    kind: session.protocol.Kind,
    target_id: u16,
    data: []const u8, // owned by entry allocator, freed after send
};

pub const EntryState = enum(u8) {
    uninitialized,
    connecting,
    ready,
    failed,
};

pub const Entry = struct {
    alloc: Allocator,
    ctx: session.client.SshContext,
    remote_bin_path: []const u8,
    ref_count: u32,
    /// Shared SSH channel to the multiplexed ghostty process (one per host).
    channel: ?ssh.Channel = null,
    /// Next target ID to assign for multiplexing.
    next_target: u16 = 1,

    ssh_thread: ?std.Thread = null,
    quit_pipe: [2]posix.fd_t = .{ -1, -1 },
    write_pipe: [2]posix.fd_t = .{ -1, -1 },

    // Registered surfaces for frame dispatch
    surfaces: [max_surfaces]?SurfaceSlot = [_]?SurfaceSlot{null} ** max_surfaces,
    surfaces_mutex: std.Thread.Mutex = .{},

    // Write queue (thread-safe)
    write_queue_mu: std.Thread.Mutex = .{},
    write_queue: std.ArrayList(WriteRequest) = .empty,

    // Connection state for race prevention between surfaces
    conn_state: std.atomic.Value(EntryState) = .{ .raw = .uninitialized },

    // Keepalive tracking (written/read only by the SSH thread)
    last_keepalive_received: i128 = 0,
    /// Set to true after receiving the first pong from the remote.
    /// Stale detection is only active when this is true, ensuring backward
    /// compatibility with older remote ghostty versions that don't support keepalive.
    keepalive_active: bool = false,

    // Reconnect configuration (set from config during setupConnection)
    max_reconnect_attempts: u32 = 5,
    reconnect_backoff: config.SshReconnectBackoff = .exponential,
    reconnect_interval_ms: u32 = 1000,

    // Reconnect IPC pipe (write end signaled from GTK thread, read end polled by SSH thread)
    reconnect_pipe: [2]posix.fd_t = .{ -1, -1 },

    // Atomic flags for manual reconnect / cancel (set from GTK thread, read by SSH thread)
    reconnect_requested: std.atomic.Value(bool) = .{ .raw = false },
    cancel_reconnect: std.atomic.Value(bool) = .{ .raw = false },

    // Authentication state (for password prompts)
    auth_state: AuthState = .{},

    // Session list query state (set by requester, collected by SSH thread)
    session_list: SessionListState = .{},

    pub const AuthState = session.shared.AuthState;

    pub const SessionListState = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        /// Accumulated session list entries (newline-delimited text).
        buf: std.ArrayList(u8) = .empty,
        /// True once the SSH thread has finished collecting entries.
        done: bool = false,
        /// True if a query is in progress.
        active: bool = false,
    };
};

pub fn init(alloc: Allocator) SshConnectionManager {
    return .{
        .connections = std.StringArrayHashMap(*Entry).init(alloc),
        .alloc = alloc,
    };
}

pub fn deinit(self: *SshConnectionManager) void {
    var it = self.connections.iterator();
    while (it.next()) |kv| {
        self.alloc.free(kv.key_ptr.*);
        const entry = kv.value_ptr.*;
        if (entry.remote_bin_path.len > 0) self.alloc.free(entry.remote_bin_path);
        if (entry.channel) |*ch| ch.close();
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);
        entry.ctx.deinit();
        self.alloc.destroy(entry);
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

/// Look up an existing connection entry without changing ref_count.
/// Returns null if no connection to the given target exists.
pub fn findEntry(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) ?*Entry {
    self.mutex.lock();
    defer self.mutex.unlock();
    const key = makeKey(self.alloc, ssh_target, jump) catch return null;
    defer self.alloc.free(key);
    return if (self.connections.get(key)) |entry| entry else null;
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

    if (self.connections.get(key)) |entry| {
        self.alloc.free(key);
        entry.ref_count += 1;
        return entry;
    }

    const entry = try self.alloc.create(Entry);
    entry.* = .{
        .alloc = self.alloc,
        .ctx = .{
            .alloc = self.alloc,
            .ssh_target = ssh_target,
            .jump = jump,
        },
        .remote_bin_path = &.{},
        .ref_count = 1,
    };
    try self.connections.put(key, entry);
    return entry;
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
    initial_label: ?[]const u8,
) bool {
    const owned_label = if (initial_label) |l|
        (entry.alloc.dupe(u8, l) catch null)
    else
        null;

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
                .label = owned_label,
            };
            return true;
        }
    }
    if (owned_label) |l| entry.alloc.free(l);
    log.err("max surfaces ({d}) exceeded for SSH connection", .{max_surfaces});
    return false;
}

/// Update the label for a registered surface (e.g. after a title change).
/// The new label is duplicated; the old one is freed.
pub fn updateSurfaceLabel(entry: *Entry, target_id: u16, new_label: []const u8) void {
    const owned = entry.alloc.dupe(u8, new_label) catch return;
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.*) |*s| {
            if (s.target_id == target_id) {
                if (s.label) |old| entry.alloc.free(old);
                s.label = owned;
                return;
            }
        }
    }
    entry.alloc.free(owned);
}

/// Update the group_id for a registered surface (e.g. after group creation).
pub fn updateSurfaceGroupId(entry: *Entry, target_id: u16, new_group_id: Uuid) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.*) |*s| {
            if (s.target_id == target_id) {
                s.group_id = new_group_id;
                return;
            }
        }
    }
}

/// Unregister a surface. After this returns, the SSH thread will not
/// access the surface's io pointer (surfaces_mutex acts as barrier).
pub fn unregisterSurface(entry: *Entry, target_id: u16) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.*) |s| {
            if (s.target_id == target_id) {
                if (s.label) |l| entry.alloc.free(l);
                slot.* = null;
                return;
            }
        }
    }
}

/// Enqueue a write request for the SSH thread to send.
/// The data is duplicated internally; the caller retains ownership of the input.
pub fn enqueueWrite(entry: *Entry, kind: session.protocol.Kind, target_id: u16, data: []const u8) void {
    const alloc = entry.alloc;
    const owned_data = alloc.dupe(u8, data) catch return;

    entry.write_queue_mu.lock();

    // Cap write queue to prevent unbounded memory growth (DoS protection)
    const max_queue_size = 4096;
    if (entry.write_queue.items.len >= max_queue_size) {
        entry.write_queue_mu.unlock();
        alloc.free(owned_data);
        log.warn("write queue full ({d} entries), dropping frame", .{max_queue_size});
        return;
    }

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

/// Detach all surfaces on this entry. Marks each as detaching, sends
/// close(detach) frames, and closes all surface mailboxes.
pub fn detachAll(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    for (&entry.surfaces) |*slot| {
        if (slot.*) |s| {
            s.io.backend.remote.detaching = true;
            enqueueWrite(entry, .close, s.target_id, &.{@intFromEnum(session.protocol.CloseMode.detach)});
            _ = s.surface_mailbox.push(.close, .{ .forever = {} });
        }
    }
}

/// Query available sessions on the remote host via the existing multiplexed
/// connection. Sends a list_request frame and collects list_response
/// responses. Returns the raw text (newline-delimited). Caller owns the result.
/// Times out after `timeout_ms`. Returns null on timeout or if no connection.
pub fn querySessions(entry: *Entry, alloc: Allocator, timeout_ms: u64) ?[]const u8 {
    const state = &entry.session_list;

    // Initialize the query
    state.mutex.lock();
    state.active = true;
    state.done = false;
    state.buf.clearRetainingCapacity();
    state.mutex.unlock();

    // Send the request through the write queue
    enqueueWrite(entry, .list_request, 0, "");

    // Wait for responses with timeout. The multiplexer sends all entries
    // synchronously, so we wait for a brief quiet period after the last entry.
    const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ms) * std.time.ns_per_ms;
    var last_len: usize = 0;

    state.mutex.lock();
    while (true) {
        // Wait up to 500ms for new data (or overall deadline)
        const now = std.time.nanoTimestamp();
        if (now >= deadline) break;

        const wait_ns: u64 = @intCast(@min(
            deadline - now,
            500 * std.time.ns_per_ms,
        ));
        state.cond.timedWait(&state.mutex, wait_ns) catch {};

        const cur_len = state.buf.items.len;
        if (cur_len > 0 and cur_len == last_len) {
            // No new data since last wake — all entries received.
            break;
        }
        last_len = cur_len;
    }

    // Harvest results
    const result = if (state.buf.items.len > 0)
        alloc.dupe(u8, state.buf.items) catch null
    else
        null;

    state.active = false;
    state.buf.clearRetainingCapacity();
    state.mutex.unlock();

    return result;
}

/// Release a reference. When ref_count reaches 0, shut down the SSH thread
/// and clean up the connection.
pub fn release(self: *SshConnectionManager, ssh_target: []const u8, jump: ?[]const u8) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    if (self.connections.get(key)) |entry| {
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
            if (entry.reconnect_pipe[1] != -1) posix.close(entry.reconnect_pipe[1]);
        }

        // Clean up remaining write queue
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);

        // Zero and free password if one was provided
        if (entry.auth_state.password) |pw| {
            @memset(@constCast(pw), 0);
            entry.alloc.free(pw);
            entry.auth_state.password = null;
        }

        if (entry.remote_bin_path.len > 0) self.alloc.free(entry.remote_bin_path);
        if (entry.channel) |*ch| ch.close();
        entry.ctx.deinit();
        self.alloc.destroy(entry);

        const removed = self.connections.fetchOrderedRemove(key);
        if (removed) |r| self.alloc.free(r.key);
    }
}

// SSH thread — exclusively owns all libssh2 calls for one connection.
// Modeled after Exec.ReadThread: blocks in posix.poll when idle, zero CPU.
pub fn sshThreadMain(entry: *Entry) void {

    // Close read ends of pipes on exit
    defer posix.close(entry.quit_pipe[0]);
    defer posix.close(entry.write_pipe[0]);
    defer if (entry.reconnect_pipe[0] != -1) posix.close(entry.reconnect_pipe[0]);

    var sess = &entry.ctx.session.?;
    var channel = &entry.channel.?;
    const ssh_sock = sess.getPollSocket();

    // Set pipe read ends to non-blocking for drain
    setNonBlocking(entry.write_pipe[0]);
    if (entry.reconnect_pipe[0] != -1) setNonBlocking(entry.reconnect_pipe[0]);

    var pollfds: [3]posix.pollfd = .{
        .{ .fd = ssh_sock, .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.write_pipe[0], .events = posix.POLL.IN, .revents = undefined },
    };

    var frame_buf: std.ArrayList(u8) = .empty;
    defer frame_buf.deinit(entry.alloc);

    var read_buf: [4096]u8 = undefined;

    // Keepalive state.
    // Stale detection only activates after receiving the first pong
    // from the remote (entry.keepalive_active). This ensures backward
    // compatibility with older remote ghostty versions that don't support keepalive.
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
                    entry.alloc,
                    read_buf[0..@intCast(rc)],
                ) catch break;
            } else break;
        }

        // Check channel EOF (remote ghostty exited — all sessions dead)
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
                entry.alloc.free(req.data);
            }
            entry.write_queue.clearRetainingCapacity();
            entry.write_queue_mu.unlock();
        }

        // Drain write pipe notification bytes
        drainPipe(entry.write_pipe[0]);

        // 4. Keepalive: send ping if interval elapsed, detect stale via pong
        const now = std.time.nanoTimestamp();
        if (now - last_keepalive_sent >= session.protocol.keepalive_interval_ns) {
            sendFrame(channel, .ping, 0, "") catch |err| {
                log.warn("ping send failed: {}", .{err});
            };
            last_keepalive_sent = now;
        }

        if (entry.keepalive_active and
            now - entry.last_keepalive_received > session.protocol.keepalive_stale_ns)
        {
            log.warn("ssh connection stale (no pong for {d}s)", .{
                @as(i64, @intCast(@divFloor(now - entry.last_keepalive_received, std.time.ns_per_s))),
            });
            // Attempt reconnection
            if (attemptReconnect(entry)) {
                // Reconnected — reset keepalive state and continue
                const reconnect_now = std.time.nanoTimestamp();
                last_keepalive_sent = reconnect_now;
                entry.last_keepalive_received = reconnect_now;

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

        // 6. Compute poll timeout: wake up in time to send the next ping
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
            // Drain write queue one final time so close frames are sent
            entry.write_queue_mu.lock();
            for (entry.write_queue.items) |req| {
                sendFrame(channel, req.kind, req.target_id, req.data) catch |err| {
                    log.warn("final write failed: {}", .{err});
                };
                entry.alloc.free(req.data);
            }
            entry.write_queue.clearRetainingCapacity();
            entry.write_queue_mu.unlock();

            // Flush SSH transport so close frames reach the remote.
            // In non-blocking mode, channel.write() may leave data in
            // libssh2's internal buffer. Switch to blocking and poll
            // until the transport has no more outbound data.
            sess.setBlocking(1);
            sess.pollTransport(500);

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

/// Attempt to reconnect the SSH connection with configurable backoff.
/// Returns true if reconnection succeeded, false if we should give up
/// (thread should exit).
fn attemptReconnect(entry: *Entry) bool {
    // Reset atomic flags
    entry.reconnect_requested.store(false, .release);
    entry.cancel_reconnect.store(false, .release);

    // Close old channel
    if (entry.channel) |*ch| {
        ch.close();
        entry.channel = null;
    }

    // If auto-reconnect is disabled, go straight to disconnected state
    if (entry.max_reconnect_attempts == 0) {
        broadcastConnectionState(entry, .{ .disconnected = .{
            .attempts_made = 0,
            .reason = .disabled,
        } });
        if (waitForManualReconnect(entry)) {
            return attemptReconnect(entry);
        }
        return false;
    }

    var attempt: u32 = 0;
    while (attempt < entry.max_reconnect_attempts) {
        attempt += 1;
        const elapsed = std.time.nanoTimestamp();

        // Broadcast "actively connecting" phase (next_retry_ns = 0)
        broadcastConnectionState(entry, .{ .reconnecting = .{
            .attempt = attempt,
            .max_attempts = entry.max_reconnect_attempts,
            .elapsed_ns = 0,
            .next_retry_ns = 0,
        } });

        log.info("reconnect attempt {d}/{d}", .{ attempt, entry.max_reconnect_attempts });

        // Close old session state
        entry.ctx.deinit();
        entry.ctx.session = null;
        entry.ctx.jump_session = null;

        // Try to reconnect
        var stderr_buf: [256]u8 = undefined;
        var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer_.interface;

        const connect_ok = if (entry.ctx.connect(stderr)) |_| true else |_| false;

        if (connect_ok) {
            // Try to open multiplexed channel (with daemon restart fallback)
            if (tryOpenChannel(entry)) |new_channel| {
                // Switch to non-blocking
                var sess = &entry.ctx.session.?;
                sess.setBlocking(0);
                entry.channel = new_channel;

                // Re-open sessions for registered surfaces
                reopenSurfaces(entry);

                log.info("reconnected after {d} attempts", .{attempt});
                return true;
            }
        }

        // Connection failed — wait with backoff before next attempt
        if (attempt < entry.max_reconnect_attempts) {
            const delay_ms = computeBackoff(entry, attempt - 1);
            const now = std.time.nanoTimestamp();
            const next_retry_ns = now + @as(i128, delay_ms) * std.time.ns_per_ms;

            // Broadcast "waiting for backoff" phase
            broadcastConnectionState(entry, .{ .reconnecting = .{
                .attempt = attempt,
                .max_attempts = entry.max_reconnect_attempts,
                .elapsed_ns = now - elapsed,
                .next_retry_ns = next_retry_ns,
            } });

            // Interruptible sleep — can be woken by quit, Retry Now, or Cancel
            if (interruptibleSleep(entry, delay_ms)) return false; // quit signaled

            // Check cancel
            if (entry.cancel_reconnect.load(.acquire)) {
                entry.cancel_reconnect.store(false, .release);
                broadcastConnectionState(entry, .{ .disconnected = .{
                    .attempts_made = attempt,
                    .reason = .cancelled,
                } });
                if (waitForManualReconnect(entry)) {
                    return attemptReconnect(entry);
                }
                return false;
            }

            // Check "Retry Now" — skip remaining backoff, loop immediately
            if (entry.reconnect_requested.load(.acquire)) {
                entry.reconnect_requested.store(false, .release);
                // Continue loop immediately (don't increment attempt — retry same one)
                continue;
            }
        }
    }

    // Exhausted all attempts
    log.warn("reconnect exhausted after {d} attempts", .{entry.max_reconnect_attempts});
    broadcastConnectionState(entry, .{ .disconnected = .{
        .attempts_made = entry.max_reconnect_attempts,
        .reason = .exhausted,
    } });

    if (waitForManualReconnect(entry)) {
        return attemptReconnect(entry);
    }
    return false;
}

/// Re-open sessions for registered surfaces using their stable IDs after reconnect.
fn reopenSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    var group_sent = std.AutoArrayHashMap(session.shared.Uuid, void).init(entry.alloc);
    defer group_sent.deinit();
    for (entry.surfaces) |slot| {
        if (slot) |s| {
            if (!session.shared.isZeroUuid(s.group_id)) {
                if (group_sent.contains(s.group_id)) continue;
                group_sent.put(s.group_id, {}) catch continue;
            }

            const open_payload = (session.protocol.Open{
                .open_type = .session_attach,
                .resize = .{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 },
                .surface_id = s.surface_id,
                .group_id = s.group_id,
                .label = s.label orelse "reconnected",
            }).encode(entry.alloc) catch continue;
            defer entry.alloc.free(open_payload);
            sendFrame(&entry.channel.?, .open, s.target_id, open_payload) catch {
                log.warn("reconnect: failed to re-open surface target={d}", .{s.target_id});
                _ = s.surface_mailbox.push(.{
                    .child_exited = .{ .exit_code = 1, .runtime_ms = 0 },
                }, .{ .forever = {} });
            };
        }
    }
    entry.surfaces_mutex.unlock();
}

/// Try to open a multiplexed channel, restarting the daemon if needed.
/// Copies remote_bin_path under surfaces_mutex to avoid racing with setupConnection.
fn tryOpenChannel(entry: *Entry) ?ssh.Channel {
    const alloc = entry.alloc;

    // Copy remote_bin_path under mutex — setupConnection writes it from another thread.
    entry.surfaces_mutex.lock();
    const remote_bin_path = alloc.dupe(u8, entry.remote_bin_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(remote_bin_path);

    // First attempt
    if (session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path)) |ch| {
        return ch;
    } else |_| {}

    // Daemon might be dead — try starting without killing existing one first
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, false) catch return null;

    return session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path) catch null;
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

        // Handle pong: update timestamp, don't dispatch to surfaces
        if (kind == .pong) {
            entry.last_keepalive_received = std.time.nanoTimestamp();
            entry.keepalive_active = true;
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Collect list_response frames into the query buffer
        if (kind == .list_response) {
            entry.session_list.mutex.lock();
            if (entry.session_list.active) {
                entry.session_list.buf.appendSlice(entry.alloc, payload) catch {};
                entry.session_list.buf.append(entry.alloc, '\n') catch {};
                entry.session_list.cond.signal();
            }
            entry.session_list.mutex.unlock();
            shiftBuffer(frame_buf, total);
            continue;
        }

        // Hold surfaces_mutex during dispatch to prevent use-after-free
        // on surface io pointers (unregisterSurface acquires the same lock).
        entry.surfaces_mutex.lock();
        if (frame_target == 0) {
            // Broadcast to all surfaces
            for (&entry.surfaces) |*slot| {
                if (slot.*) |_| dispatchFrame(kind, slot, payload);
            }
        } else {
            if (findSurfacePtr(entry, frame_target)) |slot| {
                dispatchFrame(kind, slot, payload);
            }
        }
        entry.surfaces_mutex.unlock();

        shiftBuffer(frame_buf, total);
    }
}

fn dispatchFrame(kind: session.protocol.Kind, slot: *?SurfaceSlot, payload: []const u8) void {
    const s = slot.* orelse return;
    switch (kind) {
        .data_out => {
            @call(.always_inline, termio.Termio.processOutput, .{ s.io, payload });
        },
        .opened => {
            // Parse the bundled opened response
            const parsed = session.protocol.Opened.parseHeader(payload) catch {
                log.warn("opened: invalid payload", .{});
                return;
            };
            log.info("remote session opened history_rows={d}", .{parsed.history_rows});

            // Update IDs in the slot (surfaces_mutex is held by caller).
            slot.*.?.group_id = parsed.group_id;
            if (!session.shared.isZeroUuid(parsed.surface_id)) {
                slot.*.?.surface_id = parsed.surface_id;
            }

            // Send IDs to GTK thread via mailbox so it can update ssh_ctx
            // without racing this (SSH) thread. All GTK-thread readers see
            // the update before any subsequent messages (data_out,
            // layout_restore) because the mailbox is FIFO.
            _ = s.surface_mailbox.push(.{
                .remote_opened = .{
                    .group_id = parsed.group_id,
                    .surface_id = parsed.surface_id,
                },
            }, .{ .forever = {} });

            // Pre-allocate blank history pages for scrollback restore
            if (parsed.history_rows > 0) {
                s.io.renderer_state.mutex.lock();
                defer s.io.renderer_state.mutex.unlock();
                const t = s.io.renderer_state.terminal;
                t.screens.active.pages.prependBlankPages(parsed.history_rows) catch |err| {
                    log.warn("failed to prepend history pages: {}", .{err});
                };
            }

            // If layout blob is included, send it to surface for tree recreation.
            // Bundle group_id/surface_id in the message to avoid a race:
            // the GTK thread must not read these from the Remote backend
            // since we just wrote them on this (SSH) thread.
            if (parsed.layout_blob) |layout_blob| {
                log.info("received layout blob in opened response len={d}", .{layout_blob.len});
                const blob_copy = std.heap.page_allocator.dupe(u8, layout_blob) catch {
                    log.err("failed to allocate layout blob", .{});
                    return;
                };
                _ = s.surface_mailbox.push(.{
                    .layout_restore = .{
                        .blob = blob_copy.ptr,
                        .len = @intCast(blob_copy.len),
                        .group_id = parsed.group_id,
                        .surface_id = parsed.surface_id,
                    },
                }, .{ .forever = {} });
            }
        },
        .scrollback_response => {
            // Parse scrollback chunk header
            const resp = session.protocol.ScrollbackResponse.parse(payload) catch {
                log.warn("scrollback_response: invalid payload", .{});
                return;
            };

            // row_count == 0 is the done marker
            if (resp.row_count == 0) {
                log.info("scrollback restore complete ({d} history rows)", .{resp.total_history_rows});
                return;
            }

            // Apply the chunk to the client's terminal
            s.io.renderer_state.mutex.lock();
            defer s.io.renderer_state.mutex.unlock();
            const t = s.io.renderer_state.terminal;

            page_diff.applyScrollbackChunk(
                t,
                resp.chunk_start_row,
                resp.row_count,
                resp.chunk_data,
            );
        },
        .layout => {
            log.info("received layout blob len={d}", .{payload.len});
            // page_allocator is used intentionally: this blob crosses thread
            // boundaries via the surface mailbox. The receiver (GTK thread)
            // frees it and does not have access to entry.alloc.
            const blob_copy = std.heap.page_allocator.dupe(u8, payload) catch {
                log.err("failed to allocate layout blob", .{});
                return;
            };
            _ = s.surface_mailbox.push(.{
                .layout_restore = .{
                    .blob = blob_copy.ptr,
                    .len = @intCast(blob_copy.len),
                },
            }, .{ .forever = {} });
        },
        .info => log.info("remote info: {s}", .{payload}),
        .err => log.err("remote error: {s}", .{payload}),
        .eof => {
            log.info("remote session EOF target={d}", .{s.target_id});
            _ = s.surface_mailbox.push(.{
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

fn findSurfacePtr(entry: *Entry, target_id: u16) ?*?SurfaceSlot {
    for (&entry.surfaces) |*slot| {
        if (slot.*) |s| {
            if (s.target_id == target_id) return slot;
        }
    }
    return null;
}

fn sendFrame(channel: *ssh.Channel, kind: session.protocol.Kind, target: u16, data: []const u8) !void {
    if (data.len > session.protocol.max_payload) return error.PayloadTooLarge;
    const header = (session.protocol.Header{
        .kind = kind,
        .target = target,
        .len = @intCast(data.len),
    }).encodeToBuf();
    try channel.write(&header);
    if (data.len > 0) try channel.write(data);
}

const shiftBuffer = session.shared.shiftBuffer;

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

// Public reconnect/cancel API — called from the GTK thread.

/// Signal the SSH thread to (re-)attempt reconnection.
/// Works during backoff wait ("Retry Now") and after exhaustion ("Reconnect").
pub fn requestReconnect(entry: *Entry) void {
    entry.reconnect_requested.store(true, .release);
    entry.cancel_reconnect.store(false, .release);
    // Wake the SSH thread's reconnect_pipe poll
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "r") catch {};
}

/// Signal the SSH thread to cancel the current auto-reconnect loop.
pub fn cancelReconnect(entry: *Entry) void {
    entry.cancel_reconnect.store(true, .release);
    entry.reconnect_requested.store(false, .release);
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "c") catch {};
}

/// Compute backoff delay in milliseconds for the given attempt (0-based).
fn computeBackoff(entry: *const Entry, attempt: u32) u64 {
    const base: u64 = entry.reconnect_interval_ms;
    return switch (entry.reconnect_backoff) {
        .exponential => @min(base *| (@as(u64, 1) << @intCast(@min(attempt, 30))), 30_000),
        .linear => @min(base *| (@as(u64, attempt) + 1), 30_000),
        .constant => base,
    };
}

/// Sleep for `delay_ms` but wake early if quit_pipe or reconnect_pipe
/// becomes readable. Returns true if quit was signaled (thread should exit).
fn interruptibleSleep(entry: *Entry, delay_ms: u64) bool {
    var fds: [2]posix.pollfd = .{
        .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        .{ .fd = entry.reconnect_pipe[0], .events = posix.POLL.IN, .revents = undefined },
    };
    const timeout: i32 = if (delay_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(delay_ms);
    _ = posix.poll(&fds, timeout) catch {};

    // Check quit
    if (fds[0].revents & posix.POLL.IN != 0) return true;
    // Drain reconnect pipe (caller checks atomic flags)
    if (fds[1].revents & posix.POLL.IN != 0) drainPipe(entry.reconnect_pipe[0]);
    return false;
}

/// Block indefinitely until quit or reconnect_pipe signal.
/// Returns true if reconnect was requested, false if quit.
fn waitForManualReconnect(entry: *Entry) bool {
    while (true) {
        var fds: [2]posix.pollfd = .{
            .{ .fd = entry.quit_pipe[0], .events = posix.POLL.IN, .revents = undefined },
            .{ .fd = entry.reconnect_pipe[0], .events = posix.POLL.IN, .revents = undefined },
        };
        _ = posix.poll(&fds, -1) catch return false;

        if (fds[0].revents & posix.POLL.IN != 0) return false;
        if (fds[1].revents & posix.POLL.IN != 0) {
            drainPipe(entry.reconnect_pipe[0]);
            if (entry.reconnect_requested.load(.acquire)) {
                entry.reconnect_requested.store(false, .release);
                return true;
            }
        }
    }
}
