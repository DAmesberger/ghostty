//! Surface registry + outbound write path for the SSH connection manager:
//! register / relabel / regroup / unregister surfaces, the thread-safe write
//! queue (`enqueueWrite`), layout dedup+send, session detach, and the
//! blocking `querySessions` list request. Split out of
//! `SshConnectionManager.zig`, which re-exports the `pub` helpers unchanged.

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

const types = @import("ssh_conn_types.zig");
const Uuid = types.Uuid;
const SurfaceSlot = types.SurfaceSlot;
const Session = types.Session;
const WriteRequest = types.WriteRequest;
const EntryState = types.EntryState;
const Entry = types.Entry;

const sessions = @import("ssh_conn_sessions.zig");
const findOrCreateSession = sessions.findOrCreateSession;
const removeSession = sessions.removeSession;
const moveSurfaceToSession = sessions.moveSurfaceToSession;


/// Register a surface for frame dispatch from the SSH thread.
/// The surface is placed into the session matching `group_id`, creating
/// one if it doesn't exist yet.
/// Returns true on success, false on allocation failure.
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

    const sess = findOrCreateSession(entry, group_id) orelse {
        if (owned_label) |l| entry.alloc.free(l);
        return false;
    };
    sess.surfaces.append(entry.alloc, .{
        .target_id = target_id,
        .io = io,
        .surface_mailbox = mailbox,
        .surface_id = surface_id,
        .label = owned_label,
    }) catch {
        if (owned_label) |l| entry.alloc.free(l);
        return false;
    };
    return true;
}

/// Update the label for a registered surface (e.g. after a title change).
/// The new label is duplicated; the old one is freed.
pub fn updateSurfaceLabel(entry: *Entry, target_id: u16, new_label: []const u8) void {
    const owned = entry.alloc.dupe(u8, new_label) catch return;
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) {
                if (s.label) |old| entry.alloc.free(old);
                s.label = owned;
                return;
            }
        }
    }
    entry.alloc.free(owned);
}

/// Move a surface to the session matching `new_group_id`, creating it if needed.
/// Removes the source session if it becomes empty.
pub fn updateSurfaceGroupId(entry: *Entry, target_id: u16, new_group_id: Uuid) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    moveSurfaceToSession(entry, target_id, new_group_id);
}

/// Unregister a surface. After this returns, the SSH thread will not
/// access the surface's io pointer (surfaces_mutex acts as barrier).
pub fn unregisterSurface(entry: *Entry, target_id: u16) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        if (sess.removeSurface(target_id, entry.alloc)) {
            if (sess.surfaces.items.len == 0) {
                removeSession(entry, sess.group_id);
            }
            return;
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

/// Store and send a layout blob for a specific session, deduplicating by hash.
/// Thread-safe: acquires surfaces_mutex internally.
pub fn storeAndSendLayout(entry: *Entry, group_id: Uuid, target: u16, blob: []const u8) void {
    const hash = std.hash.XxHash64.hash(0, blob);

    entry.surfaces_mutex.lock();
    const sess = entry.sessions.get(group_id);
    if (sess) |s| {
        if (hash == s.layout_hash) {
            entry.surfaces_mutex.unlock();
            return;
        }
        s.layout_hash = hash;
        if (s.layout_blob) |old| entry.alloc.free(old);
        s.layout_blob = entry.alloc.dupe(u8, blob) catch null;
    }
    entry.surfaces_mutex.unlock();

    log.info("storeAndSendLayout: sending layout ({d} bytes) for session", .{blob.len});
    enqueueWrite(entry, .layout, target, blob);
}

/// Detach all surfaces in a single session. Caller must hold surfaces_mutex.
fn detachSessionLocked(entry: *Entry, sess: *Session) void {
    for (sess.surfaces.items) |s| {
        s.io.backend.remote.detaching = true;
        enqueueWrite(entry, .close, s.target_id, &.{@intFromEnum(session.protocol.CloseMode.detach)});
        _ = s.surface_mailbox.push(.close, .{ .forever = {} });
    }
}

/// Detach all surfaces belonging to a specific session (by group_id).
pub fn detachSession(entry: *Entry, group_id: Uuid) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    if (entry.sessions.get(group_id)) |sess| {
        detachSessionLocked(entry, sess);
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
