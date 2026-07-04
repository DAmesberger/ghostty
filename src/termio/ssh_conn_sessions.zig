//! Session / surface-map primitives for the SSH connection manager: locate
//! a surface slot across sessions, find-or-create a `Session` by group_id,
//! and move a surface between sessions. Split out of
//! `SshConnectionManager.zig`; used by both the surface registry and the
//! inbound frame-dispatch path. Every helper assumes the caller holds the
//! Entry's `surfaces_mutex`.

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


/// Find a surface by target_id across all sessions. Returns a copy.
/// Caller must hold surfaces_mutex.
/// Find a surface slot by target ID, returning a mutable pointer.
/// Caller must hold surfaces_mutex.
pub fn findSurfaceSlotPtr(entry: *Entry, target_id: u16) ?*SurfaceSlot {
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) return s;
        }
    }
    return null;
}

pub fn findSurfaceAcrossSessions(entry: *const Entry, target_id: u16) ?SurfaceSlot {
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.*.findSurfaceByTargetId(target_id)) |s| return s;
    }
    return null;
}

/// Find or create a session for the given group_id. Caller must hold surfaces_mutex.
pub fn findOrCreateSession(entry: *Entry, group_id: Uuid) ?*Session {
    if (entry.sessions.get(group_id)) |s| return s;

    const sess = entry.alloc.create(Session) catch return null;
    sess.* = .{ .group_id = group_id };
    entry.sessions.put(group_id, sess) catch {
        entry.alloc.destroy(sess);
        return null;
    };
    return sess;
}

/// Remove an empty session. Caller must hold surfaces_mutex.
pub fn removeSession(entry: *Entry, group_id: Uuid) void {
    if (entry.sessions.fetchSwapRemove(group_id)) |kv| {
        kv.value.deinit(entry.alloc);
        entry.alloc.destroy(kv.value);
    }
}

/// Move a surface between sessions. Caller must hold surfaces_mutex.
pub fn moveSurfaceToSession(entry: *Entry, target_id: u16, new_group_id: Uuid) void {
    // Find and remove from current session
    var old_session: ?*Session = null;
    var surface_data: ?SurfaceSlot = null;

    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        for (sess.surfaces.items, 0..) |s, i| {
            if (s.target_id == target_id) {
                // Check if already in correct session
                if (std.mem.eql(u8, &sess.group_id, &new_group_id)) return;

                surface_data = s;
                old_session = sess;
                _ = sess.surfaces.swapRemove(i);
                break;
            }
        }
        if (surface_data != null) break;
    }

    const surf = surface_data orelse return;
    const target_sess = findOrCreateSession(entry, new_group_id) orelse return;
    target_sess.surfaces.append(entry.alloc, surf) catch return;

    // Remove empty source session
    if (old_session) |old| {
        if (old.surfaces.items.len == 0) {
            removeSession(entry, old.group_id);
        }
    }
}

/// Update surface_id for a surface. Caller must hold surfaces_mutex.
pub fn updateSurfaceIdLocked(entry: *Entry, target_id: u16, new_surface_id: Uuid) void {
    if (session.shared.isZeroUuid(new_surface_id)) return;
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |*s| {
            if (s.target_id == target_id) {
                s.surface_id = new_surface_id;
                return;
            }
        }
    }
}
