//! Session-group + reexec-control data types for the remote session daemon.
//! Split out of daemon.zig; re-exported by the facade so external importers
//! (remote_session.zig: `@import("daemon.zig").SessionGroup` / `.ReexecControl`)
//! keep resolving. Pure move — bodies are byte-identical.
const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("../session.zig");
const RemoteSession = session.remote_session.RemoteSession;
const Uuid = session.shared.Uuid;
const log = std.log.scoped(.ssh_session);

/// A group of related surfaces that share a layout and can be
/// reconnected together. Every session belongs to a group, even
/// single-surface ones.
pub const SessionGroup = struct {
    alloc: Allocator,
    id: Uuid,
    label: []u8,
    /// Session color: -1 = none (no badge), 0-7 = color index.
    /// Default derived from group UUID for consistency.
    color: i8 = -1,
    surfaces: std.AutoArrayHashMap(Uuid, *RemoteSession),
    /// Surface ids that have a `<id>.term` on disk but are NOT yet live in
    /// `surfaces` this daemon generation (persisted-but-not-attached). Kept
    /// DISJOINT from `surfaces` keys by invariant: `createSurfaceInner`
    /// removes an id from here the instant it registers a live surface, and
    /// the close paths drop it. Lets `--list`/the chooser show persisted
    /// sessions before any attach lazily reloads them. Guarded by `mutex`
    /// (same as `surfaces`).
    detached_surfaces: std.AutoArrayHashMap(Uuid, void),
    layout_blob: ?[]u8 = null,
    created_at: i64,
    mutex: std.Thread.Mutex = .{},

    pub fn deinit(self: *SessionGroup) void {
        // Drop the group's reference to each surface rather than deinit()ing it
        // directly: a detached reader thread may still be running. kill() makes
        // that reader exit promptly (PTY EOF) and drop its own reference; the
        // last release frees the surface. If a reader already exited, the
        // release here frees the surface synchronously. Either way there is no
        // double-free vs the reader and no use-after-free of a running reader.
        for (self.surfaces.values()) |sess| {
            sess.kill();
            sess.release();
        }
        self.surfaces.deinit();
        self.detached_surfaces.deinit();
        if (self.layout_blob) |blob| self.alloc.free(blob);
        self.alloc.free(self.label);
        self.alloc.destroy(self);
    }

    /// Store a layout blob (opaque, from client). Thread-safe.
    pub fn updateLayout(self: *SessionGroup, alloc: Allocator, blob: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.layout_blob) |old| alloc.free(old);
        self.layout_blob = alloc.dupe(u8, blob) catch |err| blk: {
            log.warn("failed to store layout blob: {}", .{err});
            break :blk null;
        };
    }

    /// Update the group label and/or color, then broadcast to all surface viewers.
    /// Returns false if label allocation failed.
    pub fn updateLabel(self: *SessionGroup, alloc: Allocator, new_label: ?[]const u8, new_color: ?i8) bool {
        self.mutex.lock();
        if (new_label) |raw| {
            const label = session.shared.sanitizeLabelAlloc(alloc, raw) catch {
                self.mutex.unlock();
                return false;
            };
            alloc.free(self.label);
            self.label = label;
        }
        if (new_color) |col| self.color = col;
        for (self.surfaces.values()) |surf| {
            surf.mutex.lock();
            surf.broadcastViewerStateWithLabel(.name_change, self.label, self.color);
            surf.mutex.unlock();
        }
        self.mutex.unlock();
        return true;
    }

    /// Get the first alive surface in the group (for reconnect). The returned
    /// surface has an extra reference held; the caller must `release()` it.
    /// Holds `group.mutex` across selection + retain so the surface cannot be
    /// removed and freed between the lookup and the retain.
    pub fn firstAliveSurface(self: *SessionGroup) ?*RemoteSession {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.surfaces.values()) |sess| {
            sess.mutex.lock();
            const alive = sess.alive;
            sess.mutex.unlock();
            if (alive) {
                sess.retain();
                return sess;
            }
        }
        return null;
    }
};

/// Shared, atomically-mutated control block for the GATED execve self-handoff
/// (cmux Phase 2). Pointed at by every `RemoteSession.reexec` so the reader
/// threads can observe `in_progress` and park themselves (no PTY reads) while
/// the daemon checkpoints + builds the handoff manifest, and report back via
/// `active_readers` when they have parked. Default-inert: `in_progress` is only
/// ever set when the daemon was launched with `GHOSTTY_SSH_REEXEC=1`.
pub const ReexecControl = struct {
    /// Set true just before quiescing for an execve handoff; gates new surface
    /// creation and tells every reader thread to drain + park.
    in_progress: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Count of live reader threads currently NOT parked. handleReexec waits
    /// for this to reach 0 (with a timeout) before clearing CLOEXEC + execve.
    active_readers: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};
