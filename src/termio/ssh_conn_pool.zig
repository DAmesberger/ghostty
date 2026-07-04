//! Connection-pool lifecycle for the `SshConnectionManager`: the reference-
//! counted per-host `Entry` map, plus `acquire` / `release` / `findEntry` /
//! `allocateTarget` / `abortInFlightConnect` and `init` / `deinit`. Split out
//! of `SshConnectionManager.zig`, which re-exports these unchanged. The
//! `self: *SshConnectionManager` methods reference the facade struct type via
//! the import below (facade re-exports back — a safe method-split cycle).

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

const SshConnectionManager = @import("SshConnectionManager.zig");
const types = @import("ssh_conn_types.zig");
const Uuid = types.Uuid;
const SurfaceSlot = types.SurfaceSlot;
const Session = types.Session;
const WriteRequest = types.WriteRequest;
const EntryState = types.EntryState;
const Entry = types.Entry;

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
        if (entry.cancel_pipe[0] != -1) posix.close(entry.cancel_pipe[0]);
        if (entry.cancel_pipe[1] != -1) posix.close(entry.cancel_pipe[1]);
        if (entry.channel) |*ch| ch.close();
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);
        deinitSessions(entry);
        entry.ssh_listeners.deinit(entry.alloc);
        entry.ctx.deinit();
        self.alloc.destroy(entry);
    }
    self.connections.deinit();
}

fn deinitSessions(entry: *Entry) void {
    var sit = entry.sessions.iterator();
    while (sit.next()) |skv| {
        skv.value_ptr.*.deinit(entry.alloc);
        entry.alloc.destroy(skv.value_ptr.*);
    }
    entry.sessions.deinit();
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

    // Always-present cancel pipe — created here so it exists for the FIRST
    // tcpConnect (quit_pipe/reconnect_pipe are only created later in
    // attachRemoteSurface). Its read end feeds ctx.cancel_fd so a teardown
    // can abort an in-flight connect.
    const cancel_pipe = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        posix.close(cancel_pipe[0]);
        posix.close(cancel_pipe[1]);
    }

    const entry = try self.alloc.create(Entry);
    errdefer self.alloc.destroy(entry);
    entry.* = .{
        .alloc = self.alloc,
        .ctx = .{
            .alloc = self.alloc,
            .ssh_target = ssh_target,
            .jump = jump,
            .cancel_fd = cancel_pipe[0],
        },
        .remote_bin_path = &.{},
        .ref_count = 1,
        .cancel_pipe = cancel_pipe,
        .sessions = std.AutoArrayHashMap(Uuid, *Session).init(self.alloc),
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

        // Close the always-present cancel pipe. It exists even when the SSH
        // thread was never spawned (e.g. the initial connect was aborted), so
        // close it unconditionally here. tcpConnect only polls cancel_pipe[0]
        // and requestStop only writes cancel_pipe[1] — neither closes — so
        // release owns the close and there is no double-close.
        if (entry.cancel_pipe[0] != -1) posix.close(entry.cancel_pipe[0]);
        if (entry.cancel_pipe[1] != -1) posix.close(entry.cancel_pipe[1]);

        // Clean up remaining write queue
        for (entry.write_queue.items) |req| {
            entry.alloc.free(req.data);
        }
        entry.write_queue.deinit(entry.alloc);

        // Zero and free password if one was provided
        if (entry.auth_state.password) |pw| {
            session.shared.secureZeroAndFree(entry.alloc, pw);
            entry.auth_state.password = null;
        }

        if (entry.remote_bin_path.len > 0) self.alloc.free(entry.remote_bin_path);
        if (entry.channel) |*ch| ch.close();
        deinitSessions(entry);
        entry.ssh_listeners.deinit(entry.alloc);
        entry.ctx.deinit();
        self.alloc.destroy(entry);

        const removed = self.connections.fetchOrderedRemove(key);
        if (removed) |r| self.alloc.free(r.key);
    }
}

/// Abort an in-flight initial-connect / reconnect for the connection keyed by
/// (ssh_target, jump), if this is the LAST reference. Called from the MAIN
/// thread during surface teardown (via Remote.requestStop) immediately before
/// io_thr.join(), so a dead-host connect aborts instead of hanging the join.
///
/// The whole body runs under `mutex` — the SAME lock `release()` holds for its
/// entire teardown (including `destroy(entry)`). That serialization is
/// load-bearing: the cancel signals below unblock the IO thread, which then
/// unwinds into `release()` and frees the Entry. Holding `mutex` guarantees
/// `release()` cannot free the Entry until we finish touching its fields,
/// closing the use-after-free window. Lock order is `mutex` → `auth_state.mutex`
/// (no path takes them in the reverse order), so this is deadlock-free.
pub fn abortInFlightConnect(
    self: *SshConnectionManager,
    ssh_target: []const u8,
    jump: ?[]const u8,
) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const key = makeKey(self.alloc, ssh_target, jump) catch return;
    defer self.alloc.free(key);

    const entry = self.connections.get(key) orelse return;

    // Only the last reference may latch a cancel — a shared (ref_count>1) live
    // connection must keep working for the surviving sibling.
    if (entry.ref_count > 1) return;

    // Latch the always-present cancel pipe (created in acquire): aborts an
    // in-flight tcpConnect on the IO thread (initial connect) OR the SSH
    // thread (reconnect). Write-only here; release()/deinit own the close.
    if (entry.cancel_pipe[1] != -1)
        _ = posix.write(entry.cancel_pipe[1], "c") catch {};

    // Make the reconnect loop bail promptly to its quit-parked wait. Inert in
    // steady state: the main SSH poll does not watch reconnect_pipe, so this
    // byte is simply drained on the next reconnect or closed at release.
    entry.cancel_reconnect.store(true, .release);
    if (entry.reconnect_pipe[1] != -1)
        _ = posix.write(entry.reconnect_pipe[1], "c") catch {};

    // Unblock a password-prompt cond wait (not poll-interruptible).
    entry.auth_state.mutex.lock();
    entry.auth_state.cancelled = true;
    entry.auth_state.cond.signal();
    entry.auth_state.mutex.unlock();
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

// Regression: a remote terminal surface whose ssh_target encodes the
// ProxyJump via the ` via ` syntax must resolve the SAME pool key as the
// C-API proxy connection, which calls `makeKey(host, jump)` with a separate
// jump argument. Before the cmux fix the terminal surface keyed on the bare
// host (jump=null) while the proxy keyed on host|jump, so a ProxyJump user
// got two libssh2 connections instead of one shared Entry.
test "makeKey: terminal host-via-jump target pools with proxy (host, jump)" {
    const alloc = testing.allocator;

    const host = "user@example.com:2222";
    const jump = "bastion@jump.example.com";

    // Proxy path: target and jump arrive as separate arguments.
    const proxy_key = try makeKey(alloc, host, jump);
    defer alloc.free(proxy_key);

    // Terminal path: the surface ssh_target is the canonical
    // "host via jump" string; `parseSshTarget` splits it back into
    // (target, jump) exactly as `Remote.threadEnter` does before acquire.
    const surface_target = "user@example.com:2222 via bastion@jump.example.com";
    const parsed = session.shared.parseSshTarget(surface_target);
    const terminal_key = try makeKey(alloc, parsed.target, parsed.jump);
    defer alloc.free(terminal_key);

    try testing.expectEqualStrings(host, parsed.target);
    try testing.expectEqualStrings(jump, parsed.jump.?);
    try testing.expectEqualStrings(proxy_key, terminal_key);
    try testing.expectEqualStrings("user@example.com:2222|bastion@jump.example.com", terminal_key);
}

// With no ProxyJump configured the terminal surface keeps the bare target,
// `parseSshTarget` returns jump=null, and the key is just the host — matching
// a direct (jump=null) proxy connection so they still share one Entry.
test "makeKey: bare target keys on host with no jump" {
    const alloc = testing.allocator;

    const host = "user@example.com:2222";
    const parsed = session.shared.parseSshTarget(host);
    try testing.expect(parsed.jump == null);

    const key = try makeKey(alloc, parsed.target, parsed.jump);
    defer alloc.free(key);

    const direct_key = try makeKey(alloc, host, null);
    defer alloc.free(direct_key);

    try testing.expectEqualStrings(host, key);
    try testing.expectEqualStrings(direct_key, key);
}
