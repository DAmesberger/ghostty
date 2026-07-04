//! Shared SSH connection pool keyed by (ssh_target, jump).
//! Multiple surfaces (tabs/splits) to the same host share one SSH connection,
//! one SSH channel to the remote ghostty process, and multiplexed sessions via target IDs.
//! A dedicated SSH thread per connection exclusively owns all libssh2 calls,
//! since libssh2 is NOT thread-safe. Surfaces communicate via a thread-safe
//! write queue and receive frames via direct processOutput calls.
//!
//! This file is a THIN FACADE. The implementation lives in flat sibling
//! modules (`ssh_conn_*.zig`) in this directory; every public symbol is
//! re-exported below so external importers doing
//! `@import(".../SshConnectionManager.zig").Foo` keep resolving unchanged.
//! The struct fields below still define the `SshConnectionManager` value
//! type (`App.ssh_connection_manager`); the pool methods that take
//! `self: *SshConnectionManager` live in `ssh_conn_pool.zig`.
const SshConnectionManager = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("ssh_conn_types.zig");
const pool = @import("ssh_conn_pool.zig");
const registry = @import("ssh_conn_registry.zig");
const thread = @import("ssh_conn_thread.zig");

mutex: std.Thread.Mutex = .{},
/// Entries are heap-allocated so that pointers remain stable across
/// hash map growth and ordered removal (which shifts internal arrays).
connections: std.StringArrayHashMap(*Entry),
alloc: Allocator,

// ---- Re-exported types (see ssh_conn_types.zig) ----
pub const Uuid = types.Uuid;
pub const SurfaceSlot = types.SurfaceSlot;
pub const Session = types.Session;
pub const WriteRequest = types.WriteRequest;
pub const EntryState = types.EntryState;
pub const Entry = types.Entry;

// ---- Re-exported connection-pool methods (see ssh_conn_pool.zig) ----
pub const init = pool.init;
pub const deinit = pool.deinit;
pub const findEntry = pool.findEntry;
pub const acquire = pool.acquire;
pub const allocateTarget = pool.allocateTarget;
pub const release = pool.release;
pub const abortInFlightConnect = pool.abortInFlightConnect;

// ---- Re-exported surface-registry methods (see ssh_conn_registry.zig) ----
pub const registerSurface = registry.registerSurface;
pub const updateSurfaceLabel = registry.updateSurfaceLabel;
pub const updateSurfaceGroupId = registry.updateSurfaceGroupId;
pub const unregisterSurface = registry.unregisterSurface;
pub const enqueueWrite = registry.enqueueWrite;
pub const storeAndSendLayout = registry.storeAndSendLayout;
pub const detachSession = registry.detachSession;
pub const querySessions = registry.querySessions;

// ---- Re-exported SSH-thread / reconnect methods (see ssh_conn_thread.zig) ----
pub const sshThreadMain = thread.sshThreadMain;
pub const broadcastConnectionState = thread.broadcastConnectionState;
pub const registerStateListener = thread.registerStateListener;
pub const unregisterStateListener = thread.unregisterStateListener;
pub const tryOpenChannel = thread.tryOpenChannel;
pub const tryReopenTerminalChannel = thread.tryReopenTerminalChannel;
pub const requestReconnect = thread.requestReconnect;
pub const cancelReconnect = thread.cancelReconnect;
pub const computeBackoff = thread.computeBackoff;

// Pull the sibling modules into the test binary so their inline tests
// (e.g. the makeKey regression tests in ssh_conn_pool.zig) keep running.
test {
    _ = @import("ssh_conn_types.zig");
    _ = @import("ssh_conn_sessions.zig");
    _ = @import("ssh_conn_pool.zig");
    _ = @import("ssh_conn_registry.zig");
    _ = @import("ssh_conn_frames.zig");
    _ = @import("ssh_conn_thread.zig");
}
