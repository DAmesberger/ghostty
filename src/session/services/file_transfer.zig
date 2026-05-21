//! file_transfer channel service.
//!
//! One channel = one file. The channel itself is the file: inbound
//! `channel_data` carries file bytes for uploads, outbound
//! `channel_data` carries file bytes for downloads. Control frames
//! carry progress + final-hash signals.
//!
//! Ports cmux's `KindFileUploadBegin` / `KindFileData` / `KindFileEnd`
//! family onto the channel-mux. The cmux sandbox `ensureAllowedPath`
//! is preserved verbatim (modulo Zig idioms): every transfer path is
//! resolved (symlinks included) and rejected unless it lives under an
//! allowed root (`$HOME` + `/tmp`).
//!
//! Replaces cmux's post-bootstrap scp/sftp pipe.
//!
//! Open params layout:
//!
//!   [1]   direction         u8     // 0 = upload, 1 = download
//!   [4]   mode              u32 LE // POSIX file mode (uploads only;
//!                                  // ignored for downloads)
//!   [2]   path_len          u16 LE
//!   [N]   path              UTF-8
//!   ── upload-only trailer ──
//!   [32]  expected_sha256          // all-zero = skip verification
//!   [8]   total_size        u64 LE // 0 = unknown
//!
//! Opened service_ack layout:
//!
//!   * upload:    empty
//!   * download:  [8] file_size u64 LE | [32] sha256
//!
//! Control ops:
//!
//!   * op=1 progress (daemon → opener, rate-limited):
//!         [8]  offset             u64 LE
//!         [32] partial_sha256
//!   * op=2 final (daemon → opener at completion):
//!         [32] final_sha256
//!         [1]  status             u8 (FinalStatus)
//!   * op=3 cancel (either side):
//!         empty — triggers immediate close with reason=service_error.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const Sha256 = std.crypto.hash.sha2.Sha256;

const protocol = @import("../protocol.zig");
const channel_mux = @import("../channel_mux.zig");

const log = std.log.scoped(.file_transfer_service);

/// Service id for `file_transfer`. Must match
/// `protocol.ChannelService.file_transfer`.
pub const service_id: u8 = @intFromEnum(protocol.ChannelService.file_transfer);

/// Read chunk for the file → channel pump on downloads. 128 KiB
/// matches cmux's chunking and stays comfortably below
/// `protocol.max_payload`.
const pump_read_chunk_size: usize = 128 * 1024;

/// Pump credit wait timeout — same balance as tcp_connect.
const credit_wait_timeout_ns: u64 = 1 * std.time.ns_per_s;

/// Maximum accepted `path_len`. Generous but bounded; PATH_MAX on
/// macOS is 1024 and Linux is 4096, so 4096 covers both.
const max_path_len: usize = 4096;

/// Minimum interval between progress frames during uploads. Below this
/// the pump still ticks a running sha256 forward but suppresses
/// `op=1 progress` emission — prevents progress chatter on small
/// bursts. Matches cmux's `100ms` gate.
const progress_min_interval_ns: u64 = 100 * std.time.ns_per_ms;

/// Hard byte boundary above which we always emit progress regardless
/// of timing. Matches cmux's `≥ 64 KiB` gate.
const progress_byte_boundary: usize = 64 * 1024;

/// Direction of the transfer. The client picks; the daemon obeys.
pub const Direction = enum(u8) {
    /// Client writes a file on the daemon.
    upload = 0,
    /// Daemon reads a file and streams to the client.
    download = 1,
    _,
};

/// Terminal status reported in the `op=2 final` control frame.
pub const FinalStatus = enum(u8) {
    ok = 0,
    sha_mismatch = 1,
    write_failed = 2,
    read_failed = 3,
    cancelled = 4,
    _,
};

/// Control op codes. Defined as constants rather than an enum so
/// services can ignore unknown ops cleanly (forward compatibility).
pub const op_progress: u8 = 1;
pub const op_final: u8 = 2;
pub const op_cancel: u8 = 3;

/// Per-channel service state. The mux owns serialization through its
/// helpers, so we don't carry a mutex of our own. The pump thread (only
/// used for downloads) reads `close_signal` on the *Channel pointer
/// stashed by `onOpened`.
const State = struct {
    alloc: Allocator,
    mux: *channel_mux.Mux,
    channel_id: u32,
    direction: Direction,

    /// Resolved absolute path; owned by `alloc` for the lifetime of
    /// the channel.
    path: []u8,

    /// File handle. For uploads we opened it with create+truncate
    /// (or as resolved by `mode`); for downloads, read-only.
    file_fd: posix.fd_t,

    /// Running hash. Uploads update on each on_data; downloads update
    /// on each chunk read. `Sha256` is `Copy` so we can snapshot via
    /// `var copy = h; copy.final(...)`.
    hasher: Sha256 = Sha256.init(.{}),

    /// Bytes seen so far.
    bytes_transferred: u64 = 0,

    /// For uploads: expected sha256 from the opener (verified on
    /// EOF). All zeros = skip verification.
    expected_sha256: [Sha256.digest_length]u8 = [_]u8{0} ** Sha256.digest_length,

    /// For uploads: announced total size (0 = unknown).
    declared_size: u64 = 0,

    /// True if `expected_sha256` is all zeros.
    skip_sha_verify: bool = true,

    /// For downloads: pump thread + channel-attached event, mirroring
    /// the tcp_connect / browser_proxy pattern.
    pump_thread: ?std.Thread = null,
    channel_attached: std.Thread.ResetEvent = .{},
    channel: ?*channel_mux.Channel = null,

    /// Monotonic timestamp of last `op=1 progress` emission. Atomic
    /// so the upload `on_data` (dispatch thread) can both read + CAS
    /// without contention against itself; on downloads the pump
    /// thread is the only writer.
    last_progress_ns: std.atomic.Value(u64) = .init(0),

    /// True after we emit the final op=2 control. Prevents double-send
    /// if both an EOF and a close fire.
    final_sent: std.atomic.Value(bool) = .init(false),
};

// =========================================================================
// Registration + vtable
// =========================================================================

/// Register the service in a daemon's channel-mux registry. Called
/// once at daemon startup.
pub fn register(reg: *channel_mux.Registry) !void {
    try reg.register(.{
        .id = service_id,
        .name = "file_transfer",
        .vtable = &vtable,
    });
}

pub const vtable: channel_mux.Service.VTable = .{
    .open = open,
    .on_opened = onOpened,
    .on_data = onData,
    .on_control = onControl,
    .on_eof = onEof,
    .on_close = onClose,
};

fn onOpened(state_ptr: ?*anyopaque, ch: *channel_mux.Channel) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    state.channel = ch;
    state.channel_attached.set();
}

fn open(
    _: ?*anyopaque,
    mux: *channel_mux.Mux,
    channel_id: u32,
    params: []const u8,
    ack_buf: []u8,
) channel_mux.ServiceError!channel_mux.Service.OpenResult {
    const parsed = parseOpenParams(mux.alloc, params) catch |err| {
        log.warn("file_transfer: open params invalid: {}", .{err});
        return error.InvalidRequest;
    };
    errdefer mux.alloc.free(parsed.path);

    // Sandbox check. PolicyDenied maps cleanly onto the mux's
    // policy_denied close reason.
    const resolved = ensureAllowedPath(mux.alloc, parsed.path) catch |err| {
        log.warn("file_transfer: path {s} denied: {}", .{ parsed.path, err });
        mux.alloc.free(parsed.path);
        return error.PolicyDenied;
    };
    mux.alloc.free(parsed.path);
    errdefer mux.alloc.free(resolved);

    const file_fd = switch (parsed.direction) {
        .upload => openForUpload(resolved, parsed.mode) catch |err| {
            log.warn("file_transfer upload: open {s} failed: {}", .{ resolved, err });
            return error.ServiceError;
        },
        .download => openForDownload(resolved) catch |err| {
            log.warn("file_transfer download: open {s} failed: {}", .{ resolved, err });
            return error.ServiceError;
        },
        else => return error.InvalidRequest,
    };
    errdefer posix.close(file_fd);

    const state = try mux.alloc.create(State);
    errdefer mux.alloc.destroy(state);
    state.* = .{
        .alloc = mux.alloc,
        .mux = mux,
        .channel_id = channel_id,
        .direction = parsed.direction,
        .path = resolved,
        .file_fd = file_fd,
        .expected_sha256 = parsed.expected_sha256,
        .declared_size = parsed.total_size,
        .skip_sha_verify = std.mem.allEqual(u8, &parsed.expected_sha256, 0),
    };

    switch (parsed.direction) {
        .upload => {
            // No pump for uploads — bytes are written inline by
            // on_data; on_eof finalizes.
            return .{ .state = state };
        },
        .download => {
            // Stat to fill the opened-ack (size + sha256). The sha256
            // is computed up-front so the opener can verify on the
            // fly; for very large files this is an O(N) walk through
            // the file, but cmux does the same and it's the simplest
            // correct option. Phase 9 may switch to a Merkle tree.
            const stat_size_sha = computeDownloadHeader(file_fd) catch |err| {
                log.warn("file_transfer download: header compute failed: {}", .{err});
                return error.ServiceError;
            };
            state.declared_size = stat_size_sha.size;

            // Write the opened ack: [size u64 LE][sha256 32].
            if (ack_buf.len < 8 + Sha256.digest_length) {
                log.warn("file_transfer: ack_buf too small", .{});
                return error.InvalidRequest;
            }
            std.mem.writeInt(u64, ack_buf[0..8], stat_size_sha.size, .little);
            @memcpy(
                ack_buf[8 .. 8 + Sha256.digest_length],
                &stat_size_sha.sha,
            );

            // Rewind the file so the pump starts at offset 0.
            _ = posix.lseek_SET(file_fd, 0) catch |err| {
                log.warn("file_transfer download: rewind failed: {}", .{err});
                return error.ServiceError;
            };

            state.pump_thread = std.Thread.spawn(.{}, pumpMain, .{state}) catch |err| {
                log.warn("file_transfer: pump spawn failed: {}", .{err});
                return error.ResourceExhausted;
            };

            return .{
                .state = state,
                .ack = ack_buf[0 .. 8 + Sha256.digest_length],
            };
        },
        else => unreachable,
    }
}

fn onData(state_ptr: ?*anyopaque, bytes: []const u8) channel_mux.ServiceError!void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    switch (state.direction) {
        .upload => uploadOnData(state, bytes) catch |err| {
            log.warn("file_transfer upload: write failed: {}", .{err});
            // Send op=2 final with status=write_failed before the mux
            // closes the channel from underneath us.
            sendFinal(state, .write_failed);
            return error.ServiceError;
        },
        .download => {
            // Spec: clients shouldn't send channel_data on a download
            // channel. Mirror cmux and reject — invalid_direction.
            log.warn("file_transfer download: unexpected inbound bytes ({d})", .{bytes.len});
            return error.InvalidRequest;
        },
        else => return error.InvalidRequest,
    }
}

fn uploadOnData(state: *State, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = try posix.write(state.file_fd, bytes[off..]);
        if (n == 0) return error.WriteZero;
        off += n;
    }
    state.hasher.update(bytes);
    state.bytes_transferred += bytes.len;
    maybeEmitProgress(state, bytes.len);
}

fn onControl(state_ptr: ?*anyopaque, op: u8, _: []const u8) channel_mux.ServiceError!void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    switch (op) {
        op_cancel => {
            // Either side may cancel. We don't tear down here — the
            // mux is about to call on_close anyway once we return
            // ServiceError. Returning the error lets the mux flag the
            // close reason as service_error with a clear message.
            sendFinal(state, .cancelled);
            return error.ServiceError;
        },
        else => {
            // Forward-compat: ignore unknown ops. cmux progress + final
            // are daemon → opener only; an opener sending op=1 or op=2
            // is nonsensical but not fatal.
            log.debug("file_transfer: ignoring control op={d}", .{op});
        },
    }
}

fn onEof(state_ptr: ?*anyopaque) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));
    switch (state.direction) {
        .upload => {
            // Client said "that's all the bytes". Verify the hash, send
            // the final control frame, then send our own EOF + close.
            const status: FinalStatus = if (state.skip_sha_verify)
                .ok
            else blk: {
                var snapshot = state.hasher;
                var digest: [Sha256.digest_length]u8 = undefined;
                snapshot.final(&digest);
                break :blk if (std.mem.eql(u8, &digest, &state.expected_sha256))
                    .ok
                else
                    .sha_mismatch;
            };
            sendFinal(state, status);
            // Send our half-close so the opener knows the daemon is
            // done writing.
            const ch = state.mux.getChannel(state.channel_id) orelse return;
            state.mux.sendChannelEof(ch) catch {};
        },
        .download => {
            // Opener half-closed. We don't have upstream data to send
            // either, but the pump may still be flushing buffered
            // bytes — no action needed; the pump will finish naturally.
            log.debug("file_transfer download: opener eof received", .{});
        },
        else => {},
    }
}

fn onClose(
    state_ptr: ?*anyopaque,
    _: protocol.ChannelCloseReason,
    _: []const u8,
) void {
    const state: *State = @ptrCast(@alignCast(state_ptr orelse return));

    // Defensive: unblock any pump waiting on attach (e.g. open ack
    // succeeded but the channel is being torn down before on_opened).
    state.channel_attached.set();

    if (state.pump_thread) |t| {
        // Best-effort: close the file fd to wake any pending read.
        posix.close(state.file_fd);
        t.join();
        state.pump_thread = null;
    } else {
        posix.close(state.file_fd);
    }

    state.alloc.free(state.path);
    state.alloc.destroy(state);
}

// =========================================================================
// Download pump
// =========================================================================

fn pumpMain(state: *State) void {
    pumpLoop(state) catch |err| {
        log.warn("file_transfer pump exiting on error: {}", .{err});
        sendFinal(state, .read_failed);
    };
}

fn pumpLoop(state: *State) !void {
    state.channel_attached.wait();
    var ch = state.mux.getChannel(state.channel_id) orelse return;

    var buf: [pump_read_chunk_size]u8 = undefined;
    while (!ch.close_signal.isSet()) {
        const n = posix.read(state.file_fd, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => {
                state.mux.requestClose(ch, .service_error, @errorName(err)) catch {};
                return;
            },
        };
        if (n == 0) {
            // File EOF. Send op=2 final with the final hash, then
            // half-close the channel so the opener sees the transfer
            // is complete.
            sendFinal(state, .ok);
            state.mux.sendChannelEof(ch) catch {};
            return;
        }
        state.hasher.update(buf[0..n]);
        state.bytes_transferred += n;

        var off: usize = 0;
        while (off < n) {
            if (ch.close_signal.isSet()) return;
            const sent = state.mux.sendChannelData(ch, buf[off..n]) catch |err| {
                log.warn("file_transfer pump: sendChannelData failed: {}", .{err});
                return;
            };
            if (sent == 0) {
                _ = state.mux.waitForCredit(ch, credit_wait_timeout_ns);
                continue;
            }
            off += sent;
        }

        maybeEmitProgress(state, n);
    }
}

// =========================================================================
// Progress + final emission
// =========================================================================

fn maybeEmitProgress(state: *State, chunk_size: usize) void {
    const now = monotonicNanos();
    const last = state.last_progress_ns.load(.acquire);
    const due_by_size = chunk_size >= progress_byte_boundary;
    const due_by_time = (now -% last) >= progress_min_interval_ns;
    if (!due_by_size and !due_by_time) return;
    state.last_progress_ns.store(now, .release);

    var snapshot = state.hasher;
    var partial: [Sha256.digest_length]u8 = undefined;
    snapshot.final(&partial);

    var payload: [8 + Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u64, payload[0..8], state.bytes_transferred, .little);
    @memcpy(payload[8..], &partial);

    sendControl(state, op_progress, &payload);
}

fn sendFinal(state: *State, status: FinalStatus) void {
    // Idempotent — only the first call wins. Cancel-during-upload
    // and EOF can race, so guard with an atomic.
    if (state.final_sent.swap(true, .acq_rel)) return;

    var digest: [Sha256.digest_length]u8 = undefined;
    var snapshot = state.hasher;
    snapshot.final(&digest);

    var payload: [Sha256.digest_length + 1]u8 = undefined;
    @memcpy(payload[0..Sha256.digest_length], &digest);
    payload[Sha256.digest_length] = @intFromEnum(status);
    sendControl(state, op_final, &payload);
}

fn sendControl(state: *State, op: u8, op_payload: []const u8) void {
    const ctrl = protocol.ChannelControl{
        .channel_id = state.channel_id,
        .op = op,
        .op_payload = op_payload,
    };
    const encoded = ctrl.encode(state.alloc) catch |err| {
        log.warn("file_transfer: control encode failed: {}", .{err});
        return;
    };
    defer state.alloc.free(encoded);
    state.mux.sendFrame(.channel_control, encoded) catch |err| {
        log.warn("file_transfer: control send failed: {}", .{err});
    };
}

fn monotonicNanos() u64 {
    // std.time.Instant.now() returns absolute monotonic since some
    // arbitrary epoch; we only ever subtract instants, so the epoch
    // doesn't matter.
    return @intCast(std.time.nanoTimestamp());
}

// =========================================================================
// File open helpers
// =========================================================================

fn openForUpload(path: []const u8, mode: u32) !posix.fd_t {
    // create+truncate (cmux uses os.Create which is O_RDWR|O_CREATE|O_TRUNC).
    // We use O_WRONLY since the upload path never reads.
    const flags: posix.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    };
    const fd = try posix.open(path, flags, @intCast(mode));
    return fd;
}

fn openForDownload(path: []const u8) !posix.fd_t {
    const flags: posix.O = .{ .ACCMODE = .RDONLY };
    return posix.open(path, flags, 0);
}

const SizeAndSha = struct {
    size: u64,
    sha: [Sha256.digest_length]u8,
};

fn computeDownloadHeader(fd: posix.fd_t) !SizeAndSha {
    var hasher = Sha256.init(.{});
    var buf: [pump_read_chunk_size]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = try posix.read(fd, &buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
        total += n;
    }
    var sha: [Sha256.digest_length]u8 = undefined;
    hasher.final(&sha);
    return .{ .size = total, .sha = sha };
}

// =========================================================================
// Sandbox: ensureAllowedPath (port of cmux file_transfer.go:113)
// =========================================================================

/// Compute the list of allow-roots. For the v1 port these are
/// hard-coded — `$HOME` + `/tmp`. Designed to be expandable later
/// without changing call sites. Caller owns the returned slice + each
/// element string.
fn allowedRoots(alloc: Allocator) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |r| alloc.free(r);
        list.deinit(alloc);
    }

    if (std.process.getEnvVarOwned(alloc, "HOME")) |home| {
        try list.append(alloc, home);
    } else |_| {
        // No HOME — proceed with /tmp only.
    }
    try list.append(alloc, try alloc.dupe(u8, "/tmp"));
    return list.toOwnedSlice(alloc);
}

fn freeAllowedRoots(alloc: Allocator, roots: []const []const u8) void {
    for (roots) |r| alloc.free(r);
    alloc.free(roots);
}

/// Resolve `path` and ensure it lives under one of `allowedRoots`.
/// Symlink-aware: if the target exists, its symlinks are resolved; if
/// it doesn't exist (upload path), the deepest existing ancestor is
/// resolved and the basename glued back on. Returns an owned absolute
/// path; caller frees with `alloc.free`.
pub fn ensureAllowedPath(alloc: Allocator, path: []const u8) ![]u8 {
    const roots = try allowedRoots(alloc);
    defer freeAllowedRoots(alloc, roots);
    return ensureAllowedPathWithRoots(alloc, path, roots);
}

/// Same as `ensureAllowedPath` but accepts an explicit roots list.
/// Split out so tests can drive deterministic roots.
pub fn ensureAllowedPathWithRoots(
    alloc: Allocator,
    path: []const u8,
    roots: []const []const u8,
) ![]u8 {
    if (path.len == 0 or path.len > max_path_len) return error.InvalidPath;

    // Absolutize the input first. realpath would do this and resolve
    // symlinks atomically, but it requires the target to exist.
    const abs = try absolutize(alloc, path);
    defer alloc.free(abs);

    const resolved = try resolveOrParent(alloc, abs);
    errdefer alloc.free(resolved);

    for (roots) |root| {
        const abs_root = absolutize(alloc, root) catch continue;
        defer alloc.free(abs_root);
        const resolved_root = resolveOrSelf(alloc, abs_root) catch continue;
        defer alloc.free(resolved_root);

        if (isWithinRoot(resolved, resolved_root)) return resolved;
    }
    return error.PolicyDenied;
}

/// Return an owned absolute form of `path`. If `path` is already
/// absolute we just dupe it; otherwise we prepend cwd.
fn absolutize(alloc: Allocator, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return alloc.dupe(u8, path);
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = try posix.getcwd(&cwd_buf);
    return std.fs.path.resolve(alloc, &.{ cwd, path });
}

/// Resolve `abs` via realpath; if it doesn't exist, walk up to the
/// nearest existing ancestor, realpath that, and re-glue the basename.
fn resolveOrParent(alloc: Allocator, abs: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (posix.realpath(abs, &buf)) |resolved| {
        return alloc.dupe(u8, resolved);
    } else |err| switch (err) {
        error.FileNotFound, error.NotDir => {},
        else => return err,
    }

    // Walk up. We mutate a heap copy of `abs` instead of slicing so
    // dirname/basename calls produce stable strings.
    var cursor = try alloc.dupe(u8, abs);
    defer alloc.free(cursor);

    while (true) {
        const parent = std.fs.path.dirname(cursor) orelse return error.NoExistingAncestor;
        if (parent.len == 0) return error.NoExistingAncestor;
        if (parent.len == cursor.len) return error.NoExistingAncestor; // safety
        if (posix.realpath(parent, &buf)) |resolved_parent| {
            const basename = std.fs.path.basename(abs);
            return std.fs.path.join(alloc, &.{ resolved_parent, basename });
        } else |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                // Climb again.
                const trimmed = try alloc.dupe(u8, parent);
                alloc.free(cursor);
                cursor = trimmed;
                if (std.mem.eql(u8, cursor, "/")) return error.NoExistingAncestor;
            },
            else => return err,
        }
    }
}

/// Like `resolveOrParent` but if the path doesn't exist, returns a
/// dupe of the input. Used for roots — non-existent roots are simply
/// kept as-is so prefix matching still works.
fn resolveOrSelf(alloc: Allocator, abs: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (posix.realpath(abs, &buf)) |resolved| {
        return alloc.dupe(u8, resolved);
    } else |err| switch (err) {
        error.FileNotFound, error.NotDir => return alloc.dupe(u8, abs),
        else => return err,
    }
}

/// True if `path` is `root` itself or sits beneath it. Uses the
/// trailing-separator trick to avoid prefix collisions
/// (`/tmp2` must not match `/tmp`).
fn isWithinRoot(path: []const u8, root: []const u8) bool {
    if (std.mem.eql(u8, path, root)) return true;
    // Special-case "/" so we don't double the slash.
    if (root.len == 1 and root[0] == '/') {
        return path.len > 0 and path[0] == '/';
    }
    if (path.len <= root.len) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    return path[root.len] == std.fs.path.sep;
}

// =========================================================================
// Open params codec
// =========================================================================

const ParsedParams = struct {
    direction: Direction,
    mode: u32,
    path: []u8, // owned by alloc
    expected_sha256: [Sha256.digest_length]u8 = [_]u8{0} ** Sha256.digest_length,
    total_size: u64 = 0,
};

fn parseOpenParams(alloc: Allocator, params: []const u8) !ParsedParams {
    // Fixed prefix: direction(1) + mode(4) + path_len(2) = 7 bytes.
    if (params.len < 7) return error.TooShort;
    const direction: Direction = @enumFromInt(params[0]);
    const mode = std.mem.readInt(u32, params[1..5], .little);
    const path_len = std.mem.readInt(u16, params[5..7], .little);
    if (path_len == 0 or path_len > max_path_len) return error.InvalidPathLen;

    var off: usize = 7;
    if (params.len < off + path_len) return error.Truncated;
    const path = try alloc.dupe(u8, params[off .. off + path_len]);
    errdefer alloc.free(path);
    off += path_len;

    var parsed: ParsedParams = .{
        .direction = direction,
        .mode = mode,
        .path = path,
    };

    switch (direction) {
        .upload => {
            // Upload trailer: expected_sha256(32) + total_size(8).
            if (params.len < off + Sha256.digest_length + 8) return error.Truncated;
            @memcpy(
                &parsed.expected_sha256,
                params[off .. off + Sha256.digest_length],
            );
            off += Sha256.digest_length;
            parsed.total_size = std.mem.readInt(u64, params[off..][0..8], .little);
        },
        .download => {
            // No trailer for downloads. Anything beyond `path` is
            // ignored (forward-compat).
        },
        else => return error.InvalidDirection,
    }

    return parsed;
}

/// Encode upload open params. Caller owns the returned slice.
pub fn encodeUploadParams(
    alloc: Allocator,
    path: []const u8,
    mode: u32,
    expected_sha256: [Sha256.digest_length]u8,
    total_size: u64,
) ![]u8 {
    if (path.len == 0 or path.len > max_path_len) return error.InvalidPathLen;
    const total = 1 + 4 + 2 + path.len + Sha256.digest_length + 8;
    const buf = try alloc.alloc(u8, total);
    buf[0] = @intFromEnum(Direction.upload);
    std.mem.writeInt(u32, buf[1..5], mode, .little);
    std.mem.writeInt(u16, buf[5..7], @intCast(path.len), .little);
    @memcpy(buf[7 .. 7 + path.len], path);
    @memcpy(
        buf[7 + path.len .. 7 + path.len + Sha256.digest_length],
        &expected_sha256,
    );
    std.mem.writeInt(
        u64,
        buf[7 + path.len + Sha256.digest_length ..][0..8],
        total_size,
        .little,
    );
    return buf;
}

/// Encode download open params. Caller owns the returned slice.
pub fn encodeDownloadParams(alloc: Allocator, path: []const u8) ![]u8 {
    if (path.len == 0 or path.len > max_path_len) return error.InvalidPathLen;
    const total = 1 + 4 + 2 + path.len;
    const buf = try alloc.alloc(u8, total);
    buf[0] = @intFromEnum(Direction.download);
    std.mem.writeInt(u32, buf[1..5], 0, .little); // mode unused
    std.mem.writeInt(u16, buf[5..7], @intCast(path.len), .little);
    @memcpy(buf[7 .. 7 + path.len], path);
    return buf;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

test "file_transfer encodeUploadParams roundtrip" {
    var sha = [_]u8{0} ** Sha256.digest_length;
    for (0..Sha256.digest_length) |i| sha[i] = @intCast(i);
    const buf = try encodeUploadParams(testing.allocator, "/tmp/foo", 0o644, sha, 1234);
    defer testing.allocator.free(buf);

    const parsed = try parseOpenParams(testing.allocator, buf);
    defer testing.allocator.free(parsed.path);
    try testing.expectEqual(Direction.upload, parsed.direction);
    try testing.expectEqual(@as(u32, 0o644), parsed.mode);
    try testing.expectEqualStrings("/tmp/foo", parsed.path);
    try testing.expectEqualSlices(u8, &sha, &parsed.expected_sha256);
    try testing.expectEqual(@as(u64, 1234), parsed.total_size);
}

test "file_transfer encodeDownloadParams roundtrip" {
    const buf = try encodeDownloadParams(testing.allocator, "/tmp/bar");
    defer testing.allocator.free(buf);

    const parsed = try parseOpenParams(testing.allocator, buf);
    defer testing.allocator.free(parsed.path);
    try testing.expectEqual(Direction.download, parsed.direction);
    try testing.expectEqualStrings("/tmp/bar", parsed.path);
    try testing.expectEqual(@as(u64, 0), parsed.total_size);
}

test "file_transfer parseOpenParams rejects truncated input" {
    // Only the fixed prefix, no path bytes.
    var tiny: [7]u8 = undefined;
    tiny[0] = 0;
    std.mem.writeInt(u32, tiny[1..5], 0, .little);
    std.mem.writeInt(u16, tiny[5..7], 10, .little); // claims 10-byte path
    try testing.expectError(error.Truncated, parseOpenParams(testing.allocator, &tiny));
}

test "file_transfer parseOpenParams rejects zero path_len" {
    var bad: [7]u8 = undefined;
    bad[0] = 0;
    std.mem.writeInt(u32, bad[1..5], 0, .little);
    std.mem.writeInt(u16, bad[5..7], 0, .little);
    try testing.expectError(error.InvalidPathLen, parseOpenParams(testing.allocator, &bad));
}

test "file_transfer ensureAllowedPath: under root succeeds" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("hello", .{});
    file.close();

    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = root;

    const target = try std.fs.path.join(testing.allocator, &.{ root, "hello" });
    defer testing.allocator.free(target);
    const resolved = try ensureAllowedPathWithRoots(testing.allocator, target, roots);
    defer testing.allocator.free(resolved);

    // Resolved should still live under the resolved root.
    try testing.expect(std.mem.startsWith(u8, resolved, root));
}

test "file_transfer ensureAllowedPath: non-existent path under root succeeds" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = root;

    const target = try std.fs.path.join(testing.allocator, &.{ root, "not-yet-created" });
    defer testing.allocator.free(target);
    const resolved = try ensureAllowedPathWithRoots(testing.allocator, target, roots);
    defer testing.allocator.free(resolved);
    try testing.expect(std.mem.startsWith(u8, resolved, root));
}

test "file_transfer ensureAllowedPath: outside root denied" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = root;

    // /etc/passwd is definitely not in our tmp root.
    try testing.expectError(
        error.PolicyDenied,
        ensureAllowedPathWithRoots(testing.allocator, "/etc/passwd", roots),
    );
}

test "file_transfer ensureAllowedPath: traversal denied" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = root;

    // Build "<root>/../etc/passwd" — the realpath/resolveOrParent
    // logic must collapse the .. and reject.
    const escape = try std.fs.path.join(testing.allocator, &.{ root, "..", "etc", "passwd" });
    defer testing.allocator.free(escape);
    try testing.expectError(
        error.PolicyDenied,
        ensureAllowedPathWithRoots(testing.allocator, escape, roots),
    );
}

test "file_transfer ensureAllowedPath: symlink escape denied" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    // Symlink inside tmp pointing to /etc/passwd (outside the root).
    tmp.dir.symLink("/etc/passwd", "escape", .{}) catch |err| switch (err) {
        // On systems where symlink creation isn't permitted, skip.
        error.AccessDenied => return error.SkipZigTest,
        else => return err,
    };

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = root;

    const symlink_path = try std.fs.path.join(testing.allocator, &.{ root, "escape" });
    defer testing.allocator.free(symlink_path);
    try testing.expectError(
        error.PolicyDenied,
        ensureAllowedPathWithRoots(testing.allocator, symlink_path, roots),
    );
}

test "file_transfer ensureAllowedPath: macOS /tmp -> /private/tmp normalised" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;

    const roots = try testing.allocator.alloc([]const u8, 1);
    defer testing.allocator.free(roots);
    roots[0] = "/tmp";

    const resolved = try ensureAllowedPathWithRoots(testing.allocator, "/tmp", roots);
    defer testing.allocator.free(resolved);
    // /tmp resolves to /private/tmp on macOS and that's what we want
    // to compare against: the helper must accept it as "under /tmp".
    try testing.expect(std.mem.eql(u8, resolved, "/private/tmp") or
        std.mem.eql(u8, resolved, "/tmp"));
}

// =========================================================================
// End-to-end tests
// =========================================================================

const HeapMux = struct {
    a: posix.fd_t,
    b: posix.fd_t,
    alloc: Allocator,
    registry: *channel_mux.Registry,
    mux: channel_mux.Mux,

    fn init(alloc: Allocator) !HeapMux {
        var fds: [2]posix.fd_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc != 0) return error.SocketPairFailed;
        const reg = try alloc.create(channel_mux.Registry);
        reg.* = channel_mux.Registry.init(alloc);
        const mux = channel_mux.Mux.init(alloc, fds[0], reg);
        return .{ .a = fds[0], .b = fds[1], .alloc = alloc, .registry = reg, .mux = mux };
    }

    fn deinit(self: *HeapMux) void {
        self.mux.deinit();
        self.registry.deinit();
        self.alloc.destroy(self.registry);
        posix.close(self.a);
        posix.close(self.b);
    }
};

fn readFrameAlloc(alloc: Allocator, fd: posix.fd_t) !struct {
    header: protocol.Header,
    payload: []u8,
} {
    var hbuf: [protocol.header_size]u8 = undefined;
    var off: usize = 0;
    while (off < hbuf.len) {
        const n = try posix.read(fd, hbuf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
    const header = try protocol.Header.parseFromBuf(&hbuf);
    const payload = try alloc.alloc(u8, header.len);
    off = 0;
    while (off < payload.len) {
        const n = try posix.read(fd, payload[off..]);
        if (n == 0) {
            alloc.free(payload);
            return error.UnexpectedEof;
        }
        off += n;
    }
    return .{ .header = header, .payload = payload };
}

test "file_transfer end-to-end: upload writes file and emits ok final" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var realbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &realbuf);

    var pair = try HeapMux.init(testing.allocator);
    defer pair.deinit();
    try register(pair.registry);

    // Allow our tmp root only — install via env override would be
    // intrusive; instead, place the upload under /tmp which is in the
    // default allow-list.
    const upload_name = try std.fmt.allocPrint(testing.allocator, "ghostty-ft-{d}", .{
        @as(u32, @intCast(std.time.milliTimestamp() & 0xFFFFFFFF)),
    });
    defer testing.allocator.free(upload_name);
    const upload_path = try std.fs.path.join(testing.allocator, &.{ "/tmp", upload_name });
    defer testing.allocator.free(upload_path);
    defer std.fs.cwd().deleteFile(upload_path) catch {};
    _ = root;

    const payload = "hello-upload";
    var sha: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(payload, &sha, .{});

    const params = try encodeUploadParams(
        testing.allocator,
        upload_path,
        0o644,
        sha,
        payload.len,
    );
    defer testing.allocator.free(params);

    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .file_transfer,
        .initial_window = 8,
        .service_params = params,
    };
    const open_buf = try open_frame.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);

    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, opened_frame.header.kind);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);

    // Send payload + eof.
    const data = protocol.ChannelData{ .channel_id = 1, .bytes = payload };
    const data_buf = try data.encode(testing.allocator);
    defer testing.allocator.free(data_buf);
    try pair.mux.dispatch(.channel_data, data_buf);

    const eof = protocol.ChannelEof{ .channel_id = 1 };
    const eof_bytes = eof.encode();
    try pair.mux.dispatch(.channel_eof, &eof_bytes);

    // Expect: op=2 final with status=ok, then channel_eof from us.
    var saw_final = false;
    var saw_eof = false;
    while (!saw_final or !saw_eof) {
        const frame = try readFrameAlloc(testing.allocator, pair.b);
        defer testing.allocator.free(frame.payload);
        switch (frame.header.kind) {
            .channel_control => {
                const ctrl = try protocol.ChannelControl.parse(frame.payload);
                if (ctrl.op == op_final) {
                    saw_final = true;
                    try testing.expectEqual(
                        @as(usize, Sha256.digest_length + 1),
                        ctrl.op_payload.len,
                    );
                    try testing.expectEqualSlices(
                        u8,
                        &sha,
                        ctrl.op_payload[0..Sha256.digest_length],
                    );
                    try testing.expectEqual(
                        @as(u8, @intFromEnum(FinalStatus.ok)),
                        ctrl.op_payload[Sha256.digest_length],
                    );
                }
            },
            .channel_eof => saw_eof = true,
            .channel_window, .channel_data => {},
            else => return error.UnexpectedFrame,
        }
    }

    // Verify the bytes on disk match.
    const got = try std.fs.cwd().readFileAlloc(testing.allocator, upload_path, 1024);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(payload, got);

    // Clean teardown.
    const close = protocol.ChannelClose{
        .channel_id = 1,
        .reason = .normal,
        .message = "",
    };
    const close_buf = try close.encode(testing.allocator);
    defer testing.allocator.free(close_buf);
    try pair.mux.dispatch(.channel_close, close_buf);
}

test "file_transfer end-to-end: download streams file and emits ok final" {
    // Stage a fixture under /tmp.
    const payload = "hello-download-payload";
    const name = try std.fmt.allocPrint(testing.allocator, "ghostty-ft-dl-{d}", .{
        @as(u32, @intCast(std.time.milliTimestamp() & 0xFFFFFFFF)),
    });
    defer testing.allocator.free(name);
    const path = try std.fs.path.join(testing.allocator, &.{ "/tmp", name });
    defer testing.allocator.free(path);
    defer std.fs.cwd().deleteFile(path) catch {};
    {
        const f = try std.fs.cwd().createFile(path, .{});
        defer f.close();
        try f.writeAll(payload);
    }

    var pair = try HeapMux.init(testing.allocator);
    defer pair.deinit();
    try register(pair.registry);

    const params = try encodeDownloadParams(testing.allocator, path);
    defer testing.allocator.free(params);

    const open_frame = protocol.ChannelOpen{
        .channel_id = 1,
        .service = .file_transfer,
        .initial_window = 8,
        .service_params = params,
    };
    const open_buf = try open_frame.encode(testing.allocator);
    defer testing.allocator.free(open_buf);
    try pair.mux.dispatch(.channel_open, open_buf);

    // First frame should be channel_opened carrying [size u64][sha256].
    const opened_frame = try readFrameAlloc(testing.allocator, pair.b);
    defer testing.allocator.free(opened_frame.payload);
    try testing.expectEqual(protocol.Kind.channel_opened, opened_frame.header.kind);
    const opened = try protocol.ChannelOpened.parse(opened_frame.payload);
    try testing.expectEqual(protocol.ChannelOpenStatus.ok, opened.status);
    try testing.expectEqual(
        @as(usize, 8 + Sha256.digest_length),
        opened.service_ack.len,
    );
    const advertised_size = std.mem.readInt(u64, opened.service_ack[0..8], .little);
    try testing.expectEqual(@as(u64, payload.len), advertised_size);
    var expected_sha: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(payload, &expected_sha, .{});
    try testing.expectEqualSlices(
        u8,
        &expected_sha,
        opened.service_ack[8 .. 8 + Sha256.digest_length],
    );

    // Read channel_data + control frames until we have the full
    // payload and a final-ok.
    var collected: std.ArrayList(u8) = .empty;
    defer collected.deinit(testing.allocator);
    var saw_final = false;
    while (collected.items.len < payload.len or !saw_final) {
        const frame = try readFrameAlloc(testing.allocator, pair.b);
        defer testing.allocator.free(frame.payload);
        switch (frame.header.kind) {
            .channel_data => {
                const dd = try protocol.ChannelData.parse(frame.payload);
                try collected.appendSlice(testing.allocator, dd.bytes);
            },
            .channel_control => {
                const ctrl = try protocol.ChannelControl.parse(frame.payload);
                if (ctrl.op == op_final) {
                    saw_final = true;
                    try testing.expectEqualSlices(
                        u8,
                        &expected_sha,
                        ctrl.op_payload[0..Sha256.digest_length],
                    );
                    try testing.expectEqual(
                        @as(u8, @intFromEnum(FinalStatus.ok)),
                        ctrl.op_payload[Sha256.digest_length],
                    );
                }
            },
            .channel_eof, .channel_window => {},
            else => return error.UnexpectedFrame,
        }
    }
    try testing.expectEqualStrings(payload, collected.items);

    const close = protocol.ChannelClose{
        .channel_id = 1,
        .reason = .normal,
        .message = "",
    };
    const close_buf = try close.encode(testing.allocator);
    defer testing.allocator.free(close_buf);
    try pair.mux.dispatch(.channel_close, close_buf);
}
