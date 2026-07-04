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
//!
//! This file is the service facade. Two self-contained concerns were
//! split into siblings that it re-exports:
//!   * `file_transfer_sandbox.zig` — the allow-root path sandbox
//!     (`ensureAllowedPath` / `ensureAllowedPathWithRoots`).
//!   * `file_transfer_params.zig` — the open-params wire codec
//!     (`parseOpenParams` / `encodeUploadParams` / `encodeDownloadParams`).

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
/// `pub` so the `file_transfer_sandbox` / `file_transfer_params`
/// siblings can share the same bound via `root.max_path_len`.
pub const max_path_len: usize = 4096;

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

// =========================================================================
// Facade re-exports (split-out siblings)
// =========================================================================

// Filesystem allow-root sandbox — see file_transfer_sandbox.zig.
pub const ensureAllowedPath = @import("file_transfer_sandbox.zig").ensureAllowedPath;
pub const ensureAllowedPathWithRoots = @import("file_transfer_sandbox.zig").ensureAllowedPathWithRoots;

// Open-params wire codec — see file_transfer_params.zig.
pub const encodeUploadParams = @import("file_transfer_params.zig").encodeUploadParams;
pub const encodeDownloadParams = @import("file_transfer_params.zig").encodeDownloadParams;
const parseOpenParams = @import("file_transfer_params.zig").parseOpenParams;

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
        // Closing the file fd before joining looks like a race against
        // the pump's posix.read, but the mux sets ch.close_signal
        // before calling on_close (see channel_mux.zig:closeChannel /
        // handleClose), so the pump observes the signal at its next
        // loop check and exits without touching the fd. Closing the fd
        // here also unblocks any thread currently parked inside a
        // read() syscall.
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
                // Send op=2 BEFORE requestClose. requestClose tears the
                // channel down and removes it from the mux registry; any
                // control frame queued after that point would race with
                // the channel_close frame on the wire, and the peer may
                // discard it as "frame for unknown channel". Order
                // matters for the granular FinalStatus to actually reach
                // the opener.
                sendFinal(state, .read_failed);
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
// Tests
// =========================================================================

const testing = std.testing;

// Inline tests moved with their decls live in the siblings; aggregate
// them so `zig test` on this facade still discovers them.
test {
    _ = @import("file_transfer_sandbox.zig");
    _ = @import("file_transfer_params.zig");
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

/// Pick a guaranteed-unique path under /tmp by retrying with O_EXCL
/// until create succeeds. Caller frees the returned path and is
/// responsible for deleting the file. The created file is closed
/// immediately — its only purpose is to claim the name.
fn reserveUniqueTmpPath(alloc: Allocator, prefix: []const u8) ![]u8 {
    const pid = posix.system.getpid();
    const seed_mix: u64 = @bitCast(@as(i64, @truncate(std.time.nanoTimestamp())));
    var rng = std.Random.DefaultPrng.init(seed_mix ^ @as(u64, @intCast(pid)));
    var attempt: usize = 0;
    while (attempt < 32) : (attempt += 1) {
        const suffix = rng.next();
        const path = try std.fmt.allocPrint(
            alloc,
            "/tmp/{s}-{d}-{x}",
            .{ prefix, pid, suffix },
        );
        errdefer alloc.free(path);
        const flags: posix.O = .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
        };
        if (posix.open(path, flags, 0o600)) |fd| {
            posix.close(fd);
            return path;
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                alloc.free(path);
                continue;
            },
            else => return err,
        }
    }
    return error.NoUniquePath;
}

test "file_transfer end-to-end: upload writes file and emits ok final" {
    var pair = try HeapMux.init(testing.allocator);
    defer pair.deinit();
    try register(pair.registry);

    // Place the upload under /tmp because it's in the default
    // allow-list. reserveUniqueTmpPath uses O_EXCL so parallel test
    // runs can't collide.
    const upload_path = try reserveUniqueTmpPath(testing.allocator, "ghostty-ft-up");
    defer testing.allocator.free(upload_path);
    defer std.fs.cwd().deleteFile(upload_path) catch {};

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
    // Stage a fixture under /tmp with an O_EXCL-claimed path so
    // parallel test runs can't collide.
    const payload = "hello-download-payload";
    const path = try reserveUniqueTmpPath(testing.allocator, "ghostty-ft-dl");
    defer testing.allocator.free(path);
    defer std.fs.cwd().deleteFile(path) catch {};
    {
        // reserveUniqueTmpPath already created the file as empty; open
        // again with truncate to write the fixture.
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
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
