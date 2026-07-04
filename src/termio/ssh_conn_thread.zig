//! The dedicated SSH thread for one connection `Entry`: `sshThreadMain`'s
//! poll loop (reads → frame dispatch → write-queue drain → keepalive), the
//! reconnect state machine + backoff, connection-state broadcast + listener
//! registry, terminal/mux channel (re)open, and the low-level frame send /
//! pipe helpers. Split out of `SshConnectionManager.zig`, which re-exports
//! the `pub` entrypoints unchanged.

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

const frames = @import("ssh_conn_frames.zig");
const processFrames = frames.processFrames;


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

    // Transport-level keepalive (libssh2). Distinct from the cmux
    // session-protocol channel ping/pong above: this emits SSH transport
    // keepalives that reset the remote sshd's ClientAlive/idle timer so
    // sshd does not tear the transport down (the 15s = 5s*3 ClientAlive
    // disconnect that manifested as an EOF-driven reconnect flicker).
    // Due immediately on the first loop so we never start behind.
    var next_transport_keepalive_at: i128 = now_init;

    while (true) {
        // 1. Process SSH transport (needed for tunneled sessions).
        //    libssh2 is single-threaded per-session; the per-Entry mutex
        //    serialises this with any SshChannelStreamTransport running
        //    on a mux channel of the same session (see Entry.libssh2_mutex).
        entry.libssh2_mutex.lock();
        sess.pollTransport(1);
        entry.libssh2_mutex.unlock();

        // 2. Drain reads (non-blocking tight loop). Re-acquire per
        //    iteration so a transport-reader thread can make progress
        //    between our reads instead of starving on a long burst.
        while (true) {
            entry.libssh2_mutex.lock();
            const rc = channel.readNonBlock(&read_buf);
            entry.libssh2_mutex.unlock();
            if (rc > 0) {
                frame_buf.appendSlice(
                    entry.alloc,
                    read_buf[0..@intCast(rc)],
                ) catch break;
            } else break;
        }

        // Check channel EOF. Two distinct causes:
        //   1. The remote ghostty-daemon exited cleanly (genuine
        //      session-end — surfaces should die).
        //   2. The SSH transport itself dropped (tunnel/VPN down,
        //      laptop sleep, network partition). The daemon is
        //      almost certainly still alive on the other side; we
        //      want to drive the reconnect loop instead of tearing
        //      surfaces down.
        //
        // We can't reliably distinguish (1) from (2) from EOF alone,
        // but `attemptReconnect` is the right thing to try first —
        // if max_reconnect_attempts is exhausted (or set to 0) the
        // function returns false and we fall through to the
        // session-end behaviour. With a "patient but persistent"
        // config (max_reconnect_attempts = u32.max) we essentially
        // never give up on tunnel drops, which is what cmux wants.
        entry.libssh2_mutex.lock();
        const channel_is_eof = channel.eof();
        entry.libssh2_mutex.unlock();
        if (channel_is_eof) {
            log.info("ssh channel EOF — attempting reconnect", .{});
            if (attemptReconnect(entry)) {
                // Reconnected — refresh local refs and continue the loop.
                const reconnect_now = std.time.nanoTimestamp();
                last_keepalive_sent = reconnect_now;
                entry.last_keepalive_received = reconnect_now;
                next_transport_keepalive_at = reconnect_now;
                sess = &entry.ctx.session.?;
                channel = &entry.channel.?;
                // Discard any partial frame bytes left over from the OLD
                // channel. The reopened channel is a fresh stream starting at
                // frame offset 0; concatenating the stale tail with the new
                // bytes mis-aligns the (sync-markerless) frame parser, which
                // silently consumes/drops real `.data_out` terminal output
                // mid-UTF-8 → permanent scrambling (U+FFFD) until it happens
                // to realign. reopenSurfaces re-sends the attach, so the stale
                // tail carries nothing we need.
                frame_buf.clearRetainingCapacity();
                broadcastConnectionState(entry, .connected);
                continue;
            }
            notifyAllSurfaces(entry);
            return;
        }

        // Process complete protocol frames (updates entry.last_keepalive_received).
        // processFrames is in-memory only — never calls libssh2 — so the
        // mutex stays released here, letting the transport thread make
        // progress while we dispatch frames.
        processFrames(&frame_buf, entry);

        // 3. Drain write queue. sendFrame issues 1-2 libssh2 writes; the
        //    lock is re-taken per request so the transport thread gets
        //    interleaved time between bursts.
        {
            entry.write_queue_mu.lock();
            for (entry.write_queue.items) |req| {
                entry.libssh2_mutex.lock();
                const send_err = sendFrame(channel, req.kind, req.target_id, req.data);
                entry.libssh2_mutex.unlock();
                send_err catch |err| {
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
            entry.libssh2_mutex.lock();
            const ping_err = sendFrame(channel, .ping, 0, "");
            entry.libssh2_mutex.unlock();
            if (ping_err) |_| {
                // Diagnostic: confirm pings are leaving on the main multiplex
                // channel. Multiplex-side keepalive_server_timeout (60s) fires
                // a terminal-vanish if these stop arriving.
                log.info("keepalive: sent ping (interval={d}s)", .{
                    @as(i64, @intCast(@divFloor(now - last_keepalive_sent, std.time.ns_per_s))),
                });
            } else |err| {
                log.warn("ping send failed: {}", .{err});
            }
            last_keepalive_sent = now;
        }

        // 4b. Transport-level keepalive: emit an SSH transport keepalive
        //     (keepalive@openssh.com, want_reply=1) when due so the remote
        //     sshd's ClientAlive/idle timer is reset and it does not tear
        //     the transport down. keepaliveSend returns the seconds until
        //     the next one is due; we schedule off that. A transient send
        //     error is non-fatal (keepaliveSend logs and returns 0) — we do
        //     NOT trigger attemptReconnect here, since the channel EOF and
        //     stale-pong paths already cover genuine transport loss.
        if (now >= next_transport_keepalive_at) {
            entry.libssh2_mutex.lock();
            const seconds_to_next = sess.keepaliveSend();
            entry.libssh2_mutex.unlock();
            // Clamp the reschedule so a stale/garbage value can't push the
            // next keepalive past the 15s sshd disconnect window.
            const next_s: u32 = @min(seconds_to_next, session.client.transport_keepalive_interval_s);
            next_transport_keepalive_at = now + @as(i128, next_s) * std.time.ns_per_s;
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
                next_transport_keepalive_at = reconnect_now;

                // Update local references (session/channel may have changed)
                sess = &entry.ctx.session.?;
                channel = &entry.channel.?;

                // Discard stale partial-frame bytes from the old channel — see
                // the EOF reconnect path above; carrying them across the reopen
                // desyncs the frame parser and scrambles terminal output.
                frame_buf.clearRetainingCapacity();

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
        entry.libssh2_mutex.lock();
        const sess_needs_write = sess.needsWrite();
        entry.libssh2_mutex.unlock();
        if (sess_needs_write) pollfds[0].events |= posix.POLL.OUT;

        // 6. Compute poll timeout: wake up in time to send the next
        //    session-protocol ping AND the next transport-level keepalive,
        //    whichever is sooner. Missing the transport keepalive deadline
        //    is what lets sshd disconnect the transport, so it must gate the
        //    poll timeout too.
        const elapsed_since_send = now - last_keepalive_sent;
        const remaining_ping_ns = session.protocol.keepalive_interval_ns - elapsed_since_send;
        const remaining_transport_ns = next_transport_keepalive_at - now;
        const remaining_ns = @min(remaining_ping_ns, remaining_transport_ns);
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
                entry.libssh2_mutex.lock();
                const send_err = sendFrame(channel, req.kind, req.target_id, req.data);
                entry.libssh2_mutex.unlock();
                send_err catch |err| {
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
            entry.libssh2_mutex.lock();
            sess.setBlocking(1);
            sess.pollTransport(500);
            entry.libssh2_mutex.unlock();

            return;
        }
    }
}

fn notifyAllSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();
    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.*.surfaces.items) |s| {
            _ = s.surface_mailbox.push(.{
                .child_exited = .{ .exit_code = 0, .runtime_ms = 0 },
            }, .{ .forever = {} });
        }
    }
}

/// Broadcast a connection-state transition to every consumer attached
/// to the Entry — both the per-surface mailbox fan-out (for the GTK
/// terminal renderer) and the generic SshListener registry (for the
/// libghostty C API and any other embedder). Public so the shared
/// attach helper in `session/client.zig` can drive it.
pub fn broadcastConnectionState(entry: *Entry, state: session.protocol.ConnectionState) void {
    // Surface fan-out runs under surfaces_mutex. Scope-block so the
    // defer releases it before we touch listener_mutex — the two
    // locks intentionally do not nest, so a listener callback that
    // (e.g. via the libghostty C API) eventually calls back into a
    // surfaces-mutex-guarded API never deadlocks on this thread.
    {
        entry.surfaces_mutex.lock();
        defer entry.surfaces_mutex.unlock();
        var it = entry.sessions.iterator();
        while (it.next()) |kv| {
            for (kv.value_ptr.*.surfaces.items) |s| {
                _ = s.surface_mailbox.push(.{ .connection_state = state }, .{ .forever = {} });
            }
        }
    }
    // Generic listeners (e.g. libghostty C API embedders). Cache the
    // state for late-arriving registrations under listener_mutex,
    // then dupe the slice and release the lock BEFORE invoking
    // callbacks — listeners that re-enter the listener API (e.g.
    // unregister from inside on_state) would otherwise deadlock.
    // Listeners must still be cheap (no blocking work, no embedder
    // I/O) because they run on the SSH thread.
    entry.listener_mutex.lock();
    entry.last_state = state;
    const dup_snapshot = entry.alloc.dupe(Entry.SshListener, entry.ssh_listeners.items) catch null;
    if (dup_snapshot) |snapshot| {
        entry.listener_mutex.unlock();
        defer entry.alloc.free(snapshot);
        for (snapshot) |listener| listener.on_state(listener.ctx, state);
    } else {
        // Allocation failure: fall back to iterating under the lock.
        // A listener that re-enters the listener API from on_state
        // will deadlock here — better than dropping the broadcast,
        // which is the only other option.
        defer entry.listener_mutex.unlock();
        for (entry.ssh_listeners.items) |listener| listener.on_state(listener.ctx, state);
    }
}

/// Subscribe to ConnectionState transitions on this Entry. The
/// listener's `on_state` callback fires immediately with the most
/// recent broadcasted state (if any) so registrants never miss the
/// initial transition, then on every subsequent transition.
///
/// Both the initial replay and the regular fan-out run under
/// `listener_mutex`, so a listener registered concurrent with a
/// state change observes that change exactly once. Callbacks fire on
/// the SSH thread — embedders MUST hop to their own queue before
/// doing any blocking work.
///
/// Listeners are keyed by `listener.ctx`. Re-registering the same
/// ctx replaces the previous entry (so embedders can swap callbacks
/// without an unregister round-trip).
pub fn registerStateListener(entry: *Entry, listener: Entry.SshListener) !void {
    entry.listener_mutex.lock();
    defer entry.listener_mutex.unlock();
    for (entry.ssh_listeners.items) |*existing| {
        if (existing.ctx == listener.ctx) {
            existing.* = listener;
            // Replay the cached state under the lock so the new
            // callback sees the current state before any future
            // broadcast races past us.
            if (entry.last_state) |s| listener.on_state(listener.ctx, s);
            return;
        }
    }
    try entry.ssh_listeners.append(entry.alloc, listener);
    if (entry.last_state) |s| listener.on_state(listener.ctx, s);
}

/// Drop a previously-registered listener. Idempotent: unknown ctx is
/// a no-op. After this returns, the listener's `on_state` is
/// guaranteed not to fire again from any thread.
pub fn unregisterStateListener(entry: *Entry, ctx: *anyopaque) void {
    entry.listener_mutex.lock();
    defer entry.listener_mutex.unlock();
    for (entry.ssh_listeners.items, 0..) |existing, i| {
        if (existing.ctx == ctx) {
            _ = entry.ssh_listeners.swapRemove(i);
            return;
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

    // Close old channel under the per-Entry libssh2 mutex. The mux
    // transport's reader/writer threads (SshChannelStreamTransport) may
    // still be calling libssh2 on the SAME session — they are only torn
    // down later, when the surfaces are re-opened — so `ch.close()`
    // (libssh2_channel_close + libssh2_channel_free) must serialise with
    // them, otherwise the free races inside libssh2's internal lists and
    // crashes (same class as the close-time SEGV in
    // SshChannelStreamTransport.close()). Mirrors the close/open-under-
    // mutex pattern at SshChannelStreamTransport.zig:214-219 and
    // `tryOpenChannel` below, which lock this same `entry.libssh2_mutex`.
    if (entry.channel) |*ch| {
        entry.libssh2_mutex.lock();
        defer entry.libssh2_mutex.unlock();
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
            // Reopen the TERMINAL channel in `--stdio-attach` mode (the mode
            // the initial connect used), NOT the `--mux-attach` proxy opener
            // `tryOpenChannel` — see `tryReopenTerminalChannel`. Using the mux
            // opener here reopened the terminal channel in a mode that EOFs in
            // ~77ms, causing an infinite reconnect flicker once terminal+proxy
            // shared one Entry.
            if (tryReopenTerminalChannel(entry)) |new_channel| {
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
/// Sends one `surface_attach` Open per surface in each session (group) — NOT just
/// the first surface. Each surface re-enters the daemon's viewers list keyed by its
/// own target_id and receives its own snapshot, so every pane of a split group is
/// resynced. The shared group_id ties them to the same remote session.
fn reopenSurfaces(entry: *Entry) void {
    entry.surfaces_mutex.lock();
    defer entry.surfaces_mutex.unlock();

    var it = entry.sessions.iterator();
    while (it.next()) |kv| {
        const sess = kv.value_ptr.*;
        if (sess.surfaces.items.len == 0) continue;

        // Reset history_prepended for all surfaces so reconnect can prepend fresh
        for (sess.surfaces.items) |*surf| {
            surf.history_prepended = false;
        }

        // Re-attach EVERY surface in the group, each with its own surface_id,
        // target_id, label, and LIVE grid size. Without this, surfaces[1+] of a
        // split group never re-enter the daemon viewers list and get nothing
        // after reconnect.
        for (sess.surfaces.items) |s| {
            // Re-open at the surface's CURRENT grid size, not a hardcoded 24x80.
            // A stale 24x80 resizes the remote PTY on every reconnect, so a wider
            // TUI then redraws column-misaligned against an 80-col PTY and corrupts
            // output (compounding any frame-desync scramble). Read the live size
            // from the surface terminal under its renderer lock (the same lock
            // dispatchFrame takes); fall back to 24x80 only if unreadable.
            var attach_rows: u16 = 24;
            var attach_cols: u16 = 80;
            {
                s.io.renderer_state.mutex.lock();
                defer s.io.renderer_state.mutex.unlock();
                const t = s.io.renderer_state.terminal;
                if (t.rows > 0 and t.cols > 0) {
                    attach_rows = @intCast(t.rows);
                    attach_cols = @intCast(t.cols);
                }
            }

            const open_payload = (session.protocol.Open{
                .open_type = .surface_attach,
                .resize = .{ .rows = attach_rows, .cols = attach_cols, .width_px = 0, .height_px = 0 },
                .surface_id = s.surface_id,
                .group_id = sess.group_id,
                .max_scrollback = entry.scrollback_limit,
                .label = s.label orelse "reconnected",
            }).encode(entry.alloc) catch continue;
            defer entry.alloc.free(open_payload);
            sendFrame(&entry.channel.?, .open, s.target_id, open_payload) catch {
                log.warn("reconnect: failed to re-open surface target={d}", .{s.target_id});
                // Notify just this surface — the others are attached independently.
                _ = s.surface_mailbox.push(.{
                    .child_exited = .{ .exit_code = 1, .runtime_ms = 0 },
                }, .{ .forever = {} });
            };
        }
    }
}

/// Try to open a multiplexed channel, restarting the daemon if needed.
/// Copies remote_bin_path under surfaces_mutex to avoid racing with setupConnection.
/// Public so the C-API layer can open a dedicated mux channel from the SSH thread.
pub fn tryOpenChannel(entry: *Entry) ?ssh.Channel {
    const alloc = entry.alloc;

    // Copy remote_bin_path under mutex — setupConnection writes it from another thread.
    entry.surfaces_mutex.lock();
    const remote_bin_path = alloc.dupe(u8, entry.remote_bin_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(remote_bin_path);

    // tryOpenChannel can be called concurrently with `sshThreadMain`
    // on the same Entry (e.g. from `onStateListener` running on the
    // M1 SetupWorker's thread after broadcasting `.connected`). The
    // libssh2 calls inside `openClientMuxChannel` and
    // `ensureRemoteDaemon` MUST serialise with the SSH thread's calls
    // on the same session, otherwise concurrent `libssh2_channel_*`
    // and transport-level reads/writes corrupt internal lists (we hit
    // this as a SEGV inside `_libssh2_list_first` ← `_libssh2_packet_ask`
    // ← `_libssh2_channel_free` during the M6 smoke).
    entry.libssh2_mutex.lock();
    defer entry.libssh2_mutex.unlock();

    // Use `openClientMuxChannel` (--mux-attach) not `openMultiplexChannel`
    // (--stdio-attach). The latter is the terminal-frame demuxer which
    // silently drops `.channel_*` frames in its else => {} branch.
    // --mux-attach is a pure stdio↔daemon-socket pump that lets
    // ClientMux's channel_open / channel_data / etc. reach the main
    // daemon's channel_registry where browser_proxy + port_listener +
    // tcp_connect + tcp_accepted are registered.

    // First attempt
    if (session.client.openClientMuxChannel(alloc, &entry.ctx, remote_bin_path)) |ch| {
        return ch;
    } else |_| {}

    // Daemon might be dead — try starting without killing existing one first
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, false, null) catch return null;

    return session.client.openClientMuxChannel(alloc, &entry.ctx, remote_bin_path) catch null;
}

/// Reopen the Entry's TERMINAL transport channel after a drop, using the
/// SAME `--stdio-attach` mode the initial connect used (`openMultiplexChannel`
/// → the daemon `multiplex` terminal-frame loop), NOT the `--mux-attach`
/// proxy/control opener `tryOpenChannel` (`openClientMuxChannel` → runMuxMode).
///
/// `attemptReconnect` previously reopened `entry.channel` via `tryOpenChannel`.
/// Once the SSH pool unified the terminal transport and the C-API proxy onto
/// ONE shared Entry / one `entry.channel`, that silently reopened the terminal
/// channel in mux mode after the first drop. A mux-mode channel is not a
/// long-lived terminal session: it EOFs within ~77ms, `sshThreadMain` sees
/// `channel.eof()` and reconnects, reopens-in-mux-mode, EOFs again — an
/// infinite ~340ms connect↔reconnect flicker (every reconnect succeeds, so it
/// never escalates past attempt 1). Reopening in `--stdio-attach` keeps the
/// terminal channel a real terminal session so it stays up. The proxy/control
/// mux channel is reopened separately by `onStateListener` via `tryOpenChannel`.
pub fn tryReopenTerminalChannel(entry: *Entry) ?ssh.Channel {
    const alloc = entry.alloc;

    entry.surfaces_mutex.lock();
    const remote_bin_path = alloc.dupe(u8, entry.remote_bin_path) catch {
        entry.surfaces_mutex.unlock();
        return null;
    };
    entry.surfaces_mutex.unlock();
    defer alloc.free(remote_bin_path);

    // Serialise libssh2 calls with the SSH thread on the same session
    // (see the note in `tryOpenChannel`).
    entry.libssh2_mutex.lock();
    defer entry.libssh2_mutex.unlock();

    // First attempt: the terminal-frame `--stdio-attach` channel.
    if (session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path)) |ch| {
        return ch;
    } else |_| {}

    // Daemon might be dead — try starting without killing the existing one.
    session.client.ensureRemoteDaemon(alloc, &entry.ctx, remote_bin_path, false, null) catch return null;

    return session.client.openMultiplexChannel(alloc, &entry.ctx, remote_bin_path) catch null;
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
/// `pub` so the C-API setup worker can reuse the same backoff curve for
/// its relentless *initial*-connect retry loop (see ssh_capi.zig).
pub fn computeBackoff(entry: *const Entry, attempt: u32) u64 {
    const base: u64 = entry.reconnect_interval_ms;
    const cap: u64 = entry.reconnect_max_interval_ms;
    return switch (entry.reconnect_backoff) {
        .exponential => @min(base *| (@as(u64, 1) << @intCast(@min(attempt, 30))), cap),
        .linear => @min(base *| (@as(u64, attempt) + 1), cap),
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
