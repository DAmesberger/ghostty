//! CLI client commands that talk to the running daemon over its unix socket
//! (kill-daemon, reexec probes, list/kill/rename/detach). Split out of
//! daemon.zig; `run` dispatches here. Pure move — bodies are byte-identical.
const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const session = @import("../session.zig");
const log = std.log.scoped(.ssh_session);

const daemon_net = @import("daemon_net.zig");
const connectUnixSocket = daemon_net.connectUnixSocket;
const closeFd = daemon_net.closeFd;
const readAllRaw = daemon_net.readAllRaw;
const sendFrameFd = session.shared.sendFrameFd;
const shiftBuffer = session.shared.shiftBuffer;

/// Kill any running daemon by connecting to its socket and signaling it.
/// Removes the socket file so daemonize will start a fresh one.
pub fn killDaemon(alloc: Allocator) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);

    // Try to connect to trigger graceful shutdown
    const fd = connectUnixSocket(socket_path) catch {
        // Can't connect — daemon not running, just clean up socket
        std.fs.cwd().deleteFile(socket_path) catch {};
        return;
    };
    closeFd(fd);

    // Remove socket file so accept() fails in the old daemon
    std.fs.cwd().deleteFile(socket_path) catch {};

    // Give the old daemon a moment to notice
    std.Thread.sleep(200 * std.time.ns_per_ms);
}

// ============================================================================
// cmux execve self-handoff (Phase 2, GATED) — CLI client probes
//
// IMPORTANT: both helpers run inside `<remote_bin> +ssh-session ...`. After a
// runtime update the client already `mv -f`'d the NEW binary over remote_bin,
// so THIS process is the new image — but that is irrelevant: these are runtime
// PROBES of the *already-running* (old) daemon over its unix socket, not a
// self-test of the client binary. Do not "fix" this by re-resolving the path.
// ============================================================================
/// `--query-reexec`: ask the running daemon whether it can execve-handoff.
/// Prints exactly `REEXEC 1` on a yes, `REEXEC 0` on anything else (no daemon,
/// EOF from a pre-feature daemon that dropped the unknown frame, short read,
/// or an explicit no). Always succeeds (exit 0); the client parses the line.
pub fn queryReexec(alloc: Allocator, stdout: *std.Io.Writer) !void {
    const answer: u8 = blk: {
        const socket_path = session.shared.socketPath(alloc) catch break :blk 0;
        defer alloc.free(socket_path);
        const fd = connectUnixSocket(socket_path) catch break :blk 0;
        defer closeFd(fd);
        sendFrameFd(fd, .reexec_query, 0, "") catch break :blk 0;
        var hbuf: [session.protocol.header_size]u8 = undefined;
        readAllRaw(fd, &hbuf) catch break :blk 0;
        const hdr = session.protocol.Header.parseFromBuf(&hbuf) catch break :blk 0;
        if (hdr.kind != .reexec_caps or hdr.len < 1 or hdr.len > 64) break :blk 0;
        var pbuf: [64]u8 = undefined;
        readAllRaw(fd, pbuf[0..hdr.len]) catch break :blk 0;
        break :blk if (pbuf[0] == 1) @as(u8, 1) else 0;
    };
    try stdout.print("REEXEC {d}\n", .{answer});
    try stdout.flush();
}

/// `--reexec <abs path>`: ask the running daemon to execve-replace itself with
/// the binary at `newbin`, preserving live shells. Reads reply frames to EOF: a
/// preceding `.err` frame means the daemon ABORTED (exit 1 → caller falls back);
/// a plain EOF (the daemon's connection fd closing on a successful execve) means
/// the handoff was launched (exit 0). No daemon / connect failure → exit 1.
pub fn requestReexec(alloc: Allocator, newbin: []const u8, stdout: *std.Io.Writer) !u8 {
    _ = stdout;
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = connectUnixSocket(socket_path) catch return 1;
    defer closeFd(fd);

    sendFrameFd(fd, .reexec, 0, newbin) catch return 1;

    var saw_err = false;
    while (true) {
        var hbuf: [session.protocol.header_size]u8 = undefined;
        readAllRaw(fd, &hbuf) catch break; // EOF/err → handoff launched (or done)
        const hdr = session.protocol.Header.parseFromBuf(&hbuf) catch break;
        if (hdr.len > session.protocol.max_payload) break;
        if (hdr.len > 0) {
            const pbuf = alloc.alloc(u8, hdr.len) catch break;
            defer alloc.free(pbuf);
            readAllRaw(fd, pbuf) catch break;
        }
        if (hdr.kind == .err) saw_err = true;
    }
    return if (saw_err) 1 else 0;
}

/// List sessions via the daemon's binary frame protocol.
pub fn listSessions(
    alloc: Allocator,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Send list_request frame
    sendFrameFd(fd, .list_request, 0, "") catch return;

    // Read response frames
    var buf: [8192]u8 = undefined;
    var read_buf = std.ArrayList(u8).empty;
    defer read_buf.deinit(alloc);

    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        try read_buf.appendSlice(alloc, buf[0..n]);

        // Process complete frames
        while (read_buf.items.len >= session.protocol.header_size) {
            const dk = read_buf.items[0];
            const dplen = std.mem.readInt(u32, read_buf.items[4..8], .little);
            const dtotal = session.protocol.header_size + dplen;
            if (read_buf.items.len < dtotal) break;

            const dkind = std.meta.intToEnum(session.protocol.Kind, dk) catch {
                shiftBuffer(&read_buf, dtotal);
                continue;
            };
            const dpayload = read_buf.items[session.protocol.header_size..dtotal];

            if (dkind == .list_response) {
                // Parse structured binary list response
                const entries = session.protocol.ListResponse.parse(alloc, dpayload) catch {
                    shiftBuffer(&read_buf, dtotal);
                    continue;
                };
                defer alloc.free(entries);

                for (entries) |entry| {
                    const gid_hex = session.shared.formatUuid(entry.group_id);
                    const status_str: []const u8 = switch (entry.status) {
                        .dead => "dead",
                        .attached => "attached",
                        .detached => "detached",
                    };
                    writer.print("{s}|{s}|{d} surfaces ({d} alive)|{d}|{s}\n", .{
                        &gid_hex,
                        entry.label,
                        entry.surface_count,
                        entry.alive_count,
                        entry.created_at,
                        status_str,
                    }) catch {};
                }
            }

            shiftBuffer(&read_buf, dtotal);
        }
    }

    try writer.flush();
}

/// Kill a session via the daemon's binary frame protocol.
pub fn killSession(
    alloc: Allocator,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    // Parse id as UUID for the Close struct
    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        // Fall back: try as label — find via list first
        // For simplicity, just send the raw bytes (daemon will handle it)
        const close_data = session.protocol.Close{ .mode = .session, .id = session.shared.zero_uuid };
        const close_payload = close_data.encode(alloc) catch return;
        defer alloc.free(close_payload);
        sendFrameFd(fd, .close, 0, close_payload) catch return;
        try writer.writeAll("OK\n");
        try writer.flush();
        return;
    };
    const close_data = session.protocol.Close{ .mode = .session, .id = uuid };
    const close_payload = close_data.encode(alloc) catch return;
    defer alloc.free(close_payload);
    sendFrameFd(fd, .close, 0, close_payload) catch return;
    try writer.writeAll("OK\n");
    try writer.flush();
}

/// Rename a session via the daemon's binary frame protocol.
pub fn renameSession(
    alloc: Allocator,
    id: []const u8,
    new_label: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        log.warn("invalid session id for rename: {s}", .{id});
        return;
    };

    const rename_data = session.protocol.Rename{
        .scope = .group,
        .id = uuid,
        .label = new_label,
    };
    const rename_payload = try rename_data.encode(alloc);
    defer alloc.free(rename_payload);
    try sendFrameFd(fd, .rename, 0, rename_payload);
    try writer.writeAll("OK\n");
    try writer.flush();
}

/// Detach all other viewers from a session by sending a kick_viewer frame
/// with zero UUID (meaning "kick everyone except the sender").
pub fn detachOthersSession(
    alloc: Allocator,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const socket_path = try session.shared.socketPath(alloc);
    defer alloc.free(socket_path);
    const fd = try connectUnixSocket(socket_path);
    defer closeFd(fd);

    const uuid = session.shared.parseUuid(id) catch
        session.shared.parseUuidDashed(id) catch {
        log.warn("invalid session id for detach-others: {s}", .{id});
        return;
    };

    // The kick_viewer payload is: 16-byte target viewer UUID.
    // Zero UUID means "kick all viewers except the sender".
    // We also need to tell the daemon which session group to act on,
    // so we prepend the group UUID followed by the zero target UUID.
    // However, the kick_viewer frame is handled per-session in
    // processClientFrames, so we send it with the group UUID as target
    // for the multiplexer to route, and zero UUID as the payload.
    var payload: [session.protocol.uuid_size]u8 = session.shared.zero_uuid;

    // We need to open the session first to get routed to it.
    // Send an open frame to attach temporarily, then send kick_viewer.
    const open_data = session.protocol.Open{
        .open_type = .session_attach,
        .group_id = uuid,
        .resize = .{ .rows = 24, .cols = 80, .width_px = 0, .height_px = 0 },
    };
    const open_payload = try open_data.encode(alloc);
    defer alloc.free(open_payload);
    try sendFrameFd(fd, .open, 0, open_payload);

    // Wait for the opened response.
    var hdr_buf: [session.protocol.header_size]u8 = undefined;
    const file: std.fs.File = .{ .handle = fd };
    _ = file.readAll(&hdr_buf) catch return;
    const hdr = session.protocol.Header.parseFromBuf(&hdr_buf) catch return;

    // Skip the opened payload.
    if (hdr.len > 0) {
        var skip_buf: [512]u8 = undefined;
        var remaining = hdr.len;
        while (remaining > 0) {
            const to_read = @min(remaining, skip_buf.len);
            const n = file.read(skip_buf[0..to_read]) catch break;
            if (n == 0) break;
            remaining -= @intCast(n);
        }
    }

    if (hdr.kind != .opened) {
        log.warn("detach-others: expected opened response, got {}", .{hdr.kind});
        return;
    }

    // Now we're attached to the session. Send kick_viewer with zero UUID.
    try sendFrameFd(fd, .kick_viewer, 0, &payload);
    try writer.writeAll("OK\n");
    try writer.flush();
}
