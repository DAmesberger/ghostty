const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Action = @import("ghostty.zig").Action;
/// Generic names for the reverse control bridge — the socket env vars this
/// forwarder reads. Shared with the daemon's env injection (see
/// `session/daemon.zig` `createSurface`) so the two halves can never drift.
const bridge_config = @import("../session/control_bridge_config.zig");

/// The maximum number of response bytes we will read back from the local app
/// over the reverse channel. Responses are a single newline-terminated line
/// (`OK`, `OK: ...`, `PONG`, or `ERROR: <message>`), so this is generously sized.
const max_response_bytes: usize = 4096;

/// Options struct for the `+control-send` action. This action does its own
/// manual argument handling in `run` (it forwards a free-form line), so this
/// struct mostly exists to satisfy the CLI action plumbing and the `-h`/`--help`
/// convention.
pub const Options = struct {
    _arena: ?ArenaAllocator = null,

    pub fn deinit(self: *Options) void {
        if (self._arena) |arena| arena.deinit();
        self.* = undefined;
    }

    /// Enables `-h` and `--help` to work.
    pub fn help(self: Options) !void {
        _ = self;
        return Action.help_error;
    }
};

/// `+control-send` is the remote half of ghostty's reverse control bridge. It
/// runs ON the remote host (inside the `ghostty-daemon` binary) and forwards a
/// single command line to the local app over the per-session AF_UNIX socket the
/// daemon injects as `GHOSTTY_CONTROL_SOCKET`.
///
/// It is generic transport: it does NOT interpret the command. An embedder
/// installs a shim on the remote PATH that assembles its own command line and
/// execs `ghostty-daemon +control-send <line>`; the local app decides what the
/// line means.
///
/// Wire protocol (newline-delimited) on `GHOSTTY_CONTROL_SOCKET`:
///
///   1. Authenticate first: `auth <GHOSTTY_CONTROL_TOKEN>` — the daemon replies
///      `OK: authenticated` or an `ERROR: ...` line and closes.
///   2. Send one command line, then read the single-line response.
///
/// All arguments after the `+control-send` token are joined with single spaces
/// into one line (newlines stripped). Requires `GHOSTTY_CONTROL_SOCKET` and
/// `GHOSTTY_CONTROL_TOKEN` in the environment (the daemon sets both for every
/// remote shell). Exits non-zero with a clear stderr message if they are
/// missing, the socket is unreachable, authentication fails, or the app
/// responds with an `ERROR:` line.
pub fn run(alloc: Allocator) !u8 {
    // Manual argv handling: skip argv0 and any leading `+action` token, then
    // collect the remaining args as the line to forward.
    var it = try std.process.argsWithAllocator(alloc);
    defer it.deinit();

    var rest: std.ArrayList([]const u8) = .empty;
    defer {
        for (rest.items) |item| alloc.free(item);
        rest.deinit(alloc);
    }

    _ = it.next(); // skip argv0
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return Action.help_error;
        }
        // Skip the leading `+action` token (e.g. `+control-send`).
        if (arg.len > 0 and arg[0] == '+') continue;
        try rest.append(alloc, try alloc.dupe(u8, arg));
    }

    const stderr = std.fs.File.stderr();

    const command = buildLine(alloc, rest.items) catch |err| switch (err) {
        error.NothingToSend => {
            writeAllIgnore(stderr, "control: nothing to send\n");
            return 1;
        },
        else => return err,
    };
    defer alloc.free(command);

    // Read the connection parameters the daemon injected into the shell env.
    // The var names come from `control_bridge_config` — the same source the
    // daemon uses to inject them — so the two halves can never drift apart.
    var ebuf: [256]u8 = undefined;
    const sock_path = std.posix.getenv(bridge_config.env_socket_path) orelse {
        writeAllIgnore(stderr, std.fmt.bufPrint(
            &ebuf,
            "control: {s} is not set; not running inside a managed remote session\n",
            .{bridge_config.env_socket_path},
        ) catch "control: socket path env var is not set\n");
        return 1;
    };
    if (sock_path.len == 0) {
        writeAllIgnore(stderr, std.fmt.bufPrint(
            &ebuf,
            "control: {s} is empty\n",
            .{bridge_config.env_socket_path},
        ) catch "control: socket path env var is empty\n");
        return 1;
    }
    const token = std.posix.getenv(bridge_config.env_socket_token) orelse {
        writeAllIgnore(stderr, std.fmt.bufPrint(
            &ebuf,
            "control: {s} is not set; cannot authenticate\n",
            .{bridge_config.env_socket_token},
        ) catch "control: token env var is not set\n");
        return 1;
    };

    return sendCommand(alloc, sock_path, token, command, stderr);
}

/// Join the collected arguments into a single command line, replacing any
/// embedded newlines/carriage returns with spaces so the wire line is never
/// split. Caller owns the returned slice.
fn buildLine(alloc: Allocator, items: []const []const u8) ![]u8 {
    if (items.len == 0) return error.NothingToSend;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    for (items, 0..) |item, i| {
        if (i > 0) try buf.append(alloc, ' ');
        for (item) |ch| {
            try buf.append(alloc, if (ch == '\n' or ch == '\r') ' ' else ch);
        }
    }
    return buf.toOwnedSlice(alloc);
}

/// Connect to the reverse-channel socket, authenticate, send the command, and
/// relay the response. Returns 0 on success, non-zero on any failure.
fn sendCommand(
    alloc: Allocator,
    sock_path: []const u8,
    token: []const u8,
    command: []const u8,
    stderr: std.fs.File,
) !u8 {
    var stream = std.net.connectUnixSocket(sock_path) catch |err| {
        var ebuf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &ebuf,
            "control: cannot connect to control socket {s}: {s}\n",
            .{ sock_path, @errorName(err) },
        ) catch "control: cannot connect to control socket\n";
        writeAllIgnore(stderr, msg);
        return 1;
    };
    defer stream.close();

    // 1. Authenticate first.
    const auth_line = try std.fmt.allocPrint(alloc, "auth {s}\n", .{token});
    defer alloc.free(auth_line);
    stream.writeAll(auth_line) catch {
        writeAllIgnore(stderr, "control: failed to send auth to control socket\n");
        return 1;
    };

    const auth_resp = readLine(alloc, stream) catch {
        writeAllIgnore(stderr, "control: failed to read auth response\n");
        return 1;
    };
    defer alloc.free(auth_resp);
    if (!std.mem.startsWith(u8, auth_resp, "OK")) {
        var ebuf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &ebuf,
            "control: authentication failed: {s}\n",
            .{auth_resp},
        ) catch "control: authentication failed\n";
        writeAllIgnore(stderr, msg);
        return 1;
    }

    // 2. Send the command line and read the single-line response.
    const cmd_line = try std.fmt.allocPrint(alloc, "{s}\n", .{command});
    defer alloc.free(cmd_line);
    stream.writeAll(cmd_line) catch {
        writeAllIgnore(stderr, "control: failed to send command\n");
        return 1;
    };

    const resp = readLine(alloc, stream) catch {
        writeAllIgnore(stderr, "control: failed to read response\n");
        return 1;
    };
    defer alloc.free(resp);

    if (std.mem.startsWith(u8, resp, "ERROR")) {
        var ebuf: [max_response_bytes + 64]u8 = undefined;
        const msg = std.fmt.bufPrint(&ebuf, "control: {s}\n", .{resp}) catch "control: error\n";
        writeAllIgnore(stderr, msg);
        return 1;
    }

    // Success: echo the response line to stdout.
    if (resp.len > 0) {
        const stdout = std.fs.File.stdout();
        writeAllIgnore(stdout, resp);
        writeAllIgnore(stdout, "\n");
    }
    return 0;
}

/// Read a single newline-terminated line from the stream. Strips the trailing
/// `\n` (and any `\r`). Caller owns the returned slice. Returns whatever was
/// read at EOF if no newline is seen first.
fn readLine(alloc: Allocator, stream: std.net.Stream) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    var chunk: [256]u8 = undefined;
    line: while (buf.items.len < max_response_bytes) {
        const n = try stream.read(&chunk);
        if (n == 0) break; // EOF
        for (chunk[0..n]) |ch| {
            if (ch == '\n') break :line;
            try buf.append(alloc, ch);
        }
    }
    // Drop a trailing CR (from CRLF) before transferring ownership.
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\r') {
        _ = buf.pop();
    }
    return buf.toOwnedSlice(alloc);
}

/// Write all bytes to a file, ignoring errors (used for diagnostics where a
/// failed write should not mask the original error path).
fn writeAllIgnore(file: std.fs.File, bytes: []const u8) void {
    file.writeAll(bytes) catch {};
}
