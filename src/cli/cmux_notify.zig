const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Action = @import("ghostty.zig").Action;

/// The maximum number of response bytes we will read back from the local
/// app over the reverse channel. Responses are a single newline-terminated
/// line (`OK`, `OK: ...`, `PONG`, or `ERROR: <message>`), so this is
/// generously sized.
const max_response_bytes: usize = 4096;

/// Options struct for the `+cmux-notify` action. This action does its own
/// manual argument handling in `run` (it forwards a free-form subcommand
/// such as `notify`, `notify_target`, or `report_*` to the local app), so
/// this struct mostly exists to satisfy the CLI action plumbing and the
/// `-h`/`--help` convention.
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

/// The `cmux-notify` command is the remote half of cmux's reverse control
/// channel. It runs ON the remote host (inside the `ghostty-daemon` binary)
/// and delivers a notification — or any allowed `report_*` metadata update —
/// back to the local cmux app over the per-session AF_UNIX socket the daemon
/// injects as `CMUX_SOCKET_PATH`.
///
/// It is normally invoked indirectly: the daemon installs a tiny `cmux` shim
/// on the remote's PATH whose body is `exec <daemon> +cmux-notify "$@"`, so a
/// coding agent's `cmux notify ...` call is transparently routed here.
///
/// Wire protocol (V1, newline-delimited) on `CMUX_SOCKET_PATH`:
///
///   1. Authenticate first: `auth <CMUX_SOCKET_PASSWORD>` — the daemon
///      replies `OK: authenticated` or an `ERROR: ...` line and closes.
///   2. Send one command line, then read the single-line response.
///
/// Subcommands (the first positional argument, defaulting to `notify`):
///
///   * `notify` — deliver to the current/selected surface. Builds
///     `notify <title>|<subtitle>|<body>` from `--title`/`--subtitle`/`--body`
///     (each defaulting to empty; an empty title becomes "Notification").
///
///   * `notify_target` / `report_*` — forwarded verbatim as a single
///     space-delimited line, so `cmux report_pr 12 https://... --state=open`
///     reaches the same dispatcher the local socket uses.
///
/// Requires `CMUX_SOCKET_PATH` and `CMUX_SOCKET_PASSWORD` in the environment
/// (the daemon sets both for every remote shell). Exits non-zero with a
/// clear stderr message if they are missing, the socket is unreachable,
/// authentication fails, or the app responds with an `ERROR:` line.
pub fn run(alloc: Allocator) !u8 {
    // Manual argv handling: skip argv0 and any leading `+cmux-notify` token,
    // then collect the remaining args. We do NOT use `args.parse` here
    // because this action forwards a free-form subcommand plus a mix of
    // positional and `--flag=value` arguments.
    var it = try std.process.argsWithAllocator(alloc);
    defer it.deinit();

    var rest: std.ArrayList([]const u8) = .empty;
    defer {
        for (rest.items) |item| alloc.free(item);
        rest.deinit(alloc);
    }

    _ = it.next(); // skip argv0
    while (it.next()) |arg| {
        // Allow `-h`/`--help` anywhere.
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return Action.help_error;
        }
        // Skip the `+cmux-notify` (or any `+action`) token.
        if (arg.len > 0 and arg[0] == '+') continue;
        try rest.append(alloc, try alloc.dupe(u8, arg));
    }

    const stderr = std.fs.File.stderr();

    // The command line we will send to the local app, built from `rest`.
    const command = buildCommand(alloc, rest.items) catch |err| switch (err) {
        error.NoSubcommand => {
            writeAllIgnore(stderr, "cmux-notify: nothing to send (expected e.g. `notify --body=...`)\n");
            return 1;
        },
        else => return err,
    };
    defer alloc.free(command);

    // Read the connection parameters the daemon injected into the shell env.
    const sock_path = std.posix.getenv("CMUX_SOCKET_PATH") orelse {
        writeAllIgnore(stderr, "cmux-notify: CMUX_SOCKET_PATH is not set; not running inside a cmux remote session\n");
        return 1;
    };
    if (sock_path.len == 0) {
        writeAllIgnore(stderr, "cmux-notify: CMUX_SOCKET_PATH is empty\n");
        return 1;
    }
    const token = std.posix.getenv("CMUX_SOCKET_PASSWORD") orelse {
        writeAllIgnore(stderr, "cmux-notify: CMUX_SOCKET_PASSWORD is not set; cannot authenticate to cmux\n");
        return 1;
    };

    return sendCommand(alloc, sock_path, token, command, stderr);
}

/// Build the V1 command line from the collected arguments. The first
/// positional argument selects the subcommand; everything else is either
/// parsed (for `notify`) or forwarded verbatim (for `notify_target` /
/// `report_*`). Caller owns the returned slice.
fn buildCommand(alloc: Allocator, items: []const []const u8) ![]u8 {
    if (items.len == 0) return error.NoSubcommand;

    const subcommand = items[0];
    const args_rest = items[1..];

    // `notify` (the common path): build `notify <title>|<subtitle>|<body>`.
    if (std.mem.eql(u8, subcommand, "notify")) {
        const title = optionValue(args_rest, "--title") orelse "Notification";
        const subtitle = optionValue(args_rest, "--subtitle") orelse "";
        const body = optionValue(args_rest, "--body") orelse "";

        // If an explicit target surface is given as UUIDs, route to
        // `notify_target` so the local app delivers to that exact surface.
        const workspace = optionValue(args_rest, "--workspace");
        const surface = optionValue(args_rest, "--surface");

        const t = try sanitizeField(alloc, title);
        defer alloc.free(t);
        const s = try sanitizeField(alloc, subtitle);
        defer alloc.free(s);
        const b = try sanitizeField(alloc, body);
        defer alloc.free(b);

        if (workspace) |w| {
            if (surface) |sfc| {
                return std.fmt.allocPrint(
                    alloc,
                    "notify_target {s} {s} {s}|{s}|{s}",
                    .{ w, sfc, t, s, b },
                );
            }
        }

        return std.fmt.allocPrint(alloc, "notify {s}|{s}|{s}", .{ t, s, b });
    }

    // Everything else (`notify_target`, `report_*`, etc.): forward the whole
    // line verbatim. The local app's allowlist gates which subcommands are
    // actually honored over the reverse channel; we collapse interior
    // whitespace into single spaces and strip newlines so it stays one line.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    for (items, 0..) |item, i| {
        if (i > 0) try buf.append(alloc, ' ');
        for (item) |ch| {
            // Newlines (and carriage returns) would split the wire line;
            // replace them with spaces to keep a single command line.
            try buf.append(alloc, if (ch == '\n' or ch == '\r') ' ' else ch);
        }
    }
    return buf.toOwnedSlice(alloc);
}

/// Look up the value of a `--name=value` or `--name value` style flag in the
/// argument list. Returns null if absent. The returned slice borrows from
/// `items`.
fn optionValue(items: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        const arg = items[i];
        if (std.mem.startsWith(u8, arg, name)) {
            // `--name=value`
            if (arg.len > name.len and arg[name.len] == '=') {
                return arg[name.len + 1 ..];
            }
            // `--name value` (exact match, value in the next arg)
            if (arg.len == name.len and i + 1 < items.len) {
                return items[i + 1];
            }
        }
    }
    return null;
}

/// Collapse a notification field to a single line and replace the pipe
/// delimiter with U+00A6 (BROKEN BAR, `¦`) so a user-supplied `|` never
/// corrupts the `title|subtitle|body` framing. Mirrors the local CLI's
/// `sanitizeNotificationField`. Caller owns the returned slice.
fn sanitizeField(alloc: Allocator, field: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    for (field) |ch| {
        switch (ch) {
            '\n', '\r' => try buf.append(alloc, ' '),
            '|' => try buf.appendSlice(alloc, "\u{00A6}"),
            else => try buf.append(alloc, ch),
        }
    }
    return buf.toOwnedSlice(alloc);
}

/// Connect to the reverse-channel socket, authenticate, send the command,
/// and relay the response. Returns 0 on success, non-zero on any failure.
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
            "cmux-notify: cannot connect to cmux socket {s}: {s}\n",
            .{ sock_path, @errorName(err) },
        ) catch "cmux-notify: cannot connect to cmux socket\n";
        writeAllIgnore(stderr, msg);
        return 1;
    };
    defer stream.close();

    // 1. Authenticate first.
    const auth_line = try std.fmt.allocPrint(alloc, "auth {s}\n", .{token});
    defer alloc.free(auth_line);
    stream.writeAll(auth_line) catch {
        writeAllIgnore(stderr, "cmux-notify: failed to send auth to cmux socket\n");
        return 1;
    };

    const auth_resp = readLine(alloc, stream) catch {
        writeAllIgnore(stderr, "cmux-notify: failed to read auth response from cmux\n");
        return 1;
    };
    defer alloc.free(auth_resp);
    if (!std.mem.startsWith(u8, auth_resp, "OK")) {
        var ebuf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &ebuf,
            "cmux-notify: authentication failed: {s}\n",
            .{auth_resp},
        ) catch "cmux-notify: authentication failed\n";
        writeAllIgnore(stderr, msg);
        return 1;
    }

    // 2. Send the command line and read the single-line response.
    const cmd_line = try std.fmt.allocPrint(alloc, "{s}\n", .{command});
    defer alloc.free(cmd_line);
    stream.writeAll(cmd_line) catch {
        writeAllIgnore(stderr, "cmux-notify: failed to send command to cmux\n");
        return 1;
    };

    const resp = readLine(alloc, stream) catch {
        writeAllIgnore(stderr, "cmux-notify: failed to read response from cmux\n");
        return 1;
    };
    defer alloc.free(resp);

    if (std.mem.startsWith(u8, resp, "ERROR")) {
        var ebuf: [max_response_bytes + 64]u8 = undefined;
        const msg = std.fmt.bufPrint(&ebuf, "cmux-notify: {s}\n", .{resp}) catch "cmux-notify: error\n";
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

/// Read a single newline-terminated line from the stream. Strips the
/// trailing `\n` (and any `\r`). Caller owns the returned slice. Returns
/// whatever was read at EOF if no newline is seen first.
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
    // Drop a trailing CR (from CRLF) before transferring ownership so the
    // caller frees exactly the allocation we hand back.
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
