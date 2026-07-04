//! Remote session daemon — thin facade over the flat `daemon_*` siblings.
//!
//! This file was decomposed from a ~3.3k-line monolith into cohesive siblings
//! in this same directory (so every moved line's relative `@import` paths stay
//! byte-identical). The facade keeps the public entry points (`Options`, `run`)
//! and re-exports every public type the monolith exposed so external importers
//! (`session.daemon.X`, `@import("daemon.zig").SessionGroup`, ...) keep
//! resolving unchanged.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const session = @import("../session.zig");
const HeadlessHandler = @import("../termio/HeadlessStreamHandler.zig").HeadlessHandler;

const daemon_core = @import("daemon_core.zig");
const daemon_cli = @import("daemon_cli.zig");
const daemon_multiplex = @import("daemon_multiplex.zig");
const daemon_group = @import("daemon_group.zig");

// Public data types re-exported for external importers (remote_session.zig).
pub const SessionGroup = daemon_group.SessionGroup;
pub const ReexecControl = daemon_group.ReexecControl;

// Dispatch targets for `run`, aliased from the siblings that own them.
const killDaemon = daemon_cli.killDaemon;
const queryReexec = daemon_cli.queryReexec;
const requestReexec = daemon_cli.requestReexec;
const listSessions = daemon_cli.listSessions;
const killSession = daemon_cli.killSession;
const renameSession = daemon_cli.renameSession;
const detachOthersSession = daemon_cli.detachOthersSession;
const daemonize = daemon_core.daemonize;
const daemonMain = daemon_core.daemonMain;
const multiplex = daemon_multiplex.multiplex;
const muxAttach = daemon_multiplex.muxAttach;

pub const Options = struct {
    daemonize: bool = false,
    daemon: bool = false,
    @"kill-daemon": bool = false,
    list: bool = false,
    @"protocol-version": bool = false,
    @"stdio-attach": bool = false,
    @"mux-attach": bool = false,
    kill: ?[]const u8 = null,
    rename: ?[]const u8 = null,
    @"detach-others": ?[]const u8 = null,
    session: ?[]const u8 = null,
    new: bool = false,
    label: ?[]const u8 = null,
    /// cmux Phase 2 (GATED): probe the running daemon for execve-handoff
    /// capability. Prints `REEXEC 1` iff it can, else `REEXEC 0` (incl. EOF
    /// against a pre-feature daemon). Always exits 0.
    @"query-reexec": bool = false,
    /// cmux Phase 2 (GATED): ask the running daemon to execve-replace itself
    /// with the binary at this absolute path, preserving live shells. Exits 0
    /// on a clean handoff (EOF without a preceding `.err`), non-zero otherwise
    /// so the caller falls back to `--kill-daemon` + `--daemonize`.
    reexec: ?[]const u8 = null,
};

pub fn run(
    alloc: Allocator,
    opts: Options,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !u8 {
    if (comptime builtin.os.tag == .windows) {
        try stderr.writeAll("remote sessions are only implemented on POSIX platforms.\n");
        return 1;
    }

    if (opts.@"protocol-version") {
        try stdout.print("GHOSTTY_SESSION_PROTOCOL {d}\n", .{session.protocol.protocol_version});
        try stdout.flush();
        return 0;
    }

    if (opts.@"kill-daemon") {
        try killDaemon(alloc);
        return 0;
    }

    if (opts.@"query-reexec") {
        try queryReexec(alloc, stdout);
        return 0;
    }

    if (opts.reexec) |newbin| {
        return try requestReexec(alloc, newbin, stdout);
    }

    if (opts.daemonize) {
        try daemonize(alloc);
        return 0;
    }

    if (opts.daemon) {
        try daemonMain(alloc);
        return 0;
    }

    if (opts.list) {
        try listSessions(alloc, stdout);
        return 0;
    }

    if (opts.kill) |id| {
        try killSession(alloc, id, stdout);
        return 0;
    }

    if (opts.rename) |id| {
        const new_label = opts.label orelse {
            try stderr.writeAll("Error: --label is required for rename\n");
            try stderr.flush();
            return 1;
        };
        try renameSession(alloc, id, new_label, stdout);
        return 0;
    }

    if (opts.@"detach-others") |id| {
        try detachOthersSession(alloc, id, stdout);
        return 0;
    }

    if (opts.@"stdio-attach") {
        return try multiplex(alloc, stderr);
    }

    if (opts.@"mux-attach") {
        return try muxAttach(alloc, stderr);
    }

    try stderr.writeAll("missing helper mode\n");
    return 1;
}

test {
    _ = @import("daemon_core.zig");
    _ = @import("daemon_cli.zig");
    _ = @import("daemon_multiplex.zig");
    _ = @import("daemon_group.zig");
    _ = @import("daemon_net.zig");
}
