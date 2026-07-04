//! file_transfer filesystem allow-root sandbox.
//!
//! Resolve a transfer path (symlink- and non-existent-ancestor aware)
//! and reject anything outside the allowed roots (`$HOME` + `/tmp`).
//! Pure std/posix utility with no service-domain coupling.
//!
//! Split out of `file_transfer.zig`, which re-exports the public
//! `ensureAllowedPath` / `ensureAllowedPathWithRoots` entry points.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const max_path_len = @import("file_transfer.zig").max_path_len;

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
// Tests
// =========================================================================

const testing = std.testing;

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
