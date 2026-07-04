//! Low-level socket / fd / logging primitives for the remote session daemon.
//! Split out of daemon.zig (facade re-mounts nothing from here; consumers alias
//! the individual helpers). Pure move — bodies are byte-identical to the
//! pre-split daemon.zig.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h"); // setenv / unsetenv (cmux execve self-handoff)
    @cInclude("sys/ioctl.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/un.h");
    @cInclude("sys/wait.h");
    @cInclude("termios.h");
    @cInclude("unistd.h");
});

const log = std.log.scoped(.ssh_session);

/// Write a diagnostic line to stderr (which is daemon.log in daemon mode).
/// Works in release builds unlike std.log.info.
pub fn daemonLog(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = std.posix.write(2, msg) catch {};
}

// ============================================================================
// Low-level helpers
// ============================================================================
/// Verify that the connecting peer has the same UID as us.
/// Uses platform-specific mechanisms: SO_PEERCRED on Linux,
/// getpeereid() on macOS/BSD.
pub fn verifyPeerUid(fd: posix.fd_t) !void {
    const our_uid = c.getuid();

    if (comptime builtin.os.tag == .linux) {
        // Use SO_PEERCRED on Linux
        var cred: extern struct {
            pid: c_int,
            uid: c_uint,
            gid: c_uint,
        } = undefined;
        var len: c.socklen_t = @sizeOf(@TypeOf(cred));
        if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_PEERCRED, @ptrCast(&cred), &len) != 0) {
            return error.PeerAuthFailed;
        }
        if (cred.uid != our_uid) {
            log.warn("peer UID {d} != our UID {d}, rejecting", .{ cred.uid, our_uid });
            return error.PeerAuthFailed;
        }
    } else if (comptime builtin.os.tag.isDarwin()) {
        // Use getpeereid() on macOS
        var peer_uid: c.uid_t = undefined;
        var peer_gid: c.gid_t = undefined;
        if (c.getpeereid(fd, &peer_uid, &peer_gid) != 0) {
            return error.PeerAuthFailed;
        }
        if (peer_uid != our_uid) {
            log.warn("peer UID {d} != our UID {d}, rejecting", .{ peer_uid, our_uid });
            return error.PeerAuthFailed;
        }
    }
    // On unsupported platforms, skip verification (Windows is excluded via comptime)
}

pub fn canConnect(path: []const u8) !bool {
    const fd = connectUnixSocket(path) catch return false;
    closeFd(fd);
    return true;
}

/// Check whether the socket file on disk still belongs to this daemon.
/// Returns false if the file is gone or points to a different inode.
///
/// Compares the filesystem inode of the path against the inode we
/// captured at bind time. The listener fd's `st_ino` is a kernel
/// anonymous-socket inode and CANNOT be compared against the path's
/// filesystem inode — they live in different namespaces and never
/// match. Using fstat(listener) here used to make the daemon shut
/// itself down on every 60s poll-timeout, manifesting as remote
/// terminals vanishing after exactly 1 minute of idle.
pub fn isSocketOurs(bound_inode: u64, path: []const u8) bool {
    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= path_buf.len) return false;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    var file_st: c.struct_stat = undefined;
    if (c.stat(&path_buf, &file_st) != 0) return false;
    return @as(u64, @intCast(file_st.st_ino)) == bound_inode;
}

pub fn bindUnixSocket(path: []const u8) !posix.fd_t {
    std.fs.cwd().deleteFile(path) catch {};

    const sock_flags = if (@hasDecl(c, "SOCK_CLOEXEC"))
        c.SOCK_STREAM | c.SOCK_CLOEXEC
    else
        c.SOCK_STREAM;
    const fd = c.socket(c.AF_UNIX, sock_flags, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer closeFd(fd);

    // On platforms without SOCK_CLOEXEC (e.g. macOS), set close-on-exec via fcntl.
    if (!@hasDecl(c, "SOCK_CLOEXEC")) {
        if (c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC) < 0) return error.SocketCreateFailed;
    }

    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.NameTooLong;
    @memcpy(addr.sun_path[0..path.len], path);

    if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) {
        return error.BindFailed;
    }

    // Restrict socket permissions to owner only (prevents local hijacking)
    if (c.fchmod(fd, 0o700) != 0) {
        return error.PermissionDenied;
    }

    if (c.listen(fd, 64) != 0) return error.ListenFailed;
    return fd;
}

pub fn acceptUnixSocket(listener: posix.fd_t) !posix.fd_t {
    const fd = c.accept(listener, null, null);
    if (fd < 0) return error.AcceptFailed;
    // Prevent child processes from inheriting client connection fds.
    _ = c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC);
    return fd;
}

pub fn connectUnixSocket(path: []const u8) !posix.fd_t {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer closeFd(fd);

    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.NameTooLong;
    @memcpy(addr.sun_path[0..path.len], path);

    if (c.connect(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) return error.ConnectFailed;
    return fd;
}

/// Read exactly `buf.len` bytes from fd using raw posix.read.
pub fn readAllRaw(fd: posix.fd_t, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = posix.read(fd, buf[offset..]) catch |err| return err;
        if (n == 0) return error.UnexpectedEOF;
        offset += n;
    }
}

fn writeAllFd(fd: posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try posix.write(fd, bytes[offset..]);
        offset += written;
    }
}

pub fn closeFd(fd: posix.fd_t) void {
    posix.close(fd);
}
