const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const control_bridge_config = @import("control_bridge_config.zig");

/// Build an inline env-var prefix for the remote daemon launch command that
/// carries an embedder-supplied control shim, sourced from THIS process's
/// environment (the embedder, e.g. cmux, sets `GHOSTTY_REMOTE_SHIM_*` before
/// opening connections). The forked remote daemon inherits these vars and
/// installs the shim on the session PATH (see `daemon.installEmbedderShim`).
/// Returns an empty string when no shim is configured, so non-embedder callers
/// (and the GTK/CLI paths) are unaffected. Caller owns the returned slice.
pub fn buildShimEnvPrefix(alloc: Allocator) ![]u8 {
    const name = posix.getenv(control_bridge_config.env_shim_name) orelse
        return alloc.dupe(u8, "");
    const body = posix.getenv(control_bridge_config.env_shim_body_b64) orelse
        return alloc.dupe(u8, "");
    if (name.len == 0 or body.len == 0) return alloc.dupe(u8, "");
    const mode = posix.getenv(control_bridge_config.env_shim_mode) orelse "755";

    // Values are single-quoted for the remote shell. The body is base64 (safe
    // chars only); guard the embedder-controlled name/mode against a quote that
    // would break the inline quoting (the daemon also validates the name).
    if (std.mem.indexOfScalar(u8, name, '\'') != null or
        std.mem.indexOfScalar(u8, mode, '\'') != null)
    {
        return alloc.dupe(u8, "");
    }

    return std.fmt.allocPrint(
        alloc,
        "{s}='{s}' {s}='{s}' {s}='{s}' ",
        .{
            control_bridge_config.env_shim_name,     name,
            control_bridge_config.env_shim_body_b64, body,
            control_bridge_config.env_shim_mode,     mode,
        },
    );
}
