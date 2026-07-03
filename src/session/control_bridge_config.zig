//! Names for the generic remote "control bridge" — the reverse channel that
//! lets a control CLI running INSIDE a remote session reach the local app's
//! control socket (see `services/control_bridge.zig` for the transport and
//! `cli/control_send.zig` for the generic forwarder).
//!
//! These are intentionally generic (no embedder branding): ghostty exposes a
//! reverse-control socket and a generic mechanism for an embedder to install a
//! shim on the remote session PATH. The embedder (e.g. cmux) supplies the shim
//! itself at connect time; ghostty knows nothing about it.

// ---- Socket env vars injected into every remote shell -----------------------
// The daemon binds a per-session reverse socket and exports its path + auth
// token under these names; the generic `+control-send` forwarder reads them.
// Distinct from any embedder's *local* socket env (e.g. cmux's
// CMUX_SOCKET_PATH), which is a different socket the embedder owns.

/// Env var carrying the reverse-channel AF_UNIX socket path.
pub const env_socket_path: []const u8 = "GHOSTTY_CONTROL_SOCKET";

/// Env var carrying the per-daemon auth token the forwarder must present.
pub const env_socket_token: []const u8 = "GHOSTTY_CONTROL_TOKEN";

// ---- Embedder shim spec, delivered via the daemon launch environment --------
// The client prefixes the `--daemonize` command with these env vars (the
// daemon inherits them through fork). On startup the daemon, if a name + body
// are present, base64-decodes the body and installs it as an executable named
// `<name>` in its on-PATH remote bin dir. Default (vars unset): install nothing.
// Generic: any embedder may register an executable on the remote session PATH.

/// Env var naming the shim executable to install (e.g. "cmux").
pub const env_shim_name: []const u8 = "GHOSTTY_REMOTE_SHIM_NAME";

/// Env var carrying the shim's contents, base64-encoded.
pub const env_shim_body_b64: []const u8 = "GHOSTTY_REMOTE_SHIM_BODY_B64";

/// Env var carrying the shim's octal file mode (e.g. "755"). Optional;
/// defaults to 0o755 when unset or unparsable.
pub const env_shim_mode: []const u8 = "GHOSTTY_REMOTE_SHIM_MODE";
