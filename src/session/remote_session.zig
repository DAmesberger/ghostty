//! RemoteSession: the headless ghostty terminal for remote sessions.
//!
//! This file is a thin facade. Its contents were split into two siblings for
//! readability; it re-exports the public surface so existing
//! `@import("remote_session.zig")` call sites keep working unchanged:
//!
//!   - `remote_session_core.zig`  — the `RemoteSession` struct and its entire
//!     method surface (viewer roster, size negotiation, reader/flush thread,
//!     attachAndServe, scrollback streaming, client-frame dispatch, refcount
//!     lifecycle) plus the `Uuid` alias.
//!   - `remote_vt_serialize.zig`  — pure Terminal-viewport -> VT
//!     escape-sequence serialization (`serializeViewportAsVT`), reused by
//!     `persist.zig` and `daemon_core.zig`.
//!
//! Background (unchanged): the daemon owns a full Terminal instance that is the
//! source of truth for terminal state. PTY output is fed through
//! HeadlessStreamHandler to keep this Terminal up to date. Raw PTY bytes are
//! forwarded to the attached client as .data_out frames — the client's own VT
//! parser handles rendering independently. On reconnect, the daemon's Terminal
//! viewport is serialized as VT escape sequences and sent as a .data_out frame,
//! allowing the new client to rebuild the screen naturally via processOutput.

const remote_session_core = @import("remote_session_core.zig");
const remote_vt_serialize = @import("remote_vt_serialize.zig");

pub const RemoteSession = remote_session_core.RemoteSession;
pub const Uuid = remote_session_core.Uuid;
pub const serializeViewportAsVT = remote_vt_serialize.serializeViewportAsVT;

test {
    _ = @import("remote_session_core.zig");
    _ = @import("remote_vt_serialize.zig");
}
