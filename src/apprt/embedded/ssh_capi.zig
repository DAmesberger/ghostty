//! C-API glue for the libghostty SSH connection + channel multiplexing
//! surface declared in `include/ghostty.h` (see "SSH connection +
//! channel multiplexing API" section). Phase 6B.1 lays down the
//! handle layout, the extern C entry points, and the buffer/callback
//! plumbing.
//!
//! Currently functional:
//!
//!   * `ghostty_ssh_open` acquires an `SshConnectionManager.Entry`
//!     via the embedder-provided `ghostty_app_t`, registers a
//!     `SshListener` on the Entry, and translates each broadcast
//!     `ConnectionState` into a C `ghostty_ssh_state_t` to fire the
//!     embedder's `on_state`.
//!   * `ghostty_ssh_close` / `ghostty_ssh_free` unregister the
//!     listener, release the Entry, and cascade an
//!     `on_close(reason=daemon_shutdown)` to every live channel
//!     handle rooted on the connection.
//!
//! Channel transport status:
//!
//!   * The C-API ↔ `channel_mux.ClientMux` bridge IS wired —
//!     `ghostty_ssh_open_channel` / `ghostty_channel_write` /
//!     `_eof` / `_close` all route through a real ClientMux, and
//!     the five `ChannelHandle.mux*` bridge callbacks forward mux
//!     events to the embedder's `ghostty_channel_callbacks_t`.
//!   * Production ClientMux wiring is now live. When the SSH
//!     connection reaches `.connected`, `onStateListener` invokes
//!     `wireMuxTransport` which spins up a
//!     `SshChannelStreamTransport` against the daemon channel held
//!     on the Entry and attaches a fresh `ClientMux` to the
//!     SshHandle. `ghostty_ssh_open_channel`, `ghostty_channel_*`,
//!     and inbound-channel callbacks all route through this mux.
//!     Unit tests still inject a socketpair-backed ClientMux
//!     directly via `setClientMuxForTest` to exercise the bridge
//!     without standing up real libssh2.
//!
//! Still gated on a follow-up:
//!
//!   * `ghostty_ssh_submit_host_key_decision` is a no-op today —
//!     the underlying libssh2 host-key check (src/session/ssh.zig
//!     verifyHostKey) auto-accepts unknown keys via TOFU and never
//!     fires `on_host_key`. The C entry point is present for
//!     forward compatibility; wiring lands alongside a redesign of
//!     verifyHostKey to surface a prompt.
//!
//! Threading & ownership rules (mirrors the contract documented in
//! include/ghostty.h):
//!
//!   * Every exported function is non-blocking and may be called from
//!     any thread.
//!   * Callbacks fire on libghostty-owned worker threads. The handle
//!     holds the callback set behind a mutex so submit_* calls from
//!     inside a callback are safe.
//!   * ONE EXCEPTION: ghostty_ssh_open fires on_state SYNCHRONOUSLY
//!     on the calling thread for the initial CONNECTING transition
//!     AND for any FAILED transitions emitted before this function
//!     returns (e.g. when Entry acquisition or jump-spec duplication
//!     fails). From the moment ghostty_ssh_open returns successfully,
//!     all subsequent on_state fires on libghostty worker threads.
//!     Embedders that hop to a serial queue from on_state should be
//!     prepared to see the very first one (and possibly a FAILED
//!     transition, depending on the config) happen on the open
//!     caller's thread.
//!   * Buffers passed in are copied; buffers handed to callbacks are
//!     borrowed for the callback duration.

// =========================================================================
// Facade. This file was decomposed into flat sibling modules in the same
// directory to keep every moved line's relative @import paths identical:
//
//   * ssh_capi_types.zig    — shared C-ABI extern structs + enums.
//   * ssh_capi_handles.zig  — SshHandle / ChannelHandle runtime state +
//                             state-translation / manager-resolution helpers.
//   * ssh_capi_exports.zig  — every `export fn` C-ABI entry point, the
//                             setup worker, and the inline test suite.
//
// This facade re-exports every public symbol the original file exposed so
// external importers (`apprt/embedded.zig` uses `ssh_capi.State` and
// `ssh_capi.translateConnectionState`) keep resolving, and force-imports
// the exports sibling at comptime so its `export fn` C symbols land in the
// production libghostty build.
// =========================================================================

const types = @import("ssh_capi_types.zig");
const handles = @import("ssh_capi_handles.zig");

// --- Shared C-ABI types (mirror include/ghostty.h) ---
pub const StateKind = types.StateKind;
pub const ProvisionSource = types.ProvisionSource;
pub const DisconnectReason = types.DisconnectReason;
pub const FailReason = types.FailReason;
pub const ChannelService = types.ChannelService;
pub const ChannelCloseReason = types.ChannelCloseReason;
pub const HostKeyPolicy = types.HostKeyPolicy;
pub const StatePassword = types.StatePassword;
pub const StateUpdateConfirmation = types.StateUpdateConfirmation;
pub const StateUpload = types.StateUpload;
pub const StateReconnect = types.StateReconnect;
pub const StateDisconnect = types.StateDisconnect;
pub const StateFail = types.StateFail;
pub const State = types.State;
pub const HostKey = types.HostKey;
pub const Config = types.Config;
pub const SshCallbacks = types.SshCallbacks;
pub const ChannelCallbacks = types.ChannelCallbacks;
pub const SessionStatus = types.SessionStatus;
pub const SessionEntry = types.SessionEntry;

// --- Runtime handles + state translation ---
pub const SshHandle = handles.SshHandle;
pub const ChannelHandle = handles.ChannelHandle;
pub const translateConnectionState = handles.translateConnectionState;

// Force the C-ABI export fns into the production compilation graph. An
// `export fn` only emits its C symbol when its file is pulled into the
// build; a test-only reference is NOT enough. `apprt/embedded.zig`
// comptime-references this facade, which evaluates this block and pulls
// the export fns into the libghostty surface.
comptime {
    _ = @import("ssh_capi_exports.zig");
}

// Keep every sibling's inline tests reachable from the build's test root.
test {
    _ = @import("ssh_capi_types.zig");
    _ = @import("ssh_capi_handles.zig");
    _ = @import("ssh_capi_exports.zig");
}
