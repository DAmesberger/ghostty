//! Client-side SSH connection setup.
//!
//! This file is a thin FACADE. The implementation was split into flat
//! sibling modules in this same directory to keep each concern focused,
//! while preserving every public symbol at its original `client.<name>`
//! import path so external importers (`session.zig`,
//! `apprt/embedded/ssh_capi.zig`, `termio/SshConnectionManager.zig`) are
//! unaffected:
//!
//!   * `connection.zig` — the auth/connect loop (`SshContext`,
//!     `ConnectResult`, `transport_keepalive_interval_s`, stdin password
//!     reads).
//!   * `provision.zig`  — remote ghostty + daemon provisioning
//!     (`ensureRemoteGhostty` / `ensureRemoteDaemon` + binary upload /
//!     download / hashing / update-confirmation gate) plus the generic
//!     remote-command helpers (`Capture`, `runRemoteCapture`,
//!     `buildRemoteCommand`).
//!   * `shim.zig`       — the control-bridge shim env prefix
//!     (`env_shim_*` handling).
//!   * `attach.zig`     — mux channel open + pipe/thread setup
//!     (`openMultiplexChannel`, `openClientMuxChannel`, `AttachConfig`,
//!     `attachRemoteSurface`).
//!   * `notify.zig`     — shared mailbox / broadcast state helpers.

pub const Error = error{
    RemoteCommandFailed,
    RemotePlatformUnsupported,
    RemoteUploadFailed,
    RemoteDownloadFailed,
    RemoteAuthRequired,
    RemoteCheckFailed,
};

// -- Auth / connect loop (connection.zig) --
pub const transport_keepalive_interval_s = @import("connection.zig").transport_keepalive_interval_s;
pub const ConnectResult = @import("connection.zig").ConnectResult;
pub const SshContext = @import("connection.zig").SshContext;

// -- Shared mailbox / broadcast helpers (notify.zig) --
pub const Mailbox = @import("notify.zig").Mailbox;

// -- Remote ghostty + daemon provisioning (provision.zig) --
pub const ProvisionResult = @import("provision.zig").ProvisionResult;
pub const UpdateDecision = @import("provision.zig").UpdateDecision;
pub const ensureRemoteGhostty = @import("provision.zig").ensureRemoteGhostty;
pub const ensureRemoteDaemon = @import("provision.zig").ensureRemoteDaemon;
pub const Capture = @import("provision.zig").Capture;
pub const runRemoteCapture = @import("provision.zig").runRemoteCapture;
pub const buildRemoteCommand = @import("provision.zig").buildRemoteCommand;

// -- Mux channel open + pipe/thread setup (attach.zig) --
pub const openMultiplexChannel = @import("attach.zig").openMultiplexChannel;
pub const openClientMuxChannel = @import("attach.zig").openClientMuxChannel;
pub const AttachConfig = @import("attach.zig").AttachConfig;
pub const attachRemoteSurface = @import("attach.zig").attachRemoteSurface;

test {
    // Keep the moved inline tests (and every sibling's compilation)
    // reachable from the test root now that this file no longer
    // contains them directly.
    _ = @import("connection.zig");
    _ = @import("notify.zig");
    _ = @import("provision.zig");
    _ = @import("shim.zig");
    _ = @import("attach.zig");
}
