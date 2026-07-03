//! Mux/session wire protocol — facade.
//!
//! This file was decomposed into flat sibling modules (see below) to keep
//! each cohesive area small. It stays as a thin facade so every external
//! importer that does `@import("session/protocol.zig").Foo` (or
//! `session.protocol.Foo`) keeps resolving unchanged — ALL public symbols
//! are re-exported here.
//!
//! Siblings:
//!   frame.zig             — frame header, kinds/flags, frame I/O + constants
//!   connection_state.zig  — keepalive constants + ConnectionState union
//!   session_frames.zig    — open/close/rename/opened lifecycle frames
//!   resize_scrollback.zig — Resize + ScrollbackResponse
//!   viewer_frames.zig     — multi-viewer + session_meta + list frames
//!   capabilities.zig      — Capabilities negotiation frame
//!   channel_frames.zig    — generic multiplexed channel frames + constants

const frame = @import("frame.zig");
const connection_state = @import("connection_state.zig");
const session_frames = @import("session_frames.zig");
const resize_scrollback = @import("resize_scrollback.zig");
const viewer_frames = @import("viewer_frames.zig");
const capabilities = @import("capabilities.zig");
const channel_frames = @import("channel_frames.zig");

// =========================================================================
// frame.zig — frame layer + constants
// =========================================================================

pub const max_payload = frame.max_payload;
pub const protocol_version = frame.protocol_version;
pub const header_size = frame.header_size;
pub const Flags = frame.Flags;
pub const Kind = frame.Kind;
pub const Header = frame.Header;
pub const writeFrame = frame.writeFrame;
pub const writeFrameFlags = frame.writeFrameFlags;
pub const readHeader = frame.readHeader;
pub const readPayloadAlloc = frame.readPayloadAlloc;

// =========================================================================
// connection_state.zig — connection state + keepalive
// =========================================================================

pub const keepalive_interval_ns = connection_state.keepalive_interval_ns;
pub const keepalive_stale_ns = connection_state.keepalive_stale_ns;
pub const keepalive_server_timeout_ns = connection_state.keepalive_server_timeout_ns;
pub const ConnectionState = connection_state.ConnectionState;

// =========================================================================
// Shared UUID helpers (re-exported for importers that use protocol.Uuid)
// =========================================================================

pub const Uuid = @import("shared.zig").Uuid;
pub const zero_uuid = @import("shared.zig").zero_uuid;
pub const uuid_size = 16;

// =========================================================================
// session_frames.zig — session/surface lifecycle frames
// =========================================================================

pub const OpenType = session_frames.OpenType;
pub const Open = session_frames.Open;
pub const CloseMode = session_frames.CloseMode;
pub const Close = session_frames.Close;
pub const RenameScope = session_frames.RenameScope;
pub const Rename = session_frames.Rename;
pub const Opened = session_frames.Opened;

// =========================================================================
// resize_scrollback.zig — resize + scrollback frames
// =========================================================================

pub const Resize = resize_scrollback.Resize;
pub const ScrollbackResponse = resize_scrollback.ScrollbackResponse;

// =========================================================================
// viewer_frames.zig — multi-viewer + session meta + list frames
// =========================================================================

pub const SizeMode = viewer_frames.SizeMode;
pub const ViewerStateReason = viewer_frames.ViewerStateReason;
pub const ViewerEntry = viewer_frames.ViewerEntry;
pub const ViewerState = viewer_frames.ViewerState;
pub const SizeModeChange = viewer_frames.SizeModeChange;
pub const SessionMeta = viewer_frames.SessionMeta;
pub const ListStatus = viewer_frames.ListStatus;
pub const ListEntry = viewer_frames.ListEntry;
pub const ListResponse = viewer_frames.ListResponse;

// =========================================================================
// capabilities.zig — capability negotiation frame
// =========================================================================

pub const CapabilityService = capabilities.CapabilityService;
pub const CompressionAlgo = capabilities.CompressionAlgo;
pub const Capabilities = capabilities.Capabilities;

// =========================================================================
// channel_frames.zig — generic multiplexed channel frames + constants
// =========================================================================

pub const default_channel_window_units = channel_frames.default_channel_window_units;
pub const max_channel_window_units = channel_frames.max_channel_window_units;
pub const invalid_channel_id = channel_frames.invalid_channel_id;
pub const channel_id_daemon_bit = channel_frames.channel_id_daemon_bit;
pub const ChannelService = channel_frames.ChannelService;
pub const ChannelOpenFlags = channel_frames.ChannelOpenFlags;
pub const ChannelOpenStatus = channel_frames.ChannelOpenStatus;
pub const ChannelCloseReason = channel_frames.ChannelCloseReason;
pub const ChannelOpen = channel_frames.ChannelOpen;
pub const ChannelOpened = channel_frames.ChannelOpened;
pub const ChannelData = channel_frames.ChannelData;
pub const ChannelWindow = channel_frames.ChannelWindow;
pub const ChannelEof = channel_frames.ChannelEof;
pub const ChannelClose = channel_frames.ChannelClose;
pub const ChannelControl = channel_frames.ChannelControl;

// =========================================================================
// Tests — pull in every sibling so their inline `test` blocks still run
// (Zig only runs tests in files reachable from the build's test root).
// =========================================================================

test {
    _ = frame;
    _ = connection_state;
    _ = session_frames;
    _ = resize_scrollback;
    _ = viewer_frames;
    _ = capabilities;
    _ = channel_frames;
}
