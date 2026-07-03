const protocol = @import("protocol.zig");
const SshConnectionManager = @import("../termio/SshConnectionManager.zig");

pub const Mailbox = @import("../apprt.zig").surface.Mailbox;

/// Push a state through BOTH the per-surface mailbox (if non-null)
/// AND the Entry's broadcast fan-out (which reaches every other
/// surface registered on the Entry + every libghostty C API
/// listener). During first-surface setup the Entry has zero
/// registered surfaces, so `broadcastConnectionState` does NOT
/// duplicate the `mailbox` push to the caller's surface; the
/// listener-side fan-out is the only consumer that observes the
/// transition twice would be problematic for, and listeners only
/// see this state via the broadcast path (not the mailbox).
pub fn pushAttachState(
    mailbox: ?*Mailbox,
    entry: *SshConnectionManager.Entry,
    state: protocol.ConnectionState,
) void {
    pushConnectionState(mailbox, state);
    SshConnectionManager.broadcastConnectionState(entry, state);
}

pub const UploadProgressCtx = struct {
    mbox: ?*Mailbox,
    total: u64,
    src: protocol.ConnectionState.ProvisionSource,
    /// When non-null, upload progress is ALSO broadcast to the Entry's
    /// state listeners (so the app's provisioning overlay — which observes
    /// the listener path, not the per-surface mailbox — can render it).
    entry: ?*SshConnectionManager.Entry = null,
    /// Throttle pointer for the broadcast: holds the last whole-percent
    /// value broadcast. A multi-MB upload fires `onProgress` per chunk
    /// (hundreds/thousands of times); broadcasting each one would re-render
    /// the overlay on every chunk. We broadcast only on a whole-percent
    /// change, capping the listener traffic at ~100 updates per upload.
    last_pct: ?*u8 = null,

    pub fn onProgress(ctx: @This(), bytes_sent: u64) void {
        const state: protocol.ConnectionState = .{ .uploading = .{
            .bytes_sent = bytes_sent,
            .total_bytes = ctx.total,
            .source = ctx.src,
        } };
        pushConnectionState(ctx.mbox, state);
        if (ctx.entry) |e| {
            const pct: u8 = if (ctx.total == 0)
                100
            else
                @intCast(@min(@as(u64, 100), bytes_sent * 100 / ctx.total));
            if (ctx.last_pct) |lp| {
                if (pct == lp.*) return;
                lp.* = pct;
            }
            SshConnectionManager.broadcastConnectionState(e, state);
        }
    }
};

fn pushConnectionState(mailbox: ?*Mailbox, state: protocol.ConnectionState) void {
    if (mailbox) |m| {
        _ = m.push(.{ .connection_state = state }, .{ .forever = {} });
    }
}

/// Push a provisioning state (`.downloading` / `.uploading`) to the
/// per-surface mailbox AND, when an Entry is available, broadcast it to
/// the Entry's state listeners. The app's provisioning overlay observes
/// the listener path (see `pushAttachState`'s docstring), so without the
/// broadcast a daemon upload/download is invisible to the overlay — the
/// workspace just shows a silent `connecting` hang for the upload's
/// duration. Mirrors `pushAttachState` but kept separate so callers that
/// have no Entry (the GTK picker / CLI provisioning paths) pass `null`.
pub fn pushProvisionState(
    mailbox: ?*Mailbox,
    entry: ?*SshConnectionManager.Entry,
    state: protocol.ConnectionState,
) void {
    pushConnectionState(mailbox, state);
    if (entry) |e| SshConnectionManager.broadcastConnectionState(e, state);
}
