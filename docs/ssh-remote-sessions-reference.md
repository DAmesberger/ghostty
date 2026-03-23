# SSH Remote Sessions Reference

Technical reference for Ghostty's SSH remote sessions feature. For a
user-oriented guide, see [ssh-remote-sessions.md](ssh-remote-sessions.md).

---

## Configuration Options

All options are set in the Ghostty config file or via `--option=value` CLI
flags.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ssh-target` | `?string` | `null` | SSH destination. Format: `user@host` or `user@host:port`. When set, the surface connects to the remote host via SSH instead of running a local command. Multiple tabs/splits to the same target share one underlying SSH connection. |
| `ssh-jump` | `?string` | `null` | SSH jump host (ProxyJump). Format: `user@host` or `user@host:port`. Used to tunnel through an intermediate host to reach the target. |
| `ssh-session` | `?string` | `null` | Session name or UUID to attach to. If a session with this name/UUID exists, Ghostty reattaches; otherwise a new named session is created (create-or-attach semantics). Session IDs are shown by `ghostty +session-list`. |
| `ssh-reconnect-attempts` | `u32` | `5` | Maximum automatic reconnect attempts after an SSH disconnect. Once exhausted, the overlay shows Reconnect/Exit buttons for manual retry. Set to `0` to disable auto-reconnect entirely. Available since 1.3.0. |
| `ssh-reconnect-backoff` | `enum` | `exponential` | Backoff strategy for automatic reconnection. Values: `exponential` (`min(interval * 2^attempt, 30000)`), `linear` (`min(interval * attempt, 30000)`), `constant` (fixed interval). Available since 1.3.0. |
| `ssh-reconnect-interval` | `u32` | `1000` | Base interval in milliseconds between reconnect attempts. Interpretation depends on `ssh-reconnect-backoff`. Available since 1.3.0. |
| `_ssh-group-id` | `?string` | `null` | **Internal.** Group UUID inherited from a parent surface for splits. Set automatically when creating split surfaces from an SSH remote session. Excluded from user-facing config parsing. |
| `_ssh-surface-id` | `?string` | `null` | **Internal.** Surface UUID for layout restore. When reconnecting, each surface needs a specific UUID to reattach to the correct daemon-side PTY. Excluded from user-facing config parsing. |

### Example

```
ssh-target = user@dev-server:22
ssh-jump = user@bastion
ssh-session = my-project
ssh-reconnect-attempts = 10
ssh-reconnect-backoff = exponential
ssh-reconnect-interval = 2000
```

---

## Keybinding Actions

These actions can be bound in the Ghostty config via `keybind = <key>=<action>`.

| Action | Description |
|--------|-------------|
| `ssh_create_session` | Open the SSH connection picker dialog. Lists hosts parsed from `~/.ssh/config`. Selecting a host opens an SSH remote session. You can also type an arbitrary `user@host` target in the search field and press Enter. Accepts an optional mode: `new_window` (default) or `new_tab`. |
| `ssh_session_attach` | Open the SSH connection picker, then show a list of available sessions on the selected host. Selecting a session attaches to that remote session. Accepts an optional mode: `new_window` (default) or `new_tab`. |
| `ssh_session_detach` | Detach the current remote session without killing it. The remote shells continue running; the session can be reattached later from the same or a different machine. Only effective when the surface is an SSH remote session. |
| `ssh_session_reconnect` | Manually trigger reconnection of the current remote session after a transport loss. Use when the session is disconnected but the remote daemon is still alive. |

### Example

```
keybind = ctrl+shift+o=ssh_create_session
keybind = ctrl+shift+a=ssh_session_attach
keybind = ctrl+shift+alt+o=ssh_create_session:new_tab
keybind = ctrl+shift+alt+a=ssh_session_attach:new_tab
keybind = ctrl+shift+d=ssh_session_detach
keybind = ctrl+shift+r=ssh_session_reconnect
```

---

## CLI Commands

### `+session-list`

List Ghostty-managed remote sessions on an SSH target.

```
ghostty +session-list --ssh=user@host [--jump=user@bastion]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--ssh` | Yes | SSH destination whose sessions to list. |
| `--jump` | No | SSH jump host (ProxyJump). |

Output shows session groups with their surfaces:

```
a1b2c3d4e5f6...  my-project  2 surfaces  attached
  11223344...    my-project   alive  attached
  55667788...    my-project   alive  attached
```

### `+session-kill`

Terminate a Ghostty-managed remote session.

```
ghostty +session-kill --ssh=user@host --session=<id> [--jump=user@bastion]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--ssh` | Yes | SSH destination that owns the session. |
| `--session` | Yes | Session identifier to terminate (from `+session-list`). |
| `--jump` | No | SSH jump host (ProxyJump). |

### `+ssh-session` (remote helper)

The `+ssh-session` subcommand is the remote helper binary invoked on the SSH
target. It is not typically run by the user directly. The client uploads a
copy of the Ghostty binary to the remote host and invokes it with one of the
following modes.

| Flag | Description |
|------|-------------|
| `--daemon` | Run as the session daemon (foreground). Manages session groups and PTYs. Listens on a Unix domain socket. |
| `--daemonize` | Fork into the background and exec `--daemon`. Used by the client to start the daemon on the remote. |
| `--list` | Print all active sessions to stdout (group UUIDs, labels, surface counts). |
| `--kill=<id>` | Kill a session by group UUID or label. |
| `--stdio-attach` | Run the multiplexer: connect to the daemon socket and bridge stdin/stdout to the binary protocol. This is the mode used over the SSH channel. |
| `--protocol-version` | Print `GHOSTTY_SESSION_PROTOCOL <version>` and exit. The client uses this to decide whether the remote helper needs to be re-uploaded. |
| `--session=<id>` | Session ID for attach operations (used with `--stdio-attach`). |
| `--label=<name>` | Session label for new session creation. |
| `--new` | Force creation of a new session (used with `--stdio-attach`). |
| `--kill-daemon` | Connect to the daemon socket and signal graceful shutdown, then remove the socket file. |

Remote helper install paths:

- Linux/FreeBSD: `~/.local/state/ghostty/bin/ghostty`
- macOS: `~/Library/Application Support/com.ghostty/bin/ghostty`

Daemon state directory: `$XDG_STATE_HOME/ghostty/remote-session/` (typically
`~/.local/state/ghostty/remote-session/`), containing:

- `daemon.sock` -- Unix domain socket
- `sessions/` -- Per-session state
- `registry` -- Session registry

---

## GTK UI Elements

### SshConnectionOverlay

GObject class: `GhosttySshConnectionOverlay` (subclass of `AdwBin`).

Displays a modal dialog over the current window listing SSH hosts parsed
from `~/.ssh/config`. Includes a search/filter field. The user can select
a host from the list or type an arbitrary `user@host` target and press Enter.

Signals:

| Signal | Parameters | Description |
|--------|-----------|-------------|
| `host-connect` | `target: string` | Emitted when the user selects or enters an SSH host. |

The overlay also handles connection state display during the SSH handshake:
connecting, uploading, setup, password prompts, reconnecting progress,
stale/disconnected warnings, and Reconnect/Exit buttons.

### SshSessionPicker

GObject class: `GhosttySshSessionPicker` (subclass of `AdwBin`).

Displays a modal dialog listing detached remote sessions on a given SSH
target. Uses a three-state stack: loading, list, and error views.

Signals:

| Signal | Parameters | Description |
|--------|-----------|-------------|
| `session-selected` | `target: string, session_id: string` | Emitted when the user selects a session to attach to. |

Public API:

- `setSshTarget(target)` -- Set the SSH host to query.
- `addSession(id, label, detail, status)` -- Add a session entry row.
- `setLoaded()` -- Switch from loading spinner to list view.
- `setError(message)` -- Switch to error view with the given message.

---

## Connection States

The `ConnectionState` union (defined in `src/session/protocol.zig`) represents
the state of an SSH connection as reported to surfaces for overlay display.

| State | Payload | Description |
|-------|---------|-------------|
| `connecting` | (none) | Initial SSH connection in progress. |
| `uploading` | `{ bytes_sent: u64, total_bytes: u64 }` | Helper binary is being uploaded to the remote. |
| `setup` | (none) | SSH connection established; session being opened on the daemon. |
| `connected` | (none) | Fully connected and forwarding data. Overlay is dismissed. |
| `reconnecting` | `{ attempt: u32, max_attempts: u32, elapsed_ns: i128, next_retry_ns: i128 }` | Automatic reconnection in progress after a transport loss. |
| `stale` | (none) | No keepalive received within the stale window (45 s). Connection may be dead. |
| `failed` | `FailReason` | Connection failed permanently. Reasons: `unknown`, `auth_failed`, `timeout`, `helper_failed`. |
| `disconnected` | `{ attempts_made: u32, reason: DisconnectReason }` | Reconnection exhausted or cancelled. Reasons: `exhausted`, `cancelled`, `disabled`. |
| `password_required` | `{ is_jump: bool, auth_state: ?*anyopaque }` | Interactive password authentication needed. `is_jump` indicates whether the prompt is for the jump host or the target. |

---

## Architecture Overview

### Connection Pooling

`SshConnectionManager` (in `src/termio/SshConnectionManager.zig`) is a
shared connection pool keyed by `(ssh_target, jump)`. Multiple surfaces
(tabs and splits) connecting to the same host share:

- One `Entry` in the pool.
- One SSH connection (libssh2 session).
- One SSH channel to the remote helper/multiplexer process.
- One dedicated SSH I/O thread.

The pool key is `"ssh_target"` or `"ssh_target|jump"` if a jump host is
configured. Connections are reference-counted; when the last surface
releases its reference, the SSH thread is shut down and the entry is removed.

Maximum surfaces per connection: **64** (`max_surfaces`).

### Multiplexing via Target IDs

Each surface is assigned an ephemeral 16-bit `target_id` (starting at 1,
wrapping at overflow, skipping 0). Target IDs are scoped to a single SSH
connection and are not stable across reconnects.

Every protocol frame carries a `target_id` in its header so the SSH thread
can route incoming frames to the correct surface and the remote multiplexer
can route them to the correct daemon-side session.

### SSH Thread Model

Each connection entry has a dedicated thread (`ssh-io`) that exclusively
owns all libssh2 calls (libssh2 is not thread-safe). Communication between
surfaces and the SSH thread uses:

| Mechanism | Direction | Purpose |
|-----------|-----------|---------|
| Write queue (`write_queue`) | Surface -> SSH thread | Outbound frames (stdin, resize, session_open, etc.). Thread-safe via `write_queue_mu`. |
| Write pipe (`write_pipe`) | Surface -> SSH thread | Wakes the SSH thread when new writes are enqueued. |
| `processOutput()` | SSH thread -> Surface | Inbound frames dispatched directly to the surface's termio. |
| Quit pipe (`quit_pipe`) | Manager -> SSH thread | Signals the thread to shut down. |
| Reconnect pipe (`reconnect_pipe`) | GTK thread -> SSH thread | Signals manual reconnect or cancel from the UI. |

The SSH thread polls three file descriptors: the SSH socket, the quit pipe,
and the write pipe. It drains reads in a tight non-blocking loop, processes
complete frames from a buffer, and flushes the write queue.

### Keepalive Mechanism

Both client and remote helper exchange `keepalive` frames at regular
intervals. Constants (from `src/session/protocol.zig`):

| Constant | Value | Description |
|----------|-------|-------------|
| `keepalive_interval_ns` | 15 s | How often each side sends a keepalive frame. |
| `keepalive_stale_ns` | 45 s | Client marks connection stale if no keepalive received within this window. |
| `keepalive_server_timeout_ns` | 60 s | Server (daemon) closes connection if no keepalive received within this window. |

Stale detection only activates after the first keepalive is received from
the remote, ensuring backward compatibility with older helpers that do not
support keepalive.

### Reconnection

When the connection is lost (stale detection or read error), the SSH thread
enters a reconnect loop:

1. Notify all surfaces with `ConnectionState.reconnecting`.
2. Wait according to the configured backoff strategy.
3. Re-establish the SSH connection.
4. Re-upload the helper if the protocol version changed.
5. Restart the daemon if the binary was re-uploaded.
6. Open a new multiplexer channel.
7. For each registered surface, send `session_open(mode=attach)` or `surface_open(mode=attach)` to reattach.
8. The daemon replays `layout_restore` and `state_full` snapshots.

If `ssh-reconnect-attempts` is exhausted, surfaces receive
`ConnectionState.disconnected` with reason `exhausted`. The user can
trigger a manual reconnect via the `ssh_session_reconnect` action or the
overlay's Reconnect button.

---

## Protocol Frame Format

The session wire format uses a binary frame protocol (protocol version 6).
All multi-byte integers are little-endian.

### Header Layout (8 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `kind` | Frame type (see Kind enum below). |
| 1 | 1 | `reserved` | Reserved, always 0. |
| 2 | 2 | `target_id` | `u16 LE`. Multiplexer routing key (0 = broadcast/control). |
| 4 | 4 | `payload_len` | `u32 LE`. Length of the payload following the header. |

Maximum payload size: **128 KiB** (`128 * 1024` bytes).

### Kind Enum

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 1 | `stdin` | client -> remote | Keyboard/terminal input. |
| 2 | `stdout` | remote -> client | Raw PTY output. |
| 3 | `resize` | client -> remote | Terminal size change (8-byte payload: rows u16, cols u16, width_px u16, height_px u16). |
| 4 | `detach` | client -> remote | Detach without killing the session. |
| 5 | `info` | remote -> client | Informational message. |
| 6 | `err` | remote -> client | Error message. |
| 7 | `eof` | remote -> client | Session or surface ended. |
| 8 | `session_open` | client -> remote | Create or attach to a session group. |
| 9 | `session_opened` | remote -> client | Group UUID confirmation after open. |
| 10 | `session_close` | client -> remote | Close/kill a session group. |
| 11 | `keepalive` | bidirectional | Connection health check (empty payload). |
| 12 | `state_full` | remote -> client | Full VT state snapshot for reconnect. |
| 15 | `session_list_request` | client -> remote | Request list of active sessions. |
| 16 | `session_list_entry` | remote -> client | One entry in session list response. |
| 19 | `layout_update` | client -> remote | Store layout blob on the daemon (for later restore). |
| 20 | `layout_restore` | remote -> client | Replay stored layout blob on reconnect. |
| 21 | `surface_open` | client -> remote | Add a surface to an existing session group. |
| 22 | `surface_close` | client -> remote | Remove a surface from a group. |
| 23 | `session_rename` | client -> remote | Rename a session group's label. |
| 24 | `surface_rename` | client -> remote | Rename a surface's label. |

### Key Payload Formats

**`session_open` payload:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | `Resize` (rows u16, cols u16, width_px u16, height_px u16, all LE) |
| 8 | 1 | `OpenMode` (0 = new, 1 = attach) |
| 9 | 16 | `surface_id` (UUID, raw bytes) |
| 25 | 16 | `group_id` (UUID, raw bytes) |
| 41 | N | `label` (remaining bytes; UTF-8 session name) |

**`surface_open` payload** (41 bytes fixed):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | `Resize` |
| 8 | 1 | `OpenMode` (0 = new, 1 = attach) |
| 9 | 16 | `group_id` (UUID, raw bytes) |
| 25 | 16 | `surface_id` (UUID, raw bytes) |

**`resize` payload** (8 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | `rows` (u16 LE) |
| 2 | 2 | `cols` (u16 LE) |
| 4 | 2 | `width_px` (u16 LE) |
| 6 | 2 | `height_px` (u16 LE) |

### Layout Serialization Format

The layout blob (sent via `layout_update` / `layout_restore`) uses a compact
binary format (version 1, little-endian):

```
[2] version (u16 LE, currently 1)
[2] tab_count (u16 LE)
per tab:
  [2] node_count (u16 LE)
  [2] zoomed_handle (u16 LE; 0xFFFF = none)
  [2] title_len (u16 LE; 0 = no title override)
  [title_len] title bytes (UTF-8)
  per node:
    [1] tag: 0 = leaf, 1 = split
    leaf:  [16] surface_id (UUID, raw bytes)
    split: [1] direction (0 = horizontal, 1 = vertical)
           [2] ratio (f16 bits, LE)
           [2] left_idx (u16 LE)
           [2] right_idx (u16 LE)
```

A single-tab, single-surface layout is 27 bytes. A 4-surface split tree
with 2 tabs is 128 bytes.

### Identity Model

| ID | Size | Scope | Lifetime | Purpose |
|----|------|-------|----------|---------|
| `group_id` | 128-bit UUID | Per session group | Stable across reconnects | Groups surfaces together. |
| `surface_id` | 128-bit UUID | Per surface | Stable across reconnects | Identifies a leaf in the layout tree. |
| `target_id` | 16-bit integer | Per SSH connection | Ephemeral (changes on reconnect) | Multiplexer routing key in frame headers. |

UUIDs are v4, generated client-side, transmitted as 16 raw bytes on the
wire. Human-readable session names are derived deterministically from
`group_id` using a 64-adjective x 64-noun word list (e.g. `bold-hawk`).
