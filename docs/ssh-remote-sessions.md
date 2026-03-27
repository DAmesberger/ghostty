# SSH Remote Sessions

Ghostty can run terminal sessions on a remote host over SSH, with the
ability to detach and reattach — similar to tmux or screen, but built
into the terminal emulator. Splits within a session are grouped together
and their layout is preserved across reconnects.

## Quick Start

```bash
# Connect to a remote host (creates a new session)
ghostty --ssh-target=user@host

# Connect through a jump host
ghostty --ssh-target=user@host --ssh-jump=jump@gateway
```

On first connect, Ghostty uploads a small daemon binary to the remote
host. A daemon process manages sessions on the remote, keeping them
alive across disconnects.

## Splits

Splits within a remote session work the same as local splits. Each
split pane runs an independent shell on the remote host, but all splits
in a window are grouped into a single **session group** that is tracked
as a unit.

```bash
# Open a remote session, then split:
#   Ctrl+Shift+\ (vertical split)
#   Ctrl+Shift+- (horizontal split)
```

Each split gets its own PTY on the remote. The session group tracks the
layout (which panes exist, their arrangement, and split ratios). When
you detach and later reattach, the layout is restored automatically.

## Session Management

### Named sessions

You can give sessions human-readable names. If no session with that
name exists, a new one is created. If one exists, Ghostty reattaches
to it (create-or-attach semantics):

```bash
# Create a named session (or reattach if "my-project" already exists)
ghostty --ssh-target=user@host --ssh-session=my-project
```

This makes it easy to maintain persistent named workspaces on remote
hosts without needing to look up session UUIDs.

### Listing sessions

```bash
ghostty +ssh-session --list --ssh user@host
```

Output shows session groups with their surfaces:

```
a1b2c3d4e5f6...  my-project  2 surfaces  attached
  11223344...    my-project   alive  attached
  55667788...    my-project   alive  attached
```

### Reattaching to a session

```bash
# Reattach by group UUID
ghostty --ssh-target=user@host --ssh-session=a1b2c3d4e5f6...

# Reattach by label (if unique)
ghostty --ssh-target=user@host --ssh-session=my-project
```

The remote daemon sends the saved layout blob, then a VT snapshot for
each surface. The client recreates the split tree and resumes live
output forwarding for all panes.

### Detaching from a session

Bind the `session_detach` action in your ghostty config:

```
keybind = ctrl+shift+d=session_detach
```

Detaching closes the local window but leaves all remote shells running.
You can reattach later from the same or a different machine — the full
split layout is restored.

### Killing a session

```bash
ghostty +ssh-session --kill=a1b2c3d4e5f6... --ssh user@host
```

This kills all surfaces in the group.

## Tab Title Indicators

Remote sessions display connection information in the tab title:

```
vim main.zig — user@host (my-project)
```

The format is `<title> — <ssh-target> (<session-label>)`. The session
label is shown only if one was provided via `--ssh-session`.

When the connection is degraded, a status prefix appears:

| Prefix | Meaning |
|---|---|
| `[connecting]` | Initial SSH connection in progress |
| `[reconnecting]` | Automatic reconnection after a drop |
| `[stale]` | No keepalive received (connection may be dead) |
| `[disconnected]` | Reconnection failed permanently |

These indicators update in real time and clear automatically when
the connection recovers.

## Connection Resilience

### Keepalive and stale detection

The client and remote daemon exchange keepalive frames every 15 seconds.
If no keepalive is received for 45 seconds, the connection is marked
stale and automatic reconnection begins.

### Automatic reconnect

When the SSH connection drops, Ghostty attempts to reconnect with
exponential backoff (1s → 2s → 4s → ... up to 30s). The reconnect
timeout defaults to 5 minutes. During reconnect:

1. The SSH connection is re-established
2. The daemon is restarted if needed
3. The session group is reattached (one `session_open` per group)
4. The daemon sends the layout blob and VT snapshots
5. The client recreates the split tree with correct surface sizes

If a specific surface fails to re-open during reconnect, that pane
is closed with an exit notification. Other surfaces in the group
continue working.

### Session lifecycle

Sessions persist on the remote host as long as at least one shell
process is alive, even if the client disconnects. When all surfaces
in a group have exited, the group is kept for a 5-minute grace period
(to allow reconnecting), then cleaned up automatically.

## How It Works

### Architecture

```
Local (client)                    Remote (daemon)
─────────────────                 ──────────────────
Ghostty window                   SessionGroup
  ├─ SplitTree                     ├─ group_id (UUID)
  │   ├─ Surface A ◄── VT          ├─ label
  │   └─ Surface B ◄── VT          ├─ layout_blob (opaque)
  └─ Remote backend                ├─ RemoteSession A (surface_id)
       │                           │   ├─ Terminal + PTY + shell
       └── SSH channel ────────    │   └─ HeadlessStreamHandler
           (multiplexed)       ── Multiplexer ── Daemon socket
                                   └─ RemoteSession B (surface_id)
                                       ├─ Terminal + PTY + shell
                                       └─ HeadlessStreamHandler
```

The **daemon** manages **session groups**, each containing one or more
**remote sessions** (surfaces). Each surface has its own headless
Terminal, PTY, and shell process. The layout blob is stored opaquely
by the daemon — it never interprets the layout, just replays it on
reconnect.

The **client** generates UUIDs for both the group and each surface.
IDs are stable across reconnects. The multiplexer routes frames to the
correct daemon socket connection using ephemeral 16-bit target IDs.

### Identity model

| ID | Scope | Lifetime | Purpose |
|---|---|---|---|
| `group_id` | Per session group | Stable across reconnects | Groups surfaces together |
| `surface_id` | Per surface | Stable across reconnects | Identifies a leaf in the layout |
| `target_id` | Per SSH connection | Ephemeral (changes on reconnect) | Multiplexer routing key |

Both `group_id` and `surface_id` are 128-bit UUIDs generated client-side.
They are transmitted as 16 raw bytes on the wire.

### Live data flow

```
PTY output → daemon feeds HeadlessStreamHandler → Terminal updated
           → daemon forwards raw bytes as .stdout frame
           → multiplexer → SSH channel → client
           → client processOutput() → VT parser → render
```

### New session (first surface)

```
Client generates surface_id + group_id
  → session_open(mode=new, surface_id, group_id, label)
  → Daemon creates SessionGroup + RemoteSession
  → session_opened(group_id)
  → attachAndServe: state_full snapshot + live forwarding
```

### Adding a split

```
User splits → new Surface created instantly (no round-trip)
  → surface_open(mode=new, group_id, surface_id, resize)
  → Daemon creates RemoteSession in existing SessionGroup
  → session_opened + attachAndServe
  → SplitTree change → serialize layout → layout_update(blob)
  → Daemon stores blob in SessionGroup
```

### Reconnect flow

```
Client sends session_open(mode=attach, group_id)
  → Daemon finds SessionGroup (or creates via named session)
  → session_opened(group_id) + layout_restore(blob)
  → Attaches to first alive surface: state_full + live forwarding
  → Client deserializes blob → recreates SplitTree
  → For each additional leaf: surface_open(mode=attach, surface_id)
  → Each surface gets state_full snapshot + live forwarding
  → Dead surfaces: daemon sends eof → client removes leaf
```

### Session rename flow

```
Client sends session_rename(group_id, new_label)
  → Daemon updates SessionGroup.label
  → +ssh-session --list shows the new name
```

### Protocol

Binary frame protocol over the SSH channel (protocol version 6):

| Frame type | Direction | Purpose |
|---|---|---|
| `stdin` | client → remote | Keyboard input |
| `stdout` | remote → client | Raw PTY output |
| `resize` | client → remote | Window size change |
| `state_full` | remote → client | VT snapshot for reconnect |
| `session_open` | client → remote | Create or attach to session group |
| `session_opened` | remote → client | Group UUID confirmation |
| `session_close` | client → remote | Kill a session group |
| `session_rename` | client → remote | Rename a session group |
| `surface_open` | client → remote | Add surface to existing group |
| `surface_close` | client → remote | Remove surface from group |
| `layout_update` | client → remote | Store layout blob for reconnect |
| `layout_restore` | remote → client | Replay stored layout on reconnect |
| `detach` | client → remote | Detach without killing |
| `keepalive` | bidirectional | Connection health check |
| `eof` | remote → client | Session/surface ended |

### Layout serialization

The layout is serialized as a compact binary blob (little-endian):

```
[2] version
[2] node_count
[2] zoomed_handle (0xFFFF = none)
per node:
  [1] tag: 0=leaf, 1=split
  leaf:  [16] surface_id (UUID)
  split: [1] direction, [2] ratio (f16), [2] left_idx, [2] right_idx
```

A 4-surface tree (3 splits + 4 leaves) is 98 bytes.

## Configuration Options

| Option | Description |
|---|---|
| `ssh-target` | SSH destination (`user@host` or `user@host:port`) |
| `ssh-jump` | Jump host for ProxyJump routing |
| `ssh-session` | Session name or UUID to attach to. Creates a new named session if not found. |

## Limits

- **64 surfaces per SSH connection**: Each connection supports up to
  64 multiplexed surfaces. Exceeding this limit shows an error overlay
  on the new surface.
- **No mixed local/remote splits**: A tab is either all-remote or
  all-local. This is determined by whether `ssh-target` is set at
  surface creation.
- **No scrollback on reconnect**: The VT snapshot restores only the
  visible viewport, not scrollback history. The headless Terminal
  maintains full scrollback but serializing it is not yet implemented.
- **Resize during reconnect**: The headless Terminal does not resize
  its internal state when the PTY is resized (to avoid page integrity
  issues). The shell adjusts its output via SIGWINCH, so the live
  display is correct.
- **GTK only**: Remote sessions are currently supported on the GTK
  apprt (Linux). macOS support requires Swift UI layer work and is
  planned for a future release.
