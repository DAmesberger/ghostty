# SSH Remote Sessions

Ghostty can run terminal sessions on a remote host over SSH, with the
ability to detach and reattach — similar to tmux or screen, but built
into the terminal emulator.

## Quick Start

```bash
# Connect to a remote host (creates a new session)
ghostty --ssh-target=user@host

# Connect through a jump host
ghostty --ssh-target=user@host --ssh-jump=jump@gateway
```

On first connect, Ghostty uploads a small helper binary to the remote
host (`/tmp/ghostty-remote-session/bin/ghostty-session-helper`). A
daemon process manages sessions on the remote, keeping them alive
across disconnects.

## Session Management

### Listing sessions

```bash
ghostty +session-list --ssh=user@host
```

Output shows session ID, label, status, age, and attach state:

```
1773948627-b7aef217d446  session  alive  age: 5m  detached
1773950005-5e35033f8018  session  alive  age: 23m  attached
```

### Reattaching to a session

```bash
ghostty --ssh-target=user@host --ssh-session=1773948627-b7aef217d446
```

The remote daemon sends a snapshot of the current terminal viewport,
then resumes live output forwarding. The screen is restored as it was
when you disconnected.

### Detaching from a session

Bind the `session_detach` action in your ghostty config:

```
keybind = ctrl+shift+d=session_detach
```

Detaching closes the local window but leaves the remote session
running. You can reattach later from the same or a different machine.

### Killing a session

```bash
ghostty +session-kill --ssh=user@host --session=1773948627-b7aef217d446
```

## How It Works

### Architecture

```
Local (client)                    Remote (daemon)
─────────────────                 ──────────────────
Ghostty window                   Headless ghostty
  ├─ Terminal ◄── VT parser       ├─ Terminal (source of truth)
  ├─ Renderer                     ├─ HeadlessStreamHandler
  └─ Remote backend               ├─ PTY → shell
       │                          └─ RemoteSession
       └── SSH channel ──────────── Multiplexer ── Daemon socket
```

The **daemon** on the remote is a headless ghostty instance. It owns a
full Terminal with scrollback, styles, modes — all the state a normal
ghostty surface has, minus the renderer. PTY output is processed through
`HeadlessStreamHandler` to keep this Terminal up to date.

The **client** receives raw PTY bytes forwarded as `.stdout` frames over
the SSH channel. Its own VT parser processes them independently — the
same code path as a local terminal. No custom rendering protocol needed.

### Live data flow

```
PTY output → daemon feeds HeadlessStreamHandler → Terminal updated
           → daemon forwards raw bytes as .stdout frame
           → multiplexer → SSH channel → client
           → client processOutput() → VT parser → render
```

### Reconnect flow

```
Client sends session_open(mode=attach, session_id)
  → Daemon looks up session
  → Resizes PTY to client's window size
  → Serializes viewport as VT escape sequences (SGR + characters)
  → Sends as .state_full frame
  → Client feeds through processOutput() → screen rebuilt
  → Live .stdout forwarding resumes
```

### Protocol

Binary frame protocol over the SSH channel (protocol version 5):

| Frame type | Direction | Purpose |
|---|---|---|
| `stdin` | client → remote | Keyboard input |
| `stdout` | remote → client | Raw PTY output |
| `resize` | client → remote | Window size change |
| `state_full` | remote → client | VT snapshot for reconnect |
| `session_open` | client → remote | Create or attach to session |
| `session_opened` | remote → client | Session ID confirmation |
| `session_close` | client → remote | Kill a session |
| `detach` | client → remote | Detach without killing |
| `keepalive` | bidirectional | Connection health check |
| `eof` | remote → client | Session ended |

## Configuration Options

| Option | Description |
|---|---|
| `ssh-target` | SSH destination (`user@host` or `user@host:port`) |
| `ssh-jump` | Jump host for ProxyJump routing |
| `ssh-session` | Session ID to reattach to (from `+session-list`) |

## Limitations

- **Single surface per session**: Each session is one terminal. Tabs
  and splits are not yet synchronized across reconnects (protocol
  support exists via `layout_update`/`layout_restore` but is not
  implemented).
- **No scrollback on reconnect**: The VT snapshot restores only the
  visible viewport, not scrollback history. The headless Terminal
  maintains full scrollback but serializing it is not yet implemented.
- **Resize during reconnect**: The headless Terminal does not resize
  its internal state when the PTY is resized (to avoid page integrity
  issues). The shell adjusts its output via SIGWINCH, so the live
  display is correct.
