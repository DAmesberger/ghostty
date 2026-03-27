# SSH Remote Sessions

> **Status**: Experimental feature branch (`feature/ssh-remote-sessions`).
> This is a fork — not part of upstream Ghostty.

Native SSH remote session support for Ghostty. Connect to remote hosts with full terminal fidelity, persistent sessions that survive disconnects, and seamless reattachment — without tmux, screen, or Mosh.

## What it does

Ghostty connects to remote hosts natively via SSH (using `--ssh-target` or keybindings), provisions a `ghostty-daemon` on the remote side, and communicates over a binary protocol. This gives you:

- **Persistent sessions** — detach and reattach without losing state
- **Scrollback sync** — full history is preserved across reconnects via page-diff streaming
- **Automatic reconnection** — configurable retry with exponential/linear/constant backoff
- **Per-session colored tabs** — daemon-authoritative colors with manual override
- **Session management** — list, attach, rename, kill, force-disconnect from CLI or GUI picker
- **Connection overlays** — real-time status (connecting, uploading, reconnecting, stale, password prompt)
- **Password authentication** — GUI overlay prompts for both target and jump host, no stdin hijacking
- **Splits and layouts** — tab structure, split ratios, zoom state, focus preserved across detach/reattach
- **Jump host support** — `via` syntax with multi-hop chaining: `user@host via hop1,hop2`
- **Multi-viewer sessions** — multiple clients can attach to the same session with size negotiation
- **LZ4 compression** — negotiated per-connection for frame payloads
- **SSH config integration** — reads `~/.ssh/config` for Host, HostName, User, Port

## Quick start

### Recommended keybindings

Add these to your Ghostty config to enable SSH session management:

```
keybind = ctrl+shift+s=ssh_create_session:new_tab
keybind = ctrl+shift+a=ssh_session_attach:new_tab
keybind = ctrl+shift+d=ssh_session_detach
keybind = ctrl+shift+r=ssh_session_reconnect
```

### Connect to a remote host

Use the `ssh_create_session` keybinding (above) or launch from the CLI with `--ssh-target`:

```bash
# New session via CLI
ghostty --ssh-target=user@host

# With a jump/bastion host
ghostty --ssh-target="user@host via bastion@proxy"

# Multi-hop (chained through multiple bastion hosts)
ghostty --ssh-target="user@host via hop1@bastion1,hop2@bastion2"
```

Ghostty connects via SSH, provisions `ghostty-daemon` on the remote host (first time only), and establishes a multiplexed binary session. This is **not** a regular `ssh` command — Ghostty manages the connection natively.

The connection overlay shows progress through each stage: connecting, uploading daemon binary (with progress bar), starting remote daemon, and finally connected.

### Detach a session

Press your `ssh_session_detach` keybinding (e.g. `Ctrl+Shift+D`). The session keeps running on the remote host. Your local tab closes cleanly.

### Reattach to a session

Press your `ssh_session_attach` keybinding (e.g. `Ctrl+Shift+A`). This opens a session picker dialog showing all sessions on the host. Select one to reattach.

The session picker supports inline actions per session:
- **Attach** — double-click or select and confirm
- **Rename** — pencil icon, inline edit
- **Detach Others** — disconnect all other viewers from the session
- **Kill** — terminate the session and all its surfaces
- **Refresh** — re-query the remote daemon

You can also manage sessions from the CLI:

```bash
# List all sessions on a remote host
ghostty +ssh-session --list --ssh user@host

# Attach to a specific session by ID
ghostty --ssh-target=user@host --ssh-session=SESSION_ID

# Kill a specific session
ghostty +ssh-session --kill=SESSION_ID --ssh user@host

# Rename a session
ghostty +ssh-session --rename=SESSION_ID --label=new-name --ssh user@host

# Detach all other viewers from a session
ghostty +ssh-session --detach-others=SESSION_ID --ssh user@host

# Kill the remote daemon
ghostty +ssh-session --kill-daemon --ssh user@host
```

### Session manager

Use the `ssh_manage_session` keybinding to open the session manager dialog for the current session. From here you can:

- Rename the session
- Change the session color
- Toggle size negotiation mode (smallest-wins / leader-wins)
- View connected viewers
- Force-disconnect specific viewers

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `ssh-target` | — | SSH target in `user@host[:port]` format. Supports `via` for jump hosts: `user@host via bastion@proxy` |
| `ssh-session` | — | Attach to existing session by ID or label instead of creating a new one |
| `ssh-reconnect-attempts` | `5` | Max automatic reconnect attempts after disconnect (0 = disabled) |
| `ssh-reconnect-backoff` | `exponential` | Backoff strategy: `exponential`, `linear`, or `constant` |
| `ssh-reconnect-interval` | `1000` | Base interval in ms between reconnect attempts |
| `ssh-compression` | `3` | LZ4 compression level (0 = disabled, 1-15 = enabled) |
| `ssh-size-mode` | `smallest` | Multi-viewer size negotiation: `smallest` (all viewers see full content) or `leader` (active controller's size) |

## Keybinding actions

| Action | Description |
|--------|-------------|
| `ssh_create_session:new_tab` | Open SSH connection picker, create session in a tab |
| `ssh_create_session:new_window` | Open SSH connection picker, create session in a window |
| `ssh_session_attach:new_tab` | Show session picker, attach in tab |
| `ssh_session_attach:new_window` | Show session picker, attach in window |
| `ssh_session_detach` | Detach current session (keeps running remotely) |
| `ssh_session_reconnect` | Manually trigger reconnection |
| `ssh_rename_session` | Rename current session (opens dialog) |
| `ssh_delete_session` | Kill current session (with confirmation) |
| `ssh_toggle_size_mode` | Toggle between smallest-wins and leader-wins size mode |
| `ssh_manage_session` | Open session manager: rename, color, viewers, size mode |

## CLI reference

### `+ssh-session`

Manage remote sessions over SSH.

```
ghostty +ssh-session [flags] --ssh user@host
```

| Flag | Description |
|------|-------------|
| `--list` | List sessions on the remote host |
| `--kill=ID` | Kill a specific session |
| `--rename=ID --label=NAME` | Rename a session |
| `--detach-others=ID` | Disconnect all other viewers from a session |
| `--kill-daemon` | Kill the remote daemon process |
| `--ssh=TARGET` | SSH target (supports `via` syntax for jump hosts) |
| `--protocol-version` | Print protocol version and exit (remote-side) |
| `--daemon` | Run in daemon mode (remote-side) |
| `--daemonize` | Start daemon in background and exit (remote-side) |

### `+ssh-cache`

Manage SSH terminfo cache for automatic remote host setup. Used with `shell-integration-features = ssh-terminfo`.

```
ghostty +ssh-cache [flags]
```

| Flag | Description |
|------|-------------|
| (no flags) | List all cached hosts |
| `--host=HOST` | Check if a host is cached |
| `--add=HOST` | Add a host to the cache |
| `--remove=HOST` | Remove a host from the cache |
| `--clear` | Clear the entire cache |
| `--expire-days=N` | Set cache expiration period in days |

## Connection overlay

The connection overlay shows real-time status during SSH operations:

| State | Display | Actions |
|-------|---------|---------|
| Connecting | "Connecting..." | — |
| Uploading | "Uploading local daemon binary..." + progress bar | — |
| Downloading | "Downloading from GitHub releases..." | — |
| Setup | "Starting remote daemon..." | — |
| Connected | Overlay dismissed | — |
| Reconnecting (active) | "Connecting... (attempt N of M)" | Cancel |
| Reconnecting (backoff) | "Reconnect failed, retrying in Ns (attempt N of M)" | Retry Now, Cancel |
| Stale | "Connection stale" | — |
| Failed (auth) | "Authentication failed" | Close |
| Failed (timeout) | "Connection timed out" | Close |
| Failed (setup) | "Ghostty setup failed" | Close |
| Disconnected | "Reconnect failed after N attempts" | Reconnect, Exit |
| Password required | "Password for user@host:" + input field | Submit, Cancel |

## Architecture

```
Local Ghostty                          Remote Host
+-----------------+                    +------------------+
| GTK Surface     |   SSH channel      | ghostty-daemon   |
|  +- Remote.zig  | <=== binary ====>  |  +- Helper       |
|  +- SshConn.Mgr |   protocol (v1)    |  +- RemoteSession|
|  +- Tab colors  |                    |  +- Terminal      |
|  +- Overlays    |                    |  +- PTY           |
+-----------------+                    +------------------+
```

### Protocol

Custom binary framing with 8-byte headers (kind, flags, target ID, payload length). Frame types include:

- **Data**: `data_in` (keystrokes), `data_out` (page diffs)
- **Control**: `resize`, `open`/`opened`, `close`/`eof`
- **Session**: `list_request`/`list_response`, `rename`, `session_meta`
- **Layout**: `layout` (tab/split structure sync)
- **Scrollback**: `scrollback_response` (proactive history streaming in ~90-row chunks)
- **Keepalive**: `ping`/`pong` (15s interval, 45s stale threshold, 60s server timeout)
- **Multi-viewer**: `viewer_state` (roster broadcasts), `size_mode_change`, `kick_viewer`

Compression: LZ4 block format on frame payloads (negotiated per-connection). Page diffs use their own binary encoding.

### Multiplexing

Multiple surfaces (tabs/splits) share one SSH channel per `(target, jump)` pair. The `SshConnectionManager` pools connections and assigns per-surface target IDs for frame routing.

### Provisioning

On first connect, Ghostty provisions `ghostty-daemon` on the remote host:

1. Check if `ghostty` is in PATH with matching protocol version
2. Check for previously deployed `ghostty-daemon` in `~/.local/bin/`
3. If platforms match: upload local binary via SCP
4. If cross-platform: download matching binary from GitHub releases

Subsequent connections reuse the existing daemon if the version matches.

### Reconnection

When the SSH transport drops, the client automatically attempts reconnection with configurable backoff. The daemon keeps sessions alive independently. On reconnect, the client re-opens sessions and receives full state snapshots including scrollback history.

### Timeouts

- TCP connect: 30 seconds (non-blocking with poll)
- SSH handshake: 30 seconds (non-blocking with deadline)
- Tunnel handshake: 30 seconds
- Keepalive ping: every 15 seconds
- Stale detection: 45 seconds without pong
- Server disconnect: 60 seconds without ping

### SSH authentication

Authentication methods tried in order:
1. SSH agent (if running)
2. Key files: `id_ed25519`, `id_ecdsa`, `id_rsa`, `id_ecdsa_sk`, `id_ed25519_sk`
3. Password prompt (GUI overlay for target and jump host separately)

Host key verification uses TOFU (Trust On First Use): known hosts are checked against `~/.ssh/known_hosts`, mismatches are rejected, new hosts are auto-accepted and written to known_hosts.

### SSH config

The SSH connection picker reads `~/.ssh/config` and lists configured hosts. Parsed fields:
- `Host` (alias names, wildcards skipped)
- `HostName`
- `User`
- `Port`

### Multi-viewer sessions

Multiple clients can attach to the same remote session simultaneously. The daemon tracks connected viewers and broadcasts state updates. Size negotiation controls how the PTY is sized:

- **smallest-wins** (default): PTY is sized to the minimum rows/cols across all viewers
- **leader-wins**: PTY matches the active controller's terminal size

Use `ssh_toggle_size_mode` or the session manager to switch modes. Use `kick_viewer` (via session manager) to force-disconnect specific viewers.

## Building from source

```bash
git clone https://github.com/DAmesberger/ghostty.git
cd ghostty
git checkout feature/ssh-remote-sessions
zig build
```

Requires Zig (version specified in `build.zig.zon`). The build includes `libssh2` (with `aws-lc` crypto backend) as vendored dependencies.

## Known limitations

- Linux and macOS only (remote host must be one of these, no Windows remote support)
- SSH config parsing is limited to Host/HostName/User/Port (no ProxyJump, IdentityFile, Match)
- No SSH agent forwarding (agent is used for local auth only)
- No port forwarding (local, remote, or dynamic/SOCKS)
- No X11 forwarding
- No OSC 52 clipboard pass-through (remote clipboard requests are silently ignored)
- Remote TERM/COLORTERM is inherited from the user's shell, not explicitly set by Ghostty
- Binary provisioning requires GitHub release access or a co-located local daemon binary

## Links

- [Upstream Ghostty](https://github.com/ghostty-org/ghostty)
- [Fork](https://github.com/DAmesberger/ghostty/tree/feature/ssh-remote-sessions)
- [Daemon binary releases](https://github.com/DAmesberger/ghostty/releases)
