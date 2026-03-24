# SSH Remote Sessions

> **Status**: Experimental feature branch (`feature/ssh-remote-sessions`).
> This is a fork — not part of upstream Ghostty.

Native SSH remote session support for Ghostty. Connect to remote hosts with full terminal fidelity, persistent sessions that survive disconnects, and seamless reattachment — without tmux, screen, or Mosh.

## What it does

Ghostty connects to remote hosts natively via SSH (using `--ssh-target` or keybindings), provisions a headless daemon on the remote side, and communicates over a binary protocol. This gives you:

- **Persistent sessions** — detach and reattach without losing state
- **Scrollback sync** — full history is preserved across reconnects
- **Automatic reconnection** — configurable retry with exponential backoff
- **Per-session colored tabs** — visual identification via indicator icons
- **Session management** — list, attach, kill sessions from CLI or GUI picker
- **Connection overlays** — real-time status (connecting, reconnecting, stale)
- **Password authentication** — GUI overlay prompts, no stdin hijacking
- **Splits and layouts** — preserved across detach/reattach cycles
- **Jump host support** — `via` syntax in `ssh-target` for bastion/proxy setups

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
```

Ghostty connects via SSH, provisions a headless daemon on the remote host (first time only), and establishes a multiplexed binary session. This is **not** a regular `ssh` command — Ghostty manages the connection natively.

### Detach a session

Press your `ssh_session_detach` keybinding (e.g. `Ctrl+Shift+D`). The session keeps running on the remote host. Your local tab closes cleanly.

### Reattach to a session

Press your `ssh_session_attach` keybinding (e.g. `Ctrl+Shift+A`). This opens a session picker dialog showing all detached sessions on the host. Select one to reattach.

You can also attach from the CLI:

```bash
# List sessions on a remote host
ghostty +ssh-session --list --ssh user@host

# Attach to a specific session by ID
ghostty --ssh-target=user@host --ssh-session=SESSION_ID
```

### Manage sessions

```bash
# List all sessions on a remote host
ghostty +ssh-session --list --ssh user@host

# Kill a specific session
ghostty +ssh-session --kill=SESSION_ID --ssh user@host

# Rename a session
ghostty +ssh-session --rename=SESSION_ID --label=new-name --ssh user@host
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `ssh-target` | — | SSH target. Supports `via` for jump hosts: `user@host via bastion` |
| `ssh-session` | — | Attach to existing session by ID or label |
| `ssh-reconnect-attempts` | `5` | Max automatic reconnect attempts (0 = disabled) |
| `ssh-reconnect-backoff` | `exponential` | Backoff strategy (`exponential` or `linear`) |
| `ssh-reconnect-interval` | `1000` | Base interval in ms between reconnect attempts |
| `scrollback-limit` | `10000000` | Scrollback buffer size in bytes (sent to daemon) |

## Keybinding actions

| Action | Description |
|--------|-------------|
| `ssh_session_detach` | Detach current session (keeps running remotely) |
| `ssh_session_reconnect` | Manually trigger reconnection |
| `ssh_create_session:new_tab` | Open new SSH session in a tab |
| `ssh_create_session:new_window` | Open new SSH session in a window |
| `ssh_session_attach:new_tab` | Show session picker, attach in tab |
| `ssh_session_attach:new_window` | Show session picker, attach in window |

## Architecture

```
Local Ghostty                          Remote Host
+-----------------+                    +------------------+
| GTK Surface     |   SSH channel      | ghostty-headless |
|  +- Remote.zig  | <=== binary ====>  |  +- Daemon       |
|  +- SshConn.Mgr |   protocol (v1)    |  +- RemoteSession|
|  +- Tab colors  |                    |  +- Terminal      |
|  +- Overlays    |                    |  +- PTY           |
+-----------------+                    +------------------+
```

**Protocol**: Custom binary framing (8-byte headers, zstd compression for page diffs). Frame types include: data_in/out, resize, open/opened/close, layout sync, scrollback streaming, ping/pong keepalive.

**Multiplexing**: Multiple surfaces (tabs/splits) share one SSH channel per host via target IDs. The `SshConnectionManager` pools connections.

**Provisioning**: On first connect, Ghostty uploads a headless binary matching the remote OS/arch from GitHub releases. Subsequent connections reuse the existing daemon if the version matches.

**Reconnection**: When the SSH transport drops, the client automatically attempts reconnection with configurable backoff. The daemon keeps sessions alive independently. On reconnect, the client re-opens sessions and receives full state snapshots.

## Building from source

```bash
git clone https://github.com/DAmesberger/ghostty.git
cd ghostty
git checkout feature/ssh-remote-sessions
zig build
```

Requires Zig (version specified in `build.zig.zon`).

## Known limitations

- Linux and macOS only (remote host must be one of these)
- Binary provisioning requires GitHub release access from the remote host
- No Windows remote host support
- Session labels are generated, not user-configurable at creation time
- Tab color auto-assignment uses a hash — two sessions may occasionally get the same color

## Links

- [Upstream Ghostty](https://github.com/ghostty-org/ghostty)
- [Fork](https://github.com/DAmesberger/ghostty/tree/feature/ssh-remote-sessions)
- [Headless binary releases](https://github.com/DAmesberger/ghostty/releases)
