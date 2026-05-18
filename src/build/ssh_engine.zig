//! SSH engine selection for remote session support.
//!
//! `libssh2` — vendored libssh2 + aws-lc. libghostty opens the SSH connection
//!   itself via `src/session/ssh.zig`. Self-contained; works where OpenSSH is
//!   not installed. Default for upstream Ghostty.
//!
//! `openssh` — Ghostty spawns the system `ssh` binary as a subprocess and
//!   talks to the remote daemon over its stdio pipes. Honors the user's
//!   `~/.ssh/config`, agent, known_hosts, ProxyJump, ControlMaster, and
//!   hardware-key/FIDO2 setup transparently. Drops libssh2 + aws-lc from
//!   the build. **Engine not yet implemented** — selecting this today
//!   produces a binary whose SSH path will fail at runtime; the value
//!   exists so the build-flag shape is forward-compatible.
//!
//! `both` — compile both engines in; runtime picks via the `ssh-engine`
//!   config option. Pays the libssh2 + aws-lc binary-size cost. Once the
//!   openssh engine ships, this will be the default.
pub const SshEngine = enum {
    libssh2,
    openssh,
    both,
};
