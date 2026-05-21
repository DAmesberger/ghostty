import Foundation
import GhosttyKit

extension Ghostty {
    /// The lifecycle state of an `SSHConnection`.
    ///
    /// Mirrors `ghostty_ssh_state_kind_e` plus the per-variant payload structs
    /// from the C surface (see the "SSH connection + channel API" block in
    /// `include/ghostty.h`).
    ///
    /// `passwordRequired` carries closures that resume the connection — they
    /// encapsulate the C-side `auth_token` so embedders don't have to thread
    /// it around. The same pattern is used for the host-key prompt
    /// (`Ghostty.HostKeyChallenge`).
    enum ConnectionState: Sendable {
        case connecting
        case passwordRequired(PasswordPrompt)
        case uploading(Upload)
        case downloading
        case setup
        case connected
        case reconnecting(Reconnect)
        case stale
        case failed(Failure)
        case disconnected(Disconnect)

        struct PasswordPrompt: Sendable {
            /// True when the prompt is for a jump host rather than the target.
            let isJump: Bool
            /// Host being authenticated.
            let host: String
            /// Submit a password. Safe to call from any thread; callable at most
            /// once per prompt — subsequent calls are no-ops.
            let submit: @Sendable (String) -> Void
            /// Abort the prompt; the connection transitions to FAILED.
            let cancel: @Sendable () -> Void
        }

        struct Upload: Sendable {
            let bytesSent: UInt64
            let totalBytes: UInt64
            let source: ProvisionSource

            var progress: Double {
                guard totalBytes > 0 else { return 0 }
                return Double(bytesSent) / Double(totalBytes)
            }
        }

        enum ProvisionSource: Sendable, Equatable {
            case localDaemon
            case localSelf
            case github

            static func from(_ c: ghostty_ssh_provision_source_e) -> ProvisionSource {
                switch c {
                case GHOSTTY_SSH_PROVISION_LOCAL_DAEMON: return .localDaemon
                case GHOSTTY_SSH_PROVISION_LOCAL_SELF: return .localSelf
                case GHOSTTY_SSH_PROVISION_GITHUB: return .github
                default: return .localDaemon
                }
            }
        }

        struct Reconnect: Sendable {
            let attempt: UInt32
            let maxAttempts: UInt32
            /// Time since the failure that triggered this reconnect.
            let elapsed: TimeInterval
            /// Wall-clock instant the next attempt fires. `nil` means "now".
            let nextRetry: Date?
        }

        struct Disconnect: Sendable {
            let attemptsMade: UInt32
            let reason: Reason

            enum Reason: Sendable, Equatable {
                case exhausted
                case cancelled
                case disabled

                static func from(_ c: ghostty_ssh_disconnect_reason_e) -> Reason {
                    switch c {
                    case GHOSTTY_SSH_DISCONNECT_EXHAUSTED: return .exhausted
                    case GHOSTTY_SSH_DISCONNECT_CANCELLED: return .cancelled
                    case GHOSTTY_SSH_DISCONNECT_DISABLED: return .disabled
                    default: return .exhausted
                    }
                }
            }
        }

        struct Failure: Sendable {
            let reason: Reason
            let message: String?

            enum Reason: Sendable, Equatable {
                case unknown
                case authFailed
                case timeout
                case helperFailed

                static func from(_ c: ghostty_ssh_fail_reason_e) -> Reason {
                    switch c {
                    case GHOSTTY_SSH_FAIL_UNKNOWN: return .unknown
                    case GHOSTTY_SSH_FAIL_AUTH_FAILED: return .authFailed
                    case GHOSTTY_SSH_FAIL_TIMEOUT: return .timeout
                    case GHOSTTY_SSH_FAIL_HELPER_FAILED: return .helperFailed
                    default: return .unknown
                    }
                }
            }
        }

        /// Convenience tag for cheap pattern-matching in tests + UI.
        enum Kind: Sendable, Equatable {
            case connecting, passwordRequired, uploading, downloading,
                 setup, connected, reconnecting, stale, failed, disconnected
        }

        var kind: Kind {
            switch self {
            case .connecting: return .connecting
            case .passwordRequired: return .passwordRequired
            case .uploading: return .uploading
            case .downloading: return .downloading
            case .setup: return .setup
            case .connected: return .connected
            case .reconnecting: return .reconnecting
            case .stale: return .stale
            case .failed: return .failed
            case .disconnected: return .disconnected
            }
        }

        /// True for terminal states: `failed`, `disconnected`.
        ///
        /// `stale` and `reconnecting` are recoverable.
        var isTerminal: Bool {
            switch self {
            case .failed, .disconnected: return true
            default: return false
            }
        }
    }

    /// Public error type for the SSH wrapper. Distinct from the package-
    /// internal `Ghostty.Error` so embedders can pattern-match.
    enum SSHError: Swift.Error, Sendable, CustomStringConvertible, Equatable {
        /// `ghostty_ssh_open` returned NULL — config was malformed.
        case openFailed
        /// `ghostty_ssh_open_channel` returned NULL.
        case channelOpenFailed
        /// The channel was closed before / during a write.
        case channelClosed
        /// `ghostty_ssh_list_sessions` returned false (connection not ready).
        case notReady
        /// `encodeParams()` rejected an oversized input field. Mirrors the
        /// Zig parser's hard caps (`max_host_len`, `max_path_len`,
        /// `max_metadata_len`); failing here surfaces the misuse to the
        /// embedder instead of silently truncating into a different
        /// destination than they asked for.
        case openParamsTooLong(field: String, length: Int, limit: Int)

        var description: String {
            switch self {
            case .openFailed: return "ghostty_ssh_open failed (invalid configuration)"
            case .channelOpenFailed: return "ghostty_ssh_open_channel failed"
            case .channelClosed: return "channel closed"
            case .notReady: return "SSH connection not ready"
            case let .openParamsTooLong(field, length, limit):
                return "channel open params field \"\(field)\" is \(length) bytes, exceeds limit of \(limit)"
            }
        }
    }

    /// Host key verification policy applied to the SSH transport.
    enum HostKeyHandler: Sendable {
        /// Reject unknown hosts and any pinned-key mismatch.
        case strict
        /// Trust-on-first-use: accept on first sight, pin, then enforce.
        case tofu
        /// Accept all keys. Development only.
        case insecure
        /// Delegate the decision to the embedder. Closure must call
        /// `submit(accept:persist:)` exactly once per challenge.
        case interactive(@Sendable (HostKeyChallenge) -> Void)

        var cPolicy: ghostty_ssh_host_key_policy_e {
            switch self {
            case .strict, .interactive: return GHOSTTY_SSH_HOST_KEY_STRICT
            case .tofu: return GHOSTTY_SSH_HOST_KEY_TOFU
            case .insecure: return GHOSTTY_SSH_HOST_KEY_INSECURE
            }
        }
    }

    /// Payload + resolver for an interactive host-key prompt.
    struct HostKeyChallenge: Sendable {
        let host: String
        /// SHA-256 hex fingerprint of the offered key.
        let fingerprintSHA256: String
        /// e.g. "ssh-ed25519".
        let keyType: String
        /// The offered key matches a pinned entry.
        let knownMatch: Bool
        /// A *different* key for the host is pinned (MITM-suspect).
        let knownMismatch: Bool
        /// Resolve the challenge. Safe to call from any thread; callable at
        /// most once per challenge.
        let submit: @Sendable (_ accept: Bool, _ persist: Bool) -> Void
    }

    /// An entry returned from `SSHConnection.listSessions()`.
    struct SessionListEntry: Sendable {
        let groupID: UUID
        let label: String
        let surfaceCount: UInt32
        let createdAt: Date
    }

    /// Logical terminal size used by `SSHConnection.attachSurface`.
    struct TerminalSize: Sendable {
        let rows: UInt16
        let cols: UInt16
        let widthPx: UInt32
        let heightPx: UInt32

        init(rows: UInt16, cols: UInt16, widthPx: UInt32 = 0, heightPx: UInt32 = 0) {
            self.rows = rows
            self.cols = cols
            self.widthPx = widthPx
            self.heightPx = heightPx
        }
    }
}
