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
    public enum ConnectionState: Sendable {
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
        case updateConfirmationRequired(UpdateConfirmation)

        /// A session-killing remote-daemon update is needed and a daemon
        /// is already running with live sessions at risk. Carries
        /// closures that resume the blocked connection, encapsulating the
        /// C-side `decision_token` (same pattern as `PasswordPrompt`).
        public struct UpdateConfirmation: Sendable {
            /// Host being updated (e.g. "user@host").
            public let host: String
            /// Best-effort count of live sessions an update would reset.
            public let sessionCount: UInt32
            /// True when the running daemon's protocol is incompatible:
            /// declining means disconnect, not "keep current".
            public let isMandatory: Bool
            /// Proceed: upload + force-restart (ends the live sessions).
            /// Safe to call from any thread; callable at most once.
            public let updateAndRestart: @Sendable () -> Void
            /// Keep the running daemon (no restart). For a mandatory
            /// update this disconnects instead. Callable at most once.
            public let keepCurrent: @Sendable () -> Void

            public init(
                host: String,
                sessionCount: UInt32,
                isMandatory: Bool,
                updateAndRestart: @escaping @Sendable () -> Void,
                keepCurrent: @escaping @Sendable () -> Void
            ) {
                self.host = host
                self.sessionCount = sessionCount
                self.isMandatory = isMandatory
                self.updateAndRestart = updateAndRestart
                self.keepCurrent = keepCurrent
            }
        }

        public struct PasswordPrompt: Sendable {
            /// True when the prompt is for a jump host rather than the target.
            public let isJump: Bool
            /// Host being authenticated.
            public let host: String
            /// Submit a password. Safe to call from any thread; callable at most
            /// once per prompt — subsequent calls are no-ops.
            public let submit: @Sendable (String) -> Void
            /// Abort the prompt; the connection transitions to FAILED.
            public let cancel: @Sendable () -> Void

            public init(isJump: Bool, host: String, submit: @escaping @Sendable (String) -> Void, cancel: @escaping @Sendable () -> Void) {
                self.isJump = isJump
                self.host = host
                self.submit = submit
                self.cancel = cancel
            }
        }

        public struct Upload: Sendable {
            public let bytesSent: UInt64
            public let totalBytes: UInt64
            public let source: ProvisionSource

            public var progress: Double {
                guard totalBytes > 0 else { return 0 }
                return Double(bytesSent) / Double(totalBytes)
            }

            public init(bytesSent: UInt64, totalBytes: UInt64, source: ProvisionSource) {
                self.bytesSent = bytesSent
                self.totalBytes = totalBytes
                self.source = source
            }
        }

        public enum ProvisionSource: Sendable, Equatable {
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

        public struct Reconnect: Sendable {
            public let attempt: UInt32
            public let maxAttempts: UInt32
            /// Time since the failure that triggered this reconnect.
            public let elapsed: TimeInterval
            /// Wall-clock instant the next attempt fires. `nil` means "now".
            public let nextRetry: Date?

            public init(attempt: UInt32, maxAttempts: UInt32, elapsed: TimeInterval, nextRetry: Date?) {
                self.attempt = attempt
                self.maxAttempts = maxAttempts
                self.elapsed = elapsed
                self.nextRetry = nextRetry
            }
        }

        public struct Disconnect: Sendable {
            public let attemptsMade: UInt32
            public let reason: Reason

            public enum Reason: Sendable, Equatable {
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

            public init(attemptsMade: UInt32, reason: Reason) {
                self.attemptsMade = attemptsMade
                self.reason = reason
            }
        }

        public struct Failure: Sendable {
            public let reason: Reason
            public let message: String?

            public enum Reason: Sendable, Equatable {
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

            public init(reason: Reason, message: String?) {
                self.reason = reason
                self.message = message
            }
        }

        /// Convenience tag for cheap pattern-matching in tests + UI.
        public enum Kind: Sendable, Equatable {
            case connecting, passwordRequired, uploading, downloading,
                 setup, connected, reconnecting, stale, failed, disconnected,
                 updateConfirmationRequired
        }

        public var kind: Kind {
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
            case .updateConfirmationRequired: return .updateConfirmationRequired
            }
        }

        /// True for terminal states: `failed`, `disconnected`.
        ///
        /// `stale` and `reconnecting` are recoverable.
        public var isTerminal: Bool {
            switch self {
            case .failed, .disconnected: return true
            default: return false
            }
        }

        /// Decode a flat C `ghostty_ssh_state_t` into the Swift enum
        /// WITHOUT an owning `SSHConnection`. Used by the per-surface
        /// `on_remote_state` callback path (`ghostty_surface_config_s`),
        /// which surfaces a `Remote` backend's own transport health and
        /// has no connection wrapper to bind password closures to. A
        /// terminal `Remote` backend never prompts for a password, so the
        /// `passwordRequired` closures are inert no-ops here; every other
        /// case is decoded identically to the connection path.
        public static func decode(surfaceState s: ghostty_ssh_state_t) -> ConnectionState {
            switch s.kind {
            case GHOSTTY_SSH_STATE_CONNECTING:
                return .connecting
            case GHOSTTY_SSH_STATE_DOWNLOADING:
                return .downloading
            case GHOSTTY_SSH_STATE_SETUP:
                return .setup
            case GHOSTTY_SSH_STATE_CONNECTED:
                return .connected
            case GHOSTTY_SSH_STATE_STALE:
                return .stale
            case GHOSTTY_SSH_STATE_PASSWORD_REQUIRED:
                let p = s.payload.password
                let host = p.host.map { String(cString: $0) } ?? ""
                return .passwordRequired(.init(
                    isJump: p.is_jump,
                    host: host,
                    submit: { _ in },
                    cancel: {}
                ))
            case GHOSTTY_SSH_STATE_UPDATE_CONFIRMATION_REQUIRED:
                // Inert on the per-surface path (no connection wrapper to
                // bind the decision closures to). A remote `Remote` backend
                // never drives this gate; the owning C-API connection does.
                let u = s.payload.update_confirmation
                let host = u.host.map { String(cString: $0) } ?? ""
                return .updateConfirmationRequired(.init(
                    host: host,
                    sessionCount: u.session_count,
                    isMandatory: u.is_mandatory,
                    updateAndRestart: {},
                    keepCurrent: {}
                ))
            case GHOSTTY_SSH_STATE_UPLOADING:
                let u = s.payload.upload
                return .uploading(.init(
                    bytesSent: u.bytes_sent,
                    totalBytes: u.total_bytes,
                    source: ProvisionSource.from(u.source)
                ))
            case GHOSTTY_SSH_STATE_RECONNECTING:
                let r = s.payload.reconnect
                let nextDate: Date? = r.next_retry_ns == 0
                    ? nil
                    : Date(timeIntervalSince1970: Double(r.next_retry_ns) / 1_000_000_000)
                return .reconnecting(.init(
                    attempt: r.attempt,
                    maxAttempts: r.max_attempts,
                    elapsed: Double(r.elapsed_ns) / 1_000_000_000,
                    nextRetry: nextDate
                ))
            case GHOSTTY_SSH_STATE_FAILED:
                let f = s.payload.fail
                let msg = f.message.map { String(cString: $0) }
                return .failed(.init(
                    reason: Failure.Reason.from(f.reason),
                    message: msg
                ))
            case GHOSTTY_SSH_STATE_DISCONNECTED:
                let d = s.payload.disconnect
                return .disconnected(.init(
                    attemptsMade: d.attempts_made,
                    reason: Disconnect.Reason.from(d.reason)
                ))
            default:
                return .connecting
            }
        }
    }

    /// Public error type for the SSH wrapper. Distinct from the package-
    /// internal `Ghostty.Error` so embedders can pattern-match.
    public enum SSHError: Swift.Error, Sendable, CustomStringConvertible, Equatable {
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

        public var description: String {
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
    public enum HostKeyHandler: Sendable {
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
    public struct HostKeyChallenge: Sendable {
        public let host: String
        /// SHA-256 hex fingerprint of the offered key.
        public let fingerprintSHA256: String
        /// e.g. "ssh-ed25519".
        public let keyType: String
        /// The offered key matches a pinned entry.
        public let knownMatch: Bool
        /// A *different* key for the host is pinned (MITM-suspect).
        public let knownMismatch: Bool
        /// Resolve the challenge. Safe to call from any thread; callable at
        /// most once per challenge.
        public let submit: @Sendable (_ accept: Bool, _ persist: Bool) -> Void

        public init(
            host: String,
            fingerprintSHA256: String,
            keyType: String,
            knownMatch: Bool,
            knownMismatch: Bool,
            submit: @escaping @Sendable (_ accept: Bool, _ persist: Bool) -> Void
        ) {
            self.host = host
            self.fingerprintSHA256 = fingerprintSHA256
            self.keyType = keyType
            self.knownMatch = knownMatch
            self.knownMismatch = knownMismatch
            self.submit = submit
        }
    }

    /// Lifecycle status of a remote session, mirroring `ghostty_ssh_session_status_e`.
    public enum SessionListStatus: Sendable {
        /// Session is alive but no client is attached.
        case detached
        /// Session is alive and at least one viewer is attached.
        case attached
        /// All surfaces in the session have exited.
        case dead

        static func from(_ c: ghostty_ssh_session_status_e) -> SessionListStatus {
            switch c {
            case GHOSTTY_SSH_SESSION_ATTACHED: return .attached
            case GHOSTTY_SSH_SESSION_DEAD: return .dead
            default: return .detached
            }
        }
    }

    /// An entry returned from `SSHConnection.listSessions()`.
    public struct SessionListEntry: Sendable {
        public let groupID: UUID
        public let label: String
        public let surfaceCount: UInt32
        public let createdAt: Date
        /// Lifecycle status of the session.
        public let status: SessionListStatus
        /// Color badge index: -1 = none, 0-7 = color palette slot.
        public let color: Int8

        public init(
            groupID: UUID,
            label: String,
            surfaceCount: UInt32,
            createdAt: Date,
            status: SessionListStatus = .detached,
            color: Int8 = -1
        ) {
            self.groupID = groupID
            self.label = label
            self.surfaceCount = surfaceCount
            self.createdAt = createdAt
            self.status = status
            self.color = color
        }
    }

    /// Logical terminal size used by `SSHConnection.attachSurface`.
    public struct TerminalSize: Sendable {
        public let rows: UInt16
        public let cols: UInt16
        public let widthPx: UInt32
        public let heightPx: UInt32

        public init(rows: UInt16, cols: UInt16, widthPx: UInt32 = 0, heightPx: UInt32 = 0) {
            self.rows = rows
            self.cols = cols
            self.widthPx = widthPx
            self.heightPx = heightPx
        }
    }
}
