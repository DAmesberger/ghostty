import Foundation
import Combine
import GhosttyKit

extension Ghostty {
    /// A single multiplexed SSH connection to one remote host.
    ///
    /// Wraps `ghostty_ssh_t`. Construction is `async` because libghostty's
    /// open path is asynchronous — the initializer suspends until the
    /// underlying connection reaches `connected` (or fails). Embedders
    /// observe further state transitions via `state`.
    ///
    /// Threading: all C callbacks fire on libghostty worker threads. The
    /// wrapper hops every callback through its private `ConnectionMailbox`
    /// actor before mutating Swift state, so the public API can be called
    /// from any concurrency context.
    final class SSHConnection: @unchecked Sendable {
        // MARK: Configuration

        struct Config: Sendable {
            /// "user@host[:port]".
            let target: String
            /// Comma-separated jump-host chain. Empty = direct connect.
            let jump: String
            /// Path to an identity file. Empty = let libssh2 try the agent +
            /// default identities under ~/.ssh.
            let identityFile: String
            /// SSH keepalive interval; 0 uses libghostty default (15 s).
            let keepaliveIntervalMs: UInt32
            /// Reconnect attempts after an unexpected drop. 0 disables auto-
            /// reconnect entirely; UINT32_MAX gives the libghostty default.
            let maxReconnectAttempts: UInt32
            /// Initial backoff; doubles per attempt, capped at 60 s. 0 uses
            /// libghostty default (1000 ms).
            let reconnectIntervalMs: UInt32
            /// Soft cap on per-surface scrollback bytes; 0 = daemon default.
            let scrollbackLimitBytes: UInt32

            init(
                target: String,
                jump: String = "",
                identityFile: String = "",
                keepaliveIntervalMs: UInt32 = 0,
                maxReconnectAttempts: UInt32 = .max,
                reconnectIntervalMs: UInt32 = 0,
                scrollbackLimitBytes: UInt32 = 0
            ) {
                self.target = target
                self.jump = jump
                self.identityFile = identityFile
                self.keepaliveIntervalMs = keepaliveIntervalMs
                self.maxReconnectAttempts = maxReconnectAttempts
                self.reconnectIntervalMs = reconnectIntervalMs
                self.scrollbackLimitBytes = scrollbackLimitBytes
            }
        }

        // MARK: Public surface

        /// All connection state transitions, including the initial `connecting`.
        let state: AsyncStream<ConnectionState>

        /// The most recent state snapshot. Read this on `MainActor` for a
        /// stable value; off-actor reads are safe but may observe a value
        /// that was just superseded.
        @MainActor private(set) var currentState: ConnectionState = .connecting

        /// Combine bridge over `state`. Drains the `AsyncStream` in a
        /// detached task and republishes via a `CurrentValueSubject` so
        /// consumers always see a value on subscribe.
        var connectionStatePublisher: AnyPublisher<ConnectionState, Never> {
            stateSubject.eraseToAnyPublisher()
        }

        // MARK: Internal storage

        let handle: ghostty_ssh_t
        let stateContinuation: AsyncStream<ConnectionState>.Continuation
        let stateSubject: CurrentValueSubject<ConnectionState, Never>
        let hostKeyHandler: HostKeyHandler
        let mailbox: ConnectionMailbox

        /// Strong-ref box backing the C userdata pointer. Held by `self` —
        /// released in `deinit` after the C handle is freed so trampolines
        /// can no longer fire.
        let userdataBox: ConnectionBox

        // MARK: Init

        init(config: Config, hostKey: HostKeyHandler = .strict, app: ghostty_app_t) async throws {
            self.hostKeyHandler = hostKey
            self.mailbox = ConnectionMailbox()
            self.stateSubject = CurrentValueSubject(.connecting)

            var stateCont: AsyncStream<ConnectionState>.Continuation!
            self.state = AsyncStream<ConnectionState>(bufferingPolicy: .unbounded) { stateCont = $0 }
            self.stateContinuation = stateCont

            let box = ConnectionBox()
            self.userdataBox = box

            // Stage the C config + callbacks. String fields are borrowed for
            // the duration of ghostty_ssh_open only; libghostty copies before
            // returning, so the .withCString chain below is sufficient.
            let handle: ghostty_ssh_t? = config.target.withCString { targetPtr in
                config.jump.withCString { jumpPtr in
                    config.identityFile.withCString { identityPtr in
                        var cCfg = ghostty_ssh_config_t(
                            target: targetPtr,
                            jump: config.jump.isEmpty ? nil : jumpPtr,
                            identity_file: config.identityFile.isEmpty ? nil : identityPtr,
                            keepalive_interval_ms: config.keepaliveIntervalMs,
                            max_reconnect_attempts: config.maxReconnectAttempts,
                            reconnect_interval_ms: config.reconnectIntervalMs,
                            host_key_policy: hostKey.cPolicy,
                            scrollback_limit_bytes: config.scrollbackLimitBytes
                        )
                        var cbs = ghostty_ssh_callbacks_t(
                            on_state: SSHConnection.cOnState,
                            on_host_key: SSHConnection.cOnHostKey,
                            userdata: Unmanaged.passUnretained(box).toOpaque()
                        )
                        return ghostty_ssh_open(app, &cCfg, &cbs)
                    }
                }
            }

            guard let h = handle else {
                stateContinuation.finish()
                throw SSHError.openFailed
            }
            self.handle = h
            box.attach(self)

            // Suspend until the connection reaches `connected` or terminates.
            // The trampoline yields each transition through `state` *and*
            // notifies the mailbox; we await the mailbox for the resolution.
            try await mailbox.awaitInitialConnect()
        }

        deinit {
            // Detach the box first so any in-flight trampolines become no-ops
            // (the weak ref is cleared before the C handle goes away).
            userdataBox.detach()
            stateContinuation.finish()
            let h = handle
            Task.detached {
                ghostty_ssh_close(h)
                ghostty_ssh_free(h)
            }
        }

        // MARK: Public API

        /// Open a typed channel. Returns once the open is in-flight; subscribe
        /// to the channel's `events` stream for the `opened` event.
        func openChannel<S: ChannelService>(_ service: S) async throws -> SSHChannel<S> {
            let params = service.encodeParams()

            // Construct the wrapper + box up front and wire the box to the
            // wrapper's continuations BEFORE the C open call returns — that
            // way any callback that fires immediately after open finds an
            // attached forwarder.
            let channel = SSHChannel<S>(service: service)
            let channelBox = ChannelBox()
            channelBox.attach(channel)
            // The channel retains the box for the duration of the C handle's
            // life so passUnretained is safe.
            channel.userdataBox = channelBox

            let cHandle: ghostty_channel_t? = params.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                var cbs = ghostty_channel_callbacks_t(
                    on_opened: SSHConnection.cOnChannelOpened,
                    on_data: SSHConnection.cOnChannelData,
                    on_window_credit: SSHConnection.cOnChannelWindowCredit,
                    on_eof: SSHConnection.cOnChannelEOF,
                    on_close: SSHConnection.cOnChannelClose,
                    userdata: Unmanaged.passUnretained(channelBox).toOpaque()
                )
                return ghostty_ssh_open_channel(
                    handle,
                    service.cService,
                    raw.baseAddress,
                    raw.count,
                    &cbs
                )
            }

            guard let h = cHandle else {
                channelBox.detach()
                throw SSHError.channelOpenFailed
            }
            channel.handle = h
            return channel
        }

        /// Attach (or re-attach) a terminal surface over this connection.
        /// Pass `nil` for either UUID to let libghostty generate one.
        func attachSurface(
            groupID: UUID?,
            surfaceID: UUID?,
            size: TerminalSize,
            label: String
        ) async throws -> SSHChannel<TerminalService> {
            let channel = SSHChannel<TerminalService>(service: TerminalService())
            let channelBox = ChannelBox()
            channelBox.attach(channel)
            channel.userdataBox = channelBox

            let cHandle: ghostty_channel_t? = label.withCString { labelPtr in
                Self.withOptionalUUIDBytes(groupID) { groupPtr in
                    Self.withOptionalUUIDBytes(surfaceID) { surfacePtr in
                        var cbs = ghostty_channel_callbacks_t(
                            on_opened: SSHConnection.cOnChannelOpened,
                            on_data: SSHConnection.cOnChannelData,
                            on_window_credit: SSHConnection.cOnChannelWindowCredit,
                            on_eof: SSHConnection.cOnChannelEOF,
                            on_close: SSHConnection.cOnChannelClose,
                            userdata: Unmanaged.passUnretained(channelBox).toOpaque()
                        )
                        return ghostty_ssh_attach_surface(
                            handle,
                            groupPtr,
                            surfacePtr,
                            size.rows,
                            size.cols,
                            size.widthPx,
                            size.heightPx,
                            labelPtr,
                            &cbs
                        )
                    }
                }
            }
            guard let h = cHandle else {
                channelBox.detach()
                throw SSHError.channelOpenFailed
            }
            channel.handle = h
            return channel
        }

        func listSessions() async throws -> [SessionListEntry] {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[SessionListEntry], Swift.Error>) in
                let collector = SessionListCollector(continuation: cont)
                let ptr = Unmanaged.passRetained(collector).toOpaque()
                let ok = ghostty_ssh_list_sessions(handle, SSHConnection.cOnSessionEntry, ptr)
                if !ok {
                    // Take it back and drop on the floor.
                    Unmanaged<SessionListCollector>.fromOpaque(ptr).release()
                    cont.resume(throwing: SSHError.notReady)
                }
            }
        }

        func requestReconnect() {
            ghostty_ssh_request_reconnect(handle)
        }

        func cancelReconnect() {
            ghostty_ssh_cancel_reconnect(handle)
        }

        // MARK: Helpers

        /// Run `body` with a pointer to the 16 raw bytes of `uuid`, or
        /// `nil` when `uuid` is nil.
        static func withOptionalUUIDBytes<R>(
            _ uuid: UUID?,
            _ body: (UnsafePointer<UInt8>?) -> R
        ) -> R {
            guard let u = uuid else { return body(nil) }
            var bytes = u.uuid
            return withUnsafeBytes(of: &bytes) { raw in
                body(raw.baseAddress!.assumingMemoryBound(to: UInt8.self))
            }
        }

        // MARK: Trampoline-internal state dispatch

        /// Called from the `on_state` trampoline (off-actor thread). Emits to
        /// every channel: `state` stream, `currentState`, Combine subject,
        /// and the mailbox. Allocates closures here so the C-side opaque
        /// tokens never leak into the public state value.
        func emitState(_ state: ConnectionState) {
            stateContinuation.yield(state)
            stateSubject.send(state)
            Task { @MainActor in
                self.currentState = state
            }
            Task { await self.mailbox.deliver(state) }
        }
    }
}

// MARK: - Mailbox actor

/// Bookkeeping actor used by `SSHConnection` to track the initial-connect
/// continuation. Kept private because it has no public surface.
actor ConnectionMailbox {
    private var initialContinuation: CheckedContinuation<Void, Swift.Error>?
    private var resolved: Bool = false
    private var resolvedError: Swift.Error?

    func awaitInitialConnect() async throws {
        if resolved {
            if let e = resolvedError { throw e }
            return
        }
        try await withCheckedThrowingContinuation { cont in
            self.initialContinuation = cont
        }
    }

    func deliver(_ state: Ghostty.ConnectionState) {
        guard !resolved else { return }
        switch state {
        case .connected:
            resolved = true
            initialContinuation?.resume()
            initialContinuation = nil
        case .failed(let f):
            resolved = true
            resolvedError = Ghostty.SSHError.connectionTerminated
            _ = f
            initialContinuation?.resume(throwing: Ghostty.SSHError.connectionTerminated)
            initialContinuation = nil
        case .disconnected:
            resolved = true
            resolvedError = Ghostty.SSHError.connectionTerminated
            initialContinuation?.resume(throwing: Ghostty.SSHError.connectionTerminated)
            initialContinuation = nil
        default:
            break
        }
    }
}

// MARK: - Session list collector

/// Holds the pending `listSessions` continuation + accumulating entries.
/// Lives as long as one libghostty session-list query.
final class SessionListCollector {
    var entries: [Ghostty.SessionListEntry] = []
    let continuation: CheckedContinuation<[Ghostty.SessionListEntry], Swift.Error>

    init(continuation: CheckedContinuation<[Ghostty.SessionListEntry], Swift.Error>) {
        self.continuation = continuation
    }
}

