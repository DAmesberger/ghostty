import Foundation
import Combine
import GhosttyKit

// TODO(phase-6C): widen these SSH wrapper types to `public` once cmux is
// ready to consume them via `import Ghostty`. That uplift has to be
// coordinated module-wide because the `Ghostty` namespace itself is
// internal and so are the existing Ghostty.App / Surface / Config /
// SurfaceView types cmux already imports today. The widening is
// deferred from 6B.2 into 6C precisely so the namespace + adjacent-type
// public-uplift can land as one atomic change rather than half-public,
// half-internal partial states.

extension Ghostty {
    /// A single multiplexed SSH connection to one remote host.
    ///
    /// Wraps `ghostty_ssh_t`. The initializer is synchronous and returns as
    /// soon as the C-side handle is allocated and the initial CONNECTING
    /// state is emitted — embedders observe every subsequent transition
    /// (including `passwordRequired`, `uploading`, `connected`) by iterating
    /// `state` (AsyncStream) or subscribing to `connectionStatePublisher`
    /// (Combine).
    ///
    /// Threading: all C callbacks fire on libghostty worker threads. The
    /// wrapper hops every callback through `AsyncStream` continuations and
    /// `MainActor`-isolated property updates, so the public API can be
    /// called from any concurrency context.
    public final class SSHConnection: @unchecked Sendable {
        // MARK: Configuration

        public struct Config: Sendable {
            /// "user@host[:port]".
            public let target: String
            /// Comma-separated jump-host chain. Empty = direct connect.
            public let jump: String
            /// Path to an identity file. Empty = let libssh2 try the agent +
            /// default identities under ~/.ssh.
            public let identityFile: String
            /// SSH keepalive interval; 0 uses libghostty default (15 s).
            public let keepaliveIntervalMs: UInt32
            /// Reconnect attempts after an unexpected drop. 0 disables auto-
            /// reconnect entirely; UINT32_MAX gives the libghostty default.
            public let maxReconnectAttempts: UInt32
            /// Initial backoff; grows per attempt (capped by
            /// `reconnectMaxIntervalMs`). 0 uses libghostty default (1000 ms).
            public let reconnectIntervalMs: UInt32
            /// Soft cap on per-surface scrollback bytes; 0 = daemon default.
            public let scrollbackLimitBytes: UInt32
            /// Ceiling on a single reconnect backoff sleep, in milliseconds.
            /// Combine with `maxReconnectAttempts: .max` for "patient but
            /// persistent" reconnect. 0 uses libghostty default (30 000 ms).
            public let reconnectMaxIntervalMs: UInt32

            public init(
                target: String,
                jump: String = "",
                identityFile: String = "",
                keepaliveIntervalMs: UInt32 = 0,
                maxReconnectAttempts: UInt32 = .max,
                reconnectIntervalMs: UInt32 = 0,
                scrollbackLimitBytes: UInt32 = 0,
                reconnectMaxIntervalMs: UInt32 = 0
            ) {
                self.target = target
                self.jump = jump
                self.identityFile = identityFile
                self.keepaliveIntervalMs = keepaliveIntervalMs
                self.maxReconnectAttempts = maxReconnectAttempts
                self.reconnectIntervalMs = reconnectIntervalMs
                self.scrollbackLimitBytes = scrollbackLimitBytes
                self.reconnectMaxIntervalMs = reconnectMaxIntervalMs
            }
        }

        // MARK: Public surface

        /// All connection state transitions, including the initial `connecting`.
        public let state: AsyncStream<ConnectionState>

        /// Delivers channels that the daemon opened toward the client, e.g.
        /// port_listener accepts. Each `InboundChannel` value must be either
        /// accepted (by calling `accept(as:)`) or rejected (by calling
        /// `reject()`) before iterating the next element — the mux blocks
        /// acceptance of the next inbound open until the embedder decides.
        ///
        /// The stream finishes when the connection is deallocated.
        public let inboundChannels: AsyncStream<InboundChannel>

        /// The most recent state snapshot. Read this on `MainActor` for a
        /// stable value; off-actor reads are safe but may observe a value
        /// that was just superseded.
        @MainActor public private(set) var currentState: ConnectionState = .connecting

        /// Combine bridge over `state`. The subject is fed alongside the
        /// `AsyncStream` so consumers always see a value on subscribe.
        public var connectionStatePublisher: AnyPublisher<ConnectionState, Never> {
            stateSubject.eraseToAnyPublisher()
        }

        // MARK: Internal storage

        /// Backing C handle. Stamped in after `ghostty_ssh_open` returns.
        /// `var ... ?` (not `let`) because the `userdata` box must be
        /// attached to `self` BEFORE `ghostty_ssh_open` is called — the
        /// stub-path open emits the initial CONNECTING state synchronously
        /// from inside `ghostty_ssh_open`, so the trampoline must already
        /// resolve back to this connection by the time the call returns.
        /// Read through `requireHandle()`.
        var handle: ghostty_ssh_t?
        let stateContinuation: AsyncStream<ConnectionState>.Continuation
        let stateSubject: CurrentValueSubject<ConnectionState, Never>
        let hostKeyHandler: HostKeyHandler
        let inboundContinuation: AsyncStream<InboundChannel>.Continuation

        /// Strong-ref box backing the C userdata pointer. Held by `self` —
        /// released in `deinit` after the C handle is freed so trampolines
        /// can no longer fire.
        let userdataBox: ConnectionBox

        /// Serial queue for libghostty C cleanup of this connection AND all
        /// its channels. Channels reach it via their `connection` strong
        /// reference (`SSHChannel.connection`). FIFO ordering combined with
        /// the channel-retains-connection ARC chain guarantees every
        /// `ghostty_channel_free` enqueued by an `SSHChannel.deinit` runs
        /// before the `ghostty_ssh_close`+`_free` enqueued by this
        /// connection's deinit — which is the invariant the Zig side
        /// asserts at `ssh_capi.zig:1604-1611` (`ghostty_ssh_free`'s
        /// "live channels" check). Per-connection rather than module-wide
        /// so a slow close of one host doesn't stall cleanup of another.
        let cleanupQueue = DispatchQueue(
            label: "com.ghostty.ssh.connection.cleanup",
            qos: .utility
        )

        // MARK: Init

        /// Open an SSH connection. Returns immediately once `ghostty_ssh_open`
        /// has installed the C-side handle and emitted the initial CONNECTING
        /// state. Embedders MUST consume `state` (or `connectionStatePublisher`)
        /// to observe transitions — including `passwordRequired`, whose
        /// callbacks need to fire before `connected` is reachable, which
        /// rules out a blocking "await connected" init.
        ///
        /// `app` is optional: passing `nil` keeps libghostty on its
        /// no-CoreApp stub path (synchronous CONNECTING emit, no real
        /// `SshConnectionManager`), which is what unit tests exercise.
        /// Production callers always pass a real `ghostty_app_t`.
        public init(config: Config, hostKey: HostKeyHandler = .strict, app: ghostty_app_t?) throws {
            self.hostKeyHandler = hostKey
            self.stateSubject = CurrentValueSubject(.connecting)
            self.handle = nil

            var stateCont: AsyncStream<ConnectionState>.Continuation!
            self.state = AsyncStream<ConnectionState>(bufferingPolicy: .unbounded) { stateCont = $0 }
            self.stateContinuation = stateCont

            var inboundCont: AsyncStream<InboundChannel>.Continuation!
            self.inboundChannels = AsyncStream<InboundChannel>(bufferingPolicy: .unbounded) {
                inboundCont = $0
            }
            self.inboundContinuation = inboundCont

            let box = ConnectionBox()
            self.userdataBox = box

            // CRITICAL ordering: attach the box to `self` BEFORE calling
            // ghostty_ssh_open. The stub-path open (app == nil) emits the
            // initial CONNECTING state synchronously, from inside
            // ghostty_ssh_open, by calling the on_state trampoline. That
            // trampoline resolves `self` from the box — so the box must
            // already be wired up, or the first state transition is lost.
            box.attach(self)

            // Stage the C config + callbacks. String fields are borrowed for
            // the duration of ghostty_ssh_open only; libghostty copies before
            // returning, so the .withCString chain below is sufficient.
            let opened: ghostty_ssh_t? = config.target.withCString { targetPtr in
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
                            scrollback_limit_bytes: config.scrollbackLimitBytes,
                            reconnect_max_interval_ms: config.reconnectMaxIntervalMs
                        )
                        var cbs = ghostty_ssh_callbacks_t(
                            on_state: SSHConnection.cOnState,
                            on_host_key: SSHConnection.cOnHostKey,
                            on_inbound_channel: SSHConnection.cOnInboundChannel,
                            userdata: Unmanaged.passUnretained(box).toOpaque()
                        )
                        return ghostty_ssh_open(app, &cCfg, &cbs)
                    }
                }
            }

            guard let h = opened else {
                box.detach()
                stateContinuation.finish()
                throw SSHError.openFailed
            }
            self.handle = h
            // ghostty_ssh_open synchronously emits the initial CONNECTING
            // state before returning, so by the time we reach here it has
            // already been yielded into `state`.
        }

        deinit {
            // Detach the box first so any in-flight trampolines become no-ops
            // (the weak ref is cleared before the C handle goes away).
            userdataBox.detach()
            stateContinuation.finish()
            inboundContinuation.finish()
            // `handle` is nil only when init threw before ghostty_ssh_open
            // succeeded — in that case there is nothing to free and the
            // handle counter was never incremented.
            guard let h = handle else { return }
            // Capture the userdata box strongly so it outlives the C teardown
            // below. `ghostty_ssh_close`/`_free` are what unregister the state
            // listener, so a worker-thread state callback can still be mid-
            // flight invoking the trampoline on the box until they return. If
            // the box were released the moment deinit returns (it is a `let`
            // on `self`, otherwise dropped here), that in-flight trampoline
            // would dereference freed memory. `detach()` above only clears the
            // weak back-ref; the box object itself must stay alive.
            let box = userdataBox
            // Dispatch onto the shared serial cleanup queue rather than an
            // unordered `Task.detached`. By ARC: every `SSHChannel<_>`
            // referencing this connection has already deinit'd (because each
            // strongly retains `self` via `SSHChannel.connection`), and each
            // of those deinits enqueued its `ghostty_channel_free` onto the
            // same queue. FIFO ordering on the serial queue therefore
            // guarantees `h.channels.count() == 0` when this block runs.
            cleanupQueue.async {
                ghostty_ssh_close(h)
                ghostty_ssh_free(h)
                // Keep the box alive until after the C handle is closed+freed
                // (which unregisters the listener); only then can no further
                // trampoline fire on it.
                _ = box
            }
        }

        // MARK: Public API

        /// The C handle, asserted non-nil. Init stamps `handle` before it
        /// returns successfully, so every externally-reachable method sees
        /// a bound handle — a nil here is a programmer error in this file,
        /// not a recoverable runtime condition.
        private func requireHandle() -> ghostty_ssh_t {
            precondition(handle != nil, "SSHConnection used before handle was bound")
            return handle!
        }

        /// Open a typed channel. Returns once the C-side open call is in-
        /// flight; subscribe to the channel's `events` stream for the
        /// `opened` event (success) or `closed` event (failure).
        public func openChannel<S: ChannelService>(_ service: S) throws -> SSHChannel<S> {
            let params = try service.encodeParams()

            // Construct the wrapper + box up front and wire the box to the
            // wrapper's continuations BEFORE the C open call returns — that
            // way any callback that fires immediately after open finds an
            // attached forwarder.
            let channel = SSHChannel<S>(service: service, connection: self)
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
                    requireHandle(),
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
        public func attachSurface(
            groupID: UUID?,
            surfaceID: UUID?,
            size: TerminalSize,
            label: String
        ) throws -> SSHChannel<TerminalService> {
            let channel = SSHChannel<TerminalService>(service: TerminalService(), connection: self)
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
                            requireHandle(),
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

        public func listSessions() async throws -> [SessionListEntry] {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[SessionListEntry], Swift.Error>) in
                let collector = SessionListCollector(continuation: cont)
                let ptr = Unmanaged.passRetained(collector).toOpaque()
                let ok = ghostty_ssh_list_sessions(
                    requireHandle(), SSHConnection.cOnSessionEntry, ptr)
                if !ok {
                    // Take it back and drop on the floor.
                    Unmanaged<SessionListCollector>.fromOpaque(ptr).release()
                    cont.resume(throwing: SSHError.notReady)
                }
            }
        }

        public func requestReconnect() {
            ghostty_ssh_request_reconnect(requireHandle())
        }

        public func cancelReconnect() {
            ghostty_ssh_cancel_reconnect(requireHandle())
        }

        /// Rename a remote session. Fire-and-forget; no-op if the session is unknown.
        public func renameSession(groupID: UUID, label: String) {
            var bytes = groupID.uuid
            withUnsafeBytes(of: &bytes) { raw in
                let ptr = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                label.withCString { labelPtr in
                    ghostty_ssh_rename_session(requireHandle(), ptr, labelPtr)
                }
            }
        }

        /// Kill a remote session and all its surfaces. Fire-and-forget; no-op if unknown.
        public func killSession(groupID: UUID) {
            var bytes = groupID.uuid
            withUnsafeBytes(of: &bytes) { raw in
                let ptr = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                ghostty_ssh_kill_session(requireHandle(), ptr)
            }
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

        /// Called from the `on_state` trampoline (off-libghostty thread).
        /// Yields to the AsyncStream + Combine subject and updates the
        /// MainActor snapshot. Allocates closures here so the C-side opaque
        /// tokens never leak into the public state value.
        func emitState(_ state: ConnectionState) {
            stateContinuation.yield(state)
            stateSubject.send(state)
            Task { @MainActor in
                self.currentState = state
            }
        }

        /// Called from the `on_inbound_channel` trampoline. Yields an
        /// `InboundChannel` into `inboundChannels` so the embedder can
        /// accept or reject. Must NOT block — the continuation is
        /// non-blocking (`.unbounded` buffer policy).
        func emitInbound(_ inbound: InboundChannel) {
            inboundContinuation.yield(inbound)
        }
    }

    // MARK: - InboundChannel

    /// A daemon-originated channel delivered via `SSHConnection.inboundChannels`.
    ///
    /// The embedder must call exactly one of `accept(as:)` or `reject()`.
    /// The underlying C handle is valid until one of those methods is called.
    public struct InboundChannel: Sendable {
        /// Raw service id byte from the wire (matches `ghostty_channel_service_e`).
        public let serviceID: UInt8
        /// Service-specific parameter bytes, copied at delivery time.
        public let params: Data

        // State machine: nil = pending, true = accepted, false = rejected.
        // Sendable because UnsafeMutableRawPointer is round-tripped through UInt.
        private let handleBits: UInt
        private let stateMachine: InboundChannelState
        /// Strong ref to the parent connection so the resulting `SSHChannel`
        /// (on `accept`) can inherit it, mirroring the C-side parent-child
        /// lifetime in Swift ARC. The reference also keeps the connection
        /// alive while the inbound is sitting in the `inboundChannels`
        /// AsyncStream waiting for the embedder to decide.
        private let connection: SSHConnection

        init(handleBits: UInt, serviceID: UInt8, params: Data, connection: SSHConnection) {
            self.handleBits = handleBits
            self.serviceID = serviceID
            self.params = params
            self.stateMachine = InboundChannelState()
            self.connection = connection
        }

        /// Accept the channel with an embedder-constructed service descriptor.
        /// Returns `nil` if the service id in `service` doesn't match the
        /// wire `serviceID`, or if the channel was already accepted or rejected.
        ///
        /// Ownership: on success the returned `SSHChannel` takes ownership of
        /// the underlying C handle. On `nil` return the channel is rejected and
        /// freed internally.
        public func accept<S: ChannelService>(using service: S) -> SSHChannel<S>? {
            guard stateMachine.claim() else { return nil }
            // Verify that the service the embedder chose matches the wire service.
            let expectedID = UInt8(service.cService.rawValue)
            guard serviceID == expectedID else {
                let h = ghostty_channel_t(bitPattern: handleBits)
                ghostty_channel_free(h)
                return nil
            }
            let channel = SSHChannel<S>(service: service, connection: connection)
            let channelBox = ChannelBox()
            channelBox.attach(channel)
            channel.userdataBox = channelBox

            let h = ghostty_channel_t(bitPattern: handleBits)
            // Install the Swift callbacks on the pre-allocated C handle so
            // subsequent mux events (data, close, window) route to this box.
            var cbs = ghostty_channel_callbacks_t(
                on_opened: Ghostty.SSHConnection.cOnChannelOpened,
                on_data: Ghostty.SSHConnection.cOnChannelData,
                on_window_credit: Ghostty.SSHConnection.cOnChannelWindowCredit,
                on_eof: Ghostty.SSHConnection.cOnChannelEOF,
                on_close: Ghostty.SSHConnection.cOnChannelClose,
                userdata: Unmanaged.passUnretained(channelBox).toOpaque()
            )
            ghostty_channel_set_callbacks(h, &cbs)
            channel.handle = h
            return channel
        }

        /// Reject the channel. The daemon receives `service_not_supported`.
        public func reject() {
            guard stateMachine.claim() else { return }
            let h = ghostty_channel_t(bitPattern: handleBits)
            ghostty_channel_free(h)
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

// MARK: - InboundChannel state

/// Thread-safe one-shot claim for `InboundChannel.accept/reject`.
final class InboundChannelState: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    /// Returns true and claims on first call; false on every subsequent call.
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}

