import Foundation
import GhosttyKit

// Note: ghostty_ssh_t and ghostty_channel_t share `OpaquePointer` as their
// underlying Swift type with ghostty_surface_t, which is already declared
// `@unchecked Sendable` in GhosttyPackage.swift. The conformance applies
// transitively — no additional declaration here.

extension Ghostty {
    /// A single multiplexed byte stream over an `SSHConnection`, typed by its
    /// `ChannelService`.
    ///
    /// The class is `@unchecked Sendable`: its public `output` / `events`
    /// streams are produced via continuations from the C-callback boundary
    /// (any libghostty worker thread), and `write(_:)` is internally
    /// serialised through a private actor so the credit accounting stays
    /// consistent.
    public final class SSHChannel<S: ChannelService>: @unchecked Sendable {
        // MARK: Public surface

        public let service: S

        public let output: AsyncStream<Data>
        public let events: AsyncStream<Event>

        public enum Event: Sendable {
            /// The peer accepted the open. `serviceAck` is service-defined.
            case opened(serviceAck: Data, initialPeerWindow: UInt32)
            /// Outbound credit was granted by the peer.
            case windowCredit(UInt32)
            /// The peer half-closed; no further `output` data will arrive.
            case eof
            /// Terminal — the channel is dead. `wasTransport` is true when the
            /// underlying SSH connection dropped and the channel will (for
            /// terminal services) be auto-reopened.
            case closed(reason: CloseReason, message: String?, wasTransport: Bool)
        }

        public enum CloseReason: Sendable {
            case normal
            case peerReset
            case serviceError
            case policyDenied
            case idleTimeout
            case daemonShutdown
            case transport
            case unknown

            static func from(_ c: ghostty_channel_close_reason_e) -> CloseReason {
                switch c {
                case GHOSTTY_CHANNEL_CLOSE_NORMAL: return .normal
                case GHOSTTY_CHANNEL_CLOSE_PEER_RESET: return .peerReset
                case GHOSTTY_CHANNEL_CLOSE_SERVICE_ERROR: return .serviceError
                case GHOSTTY_CHANNEL_CLOSE_POLICY_DENIED: return .policyDenied
                case GHOSTTY_CHANNEL_CLOSE_IDLE_TIMEOUT: return .idleTimeout
                case GHOSTTY_CHANNEL_CLOSE_DAEMON_SHUTDOWN: return .daemonShutdown
                case GHOSTTY_CHANNEL_CLOSE_TRANSPORT: return .transport
                default: return .unknown
                }
            }
        }

        // MARK: Internal storage

        /// Backing C handle. Stamped in by `SSHConnection.openChannel` /
        /// `attachSurface` after the wrapper is wired up but before it
        /// returns to the embedder. Read via the `requireHandle` helper —
        /// the only path that observes nil is the brief window inside
        /// `openChannel` itself, where nothing public can touch the wrapper.
        var handle: ghostty_channel_t?

        let outputContinuation: AsyncStream<Data>.Continuation
        let eventContinuation: AsyncStream<Event>.Continuation

        /// Backpressure / write state. All mutations are serialised through
        /// the actor — callers go through `write(_:)` which awaits it.
        let state: ChannelState

        /// Strong reference to the box backing the C `userdata` pointer.
        /// Kept here so the box outlives the C handle; cleared in `deinit`
        /// after the handle is freed.
        var userdataBox: ChannelBox?

        // MARK: Init

        /// Internal — only `SSHConnection` constructs channels.
        init(service: S) {
            self.handle = nil
            self.service = service

            var outCont: AsyncStream<Data>.Continuation!
            self.output = AsyncStream<Data>(bufferingPolicy: .unbounded) { outCont = $0 }
            self.outputContinuation = outCont

            var evtCont: AsyncStream<Event>.Continuation!
            self.events = AsyncStream<Event>(bufferingPolicy: .unbounded) { evtCont = $0 }
            self.eventContinuation = evtCont

            self.state = ChannelState()
        }

        deinit {
            // Detach the box first so any in-flight trampoline becomes a
            // no-op before the C handle is freed.
            userdataBox?.detach()

            // Tear down streams so consumers see the end-of-stream sentinel
            // even if the channel was dropped without an explicit close.
            outputContinuation.finish()
            eventContinuation.finish()

            // Free is safe to call after close; libghostty handles both.
            guard let h = handle else { return }
            Task.detached {
                ghostty_channel_free(h)
            }
        }

        private func requireHandle() -> ghostty_channel_t {
            // openChannel always stamps the handle before publishing the
            // wrapper, so this is non-nil for any externally visible call.
            // We force-unwrap with a precondition rather than throwing because
            // a nil here is a programmer error in this file, not a runtime
            // condition embedders can recover from.
            precondition(handle != nil, "SSHChannel used before handle was bound")
            return handle!
        }

        // MARK: Public API

        /// Write `data` to the remote end. Implements backpressure internally
        /// via window-credit events — callers see plain `async throws` with
        /// no manual accounting.
        ///
        /// Throws `Ghostty.SSHError.channelClosed` if the channel is closed or
        /// closes during the write.
        public func write(_ data: Data) async throws {
            guard !data.isEmpty else { return }
            let h = requireHandle()

            var offset = 0
            let total = data.count
            while offset < total {
                // Wait until we have at least *some* credit to spend.
                try await state.awaitCredit()

                // Snapshot the credit available right now, then attempt a
                // write up to that many bytes.
                let attempt = await state.takeCredit(max: total - offset)
                if attempt == 0 { continue }

                let written = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Int in
                    let base = raw.baseAddress!.advanced(by: offset)
                    let n = ghostty_channel_write(h, base, attempt)
                    return n
                }

                if written == .max {  // SIZE_MAX → terminal error
                    throw Ghostty.SSHError.channelClosed
                }

                // Refund any unused portion of the credit we held.
                if written < attempt {
                    await state.refundCredit(attempt - written)
                }

                offset += written
            }
        }

        /// Half-close the local end of the channel.
        public func sendEOF() {
            ghostty_channel_eof(requireHandle())
        }

        /// Close the channel with a NORMAL reason. The `closed` event will
        /// arrive on `events` after the close round-trip.
        public func close() {
            ghostty_channel_close(requireHandle(), GHOSTTY_CHANNEL_CLOSE_NORMAL)
        }
    }
}

// MARK: - Backpressure actor

/// Tracks the outbound credit window for a single channel.
///
/// libghostty's `on_window_credit` callback delivers additional credit; we
/// add to `credit` and signal any waiters. `write()` consumes credit via
/// `takeCredit(max:)`, refunding the unused portion when the C write returns
/// less than we asked for.
final actor ChannelState {
    private var credit: Int = 0
    private var closed: Bool = false
    private var waiters: [CheckedContinuation<Void, Swift.Error>] = []

    /// Suspend until `credit > 0` or the channel closes.
    func awaitCredit() async throws {
        if closed { throw Ghostty.SSHError.channelClosed }
        if credit > 0 { return }
        try await withCheckedThrowingContinuation { cont in
            waiters.append(cont)
        }
    }

    /// Reserve up to `max` bytes of credit. Returns the actual amount taken.
    func takeCredit(max: Int) -> Int {
        let take = Swift.min(credit, max)
        credit -= take
        return take
    }

    /// Return unused credit back to the pool (and re-wake one waiter if it
    /// changed the boundary).
    func refundCredit(_ n: Int) {
        if n <= 0 { return }
        credit += n
        wakeOne()
    }

    /// Called from the `on_window_credit` trampoline. Adds bytes and wakes
    /// pending writers.
    func grant(_ n: UInt32) {
        credit += Int(n)
        wakeAll()
    }

    /// Called from the `on_close` trampoline. Aborts every pending writer.
    func markClosed() {
        if closed { return }
        closed = true
        let pending = waiters
        waiters.removeAll()
        for w in pending { w.resume(throwing: Ghostty.SSHError.channelClosed) }
    }

    private func wakeOne() {
        if waiters.isEmpty { return }
        let w = waiters.removeFirst()
        w.resume()
    }

    private func wakeAll() {
        if waiters.isEmpty { return }
        let pending = waiters
        waiters.removeAll()
        for w in pending { w.resume() }
    }
}
