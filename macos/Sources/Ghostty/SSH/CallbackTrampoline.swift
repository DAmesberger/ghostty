import Foundation
import GhosttyKit

// =====================================================================
// C ABI trampolines: bridges from libghostty worker threads into the
// Swift SSH wrapper.
//
// Design:
//
// * The C `userdata` field carries `Unmanaged<Box>.toOpaque()` where the
//   box is a class holding a `weak` reference to the owning wrapper
//   (`SSHConnection` or `SSHChannel<S>`). Using `passUnretained` keeps
//   the C side from artificially extending the wrapper's lifetime — the
//   wrapper is the lifetime root.
// * The wrapper owns the box; `deinit` calls `box.detach()` first, so any
//   in-flight callback that fires after free sees a `nil` weak ref and
//   becomes a no-op. Boxes are heap-allocated so their address stays
//   stable for the lifetime of the C handle.
// * Trampolines never block the C thread. They memcpy callback buffers
//   immediately into Swift-owned storage, then yield to continuations
//   (non-blocking) or hop into a `Task` for actor calls.
// =====================================================================

// MARK: - Userdata boxes

/// Backing-storage class held in `ghostty_ssh_callbacks_t.userdata`.
/// Holds a `weak` reference to the connection wrapper.
final class ConnectionBox: @unchecked Sendable {
    private let lock = NSLock()
    private weak var connection: Ghostty.SSHConnection?

    func attach(_ c: Ghostty.SSHConnection) {
        lock.lock(); defer { lock.unlock() }
        connection = c
    }

    func detach() {
        lock.lock(); defer { lock.unlock() }
        connection = nil
    }

    func resolved() -> Ghostty.SSHConnection? {
        lock.lock(); defer { lock.unlock() }
        return connection
    }
}

/// Backing-storage class held in `ghostty_channel_callbacks_t.userdata`.
///
/// The trampoline doesn't know `S`, so the box hides the typed event
/// continuation behind a closure installed at `attach` time. All access
/// is serialised through `lock` so concurrent C callbacks + the wrapper's
/// `deinit` race safely.
final class ChannelBox: @unchecked Sendable {
    private let lock = NSLock()
    /// Holds a strong reference to the channel only via these three fields;
    /// we keep them nil-able so `detach()` can drop the references and
    /// stop forwarding once the wrapper's `deinit` runs.
    private var outputCont: AsyncStream<Data>.Continuation?
    private var eventForwarder: ((TypeErasedChannelEvent) -> Void)?
    private var state: ChannelState?

    func attach<S: Ghostty.ChannelService>(_ c: Ghostty.SSHChannel<S>) {
        let outCont = c.outputContinuation
        let evtCont = c.eventContinuation
        let forwarder: (TypeErasedChannelEvent) -> Void = { ev in
            evtCont.yield(ev.translated(for: S.self))
        }
        lock.lock()
        outputCont = outCont
        eventForwarder = forwarder
        state = c.state
        lock.unlock()
    }

    func detach() {
        lock.lock()
        outputCont?.finish()
        outputCont = nil
        eventForwarder = nil
        state = nil
        lock.unlock()
    }

    func yieldOutput(_ data: Data) {
        lock.lock(); let cont = outputCont; lock.unlock()
        cont?.yield(data)
    }

    func yieldEvent(_ ev: TypeErasedChannelEvent) {
        lock.lock(); let fwd = eventForwarder; lock.unlock()
        fwd?(ev)
    }

    func finishOutput() {
        lock.lock(); let cont = outputCont; outputCont = nil; lock.unlock()
        cont?.finish()
    }

    /// Drop both streams atomically. Used from on_close.
    func finishAll() {
        lock.lock()
        outputCont?.finish()
        outputCont = nil
        eventForwarder = nil
        lock.unlock()
    }

    func resolvedState() -> ChannelState? {
        lock.lock(); defer { lock.unlock() }
        return state
    }
}

/// Type-erased channel event payload. The box's installed forwarder
/// translates this into the generic `SSHChannel<S>.Event` before yielding.
struct TypeErasedChannelEvent: Sendable {
    let payload: Payload

    enum Payload: Sendable {
        case opened(serviceAck: Data, initialPeerWindow: UInt32)
        case windowCredit(UInt32)
        case eof
        case closed(reason: ghostty_channel_close_reason_e, message: String?)
    }

    func translated<S: Ghostty.ChannelService>(for: S.Type) -> Ghostty.SSHChannel<S>.Event {
        switch payload {
        case .opened(let ack, let win):
            return .opened(serviceAck: ack, initialPeerWindow: win)
        case .windowCredit(let n):
            return .windowCredit(n)
        case .eof:
            return .eof
        case .closed(let reason, let message):
            return .closed(
                reason: Ghostty.SSHChannel<S>.CloseReason.from(reason),
                message: message,
                wasTransport: reason == GHOSTTY_CHANNEL_CLOSE_TRANSPORT
            )
        }
    }
}

// MARK: - SSHConnection callbacks

extension Ghostty.SSHConnection {

    static let cOnState: @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<ghostty_ssh_state_t>?
    ) -> Void = { userdata, statePtr in
        guard let ud = userdata, let s = statePtr?.pointee else { return }
        let box = Unmanaged<ConnectionBox>.fromOpaque(ud).takeUnretainedValue()
        guard let conn = box.resolved() else { return }
        let translated = translate(state: s, connection: conn)
        // Hop off the C worker thread. `emitState` is safe to call from
        // any thread; the actor + MainActor hops happen inside it.
        conn.emitState(translated)
    }

    static let cOnHostKey: @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<ghostty_ssh_host_key_t>?
    ) -> Void = { userdata, hkPtr in
        guard let ud = userdata, let hk = hkPtr?.pointee else { return }
        let box = Unmanaged<ConnectionBox>.fromOpaque(ud).takeUnretainedValue()
        guard let conn = box.resolved() else { return }

        let host = hk.host.map { String(cString: $0) } ?? ""
        let fp = hk.fingerprint_sha256.map { String(cString: $0) } ?? ""
        let kt = hk.key_type.map { String(cString: $0) } ?? ""
        let token = hk.decision_token
        // Capture the handle as a UInt bit pattern — UnsafeMutableRawPointer
        // is intentionally non-Sendable in stdlib, so we round-trip through
        // an integer to stay clean under strict concurrency.
        let handleBits = UInt(bitPattern: conn.handle)

        let challenge = Ghostty.HostKeyChallenge(
            host: host,
            fingerprintSHA256: fp,
            keyType: kt,
            knownMatch: hk.known_match,
            knownMismatch: hk.known_mismatch,
            submit: { accept, persist in
                let h = ghostty_ssh_t(bitPattern: handleBits)
                ghostty_ssh_submit_host_key_decision(h, token, accept, persist)
            }
        )

        switch conn.hostKeyHandler {
        case .strict:
            challenge.submit(challenge.knownMatch, false)
        case .tofu:
            challenge.submit(!challenge.knownMismatch, true)
        case .insecure:
            challenge.submit(true, true)
        case .interactive(let handler):
            handler(challenge)
        }
    }

    /// Translate a C state struct into the Swift enum. Allocates closures
    /// for `passwordRequired` that capture the handle + token.
    static func translate(
        state: ghostty_ssh_state_t,
        connection: Ghostty.SSHConnection
    ) -> Ghostty.ConnectionState {
        switch state.kind {
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
            let p = state.payload.password
            let host = p.host.map { String(cString: $0) } ?? ""
            let token = p.auth_token
            let handleBits = UInt(bitPattern: connection.handle)
            return .passwordRequired(.init(
                isJump: p.is_jump,
                host: host,
                submit: { pw in
                    let h = ghostty_ssh_t(bitPattern: handleBits)
                    pw.withCString { ptr in
                        ghostty_ssh_submit_password(h, token, ptr)
                    }
                },
                cancel: {
                    let h = ghostty_ssh_t(bitPattern: handleBits)
                    ghostty_ssh_cancel_password(h, token)
                }
            ))
        case GHOSTTY_SSH_STATE_UPLOADING:
            let u = state.payload.upload
            return .uploading(.init(
                bytesSent: u.bytes_sent,
                totalBytes: u.total_bytes,
                source: Ghostty.ConnectionState.ProvisionSource.from(u.source)
            ))
        case GHOSTTY_SSH_STATE_RECONNECTING:
            let r = state.payload.reconnect
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
            let f = state.payload.fail
            let msg = f.message.map { String(cString: $0) }
            return .failed(.init(
                reason: Ghostty.ConnectionState.Failure.Reason.from(f.reason),
                message: msg
            ))
        case GHOSTTY_SSH_STATE_DISCONNECTED:
            let d = state.payload.disconnect
            return .disconnected(.init(
                attemptsMade: d.attempts_made,
                reason: Ghostty.ConnectionState.Disconnect.Reason.from(d.reason)
            ))
        default:
            return .connecting
        }
    }

    // MARK: - Session list callback

    static let cOnSessionEntry: @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<ghostty_ssh_session_entry_t>?
    ) -> Void = { userdata, entryPtr in
        guard let ud = userdata else { return }
        // entry == NULL signals completion; reclaim the retained box.
        guard let entry = entryPtr?.pointee else {
            let collector = Unmanaged<SessionListCollector>.fromOpaque(ud).takeRetainedValue()
            collector.continuation.resume(returning: collector.entries)
            return
        }
        let collector = Unmanaged<SessionListCollector>.fromOpaque(ud).takeUnretainedValue()
        let groupID: UUID = entry.group_id.map { ptr in
            var bytes = uuid_t(
                ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7],
                ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]
            )
            return UUID(uuid: bytes)
        } ?? UUID()
        let label = entry.label.map { String(cString: $0) } ?? ""
        let created = Date(timeIntervalSince1970: Double(entry.created_at_ns) / 1_000_000_000)
        collector.entries.append(Ghostty.SessionListEntry(
            groupID: groupID,
            label: label,
            surfaceCount: entry.surface_count,
            createdAt: created
        ))
    }

    // MARK: - Channel callbacks (single set, dispatched via ChannelBox)

    static let cOnChannelOpened: @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeRawPointer?,
        Int,
        UInt32
    ) -> Void = { userdata, ackPtr, ackLen, peerWindow in
        guard let ud = userdata else { return }
        let box = Unmanaged<ChannelBox>.fromOpaque(ud).takeUnretainedValue()
        let ack: Data
        if let p = ackPtr, ackLen > 0 {
            ack = Data(bytes: p, count: ackLen)
        } else {
            ack = Data()
        }
        // Channel opens with `initialPeerWindow` bytes of outbound credit.
        if let st = box.resolvedState() {
            Task { await st.grant(peerWindow) }
        }
        box.yieldEvent(TypeErasedChannelEvent(
            payload: .opened(serviceAck: ack, initialPeerWindow: peerWindow)
        ))
    }

    static let cOnChannelData: @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeRawPointer?,
        Int
    ) -> Void = { userdata, bytesPtr, len in
        guard let ud = userdata, let p = bytesPtr, len > 0 else { return }
        let box = Unmanaged<ChannelBox>.fromOpaque(ud).takeUnretainedValue()
        // Memcpy NOW — the buffer is invalid the moment we return.
        let data = Data(bytes: p, count: len)
        box.yieldOutput(data)
    }

    static let cOnChannelWindowCredit: @convention(c) (
        UnsafeMutableRawPointer?,
        UInt32
    ) -> Void = { userdata, credit in
        guard let ud = userdata else { return }
        let box = Unmanaged<ChannelBox>.fromOpaque(ud).takeUnretainedValue()
        if let st = box.resolvedState() {
            Task { await st.grant(credit) }
        }
        box.yieldEvent(TypeErasedChannelEvent(payload: .windowCredit(credit)))
    }

    static let cOnChannelEOF: @convention(c) (
        UnsafeMutableRawPointer?
    ) -> Void = { userdata in
        guard let ud = userdata else { return }
        let box = Unmanaged<ChannelBox>.fromOpaque(ud).takeUnretainedValue()
        box.yieldEvent(TypeErasedChannelEvent(payload: .eof))
        box.finishOutput()
    }

    static let cOnChannelClose: @convention(c) (
        UnsafeMutableRawPointer?,
        ghostty_channel_close_reason_e,
        UnsafePointer<CChar>?
    ) -> Void = { userdata, reason, msgPtr in
        guard let ud = userdata else { return }
        let box = Unmanaged<ChannelBox>.fromOpaque(ud).takeUnretainedValue()
        let msg = msgPtr.map { String(cString: $0) }
        if let st = box.resolvedState() {
            Task { await st.markClosed() }
        }
        box.yieldEvent(TypeErasedChannelEvent(payload: .closed(reason: reason, message: msg)))
        // Channel is now dead; tear down both streams.
        box.finishAll()
    }
}
