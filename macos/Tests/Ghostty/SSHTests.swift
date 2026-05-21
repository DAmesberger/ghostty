import Testing
import Foundation
@testable import Ghostty
@testable import GhosttyKit

// Two flavors of tests live here:
//
//   1. Pure-Swift unit tests for the parts that don't touch libghostty at
//      all — backpressure actor, wire-format encoding, C-enum mappings.
//      These are fast and deterministic.
//
//   2. Integration-against-stub tests that exercise the trampoline ↔
//      AsyncStream plumbing through the real `ghostty_ssh_*` C entry
//      points exported by `src/apprt/embedded/ssh_capi.zig`. Those exports
//      are stubs today (no real libssh2 transport) but they do drive the
//      callback contract — emit CONNECTING, cascade DAEMON_SHUTDOWN on
//      close, emit SERVICE_ERROR on channel open. That's enough to verify
//      the Swift wrapper translates them correctly.
//
// The integration tests require GhosttyKit.xcframework to be built (i.e.
// the test runs through xcodebuild against the real GhosttyKit target).
// They do NOT require a network, ssh daemon, or libssh2.

struct SSHTests {

    // MARK: - Backpressure actor

    @Test
    func channelStateBlocksUntilGrant() async throws {
        let s = ChannelState()
        let task = Task { try await s.awaitCredit() }
        // Should be parked.
        try? await Task.sleep(nanoseconds: 5_000_000)
        #expect(!task.isCancelled)

        await s.grant(64)
        try await task.value
        let took = await s.takeCredit(max: 64)
        #expect(took == 64)
    }

    @Test
    func channelStateTakeAndRefund() async {
        let s = ChannelState()
        await s.grant(100)
        let a = await s.takeCredit(max: 30)
        #expect(a == 30)
        let b = await s.takeCredit(max: 100)
        #expect(b == 70)  // only 70 remained
        let c = await s.takeCredit(max: 10)
        #expect(c == 0)
        await s.refundCredit(5)
        let d = await s.takeCredit(max: 100)
        #expect(d == 5)
    }

    @Test
    func channelStateCloseThrows() async {
        let s = ChannelState()
        await s.markClosed()
        do {
            try await s.awaitCredit()
            Issue.record("awaitCredit on closed state should throw")
        } catch {
            #expect(error is Ghostty.SSHError)
        }
    }

    @Test
    func channelStateCloseUnblocksWaiter() async throws {
        let s = ChannelState()
        let task = Task<Bool, Never> {
            do {
                try await s.awaitCredit()
                return false  // unexpected
            } catch {
                return error is Ghostty.SSHError
            }
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
        await s.markClosed()
        let threw = await task.value
        #expect(threw)
    }

    @Test
    func channelStateMultipleWaitersAllResume() async throws {
        let s = ChannelState()
        let t1 = Task { try await s.awaitCredit() }
        let t2 = Task { try await s.awaitCredit() }
        let t3 = Task { try await s.awaitCredit() }
        try? await Task.sleep(nanoseconds: 5_000_000)

        await s.grant(1)  // wake all (current impl is wake-all-on-grant)
        try await t1.value
        try await t2.value
        try await t3.value
    }

    // MARK: - Service param encoding (wire-format contract)

    @Test
    func tcpConnectEncodesNullTerminatedHostPlusBEPort() {
        let svc = Ghostty.TCPConnectService(host: "example.com", port: 0x1F90)  // 8080
        let bytes = [UInt8](svc.encodeParams())
        var expected: [UInt8] = Array("example.com".utf8)
        expected.append(0)        // NUL
        expected.append(0x1F)     // port big-endian high
        expected.append(0x90)     // port big-endian low
        #expect(bytes == expected)
    }

    @Test
    func portListenerEncodingMatchesTCPShape() {
        let svc = Ghostty.PortListenerService(bindHost: "0.0.0.0", port: 22)
        let bytes = [UInt8](svc.encodeParams())
        var expected: [UInt8] = Array("0.0.0.0".utf8)
        expected.append(0)
        expected.append(0)   // port BE high
        expected.append(22)  // port BE low
        #expect(bytes == expected)
    }

    @Test(arguments: [
        (Ghostty.FileTransferService.Operation.upload(remotePath: "/tmp/a"), UInt8(0)),
        (Ghostty.FileTransferService.Operation.download(remotePath: "/tmp/a"), UInt8(1)),
    ])
    func fileTransferEncoding(op: Ghostty.FileTransferService.Operation, tag: UInt8) {
        let svc = Ghostty.FileTransferService(operation: op)
        let bytes = [UInt8](svc.encodeParams())
        #expect(bytes.first == tag)
        #expect(bytes.last == 0)  // NUL terminator
        let path = String(decoding: bytes.dropFirst().dropLast(), as: UTF8.self)
        #expect(path == "/tmp/a")
    }

    @Test
    func browserProxyEncodesMethodTargetAndHeaders() {
        let svc = Ghostty.BrowserProxyService(
            target: "example.com:443",
            method: .connect,
            headers: ["X-Foo": "bar"]
        )
        let bytes = [UInt8](svc.encodeParams())
        // [0] method tag (connect=0)
        #expect(bytes[0] == 0)
        // [1..N] target NUL-terminated
        let nulIdx = bytes[1...].firstIndex(of: 0)!
        #expect(String(decoding: bytes[1..<nulIdx], as: UTF8.self) == "example.com:443")
        // [N+1..N+2] header count BE = 1
        #expect(bytes[nulIdx + 1] == 0)
        #expect(bytes[nulIdx + 2] == 1)
        // Followed by NUL-terminated "X-Foo" then NUL-terminated "bar"
        let rest = Array(bytes[(nulIdx + 3)...])
        let firstNul = rest.firstIndex(of: 0)!
        #expect(String(decoding: rest[0..<firstNul], as: UTF8.self) == "X-Foo")
        let after = Array(rest[(firstNul + 1)...])
        let secondNul = after.firstIndex(of: 0)!
        #expect(String(decoding: after[0..<secondNul], as: UTF8.self) == "bar")
    }

    @Test
    func terminalServiceEncodesEmptyParams() {
        #expect(Ghostty.TerminalService().encodeParams().isEmpty)
    }

    // MARK: - C-enum to Swift-enum mappings

    @Test(arguments: [
        (GHOSTTY_SSH_PROVISION_LOCAL_DAEMON, Ghostty.ConnectionState.ProvisionSource.localDaemon),
        (GHOSTTY_SSH_PROVISION_LOCAL_SELF, .localSelf),
        (GHOSTTY_SSH_PROVISION_GITHUB, .github),
    ])
    func provisionSourceMapping(_ c: ghostty_ssh_provision_source_e, _ swift: Ghostty.ConnectionState.ProvisionSource) {
        #expect(Ghostty.ConnectionState.ProvisionSource.from(c) == swift)
    }

    @Test(arguments: [
        (GHOSTTY_SSH_FAIL_AUTH_FAILED, Ghostty.ConnectionState.Failure.Reason.authFailed),
        (GHOSTTY_SSH_FAIL_TIMEOUT, .timeout),
        (GHOSTTY_SSH_FAIL_HELPER_FAILED, .helperFailed),
        (GHOSTTY_SSH_FAIL_UNKNOWN, .unknown),
    ])
    func failReasonMapping(_ c: ghostty_ssh_fail_reason_e, _ swift: Ghostty.ConnectionState.Failure.Reason) {
        #expect(Ghostty.ConnectionState.Failure.Reason.from(c) == swift)
    }

    @Test(arguments: [
        (GHOSTTY_CHANNEL_CLOSE_NORMAL, Ghostty.SSHChannel<Ghostty.TerminalService>.CloseReason.normal),
        (GHOSTTY_CHANNEL_CLOSE_PEER_RESET, .peerReset),
        (GHOSTTY_CHANNEL_CLOSE_TRANSPORT, .transport),
        (GHOSTTY_CHANNEL_CLOSE_DAEMON_SHUTDOWN, .daemonShutdown),
    ])
    func channelCloseReasonMapping(
        _ c: ghostty_channel_close_reason_e,
        _ swift: Ghostty.SSHChannel<Ghostty.TerminalService>.CloseReason
    ) {
        #expect(Ghostty.SSHChannel<Ghostty.TerminalService>.CloseReason.from(c) == swift)
    }

    // MARK: - Integration: SSHConnection state-machine over real C ABI
    //
    // Drives the stub `ghostty_ssh_*` exports in
    // `src/apprt/embedded/ssh_capi.zig`. The stub's contract is:
    //
    //   * `ghostty_ssh_open` synchronously emits a CONNECTING state then
    //     parks (no further callbacks until the embedder calls close).
    //   * `ghostty_ssh_close` cascades `on_close(DAEMON_SHUTDOWN)` to every
    //     live channel, then emits `disconnected(reason=cancelled)`.
    //
    // Both tests verify the Swift trampoline → AsyncStream plumbing on the
    // real C ABI, not on a Swift mock.

    @Test
    func sshConnectionEmitsInitialConnectingAndDisconnectsOnClose() async throws {
        // Dummy non-null app pointer — the stub ignores it.
        let dummyApp = ghostty_app_t(bitPattern: 0xDEAD_BEEF)!
        let conn = try Ghostty.SSHConnection(
            config: .init(target: "stub@localhost"),
            hostKey: .insecure,
            app: dummyApp
        )

        // The stub emits CONNECTING synchronously inside ghostty_ssh_open,
        // and emits disconnected(cancelled) when we call ghostty_ssh_close.
        // Collect the first two state values, then verify.
        // Pass the handle through UInt(bitPattern:) since `ghostty_ssh_t`
        // is `UnsafeMutableRawPointer`, intentionally non-Sendable.
        let handleBits = UInt(bitPattern: conn.handle)
        let stream = conn.state
        let firstTwo: [Ghostty.ConnectionState] = try await withTimeout(seconds: 2) {
            var collected: [Ghostty.ConnectionState] = []
            var emittedClose = false
            for await s in stream {
                collected.append(s)
                if !emittedClose {
                    emittedClose = true
                    let h = ghostty_ssh_t(bitPattern: handleBits)
                    ghostty_ssh_close(h)
                }
                if collected.count >= 2 { break }
            }
            return collected
        }

        #expect(firstTwo.count == 2)
        #expect(firstTwo.first?.kind == .connecting)
        guard case let .disconnected(d) = firstTwo.last else {
            Issue.record("expected .disconnected, got \(String(describing: firstTwo.last))")
            return
        }
        #expect(d.reason == .cancelled)
    }

    @Test
    func sshChannelOpenSurfacesStubServiceErrorClose() async throws {
        let dummyApp = ghostty_app_t(bitPattern: 0xCAFE_BABE)!
        let conn = try Ghostty.SSHConnection(
            config: .init(target: "stub@localhost"),
            hostKey: .insecure,
            app: dummyApp
        )

        // ghostty_ssh_open_channel returns a handle, then synchronously
        // emits on_close(SERVICE_ERROR) — exactly what we want to verify
        // the trampoline turns into a .closed event with the right reason
        // and that the events AsyncStream finishes afterwards.
        let channel = try conn.openChannel(Ghostty.TCPConnectService(host: "x", port: 1))

        let events: [Ghostty.SSHChannel<Ghostty.TCPConnectService>.Event] =
            try await withTimeout(seconds: 2) {
                var collected: [Ghostty.SSHChannel<Ghostty.TCPConnectService>.Event] = []
                for await ev in channel.events {
                    collected.append(ev)
                }
                return collected
            }

        // Stub emits exactly one event: the SERVICE_ERROR close. The stream
        // then finishes (loop exits).
        #expect(events.count == 1)
        guard case let .closed(reason, _, wasTransport) = events.first else {
            Issue.record("expected .closed event, got \(String(describing: events.first))")
            return
        }
        #expect(reason == .serviceError)
        #expect(wasTransport == false)
    }
}

// MARK: - Test helpers

/// Race `op` against a timeout. Throws `TimeoutError` if `op` doesn't
/// produce a value in time. Keeps the suite responsive when a regression
/// in the trampoline plumbing causes a stream to never yield or finish.
func withTimeout<T: Sendable>(
    seconds: Double,
    op: @Sendable @escaping () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await op()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TimeoutError()
        }
        let first = try await group.next()!
        group.cancelAll()
        return first
    }
}

struct TimeoutError: Swift.Error {}

// MARK: - Equatable conformances for test convenience

extension Ghostty.SSHChannel.CloseReason: Equatable {}
