import Testing
import Foundation
@testable import Ghostty
@testable import GhosttyKit

// Tests that don't require a live libghostty (no ghostty_app_t, no real SSH
// connection). They cover:
//
//   * The pure-Swift backpressure actor inside SSHChannel
//   * Service.encodeParams() wire formats — these are spec-locked because
//     the daemon-side decoders depend on them byte-for-byte.
//   * C-enum → Swift-enum mappings.
//
// Tests that DO require a live libghostty (full SSHConnection state-machine,
// SSHChannel.write through a real channel) are in scope but blocked on a
// stub libghostty for the test target. See SSHTestPlan.swift.txt notes.

struct SSHTests {

    // MARK: - Backpressure actor

    @Test
    func channelStateBlocksUntilGrant() async {
        let s = ChannelState()
        let task = Task { try await s.awaitCredit() }
        // Should be parked.
        try? await Task.sleep(nanoseconds: 5_000_000)
        #expect(!task.isCancelled)

        await s.grant(64)
        await #expect(throws: Never.self) { try await task.value }
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
        await #expect(throws: Ghostty.SSHError.self) {
            try await s.awaitCredit()
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
        let host = "example.com".utf8.map(UInt8.init)
        var expected = host
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
}

// MARK: - Equatable conformances for test convenience

extension Ghostty.ConnectionState.ProvisionSource: Equatable {}
extension Ghostty.ConnectionState.Failure.Reason: Equatable {}
extension Ghostty.SSHChannel.CloseReason: Equatable {}
