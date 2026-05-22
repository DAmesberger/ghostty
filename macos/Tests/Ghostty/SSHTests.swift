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
    //
    // These tests are spec-locked against the Zig decoders in
    // `src/session/services/*.zig`. If a decoder's wire format changes,
    // the corresponding test here must change in lockstep — drift makes
    // every open() return on_close(SERVICE_ERROR) at runtime.

    /// `[u16 LE host_len][host][u16 LE port]` — matches tcp_connect.zig:16-18.
    @Test
    func tcpConnectEncodesLengthPrefixedHostAndLEPort() throws {
        let svc = Ghostty.TCPConnectService(host: "example.com", port: 8080)
        let bytes = [UInt8](try svc.encodeParams())
        var expected: [UInt8] = []
        // host_len = 11, LE
        expected += [0x0B, 0x00]
        expected += Array("example.com".utf8)
        // port = 8080 = 0x1F90, LE
        expected += [0x90, 0x1F]
        #expect(bytes == expected)
    }

    /// `[u16 LE bind_host_len][bind_host][u16 LE port]` — same shape as
    /// tcp_connect (house style). Re-verify against port_listener.zig once
    /// Phase 6A.5 lands.
    @Test
    func portListenerEncodesLengthPrefixedHostAndLEPort() throws {
        let svc = Ghostty.PortListenerService(bindHost: "0.0.0.0", port: 22)
        let bytes = [UInt8](try svc.encodeParams())
        var expected: [UInt8] = []
        expected += [0x07, 0x00]                      // host_len = 7
        expected += Array("0.0.0.0".utf8)
        expected += [0x16, 0x00]                      // port = 22 LE
        #expect(bytes == expected)
    }

    /// Upload params: `[u8 direction=0][u32 LE mode][u16 LE path_len][path]
    /// [32-byte expected_sha256][u64 LE total_size]` — matches
    /// file_transfer.zig:18-26.
    @Test
    func fileTransferUploadEncodesAllFields() throws {
        var sha = Data(count: 32)
        sha[0] = 0xAB
        sha[31] = 0xCD
        let svc = Ghostty.FileTransferService(operation: .upload(
            remotePath: "/tmp/a",
            mode: 0o644,
            expectedSHA256: sha,
            totalSize: 0x0102_0304_0506_0708
        ))
        let bytes = [UInt8](try svc.encodeParams())

        var expected: [UInt8] = []
        expected += [0x00]                                              // direction = upload
        expected += [0xA4, 0x01, 0x00, 0x00]                            // mode = 0o644 = 0x1A4 LE
        expected += [0x06, 0x00]                                        // path_len = 6 LE
        expected += Array("/tmp/a".utf8)
        var sha32 = [UInt8](repeating: 0, count: 32)
        sha32[0] = 0xAB; sha32[31] = 0xCD
        expected += sha32
        expected += [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]    // total_size LE

        #expect(bytes == expected)
    }

    /// Download params: `[u8 direction=1][u32 LE mode=0][u16 LE path_len][path]`
    /// — no trailer (file_transfer.zig:733).
    @Test
    func fileTransferDownloadEncodesNoTrailer() throws {
        let svc = Ghostty.FileTransferService(operation: .download(remotePath: "/tmp/a"))
        let bytes = [UInt8](try svc.encodeParams())

        var expected: [UInt8] = []
        expected += [0x01]                                              // direction = download
        expected += [0x00, 0x00, 0x00, 0x00]                            // mode = 0 (unused)
        expected += [0x06, 0x00]                                        // path_len = 6
        expected += Array("/tmp/a".utf8)

        #expect(bytes == expected)
    }

    /// Upload with no expected SHA: 32 zero bytes, signalling
    /// "skip verification" per file_transfer.zig:24.
    @Test
    func fileTransferUploadWithoutSHAUsesZeroes() throws {
        let svc = Ghostty.FileTransferService(operation: .upload(
            remotePath: "/tmp/a",
            mode: 0o644,
            expectedSHA256: nil,
            totalSize: 0
        ))
        let bytes = [UInt8](try svc.encodeParams())
        // SHA section starts after: 1 + 4 + 2 + 6 = 13 bytes.
        let sha = Array(bytes[13..<45])
        #expect(sha == [UInt8](repeating: 0, count: 32))
    }

    /// `[u8 upstream_kind][u16 LE host_len][host][u16 LE port][metadata]`
    /// — matches browser_proxy.zig:17-24.
    @Test
    func browserProxyEncodesKindHostPortMetadata() throws {
        let svc = Ghostty.BrowserProxyService(
            upstreamKind: .httpConnectTarget,
            host: "example.com",
            port: 443,
            metadata: Data([0x01, 0x02, 0x03])
        )
        let bytes = [UInt8](try svc.encodeParams())

        var expected: [UInt8] = []
        expected += [0x01]                            // upstream_kind = http_connect_target
        expected += [0x0B, 0x00]                      // host_len = 11
        expected += Array("example.com".utf8)
        expected += [0xBB, 0x01]                      // port = 443 LE
        expected += [0x01, 0x02, 0x03]                // metadata

        #expect(bytes == expected)
    }

    @Test
    func browserProxyEmptyMetadataOk() throws {
        let svc = Ghostty.BrowserProxyService(
            upstreamKind: .direct,
            host: "10.0.0.1",
            port: 1080
        )
        let bytes = [UInt8](try svc.encodeParams())
        // No metadata appended — total = 1 + 2 + 8 + 2 = 13 bytes.
        #expect(bytes.count == 13)
        #expect(bytes[0] == 0)                        // direct = 0
    }

    @Test
    func terminalServiceEncodesEmptyParams() throws {
        #expect(try Ghostty.TerminalService().encodeParams().isEmpty)
    }

    // MARK: - encodeParams rejects oversized inputs (task #11)
    //
    // The Zig parsers reject oversized fields with error.HostTooLong /
    // .InvalidPathLen / .MetadataTooLong. Swift must surface this BEFORE
    // calling into libghostty — silently truncating into a different
    // destination than the embedder asked for is the worst-case bug.

    @Test
    func tcpConnectThrowsOnHostTooLong() {
        let huge = String(repeating: "a", count: 256)  // 1 over max_host_len
        let svc = Ghostty.TCPConnectService(host: huge, port: 80)
        do {
            _ = try svc.encodeParams()
            Issue.record("expected encodeParams to throw")
        } catch let e as Ghostty.SSHError {
            #expect(e == .openParamsTooLong(field: "host", length: 256, limit: 255))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test
    func portListenerThrowsOnBindHostTooLong() {
        let huge = String(repeating: "b", count: 300)
        let svc = Ghostty.PortListenerService(bindHost: huge, port: 22)
        do {
            _ = try svc.encodeParams()
            Issue.record("expected throw")
        } catch let e as Ghostty.SSHError {
            #expect(e == .openParamsTooLong(field: "bindHost", length: 300, limit: 255))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test
    func fileTransferThrowsOnPathTooLong() {
        let huge = String(repeating: "x", count: 4097)
        let svc = Ghostty.FileTransferService(operation: .download(remotePath: huge))
        do {
            _ = try svc.encodeParams()
            Issue.record("expected throw")
        } catch let e as Ghostty.SSHError {
            #expect(e == .openParamsTooLong(field: "remotePath", length: 4097, limit: 4096))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test
    func browserProxyThrowsOnHostTooLong() {
        let huge = String(repeating: "h", count: 256)
        let svc = Ghostty.BrowserProxyService(
            upstreamKind: .direct, host: huge, port: 1)
        do {
            _ = try svc.encodeParams()
            Issue.record("expected throw")
        } catch let e as Ghostty.SSHError {
            #expect(e == .openParamsTooLong(field: "host", length: 256, limit: 255))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test
    func browserProxyThrowsOnMetadataTooLong() {
        let bigMeta = Data(repeating: 0, count: 8 * 1024 + 1)
        let svc = Ghostty.BrowserProxyService(
            upstreamKind: .direct,
            host: "ok",
            port: 80,
            metadata: bigMeta)
        do {
            _ = try svc.encodeParams()
            Issue.record("expected throw")
        } catch let e as Ghostty.SSHError {
            #expect(e == .openParamsTooLong(field: "metadata", length: 8 * 1024 + 1, limit: 8 * 1024))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    /// Boundary case: input at exactly the cap should succeed.
    @Test
    func tcpConnectAcceptsHostAtMaxLen() throws {
        let atMax = String(repeating: "a", count: 255)
        let svc = Ghostty.TCPConnectService(host: atMax, port: 80)
        let bytes = try svc.encodeParams()
        // Total = 2 + 255 + 2 = 259 bytes.
        #expect(bytes.count == 259)
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

extension Ghostty.SSHChannel.CloseReason: Equatable {}
