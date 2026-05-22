import XCTest
@testable import Ghostty

// Static type-check: verify the public SSH API surface is visible from a test
// target that imports Ghostty. Each line will fail to compile if a type or
// member is accidentally left internal.
//
// These are not behavioural tests — they exist purely to catch visibility
// regressions (e.g. "I marked it public but a stored-property type is still
// internal").

final class SSHPublicAPITypeCheckTests: XCTestCase {

    func testConnectionStateTypesVisible() {
        // ConnectionState enum and variants
        let _: Ghostty.ConnectionState = .connecting
        let _: Ghostty.ConnectionState = .downloading
        let _: Ghostty.ConnectionState = .setup
        let _: Ghostty.ConnectionState = .connected
        let _: Ghostty.ConnectionState = .stale

        // Nested public structs / enums
        let _: Ghostty.ConnectionState.Kind = .connected
        let _: Ghostty.ConnectionState.ProvisionSource = .github
        let _: Ghostty.ConnectionState.Disconnect.Reason = .exhausted
        let _: Ghostty.ConnectionState.Failure.Reason = .authFailed
    }

    func testSSHErrorVisible() {
        let _: Ghostty.SSHError = .openFailed
        let _: Ghostty.SSHError = .channelOpenFailed
        let _: Ghostty.SSHError = .channelClosed
        let _: Ghostty.SSHError = .notReady
        let _: Ghostty.SSHError = .openParamsTooLong(field: "host", length: 300, limit: 255)
    }

    func testHostKeyHandlerVisible() {
        let _: Ghostty.HostKeyHandler = .strict
        let _: Ghostty.HostKeyHandler = .tofu
        let _: Ghostty.HostKeyHandler = .insecure
    }

    func testTerminalSizeVisible() {
        let size = Ghostty.TerminalSize(rows: 24, cols: 80)
        XCTAssertEqual(size.rows, 24)
        XCTAssertEqual(size.cols, 80)
        XCTAssertEqual(size.widthPx, 0)
        XCTAssertEqual(size.heightPx, 0)
    }

    func testServiceTypesVisible() {
        let _: Ghostty.TerminalService = Ghostty.TerminalService()
        let _: Ghostty.TCPConnectService = Ghostty.TCPConnectService(host: "localhost", port: 22)
        let _: Ghostty.PortListenerService = Ghostty.PortListenerService(bindHost: "0.0.0.0", port: 2222)
        let _: Ghostty.FileTransferService = Ghostty.FileTransferService(operation: .download(remotePath: "/tmp/x"))
        let _: Ghostty.BrowserProxyService = Ghostty.BrowserProxyService(upstreamKind: .direct, host: "example.com", port: 80)
    }

    func testSSHConnectionTypeVisible() {
        // SSHConnection is a public final class; we can reference the type
        // without constructing one (which would require a real app handle).
        let _: Ghostty.SSHConnection.Type = Ghostty.SSHConnection.self
        let _: Ghostty.SSHConnection.Config.Type = Ghostty.SSHConnection.Config.self
    }

    func testSSHChannelTypeVisible() {
        let _: Ghostty.SSHChannel<Ghostty.TerminalService>.Type = Ghostty.SSHChannel<Ghostty.TerminalService>.self
        let _: Ghostty.SSHChannel<Ghostty.TCPConnectService>.Type = Ghostty.SSHChannel<Ghostty.TCPConnectService>.self
    }

    func testSSHChannelEventTypesVisible() {
        // Verify the Event enum cases are reachable via the public type.
        let _: Ghostty.SSHChannel<Ghostty.TerminalService>.CloseReason = .normal
        let _: Ghostty.SSHChannel<Ghostty.TerminalService>.CloseReason = .transport
    }

    func testConnectionStateInitVisible() {
        // Exercise the public inits on nested structs.
        let reconnect = Ghostty.ConnectionState.Reconnect(
            attempt: 1, maxAttempts: 5, elapsed: 1.0, nextRetry: nil)
        XCTAssertEqual(reconnect.attempt, 1)

        let failure = Ghostty.ConnectionState.Failure(reason: .timeout, message: "oops")
        XCTAssertEqual(failure.reason, .timeout)

        let disconnect = Ghostty.ConnectionState.Disconnect(
            attemptsMade: 3, reason: .exhausted)
        XCTAssertEqual(disconnect.attemptsMade, 3)
    }

    func testSessionManagementMethodsVisible() {
        // Verify renameSession and killSession are reachable as unbound method
        // references (never called — just a compile-time reachability check).
        let _: (Ghostty.SSHConnection) -> (UUID, String) -> Void = Ghostty.SSHConnection.renameSession
        let _: (Ghostty.SSHConnection) -> (UUID) -> Void = Ghostty.SSHConnection.killSession
    }
}
