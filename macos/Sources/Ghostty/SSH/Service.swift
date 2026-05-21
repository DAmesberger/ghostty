import Foundation
import GhosttyKit

extension Ghostty {
    /// A channel service descriptor. Conforming types describe both the C-side
    /// service id (`ghostty_channel_service_e`) and the wire `params` payload
    /// to send at open time.
    ///
    /// The protocol is `Sendable` because services are passed across actor
    /// boundaries on the open path.
    public protocol ChannelService: Sendable {
        var cService: ghostty_channel_service_e { get }
        /// Bytes copied by libghostty during `ghostty_ssh_open_channel`. May
        /// be empty for services with no per-open parameters.
        func encodeParams() -> Data
    }

    /// A remote interactive terminal. Use `SSHConnection.attachSurface` rather
    /// than `openChannel(TerminalService())` for new terminal sessions — the
    /// attach helper drives the legacy session-protocol open path that survives
    /// reconnects by `(groupID, surfaceID)`.
    public struct TerminalService: ChannelService {
        public init() {}
        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_TERMINAL }
        public func encodeParams() -> Data { Data() }
    }

    /// Open a raw TCP connection through the remote host.
    public struct TCPConnectService: ChannelService {
        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_TCP_CONNECT }

        /// Wire format: NUL-terminated host string, followed by big-endian
        /// uint16 port. Matches `session/services/tcp_connect.zig`.
        public func encodeParams() -> Data {
            var out = Data(host.utf8)
            out.append(0)
            var be = port.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
            return out
        }
    }

    /// Ask the remote to listen on a port and forward each accepted connection
    /// back as a sub-channel. Inbound sub-channels are surfaced via the
    /// owning `SSHConnection`'s incoming-channel stream (out of scope for
    /// this file).
    public struct PortListenerService: ChannelService {
        public let bindHost: String
        public let port: UInt16

        public init(bindHost: String, port: UInt16) {
            self.bindHost = bindHost
            self.port = port
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_PORT_LISTENER }

        public func encodeParams() -> Data {
            var out = Data(bindHost.utf8)
            out.append(0)
            var be = port.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
            return out
        }
    }

    /// File transfer operations performed against the remote daemon.
    public struct FileTransferService: ChannelService {
        public enum Operation: Sendable {
            case upload(remotePath: String)
            case download(remotePath: String)
        }

        public let operation: Operation

        public init(operation: Operation) {
            self.operation = operation
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_FILE_TRANSFER }

        /// Wire format: 1-byte op tag (0=upload, 1=download), then
        /// NUL-terminated remote path.
        public func encodeParams() -> Data {
            var out = Data()
            switch operation {
            case .upload(let path):
                out.append(0)
                out.append(contentsOf: path.utf8)
            case .download(let path):
                out.append(1)
                out.append(contentsOf: path.utf8)
            }
            out.append(0)
            return out
        }
    }

    /// HTTP/HTTPS-aware browser proxy. The remote daemon issues the
    /// outbound CONNECT/GET on the embedder's behalf; the channel carries
    /// the resulting bidirectional byte stream (transparent TLS payload for
    /// CONNECT, body bytes for plain HTTP).
    public struct BrowserProxyService: ChannelService {
        public enum Method: Sendable {
            case connect  // HTTPS CONNECT tunnel — `target` is host:port
            case get
            case post
            case put
            case delete
            case head
            case options
            case patch
        }

        public let target: String
        public let method: Method
        public let headers: [String: String]

        public init(target: String, method: Method = .connect, headers: [String: String] = [:]) {
            self.target = target
            self.method = method
            self.headers = headers
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_BROWSER_PROXY }

        /// Wire format: 1-byte method tag, NUL-terminated target,
        /// big-endian uint16 header count, then for each header:
        /// NUL-terminated name, NUL-terminated value.
        /// Matches `session/services/browser_proxy.zig`.
        public func encodeParams() -> Data {
            var out = Data()
            out.append(methodTag)
            out.append(contentsOf: target.utf8)
            out.append(0)
            var count = UInt16(min(headers.count, Int(UInt16.max))).bigEndian
            withUnsafeBytes(of: &count) { out.append(contentsOf: $0) }
            for (name, value) in headers {
                out.append(contentsOf: name.utf8)
                out.append(0)
                out.append(contentsOf: value.utf8)
                out.append(0)
            }
            return out
        }

        private var methodTag: UInt8 {
            switch method {
            case .connect: return 0
            case .get: return 1
            case .post: return 2
            case .put: return 3
            case .delete: return 4
            case .head: return 5
            case .options: return 6
            case .patch: return 7
            }
        }
    }
}
