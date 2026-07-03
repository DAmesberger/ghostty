import Foundation
import GhosttyKit

extension Ghostty {
    /// A channel service descriptor. Conforming types describe both the C-side
    /// service id (`ghostty_channel_service_e`) and the wire `params` payload
    /// to send at open time.
    ///
    /// Every `encodeParams()` implementation here is byte-for-byte locked to
    /// the corresponding decoder in `src/session/services/*.zig`. Drift will
    /// surface as `error.InvalidRequest` from the daemon → on_close(SERVICE_ERROR)
    /// on the embedder's side, so the integration tests under task #6
    /// (stub-libghostty mock) will catch any regression.
    ///
    /// The protocol is `Sendable` because services are passed across actor
    /// boundaries on the open path.
    public protocol ChannelService: Sendable {
        var cService: ghostty_channel_service_e { get }
        /// Bytes copied by libghostty during `ghostty_ssh_open_channel`. May
        /// be empty for services with no per-open parameters.
        ///
        /// Throws `Ghostty.SSHError.openParamsTooLong` when an input field
        /// exceeds the corresponding Zig parser's hard cap (`max_host_len` /
        /// `max_path_len` / `max_metadata_len`). Failing here rather than
        /// silently truncating prevents the worst-case bug — embedder asks
        /// for `host="really-long-name.example.com"`, gets a "successful"
        /// channel pointed at the truncated prefix instead of an error.
        func encodeParams() throws -> Data
    }

    /// Open a raw TCP connection through the remote host.
    ///
    /// Wire format (matches `src/session/services/tcp_connect.zig`):
    ///
    ///     [u16 LE host_len][host UTF-8 bytes][u16 LE port]
    public struct TCPConnectService: ChannelService {
        /// Max accepted host length on the daemon side. Mirrors
        /// `tcp_connect.zig`'s `max_host_len` — the daemon will reject
        /// `error.InvalidRequest` if this is exceeded; we mirror the limit
        /// so the wire stays clean.
        public static let maxHostLen: Int = 255

        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_TCP_CONNECT }

        public func encodeParams() throws -> Data {
            let hostBytes = Array(host.utf8)
            guard hostBytes.count <= Self.maxHostLen else {
                throw Ghostty.SSHError.openParamsTooLong(
                    field: "host", length: hostBytes.count, limit: Self.maxHostLen)
            }
            var out = Data()
            appendLEUInt16(UInt16(hostBytes.count), to: &out)
            out.append(contentsOf: hostBytes)
            appendLEUInt16(port, to: &out)
            return out
        }
    }

    /// Ask the remote to listen on `bindHost:port` and surface each accepted
    /// connection back as an inbound sub-channel.
    ///
    /// Wire format mirrors `tcp_connect`'s open-params (length-prefixed host,
    /// little-endian port) to match the project house style. The Zig encoder
    /// is in flight under Phase 6A.5; once it lands, this comment + the
    /// integration test in task #6 must verify the layout matches.
    ///
    ///     [u16 LE bind_host_len][bind_host UTF-8 bytes][u16 LE port]
    public struct PortListenerService: ChannelService {
        public static let maxBindHostLen: Int = 255

        public let bindHost: String
        public let port: UInt16

        public init(bindHost: String, port: UInt16) {
            self.bindHost = bindHost
            self.port = port
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_PORT_LISTENER }

        public func encodeParams() throws -> Data {
            let hostBytes = Array(bindHost.utf8)
            guard hostBytes.count <= Self.maxBindHostLen else {
                throw Ghostty.SSHError.openParamsTooLong(
                    field: "bindHost", length: hostBytes.count, limit: Self.maxBindHostLen)
            }
            var out = Data()
            appendLEUInt16(UInt16(hostBytes.count), to: &out)
            out.append(contentsOf: hostBytes)
            appendLEUInt16(port, to: &out)
            return out
        }
    }

    /// File transfer (upload or download) against the remote daemon's
    /// sandboxed file roots.
    ///
    /// Wire format (matches `src/session/services/file_transfer.zig`):
    ///
    ///     [u8 direction]    // 0 = upload, 1 = download
    ///     [u32 LE mode]     // POSIX file mode; uploads only, ignored on download
    ///     [u16 LE path_len]
    ///     [path UTF-8 bytes]
    ///     ── upload-only trailer ──
    ///     [32-byte expected_sha256]  // all-zero = skip verification
    ///     [u64 LE total_size]        // 0 = unknown
    public struct FileTransferService: ChannelService {
        public static let maxPathLen: Int = 4096
        public static let sha256Length: Int = 32

        public enum Operation: Sendable {
            /// Upload a file to the remote daemon. `expectedSHA256`, when
            /// 32 bytes, is verified at completion; pass `nil` (or empty)
            /// to skip. `totalSize == 0` signals "unknown".
            case upload(
                remotePath: String,
                mode: UInt32 = 0o644,
                expectedSHA256: Data? = nil,
                totalSize: UInt64 = 0
            )
            /// Download a file from the remote daemon.
            case download(remotePath: String)
        }

        public let operation: Operation

        public init(operation: Operation) {
            self.operation = operation
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_FILE_TRANSFER }

        public func encodeParams() throws -> Data {
            var out = Data()
            switch operation {
            case let .upload(path, mode, expected, totalSize):
                let pathBytes = try validatedPath(path)
                out.append(0)                                     // direction
                appendLEUInt32(mode, to: &out)                    // mode
                appendLEUInt16(UInt16(pathBytes.count), to: &out) // path_len
                out.append(contentsOf: pathBytes)
                // 32-byte SHA-256: copy what was given, zero-pad/truncate to 32.
                // `nil`/empty signals "skip verification" per file_transfer.zig:24;
                // longer-than-32 is silently truncated (matches the SHA-256 digest
                // length contract — there's no other valid interpretation).
                var sha = [UInt8](repeating: 0, count: Self.sha256Length)
                if let e = expected {
                    let take = min(e.count, Self.sha256Length)
                    e.copyBytes(to: &sha, count: take)
                }
                out.append(contentsOf: sha)
                appendLEUInt64(totalSize, to: &out)
            case let .download(path):
                let pathBytes = try validatedPath(path)
                out.append(1)                                     // direction
                appendLEUInt32(0, to: &out)                       // mode (unused)
                appendLEUInt16(UInt16(pathBytes.count), to: &out) // path_len
                out.append(contentsOf: pathBytes)
            }
            return out
        }

        private func validatedPath(_ s: String) throws -> [UInt8] {
            let bytes = Array(s.utf8)
            guard bytes.count <= Self.maxPathLen else {
                throw Ghostty.SSHError.openParamsTooLong(
                    field: "remotePath", length: bytes.count, limit: Self.maxPathLen)
            }
            return bytes
        }
    }

    /// Browser-proxy channel. Carries an SSH-tunneled byte stream to one
    /// upstream `host:port`, with an `upstreamKind` byte that tells the
    /// daemon what wire-level shape to expect on the channel (direct passthrough,
    /// HTTP CONNECT target, SOCKS5 target). `metadata` is an opaque UTF-8
    /// blob the daemon passes through to upstream-kind-specific logic;
    /// today it's informational and ≤ 8 KiB.
    ///
    /// Wire format (matches `src/session/services/browser_proxy.zig`):
    ///
    ///     [u8 upstream_kind]
    ///     [u16 LE host_len]
    ///     [host UTF-8 bytes]
    ///     [u16 LE port]
    ///     [metadata UTF-8 bytes; may be empty]
    public struct BrowserProxyService: ChannelService {
        public static let maxHostLen: Int = 255
        public static let maxMetadataLen: Int = 8 * 1024

        /// Mirrors `browser_proxy.zig`'s `UpstreamKind` enum byte values
        /// (browser_proxy.zig:80-85). Raw value IS the wire-byte the daemon
        /// expects.
        public enum UpstreamKind: UInt8, Sendable {
            case direct = 0
            case httpConnectTarget = 1
            case socks5Target = 2
        }

        public let upstreamKind: UpstreamKind
        public let host: String
        public let port: UInt16
        public let metadata: Data

        public init(
            upstreamKind: UpstreamKind,
            host: String,
            port: UInt16,
            metadata: Data = Data()
        ) {
            self.upstreamKind = upstreamKind
            self.host = host
            self.port = port
            self.metadata = metadata
        }

        public var cService: ghostty_channel_service_e { GHOSTTY_CHANNEL_SERVICE_BROWSER_PROXY }

        public func encodeParams() throws -> Data {
            let hostBytes = Array(host.utf8)
            guard hostBytes.count <= Self.maxHostLen else {
                throw Ghostty.SSHError.openParamsTooLong(
                    field: "host", length: hostBytes.count, limit: Self.maxHostLen)
            }
            guard metadata.count <= Self.maxMetadataLen else {
                throw Ghostty.SSHError.openParamsTooLong(
                    field: "metadata", length: metadata.count, limit: Self.maxMetadataLen)
            }
            var out = Data()
            out.append(upstreamKind.rawValue)
            appendLEUInt16(UInt16(hostBytes.count), to: &out)
            out.append(contentsOf: hostBytes)
            appendLEUInt16(port, to: &out)
            out.append(metadata)
            return out
        }
    }
}

// MARK: - Little-endian encoding helpers

/// Append a little-endian `UInt16` to `out`.
private func appendLEUInt16(_ v: UInt16, to out: inout Data) {
    var le = v.littleEndian
    withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
}

/// Append a little-endian `UInt32` to `out`.
private func appendLEUInt32(_ v: UInt32, to out: inout Data) {
    var le = v.littleEndian
    withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
}

/// Append a little-endian `UInt64` to `out`.
private func appendLEUInt64(_ v: UInt64, to out: inout Data) {
    var le = v.littleEndian
    withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
}
