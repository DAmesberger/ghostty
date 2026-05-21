import Foundation
import GhosttyKit

// Indirection layer between the Swift SSH wrapper and libghostty's
// C entry points. Production code calls
//
//   LibghosttySSHAPI.current.openChannel(...)
//
// instead of `ghostty_ssh_open_channel(...)`. The default `current`
// value points at the real C symbols, so behavior is identical to
// calling the C ABI directly.
//
// Tests under `macos/Tests/Ghostty/` install a mock table at setUp
// (`LibghosttySSHAPI.installForTesting(...)`) and tear it down at
// teardown (`LibghosttySSHAPI.uninstallForTesting()`). The mock
// records every call so tests can assert against the exact wire
// bytes Swift sent to "C" — pinning the wire format end-to-end.
//
// Concurrency contract (production):
//   * `current` is read-only after process start (and after each test
//     restores the production table at tearDown). Lock-free reads are
//     correct because production code never swaps.
//
// Concurrency contract (tests):
//   * `installForTesting` is only valid when zero handles are
//     outstanding — enforced by `outstandingHandleCount`. This is a
//     precondition; misuse traps in debug, no-ops in release.
//   * Test bundles run their @Test functions on independent thread
//     pools, so the install/uninstall happen-before the mock's
//     trampolines fire. No barrier needed.

extension Ghostty {

    /// The 17 libghostty SSH/channel C entry points expressed as
    /// `@convention(c)` function pointers. Defaulted to the real
    /// libghostty symbols; tests can install an alternate set.
    struct LibghosttySSHAPI: Sendable {
        // SSH lifecycle.
        //
        // Note: C pointer params import into Swift as Optional unless the
        // header annotates them `_Nonnull`. `ghostty.h` does not, so every
        // handle / struct-pointer param below is `?`-typed to match the
        // real symbol's imported `@convention(c)` signature exactly — a
        // non-optional mismatch is a hard compile error when the real
        // function is assigned into the field.
        let sshOpen: @convention(c) (
            ghostty_app_t?,
            UnsafePointer<ghostty_ssh_config_t>?,
            UnsafePointer<ghostty_ssh_callbacks_t>?
        ) -> ghostty_ssh_t?

        let sshSubmitPassword: @convention(c) (
            ghostty_ssh_t?, UInt64, UnsafePointer<CChar>?
        ) -> Void

        let sshCancelPassword: @convention(c) (ghostty_ssh_t?, UInt64) -> Void

        let sshSubmitHostKeyDecision: @convention(c) (
            ghostty_ssh_t?, UInt64, Bool, Bool
        ) -> Void

        let sshRequestReconnect: @convention(c) (ghostty_ssh_t?) -> Void
        let sshCancelReconnect: @convention(c) (ghostty_ssh_t?) -> Void
        let sshClose: @convention(c) (ghostty_ssh_t?) -> Void
        let sshFree: @convention(c) (ghostty_ssh_t?) -> Void

        // Channels
        let sshOpenChannel: @convention(c) (
            ghostty_ssh_t?,
            ghostty_channel_service_e,
            UnsafeRawPointer?,
            Int,
            UnsafePointer<ghostty_channel_callbacks_t>?
        ) -> ghostty_channel_t?

        let channelWrite: @convention(c) (
            ghostty_channel_t?, UnsafeRawPointer?, Int
        ) -> Int

        let channelEof: @convention(c) (ghostty_channel_t?) -> Void

        let channelClose: @convention(c) (
            ghostty_channel_t?, ghostty_channel_close_reason_e
        ) -> Void

        let channelFree: @convention(c) (ghostty_channel_t?) -> Void

        // Surface attach (terminal-channel sugar)
        let sshAttachSurface: @convention(c) (
            ghostty_ssh_t?,
            UnsafePointer<UInt8>?,   // group_id (16 bytes or NULL)
            UnsafePointer<UInt8>?,   // surface_id (16 bytes or NULL)
            UInt16, UInt16, UInt32, UInt32,
            UnsafePointer<CChar>?,
            UnsafePointer<ghostty_channel_callbacks_t>?
        ) -> ghostty_channel_t?

        // Session management
        let sshListSessions: @convention(c) (
            ghostty_ssh_t?,
            (@convention(c) (UnsafeMutableRawPointer?, UnsafePointer<ghostty_ssh_session_entry_t>?) -> Void)?,
            UnsafeMutableRawPointer?
        ) -> Bool

        let sshRenameSession: @convention(c) (
            ghostty_ssh_t?, UnsafePointer<UInt8>?, UnsafePointer<CChar>?
        ) -> Void

        let sshKillSession: @convention(c) (
            ghostty_ssh_t?, UnsafePointer<UInt8>?
        ) -> Void

        /// Default table — every pointer is the real libghostty symbol.
        /// Production builds use this table for the entire process
        /// lifetime; tests swap in alternates via `installForTesting`.
        static let real: LibghosttySSHAPI = .init(
            sshOpen: ghostty_ssh_open,
            sshSubmitPassword: ghostty_ssh_submit_password,
            sshCancelPassword: ghostty_ssh_cancel_password,
            sshSubmitHostKeyDecision: ghostty_ssh_submit_host_key_decision,
            sshRequestReconnect: ghostty_ssh_request_reconnect,
            sshCancelReconnect: ghostty_ssh_cancel_reconnect,
            sshClose: ghostty_ssh_close,
            sshFree: ghostty_ssh_free,
            sshOpenChannel: ghostty_ssh_open_channel,
            channelWrite: ghostty_channel_write,
            channelEof: ghostty_channel_eof,
            channelClose: ghostty_channel_close,
            channelFree: ghostty_channel_free,
            sshAttachSurface: ghostty_ssh_attach_surface,
            sshListSessions: ghostty_ssh_list_sessions,
            sshRenameSession: ghostty_ssh_rename_session,
            sshKillSession: ghostty_ssh_kill_session
        )

        // MARK: - Global current table

        /// Lock-free read in production. `nonisolated(unsafe)` because
        /// the value is only swapped during test setUp BEFORE any
        /// handle is created and restored at tearDown AFTER all handles
        /// are freed (enforced by `outstandingHandleCount`).
        nonisolated(unsafe) private static var _current: LibghosttySSHAPI = .real

        /// The currently-installed table. Read this exactly once per
        /// C-call site and then call through — the per-call lock-free
        /// read is the entire point of the indirection layer.
        static var current: LibghosttySSHAPI { _current }

        // MARK: - Outstanding-handle counter

        /// Counter of live SSH handles (incremented on every successful
        /// `ssh_open` / `ssh_attach_surface` / `ssh_open_channel`,
        /// decremented on every `*_free`). Tests gate `installForTesting`
        /// on this being zero so the table can't be swapped out from
        /// under a live handle.
        nonisolated(unsafe) private static var _outstandingHandleCount: Int = 0
        private static let counterLock = NSLock()

        static func incrementHandleCount() {
            counterLock.lock()
            _outstandingHandleCount += 1
            counterLock.unlock()
        }

        static func decrementHandleCount() {
            counterLock.lock()
            _outstandingHandleCount -= 1
            counterLock.unlock()
        }

        static var outstandingHandleCount: Int {
            counterLock.lock()
            defer { counterLock.unlock() }
            return _outstandingHandleCount
        }

        // MARK: - Test installation

        #if DEBUG
        /// Install an alternate `LibghosttySSHAPI` table. Preconditions:
        ///   * No SSH handles are currently outstanding. Mocks would
        ///     corrupt live handles otherwise. Misuse traps.
        ///   * Must be called from test setUp (or equivalent) before
        ///     any wrapper-level open() runs.
        ///
        /// `uninstallForTesting()` restores the production table.
        static func installForTesting(_ api: LibghosttySSHAPI) {
            counterLock.lock()
            let count = _outstandingHandleCount
            counterLock.unlock()
            precondition(
                count == 0,
                "LibghosttySSHAPI.installForTesting requires zero outstanding handles, found \(count)"
            )
            _current = api
        }

        /// Restore the real libghostty table. Should be called from
        /// test tearDown.
        static func uninstallForTesting() {
            counterLock.lock()
            let count = _outstandingHandleCount
            counterLock.unlock()
            precondition(
                count == 0,
                "LibghosttySSHAPI.uninstallForTesting requires zero outstanding handles, found \(count)"
            )
            _current = .real
        }
        #endif
    }
}
