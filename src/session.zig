pub const shared = @import("session/shared.zig");
pub const protocol = @import("session/protocol.zig");
pub const channel_mux = @import("session/channel_mux.zig");
pub const services = struct {
    pub const tcp_connect = @import("session/services/tcp_connect.zig");
    pub const browser_proxy = @import("session/services/browser_proxy.zig");
    pub const file_transfer = @import("session/services/file_transfer.zig");
    pub const port_listener = @import("session/services/port_listener.zig");
    pub const tcp_accepted = @import("session/services/tcp_accepted.zig");
    pub const cmux_control = @import("session/services/cmux_control.zig");
};
pub const layout = @import("session/layout.zig");
pub const registry = @import("session/registry.zig");
pub const client = @import("session/client.zig");
pub const daemon = @import("session/daemon.zig");
pub const ssh = @import("session/ssh.zig");
pub const ssh_config = @import("session/ssh_config.zig");
pub const remote_session = @import("session/remote_session.zig");
pub const page_diff = @import("session/page_diff.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
