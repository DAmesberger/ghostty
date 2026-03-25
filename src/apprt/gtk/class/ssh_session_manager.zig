const std = @import("std");
const Allocator = std.mem.Allocator;

const adw = @import("adw");
const gobject = @import("gobject");
const gtk = @import("gtk");

const apprt = @import("../../../apprt.zig");
const session = @import("../../../session.zig");
const gresource = @import("../build/gresource.zig");
const Common = @import("../class.zig").Common;
const Application = @import("application.zig").Application;
const Window = @import("window.zig").Window;
const SshConnectionManager = @import("../../../termio/SshConnectionManager.zig");

const log = std.log.scoped(.gtk_ghostty_ssh_session_manager);

pub const SshSessionManager = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.Bin;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshSessionManager",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    const Private = struct {
        dialog: *adw.Dialog,
        name_entry: *gtk.Entry,
        host_label: *gtk.Label,
        viewers_label: *gtk.Label,
        size_mode_label: *gtk.Label,

        /// Back-reference to the window that opened this dialog.
        window: ?*Window = null,

        pub var offset: c_int = 0;
    };

    pub fn new() ?*Self {
        const self = gobject.ext.newInstance(Self, .{});
        _ = self.refSink();
        return self;
    }

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));
    }

    fn dispose(self: *Self) callconv(.c) void {
        gtk.Widget.disposeTemplate(self.as(gtk.Widget), getGObjectType());
        gobject.Object.virtual_methods.dispose.call(Class.parent, self.as(Parent));
    }

    fn dialogClosed(_: *adw.Dialog, self: *SshSessionManager) callconv(.c) void {
        self.unref();
    }

    //---------------------------------------------------------------
    // Public API

    pub fn present(self: *SshSessionManager, window: *Window) void {
        const priv = self.private();
        priv.window = window;
        priv.dialog.present(window.as(gtk.Widget));
    }

    /// Populate the dialog with session data from the active surface.
    pub fn populate(self: *SshSessionManager, window: *Window) void {
        const priv = self.private();
        const surface = window.getActiveSurface() orelse return;
        const core = surface.core() orelse return;
        if (core.io.backend != .remote) return;

        const remote = &core.io.backend.remote;
        const label = remote.ssh_ctx.label orelse "unnamed";
        const target = remote.ssh_ctx.target;

        // Set session name
        priv.name_entry.getBuffer().setText(
            @ptrCast(label.ptr),
            @intCast(label.len),
        );

        // Set host
        var host_buf: [128]u8 = undefined;
        const host_str = std.fmt.bufPrint(&host_buf, "Host: {s}", .{target}) catch "Host: ?";
        priv.host_label.setText(@ptrCast(host_str.ptr));

        // Set viewer count
        var viewers_buf: [32]u8 = undefined;
        const viewers_str = std.fmt.bufPrint(&viewers_buf, "{d} viewer{s}", .{
            core.viewer_count,
            @as([]const u8, if (core.viewer_count != 1) "s" else ""),
        }) catch "? viewers";
        priv.viewers_label.setText(@ptrCast(viewers_str.ptr));

        // Set size mode
        const mode_str: [*:0]const u8 = switch (core.size_mode_current) {
            .smallest_wins => "smallest",
            .leader_wins => "leader",
        };
        priv.size_mode_label.setText(mode_str);
    }

    //---------------------------------------------------------------
    // Template callbacks

    fn renameClicked(_: *gtk.Button, self: *SshSessionManager) callconv(.c) void {
        const priv = self.private();
        const window = priv.window orelse return;
        const surface = window.getActiveSurface() orelse return;
        const core = surface.core() orelse return;
        if (core.io.backend != .remote) return;

        const remote = &core.io.backend.remote;
        const conn_entry = remote.conn_entry orelse return;
        const alloc = Application.default().allocator();

        const name = std.mem.span(priv.name_entry.getBuffer().getText());
        if (name.len == 0) return;

        const rename_data = session.protocol.Rename{
            .scope = .group,
            .id = remote.ssh_ctx.group_id,
            .label = name,
        };
        const payload = rename_data.encode(alloc) catch return;
        defer alloc.free(payload);
        SshConnectionManager.enqueueWrite(conn_entry, .rename, remote.target_id, payload);

        // Close the dialog after action.
        _ = priv.dialog.close();
    }

    fn detachOthersClicked(_: *gtk.Button, self: *SshSessionManager) callconv(.c) void {
        const priv = self.private();
        const window = priv.window orelse return;
        const surface = window.getActiveSurface() orelse return;
        const core = surface.core() orelse return;
        if (core.io.backend != .remote) return;

        const remote = &core.io.backend.remote;
        const conn_entry = remote.conn_entry orelse return;

        // Zero UUID = kick all others except sender.
        const payload = &session.shared.zero_uuid;
        SshConnectionManager.enqueueWrite(conn_entry, .kick_viewer, remote.target_id, payload);

        _ = priv.dialog.close();
    }

    fn deleteClicked(_: *gtk.Button, self: *SshSessionManager) callconv(.c) void {
        const priv = self.private();
        const window = priv.window orelse return;
        const surface = window.getActiveSurface() orelse return;
        const core = surface.core() orelse return;
        if (core.io.backend != .remote) return;

        const remote = &core.io.backend.remote;
        const conn_entry = remote.conn_entry orelse return;
        const alloc = Application.default().allocator();

        const close_data = session.protocol.Close{
            .mode = .session,
            .id = remote.ssh_ctx.group_id,
        };
        const payload = close_data.encode(alloc) catch return;
        defer alloc.free(payload);
        SshConnectionManager.enqueueWrite(conn_entry, .close, remote.target_id, payload);

        _ = priv.dialog.close();
    }

    //---------------------------------------------------------------

    const C = Common(Self, Private);
    pub const as = C.as;
    pub const ref = C.ref;
    pub const refSink = C.refSink;
    pub const unref = C.unref;
    const private = C.private;

    pub const Class = extern struct {
        parent_class: Parent.Class,
        var parent: *Parent.Class = undefined;
        pub const Instance = Self;

        fn init(class: *Class) callconv(.c) void {
            gtk.Widget.Class.setTemplateFromResource(
                class.as(gtk.Widget.Class),
                comptime gresource.blueprint(.{
                    .major = 1,
                    .minor = 5,
                    .name = "ssh-session-manager",
                }),
            );

            // Bindings
            class.bindTemplateChildPrivate("dialog", .{});
            class.bindTemplateChildPrivate("name_entry", .{});
            class.bindTemplateChildPrivate("host_label", .{});
            class.bindTemplateChildPrivate("viewers_label", .{});
            class.bindTemplateChildPrivate("size_mode_label", .{});

            // Template callbacks
            class.bindTemplateCallback("closed", &dialogClosed);
            class.bindTemplateCallback("rename_clicked", &renameClicked);
            class.bindTemplateCallback("detach_others_clicked", &detachOthersClicked);
            class.bindTemplateCallback("delete_clicked", &deleteClicked);

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
        pub const bindTemplateCallback = C.Class.bindTemplateCallback;
    };
};
