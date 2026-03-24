const std = @import("std");
const Allocator = std.mem.Allocator;

const adw = @import("adw");
const gobject = @import("gobject");
const gtk = @import("gtk");

const session = @import("../../../session.zig");
const gresource = @import("../build/gresource.zig");
const Common = @import("../class.zig").Common;
const Application = @import("application.zig").Application;

const log = std.log.scoped(.gtk_ghostty_ssh_viewer_panel);

/// Floating overlay panel showing the multi-viewer roster for an SSH
/// remote session.  Toggled via the `ssh_toggle_viewer_panel` action.
pub const SshViewerPanel = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.Bin;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshViewerPanel",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    const Private = struct {
        revealer: *gtk.Revealer,
        title_label: *gtk.Label,
        mode_label: *gtk.Label,
        size_label: *gtk.Label,
        viewer_list: *gtk.ListBox,

        pub var offset: c_int = 0;
    };

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));
    }

    fn dispose(self: *Self) callconv(.c) void {
        gtk.Widget.disposeTemplate(
            self.as(gtk.Widget),
            getGObjectType(),
        );
        gobject.Object.virtual_methods.dispose.call(
            Class.parent,
            self.as(Parent),
        );
    }

    //---------------------------------------------------------------
    // Public API

    /// Toggle the panel visibility.
    pub fn toggle(self: *SshViewerPanel) void {
        const priv = self.private();
        const currently_visible = priv.revealer.getRevealChild() != 0;
        priv.revealer.setRevealChild(if (currently_visible) 0 else 1);
    }

    /// Update the panel with new viewer state.
    pub fn update(
        self: *SshViewerPanel,
        viewer_count: u16,
        size_mode: session.protocol.SizeMode,
        effective_rows: u16,
        effective_cols: u16,
    ) void {
        const priv = self.private();

        // Update header labels
        var title_buf: [32]u8 = undefined;
        const title = std.fmt.bufPrint(&title_buf, "{d} Viewer{s}", .{
            viewer_count,
            if (viewer_count != 1) "s" else "",
        }) catch "Viewers";
        priv.title_label.setText(@ptrCast(title.ptr));

        const mode_text: [*:0]const u8 = switch (size_mode) {
            .smallest_wins => "smallest",
            .leader_wins => "leader",
        };
        priv.mode_label.setText(mode_text);

        var size_buf: [32]u8 = undefined;
        const size = std.fmt.bufPrint(&size_buf, "{d}\xc3\x97{d}", .{
            effective_cols,
            effective_rows,
        }) catch "?";
        priv.size_label.setText(@ptrCast(size.ptr));
    }

    //---------------------------------------------------------------

    const C = Common(Self, Private);
    pub const as = C.as;
    pub const ref = C.ref;
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
                    .name = "ssh-viewer-panel",
                }),
            );

            // Bindings
            class.bindTemplateChildPrivate("revealer", .{});
            class.bindTemplateChildPrivate("title_label", .{});
            class.bindTemplateChildPrivate("mode_label", .{});
            class.bindTemplateChildPrivate("size_label", .{});
            class.bindTemplateChildPrivate("viewer_list", .{});

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
    };
};
