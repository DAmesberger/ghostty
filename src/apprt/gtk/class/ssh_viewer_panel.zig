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

    /// Update the panel with new viewer state including roster.
    pub fn update(
        self: *SshViewerPanel,
        state: apprt.surface.Message.ViewerStateUpdate,
    ) void {
        const priv = self.private();

        // Update header labels.
        var title_buf: [32]u8 = undefined;
        const title = std.fmt.bufPrint(&title_buf, "{d} Viewer{s}", .{
            state.viewer_count,
            @as([]const u8, if (state.viewer_count != 1) "s" else ""),
        }) catch "Viewers";
        priv.title_label.setText(@ptrCast(title.ptr));

        const mode_text: [*:0]const u8 = switch (state.size_mode) {
            .smallest_wins => "smallest",
            .leader_wins => "leader",
        };
        priv.mode_label.setText(mode_text);

        var size_buf: [32]u8 = undefined;
        const size = std.fmt.bufPrint(&size_buf, "{d}\xc3\x97{d}", .{
            state.effective_cols,
            state.effective_rows,
        }) catch "?";
        priv.size_label.setText(@ptrCast(size.ptr));

        // Clear and repopulate the viewer list.
        priv.viewer_list.removeAll();

        const count = @min(state.viewer_count, 8);
        for (state.viewers[0..count]) |vi| {
            if (vi.label_len == 0 and !vi.is_controller) continue;

            // Create a row for this viewer.
            const row_box = gtk.Box.new(.horizontal, 8);
            row_box.as(gtk.Widget).setMarginStart(4);
            row_box.as(gtk.Widget).setMarginEnd(4);

            // Controller indicator.
            const indicator = gtk.Label.new(if (vi.is_controller) "\xe2\x97\x8f" else "\xe2\x97\x8b"); // ● or ○
            if (vi.is_controller) {
                indicator.as(gtk.Widget).addCssClass("success");
            }
            row_box.append(indicator.as(gtk.Widget));

            // Viewer label.
            const label_text = vi.label[0..vi.label_len];
            const name_label = gtk.Label.new(@ptrCast(if (label_text.len > 0) label_text.ptr else "anonymous"));
            name_label.setHexpand(1);
            name_label.setXalign(0);
            row_box.append(name_label.as(gtk.Widget));

            // Size info.
            var dim_buf: [16]u8 = undefined;
            const dim = std.fmt.bufPrint(&dim_buf, "{d}\xc3\x97{d}", .{ vi.cols, vi.rows }) catch "?";
            const dim_label = gtk.Label.new(@ptrCast(dim.ptr));
            dim_label.as(gtk.Widget).addCssClass("dim-label");
            row_box.append(dim_label.as(gtk.Widget));

            priv.viewer_list.append(row_box.as(gtk.Widget));
        }
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
