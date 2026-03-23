const std = @import("std");
const adw = @import("adw");
const gio = @import("gio");
const glib = @import("glib");
const gobject = @import("gobject");
const gtk = @import("gtk");

const gresource = @import("../build/gresource.zig");
const i18n = @import("../../../os/main.zig").i18n;
const ext = @import("../ext.zig");
const Common = @import("../class.zig").Common;
const Dialog = @import("dialog.zig").Dialog;

const log = std.log.scoped(.gtk_ghostty_title_dialog);

pub const TitleDialog = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.AlertDialog;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttyTitleDialog",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    pub const properties = struct {
        pub const target = struct {
            pub const name = "target";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                Target,
                .{
                    .default = .surface,
                    .accessor = gobject.ext
                        .privateFieldAccessor(
                        Self,
                        Private,
                        &Private.offset,
                        "target",
                    ),
                },
            );
        };
        pub const @"initial-value" = struct {
            pub const name = "initial-value";
            pub const get = impl.get;
            pub const set = impl.set;
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = C.privateStringFieldAccessor("initial_value"),
                },
            );
        };

        pub const @"initial-color" = struct {
            pub const name = "initial-color";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                i8,
                .{
                    .default = -1,
                    .minimum = -1,
                    .maximum = 7,
                    .accessor = gobject.ext.privateFieldAccessor(
                        Self,
                        Private,
                        &Private.offset,
                        "color",
                    ),
                },
            );
        };
    };

    pub const signals = struct {
        /// Set the title to the given value.
        pub const set = struct {
            pub const name = "set";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{ [*:0]const u8, c_int },
                void,
            );
        };
    };

    const Private = struct {
        /// The initial value of the entry field.
        initial_value: ?[:0]const u8 = null,

        /// Selected color index. -1 = auto, 0-7 = manual color.
        color: i8 = -1,

        // Template bindings
        target: Target,
        entry: *gtk.Entry,
        color_box: *gtk.Box,

        pub var offset: c_int = 0;
    };

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));
    }

    pub fn new(target: Target, initial_value: ?[:0]const u8) *Self {
        return newWithColor(target, initial_value, -1);
    }

    pub fn newWithColor(target: Target, initial_value: ?[:0]const u8, initial_color: i8) *Self {
        return gobject.ext.newInstance(Self, .{
            .target = target,
            .@"initial-value" = initial_value,
            .@"initial-color" = initial_color,
        });
    }

    pub fn present(self: *Self, parent_: *gtk.Widget) void {
        // If we have a window we can attach to, we prefer that.
        const parent: *gtk.Widget = if (ext.getAncestor(
            adw.ApplicationWindow,
            parent_,
        )) |window|
            window.as(gtk.Widget)
        else if (ext.getAncestor(
            adw.Window,
            parent_,
        )) |window|
            window.as(gtk.Widget)
        else
            parent_;

        // Set our initial value
        const priv = self.private();
        if (priv.initial_value) |v| {
            priv.entry.getBuffer().setText(v, -1);
        }

        // Set up color buttons for tab target
        if (priv.target == .tab) {
            setupColorButtons(self);
        }

        // Set the title for the dialog
        self.as(Dialog.Parent).setHeading(priv.target.title());

        // Show it. We could also just use virtual methods to bind to
        // response but this is pretty simple.
        self.as(adw.AlertDialog).choose(
            parent,
            null,
            alertDialogReady,
            self,
        );
    }

    fn alertDialogReady(
        _: ?*gobject.Object,
        result: *gio.AsyncResult,
        ud: ?*anyopaque,
    ) callconv(.c) void {
        const self: *Self = @ptrCast(@alignCast(ud));
        const response = self.as(adw.AlertDialog).chooseFinish(result);

        // If we didn't hit "okay" then we do nothing.
        if (std.mem.orderZ(u8, "ok", response) != .eq) return;

        // Emit our signal with the new title and color.
        const priv = self.private();
        const title = std.mem.span(priv.entry.getBuffer().getText());
        const color: c_int = if (priv.target == .tab)
            @as(c_int, self.readSelectedColor())
        else
            @as(c_int, -1);
        signals.set.impl.emit(
            self,
            null,
            .{ title.ptr, color },
            null,
        );
    }

    const color_labels = [8][:0]const u8{
        "\xe2\x97\x8f", // ● (blue - styled via CSS)
        "\xe2\x97\x8f", // ● (red)
        "\xe2\x97\x8f", // ● (yellow)
        "\xe2\x97\x8f", // ● (green)
        "\xe2\x97\x8f", // ● (purple)
        "\xe2\x97\x8f", // ● (orange)
        "\xe2\x97\x8f", // ● (brown)
        "\xe2\x97\x8f", // ● (gray)
    };

    const color_css_classes = [8][:0]const u8{
        "color-blue",
        "color-red",
        "color-yellow",
        "color-green",
        "color-purple",
        "color-orange",
        "color-brown",
        "color-gray",
    };

    fn setupColorButtons(self: *Self) void {
        const priv = self.private();
        const box = priv.color_box;

        // "None" button (no color circle)
        const auto_btn = gtk.ToggleButton.new();
        auto_btn.as(gtk.Button).setLabel("None");
        auto_btn.as(gtk.Widget).addCssClass("flat");
        if (priv.color < 0) auto_btn.setActive(1);
        box.append(auto_btn.as(gtk.Widget));

        // Color buttons grouped with auto
        for (0..8) |i| {
            const btn = gtk.ToggleButton.new();
            btn.as(gtk.Button).setLabel(color_labels[i]);
            btn.as(gtk.Widget).addCssClass("flat");
            btn.as(gtk.Widget).addCssClass("circular");
            btn.as(gtk.Widget).addCssClass(color_css_classes[i]);
            btn.setGroup(auto_btn);
            if (priv.color >= 0 and @as(u8, @intCast(priv.color)) == i) {
                btn.setActive(1);
            }
            box.append(btn.as(gtk.Widget));
        }
    }

    /// Read the active color button from the color_box.
    /// Returns -1 for auto, 0-7 for a color index.
    fn readSelectedColor(self: *Self) i8 {
        const box = self.private().color_box;
        var child = box.as(gtk.Widget).getFirstChild();
        var idx: i8 = -1; // first button = auto = -1
        while (child) |c| {
            if (gobject.ext.cast(gtk.ToggleButton, c)) |toggle| {
                if (toggle.getActive() != 0) return idx;
                idx += 1;
            }
            child = c.getNextSibling();
        }
        return -1;
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

    fn finalize(self: *Self) callconv(.c) void {
        const priv = self.private();
        if (priv.initial_value) |v| {
            glib.free(@ptrCast(@constCast(v)));
            priv.initial_value = null;
        }

        gobject.Object.virtual_methods.finalize.call(
            Class.parent,
            self.as(Parent),
        );
    }

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
                    .name = "title-dialog",
                }),
            );

            // Signals
            signals.set.impl.register(.{});

            // Bindings
            class.bindTemplateChildPrivate("entry", .{});
            class.bindTemplateChildPrivate("color_box", .{});

            // Properties
            gobject.ext.registerProperties(class, &.{
                properties.@"initial-value".impl,
                properties.@"initial-color".impl,
                properties.target.impl,
            });

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
            gobject.Object.virtual_methods.finalize.implement(class, &finalize);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
        pub const bindTemplateCallback = C.Class.bindTemplateCallback;
    };
};

pub const Target = enum(c_int) {
    surface,
    tab,
    pub fn title(self: Target) [*:0]const u8 {
        return switch (self) {
            .surface => i18n._("Change Terminal Title"),
            .tab => i18n._("Change Tab Title"),
        };
    }

    pub const getGObjectType = gobject.ext.defineEnum(
        Target,
        .{ .name = "GhosttyTitleDialogTarget" },
    );
};
