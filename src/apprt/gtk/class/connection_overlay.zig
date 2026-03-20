const std = @import("std");
const adw = @import("adw");
const gdk = @import("gdk");
const glib = @import("glib");
const gobject = @import("gobject");
const gtk = @import("gtk");

const gresource = @import("../build/gresource.zig");
const Common = @import("../class.zig").Common;

const log = std.log.scoped(.gtk_ghostty_connection_overlay);

/// Overlay that shows SSH connection status, upload progress, and password
/// prompts. Replaces the z2d-based ConnectionOverlay with a native GTK widget
/// consistent with ResizeOverlay, SearchOverlay, etc.
pub const ConnectionOverlay = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.Bin;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttyConnectionOverlay",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    pub const properties = struct {
        pub const status = struct {
            pub const name = "status";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = C.privateStringFieldAccessor("status_text"),
                },
            );
        };

        pub const @"show-progress" = struct {
            pub const name = "show-progress";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                bool,
                .{
                    .default = false,
                    .accessor = gobject.ext.privateFieldAccessor(
                        Self,
                        Private,
                        &Private.offset,
                        "show_progress",
                    ),
                },
            );
        };

        pub const progress = struct {
            pub const name = "progress";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                f64,
                .{
                    .default = 0.0,
                    .minimum = 0.0,
                    .maximum = 1.0,
                    .accessor = gobject.ext.privateFieldAccessor(
                        Self,
                        Private,
                        &Private.offset,
                        "progress_fraction",
                    ),
                },
            );
        };

        pub const @"show-password" = struct {
            pub const name = "show-password";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                bool,
                .{
                    .default = false,
                    .accessor = gobject.ext.privateFieldAccessor(
                        Self,
                        Private,
                        &Private.offset,
                        "show_password",
                    ),
                },
            );
        };
    };

    pub const signals = struct {
        /// Emitted when the user submits a password via the entry.
        pub const @"password-submitted" = struct {
            pub const name = "password-submitted";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{?[*:0]const u8},
                void,
            );
        };

        /// Emitted when the user cancels the password prompt (Escape).
        pub const @"password-cancelled" = struct {
            pub const name = "password-cancelled";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{},
                void,
            );
        };

        /// Emitted when the user clicks the action button (Cancel/Close).
        pub const @"action-triggered" = struct {
            pub const name = "action-triggered";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{},
                void,
            );
        };
    };

    const Private = struct {
        /// The label showing connection status text.
        status_label: *gtk.Label,

        /// The progress bar for upload progress.
        progress_bar: *gtk.ProgressBar,

        /// The password entry for interactive auth.
        password_entry: *gtk.PasswordEntry,

        /// The action button (Cancel/Close) for reconnecting/failed states.
        action_button: *gtk.Button,

        /// The status text (null = hidden).
        status_text: ?[:0]const u8 = null,

        /// Whether the progress bar is visible.
        show_progress: bool = false,

        /// The progress fraction (0.0–1.0).
        progress_fraction: f64 = 0.0,

        /// Whether the password entry is visible.
        show_password: bool = false,

        /// Key controller for Escape handling.
        key_controller: ?*gtk.EventControllerKey = null,

        pub var offset: c_int = 0;
    };

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));

        const priv = self.private();

        // Add a key controller on the overlay itself to handle Escape for
        // both the password entry and the action button states.
        const key_ctrl = gtk.EventControllerKey.new();
        _ = gtk.EventControllerKey.signals.key_pressed.connect(
            key_ctrl,
            *Self,
            onKeyPressed,
            self,
            .{},
        );
        self.as(gtk.Widget).addController(key_ctrl.as(gtk.EventController));
        priv.key_controller = key_ctrl;
    }

    /// Set the status text and update visibility. Passing null hides the overlay.
    pub fn setStatus(self: *Self, text: ?[:0]const u8) void {
        const priv = self.private();
        if (priv.status_text) |v| glib.free(@ptrCast(@constCast(v)));
        priv.status_text = null;
        if (text) |v| priv.status_text = glib.ext.dupeZ(u8, v);
        self.as(gobject.Object).notifyByPspec(properties.status.impl.param_spec);

        // Update label
        if (text) |v| {
            priv.status_label.setLabel(v);
            self.as(gtk.Widget).setVisible(1);
        } else {
            self.as(gtk.Widget).setVisible(0);
        }
    }

    /// Set the progress bar visibility.
    pub fn setShowProgress(self: *Self, show: bool) void {
        const priv = self.private();
        priv.show_progress = show;
        priv.progress_bar.as(gtk.Widget).setVisible(@intFromBool(show));
        self.as(gobject.Object).notifyByPspec(properties.@"show-progress".impl.param_spec);
    }

    /// Set the progress fraction (0.0–1.0).
    pub fn setProgress(self: *Self, fraction: f64) void {
        const priv = self.private();
        priv.progress_fraction = fraction;
        priv.progress_bar.setFraction(fraction);
        self.as(gobject.Object).notifyByPspec(properties.progress.impl.param_spec);
    }

    /// Show or hide the password entry. When shown, the overlay becomes interactive.
    pub fn setShowPassword(self: *Self, show: bool) void {
        const priv = self.private();
        priv.show_password = show;
        priv.password_entry.as(gtk.Widget).setVisible(@intFromBool(show));

        const widget = self.as(gtk.Widget);
        if (show) {
            // Make overlay interactive so it captures keyboard input.
            widget.setCanFocus(1);
            widget.setCanTarget(1);
            widget.setFocusable(1);
            _ = priv.password_entry.as(gtk.Widget).grabFocus();
        } else {
            // Only return to non-interactive if action button is also hidden.
            if (priv.action_button.as(gtk.Widget).getVisible() == 0) {
                widget.setCanFocus(0);
                widget.setCanTarget(0);
                widget.setFocusable(0);
            }
        }

        self.as(gobject.Object).notifyByPspec(properties.@"show-password".impl.param_spec);
    }

    /// Show or hide the action button with the given label. When shown with the
    /// password hidden, the overlay becomes interactive so the button can be clicked.
    pub fn setActionButton(self: *Self, label: ?[:0]const u8) void {
        const priv = self.private();
        if (label) |l| {
            priv.action_button.setLabel(l);
            priv.action_button.as(gtk.Widget).setVisible(1);
            // Make overlay interactive so the button can receive input.
            const widget = self.as(gtk.Widget);
            widget.setCanFocus(1);
            widget.setCanTarget(1);
            widget.setFocusable(1);
            // Focus the button so Enter activates it.
            _ = priv.action_button.as(gtk.Widget).grabFocus();
        } else {
            priv.action_button.as(gtk.Widget).setVisible(0);
            // Only return to non-interactive if password is also hidden.
            if (!priv.show_password) {
                const widget = self.as(gtk.Widget);
                widget.setCanFocus(0);
                widget.setCanTarget(0);
                widget.setFocusable(0);
            }
        }
    }

    // Template callback: user pressed Enter in the password entry.
    fn passwordActivate(_: *gtk.PasswordEntry, self: *Self) callconv(.c) void {
        const priv = self.private();
        const text = priv.password_entry.as(gtk.Editable).getText();
        signals.@"password-submitted".impl.emit(self, null, .{text}, null);

        // Clear the entry after submission.
        priv.password_entry.as(gtk.Editable).deleteText(0, -1);
    }

    // Template callback: user clicked the action button.
    fn actionButtonClicked(_: *gtk.Button, self: *Self) callconv(.c) void {
        signals.@"action-triggered".impl.emit(self, null, .{}, null);
    }

    // Key pressed handler on the overlay for Escape.
    fn onKeyPressed(
        _: *gtk.EventControllerKey,
        keyval: c_uint,
        _: c_uint,
        _: gdk.ModifierType,
        self: *Self,
    ) callconv(.c) c_int {
        if (keyval == gdk.KEY_Escape) {
            const priv = self.private();
            if (priv.show_password) {
                signals.@"password-cancelled".impl.emit(self, null, .{}, null);
                return 1;
            }
            // Handle Escape for action button states (reconnecting/failed).
            if (priv.action_button.as(gtk.Widget).getVisible() != 0) {
                signals.@"action-triggered".impl.emit(self, null, .{}, null);
                return 1;
            }
        }
        return 0;
    }

    //---------------------------------------------------------------
    // Virtual methods

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
        if (priv.status_text) |v| {
            glib.free(@ptrCast(@constCast(v)));
            priv.status_text = null;
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
                    .minor = 2,
                    .name = "connection-overlay",
                }),
            );

            // Bindings
            class.bindTemplateChildPrivate("status_label", .{});
            class.bindTemplateChildPrivate("progress_bar", .{});
            class.bindTemplateChildPrivate("password_entry", .{});
            class.bindTemplateChildPrivate("action_button", .{});

            // Template callbacks
            class.bindTemplateCallback("password_activate", &passwordActivate);
            class.bindTemplateCallback("action_button_clicked", &actionButtonClicked);

            // Properties
            gobject.ext.registerProperties(class, &.{
                properties.status.impl,
                properties.@"show-progress".impl,
                properties.progress.impl,
                properties.@"show-password".impl,
            });

            // Signals
            signals.@"password-submitted".impl.register(.{});
            signals.@"password-cancelled".impl.register(.{});
            signals.@"action-triggered".impl.register(.{});

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
            gobject.Object.virtual_methods.finalize.implement(class, &finalize);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
        pub const bindTemplateCallback = C.Class.bindTemplateCallback;
    };
};
