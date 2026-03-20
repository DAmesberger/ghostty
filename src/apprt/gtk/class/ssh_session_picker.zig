const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const adw = @import("adw");
const gio = @import("gio");
const glib = @import("glib");
const gobject = @import("gobject");
const gtk = @import("gtk");

const gresource = @import("../build/gresource.zig");
const Common = @import("../class.zig").Common;
const Application = @import("application.zig").Application;
const Window = @import("window.zig").Window;

const log = std.log.scoped(.gtk_ghostty_ssh_session_picker);

pub const SshSessionPicker = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.Bin;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshSessionPicker",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    pub const signals = struct {
        /// Emitted when the user selects a session. Parameters are the
        /// SSH target string and the session ID (UUID).
        pub const @"session-selected" = struct {
            pub const name = "session-selected";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{ ?[*:0]const u8, ?[*:0]const u8 },
                void,
            );
        };
    };

    const Private = struct {
        /// The dialog object containing the picker UI.
        dialog: *adw.Dialog,

        /// The stack widget for switching between loading/list/error views.
        stack: *gtk.Stack,

        /// The error label.
        error_label: *gtk.Label,

        /// The list view.
        view: *gtk.ListView,

        /// The selection model.
        model: *gtk.SingleSelection,

        /// The list store backing the model.
        source: *gio.ListStore,

        /// The SSH target this picker is querying.
        ssh_target: ?[:0]const u8 = null,

        pub var offset: c_int = 0;
    };

    /// Create a new instance of the SSH session picker.
    pub fn new() ?*Self {
        const self = gobject.ext.newInstance(Self, .{});

        // Sink ourselves so that we aren't floating anymore.
        _ = self.refSink();

        return self.ref();
    }

    //---------------------------------------------------------------
    // Virtual Methods

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));
    }

    fn dispose(self: *Self) callconv(.c) void {
        const priv = self.private();
        priv.source.removeAll();

        if (priv.ssh_target) |t| {
            Application.default().allocator().free(t);
            priv.ssh_target = null;
        }

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
    // Signal Handlers

    fn close(self: *SshSessionPicker) void {
        const priv = self.private();
        _ = priv.dialog.close();
    }

    fn dialogClosed(_: *adw.Dialog, self: *SshSessionPicker) callconv(.c) void {
        self.unref();
    }

    fn rowActivated(_: *gtk.ListView, pos: c_uint, self: *SshSessionPicker) callconv(.c) void {
        self.activated(pos);
    }

    //---------------------------------------------------------------
    // Public API

    /// Show the picker as a dialog over the given window.
    pub fn present(self: *SshSessionPicker, window: *Window) void {
        const priv = self.private();

        // Show the dialog
        priv.dialog.present(window.as(gtk.Widget));

        // Start in loading state
        priv.stack.setVisibleChildName("loading");
    }

    /// Set the SSH target associated with this picker.
    pub fn setSshTarget(self: *SshSessionPicker, target: [:0]const u8) void {
        const priv = self.private();
        const alloc = Application.default().allocator();
        if (priv.ssh_target) |t| alloc.free(t);
        priv.ssh_target = alloc.dupeZ(u8, target) catch null;
    }

    /// Add a session entry to the list.
    pub fn addSession(
        self: *SshSessionPicker,
        id: [:0]const u8,
        label: [:0]const u8,
        detail: [:0]const u8,
        status: [:0]const u8,
    ) void {
        const priv = self.private();
        const entry = SshSessionEntry.newFromData(id, label, detail, status) orelse return;
        priv.source.append(entry.as(gobject.Object));
        entry.unref();
    }

    /// Transition the stack to the list view.
    pub fn setLoaded(self: *SshSessionPicker) void {
        const priv = self.private();
        priv.stack.setVisibleChildName("list");
    }

    /// Show an error message.
    pub fn setError(self: *SshSessionPicker, message: [:0]const u8) void {
        const priv = self.private();
        priv.error_label.setText(message);
        priv.stack.setVisibleChildName("error");
    }

    //---------------------------------------------------------------
    // Internal

    /// Emit the session-selected signal with the selected entry.
    fn activated(self: *SshSessionPicker, pos: c_uint) void {
        const priv = self.private();

        const object_ = priv.model.as(gio.ListModel).getObject(pos);
        defer if (object_) |object| object.unref();

        self.close();

        const entry = gobject.ext.cast(SshSessionEntry, object_ orelse return) orelse return;

        const session_id = entry.propGetSessionId() orelse return;
        const ssh_target: ?[*:0]const u8 = if (priv.ssh_target) |t| t.ptr else null;
        const sid_ptr: [*:0]const u8 = session_id.ptr;

        signals.@"session-selected".impl.emit(
            self,
            null,
            .{ ssh_target, @as(?[*:0]const u8, sid_ptr) },
            null,
        );
    }

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
            gobject.ext.ensureType(SshSessionEntry);
            gtk.Widget.Class.setTemplateFromResource(
                class.as(gtk.Widget.Class),
                comptime gresource.blueprint(.{
                    .major = 1,
                    .minor = 5,
                    .name = "ssh-session-picker",
                }),
            );

            // Bindings
            class.bindTemplateChildPrivate("dialog", .{});
            class.bindTemplateChildPrivate("stack", .{});
            class.bindTemplateChildPrivate("error_label", .{});
            class.bindTemplateChildPrivate("view", .{});
            class.bindTemplateChildPrivate("model", .{});
            class.bindTemplateChildPrivate("source", .{});

            // Template Callbacks
            class.bindTemplateCallback("closed", &dialogClosed);
            class.bindTemplateCallback("row_activated", &rowActivated);

            // Signals
            signals.@"session-selected".impl.register(.{});

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
        pub const bindTemplateCallback = C.Class.bindTemplateCallback;
    };
};

/// GObject wrapper for an SSH session entry in the list model.
pub const SshSessionEntry = extern struct {
    pub const Self = @This();
    pub const Parent = gobject.Object;
    parent: Parent,

    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshSessionEntry",
        .instanceInit = &init,
        .classInit = Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    const properties = struct {
        pub const title = struct {
            pub const name = "title";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = gobject.ext.typedAccessor(
                        Self,
                        ?[:0]const u8,
                        .{
                            .getter = propGetTitle,
                            .getter_transfer = .none,
                        },
                    ),
                },
            );
        };

        pub const subtitle = struct {
            pub const name = "subtitle";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = gobject.ext.typedAccessor(
                        Self,
                        ?[:0]const u8,
                        .{
                            .getter = propGetSubtitle,
                            .getter_transfer = .none,
                        },
                    ),
                },
            );
        };

        pub const status = struct {
            pub const name = "status";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = gobject.ext.typedAccessor(
                        Self,
                        ?[:0]const u8,
                        .{
                            .getter = propGetStatus,
                            .getter_transfer = .none,
                        },
                    ),
                },
            );
        };

        pub const @"session-id" = struct {
            pub const name = "session-id";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                ?[:0]const u8,
                .{
                    .default = null,
                    .accessor = gobject.ext.typedAccessor(
                        Self,
                        ?[:0]const u8,
                        .{
                            .getter = propGetSessionId,
                            .getter_transfer = .none,
                        },
                    ),
                },
            );
        };
    };

    const Private = struct {
        arena: ArenaAllocator,
        title_str: ?[:0]const u8 = null,
        subtitle_str: ?[:0]const u8 = null,
        status_str: ?[:0]const u8 = null,
        session_id_str: ?[:0]const u8 = null,

        pub var offset: c_int = 0;
    };

    /// Create a new SshSessionEntry from raw data.
    pub fn newFromData(
        id: [:0]const u8,
        label: [:0]const u8,
        detail: [:0]const u8,
        status: [:0]const u8,
    ) ?*Self {
        const self = gobject.ext.newInstance(Self, .{});
        const priv = self.private();
        const alloc = priv.arena.allocator();

        // Title: the session label
        priv.title_str = alloc.dupeZ(u8, label) catch {
            self.unref();
            return null;
        };

        // Subtitle: surface count / detail info
        priv.subtitle_str = alloc.dupeZ(u8, detail) catch {
            self.unref();
            return null;
        };

        // Status: attached/detached
        priv.status_str = alloc.dupeZ(u8, status) catch {
            self.unref();
            return null;
        };

        // Session ID
        priv.session_id_str = alloc.dupeZ(u8, id) catch {
            self.unref();
            return null;
        };

        return self;
    }

    fn init(self: *Self, _: *Class) callconv(.c) void {
        const priv = self.private();
        priv.arena = .init(Application.default().allocator());
    }

    fn finalize(self: *Self) callconv(.c) void {
        const priv = self.private();
        priv.arena.deinit();

        gobject.Object.virtual_methods.finalize.call(
            Class.parent,
            self.as(Parent),
        );
    }

    //---------------------------------------------------------------

    pub fn propGetTitle(self: *Self) ?[:0]const u8 {
        return self.private().title_str;
    }

    pub fn propGetSubtitle(self: *Self) ?[:0]const u8 {
        return self.private().subtitle_str;
    }

    pub fn propGetStatus(self: *Self) ?[:0]const u8 {
        return self.private().status_str;
    }

    pub fn propGetSessionId(self: *Self) ?[:0]const u8 {
        return self.private().session_id_str;
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
            gobject.ext.registerProperties(class, &.{
                properties.title.impl,
                properties.subtitle.impl,
                properties.status.impl,
                properties.@"session-id".impl,
            });

            gobject.Object.virtual_methods.finalize.implement(class, &finalize);
        }
    };
};
