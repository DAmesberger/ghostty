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
const ssh_config = @import("../../../session/ssh_config.zig");

const log = std.log.scoped(.gtk_ghostty_ssh_connection_overlay);

pub const SshConnectionOverlay = extern struct {
    const Self = @This();
    parent_instance: Parent,
    pub const Parent = adw.Bin;
    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshConnectionOverlay",
        .instanceInit = &init,
        .classInit = &Class.init,
        .parent_class = &Class.parent,
        .private = .{ .Type = Private, .offset = &Private.offset },
    });

    pub const signals = struct {
        /// Emitted when the user selects an SSH host. The parameter is
        /// the SSH target string (e.g. "user@hostname" or "user@hostname:port").
        pub const @"host-connect" = struct {
            pub const name = "host-connect";
            pub const connect = impl.connect;
            const impl = gobject.ext.defineSignal(
                name,
                Self,
                &.{?[*:0]const u8},
                void,
            );
        };
    };

    const Private = struct {
        /// The dialog object containing the overlay UI.
        dialog: *adw.Dialog,

        /// The search input text field.
        search: *gtk.SearchEntry,

        /// The view containing each result row.
        view: *gtk.ListView,

        /// The model that provides filtered data for the view to display.
        model: *gtk.SingleSelection,

        /// The list that serves as the data source of the model.
        source: *gio.ListStore,

        pub var offset: c_int = 0;
    };

    /// Create a new instance of the SSH connection overlay. The caller will own a
    /// reference to the object.
    pub fn new() *Self {
        const self = gobject.ext.newInstance(Self, .{});

        // Sink ourselves so that we aren't floating anymore. We'll unref
        // ourselves when the dialog is closed or a host is activated.
        _ = self.refSink();

        // Populate the model with hosts from ~/.ssh/config.
        self.populateHosts();

        // Bump the ref so that the caller has a reference.
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

    fn close(self: *SshConnectionOverlay) void {
        const priv = self.private();
        _ = priv.dialog.close();
    }

    fn dialogClosed(_: *adw.Dialog, self: *SshConnectionOverlay) callconv(.c) void {
        self.unref();
    }

    fn searchStopped(_: *gtk.SearchEntry, self: *SshConnectionOverlay) callconv(.c) void {
        // ESC was pressed - close the overlay
        self.close();
    }

    fn searchActivated(search: *gtk.SearchEntry, self: *SshConnectionOverlay) callconv(.c) void {
        const priv = self.private();
        const n_items = priv.model.as(gio.ListModel).getNItems();
        const text_gstr = search.as(gtk.Editable).getText();
        const text: []const u8 = std.mem.sliceTo(text_gstr, 0);

        // If there are filtered results and the text doesn't contain '@',
        // activate the first/selected result (existing behavior).
        if (n_items > 0 and std.mem.indexOfScalar(u8, text, '@') == null) {
            self.activated(priv.model.getSelected());
            return;
        }

        // Otherwise, treat the search text as an ad-hoc SSH target if it
        // looks like one (non-empty and contains '@' or is a bare hostname).
        if (text.len > 0) {
            self.close();
            // We need a sentinel-terminated copy for the signal emission.
            // The text is borrowed from GTK so we can just pass the pointer
            // with the right sentinel cast.
            signals.@"host-connect".impl.emit(
                self,
                null,
                .{text_gstr},
                null,
            );
        }
    }

    fn rowActivated(_: *gtk.ListView, pos: c_uint, self: *SshConnectionOverlay) callconv(.c) void {
        self.activated(pos);
    }

    //---------------------------------------------------------------

    /// Show or hide the SSH hosts dialog. If the dialog is shown it will
    /// be modal over the given window.
    pub fn toggle(self: *SshConnectionOverlay, window: *Window) void {
        const priv = self.private();

        // If the dialog has been shown, close it.
        if (priv.dialog.as(gtk.Widget).getRealized() != 0) {
            self.close();
            return;
        }

        // Show the dialog
        priv.dialog.present(window.as(gtk.Widget));

        // Focus on the search bar when opening the dialog
        _ = priv.search.as(gtk.Widget).grabFocus();
    }

    /// Helper function to emit the connect signal with the selected host's
    /// target string.
    fn activated(self: *SshConnectionOverlay, pos: c_uint) void {
        const priv = self.private();

        // Use priv.model and not priv.source here to use the list of *visible* results
        const object_ = priv.model.as(gio.ListModel).getObject(pos);
        defer if (object_) |object| object.unref();

        // Close before emitting the signal to avoid being replaced by
        // another dialog.
        self.close();

        const entry = gobject.ext.cast(SshHostEntry, object_ orelse return) orelse return;

        const target = entry.propGetTarget() orelse return;

        signals.@"host-connect".impl.emit(
            self,
            null,
            .{target},
            null,
        );
    }

    /// Parse ~/.ssh/config and populate the list store with host entries.
    fn populateHosts(self: *SshConnectionOverlay) void {
        const priv = self.private();
        const alloc = Application.default().allocator();

        const hosts = ssh_config.parseConfig(alloc) catch |err| {
            log.warn("failed to parse SSH config: {}", .{err});
            return;
        };
        defer {
            for (hosts) |h| {
                alloc.free(h.alias);
                alloc.free(h.hostname);
                if (h.user) |u| alloc.free(u);
            }
            alloc.free(hosts);
        }

        for (hosts) |host| {
            const entry = SshHostEntry.newFromHost(host) orelse continue;
            priv.source.append(entry.as(gobject.Object));
            entry.unref();
        }
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
            gobject.ext.ensureType(SshHostEntry);
            gtk.Widget.Class.setTemplateFromResource(
                class.as(gtk.Widget.Class),
                comptime gresource.blueprint(.{
                    .major = 1,
                    .minor = 5,
                    .name = "ssh-connection-overlay",
                }),
            );

            // Bindings
            class.bindTemplateChildPrivate("dialog", .{});
            class.bindTemplateChildPrivate("search", .{});
            class.bindTemplateChildPrivate("view", .{});
            class.bindTemplateChildPrivate("model", .{});
            class.bindTemplateChildPrivate("source", .{});

            // Template Callbacks
            class.bindTemplateCallback("closed", &dialogClosed);
            class.bindTemplateCallback("search_stopped", &searchStopped);
            class.bindTemplateCallback("search_activated", &searchActivated);
            class.bindTemplateCallback("row_activated", &rowActivated);

            // Signals
            signals.@"host-connect".impl.register(.{});

            // Virtual methods
            gobject.Object.virtual_methods.dispose.implement(class, &dispose);
        }

        pub const as = C.Class.as;
        pub const bindTemplateChildPrivate = C.Class.bindTemplateChildPrivate;
        pub const bindTemplateCallback = C.Class.bindTemplateCallback;
    };
};

/// GObject wrapper for an SSH host entry in the list model.
///
/// As GTK list models only accept objects that are within the GObject hierarchy,
/// we have to construct a wrapper to be easily consumed by the list model.
pub const SshHostEntry = extern struct {
    pub const Self = @This();
    pub const Parent = gobject.Object;
    parent: Parent,

    pub const getGObjectType = gobject.ext.defineClass(Self, .{
        .name = "GhosttySshHostEntry",
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

        pub const target = struct {
            pub const name = "target";
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
                            .getter = propGetTarget,
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
        target_str: ?[:0]const u8 = null,

        pub var offset: c_int = 0;
    };

    /// Create a new SshHostEntry from an SshHost.
    pub fn newFromHost(host: ssh_config.SshHost) ?*Self {
        const self = gobject.ext.newInstance(Self, .{});
        const priv = self.private();
        const alloc = priv.arena.allocator();

        // Title: the SSH alias
        priv.title_str = alloc.dupeZ(u8, host.alias) catch {
            self.unref();
            return null;
        };

        // Subtitle: user@hostname:port (always show full detail)
        priv.subtitle_str = blk: {
            if (host.user) |user| {
                break :blk std.fmt.allocPrintSentinel(alloc, "{s}@{s}:{d}", .{
                    user,
                    host.hostname,
                    host.port,
                }, 0) catch {
                    self.unref();
                    return null;
                };
            } else {
                break :blk std.fmt.allocPrintSentinel(alloc, "{s}:{d}", .{
                    host.hostname,
                    host.port,
                }, 0) catch {
                    self.unref();
                    return null;
                };
            }
        };

        // Target: the string to pass to SSH connection
        // user@hostname or user@hostname:port (if port != 22)
        // If no user, just hostname or hostname:port
        priv.target_str = blk: {
            if (host.user) |user| {
                if (host.port != 22) {
                    break :blk std.fmt.allocPrintSentinel(alloc, "{s}@{s}:{d}", .{
                        user,
                        host.hostname,
                        host.port,
                    }, 0) catch {
                        self.unref();
                        return null;
                    };
                } else {
                    break :blk std.fmt.allocPrintSentinel(alloc, "{s}@{s}", .{
                        user,
                        host.hostname,
                    }, 0) catch {
                        self.unref();
                        return null;
                    };
                }
            } else {
                if (host.port != 22) {
                    break :blk std.fmt.allocPrintSentinel(alloc, "{s}:{d}", .{
                        host.hostname,
                        host.port,
                    }, 0) catch {
                        self.unref();
                        return null;
                    };
                } else {
                    break :blk alloc.dupeZ(u8, host.hostname) catch {
                        self.unref();
                        return null;
                    };
                }
            }
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

    pub fn propGetTarget(self: *Self) ?[:0]const u8 {
        return self.private().target_str;
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
                properties.target.impl,
            });

            gobject.Object.virtual_methods.finalize.implement(class, &finalize);
        }
    };
};
