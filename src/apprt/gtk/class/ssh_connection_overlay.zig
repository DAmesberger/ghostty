const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const adw = @import("adw");
const gio = @import("gio");
const glib = @import("glib");
const gobject = @import("gobject");
const gtk = @import("gtk");

const posix = std.posix;
const xdg = @import("../../../os/xdg.zig");
const gresource = @import("../build/gresource.zig");
const Common = @import("../class.zig").Common;
const Application = @import("application.zig").Application;
const Window = @import("window.zig").Window;
const ssh_config = @import("../../../session/ssh_config.zig");

const log = std.log.scoped(.gtk_ghostty_ssh_connection_overlay);

const max_recent_entries = 50;

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

        // Build the list item factory in code so we can connect delete
        // button clicks with proper per-row data.
        const factory = gtk.SignalListItemFactory.new();
        _ = gtk.SignalListItemFactory.signals.setup.connect(factory, *Self, &factorySetup, self, .{});
        _ = gtk.SignalListItemFactory.signals.bind.connect(factory, *Self, &factoryBind, self, .{});
        self.private().view.setFactory(factory.as(gtk.ListItemFactory));
    }

    fn factorySetup(_: *gtk.SignalListItemFactory, list_item_obj: *gobject.Object, _: *Self) callconv(.c) void {
        const list_item = gobject.ext.cast(gtk.ListItem, list_item_obj) orelse return;

        const row_box = gtk.Box.new(.horizontal, 8);
        row_box.as(gtk.Widget).setMarginStart(12);
        row_box.as(gtk.Widget).setMarginEnd(6);
        row_box.as(gtk.Widget).setMarginTop(8);
        row_box.as(gtk.Widget).setMarginBottom(8);

        const icon = gtk.Image.new();
        icon.as(gtk.Widget).setValign(.center);
        icon.as(gtk.Widget).addCssClass("dim-label");
        row_box.append(icon.as(gtk.Widget));

        const info_box = gtk.Box.new(.vertical, 2);
        info_box.as(gtk.Widget).setValign(.center);
        info_box.as(gtk.Widget).setHexpand(1);

        const title_label = gtk.Label.new(null);
        title_label.as(gtk.Widget).setHalign(.start);
        title_label.setEllipsize(.end);
        title_label.setSingleLineMode(1);
        title_label.as(gtk.Widget).addCssClass("heading");
        info_box.append(title_label.as(gtk.Widget));

        const subtitle_label = gtk.Label.new(null);
        subtitle_label.as(gtk.Widget).setHalign(.start);
        subtitle_label.setEllipsize(.end);
        subtitle_label.setSingleLineMode(1);
        subtitle_label.as(gtk.Widget).addCssClass("dim-label");
        subtitle_label.as(gtk.Widget).addCssClass("caption");
        info_box.append(subtitle_label.as(gtk.Widget));

        row_box.append(info_box.as(gtk.Widget));

        const delete_btn = gtk.Button.new();
        delete_btn.setIconName("user-trash-symbolic");
        delete_btn.as(gtk.Widget).setValign(.center);
        delete_btn.as(gtk.Widget).addCssClass("flat");
        delete_btn.as(gtk.Widget).addCssClass("circular");
        delete_btn.as(gtk.Widget).setVisible(0);
        row_box.append(delete_btn.as(gtk.Widget));

        list_item.setChild(row_box.as(gtk.Widget));
    }

    fn factoryBind(_: *gtk.SignalListItemFactory, list_item_obj: *gobject.Object, self: *Self) callconv(.c) void {
        const list_item = gobject.ext.cast(gtk.ListItem, list_item_obj) orelse return;
        const entry = gobject.ext.cast(SshHostEntry, list_item.getItem() orelse return) orelse return;
        const row_box = gobject.ext.cast(gtk.Box, list_item.getChild() orelse return) orelse return;

        // Walk children: icon, info_box, delete_btn
        const icon = gobject.ext.cast(gtk.Image, row_box.as(gtk.Widget).getFirstChild() orelse return) orelse return;
        const info_widget = icon.as(gtk.Widget).getNextSibling() orelse return;
        const info_box = gobject.ext.cast(gtk.Box, info_widget) orelse return;
        const delete_widget = info_widget.getNextSibling() orelse return;
        const delete_btn = gobject.ext.cast(gtk.Button, delete_widget) orelse return;

        if (entry.propGetIcon()) |icon_name| {
            icon.setFromIconName(@ptrCast(icon_name.ptr));
        }

        // Title label is first child of info_box
        const title_widget = info_box.as(gtk.Widget).getFirstChild() orelse return;
        const title_label = gobject.ext.cast(gtk.Label, title_widget) orelse return;
        title_label.setText(entry.propGetTitle() orelse "");

        // Subtitle label is second child
        const subtitle_widget = title_widget.getNextSibling() orelse return;
        const subtitle_label = gobject.ext.cast(gtk.Label, subtitle_widget) orelse return;
        subtitle_label.setText(entry.propGetSubtitle() orelse "");

        // Show delete button only for recent entries
        const deletable = entry.propGetDeletable();
        delete_btn.as(gtk.Widget).setVisible(@intFromBool(deletable));

        if (deletable) {
            // Connect delete button click — pass the overlay and target
            const target = entry.propGetTarget() orelse return;
            _ = gtk.Button.signals.clicked.connect(delete_btn, *Self, &onDeleteClicked, self, .{});
            // Store target in the button's widget name for retrieval on click
            delete_btn.as(gtk.Widget).setName(target);
        }
    }

    fn onDeleteClicked(button: *gtk.Button, self: *Self) callconv(.c) void {
        const name = button.as(gtk.Widget).getName();
        self.deleteRecent(name);
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

    /// Delete a recent connection entry from the history file and list store.
    pub fn deleteRecent(self: *SshConnectionOverlay, target: [*:0]const u8) void {
        const priv = self.private();
        const alloc = Application.default().allocator();
        const target_slice: []const u8 = std.mem.sliceTo(target, 0);

        removeRecentConnection(alloc, target_slice);

        // Remove matching entry from the ListStore.
        const n = priv.source.as(gio.ListModel).getNItems();
        for (0..n) |i| {
            const obj = priv.source.as(gio.ListModel).getObject(@intCast(i)) orelse continue;
            defer obj.unref();
            const entry = gobject.ext.cast(SshHostEntry, obj) orelse continue;
            const entry_target = entry.propGetTarget() orelse continue;
            if (std.mem.eql(u8, std.mem.sliceTo(entry_target, 0), target_slice)) {
                priv.source.remove(@intCast(i));
                break;
            }
        }
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

    /// Load recent connections and ~/.ssh/config hosts into the list store.
    /// Recent connections appear first, followed by config hosts that
    /// aren't already in the recent list.
    fn populateHosts(self: *SshConnectionOverlay) void {
        const priv = self.private();
        const alloc = Application.default().allocator();

        // 1. Load recent connections (appear at top).
        const recents = loadRecentConnections(alloc);
        defer freeRecentConnections(alloc, recents);

        for (recents) |r| {
            const entry = SshHostEntry.newRecent(r.target, r.timestamp) orelse continue;
            priv.source.append(entry.as(gobject.Object));
            entry.unref();
        }

        // 2. Load SSH config hosts, skipping any already in recents.
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
            // Skip if this host's target is already in the recent list.
            const dominated = for (recents) |r| {
                if (hostMatchesTarget(host, r.target)) break true;
            } else false;
            if (dominated) continue;

            const entry = SshHostEntry.newFromHost(host) orelse continue;
            priv.source.append(entry.as(gobject.Object));
            entry.unref();
        }
    }

    /// Check if an SSH config host matches a recent connection target string.
    fn hostMatchesTarget(host: ssh_config.SshHost, target: []const u8) bool {
        // Compare alias
        if (std.mem.eql(u8, host.alias, target)) return true;
        // Compare hostname
        if (std.mem.eql(u8, host.hostname, target)) return true;
        // Compare user@hostname
        if (host.user) |user| {
            // Build user@hostname for comparison
            var buf: [512]u8 = undefined;
            const formatted = std.fmt.bufPrint(&buf, "{s}@{s}", .{ user, host.hostname }) catch return false;
            if (std.mem.eql(u8, formatted, target)) return true;
            // With port
            const formatted_port = std.fmt.bufPrint(&buf, "{s}@{s}:{d}", .{ user, host.hostname, host.port }) catch return false;
            if (std.mem.eql(u8, formatted_port, target)) return true;
        }
        return false;
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

        pub const deletable = struct {
            pub const name = "deletable";
            const impl = gobject.ext.defineProperty(
                name,
                Self,
                bool,
                .{
                    .default = false,
                    .accessor = gobject.ext.typedAccessor(
                        Self,
                        bool,
                        .{ .getter = propGetDeletable },
                    ),
                },
            );
        };

        pub const icon = struct {
            pub const name = "icon";
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
                            .getter = propGetIcon,
                            .getter_transfer = .none,
                        },
                    ),
                },
            );
        };

        /// Sort key for custom ordering: recent entries (negative timestamp)
        /// sort before config entries (0).
        pub const sort_key = struct {
            pub const name = "sort-key";
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
                            .getter = propGetSortKey,
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
        sort_key_str: ?[:0]const u8 = null,
        icon_name: [:0]const u8 = "network-server-symbolic",
        is_deletable: bool = false,

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

        // Sort key: "1-{alias}" — config entries sort after recents ("0-...")
        priv.sort_key_str = std.fmt.allocPrintSentinel(alloc, "1-{s}", .{host.alias}, 0) catch {
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

    fn propGetDeletable(self: *Self) bool {
        return self.private().is_deletable;
    }

    fn propGetIcon(self: *Self) ?[:0]const u8 {
        return self.private().icon_name;
    }

    fn propGetSortKey(self: *Self) ?[:0]const u8 {
        return self.private().sort_key_str;
    }

    /// Create a new SshHostEntry from a recent connection target string.
    pub fn newRecent(target: []const u8, timestamp: i64) ?*Self {
        const self = gobject.ext.newInstance(Self, .{});
        const priv = self.private();
        const alloc = priv.arena.allocator();

        priv.is_deletable = true;
        priv.icon_name = "document-open-recent-symbolic";

        // Sort key: "0-{inverted_timestamp}" — recents sort before config ("1-..."),
        // and within recents, most recent first (smaller inverted = more recent).
        const inverted = std.math.maxInt(i64) - timestamp;
        priv.sort_key_str = std.fmt.allocPrintSentinel(alloc, "0-{d:0>19}", .{inverted}, 0) catch {
            self.unref();
            return null;
        };

        // Title: the target string itself
        priv.title_str = alloc.dupeZ(u8, target) catch {
            self.unref();
            return null;
        };

        // Subtitle: "Recent connection"
        priv.subtitle_str = alloc.dupeZ(u8, "Recent connection") catch {
            self.unref();
            return null;
        };

        // Target: the connection string as-is
        priv.target_str = alloc.dupeZ(u8, target) catch {
            self.unref();
            return null;
        };

        return self;
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
                properties.deletable.impl,
                properties.icon.impl,
                properties.sort_key.impl,
            });

            gobject.Object.virtual_methods.finalize.implement(class, &finalize);
        }
    };
};

// ---------------------------------------------------------------
// Recent connections file I/O
// ---------------------------------------------------------------

const RecentEntry = struct {
    target: []const u8,
    timestamp: i64,
};

fn recentFilePath(alloc: Allocator) ![]const u8 {
    const state_dir = try xdg.state(alloc, .{ .subdir = "ghostty" });
    defer alloc.free(state_dir);
    return try std.fs.path.join(alloc, &.{ state_dir, "ssh_recent" });
}

/// Load recent connections from disk, sorted by timestamp descending.
fn loadRecentConnections(alloc: Allocator) []RecentEntry {
    const path = recentFilePath(alloc) catch return &.{};
    defer alloc.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return &.{};
    defer file.close();

    const content = file.readToEndAlloc(alloc, 1024 * 64) catch return &.{};
    defer alloc.free(content);

    var entries: std.ArrayListUnmanaged(RecentEntry) = .empty;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, '|');
        const target_raw = parts.next() orelse continue;
        const ts_raw = parts.next() orelse continue;
        const target = alloc.dupe(u8, target_raw) catch continue;
        const timestamp = std.fmt.parseInt(i64, ts_raw, 10) catch 0;
        entries.append(alloc, .{ .target = target, .timestamp = timestamp }) catch {
            alloc.free(target);
            continue;
        };
    }

    // Sort by timestamp descending (most recent first).
    const slice = entries.toOwnedSlice(alloc) catch return &.{};
    std.mem.sort(RecentEntry, slice, {}, struct {
        fn cmp(_: void, a: RecentEntry, b: RecentEntry) bool {
            return a.timestamp > b.timestamp;
        }
    }.cmp);
    return slice;
}

fn freeRecentConnections(alloc: Allocator, entries: []RecentEntry) void {
    for (entries) |e| alloc.free(e.target);
    alloc.free(entries);
}

/// Save a connection target to the recent connections file.
/// Updates the timestamp if already present, otherwise appends. Caps at max_recent_entries.
pub fn saveRecentConnection(alloc: Allocator, target: []const u8) void {
    const path = recentFilePath(alloc) catch return;
    defer alloc.free(path);

    // Ensure parent directory exists.
    if (std.fs.path.dirnamePosix(path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return,
        };
    }

    var entries: std.ArrayListUnmanaged(RecentEntry) = .empty;
    defer {
        for (entries.items) |e| alloc.free(e.target);
        entries.deinit(alloc);
    }

    // Load existing entries, skipping the one we're updating.
    const existing = loadRecentConnections(alloc);
    defer freeRecentConnections(alloc, existing);
    for (existing) |e| {
        if (std.mem.eql(u8, e.target, target)) continue;
        entries.append(alloc, .{
            .target = alloc.dupe(u8, e.target) catch continue,
            .timestamp = e.timestamp,
        }) catch continue;
    }

    // Prepend the new/updated entry.
    const now = std.time.timestamp();
    const target_copy = alloc.dupe(u8, target) catch return;
    entries.insert(alloc, 0, .{ .target = target_copy, .timestamp = now }) catch {
        alloc.free(target_copy);
        return;
    };

    // Cap at max entries.
    while (entries.items.len > max_recent_entries) {
        if (entries.pop()) |removed| alloc.free(removed.target);
    }

    // Write back.
    writeRecentFile(alloc, path, entries.items);
}

/// Remove a recent connection entry by target string.
fn removeRecentConnection(alloc: Allocator, target: []const u8) void {
    const path = recentFilePath(alloc) catch return;
    defer alloc.free(path);

    const existing = loadRecentConnections(alloc);
    defer freeRecentConnections(alloc, existing);

    var entries: std.ArrayListUnmanaged(RecentEntry) = .empty;
    defer {
        for (entries.items) |e| alloc.free(e.target);
        entries.deinit(alloc);
    }

    for (existing) |e| {
        if (std.mem.eql(u8, e.target, target)) continue;
        entries.append(alloc, .{
            .target = alloc.dupe(u8, e.target) catch continue,
            .timestamp = e.timestamp,
        }) catch continue;
    }

    writeRecentFile(alloc, path, entries.items);
}

fn writeRecentFile(alloc: Allocator, path: []const u8, entries: []const RecentEntry) void {
    const file = std.fs.createFileAbsolute(path, .{ .truncate = true }) catch return;
    defer file.close();
    // Build content in memory and write at once.
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const w = buf.writer(alloc);
    for (entries) |e| {
        w.print("{s}|{d}\n", .{ e.target, e.timestamp }) catch return;
    }
    file.writeAll(buf.items) catch return;
}
