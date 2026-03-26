const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const adw = @import("adw");
const gio = @import("gio");
const glib = @import("glib");
const gobject = @import("gobject");
const gtk = @import("gtk");

const session = @import("../../../session.zig");
const SshConnectionManager = @import("../../../termio/SshConnectionManager.zig");
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

    /// Per-row data for session entries in the ListBox.
    const RowData = struct {
        alloc: Allocator,
        picker: *SshSessionPicker,
        session_id: [:0]u8,
        current_title: [:0]u8,
    };

    const Private = struct {
        /// The dialog object containing the picker UI.
        dialog: *adw.Dialog,

        /// The stack widget for switching between loading/list/error views.
        stack: *gtk.Stack,

        /// The error label.
        error_label: *gtk.Label,

        /// The list box for session rows.
        list_box: *gtk.ListBox,

        /// The SSH target this picker is querying.
        ssh_target: ?[:0]const u8 = null,

        /// Back-reference to the window that opened us.
        window: ?*Window = null,

        /// Tracked row data allocations for cleanup.
        row_data: std.ArrayListUnmanaged(*RowData) = .empty,

        pub var offset: c_int = 0;
    };

    /// Create a new instance of the SSH session picker.
    pub fn new() ?*Self {
        const self = gobject.ext.newInstance(Self, .{});

        // Sink the floating ref so we own a single strong ref.
        // dialogClosed will unref this when the dialog is dismissed.
        _ = self.refSink();

        return self;
    }

    //---------------------------------------------------------------
    // Virtual Methods

    fn init(self: *Self, _: *Class) callconv(.c) void {
        gtk.Widget.initTemplate(self.as(gtk.Widget));
    }

    fn dispose(self: *Self) callconv(.c) void {
        const priv = self.private();
        self.clearRows();

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

    fn rowActivated(_: *gtk.ListBox, row: *gtk.ListBoxRow, self: *SshSessionPicker) callconv(.c) void {
        const index = row.getIndex();
        if (index < 0) return;
        const idx: usize = @intCast(index);
        const priv = self.private();
        if (idx >= priv.row_data.items.len) return;
        const rd = priv.row_data.items[idx];

        self.close();

        const ssh_target: ?[*:0]const u8 = if (priv.ssh_target) |t| t.ptr else null;
        const sid_ptr: [*:0]const u8 = rd.session_id.ptr;

        signals.@"session-selected".impl.emit(
            self,
            null,
            .{ ssh_target, @as(?[*:0]const u8, sid_ptr) },
            null,
        );
    }

    fn refreshClicked(_: *gtk.Button, self: *SshSessionPicker) callconv(.c) void {
        const priv = self.private();
        self.clearRows();
        priv.stack.setVisibleChildName("loading");
        if (priv.ssh_target) |target| {
            queryAndPopulate(self, target);
        }
    }

    //---------------------------------------------------------------
    // Inline row button handlers (connected programmatically)

    fn onRenameRow(_: *gtk.Button, rd: *RowData) callconv(.c) void {
        const picker = rd.picker;
        const priv = picker.private();

        // Show a simple rename dialog.
        const dialog = adw.AlertDialog.new("Rename Session", null);
        dialog.addResponse("cancel", "Cancel");
        dialog.addResponse("ok", "Rename");
        dialog.setDefaultResponse("ok");
        dialog.setCloseResponse("cancel");

        const name_entry = gtk.Entry.new();
        name_entry.as(gtk.Widget).setMarginStart(24);
        name_entry.as(gtk.Widget).setMarginEnd(24);
        name_entry.getBuffer().setText(@ptrCast(rd.current_title.ptr), @intCast(rd.current_title.len));
        dialog.setExtraChild(name_entry.as(gtk.Widget));

        // Store context for the async callback.
        const alloc = Application.default().allocator();
        const RenameCtx = struct {
            picker: *SshSessionPicker,
            sid: [:0]u8,
        };
        const ctx = alloc.create(RenameCtx) catch return;
        ctx.* = .{
            .picker = picker,
            .sid = alloc.dupeZ(u8, rd.session_id) catch {
                alloc.destroy(ctx);
                return;
            },
        };

        dialog.choose(
            priv.dialog.as(gtk.Widget),
            null,
            struct {
                fn cb(source: ?*gobject.Object, result: *gio.AsyncResult, ud: ?*anyopaque) callconv(.c) void {
                    const c: *RenameCtx = @ptrCast(@alignCast(ud));
                    const a = Application.default().allocator();
                    defer {
                        a.free(c.sid);
                        a.destroy(c);
                    }
                    const d: *adw.AlertDialog = @ptrCast(source orelse return);
                    const extra = d.getExtraChild() orelse return;
                    const e = gobject.ext.cast(gtk.Entry, extra) orelse return;
                    const name = std.mem.span(e.getBuffer().getText());

                    const response = d.chooseFinish(result);
                    if (std.mem.orderZ(u8, "ok", response) != .eq) return;
                    if (name.len == 0) return;

                    // Run rename on remote via background thread.
                    const p = c.picker.private();
                    const ssh_target = p.ssh_target orelse return;

                    const RenameData = struct {
                        alloc: Allocator,
                        ssh_t: [:0]const u8,
                        session_id: [:0]const u8,
                        new_label: [:0]u8,
                        picker: *SshSessionPicker,
                    };
                    const rnd = a.create(RenameData) catch return;
                    rnd.* = .{
                        .alloc = a,
                        .ssh_t = ssh_target,
                        .session_id = c.sid,
                        .new_label = a.dupeZ(u8, name) catch {
                            a.destroy(rnd);
                            return;
                        },
                        .picker = c.picker,
                    };
                    // Keep sid alive — steal it from ctx
                    c.sid = a.dupeZ(u8, "") catch return;

                    _ = std.Thread.spawn(.{}, renameSessionThread, .{rnd}) catch {
                        a.free(rnd.new_label);
                        a.free(rnd.session_id);
                        a.destroy(rnd);
                        return;
                    };
                }
            }.cb,
            ctx,
        );
    }

    fn onDetachRow(_: *gtk.Button, rd: *RowData) callconv(.c) void {
        const picker = rd.picker;
        const priv = picker.private();

        const dialog = adw.AlertDialog.new(
            "Detach Others?",
            "This will disconnect all other viewers from this session.",
        );
        dialog.addResponse("cancel", "Cancel");
        dialog.addResponse("detach", "Detach Others");
        dialog.setResponseAppearance("detach", .destructive);
        dialog.setDefaultResponse("cancel");
        dialog.setCloseResponse("cancel");

        const alloc = Application.default().allocator();
        const DetachCtx = struct {
            picker: *SshSessionPicker,
            sid: [:0]u8,
        };
        const ctx = alloc.create(DetachCtx) catch return;
        ctx.* = .{
            .picker = picker,
            .sid = alloc.dupeZ(u8, rd.session_id) catch {
                alloc.destroy(ctx);
                return;
            },
        };

        dialog.choose(
            priv.dialog.as(gtk.Widget),
            null,
            struct {
                fn cb(source: ?*gobject.Object, result: *gio.AsyncResult, ud: ?*anyopaque) callconv(.c) void {
                    const c: *DetachCtx = @ptrCast(@alignCast(ud));
                    const a = Application.default().allocator();
                    defer {
                        a.free(c.sid);
                        a.destroy(c);
                    }
                    const d: *adw.AlertDialog = @ptrCast(source orelse return);
                    const response = d.chooseFinish(result);
                    if (std.mem.orderZ(u8, "detach", response) != .eq) return;

                    const p = c.picker.private();
                    const ssh_target = p.ssh_target orelse return;

                    const DetachData = struct {
                        alloc: Allocator,
                        ssh_t: [:0]const u8,
                        session_id: [:0]const u8,
                    };
                    const dd = a.create(DetachData) catch return;
                    dd.* = .{
                        .alloc = a,
                        .ssh_t = ssh_target,
                        .session_id = c.sid,
                    };
                    c.sid = a.dupeZ(u8, "") catch return;

                    _ = std.Thread.spawn(.{}, detachOthersThread, .{dd}) catch {
                        a.free(dd.session_id);
                        a.destroy(dd);
                        return;
                    };
                }
            }.cb,
            ctx,
        );
    }

    fn onKillRow(_: *gtk.Button, rd: *RowData) callconv(.c) void {
        const picker = rd.picker;
        const priv = picker.private();

        const dialog = adw.AlertDialog.new(
            "Kill Session?",
            "This will terminate all surfaces in this session.",
        );
        dialog.addResponse("cancel", "Cancel");
        dialog.addResponse("kill", "Kill");
        dialog.setResponseAppearance("kill", .destructive);
        dialog.setDefaultResponse("cancel");
        dialog.setCloseResponse("cancel");

        const alloc = Application.default().allocator();
        const KillCtx = struct {
            picker: *SshSessionPicker,
            sid: [:0]u8,
        };
        const ctx = alloc.create(KillCtx) catch return;
        ctx.* = .{
            .picker = picker,
            .sid = alloc.dupeZ(u8, rd.session_id) catch {
                alloc.destroy(ctx);
                return;
            },
        };

        dialog.choose(
            priv.dialog.as(gtk.Widget),
            null,
            struct {
                fn cb(source: ?*gobject.Object, result: *gio.AsyncResult, ud: ?*anyopaque) callconv(.c) void {
                    const c: *KillCtx = @ptrCast(@alignCast(ud));
                    const a = Application.default().allocator();
                    defer {
                        a.free(c.sid);
                        a.destroy(c);
                    }
                    const d: *adw.AlertDialog = @ptrCast(source orelse return);
                    const response = d.chooseFinish(result);
                    if (std.mem.orderZ(u8, "kill", response) != .eq) return;

                    const p = c.picker.private();
                    const ssh_target = p.ssh_target orelse return;

                    const KillData = struct {
                        alloc: Allocator,
                        ssh_t: [:0]const u8,
                        session_id: [:0]const u8,
                        picker: *SshSessionPicker,
                    };
                    const kd = a.create(KillData) catch return;
                    kd.* = .{
                        .alloc = a,
                        .ssh_t = ssh_target,
                        .session_id = c.sid,
                        .picker = c.picker,
                    };
                    c.sid = a.dupeZ(u8, "") catch return;

                    _ = std.Thread.spawn(.{}, killSessionThread, .{kd}) catch {
                        a.free(kd.session_id);
                        a.destroy(kd);
                        return;
                    };
                }
            }.cb,
            ctx,
        );
    }

    //---------------------------------------------------------------
    // Public API

    /// Show the picker as a dialog over the given window.
    pub fn present(self: *SshSessionPicker, window: *Window) void {
        const priv = self.private();
        priv.window = window;

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

    /// Add a session entry to the list as a rich row with inline action buttons.
    pub fn addSession(
        self: *SshSessionPicker,
        id: [:0]const u8,
        label: [:0]const u8,
        detail: [:0]const u8,
        status: [:0]const u8,
    ) void {
        const priv = self.private();
        const alloc = Application.default().allocator();

        // Allocate row data for signal handlers.
        const rd = alloc.create(RowData) catch return;
        rd.* = .{
            .alloc = alloc,
            .picker = self,
            .session_id = alloc.dupeZ(u8, id) catch {
                alloc.destroy(rd);
                return;
            },
            .current_title = alloc.dupeZ(u8, label) catch {
                alloc.free(rd.session_id);
                alloc.destroy(rd);
                return;
            },
        };
        priv.row_data.append(alloc, rd) catch {
            alloc.free(rd.current_title);
            alloc.free(rd.session_id);
            alloc.destroy(rd);
            return;
        };

        // Build row widget hierarchy:
        //   Box(horizontal) {
        //     Box(vertical) { title_label, subtitle_label }  -- hexpand
        //     Label(status)  -- dim caption
        //     Button(rename) Button(detach) Button(kill)
        //   }
        const row_box = gtk.Box.new(.horizontal, 12);
        row_box.as(gtk.Widget).setMarginStart(12);
        row_box.as(gtk.Widget).setMarginEnd(12);
        row_box.as(gtk.Widget).setMarginTop(8);
        row_box.as(gtk.Widget).setMarginBottom(8);

        // Info section
        const info_box = gtk.Box.new(.vertical, 2);
        info_box.as(gtk.Widget).setValign(.center);
        info_box.as(gtk.Widget).setHexpand(1);

        const title_label = gtk.Label.new(@ptrCast(label.ptr));
        title_label.as(gtk.Widget).setHalign(.start);
        title_label.setEllipsize(.end);
        title_label.setSingleLineMode(1);
        title_label.as(gtk.Widget).addCssClass("heading");
        info_box.append(title_label.as(gtk.Widget));

        // Subtitle: combine detail and status
        var sub_buf: [256]u8 = undefined;
        const subtitle = std.fmt.bufPrintZ(&sub_buf, "{s} · {s}", .{ detail, status }) catch detail;
        const subtitle_label = gtk.Label.new(subtitle);
        subtitle_label.as(gtk.Widget).setHalign(.start);
        subtitle_label.setEllipsize(.end);
        subtitle_label.setSingleLineMode(1);
        subtitle_label.as(gtk.Widget).addCssClass("dim-label");
        subtitle_label.as(gtk.Widget).addCssClass("caption");
        info_box.append(subtitle_label.as(gtk.Widget));

        row_box.append(info_box.as(gtk.Widget));

        // Action buttons
        const btn_box = gtk.Box.new(.horizontal, 4);
        btn_box.as(gtk.Widget).setValign(.center);

        const rename_btn = gtk.Button.newFromIconName("document-edit-symbolic");
        rename_btn.as(gtk.Widget).addCssClass("flat");
        rename_btn.as(gtk.Widget).setTooltipText("Rename session");
        _ = gtk.Button.signals.clicked.connect(rename_btn, *RowData, onRenameRow, rd, .{});
        btn_box.append(rename_btn.as(gtk.Widget));

        const detach_btn = gtk.Button.newFromIconName("system-log-out-symbolic");
        detach_btn.as(gtk.Widget).addCssClass("flat");
        detach_btn.as(gtk.Widget).setTooltipText("Detach other viewers");
        _ = gtk.Button.signals.clicked.connect(detach_btn, *RowData, onDetachRow, rd, .{});
        btn_box.append(detach_btn.as(gtk.Widget));

        const kill_btn = gtk.Button.newFromIconName("edit-delete-symbolic");
        kill_btn.as(gtk.Widget).addCssClass("flat");
        kill_btn.as(gtk.Widget).addCssClass("error");
        kill_btn.as(gtk.Widget).setTooltipText("Kill session");
        _ = gtk.Button.signals.clicked.connect(kill_btn, *RowData, onKillRow, rd, .{});
        btn_box.append(kill_btn.as(gtk.Widget));

        row_box.append(btn_box.as(gtk.Widget));

        priv.list_box.append(row_box.as(gtk.Widget));
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

    /// Remove all rows and free associated data.
    fn clearRows(self: *SshSessionPicker) void {
        const priv = self.private();
        const alloc = Application.default().allocator();

        // Remove all children from the ListBox.
        // Iterate from first row until none remain.
        while (priv.list_box.getRowAtIndex(0)) |row| {
            priv.list_box.remove(row.as(gtk.Widget));
        }

        // Free row data.
        for (priv.row_data.items) |rd| {
            alloc.free(rd.session_id);
            alloc.free(rd.current_title);
            alloc.destroy(rd);
        }
        priv.row_data.clearRetainingCapacity();
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
            class.bindTemplateChildPrivate("list_box", .{});

            // Template Callbacks
            class.bindTemplateCallback("closed", &dialogClosed);
            class.bindTemplateCallback("row_activated", &rowActivated);
            class.bindTemplateCallback("refresh_clicked", &refreshClicked);

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

/// GObject wrapper for an SSH session entry (used for data transport only).
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

/// Background thread to rename a session on the remote.
fn renameSessionThread(rnd: anytype) void {
    defer {
        // Trigger a refresh on the GTK thread.
        _ = glib.idleAdd(struct {
            fn cb(data: ?*anyopaque) callconv(.c) c_int {
                const d: @TypeOf(rnd) = @ptrCast(@alignCast(data));
                // Refresh the picker to show the updated name.
                refreshClicked: {
                    const p = d.picker.private();
                    if (p.ssh_target) |target| {
                        d.picker.clearRows();
                        p.stack.setVisibleChildName("loading");
                        queryAndPopulate(d.picker, target);
                    }
                    break :refreshClicked;
                }
                d.alloc.free(d.new_label);
                d.alloc.free(d.session_id);
                d.alloc.destroy(d);
                return 0; // G_SOURCE_REMOVE
            }
        }.cb, rnd);
    }

    const alloc = rnd.alloc;
    const parsed = session.shared.parseSshTarget(rnd.ssh_t);

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = parsed.target,
        .jump = parsed.jump,
    };
    defer ctx.deinit();

    const provision = session.client.ensureRemoteGhostty(alloc, &ctx, stderr, null) catch return;
    defer alloc.free(provision.path);
    session.client.ensureRemoteDaemon(alloc, &ctx, provision.path, provision.provisioned) catch return;

    const cmd = std.fmt.allocPrint(alloc, "{s} {s} --rename={s} --label={s}", .{
        provision.path,
        session.shared.remote_subcommand,
        rnd.session_id,
        rnd.new_label,
    }) catch return;
    defer alloc.free(cmd);

    const result = session.client.runRemoteCapture(alloc, &ctx, cmd) catch return;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    log.info("rename session result: exit={d}", .{result.exit_code});
}

/// Background thread to detach other viewers from a session on the remote.
fn detachOthersThread(dd: anytype) void {
    defer {
        dd.alloc.free(dd.session_id);
        dd.alloc.destroy(dd);
    }

    const alloc = dd.alloc;
    const parsed = session.shared.parseSshTarget(dd.ssh_t);

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = parsed.target,
        .jump = parsed.jump,
    };
    defer ctx.deinit();

    const provision = session.client.ensureRemoteGhostty(alloc, &ctx, stderr, null) catch return;
    defer alloc.free(provision.path);
    session.client.ensureRemoteDaemon(alloc, &ctx, provision.path, provision.provisioned) catch return;

    const cmd = std.fmt.allocPrint(alloc, "{s} {s} --detach-others={s}", .{
        provision.path,
        session.shared.remote_subcommand,
        dd.session_id,
    }) catch return;
    defer alloc.free(cmd);

    const result = session.client.runRemoteCapture(alloc, &ctx, cmd) catch return;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    log.info("detach others result: exit={d}", .{result.exit_code});
}

/// Background thread to kill a session on the remote.
fn killSessionThread(kd: anytype) void {
    defer {
        // Remove the session from the list on the GTK thread by refreshing.
        _ = glib.idleAdd(struct {
            fn cb(data: ?*anyopaque) callconv(.c) c_int {
                const d: @TypeOf(kd) = @ptrCast(@alignCast(data));
                // Refresh to reflect the killed session.
                const p = d.picker.private();
                if (p.ssh_target) |target| {
                    d.picker.clearRows();
                    p.stack.setVisibleChildName("loading");
                    queryAndPopulate(d.picker, target);
                }
                d.alloc.free(d.session_id);
                d.alloc.destroy(d);
                return 0; // G_SOURCE_REMOVE
            }
        }.cb, kd);
    }

    // Run the kill command on the remote.
    const alloc = kd.alloc;
    const parsed = session.shared.parseSshTarget(kd.ssh_t);

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer_.interface;

    var ctx: session.client.SshContext = .{
        .alloc = alloc,
        .ssh_target = parsed.target,
        .jump = parsed.jump,
    };
    defer ctx.deinit();

    const provision = session.client.ensureRemoteGhostty(alloc, &ctx, stderr, null) catch return;
    defer alloc.free(provision.path);
    session.client.ensureRemoteDaemon(alloc, &ctx, provision.path, provision.provisioned) catch return;

    const cmd = std.fmt.allocPrint(alloc, "{s} {s} --kill={s}", .{
        provision.path,
        session.shared.remote_subcommand,
        kd.session_id,
    }) catch return;
    defer alloc.free(cmd);

    const result = session.client.runRemoteCapture(alloc, &ctx, cmd) catch return;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    log.info("kill session result: exit={d}", .{result.exit_code});
}

/// The picker should already be presented (in loading state).
pub fn queryAndPopulate(picker: *SshSessionPicker, target: [:0]const u8) void {
    const alloc = Application.default().allocator();

    const thread_data = alloc.create(SessionQueryData) catch return;
    thread_data.* = .{
        .picker = picker.ref(),
        .ssh_target = alloc.dupeZ(u8, target) catch {
            picker.unref();
            alloc.destroy(thread_data);
            return;
        },
    };

    const thread = std.Thread.spawn(.{}, sessionQueryThread, .{thread_data}) catch {
        picker.unref();
        alloc.free(thread_data.ssh_target);
        alloc.destroy(thread_data);
        return;
    };
    thread.detach();
}

const SessionQueryData = struct {
    picker: *SshSessionPicker,
    ssh_target: [:0]const u8,
};

const QueryErrorData = struct {
    picker: *SshSessionPicker,
    msg: [:0]const u8,
};

fn sessionQueryThread(data: *SessionQueryData) void {
    defer {
        const alloc = Application.default().allocator();
        data.picker.unref();
        alloc.free(data.ssh_target);
        alloc.destroy(data);
    }

    const alloc = Application.default().allocator();

    // Query sessions from the remote host via SSH
    const sessions = querySshSessions(alloc, data.ssh_target) catch |err| {
        log.warn("failed to query SSH sessions: {}", .{err});
        const msg: [:0]const u8 = switch (err) {
            error.PasswordRequired => "Password authentication required. Open a regular SSH tab first, then retry.",
            error.SessionQueryFailed => "Failed to query remote sessions. Check that the daemon is running.",
            else => "Failed to connect or query sessions",
        };
        const err_data = alloc.create(QueryErrorData) catch return;
        err_data.* = .{ .picker = data.picker.ref(), .msg = msg };
        _ = glib.idleAdd(struct {
            fn callback(ptr: ?*anyopaque) callconv(.c) c_int {
                const d: *QueryErrorData = @ptrCast(@alignCast(ptr orelse return 0));
                d.picker.setError(d.msg);
                d.picker.unref();
                Application.default().allocator().destroy(d);
                return 0;
            }
        }.callback, err_data);
        return;
    };
    defer {
        for (sessions) |s| {
            alloc.free(s.id);
            alloc.free(s.label);
            alloc.free(s.detail);
            alloc.free(s.status);
        }
        alloc.free(sessions);
    }

    // Copy session data to owned strings for the idle callback
    const callback_data = alloc.create(SessionResultData) catch return;
    callback_data.* = .{
        .picker = data.picker.ref(),
        .ssh_target = alloc.dupeZ(u8, data.ssh_target) catch {
            data.picker.unref();
            alloc.destroy(callback_data);
            return;
        },
        .sessions = blk: {
            break :blk dupeSessionEntries(alloc, sessions) catch {
                data.picker.unref();
                alloc.destroy(callback_data);
                return;
            };
        },
    };

    _ = glib.idleAdd(sessionResultCallback, @as(?*anyopaque, @ptrCast(callback_data)));
}

const SessionResultData = struct {
    picker: *SshSessionPicker,
    ssh_target: [:0]const u8,
    sessions: []Entry,

    const Entry = struct {
        id: [:0]const u8,
        label: [:0]const u8,
        detail: [:0]const u8,
        status: [:0]const u8,
    };
};

fn dupeSessionEntries(alloc: Allocator, sessions: []const SessionQueryEntry) ![]SessionResultData.Entry {
    const list = try alloc.alloc(SessionResultData.Entry, sessions.len);
    errdefer alloc.free(list);
    for (sessions, 0..) |s, i| {
        errdefer for (list[0..i]) |*prev| {
            if (prev.id.len > 0) alloc.free(prev.id);
            if (prev.label.len > 0) alloc.free(prev.label);
            if (prev.detail.len > 0) alloc.free(prev.detail);
            if (prev.status.len > 0) alloc.free(prev.status);
        };
        list[i] = .{
            .id = try alloc.dupeZ(u8, s.id),
            .label = try alloc.dupeZ(u8, s.label),
            .detail = try alloc.dupeZ(u8, s.detail),
            .status = try alloc.dupeZ(u8, s.status),
        };
    }
    return list;
}

fn sessionResultCallback(user_data: ?*anyopaque) callconv(.c) c_int {
    const data: *SessionResultData = @ptrCast(@alignCast(user_data orelse return 0));
    defer {
        const alloc = Application.default().allocator();
        data.picker.unref();
        for (data.sessions) |s| {
            if (s.id.len > 0) alloc.free(s.id);
            if (s.label.len > 0) alloc.free(s.label);
            if (s.detail.len > 0) alloc.free(s.detail);
            if (s.status.len > 0) alloc.free(s.status);
        }
        alloc.free(data.sessions);
        alloc.free(data.ssh_target);
        alloc.destroy(data);
    }

    data.picker.setSshTarget(data.ssh_target);

    log.info("session query result: {d} sessions found for target '{s}'", .{ data.sessions.len, data.ssh_target });

    if (data.sessions.len == 0) {
        data.picker.private().stack.setVisibleChildName("empty");
        return 0;
    }

    for (data.sessions) |s| {
        data.picker.addSession(s.id, s.label, s.detail, s.status);
    }
    data.picker.setLoaded();

    return 0; // G_SOURCE_REMOVE
}

/// Query sessions from a remote host. First tries the existing multiplexed
/// connection (fast). If none exists, establishes a temporary SSH connection
/// using key-based auth and runs the remote `--list` command directly.
fn querySshSessions(alloc: Allocator, ssh_target: []const u8) ![]SessionQueryEntry {
    const raw_output = blk: {
        // Fast path: use existing multiplexed connection if available.
        // querySessions returns raw binary ListResponse frames. We need to
        // convert them to the same text format the slow path produces so
        // the parser below can handle both uniformly.
        const mgr = &Application.default().core().ssh_connection_manager;
        log.info("session query: looking up target='{s}'", .{ssh_target});
        if (mgr.findEntry(ssh_target, null)) |entry| {
            log.info("session query: found entry, state={s}", .{@tagName(entry.conn_state.load(.seq_cst))});
            if (entry.conn_state.load(.seq_cst) == .ready) {
                const raw_binary = SshConnectionManager.querySessions(entry, alloc, 5000);
                log.info("session query: fast path result={any}", .{raw_binary != null});
                if (raw_binary) |binary| {
                    defer alloc.free(binary);
                    // Parse binary ListResponse and convert to text format.
                    const entries = session.protocol.ListResponse.parse(alloc, binary) catch
                        return error.SessionQueryFailed;
                    defer alloc.free(entries);

                    var text_buf: std.ArrayList(u8) = .empty;
                    errdefer text_buf.deinit(alloc);
                    const w = text_buf.writer(alloc);
                    for (entries) |e| {
                        const gid_hex = session.shared.formatUuid(e.group_id);
                        const status_str: []const u8 = switch (e.status) {
                            .dead => "dead",
                            .attached => "attached",
                            .detached => "detached",
                        };
                        w.print("{s}|{s}|{d} surfaces ({d} alive)|{d}|{s}\n", .{
                            &gid_hex,
                            e.label,
                            e.surface_count,
                            e.alive_count,
                            e.created_at,
                            status_str,
                        }) catch {};
                    }
                    break :blk (text_buf.toOwnedSlice(alloc) catch return error.SessionQueryFailed);
                }
                return error.SessionQueryFailed;
            }
        } else {
            log.info("session query: no entry found for target", .{});
        }

        // Slow path: establish a temporary SSH connection for the query
        const parsed = session.shared.parseSshTarget(ssh_target);
        var ctx: session.client.SshContext = .{
            .alloc = alloc,
            .ssh_target = parsed.target,
            .jump = parsed.jump,
        };
        defer ctx.deinit();

        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer_ = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer_.interface;

        const connect_result = ctx.connectWithAuth(stderr, null, false) catch
            return error.NoActiveConnection;
        switch (connect_result) {
            .success => {},
            .password_required_target, .password_required_jump =>
                return error.PasswordRequired,
        }

        log.info("session query: SSH connected, checking remote Ghostty...", .{});

        const provision = session.client.ensureRemoteGhostty(alloc, &ctx, stderr, null) catch |err| {
            log.warn("session query: ensureRemoteGhostty failed: {}", .{err});
            return error.NoActiveConnection;
        };
        const remote_bin_path = provision.path;
        defer alloc.free(remote_bin_path);

        log.info("session query: remote Ghostty at {s}, starting daemon...", .{remote_bin_path});

        session.client.ensureRemoteDaemon(alloc, &ctx, remote_bin_path, provision.provisioned) catch |err| {
            log.warn("session query: ensureRemoteDaemon failed: {}", .{err});
            return error.NoActiveConnection;
        };

        log.info("session query: daemon ready, listing sessions...", .{});

        const cmd = std.fmt.allocPrint(
            alloc,
            "{s} " ++ session.shared.remote_subcommand ++ " --list",
            .{remote_bin_path},
        ) catch return error.SessionQueryFailed;
        defer alloc.free(cmd);

        const result = session.client.runRemoteCapture(alloc, &ctx, cmd) catch
            return error.SessionQueryFailed;
        defer alloc.free(result.stderr);
        if (result.exit_code != 0) {
            alloc.free(result.stdout);
            return error.SessionQueryFailed;
        }
        break :blk result.stdout;
    };
    defer alloc.free(raw_output);

    // Parse the output: each line is a session entry
    // Format: "uuid|label|N surfaces|timestamp|status"
    // Lines starting with "  " are surface detail lines (skip them)
    var entries: std.ArrayListUnmanaged(SessionQueryEntry) = .{};
    errdefer {
        for (entries.items) |e| {
            alloc.free(e.id);
            alloc.free(e.label);
            alloc.free(e.detail);
            alloc.free(e.status);
        }
        entries.deinit(alloc);
    }

    var lines = std.mem.splitScalar(u8, raw_output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // Skip surface detail lines (indented)
        if (line.len > 2 and line[0] == ' ' and line[1] == ' ') continue;

        // Parse: uuid|label|surfaces_info|timestamp|status
        var parts = std.mem.splitScalar(u8, line, '|');
        const id_raw = parts.next() orelse continue;
        const label_raw = parts.next() orelse continue;
        const surfaces_raw = parts.next() orelse continue;
        const timestamp_raw = parts.next() orelse continue;
        const status_raw = parts.next() orelse continue;

        // Format detail with human-readable age
        const created_at = std.fmt.parseInt(i64, timestamp_raw, 10) catch 0;
        const now = std.time.timestamp();
        const age_secs: u64 = if (created_at > 0) @intCast(@max(0, now - created_at)) else 0;
        var age_buf: [32]u8 = undefined;
        const detail = if (age_secs > 0)
            std.fmt.allocPrint(alloc, "{s}, created {s} ago", .{ surfaces_raw, formatAge(&age_buf, age_secs) }) catch
                try alloc.dupe(u8, surfaces_raw)
        else
            try alloc.dupe(u8, surfaces_raw);

        try entries.append(alloc, .{
            .id = try alloc.dupe(u8, id_raw),
            .label = try alloc.dupe(u8, label_raw),
            .detail = detail,
            .status = try alloc.dupe(u8, status_raw),
            .created_at = created_at,
        });
    }

    // Sort descending by creation time (newest first)
    std.mem.sortUnstable(SessionQueryEntry, entries.items, {}, struct {
        fn lessThan(_: void, a: SessionQueryEntry, b: SessionQueryEntry) bool {
            return a.created_at > b.created_at;
        }
    }.lessThan);

    return try entries.toOwnedSlice(alloc);
}

const SessionQueryEntry = struct {
    id: []const u8,
    label: []const u8,
    detail: []const u8,
    status: []const u8,
    created_at: i64,
};

fn formatAge(buf: *[32]u8, secs: u64) []const u8 {
    if (secs < 60) {
        return std.fmt.bufPrint(buf, "{d}s", .{secs}) catch "?";
    } else if (secs < 3600) {
        return std.fmt.bufPrint(buf, "{d}m", .{secs / 60}) catch "?";
    } else if (secs < 86400) {
        return std.fmt.bufPrint(buf, "{d}h{d}m", .{ secs / 3600, (secs % 3600) / 60 }) catch "?";
    } else {
        return std.fmt.bufPrint(buf, "{d}d{d}h", .{ secs / 86400, (secs % 86400) / 3600 }) catch "?";
    }
}
