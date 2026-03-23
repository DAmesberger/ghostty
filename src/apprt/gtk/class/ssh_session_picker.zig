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

/// Spawn a background thread to query SSH sessions and populate the picker.
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

    if (data.sessions.len == 0) {
        data.picker.setError("No detached sessions found on this host");
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
        // Fast path: use existing multiplexed connection if available
        const mgr = &Application.default().core().ssh_connection_manager;
        if (mgr.findEntry(ssh_target, null)) |entry| {
            if (entry.conn_state.load(.seq_cst) == .ready) {
                break :blk SshConnectionManager.querySessions(entry, alloc, 5000) orelse
                    return error.SessionQueryFailed;
            }
        }

        // Slow path: establish a temporary SSH connection for the query
        var ctx: session.client.SshContext = .{
            .alloc = alloc,
            .ssh_target = ssh_target,
            .jump = null,
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
