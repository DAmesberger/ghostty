const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addLibrary(.{
        .name = "ssh2",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("main.zig"),
        }),
        .linkage = .static,
    });
    lib.linkLibC();
    if (target.result.os.tag.isDarwin()) {
        const apple_sdk = @import("apple_sdk");
        try apple_sdk.addPaths(b, lib);
    }

    // Link vendored aws-lc (libcrypto) — reports as OpenSSL 1.1.1g,
    // so the LIBSSH2_OPENSSL backend is the correct choice.
    if (b.lazyDependency("aws_lc", .{
        .target = target,
        .optimize = optimize,
    })) |awslc_dep| {
        lib.linkLibrary(awslc_dep.artifact("crypto"));
    }

    // Link vendored zlib for SSH compression (zlib@openssh.com)
    if (b.lazyDependency("zlib", .{
        .target = target,
        .optimize = optimize,
    })) |zlib_dep| {
        lib.linkLibrary(zlib_dep.artifact("z"));
    }

    // Add our generated config header
    lib.addIncludePath(b.path(""));

    if (b.lazyDependency("libssh2", .{})) |upstream| {
        lib.addIncludePath(upstream.path("include"));
        lib.addIncludePath(upstream.path("src"));
        lib.installHeadersDirectory(
            upstream.path("include"),
            "",
            .{ .include_extensions = &.{".h"} },
        );

        var flags: std.ArrayList([]const u8) = .empty;
        defer flags.deinit(b.allocator);
        try flags.appendSlice(b.allocator, &.{
            "-DHAVE_CONFIG_H",
            "-DLIBSSH2_OPENSSL",
        });

        lib.addCSourceFiles(.{
            .root = upstream.path("src"),
            .files = srcs,
            .flags = flags.items,
        });
    }

    b.installArtifact(lib);
}

/// libssh2 source files for the OpenSSL backend.
/// Excludes backend-specific files for other backends (mbedtls, libgcrypt,
/// wincng, os400qc3) and platform-specific files (agent_win).
const srcs: []const []const u8 = &.{
    "agent.c",
    "bcrypt_pbkdf.c",
    "blowfish.c",
    "chacha.c",
    "channel.c",
    "cipher-chachapoly.c",
    "comp.c",
    "crypt.c",
    "crypto.c",
    "global.c",
    "hostkey.c",
    "keepalive.c",
    "kex.c",
    "knownhost.c",
    "mac.c",
    "misc.c",
    "openssl.c",
    "packet.c",
    "pem.c",
    "poly1305.c",
    "publickey.c",
    "scp.c",
    "session.c",
    "sftp.c",
    "transport.c",
    "userauth.c",
    "userauth_kbd_packet.c",
    "version.c",
};
