const std = @import("std");

const Build = std.Build;
const OptimizeMode = std.builtin.OptimizeMode;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addLibrary(.{
        .name = "crypto",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .linkage = .static,
    });

    if (target.result.os.tag.isDarwin()) {
        const apple_sdk = @import("apple_sdk");
        try apple_sdk.addPaths(b, lib);
    }

    if (b.lazyDependency("aws_lc", .{})) |upstream| {
        const arch = target.result.cpu.arch;
        const os = target.result.os.tag;
        const is_darwin = os.isDarwin();
        const is_darwin_x86_64 = is_darwin and arch == .x86_64;

        // Zig 0.15.2 crashes while parsing Mach-O unwind metadata emitted for
        // some s2n-bignum assembly objects on Darwin. The include-overrides
        // headers suppress CFI directives for this configuration.
        if (is_darwin and (arch == .aarch64 or arch == .x86_64)) {
            lib.addIncludePath(b.path("include-overrides"));
        }

        // Include paths
        lib.addIncludePath(upstream.path("include"));
        lib.addIncludePath(upstream.path("crypto"));
        lib.addIncludePath(upstream.path("third_party/s2n-bignum/s2n-bignum-imported/include"));

        // Install headers for downstream consumers
        lib.installHeadersDirectory(upstream.path("include"), "", .{});

        // Compile flags
        const c_flags = cFlags(is_darwin);
        const asm_flags_val = asmFlags();
        const bcm_flags = bcmFlags(is_darwin);

        // ---- crypto_objects: Non-FIPS C sources ----
        lib.addCSourceFiles(.{
            .root = upstream.path("crypto"),
            .files = crypto_srcs,
            .flags = c_flags,
        });

        // Generated err_data.c
        lib.addCSourceFile(.{ .file = upstream.path("generated-src/err_data.c"), .flags = c_flags });

        // ---- FIPS module (bcm.c unity build + cpucap) ----
        lib.addCSourceFiles(.{
            .root = upstream.path("crypto/fipsmodule"),
            .files = &.{ "bcm.c", "fips_shared_support.c", "cpucap/cpucap.c" },
            .flags = bcm_flags,
        });

        // ---- Architecture-specific assembly ----
        if (arch == .x86_64) {
            const perlasm_root = if (is_darwin)
                "generated-src/mac-x86_64/crypto"
            else
                "generated-src/linux-x86_64/crypto";

            // x86_64-only checked-in assembly (AVX)
            addAsmSourceFiles(b, lib, upstream.path("crypto"), &.{"hrss/asm/poly_rq_mul.S"}, c_flags, is_darwin_x86_64);

            // Pre-generated x86_64 perlasm
            addAsmSourceFiles(b, lib, upstream.path(perlasm_root), perlasm_x86_64, asm_flags_val, is_darwin_x86_64);

            // s2n-bignum x86_64 assembly
            addAsmSourceFiles(b, lib, upstream.path("third_party/s2n-bignum/s2n-bignum-imported/x86_att"), s2n_bignum_x86_64, asm_flags_val, is_darwin_x86_64);

            // mlkem-native x86_64 assembly
            addAsmSourceFiles(b, lib, upstream.path("crypto/fipsmodule/ml_kem/mlkem/native/x86_64/src"), mlkem_x86_64, asm_flags_val, is_darwin_x86_64);
        } else if (arch == .aarch64) {
            const perlasm_root = if (is_darwin)
                "generated-src/ios-aarch64/crypto"
            else
                "generated-src/linux-aarch64/crypto";

            // Pre-generated aarch64 perlasm
            lib.addCSourceFiles(.{
                .root = upstream.path(perlasm_root),
                .files = perlasm_aarch64,
                .flags = asm_flags_val,
            });

            // s2n-bignum aarch64 assembly
            lib.addCSourceFiles(.{
                .root = upstream.path("third_party/s2n-bignum/s2n-bignum-imported/arm"),
                .files = s2n_bignum_aarch64,
                .flags = asm_flags_val,
            });

            // mlkem-native aarch64 assembly
            lib.addCSourceFiles(.{
                .root = upstream.path("crypto/fipsmodule/ml_kem/mlkem/native/aarch64/src"),
                .files = mlkem_aarch64,
                .flags = asm_flags_val,
            });

            // s2n-bignum aes-xts (aarch64-only)
            lib.addCSourceFiles(.{
                .root = upstream.path("third_party/s2n-bignum/s2n-bignum-to-be-imported/arm/aes"),
                .files = &.{ "aes-xts-enc.S", "aes-xts-dec.S" },
                .flags = asm_flags_val,
            });
        }

        // ---- Jitterentropy (MUST be -O0) ----
        if (!is_darwin) {
            const jitter_flags: []const []const u8 = &.{ "-DAWSLC", "-O0", "-fwrapv" };
            lib.addIncludePath(upstream.path("third_party/jitterentropy/jitterentropy-library"));
            lib.addCSourceFiles(.{
                .root = upstream.path("third_party/jitterentropy/jitterentropy-library/src"),
                .files = &.{
                    "jitterentropy-base.c",
                    "jitterentropy-gcd.c",
                    "jitterentropy-health.c",
                    "jitterentropy-noise.c",
                    "jitterentropy-sha3.c",
                    "jitterentropy-timer.c",
                },
                .flags = jitter_flags,
            });
        }

        // Platform libraries
        lib.linkSystemLibrary("pthread");
    }

    b.installArtifact(lib);
}

fn cFlags(is_darwin: bool) []const []const u8 {
    if (is_darwin) {
        return &.{
            "-DBORINGSSL_IMPLEMENTATION",
            "-D_GNU_SOURCE",
            "-DDISABLE_CPU_JITTER_ENTROPY",
        };
    }
    return &.{ "-DBORINGSSL_IMPLEMENTATION", "-D_GNU_SOURCE" };
}

fn asmFlags() []const []const u8 {
    return &.{ "-DBORINGSSL_IMPLEMENTATION", "-DS2N_BN_HIDE_SYMBOLS" };
}

fn bcmFlags(is_darwin: bool) []const []const u8 {
    if (is_darwin) {
        return &.{
            "-DBORINGSSL_IMPLEMENTATION",
            "-DS2N_BN_HIDE_SYMBOLS",
            "-D_GNU_SOURCE",
            "-DDISABLE_CPU_JITTER_ENTROPY",
        };
    }
    return &.{ "-DBORINGSSL_IMPLEMENTATION", "-DS2N_BN_HIDE_SYMBOLS", "-D_GNU_SOURCE" };
}

fn stripCfiAsmSource(allocator: std.mem.Allocator, bytes: []const u8) []const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var first = true;

    while (lines.next()) |line| {
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, ".cfi_")) continue;

        if (!first) out.append(allocator, '\n') catch @panic("OOM");
        first = false;
        out.appendSlice(allocator, line) catch @panic("OOM");
    }

    if (bytes.len > 0 and bytes[bytes.len - 1] == '\n') {
        out.append(allocator, '\n') catch @panic("OOM");
    }

    return out.toOwnedSlice(allocator) catch @panic("OOM");
}

fn addAsmSourceFiles(
    b: *Build,
    lib: *Build.Step.Compile,
    root: Build.LazyPath,
    files: []const []const u8,
    flags: []const []const u8,
    strip_cfi: bool,
) void {
    if (!strip_cfi) {
        lib.addCSourceFiles(.{
            .root = root,
            .files = files,
            .flags = flags,
        });
        return;
    }

    // On Darwin x86_64, strip .cfi_ directives from assembly to work around
    // Zig 0.15.2 Mach-O parser crashes.
    const write_files = b.addWriteFiles();
    const root_path = root.getPath(b);

    for (files) |file| {
        const source_path = b.pathJoin(&.{ root_path, file });
        const source_bytes = std.fs.cwd().readFileAlloc(b.allocator, source_path, 32 * 1024 * 1024) catch |err| {
            std.debug.panic("failed to read assembly source {s}: {s}", .{ source_path, @errorName(err) });
        };
        const stripped_bytes = stripCfiAsmSource(b.allocator, source_bytes);
        const generated = write_files.add(file, stripped_bytes);
        lib.addCSourceFile(.{
            .file = generated,
            .flags = flags,
        });
    }
}

// =========================================================================
// Source file lists
// =========================================================================

const crypto_srcs: []const []const u8 = &.{
    "asn1/a_bitstr.c",
    "asn1/a_bool.c",
    "asn1/a_d2i_fp.c",
    "asn1/a_dup.c",
    "asn1/a_gentm.c",
    "asn1/a_i2d_fp.c",
    "asn1/a_int.c",
    "asn1/a_mbstr.c",
    "asn1/a_object.c",
    "asn1/a_octet.c",
    "asn1/a_strex.c",
    "asn1/a_strnid.c",
    "asn1/a_time.c",
    "asn1/a_type.c",
    "asn1/a_utctm.c",
    "asn1/a_utf8.c",
    "asn1/asn1_lib.c",
    "asn1/asn1_par.c",
    "asn1/asn_pack.c",
    "asn1/f_int.c",
    "asn1/f_string.c",
    "asn1/tasn_dec.c",
    "asn1/tasn_enc.c",
    "asn1/tasn_fre.c",
    "asn1/tasn_new.c",
    "asn1/tasn_typ.c",
    "asn1/tasn_utl.c",
    "asn1/posix_time.c",
    "base64/base64.c",
    "bio/bio.c",
    "bio/bio_addr.c",
    "bio/bio_mem.c",
    "bio/connect.c",
    "bio/dgram.c",
    "bio/errno.c",
    "bio/fd.c",
    "bio/file.c",
    "bio/hexdump.c",
    "bio/md.c",
    "bio/pair.c",
    "bio/printf.c",
    "bio/socket.c",
    "bio/socket_helper.c",
    "blake2/blake2.c",
    "bn_extra/bn_asn1.c",
    "bn_extra/convert.c",
    "buf/buf.c",
    "bytestring/asn1_compat.c",
    "bytestring/ber.c",
    "bytestring/cbb.c",
    "bytestring/cbs.c",
    "bytestring/unicode.c",
    "chacha/chacha.c",
    "cipher_extra/cipher_extra.c",
    "cipher_extra/derive_key.c",
    "cipher_extra/e_aesctrhmac.c",
    "cipher_extra/e_aesgcmsiv.c",
    "cipher_extra/e_chacha20poly1305.c",
    "cipher_extra/e_aes_cbc_hmac_sha1.c",
    "cipher_extra/e_aes_cbc_hmac_sha256.c",
    "cipher_extra/e_des.c",
    "cipher_extra/e_null.c",
    "cipher_extra/e_rc2.c",
    "cipher_extra/e_rc4.c",
    "cipher_extra/e_tls.c",
    "cipher_extra/tls_cbc.c",
    "conf/conf.c",
    "console/console.c",
    "crypto.c",
    "des/des.c",
    "dh_extra/params.c",
    "dh_extra/dh_asn1.c",
    "digest_extra/digest_extra.c",
    "dsa/dsa.c",
    "dsa/dsa_asn1.c",
    "ecdh_extra/ecdh_extra.c",
    "ecdsa_extra/ecdsa_asn1.c",
    "ec_extra/ec_asn1.c",
    "ec_extra/ec_derive.c",
    "ec_extra/hash_to_curve.c",
    "err/err.c",
    "engine/engine.c",
    "evp_extra/evp_asn1.c",
    "evp_extra/p_dh.c",
    "evp_extra/p_dh_asn1.c",
    "evp_extra/p_dsa.c",
    "evp_extra/p_dsa_asn1.c",
    "evp_extra/p_ec_asn1.c",
    "evp_extra/p_ed25519_asn1.c",
    "evp_extra/p_hmac_asn1.c",
    "evp_extra/p_kem_asn1.c",
    "evp_extra/p_pqdsa_asn1.c",
    "evp_extra/p_rsa_asn1.c",
    "evp_extra/p_x25519.c",
    "evp_extra/p_x25519_asn1.c",
    "evp_extra/p_methods.c",
    "evp_extra/print.c",
    "evp_extra/scrypt.c",
    "evp_extra/sign.c",
    "ex_data.c",
    "hpke/hpke.c",
    "hrss/hrss.c",
    "lhash/lhash.c",
    "md4/md4.c",
    "mem.c",
    "obj/obj.c",
    "obj/obj_xref.c",
    "ocsp/ocsp_asn.c",
    "ocsp/ocsp_client.c",
    "ocsp/ocsp_extension.c",
    "ocsp/ocsp_http.c",
    "ocsp/ocsp_lib.c",
    "ocsp/ocsp_print.c",
    "ocsp/ocsp_server.c",
    "ocsp/ocsp_verify.c",
    "pem/pem_all.c",
    "pem/pem_info.c",
    "pem/pem_lib.c",
    "pem/pem_oth.c",
    "pem/pem_pk8.c",
    "pem/pem_pkey.c",
    "pem/pem_x509.c",
    "pem/pem_xaux.c",
    "pkcs7/bio/cipher.c",
    "pkcs7/pkcs7.c",
    "pkcs7/pkcs7_asn1.c",
    "pkcs7/pkcs7_x509.c",
    "pkcs8/pkcs8.c",
    "pkcs8/pkcs8_x509.c",
    "pkcs8/p5_pbev2.c",
    "poly1305/poly1305.c",
    "poly1305/poly1305_arm.c",
    "poly1305/poly1305_vec.c",
    "pool/pool.c",
    "rand_extra/ccrandomgeneratebytes.c",
    "rand_extra/deterministic.c",
    "rand_extra/getentropy.c",
    "rand_extra/rand_extra.c",
    "rand_extra/vm_ube_fallback.c",
    "rand_extra/urandom.c",
    "rand_extra/windows.c",
    "rc4/rc4.c",
    "refcount_c11.c",
    "refcount_lock.c",
    "refcount_win.c",
    "rsa_extra/rsa_asn1.c",
    "rsa_extra/rsassa_pss_asn1.c",
    "rsa_extra/rsa_crypt.c",
    "rsa_extra/rsa_print.c",
    "stack/stack.c",
    "siphash/siphash.c",
    "spake25519/spake25519.c",
    "thread.c",
    "thread_none.c",
    "thread_pthread.c",
    "thread_win.c",
    "trust_token/pmbtoken.c",
    "trust_token/trust_token.c",
    "trust_token/voprf.c",
    "ube/ube.c",
    "ube/fork_ube_detect.c",
    "ube/vm_ube_detect.c",
    "x509/a_digest.c",
    "x509/a_sign.c",
    "x509/a_verify.c",
    "x509/algorithm.c",
    "x509/asn1_gen.c",
    "x509/by_dir.c",
    "x509/by_file.c",
    "x509/i2d_pr.c",
    "x509/name_print.c",
    "x509/policy.c",
    "x509/rsa_pss.c",
    "x509/t_crl.c",
    "x509/t_req.c",
    "x509/t_x509.c",
    "x509/t_x509a.c",
    "x509/v3_akey.c",
    "x509/v3_akeya.c",
    "x509/v3_alt.c",
    "x509/v3_bcons.c",
    "x509/v3_bitst.c",
    "x509/v3_conf.c",
    "x509/v3_cpols.c",
    "x509/v3_crld.c",
    "x509/v3_enum.c",
    "x509/v3_extku.c",
    "x509/v3_genn.c",
    "x509/v3_ia5.c",
    "x509/v3_info.c",
    "x509/v3_int.c",
    "x509/v3_lib.c",
    "x509/v3_ncons.c",
    "x509/v3_ocsp.c",
    "x509/v3_pcons.c",
    "x509/v3_pmaps.c",
    "x509/v3_prn.c",
    "x509/v3_purp.c",
    "x509/v3_skey.c",
    "x509/v3_utl.c",
    "x509/x_algor.c",
    "x509/x_all.c",
    "x509/x_attrib.c",
    "x509/x_crl.c",
    "x509/x_exten.c",
    "x509/x_name.c",
    "x509/x_pubkey.c",
    "x509/x_req.c",
    "x509/x_sig.c",
    "x509/x_spki.c",
    "x509/x_val.c",
    "x509/x_x509.c",
    "x509/x_x509a.c",
    "x509/x509_att.c",
    "x509/x509_cmp.c",
    "x509/x509_d2.c",
    "x509/x509_def.c",
    "x509/x509_ext.c",
    "x509/x509_lu.c",
    "x509/x509_obj.c",
    "x509/x509_req.c",
    "x509/x509_set.c",
    "x509/x509_trs.c",
    "x509/x509_txt.c",
    "x509/x509_v3.c",
    "x509/x509_vfy.c",
    "x509/x509_vpm.c",
    "x509/x509.c",
    "x509/x509cset.c",
    "x509/x509name.c",
    "x509/x509rset.c",
    "x509/x509spki.c",
    "ui/ui.c",
    "decrepit/bio/base64_bio.c",
    "decrepit/blowfish/blowfish.c",
    "decrepit/cast/cast.c",
    "decrepit/cast/cast_tables.c",
    "decrepit/cfb/cfb.c",
    "decrepit/dh/dh_decrepit.c",
    "decrepit/evp/evp_do_all.c",
    "decrepit/obj/obj_decrepit.c",
    "decrepit/ripemd/ripemd.c",
    "decrepit/rsa/rsa_decrepit.c",
    "decrepit/x509/x509_decrepit.c",
};

const perlasm_x86_64: []const []const u8 = &.{
    "fipsmodule/aesni-gcm-avx512.S",
    "fipsmodule/aesni-gcm-x86_64.S",
    "fipsmodule/aesni-x86_64.S",
    "fipsmodule/aesni-xts-avx512.S",
    "fipsmodule/ghash-ssse3-x86_64.S",
    "fipsmodule/ghash-x86_64.S",
    "fipsmodule/md5-x86_64.S",
    "fipsmodule/p256-x86_64-asm.S",
    "fipsmodule/p256_beeu-x86_64-asm.S",
    "fipsmodule/rdrand-x86_64.S",
    "fipsmodule/rsaz-2k-avx512.S",
    "fipsmodule/rsaz-3k-avx512.S",
    "fipsmodule/rsaz-4k-avx512.S",
    "fipsmodule/rsaz-avx2.S",
    "fipsmodule/sha1-x86_64.S",
    "fipsmodule/sha256-x86_64.S",
    "fipsmodule/sha512-x86_64.S",
    "fipsmodule/vpaes-x86_64.S",
    "fipsmodule/x86_64-mont.S",
    "fipsmodule/x86_64-mont5.S",
    "chacha/chacha-x86_64.S",
    "cipher_extra/chacha20_poly1305_x86_64.S",
    "cipher_extra/aes128gcmsiv-x86_64.S",
    "cipher_extra/aesni-sha1-x86_64.S",
    "cipher_extra/aesni-sha256-x86_64.S",
};

const perlasm_aarch64: []const []const u8 = &.{
    "fipsmodule/aesv8-armx.S",
    "fipsmodule/aesv8-gcm-armv8.S",
    "fipsmodule/aesv8-gcm-armv8-unroll8.S",
    "fipsmodule/armv8-mont.S",
    "fipsmodule/bn-armv8.S",
    "fipsmodule/ghash-neon-armv8.S",
    "fipsmodule/ghashv8-armx.S",
    "fipsmodule/keccak1600-armv8.S",
    "fipsmodule/md5-armv8.S",
    "fipsmodule/p256-armv8-asm.S",
    "fipsmodule/p256_beeu-armv8-asm.S",
    "fipsmodule/rndr-armv8.S",
    "fipsmodule/sha1-armv8.S",
    "fipsmodule/sha256-armv8.S",
    "fipsmodule/sha512-armv8.S",
    "fipsmodule/vpaes-armv8.S",
    "chacha/chacha-armv8.S",
    "cipher_extra/chacha20_poly1305_armv8.S",
};

const s2n_bignum_x86_64: []const []const u8 = &.{
    "p256/p256_montjscalarmul.S",
    "p256/p256_montjscalarmul_alt.S",
    "p256/bignum_montinv_p256.S",
    "p384/bignum_add_p384.S",
    "p384/bignum_sub_p384.S",
    "p384/bignum_neg_p384.S",
    "p384/bignum_tomont_p384.S",
    "p384/bignum_deamont_p384.S",
    "p384/bignum_montmul_p384.S",
    "p384/bignum_montmul_p384_alt.S",
    "p384/bignum_montsqr_p384.S",
    "p384/bignum_montsqr_p384_alt.S",
    "p384/bignum_nonzero_6.S",
    "p384/bignum_littleendian_6.S",
    "p384/p384_montjdouble.S",
    "p384/p384_montjdouble_alt.S",
    "p384/p384_montjscalarmul.S",
    "p384/p384_montjscalarmul_alt.S",
    "p384/bignum_montinv_p384.S",
    "p384/bignum_tomont_p384_alt.S",
    "p384/bignum_deamont_p384_alt.S",
    "p521/bignum_add_p521.S",
    "p521/bignum_sub_p521.S",
    "p521/bignum_neg_p521.S",
    "p521/bignum_mul_p521.S",
    "p521/bignum_mul_p521_alt.S",
    "p521/bignum_sqr_p521.S",
    "p521/bignum_sqr_p521_alt.S",
    "p521/bignum_tolebytes_p521.S",
    "p521/bignum_fromlebytes_p521.S",
    "p521/p521_jdouble.S",
    "p521/p521_jdouble_alt.S",
    "p521/p521_jscalarmul.S",
    "p521/p521_jscalarmul_alt.S",
    "p521/bignum_inv_p521.S",
    "curve25519/bignum_mod_n25519.S",
    "curve25519/bignum_neg_p25519.S",
    "curve25519/bignum_madd_n25519.S",
    "curve25519/bignum_madd_n25519_alt.S",
    "curve25519/edwards25519_decode.S",
    "curve25519/edwards25519_decode_alt.S",
    "curve25519/edwards25519_encode.S",
    "curve25519/edwards25519_scalarmulbase.S",
    "curve25519/edwards25519_scalarmulbase_alt.S",
    "curve25519/edwards25519_scalarmuldouble.S",
    "curve25519/edwards25519_scalarmuldouble_alt.S",
    "curve25519/curve25519_x25519.S",
    "curve25519/curve25519_x25519_alt.S",
    "curve25519/curve25519_x25519base.S",
    "curve25519/curve25519_x25519base_alt.S",
    "sha3/sha3_keccak_f1600.S",
};

const s2n_bignum_aarch64: []const []const u8 = &.{
    "p256/p256_montjscalarmul.S",
    "p256/p256_montjscalarmul_alt.S",
    "p256/bignum_montinv_p256.S",
    "p384/bignum_add_p384.S",
    "p384/bignum_sub_p384.S",
    "p384/bignum_neg_p384.S",
    "p384/bignum_tomont_p384.S",
    "p384/bignum_deamont_p384.S",
    "p384/bignum_montmul_p384.S",
    "p384/bignum_montmul_p384_alt.S",
    "p384/bignum_montsqr_p384.S",
    "p384/bignum_montsqr_p384_alt.S",
    "p384/bignum_nonzero_6.S",
    "p384/bignum_littleendian_6.S",
    "p384/p384_montjdouble.S",
    "p384/p384_montjdouble_alt.S",
    "p384/p384_montjscalarmul.S",
    "p384/p384_montjscalarmul_alt.S",
    "p384/bignum_montinv_p384.S",
    "p521/bignum_add_p521.S",
    "p521/bignum_sub_p521.S",
    "p521/bignum_neg_p521.S",
    "p521/bignum_mul_p521.S",
    "p521/bignum_mul_p521_alt.S",
    "p521/bignum_sqr_p521.S",
    "p521/bignum_sqr_p521_alt.S",
    "p521/bignum_tolebytes_p521.S",
    "p521/bignum_fromlebytes_p521.S",
    "p521/p521_jdouble.S",
    "p521/p521_jdouble_alt.S",
    "p521/p521_jscalarmul.S",
    "p521/p521_jscalarmul_alt.S",
    "p521/bignum_inv_p521.S",
    "curve25519/bignum_mod_n25519.S",
    "curve25519/bignum_neg_p25519.S",
    "curve25519/bignum_madd_n25519.S",
    "curve25519/bignum_madd_n25519_alt.S",
    "curve25519/edwards25519_decode.S",
    "curve25519/edwards25519_decode_alt.S",
    "curve25519/edwards25519_encode.S",
    "curve25519/edwards25519_scalarmulbase.S",
    "curve25519/edwards25519_scalarmulbase_alt.S",
    "curve25519/edwards25519_scalarmuldouble.S",
    "curve25519/edwards25519_scalarmuldouble_alt.S",
    "curve25519/curve25519_x25519_byte.S",
    "curve25519/curve25519_x25519_byte_alt.S",
    "curve25519/curve25519_x25519base_byte.S",
    "curve25519/curve25519_x25519base_byte_alt.S",
    "fastmul/bignum_kmul_16_32.S",
    "fastmul/bignum_kmul_32_64.S",
    "fastmul/bignum_ksqr_16_32.S",
    "fastmul/bignum_ksqr_32_64.S",
    "fastmul/bignum_emontredc_8n.S",
    "generic/bignum_ge.S",
    "generic/bignum_mul.S",
    "generic/bignum_optsub.S",
    "generic/bignum_sqr.S",
    "generic/bignum_copy_row_from_table.S",
    "generic/bignum_copy_row_from_table_8n.S",
    "generic/bignum_copy_row_from_table_16.S",
    "generic/bignum_copy_row_from_table_32.S",
    "sha3/sha3_keccak_f1600.S",
    "sha3/sha3_keccak4_f1600_alt.S",
};

const mlkem_x86_64: []const []const u8 = &.{
    "intt.S",
    "ntt.S",
    "mulcache_compute.S",
    "nttfrombytes.S",
    "ntttobytes.S",
    "nttunpack.S",
    "reduce.S",
    "tomont.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k2.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k3.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k4.S",
    "rej_uniform_asm.S",
};

const mlkem_aarch64: []const []const u8 = &.{
    "intt.S",
    "ntt.S",
    "poly_mulcache_compute_asm.S",
    "poly_reduce_asm.S",
    "poly_tobytes_asm.S",
    "poly_tomont_asm.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k2.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k3.S",
    "polyvec_basemul_acc_montgomery_cached_asm_k4.S",
    "rej_uniform_asm.S",
};
