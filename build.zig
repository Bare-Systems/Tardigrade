const std = @import("std");

/// TLS/crypto build profile (#379, epic #327). `general` links the single
/// approved OpenSSL adapter as a compatibility backend; `appliance` is the
/// Bare Systems profile: no OpenSSL configuration, import, or linkage — the
/// OpenSSL adapter module is replaced with a native stub at the build graph
/// level, so `@cImport("openssl/...")` is never analyzed and `libssl`/
/// `libcrypto` are never linked. There is no runtime fallback between
/// profiles; the selection is embedded in the binary and reported by
/// `tardi version`. See docs/TLS_DEPENDENCY_POLICY.md.
const TlsProfile = enum { general, appliance };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const prefer_static_system_libs = b.option(bool, "prefer-static-system-libs", "Prefer static linking for system libraries") orelse false;
    const require_static_system_libs = b.option(bool, "require-static-system-libs", "Require static linking for system libraries") orelse false;
    const static_executable = b.option(bool, "static-executable", "Build the tardi executable as a static binary") orelse false;
    const app_version = b.option([]const u8, "version", "Version string embedded in the tardi binary") orelse "dev";
    const go_bin = b.option([]const u8, "go-bin", "Go command used to build the PKI crypto/x509 oracle") orelse "go";
    const tls_profile = b.option(
        TlsProfile,
        "tls-profile",
        "TLS/crypto profile: 'general' (default) links the approved OpenSSL adapter; 'appliance' forbids all foreign TLS/crypto linkage (#379)",
    ) orelse .general;
    const link_openssl_adapter = tls_profile == .general;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", app_version);
    build_options.addOption([]const u8, "tls_profile", @tagName(tls_profile));
    build_options.addOption(bool, "tls_openssl_adapter", link_openssl_adapter);
    const compat_mod = b.createModule(.{
        .root_source_file = b.path("src/zig_compat.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // QUIC varint codec as a shared module: it is consumed by the quic package,
    // the http3 package, and (transitively) the exe, and a Zig source file may
    // belong to exactly one module across a compilation graph.
    const quic_varint_mod = b.createModule(.{
        .root_source_file = b.path("src/quic/varint.zig"),
        .target = target,
        .optimize = optimize,
    });
    const crypto_secrets_mod = b.createModule(.{
        .root_source_file = b.path("src/crypto/secrets.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tls_core_mod = b.createModule(.{
        .root_source_file = b.path("src/tls/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tls_core_mod.addImport("crypto_secrets", crypto_secrets_mod);

    // Shared leaf modules. A Zig source file belongs to exactly one module,
    // so anything consumed by both the exe tree and the quic/http3 packages
    // (varint, huffman tables, the protocol-neutral stream contract) is a
    // named module everywhere.
    const hpack_huffman_mod = b.createModule(.{
        .root_source_file = b.path("src/http/hpack_huffman.zig"),
        .target = target,
        .optimize = optimize,
    });
    const stream_transport_mod = b.createModule(.{
        .root_source_file = b.path("src/http/stream_transport.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Native QUIC transport and HTTP/3 packages (#240): the production
    // HTTP/3 backend since #328. No system libraries.
    const quic_mod = b.createModule(.{
        .root_source_file = b.path("src/quic/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_mod.addImport("quic_varint", quic_varint_mod);
    quic_mod.addImport("tls_core", tls_core_mod);
    quic_mod.addImport("crypto_secrets", crypto_secrets_mod);
    const http3_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    http3_mod.addImport("hpack_huffman", hpack_huffman_mod);
    http3_mod.addImport("stream_transport", stream_transport_mod);
    http3_mod.addImport("quic_varint", quic_varint_mod);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("build_options", build_options.createModule());
    exe_mod.addImport("quic_varint", quic_varint_mod);
    exe_mod.addImport("hpack_huffman", hpack_huffman_mod);
    exe_mod.addImport("stream_transport", stream_transport_mod);
    exe_mod.addImport("quic", quic_mod);
    exe_mod.addImport("http3", http3_mod);
    exe_mod.addImport("tls_core", tls_core_mod);

    const exe = b.addExecutable(.{
        .name = "tardi",
        .root_module = exe_mod,
        .linkage = if (static_executable) .static else null,
    });
    if (link_openssl_adapter) configureSsl(exe, prefer_static_system_libs, require_static_system_libs);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    if (link_openssl_adapter) configureSsl(exe_unit_tests, prefer_static_system_libs, require_static_system_libs);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const tls_core_tests = b.addTest(.{ .root_module = tls_core_mod });
    const run_tls_core_tests = b.addRunArtifact(tls_core_tests);
    const tls_step = b.step("test-tls", "Run pure-Zig TLS core unit tests");
    tls_step.dependOn(&run_tls_core_tests.step);
    test_step.dependOn(&run_tls_core_tests.step);

    const allocation_regression_mod = b.createModule(.{
        .root_source_file = b.path("src/allocation_regression.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    allocation_regression_mod.addImport("build_options", build_options.createModule());
    allocation_regression_mod.addImport("quic_varint", quic_varint_mod);
    allocation_regression_mod.addImport("hpack_huffman", hpack_huffman_mod);
    allocation_regression_mod.addImport("stream_transport", stream_transport_mod);
    allocation_regression_mod.addImport("quic", quic_mod);
    allocation_regression_mod.addImport("http3", http3_mod);
    allocation_regression_mod.addImport("tls_core", tls_core_mod);

    const allocation_regression_tests = b.addTest(.{
        .root_module = allocation_regression_mod,
        .filters = &.{"allocation"},
    });
    if (link_openssl_adapter) configureSsl(allocation_regression_tests, prefer_static_system_libs, require_static_system_libs);
    const run_allocation_regression_tests = b.addRunArtifact(allocation_regression_tests);
    test_step.dependOn(&run_allocation_regression_tests.step);

    const allocation_regression_exe = b.addExecutable(.{
        .name = "allocation_regression",
        .root_module = allocation_regression_mod,
    });
    if (link_openssl_adapter) configureSsl(allocation_regression_exe, prefer_static_system_libs, require_static_system_libs);
    const run_allocation_regression = b.addRunArtifact(allocation_regression_exe);
    const allocation_regression_step = b.step("bench-allocations", "Report hot-path allocation budgets as JSON");
    allocation_regression_step.dependOn(&run_allocation_regression.step);

    const integration_options = b.addOptions();
    integration_options.addOption([]const u8, "tardigrade_bin_path", b.getInstallPath(.bin, "tardi"));

    const integration_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_mod.addImport("integration_options", integration_options.createModule());
    integration_mod.addImport("build_options", build_options.createModule());
    integration_mod.addImport("zig_compat", compat_mod);

    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.step.dependOn(b.getInstallStep());

    const integration_step = b.step("test-integration", "Run live-process integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    // Failure-mode / chaos harness (#169): the same live-process harness filtered
    // to the `failure:`-prefixed tests so operators can exercise broken origins
    // and clients in isolation.
    const failure_mode_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    failure_mode_mod.addImport("integration_options", integration_options.createModule());
    failure_mode_mod.addImport("build_options", build_options.createModule());
    failure_mode_mod.addImport("zig_compat", compat_mod);

    const failure_mode_tests = b.addTest(.{
        .root_module = failure_mode_mod,
        .filters = &.{"failure:"},
    });
    const run_failure_mode_tests = b.addRunArtifact(failure_mode_tests);
    run_failure_mode_tests.step.dependOn(b.getInstallStep());

    const failure_mode_step = b.step("test-failure", "Run failure-mode / chaos tests against broken origins and clients");
    failure_mode_step.dependOn(&run_failure_mode_tests.step);

    const security_corpus_mod = b.createModule(.{
        .root_source_file = b.path("tests/security/request_parser_corpus.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    security_corpus_mod.addImport("zig_compat", compat_mod);
    security_corpus_mod.addImport("request_mod", b.createModule(.{
        .root_source_file = b.path("src/http/request.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    }));

    const security_corpus_tests = b.addTest(.{
        .root_module = security_corpus_mod,
    });
    const run_security_corpus_tests = b.addRunArtifact(security_corpus_tests);
    const security_corpus_step = b.step("test-security-corpus", "Run request parser corpus regression tests");
    security_corpus_step.dependOn(&run_security_corpus_tests.step);

    // varint.zig lives in its own module, so its tests need their own run.
    const quic_varint_tests = b.addTest(.{ .root_module = quic_varint_mod });
    const run_quic_varint_tests = b.addRunArtifact(quic_varint_tests);
    const quic_tests = b.addTest(.{ .root_module = quic_mod });
    const run_quic_tests = b.addRunArtifact(quic_tests);
    const quic_step = b.step("test-quic", "Run pure-Zig QUIC/HTTP-3 unit tests");
    quic_step.dependOn(&run_quic_tests.step);
    quic_step.dependOn(&run_quic_varint_tests.step);
    // Also exercise them under the default `zig build test`.
    test_step.dependOn(&run_quic_tests.step);
    test_step.dependOn(&run_quic_varint_tests.step);

    // Pure-Zig cryptographic-provider package (#370, epic #327): the stable
    // provider boundary plus its first backend. Standalone test target and part
    // of the default `zig build test`. No system libraries.
    const crypto_mod = b.createModule(.{
        .root_source_file = b.path("src/crypto/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_mod.addImport("crypto_secrets", crypto_secrets_mod);
    tls_core_mod.addImport("crypto", crypto_mod);
    const crypto_tests = b.addTest(.{ .root_module = crypto_mod });
    const run_crypto_tests = b.addRunArtifact(crypto_tests);
    const crypto_secret_tests = b.addTest(.{ .root_module = crypto_secrets_mod });
    const run_crypto_secret_tests = b.addRunArtifact(crypto_secret_tests);
    const crypto_step = b.step("test-crypto", "Run pure-Zig cryptographic-provider unit tests");
    crypto_step.dependOn(&run_crypto_tests.step);
    crypto_step.dependOn(&run_crypto_secret_tests.step);
    test_step.dependOn(&run_crypto_tests.step);
    test_step.dependOn(&run_crypto_secret_tests.step);

    // Deterministic crypto vector harness (#373): provider-neutral test
    // vectors, TLS 1.3 key schedule values, QUIC packet-protection material,
    // and explicit negative coverage for deferred capabilities.
    const crypto_vector_mod = b.createModule(.{
        .root_source_file = b.path("tests/crypto_vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_vector_mod.addImport("crypto", crypto_mod);
    crypto_vector_mod.addImport("tls_core", tls_core_mod);
    crypto_vector_mod.addImport("quic", quic_mod);
    const crypto_vector_tests = b.addTest(.{ .root_module = crypto_vector_mod });
    const run_crypto_vector_tests = b.addRunArtifact(crypto_vector_tests);
    const crypto_vector_step = b.step("test-crypto-vectors", "Run deterministic TLS/QUIC cryptographic vector harness");
    crypto_vector_step.dependOn(&run_crypto_vector_tests.step);
    crypto_step.dependOn(&run_crypto_vector_tests.step);
    test_step.dependOn(&run_crypto_vector_tests.step);

    // Differential OpenSSL oracle checks (#377): spawn the system `openssl`
    // command out-of-process for deterministic TLS/QUIC derivation stages.
    if (link_openssl_adapter) {
        const crypto_openssl_diff_mod = b.createModule(.{
            .root_source_file = b.path("tests/crypto_openssl_diff.zig"),
            .target = target,
            .optimize = optimize,
        });
        crypto_openssl_diff_mod.addImport("crypto", crypto_mod);
        crypto_openssl_diff_mod.addImport("tls_core", tls_core_mod);
        crypto_openssl_diff_mod.addImport("quic", quic_mod);
        crypto_openssl_diff_mod.addImport("zig_compat", compat_mod);
        const crypto_openssl_diff_tests = b.addTest(.{ .root_module = crypto_openssl_diff_mod });
        const run_crypto_openssl_diff_tests = b.addRunArtifact(crypto_openssl_diff_tests);
        const crypto_openssl_diff_step = b.step("test-crypto-openssl", "Run out-of-process OpenSSL differential crypto checks");
        crypto_openssl_diff_step.dependOn(&run_crypto_openssl_diff_tests.step);
        crypto_step.dependOn(&run_crypto_openssl_diff_tests.step);
        test_step.dependOn(&run_crypto_openssl_diff_tests.step);
    }

    // Bounded checked-in Wycheproof-style corpus (#374): reduced offline
    // negative/edge vectors for provider-supported pure-Zig operations.
    const crypto_corpus_mod = b.createModule(.{
        .root_source_file = b.path("tests/crypto_corpus.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_corpus_mod.addImport("crypto", crypto_mod);
    const crypto_corpus_tests = b.addTest(.{ .root_module = crypto_corpus_mod });
    const run_crypto_corpus_tests = b.addRunArtifact(crypto_corpus_tests);
    const crypto_corpus_step = b.step("test-crypto-corpus", "Run bounded checked-in crypto corpus");
    crypto_corpus_step.dependOn(&run_crypto_corpus_tests.step);
    crypto_step.dependOn(&run_crypto_corpus_tests.step);
    test_step.dependOn(&run_crypto_corpus_tests.step);

    // A direct TLS-owned backend handshake through the record stack. This is a
    // standalone module because it uses socket-pair carriers and the concrete
    // pure-Zig crypto provider in addition to the reusable tls_core module.
    const record_mode_handshake_test_mod = b.createModule(.{
        .root_source_file = b.path("src/tls/tls13_backend_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    record_mode_handshake_test_mod.addImport("tls_core", tls_core_mod);
    record_mode_handshake_test_mod.addImport("crypto_secrets", crypto_secrets_mod);
    record_mode_handshake_test_mod.addImport("crypto", crypto_mod);
    const record_mode_handshake_tests = b.addTest(.{ .root_module = record_mode_handshake_test_mod });
    const run_record_mode_handshake_tests = b.addRunArtifact(record_mode_handshake_tests);
    tls_step.dependOn(&run_record_mode_handshake_tests.step);
    quic_step.dependOn(&run_record_mode_handshake_tests.step);
    test_step.dependOn(&run_record_mode_handshake_tests.step);

    const http3_tests = b.addTest(.{ .root_module = http3_mod });
    const run_http3_tests = b.addRunArtifact(http3_tests);
    quic_step.dependOn(&run_http3_tests.step);
    test_step.dependOn(&run_http3_tests.step);

    // Local pure-Zig QUIC/TLS/H3 connection-driver smoke harness (#314): the
    // stitching layer lives outside src/quic/ and src/http3/ so neither package
    // learns about the other; it consumes both as modules.
    const quic_h3_smoke_mod = b.createModule(.{
        .root_source_file = b.path("tests/quic_h3_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_h3_smoke_mod.addImport("quic", quic_mod);
    quic_h3_smoke_mod.addImport("http3", http3_mod);
    quic_h3_smoke_mod.addImport("stream_transport", stream_transport_mod);
    const quic_h3_smoke_tests = b.addTest(.{ .root_module = quic_h3_smoke_mod });
    const run_quic_h3_smoke_tests = b.addRunArtifact(quic_h3_smoke_tests);
    quic_step.dependOn(&run_quic_h3_smoke_tests.step);
    test_step.dependOn(&run_quic_h3_smoke_tests.step);

    // Deterministic native QUIC/H3 end-to-end harness (#247): the connection
    // driver and H3 glue over a simulated network with controlled loss,
    // reordering, duplication, and delay.
    const quic_h3_e2e_mod = b.createModule(.{
        .root_source_file = b.path("tests/quic_h3_e2e.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_h3_e2e_mod.addImport("quic", quic_mod);
    quic_h3_e2e_mod.addImport("http3", http3_mod);
    quic_h3_e2e_mod.addImport("stream_transport", stream_transport_mod);
    const quic_h3_e2e_tests = b.addTest(.{ .root_module = quic_h3_e2e_mod });
    const run_quic_h3_e2e_tests = b.addRunArtifact(quic_h3_e2e_tests);
    const quic_h3_driver_step = b.step("test-quic-h3-driver", "Run deterministic native QUIC/H3 driver scenarios");
    quic_h3_driver_step.dependOn(&run_quic_h3_e2e_tests.step);
    quic_step.dependOn(&run_quic_h3_e2e_tests.step);
    test_step.dependOn(&run_quic_h3_e2e_tests.step);

    // Real-UDP smoke test (#247 phase 4): the same native stack over actual
    // loopback sockets with poll(2)-driven timers and DCID routing.
    const quic_h3_udp_mod = b.createModule(.{
        .root_source_file = b.path("tests/quic_h3_udp_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    quic_h3_udp_mod.addImport("quic", quic_mod);
    quic_h3_udp_mod.addImport("http3", http3_mod);
    quic_h3_udp_mod.addImport("stream_transport", stream_transport_mod);
    const quic_h3_udp_tests = b.addTest(.{ .root_module = quic_h3_udp_mod });
    const run_quic_h3_udp_tests = b.addRunArtifact(quic_h3_udp_tests);
    quic_step.dependOn(&run_quic_h3_udp_tests.step);
    test_step.dependOn(&run_quic_h3_udp_tests.step);

    // Out-of-process interop client/server for #247 phase 5. Built on the
    // native driver only; external peers (ngtcp2/nghttp3, quiche, aioquic)
    // run as separate processes — see scripts/interop/README.md.
    const h3_interop_mod = b.createModule(.{
        .root_source_file = b.path("tests/h3_interop_tool.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    h3_interop_mod.addImport("quic", quic_mod);
    h3_interop_mod.addImport("http3", http3_mod);
    h3_interop_mod.addImport("stream_transport", stream_transport_mod);
    const h3_interop_tool = b.addExecutable(.{
        .name = "h3_interop_tool",
        .root_module = h3_interop_mod,
    });
    const h3_interop_install = b.addInstallArtifact(h3_interop_tool, .{});
    const h3_interop_step = b.step("build-h3-interop", "Build the native HTTP/3 interop client/server tool");
    h3_interop_step.dependOn(&h3_interop_install.step);

    // Pure-Zig PKI foundation (#339): no system libraries. Consumes the
    // crypto-provider seam for certificate signature verification (#343).
    const pki_mod = b.createModule(.{
        .root_source_file = b.path("src/pki/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    pki_mod.addImport("crypto", crypto_mod);
    pki_mod.addAnonymousImport("pki_malformed_der", .{
        .root_source_file = b.path("tests/vectors/pki/malformed-truncated.der"),
    });
    // Shared between the PKI unit tests and the differential harness; a single
    // module instance because one source file may only belong to one module.
    const pki_reduced_corpus_mod = b.createModule(.{
        .root_source_file = b.path("tests/vectors/pki/reduced/manifest.zig"),
        .target = target,
        .optimize = optimize,
    });
    pki_mod.addImport("pki_reduced_corpus", pki_reduced_corpus_mod);
    const pki_tests = b.addTest(.{ .root_module = pki_mod });
    const run_pki_tests = b.addRunArtifact(pki_tests);
    const pki_step = b.step("test-pki", "Run pure-Zig PKI DER unit tests");
    pki_step.dependOn(&run_pki_tests.step);
    test_step.dependOn(&run_pki_tests.step);

    // Optional out-of-process OpenSSL differential checks for the fixed Name
    // Constraints and certificate-policy matrices. This is not part of the
    // ordinary offline `test` or `test-pki` targets.
    const pki_openssl_diff_mod = b.createModule(.{
        .root_source_file = b.path("tests/pki_openssl_diff.zig"),
        .target = target,
        .optimize = optimize,
    });
    pki_openssl_diff_mod.addImport("crypto", crypto_mod);
    pki_openssl_diff_mod.addImport("pki", pki_mod);
    pki_openssl_diff_mod.addImport("zig_compat", compat_mod);
    const pki_openssl_diff_tests = b.addTest(.{ .root_module = pki_openssl_diff_mod });
    const run_pki_openssl_diff_tests = b.addRunArtifact(pki_openssl_diff_tests);
    const pki_openssl_diff_step = b.step("test-pki-openssl", "Compare PKI validation fixtures with OpenSSL");
    pki_openssl_diff_step.dependOn(&run_pki_openssl_diff_tests.step);
    const pki_policy_openssl_diff_tests = b.addTest(.{
        .root_module = pki_openssl_diff_mod,
        .filters = &.{"certificate policy"},
    });
    const run_pki_policy_openssl_diff_tests = b.addRunArtifact(pki_policy_openssl_diff_tests);
    const pki_policy_openssl_diff_step = b.step("test-pki-policy-openssl", "Compare certificate-policy fixtures with OpenSSL");
    pki_policy_openssl_diff_step.dependOn(&run_pki_policy_openssl_diff_tests.step);

    // Three-way hostile-corpus validation (#348): Tardigrade runs in process;
    // OpenSSL and Go crypto/x509 are invoked as independent processes. These
    // targets stay opt-in because the external validators are test tools, not
    // production dependencies.
    const pki_process_helper_mod = b.createModule(.{
        .root_source_file = b.path("tests/pki_process_helper.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const pki_process_helper = b.addExecutable(.{
        .name = "pki_process_helper",
        .root_module = pki_process_helper_mod,
    });
    const pki_process_helper_install = b.addInstallArtifact(pki_process_helper, .{});
    const pki_go_validator_build = b.addSystemCommand(&.{ go_bin, "build", "-trimpath", "-o" });
    const pki_go_validator_output = pki_go_validator_build.addOutputFileArg("pki_go_validator");
    pki_go_validator_build.addFileArg(b.path("tests/pki_go_validator.go"));
    const pki_go_validator_install = b.addInstallBinFile(pki_go_validator_output, "pki_go_validator");
    const pki_diff_options = b.addOptions();
    pki_diff_options.addOption([]const u8, "process_helper_path", b.getInstallPath(.bin, "pki_process_helper"));
    pki_diff_options.addOption([]const u8, "go_validator_path", b.getInstallPath(.bin, "pki_go_validator"));
    pki_diff_options.addOption([]const u8, "go_bin", go_bin);
    pki_diff_options.addOption(u32, "stable_validator_deadline_ms", 10_000);
    pki_diff_options.addOption(u32, "extended_validator_deadline_ms", 30_000);

    const pki_differential_mod = b.createModule(.{
        .root_source_file = b.path("tests/pki_differential.zig"),
        .target = target,
        .optimize = optimize,
    });
    pki_differential_mod.addImport("crypto", crypto_mod);
    pki_differential_mod.addImport("pki", pki_mod);
    pki_differential_mod.addImport("zig_compat", compat_mod);
    pki_differential_mod.addImport("pki_diff_options", pki_diff_options.createModule());
    pki_differential_mod.addAnonymousImport("pki_root_crt", .{
        .root_source_file = b.path("tests/vectors/pki/root.crt"),
    });
    pki_differential_mod.addAnonymousImport("pki_intermediate_crt", .{
        .root_source_file = b.path("tests/vectors/pki/intermediate.crt"),
    });
    pki_differential_mod.addAnonymousImport("pki_duplicate_extension_crt", .{
        .root_source_file = b.path("tests/vectors/pki/duplicate-extension-leaf.crt"),
    });
    pki_differential_mod.addAnonymousImport("pki_signature_corrupt_crt", .{
        .root_source_file = b.path("tests/vectors/pki/signature-corrupt-leaf.crt"),
    });
    pki_differential_mod.addImport("pki_reduced_corpus", pki_reduced_corpus_mod);
    const pki_differential_core_tests = b.addTest(.{
        .root_module = pki_differential_mod,
        .filters = &.{"pki differential core corpus"},
    });
    const run_pki_differential_core_tests = b.addRunArtifact(pki_differential_core_tests);
    run_pki_differential_core_tests.step.dependOn(&pki_go_validator_install.step);
    const pki_differential_step = b.step("test-pki-differential", "Run stable PKI differential corpus against OpenSSL and Go");
    pki_differential_step.dependOn(&run_pki_differential_core_tests.step);

    const pki_differential_full_tests = b.addTest(.{
        .root_module = pki_differential_mod,
        .filters = &.{"pki differential full corpus"},
    });
    const run_pki_differential_full_tests = b.addRunArtifact(pki_differential_full_tests);
    run_pki_differential_full_tests.step.dependOn(&pki_go_validator_install.step);
    const pki_differential_extended_step = b.step("test-pki-differential-extended", "Run full PKI differential corpus against OpenSSL and Go");
    pki_differential_extended_step.dependOn(&run_pki_differential_full_tests.step);

    // Offline mismatch-minimization tests (#348): the reducer itself plus the
    // harness oracle run fully in process, so they belong to the ordinary
    // `test` target even though they live in the differential module.
    const pki_reduce_tests = b.addTest(.{
        .root_module = pki_differential_mod,
        .filters = &.{"pki reduce"},
    });
    const run_pki_reduce_tests = b.addRunArtifact(pki_reduce_tests);
    run_pki_reduce_tests.step.dependOn(&pki_process_helper_install.step);
    const pki_reduce_step = b.step("test-pki-reduce", "Run offline PKI mismatch-minimization tests");
    pki_reduce_step.dependOn(&run_pki_reduce_tests.step);
    test_step.dependOn(&run_pki_reduce_tests.step);
}

fn pathExists(path: []const u8) bool {
    std.Io.Dir.accessAbsolute(std.Io.Threaded.global_single_threaded.io(), path, .{}) catch return false;
    return true;
}

/// Link OpenSSL against a compile step.
fn configureSsl(
    compile: *std.Build.Step.Compile,
    prefer_static: bool,
    require_static: bool,
) void {
    configureSystemLibrarySearchPaths(compile, prefer_static);
    linkSystemLibrary(compile, "ssl", prefer_static, require_static);
    linkSystemLibrary(compile, "crypto", prefer_static, require_static);
}

fn linkSystemLibrary(
    compile: *std.Build.Step.Compile,
    name: []const u8,
    prefer_static_system_libs: bool,
    require_static_system_libs: bool,
) void {
    compile.root_module.linkSystemLibrary(name, .{
        .use_pkg_config = .no,
        .preferred_link_mode = if (prefer_static_system_libs) .static else .dynamic,
        .search_strategy = if (prefer_static_system_libs)
            (if (require_static_system_libs) .no_fallback else .mode_first)
        else
            .paths_first,
    });
}

fn configureSystemLibrarySearchPaths(
    compile: *std.Build.Step.Compile,
    prefer_static_system_libs: bool,
) void {
    const target = compile.rootModuleTarget();
    // Always add Homebrew paths on macOS so OpenSSL (not in Apple's SDK) is found.
    if (target.os.tag == .macos) {
        compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        if (pathExists("/usr/local/include")) compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/include" });
        compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        if (pathExists("/usr/local/opt/openssl@3/include")) compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/opt/openssl@3/include" });
        compile.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        if (pathExists("/usr/local/lib")) compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        compile.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        if (pathExists("/usr/local/opt/openssl@3/lib")) compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/opt/openssl@3/lib" });
    }
    if (target.os.tag == .linux) {
        if (pathExists("/usr/local/include")) compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/include" });
        compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
        if (pathExists("/usr/local/lib")) compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        switch (target.cpu.arch) {
            .aarch64 => {
                compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include/aarch64-linux-gnu" });
                compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib/aarch64-linux-gnu" });
                compile.root_module.addLibraryPath(.{ .cwd_relative = "/lib/aarch64-linux-gnu" });
            },
            .x86_64 => {
                compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
                compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });
                compile.root_module.addLibraryPath(.{ .cwd_relative = "/lib/x86_64-linux-gnu" });
            },
            else => {},
        }
    }
    if (!prefer_static_system_libs) return;
    compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/lib" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
}
