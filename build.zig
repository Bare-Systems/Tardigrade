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

/// Resolves the source revision embedded in benchmark/diagnostic metadata
/// (e.g. `crypto_bench`'s `_meta.tardigrade_commit`, #378's benchmark
/// contract). Runs `git rev-parse HEAD` at configure time and falls back to
/// `"unknown"` rather than failing the build when there is no `.git`
/// directory to inspect (a source archive, a shallow export, etc.) or `git`
/// itself is unavailable.
fn gitCommitSha(b: *std.Build) []const u8 {
    var code: u8 = undefined;
    const output = b.runAllowFail(&.{ "git", "rev-parse", "HEAD" }, &code, .ignore) catch return "unknown";
    const trimmed = std.mem.trim(u8, output, " \t\r\n");
    if (trimmed.len == 0) return "unknown";
    return trimmed;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const prefer_static_system_libs = b.option(bool, "prefer-static-system-libs", "Prefer static linking for system libraries") orelse false;
    const require_static_system_libs = b.option(bool, "require-static-system-libs", "Require static linking for system libraries") orelse false;
    const static_executable = b.option(bool, "static-executable", "Build the tardi executable as a static binary") orelse false;
    const app_version = b.option([]const u8, "version", "Version string embedded in the tardi binary") orelse "dev";
    const commit_sha = b.option([]const u8, "commit", "Source commit SHA embedded in benchmark/diagnostic metadata (default: `git rev-parse HEAD`, or \"unknown\")") orelse gitCommitSha(b);
    const go_bin = b.option([]const u8, "go-bin", "Go command used to build the PKI crypto/x509 oracle") orelse "go";
    const quic_test_filter = b.option([]const u8, "quic-test-filter", "Filter tests run by the test-quic step");
    const quic_test_filters: []const []const u8 = if (quic_test_filter) |filter| &.{filter} else &.{};
    const crypto_test_filter = b.option([]const u8, "crypto-test-filter", "Filter tests run by the test-crypto-provider-fuzz step");
    const crypto_test_filters: []const []const u8 = if (crypto_test_filter) |filter| &.{filter} else &.{};
    // #494: unlike the crypto/QUIC provider-fuzz steps, this step's root
    // module (tls_core_mod) is the *entire* pure-Zig TLS suite -- also run
    // unfiltered by `test-tls`/`test` -- not a dedicated fuzz-only root
    // file, so an unfiltered default here would just re-run the whole
    // suite under a second name. `tls_core_mod` also already contains
    // unrelated pre-existing "fuzz: ..." tests (sni_provider.zig,
    // ticket_key_snapshot.zig, ticket_protection.zig's own combined
    // identity/resolve target), so a bare "fuzz: " prefix would silently
    // pull those in too. Every #494-A target below is therefore named
    // "fuzz: TLS resumption: ..." and this defaults to that exact
    // namespace, scoping the step to only those targets; pass an explicit
    // filter to select one target for a longer local run.
    const tls_resumption_test_filter = b.option([]const u8, "tls-resumption-test-filter", "Filter tests run by the test-tls-resumption-fuzz step (default: \"fuzz: TLS resumption:\", i.e. only the #494 session/PSK/ticket/resumption fuzz targets)") orelse "fuzz: TLS resumption:";
    const tls_resumption_test_filters: []const []const u8 = &.{tls_resumption_test_filter};
    // Shared TLS protocol-engine fuzz targets (#491, epic #323-K):
    // handshake message/extension codecs, policy negotiation, transcript/HRR
    // state, and TLS-owned reassembly. Keep this namespace separate from
    // #494's resumption targets so local coverage-guided runs can select the
    // protocol boundary without also driving PSK/ticket/cache state.
    const tls_protocol_test_filter = b.option([]const u8, "tls-protocol-test-filter", "Filter tests run by the test-tls-protocol-fuzz step (default: \"fuzz: TLS protocol:\", i.e. only #491 shared TLS handshake/negotiation/transcript/reassembly fuzz targets)") orelse "fuzz: TLS protocol:";
    const tls_protocol_test_filters: []const []const u8 = &.{tls_protocol_test_filter};
    // TLS record / protection / epoch / encrypted-stream fuzz targets (#493,
    // epic #325-K). Same shape as #491/#494 above: a dedicated namespace so
    // local coverage-guided runs can select this boundary without also
    // driving the shared protocol engine or resumption state.
    const tls_record_test_filter = b.option(
        []const u8,
        "tls-record-test-filter",
        "Filter tests run by the test-tls-record-fuzz step (default: \"fuzz: TLS record:\", i.e. only #493 record/protection/epoch/encrypted-stream fuzz targets)",
    ) orelse "fuzz: TLS record:";
    const tls_record_test_filters: []const []const u8 = &.{tls_record_test_filter};
    // PKI parser/validator fuzz targets (#492, epic #324-K): DER decoding,
    // PEM/chain loading, the X.509 semantic model, and path building and
    // RFC 5280 validation. Same shape as the TLS steps above: the targets
    // live next to the code in `pki_mod`, which `test-pki`/`test` already
    // runs unfiltered, so this step exists to give them one stable,
    // individually filterable name for long coverage-guided runs.
    const pki_test_filter = b.option([]const u8, "pki-test-filter", "Filter tests run by the test-pki-fuzz step (default: \"fuzz: PKI:\", i.e. only #492 DER/PEM/X.509/path-validation fuzz targets)") orelse "fuzz: PKI:";
    const pki_test_filters: []const []const u8 = &.{pki_test_filter};
    const tls_profile = b.option(
        TlsProfile,
        "tls-profile",
        "TLS/crypto profile: 'general' (default) links the approved OpenSSL adapter; 'appliance' forbids all foreign TLS/crypto linkage (#379)",
    ) orelse .general;
    const link_openssl_adapter = tls_profile == .general;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", app_version);
    build_options.addOption([]const u8, "commit", commit_sha);
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
        // appliance_credentials.zig's own unit tests exercise the file-reading
        // path (std.c.close) directly inside this module's test binary,
        // unlike identity_loader.zig's file helpers which were previously
        // only reached through exe_mod (already link_libc = true).
        .link_libc = true,
    });
    tls_core_mod.addImport("crypto_secrets", crypto_secrets_mod);
    tls_core_mod.addImport("zig_compat", compat_mod);

    // Shared leaf modules. A Zig source file belongs to exactly one module,
    // so anything consumed by both the exe tree and the quic/http3 packages
    // (varint, huffman tables, the protocol-neutral stream contract) is a
    // named module everywhere.
    const hpack_huffman_mod = b.createModule(.{
        .root_source_file = b.path("src/http/hpack_huffman.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hpack_mod = b.createModule(.{
        .root_source_file = b.path("src/http/hpack.zig"),
        .target = target,
        .optimize = optimize,
    });
    hpack_mod.addImport("hpack_huffman", hpack_huffman_mod);
    const stream_transport_mod = b.createModule(.{
        .root_source_file = b.path("src/http/stream_transport.zig"),
        .target = target,
        .optimize = optimize,
    });
    const http_encrypted_stream_connection_mod = b.createModule(.{
        .root_source_file = b.path("src/http/encrypted_stream_connection.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_encrypted_stream_connection_mod.addImport("tls_core", tls_core_mod);
    const http_request_mod = b.createModule(.{
        .root_source_file = b.path("src/http/request.zig"),
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

    // Test-only twin of quic_mod (#490 sixth-pass review), same shape as
    // exe_test_mod above: used only for quic_tests below, so quic_mod
    // itself -- the module every production consumer (exe_mod, http3_mod's
    // siblings, allocation_regression_mod, ...) actually imports -- never
    // resolves test_quic_crypto at all.
    const quic_test_mod = b.createModule(.{
        .root_source_file = b.path("src/quic/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_test_mod.addImport("quic_varint", quic_varint_mod);
    quic_test_mod.addImport("tls_core", tls_core_mod);
    quic_test_mod.addImport("crypto_secrets", crypto_secrets_mod);
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
    exe_mod.addImport("zig_compat", compat_mod);
    exe_mod.addImport("quic_varint", quic_varint_mod);
    exe_mod.addImport("hpack_huffman", hpack_huffman_mod);
    exe_mod.addImport("stream_transport", stream_transport_mod);
    exe_mod.addImport("quic", quic_mod);
    exe_mod.addImport("http3", http3_mod);
    exe_mod.addImport("tls_core", tls_core_mod);

    // Test-only twin of exe_mod (#490 sixth-pass review): same root file and
    // dependencies, used *only* for exe_unit_tests below. Production code
    // reachable from `exe`/`run_cmd` is exe_mod itself, which never gets the
    // test_quic_crypto import wired in (added further down, once
    // test_quic_crypto_mod exists) -- so referencing it from production
    // code, under any local binding name or via an inline `@import`, is a
    // compile error, not something a source-text scanner has to catch.
    // Zig's per-module "a source file belongs to exactly one module" rule is
    // scoped to one compilation graph; exe_mod (the `exe`/`exe_unit_tests`
    // graph) and exe_test_mod (its own independent `zig test` invocation)
    // never appear in the same graph together, so both rooting at
    // src/main.zig is not the ambiguity that rule guards against.
    const exe_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_test_mod.addImport("build_options", build_options.createModule());
    exe_test_mod.addImport("zig_compat", compat_mod);
    exe_test_mod.addImport("quic_varint", quic_varint_mod);
    exe_test_mod.addImport("hpack_huffman", hpack_huffman_mod);
    exe_test_mod.addImport("stream_transport", stream_transport_mod);
    exe_test_mod.addImport("quic", quic_mod);
    exe_test_mod.addImport("http3", http3_mod);
    exe_test_mod.addImport("tls_core", tls_core_mod);

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
        .root_module = exe_test_mod,
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

    // Session/PSK/ticket/resumption fuzz targets (#494, epic #326-K),
    // following the shared contract in docs/CRYPTO_FUZZ_CONTRACT.md and
    // #376's test-crypto-provider-fuzz naming pattern. The targets
    // themselves are inline `test "fuzz: ..."` blocks next to the code
    // they exercise (new_session_ticket.zig, session.zig,
    // pre_shared_key.zig, ticket_protection.zig) and already replay their
    // deterministic seed corpus under plain `test-tls`/`test`; this step
    // exists to give them a stable, individually filterable/long-runnable
    // name, matching #376's `-Dcrypto-test-filter` shape.
    const tls_resumption_fuzz_tests = b.addTest(.{ .root_module = tls_core_mod, .filters = tls_resumption_test_filters });
    const run_tls_resumption_fuzz_tests = b.addRunArtifact(tls_resumption_fuzz_tests);
    const tls_resumption_fuzz_step = b.step("test-tls-resumption-fuzz", "Run TLS session/PSK/ticket/resumption fuzz targets (#494)");
    tls_resumption_fuzz_step.dependOn(&run_tls_resumption_fuzz_tests.step);

    const tls_protocol_fuzz_tests = b.addTest(.{ .root_module = tls_core_mod, .filters = tls_protocol_test_filters });
    const run_tls_protocol_fuzz_tests = b.addRunArtifact(tls_protocol_fuzz_tests);
    const tls_protocol_fuzz_step = b.step("test-tls-protocol-fuzz", "Run shared TLS protocol-engine fuzz targets (#491)");
    tls_protocol_fuzz_step.dependOn(&run_tls_protocol_fuzz_tests.step);

    // Record codec, protection, epoch/key lifecycle, and encrypted-stream
    // fuzz targets (#493, epic #325-K). Like #494/#491 above, these are
    // inline `test "fuzz: ..."` blocks next to the code they exercise
    // (record_codec.zig, record_protection.zig, record_epoch_bridge.zig,
    // encrypted_stream.zig) and already replay their deterministic seed
    // corpus under plain `test-tls`/`test`; this step gives them a stable,
    // individually filterable/long-runnable name.
    const tls_record_fuzz_tests = b.addTest(.{ .root_module = tls_core_mod, .filters = tls_record_test_filters });
    const run_tls_record_fuzz_tests = b.addRunArtifact(tls_record_fuzz_tests);
    const tls_record_fuzz_step = b.step("test-tls-record-fuzz", "Run TLS record/protection/epoch/encrypted-stream fuzz targets (#493)");
    tls_record_fuzz_step.dependOn(&run_tls_record_fuzz_tests.step);

    const allocation_regression_mod = b.createModule(.{
        .root_source_file = b.path("src/allocation_regression.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    allocation_regression_mod.addImport("build_options", build_options.createModule());
    allocation_regression_mod.addImport("zig_compat", compat_mod);
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
    integration_mod.addImport("hpack_huffman", hpack_huffman_mod);
    integration_mod.addImport("hpack", hpack_mod);
    integration_mod.addImport("tls_core", tls_core_mod);

    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.step.dependOn(b.getInstallStep());

    const integration_step = b.step("test-integration", "Run live-process integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    const native_listener_integration_tests = b.addTest(.{
        .root_module = integration_mod,
        .filters = &.{"native TLS listener"},
    });
    const run_native_listener_integration_tests = b.addRunArtifact(native_listener_integration_tests);
    run_native_listener_integration_tests.step.dependOn(b.getInstallStep());
    const native_listener_integration_step = b.step("test-integration-native-tls", "Run native TLS listener HTTP integration tests");
    native_listener_integration_step.dependOn(&run_native_listener_integration_tests.step);

    // Resumption/0-RTT external interop, restart, and soak suite (#369, and
    // #522's `h3interop.*` QUIC/H3 cases -- `h3interop.` contains the
    // `interop.` filter substring, so they run under this same step): the
    // same live-process harness filtered to the stable `interop.`/
    // `restart.`/`rotation.`/`soak.` case-ID prefixes (`rotation.` added by
    // #519 for the persistent ticket-key rotation/reload-atomicity/
    // certificate-binding composed proofs, which need the same real-process/
    // real-SIGHUP coverage on platforms where the full `test-integration`
    // suite is skipped -- see ci.yml). Kept as its own step (not folded into
    // `test-integration-native-tls`) so CI can budget it separately -- it
    // shells out to a real `openssl`/`gtlsclient` subprocess per case and
    // spawns/kills/SIGHUPs real Tardigrade processes for restart/rotation
    // coverage.
    const resumption_interop_tests = b.addTest(.{
        .root_module = integration_mod,
        .filters = &.{ "interop.", "restart.", "rotation.", "soak." },
    });
    const run_resumption_interop_tests = b.addRunArtifact(resumption_interop_tests);
    run_resumption_interop_tests.step.dependOn(b.getInstallStep());
    const resumption_interop_step = b.step("test-integration-resumption-interop", "Run #369 external OpenSSL interop, #522 QUIC/H3 interop, restart, #519 rotation, and soak cases");
    resumption_interop_step.dependOn(&run_resumption_interop_tests.step);

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
    failure_mode_mod.addImport("hpack_huffman", hpack_huffman_mod);
    failure_mode_mod.addImport("hpack", hpack_mod);
    failure_mode_mod.addImport("tls_core", tls_core_mod);

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
    const quic_varint_tests = b.addTest(.{ .root_module = quic_varint_mod, .filters = quic_test_filters });
    const run_quic_varint_tests = b.addRunArtifact(quic_varint_tests);
    const quic_tests = b.addTest(.{ .root_module = quic_test_mod, .filters = quic_test_filters });
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
    quic_mod.addImport("crypto", crypto_mod);
    quic_test_mod.addImport("crypto", crypto_mod);
    tls_core_mod.addImport("crypto", crypto_mod);
    exe_mod.addImport("crypto", crypto_mod);
    exe_test_mod.addImport("crypto", crypto_mod);

    // Test-only QUIC/H3 crypto provider composition (#490): owns concrete
    // `pure_zig.Provider` construction so `src/quic/` and the native HTTP/3
    // composition root never do. Wired only into explicit test/tool roots --
    // quic_test_mod and exe_test_mod (used solely by quic_tests/
    // exe_unit_tests below), the QUIC/H3 smoke/e2e/UDP test modules further
    // down, the test-only Runtime clone those UDP tests build against, and
    // the opt-in H3 interop tool -- never into quic_mod, exe_mod, or any
    // other module that feeds the shipped `tardi` build. Renaming the local
    // binding, using an inline `@import`, or any other indirection cannot
    // resolve a module this import isn't wired into: the compiler itself
    // enforces the boundary, not a source-text scanner trying to
    // approximate it (#490 sixth-pass review: a prior version of this
    // comment relied on `scripts/audit_crypto_boundary.zig` pattern-matching
    // for this, which a renamed binding or an inline `@import` bypassed, and
    // which couldn't see that Zig declarations are order-independent -- a
    // public production declaration can call a private helper physically
    // written after a "test boundary" marker, so no text-position heuristic
    // can make that region truly unreachable).
    const test_quic_crypto_mod = b.createModule(.{
        .root_source_file = b.path("tests/support/quic_crypto.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_quic_crypto_mod.addImport("crypto", crypto_mod);
    quic_test_mod.addImport("test_quic_crypto", test_quic_crypto_mod);
    exe_test_mod.addImport("test_quic_crypto", test_quic_crypto_mod);

    const crypto_tests = b.addTest(.{ .root_module = crypto_mod });
    const run_crypto_tests = b.addRunArtifact(crypto_tests);
    const crypto_secret_tests = b.addTest(.{ .root_module = crypto_secrets_mod });
    const run_crypto_secret_tests = b.addRunArtifact(crypto_secret_tests);
    const crypto_step = b.step("test-crypto", "Run pure-Zig cryptographic-provider unit tests");
    crypto_step.dependOn(&run_crypto_tests.step);
    crypto_step.dependOn(&run_crypto_secret_tests.step);
    test_step.dependOn(&run_crypto_tests.step);
    test_step.dependOn(&run_crypto_secret_tests.step);

    // Deterministic, dependency-free crypto-boundary audit (#490): a checked-in
    // Zig program rather than a shell script shelling out to an ambient `rg`,
    // so every CI runner and platform enforces it identically with nothing
    // extra to install. This is a source-audit build tool that inspects the
    // repository and must run on the machine doing the build, so it (and its
    // `zig_compat` dependency) are built for the build host, not the
    // user-selected `-Dtarget` — a cross build (e.g. `-Dtarget=aarch64-linux`
    // on an x86 host) would otherwise produce a foreign executable that
    // `addRunArtifact` cannot execute.
    const host_compat_mod = b.createModule(.{
        .root_source_file = b.path("src/zig_compat.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .link_libc = true,
    });
    const crypto_boundary_audit_mod = b.createModule(.{
        .root_source_file = b.path("scripts/audit_crypto_boundary.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    crypto_boundary_audit_mod.addImport("zig_compat", host_compat_mod);
    const crypto_boundary_audit_exe = b.addExecutable(.{
        .name = "audit_crypto_boundary",
        .root_module = crypto_boundary_audit_mod,
    });
    const crypto_boundary_audit_tests = b.addTest(.{ .root_module = crypto_boundary_audit_mod });
    const run_crypto_boundary_audit_tests = b.addRunArtifact(crypto_boundary_audit_tests);
    const crypto_boundary_audit = b.addRunArtifact(crypto_boundary_audit_exe);
    crypto_boundary_audit.addArg(".");
    crypto_boundary_audit.setCwd(b.path("."));
    const crypto_boundary_step = b.step("audit-crypto-boundary", "Audit direct keyed crypto usage outside provider-owned modules");
    crypto_boundary_step.dependOn(&run_crypto_boundary_audit_tests.step);
    crypto_boundary_step.dependOn(&crypto_boundary_audit.step);
    crypto_step.dependOn(&run_crypto_boundary_audit_tests.step);
    crypto_step.dependOn(&crypto_boundary_audit.step);
    test_step.dependOn(&run_crypto_boundary_audit_tests.step);
    test_step.dependOn(&crypto_boundary_audit.step);

    // Bounded session-resumption cache (#364/#365). Kept as a standalone
    // test target for focused cache/persistence coverage, while also exported
    // through `tls_core` for the shared native resumption runtime.
    const session_cache_mod = b.createModule(.{
        .root_source_file = b.path("src/tls/session_cache.zig"),
        .target = target,
        .optimize = optimize,
        // Pulls in `zig_compat.Mutex` (std.Io.Mutex-backed, not a spin lock)
        // for the cache's own thread safety, same as `http/buffer_pool.zig`.
        .link_libc = true,
    });
    session_cache_mod.addImport("crypto", crypto_mod);
    session_cache_mod.addImport("zig_compat", compat_mod);
    const session_cache_tests = b.addTest(.{ .root_module = session_cache_mod });
    const run_session_cache_tests = b.addRunArtifact(session_cache_tests);
    const session_cache_step = b.step("test-session-cache", "Run bounded session-resumption cache unit tests (#364)");
    session_cache_step.dependOn(&run_session_cache_tests.step);
    test_step.dependOn(&run_session_cache_tests.step);

    const session_cache_persistence_mod = b.createModule(.{
        .root_source_file = b.path("src/tls/session_cache_persistence.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    session_cache_persistence_mod.addImport("crypto", crypto_mod);
    session_cache_persistence_mod.addImport("zig_compat", compat_mod);
    const session_cache_persistence_tests = b.addTest(.{ .root_module = session_cache_persistence_mod });
    const run_session_cache_persistence_tests = b.addRunArtifact(session_cache_persistence_tests);
    session_cache_step.dependOn(&run_session_cache_persistence_tests.step);
    test_step.dependOn(&run_session_cache_persistence_tests.step);

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
    // command and a test-only EVP child process out-of-process for
    // deterministic TLS/QUIC derivation and primitive stages.
    if (link_openssl_adapter) {
        const evp_oracle_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        evp_oracle_mod.addCSourceFile(.{ .file = b.path("tests/evp_oracle.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Wno-deprecated-declarations" } });
        const evp_oracle = b.addExecutable(.{
            .name = "evp_oracle",
            .root_module = evp_oracle_mod,
        });
        configureSystemLibrarySearchPaths(evp_oracle, prefer_static_system_libs);
        linkSystemLibrary(evp_oracle, "crypto", prefer_static_system_libs, require_static_system_libs);
        const evp_oracle_install = b.addInstallArtifact(evp_oracle, .{});
        const crypto_openssl_diff_options = b.addOptions();
        crypto_openssl_diff_options.addOption([]const u8, "evp_oracle_path", b.getInstallPath(.bin, "evp_oracle"));

        const crypto_openssl_diff_mod = b.createModule(.{
            .root_source_file = b.path("tests/crypto_openssl_diff.zig"),
            .target = target,
            .optimize = optimize,
        });
        crypto_openssl_diff_mod.addImport("crypto_openssl_diff_options", crypto_openssl_diff_options.createModule());
        crypto_openssl_diff_mod.addImport("crypto", crypto_mod);
        crypto_openssl_diff_mod.addImport("tls_core", tls_core_mod);
        crypto_openssl_diff_mod.addImport("quic", quic_mod);
        crypto_openssl_diff_mod.addImport("zig_compat", compat_mod);
        const crypto_openssl_diff_tests = b.addTest(.{ .root_module = crypto_openssl_diff_mod });
        const run_crypto_openssl_diff_tests = b.addRunArtifact(crypto_openssl_diff_tests);
        run_crypto_openssl_diff_tests.step.dependOn(&evp_oracle_install.step);
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

    // Standalone CryptoProvider fuzz targets (#376, epic #327-G): AEAD,
    // key exchange, signature verification, signing-key boundary, and
    // shared secret container properties, following the shared fuzz
    // contract in docs/CRYPTO_FUZZ_CONTRACT.md. Deterministic seed-corpus
    // replay runs by default; `-Doptimize=ReleaseFast --fuzz=<N>` drives
    // real coverage-guided exploration, matching docs/QUIC_H3_FUZZ_MATRIX.md.
    const crypto_provider_fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/crypto_provider_fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_provider_fuzz_mod.addImport("crypto", crypto_mod);
    const crypto_provider_fuzz_tests = b.addTest(.{ .root_module = crypto_provider_fuzz_mod, .filters = crypto_test_filters });
    const run_crypto_provider_fuzz_tests = b.addRunArtifact(crypto_provider_fuzz_tests);
    const crypto_provider_fuzz_step = b.step("test-crypto-provider-fuzz", "Run standalone CryptoProvider AEAD/KEX/verify/signing-key/secret-helper fuzz targets (#376)");
    crypto_provider_fuzz_step.dependOn(&run_crypto_provider_fuzz_tests.step);
    crypto_step.dependOn(&run_crypto_provider_fuzz_tests.step);
    test_step.dependOn(&run_crypto_provider_fuzz_tests.step);

    // CryptoProvider/record/ticket-protection benchmark suite (#378, epic
    // #327-I): reports latency, throughput, and allocation measurements for
    // the shared crypto seam as JSON. `test-crypto-bench` runs every
    // workload at a tiny iteration count purely as a correctness smoke check
    // (crash/API-drift detection, not a timing signal), so it is safe to
    // include in the default `zig build test`; `bench-crypto` runs the same
    // suites at full iteration counts and prints the report.
    const crypto_bench_mod = b.createModule(.{
        .root_source_file = b.path("src/crypto_bench/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    crypto_bench_mod.addImport("build_options", build_options.createModule());
    crypto_bench_mod.addImport("zig_compat", compat_mod);
    crypto_bench_mod.addImport("crypto", crypto_mod);
    crypto_bench_mod.addImport("tls_core", tls_core_mod);

    const crypto_bench_tests = b.addTest(.{ .root_module = crypto_bench_mod });
    const run_crypto_bench_tests = b.addRunArtifact(crypto_bench_tests);
    const crypto_bench_test_step = b.step("test-crypto-bench", "Run the CryptoProvider/record/ticket-protection benchmark suite as a correctness smoke check (#378)");
    crypto_bench_test_step.dependOn(&run_crypto_bench_tests.step);
    crypto_step.dependOn(&run_crypto_bench_tests.step);
    test_step.dependOn(&run_crypto_bench_tests.step);

    const crypto_bench_exe = b.addExecutable(.{
        .name = "crypto_bench",
        .root_module = crypto_bench_mod,
    });
    const run_crypto_bench = b.addRunArtifact(crypto_bench_exe);
    const crypto_bench_step = b.step("bench-crypto", "Report CryptoProvider/record/ticket-protection benchmark measurements as JSON (#378)");
    crypto_bench_step.dependOn(&run_crypto_bench.step);

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
    record_mode_handshake_test_mod.addImport("http_encrypted_stream_connection", http_encrypted_stream_connection_mod);
    record_mode_handshake_test_mod.addImport("http_request", http_request_mod);
    const record_mode_handshake_tests = b.addTest(.{ .root_module = record_mode_handshake_test_mod });
    const run_record_mode_handshake_tests = b.addRunArtifact(record_mode_handshake_tests);
    tls_step.dependOn(&run_record_mode_handshake_tests.step);
    quic_step.dependOn(&run_record_mode_handshake_tests.step);
    test_step.dependOn(&run_record_mode_handshake_tests.step);

    // Dedicated test-only root for key_schedule_tests.zig (#490 review): a
    // standalone module, structurally separate from tls_core_mod (src/tls/
    // root.zig, the production TLS module every native TLS/QUIC/HTTP/exe
    // consumer depends on). key_schedule_tests.zig carries approved direct-
    // crypto fixtures (a std.crypto.auth.hmac.sha2.HmacSha256 cross-check,
    // raw CryptoProvider vtable construction) that scripts/
    // audit_crypto_boundary.zig deliberately never scans, on the invariant
    // that no production code path can resolve the file that carries them —
    // this module is wired only into test artifacts below, never into
    // quic_mod/exe_mod/the tardi executable, so that invariant is structural
    // (a Zig compiler property), not merely a convention.
    const key_schedule_test_root_mod = b.createModule(.{
        .root_source_file = b.path("src/tls/key_schedule_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    key_schedule_test_root_mod.addImport("tls_core", tls_core_mod);
    key_schedule_test_root_mod.addImport("crypto", crypto_mod);
    const key_schedule_tests_artifact = b.addTest(.{ .root_module = key_schedule_test_root_mod });
    const run_key_schedule_tests = b.addRunArtifact(key_schedule_tests_artifact);
    tls_step.dependOn(&run_key_schedule_tests.step);
    crypto_step.dependOn(&run_key_schedule_tests.step);
    test_step.dependOn(&run_key_schedule_tests.step);

    const http3_tests = b.addTest(.{ .root_module = http3_mod, .filters = quic_test_filters });
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
    quic_h3_smoke_mod.addImport("test_quic_crypto", test_quic_crypto_mod);
    const quic_h3_smoke_tests = b.addTest(.{ .root_module = quic_h3_smoke_mod, .filters = quic_test_filters });
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
    quic_h3_e2e_mod.addImport("test_quic_crypto", test_quic_crypto_mod);
    const quic_h3_e2e_tests = b.addTest(.{ .root_module = quic_h3_e2e_mod, .filters = quic_test_filters });
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
    quic_h3_udp_mod.addImport("tls_core", tls_core_mod);
    quic_h3_udp_mod.addImport("zig_compat", compat_mod);
    quic_h3_udp_mod.addImport("build_options", build_options.createModule());
    quic_h3_udp_mod.addImport("test_quic_crypto", test_quic_crypto_mod);
    const udp_http3_runtime_mod = b.createModule(.{
        .root_source_file = b.path("src/http/http3_runtime.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    udp_http3_runtime_mod.addImport("zig_compat", compat_mod);
    udp_http3_runtime_mod.addImport("stream_transport", stream_transport_mod);
    udp_http3_runtime_mod.addImport("quic", quic_mod);
    udp_http3_runtime_mod.addImport("http3", http3_mod);
    udp_http3_runtime_mod.addImport("tls_core", tls_core_mod);
    udp_http3_runtime_mod.addImport("crypto", crypto_mod);
    udp_http3_runtime_mod.addImport("build_options", build_options.createModule());
    udp_http3_runtime_mod.addImport("test_quic_crypto", test_quic_crypto_mod);
    quic_h3_udp_mod.addImport("http3_runtime", udp_http3_runtime_mod);
    const quic_h3_udp_tests = b.addTest(.{ .root_module = quic_h3_udp_mod, .filters = quic_test_filters });
    const run_quic_h3_udp_tests = b.addRunArtifact(quic_h3_udp_tests);
    quic_step.dependOn(&run_quic_h3_udp_tests.step);
    test_step.dependOn(&run_quic_h3_udp_tests.step);

    // Shared interop/conformance matrix vocabulary (#338): the single place
    // that maps a matrix row's cipher-suite/group/signature/ALPN names onto
    // an engine policy. Both interop tools import it, so a row means the
    // same thing on the record transport and on QUIC.
    const tls_interop_matrix_mod = b.createModule(.{
        .root_source_file = b.path("tests/tls_interop_matrix.zig"),
        .target = target,
        .optimize = optimize,
    });
    tls_interop_matrix_mod.addImport("tls_core", tls_core_mod);
    const tls_interop_matrix_tests = b.addTest(.{ .root_module = tls_interop_matrix_mod });
    const run_tls_interop_matrix_tests = b.addRunArtifact(tls_interop_matrix_tests);
    const tls_interop_matrix_step = b.step("test-tls-interop-matrix", "Run #338 interop matrix vocabulary unit tests");
    tls_interop_matrix_step.dependOn(&run_tls_interop_matrix_tests.step);
    test_step.dependOn(&run_tls_interop_matrix_tests.step);

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
    h3_interop_mod.addImport("tls_interop_matrix", tls_interop_matrix_mod);
    const h3_interop_tool = b.addExecutable(.{
        .name = "h3_interop_tool",
        .root_module = h3_interop_mod,
    });
    const h3_interop_install = b.addInstallArtifact(h3_interop_tool, .{});
    const h3_interop_step = b.step("build-h3-interop", "Build the native HTTP/3 interop client/server tool");
    h3_interop_step.dependOn(&h3_interop_install.step);

    // Out-of-process record-transport TLS conformance driver (#338). Runs
    // the shared engine as client or server against external peers
    // (`openssl s_server`/`s_client`, `gnutls-serv`/`gnutls-cli`) over a
    // real TCP socket — see scripts/interop/run-tls-interop.sh.
    const tls_interop_mod = b.createModule(.{
        .root_source_file = b.path("tests/tls_interop_tool.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tls_interop_mod.addImport("tls_core", tls_core_mod);
    tls_interop_mod.addImport("crypto", crypto_mod);
    tls_interop_mod.addImport("tls_interop_matrix", tls_interop_matrix_mod);
    const tls_interop_tool = b.addExecutable(.{
        .name = "tls_interop_tool",
        .root_module = tls_interop_mod,
    });
    const tls_interop_install = b.addInstallArtifact(tls_interop_tool, .{});
    const tls_interop_step = b.step("build-tls-interop", "Build the shared-TLS-engine record-transport interop client/server tool");
    tls_interop_step.dependOn(&tls_interop_install.step);

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
    // The appliance credential loader (#392) reuses the PKI PEM/X.509
    // machinery; pki does not import tls_core, so this stays acyclic.
    tls_core_mod.addImport("pki", pki_mod);
    const pki_tests = b.addTest(.{ .root_module = pki_mod });
    const run_pki_tests = b.addRunArtifact(pki_tests);
    const pki_step = b.step("test-pki", "Run pure-Zig PKI DER unit tests");
    pki_step.dependOn(&run_pki_tests.step);
    test_step.dependOn(&run_pki_tests.step);

    // DER/PEM/X.509/path-validation fuzz targets (#492, epic #324-K). The
    // targets are inline `test "fuzz: PKI: ..."` blocks inside `pki_mod`, so
    // their deterministic seed-corpus replay is already part of `test-pki`
    // and `test`; this step only scopes them for `--fuzz=<N>` runs.
    const pki_fuzz_tests = b.addTest(.{ .root_module = pki_mod, .filters = pki_test_filters });
    const run_pki_fuzz_tests = b.addRunArtifact(pki_fuzz_tests);
    const pki_fuzz_step = b.step("test-pki-fuzz", "Run PKI DER/PEM/X.509/path-validation fuzz targets (#492)");
    pki_fuzz_step.dependOn(&run_pki_fuzz_tests.step);

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
    const pki_go_validator_tests = b.addSystemCommand(&.{ go_bin, "test" });
    pki_go_validator_tests.addFileArg(b.path("tests/pki_go_validator.go"));
    pki_go_validator_tests.addFileArg(b.path("tests/pki_go_validator_test.go"));
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
    pki_differential_mod.addAnonymousImport("pki_der_non_minimal_long_length_crt", .{
        .root_source_file = b.path("tests/vectors/pki/der-non-minimal-long-length.crt"),
    });
    pki_differential_mod.addAnonymousImport("pki_der_non_minimal_long_length_der", .{
        .root_source_file = b.path("tests/vectors/pki/der-non-minimal-long-length.der"),
    });
    pki_differential_mod.addImport("pki_reduced_corpus", pki_reduced_corpus_mod);
    const pki_differential_core_tests = b.addTest(.{
        .root_module = pki_differential_mod,
        .filters = &.{"pki differential core corpus"},
    });
    const run_pki_differential_core_tests = b.addRunArtifact(pki_differential_core_tests);
    run_pki_differential_core_tests.step.dependOn(&pki_go_validator_install.step);
    run_pki_differential_core_tests.step.dependOn(&pki_go_validator_tests.step);
    const pki_differential_step = b.step("test-pki-differential", "Run stable PKI differential corpus against OpenSSL and Go");
    pki_differential_step.dependOn(&run_pki_differential_core_tests.step);

    const pki_differential_full_tests = b.addTest(.{
        .root_module = pki_differential_mod,
        .filters = &.{"pki differential full corpus"},
    });
    const run_pki_differential_full_tests = b.addRunArtifact(pki_differential_full_tests);
    run_pki_differential_full_tests.step.dependOn(&pki_go_validator_install.step);
    run_pki_differential_full_tests.step.dependOn(&pki_go_validator_tests.step);
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
