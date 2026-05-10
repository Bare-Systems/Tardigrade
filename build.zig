const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const prefer_static_system_libs = b.option(bool, "prefer-static-system-libs", "Prefer static linking for system libraries") orelse false;
    const require_static_system_libs = b.option(bool, "require-static-system-libs", "Require static linking for system libraries") orelse false;
    const static_executable = b.option(bool, "static-executable", "Build the tardigrade executable as a static binary") orelse false;
    const enable_http3_ngtcp2 = b.option(bool, "enable-http3-ngtcp2", "Enable experimental HTTP/3 ngtcp2/nghttp3 system-library integration") orelse false;
    const app_version = b.option([]const u8, "version", "Version string embedded in the tardigrade binary") orelse "dev";
    const osslclient_default_path = "/tmp/ngtcp2-upstream/build/examples/osslclient";
    const http3_osslclient_path = b.option([]const u8, "http3-osslclient-path", "Path to the ngtcp2 OpenSSL HTTP/3 example client used by 0-RTT integration tests") orelse if (pathExists(osslclient_default_path)) osslclient_default_path else "";

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_http3_ngtcp2", enable_http3_ngtcp2);
    build_options.addOption([]const u8, "version", app_version);
    const compat_mod = b.createModule(.{
        .root_source_file = b.path("src/zig_compat.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("build_options", build_options.createModule());

    const exe = b.addExecutable(.{
        .name = "tardigrade",
        .root_module = exe_mod,
        .linkage = if (static_executable) .static else null,
    });
    configureSsl(exe, enable_http3_ngtcp2, prefer_static_system_libs, require_static_system_libs);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    configureSsl(exe_unit_tests, enable_http3_ngtcp2, prefer_static_system_libs, require_static_system_libs);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const integration_options = b.addOptions();
    integration_options.addOption([]const u8, "tardigrade_bin_path", b.getInstallPath(.bin, "tardigrade"));
    integration_options.addOption([]const u8, "http3_resumption_client_bin_path", if (enable_http3_ngtcp2) b.getInstallPath(.bin, "http3_resumption_client") else "");
    integration_options.addOption([]const u8, "http3_osslclient_bin_path", http3_osslclient_path);

    if (enable_http3_ngtcp2) {
        const resumption_client_mod = b.createModule(.{
            .root_source_file = b.path("tests/http3_resumption_client.zig"),
            .target = target,
            .optimize = optimize,
        });
        const resumption_client = b.addExecutable(.{
            .name = "http3_resumption_client",
            .root_module = resumption_client_mod,
        });
        b.installArtifact(resumption_client);
    }

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
}

fn pathExists(path: []const u8) bool {
    std.Io.Dir.accessAbsolute(std.Io.Threaded.global_single_threaded.io(), path, .{}) catch return false;
    return true;
}

/// Link OpenSSL (required) and optional HTTP/3 libraries against a compile step.
fn configureSsl(
    compile: *std.Build.Step.Compile,
    enable_http3_ngtcp2: bool,
    prefer_static: bool,
    require_static: bool,
) void {
    configureSystemLibrarySearchPaths(compile, prefer_static);
    linkSystemLibrary(compile, "ssl", prefer_static, require_static);
    linkSystemLibrary(compile, "crypto", prefer_static, require_static);
    if (enable_http3_ngtcp2) {
        linkSystemLibrary(compile, "ngtcp2", prefer_static, require_static);
        linkSystemLibrary(compile, "ngtcp2_crypto_ossl", prefer_static, require_static);
        linkSystemLibrary(compile, "nghttp3", prefer_static, require_static);
    }
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
    // Always add Homebrew paths on macOS so OpenSSL (not in Apple's SDK) is found.
    if (compile.rootModuleTarget().os.tag == .macos) {
        compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        compile.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        compile.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }
    if (!prefer_static_system_libs) return;
    compile.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/lib" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    compile.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
}
