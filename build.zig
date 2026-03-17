const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
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

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("build_options", build_options.createModule());

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "tardigrade",
        .root_module = exe_mod,
        .linkage = if (static_executable) .static else null,
    });
    configureSystemLibrarySearchPaths(exe, prefer_static_system_libs);
    exe.linkLibC();
    linkSystemLibrary(exe, "ssl", prefer_static_system_libs, require_static_system_libs);
    linkSystemLibrary(exe, "crypto", prefer_static_system_libs, require_static_system_libs);
    if (enable_http3_ngtcp2) {
        linkSystemLibrary(exe, "ngtcp2", prefer_static_system_libs, require_static_system_libs);
        linkSystemLibrary(exe, "ngtcp2_crypto_ossl", prefer_static_system_libs, require_static_system_libs);
        linkSystemLibrary(exe, "nghttp3", prefer_static_system_libs, require_static_system_libs);
    }

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    configureSystemLibrarySearchPaths(exe_unit_tests, prefer_static_system_libs);
    exe_unit_tests.linkLibC();
    linkSystemLibrary(exe_unit_tests, "ssl", prefer_static_system_libs, require_static_system_libs);
    linkSystemLibrary(exe_unit_tests, "crypto", prefer_static_system_libs, require_static_system_libs);
    if (enable_http3_ngtcp2) {
        linkSystemLibrary(exe_unit_tests, "ngtcp2", prefer_static_system_libs, require_static_system_libs);
        linkSystemLibrary(exe_unit_tests, "ngtcp2_crypto_ossl", prefer_static_system_libs, require_static_system_libs);
        linkSystemLibrary(exe_unit_tests, "nghttp3", prefer_static_system_libs, require_static_system_libs);
    }

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const integration_options = b.addOptions();
    integration_options.addOption([]const u8, "tardigrade_bin_path", b.getInstallPath(.bin, "tardigrade"));
    integration_options.addOption([]const u8, "http3_resumption_client_bin_path", if (enable_http3_ngtcp2) b.getInstallPath(.bin, "http3_resumption_client") else "");
    integration_options.addOption([]const u8, "http3_osslclient_bin_path", http3_osslclient_path);

    if (enable_http3_ngtcp2) {
        const resumption_client = b.addExecutable(.{
            .name = "http3_resumption_client",
            .root_source_file = b.path("tests/http3_resumption_client.zig"),
            .target = target,
            .optimize = optimize,
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

    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.step.dependOn(b.getInstallStep());

    const integration_step = b.step("test-integration", "Run live-process integration tests");
    integration_step.dependOn(&run_integration_tests.step);
}

fn pathExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

fn linkSystemLibrary(
    compile: *std.Build.Step.Compile,
    name: []const u8,
    prefer_static_system_libs: bool,
    require_static_system_libs: bool,
) void {
    compile.linkSystemLibrary2(name, .{
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
    if (!prefer_static_system_libs) return;
    compile.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    compile.addLibraryPath(.{ .cwd_relative = "/lib" });
    compile.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    compile.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
}
