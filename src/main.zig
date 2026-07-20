const std = @import("std");
const build_options = @import("build_options");
const compat = @import("zig_compat.zig");
const edge_config = @import("edge_config.zig");
const edge_gateway = @import("edge_gateway.zig");
const http = @import("http.zig");
const runtime_allocator = @import("runtime_allocator.zig");
const tls_core = @import("tls_core");

const ENV_CONFIG_PATH = "TARDIGRADE_CONFIG_PATH";
const CHECK_DEFAULT_CONFIG_PATH = "./tardigrade.toml";
const EXIT_INTERNAL_ERROR: u8 = 1;
const EXIT_CONFIG_INVALID: u8 = 2;

const CliCommand = union(enum) {
    run: RunOptions,
    check: CommonOptions,
    validate: CommonOptions,
    status: SignalOptions,
    print_config: CommonOptions,
    routes: CommonOptions,
    upstreams: CommonOptions,
    reload: SignalOptions,
    stop: SignalOptions,
    version,
    help,
    config_init: ConfigInitOptions,
};

const CommonOptions = struct {
    config_path: ?[]const u8 = null,
};

const RunOptions = struct {
    common: CommonOptions = .{},
    daemon: bool = false,
    daemonized: bool = false,
};

const SignalOptions = struct {
    common: CommonOptions = .{},
    pid_file: ?[]const u8 = null,
    pid: ?std.posix.pid_t = null,
};

const ConfigInitOptions = struct {
    output_path: []const u8 = "tardigrade.conf",
    force: bool = false,
    stdout: bool = false,
};

const ValidationMode = enum {
    check,
    legacy,
};

const starter_config =
    \\# Tardigrade starter config.
    \\# All HTTP request-path behavior is config-defined.
    \\
    \\pid /var/run/tardigrade.pid;
    \\listen 8069;
    \\server_name localhost;
    \\
    \\root ./public;
    \\try_files $uri /index.html;
    \\
    \\location = / {
    \\    return 302 /index.html;
    \\}
    \\
    \\location / {
    \\    root ./public;
    \\    try_files $uri /index.html;
    \\}
    \\
    \\# Example reverse-proxy route:
    \\# location = /v1/chat {
    \\#     proxy_pass http://127.0.0.1:8080/v1/chat;
    \\# }
    \\
;

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

pub fn main(init: std.process.Init.Minimal) !void {
    var control_allocator_state = runtime_allocator.ControlPlaneAllocator{};
    defer std.debug.assert(control_allocator_state.deinit() == .ok);
    const control_allocator = control_allocator_state.allocator();

    var args_iter = init.args.iterate();
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(control_allocator);
    while (args_iter.next()) |arg| try args_list.append(control_allocator, arg);
    const args = args_list.items;

    const command = parseCliCommand(args[1..]) catch |err| {
        var stderr_buf: [2048]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try printCliParseError(&stderr, err);
        try printUsage(&stderr);
        try stderr.flush();
        return err;
    };

    switch (command) {
        .help => {
            var stdout_buf: [2048]u8 = undefined;
            var stdout = compat.stdoutWriter(&stdout_buf);
            try printUsage(&stdout);
            try stdout.flush();
        },
        .version => {
            var stdout_buf: [256]u8 = undefined;
            var stdout = compat.stdoutWriter(&stdout_buf);
            // The selected TLS profile is part of the artifact's identity
            // (#379): operators and release audits verify from this line
            // which backend a binary was built with.
            try stdout.print("{s} (tls-profile={s}, tls-backend={s})\n", .{
                http.SERVER_VERSION,
                build_options.tls_profile,
                if (build_options.tls_openssl_adapter) "openssl-adapter" else "native",
            });
            try stdout.flush();
        },
        .config_init => |options| try writeStarterConfig(options),
        .status => |options| try executeStatusCommand(control_allocator, options),
        .print_config => |options| try executePrintConfigCommand(control_allocator, options),
        .routes => |options| try executeRoutesCommand(control_allocator, options),
        .upstreams => |options| try executeUpstreamsCommand(control_allocator, options),
        .reload => |options| try executeSignalCommand(control_allocator, "reload", std.posix.SIG.HUP, options),
        .stop => |options| try executeSignalCommand(control_allocator, "stop", std.posix.SIG.TERM, options),
        .check => |options| try executeValidationCommandOrExit(control_allocator, options, .check),
        .validate => |options| try executeValidationCommandOrExit(control_allocator, options, .legacy),
        .run => |options| {
            if (environmentRequestsValidate()) {
                try executeValidationCommandOrExit(control_allocator, options.common, .legacy);
                return;
            }
            try executeRunCommandOrExit(runtime_allocator.runtimeAllocator(), args, options);
        },
    }
}

fn parseCliCommand(args: []const []const u8) !CliCommand {
    if (args.len == 0) return .{ .run = .{} };

    const first = args[0];
    if (std.mem.eql(u8, first, "help") or std.mem.eql(u8, first, "-h") or std.mem.eql(u8, first, "--help")) {
        return .help;
    }
    if (std.mem.eql(u8, first, "version")) return .version;
    if (std.mem.eql(u8, first, "run")) return try parseRunCommand(args[1..]);
    if (std.mem.eql(u8, first, "check")) return try parseCheckCommand(args[1..]);
    if (std.mem.eql(u8, first, "validate")) return try parseValidateCommand(args[1..]);
    if (std.mem.eql(u8, first, "status")) return try parseSignalCommand(.status, args[1..]);
    if (std.mem.eql(u8, first, "print-config")) return try parsePrintConfigCommand(args[1..]);
    if (std.mem.eql(u8, first, "routes")) return if (try parseInspectOptions(args[1..])) |o| .{ .routes = o } else .help;
    if (std.mem.eql(u8, first, "upstreams")) return if (try parseInspectOptions(args[1..])) |o| .{ .upstreams = o } else .help;
    if (std.mem.eql(u8, first, "reload")) return try parseSignalCommand(.reload, args[1..]);
    if (std.mem.eql(u8, first, "stop")) return try parseSignalCommand(.stop, args[1..]);
    if (std.mem.eql(u8, first, "config")) {
        if (args.len >= 2 and std.mem.eql(u8, args[1], "init")) return try parseConfigInitCommand(args[2..]);
        if (args.len >= 2 and std.mem.eql(u8, args[1], "print")) return try parsePrintConfigCommand(args[2..]);
        if (args.len >= 2 and std.mem.eql(u8, args[1], "validate")) return try parseCheckCommand(args[2..]);
        return error.InvalidCommand;
    }

    return try parseRunCommand(args);
}

fn parseRunCommand(args: []const []const u8) !CliCommand {
    var options = RunOptions{};
    var validate_only = false;
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--validate-config")) {
            validate_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemon")) {
            options.daemon = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemonized")) {
            options.daemonized = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--worker")) continue;
        if (std.mem.eql(u8, arg, "--worker-id")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            idx += 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--worker-id=")) continue;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.common.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }

    if (validate_only) return .{ .validate = options.common };
    return .{ .run = options };
}

fn parseValidateCommand(args: []const []const u8) !CliCommand {
    var options = CommonOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--validate-config")) continue;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }
    return .{ .validate = options };
}

fn parseCheckCommand(args: []const []const u8) !CliCommand {
    var options = CommonOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (!std.mem.startsWith(u8, arg, "-")) {
            if (options.config_path != null) return error.TooManyArguments;
            options.config_path = arg;
            continue;
        }
        return error.UnknownOption;
    }
    return .{ .check = options };
}

fn parseSignalCommand(comptime kind: enum { reload, stop, status }, args: []const []const u8) !CliCommand {
    var options = SignalOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.common.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--pid-file")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.pid_file = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--pid")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.pid = try parsePid(args[idx + 1]);
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }

    return switch (kind) {
        .reload => .{ .reload = options },
        .stop => .{ .stop = options },
        .status => .{ .status = options },
    };
}

fn parsePrintConfigCommand(args: []const []const u8) !CliCommand {
    var options = CommonOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }
    return .{ .print_config = options };
}

/// Parse the `[-c <path>]` / `[-h]` options shared by the `routes` and
/// `upstreams` inspection commands. Returns null when help was requested.
fn parseInspectOptions(args: []const []const u8) !?CommonOptions {
    var options = CommonOptions{};
    var saw_positional = false;
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return null;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnknownOption;
        // Concise positional form, e.g. `routes ./tardigrade.conf` (like `check`).
        if (saw_positional or options.config_path != null) return error.TooManyArguments;
        options.config_path = arg;
        saw_positional = true;
    }
    return options;
}

fn parseConfigInitCommand(args: []const []const u8) !CliCommand {
    var options = ConfigInitOptions{};
    var saw_output = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--force")) {
            options.force = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--stdout")) {
            options.stdout = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnknownOption;
        if (saw_output) return error.TooManyArguments;
        options.output_path = arg;
        saw_output = true;
    }
    return .{ .config_init = options };
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  tardigrade check [<config>]
        \\  tardigrade run [-c <path>] [--daemon]
        \\  tardigrade validate [-c <path>]
        \\  tardigrade status [-c <path>] [--pid-file <path> | --pid <pid>]
        \\  tardigrade print-config [-c <path>]
        \\  tardigrade routes [<config>] [-c <path>]
        \\  tardigrade upstreams [<config>] [-c <path>]
        \\  tardigrade reload [-c <path>] [--pid-file <path> | --pid <pid>]
        \\  tardigrade stop [-c <path>] [--pid-file <path> | --pid <pid>]
        \\  tardigrade version
        \\  tardigrade config init [<path>] [--force | --stdout]
        \\  tardigrade config print [-c <path>]
        \\  tardigrade config validate [<config>]
        \\
        \\Notes:
        \\  - `check [<config>]` validates a config file without starting the server.
        \\    Accepts a positional config path or defaults to `./tardigrade.toml`.
        \\    `config validate [<config>]` is a verbose alias for the same command.
        \\  - Legacy `validate` and `--validate-config` remain supported.
        \\  - `status` reports process state when a pid target is available.
        \\  - `print-config` prints the effective operator-facing config summary.
        \\  - `routes` prints the resolved routing table (match type, pattern,
        \\    priority, action, auth) for the effective config.
        \\  - `upstreams` lists the upstream targets referenced by the routes plus
        \\    the default upstream base URL.
        \\  - Runtime config discovery checks `-c/--config`, `TARDIGRADE_CONFIG_PATH`,
        \\    `./tardigrade.conf`, `./config/tardigrade.conf`,
        \\    `/etc/tardigrade/tardigrade.conf`, and
        \\    `$HOME/.config/tardigrade/tardigrade.conf`.
        \\
    );
}

fn printCliParseError(writer: anytype, err: anyerror) !void {
    const msg = switch (err) {
        error.InvalidCommand => "error: unknown command\n",
        error.UnknownOption => "error: unknown option\n",
        error.MissingOptionValue => "error: missing option value\n",
        error.TooManyArguments => "error: too many positional arguments\n",
        else => "error: invalid command line\n",
    };
    try writer.writeAll(msg);
}

fn environmentRequestsValidate() bool {
    const env = compat.getEnvVarOwned(std.heap.page_allocator, "TARDIGRADE_VALIDATE_CONFIG_ONLY") catch return false;
    defer std.heap.page_allocator.free(env);
    return std.mem.eql(u8, env, "1") or std.ascii.eqlIgnoreCase(env, "true");
}

fn executeValidationCommandOrExit(allocator: std.mem.Allocator, options: CommonOptions, mode: ValidationMode) !void {
    executeValidateCommand(allocator, options, mode) catch |err| {
        var stderr_buf: [2048]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try printConfigCommandError(&stderr, err, options, mode);
        try stderr.flush();
        std.process.exit(configCommandExitCode(err));
    };
}

fn executeValidateCommand(allocator: std.mem.Allocator, options: CommonOptions, mode: ValidationMode) !void {
    const resolved_config_path = try resolveValidationConfigPath(allocator, options.config_path, mode);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    // Appliance TLS profile (#392): `check` performs the complete credential
    // preflight — exact PEM/PKCS#8 contract, chain parse, Ed25519 key parse,
    // leaf/key match, server-name policy, flight bounds, provider snapshot
    // construction and clean teardown — without binding any socket.
    if (edge_config.is_appliance_tls_profile and edge_config.hasTlsFiles(&cfg)) {
        try tls_core.appliance_credentials.validateFiles(
            allocator,
            cfg.tls_cert_path,
            cfg.tls_key_path,
            .{ .server_name = cfg.tls_server_name },
        );
    }
    edge_config.warnRiskyConfig(&cfg);
    var stdout_buf: [2048]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.writeAll("configuration valid\n");
    try writeConfigSummary(&stdout, resolved_config_path, &cfg);
    try stdout.flush();
}

fn printConfigCommandError(writer: anytype, err: anyerror, options: CommonOptions, mode: ValidationMode) !void {
    const target = validationTargetDescription(options, mode);
    switch (err) {
        error.ConfigPathNotFound => try writer.print("error: configuration parse failed: config file not found: {s}\n", .{target}),
        error.MissingConfigPath => try writer.writeAll("error: configuration parse failed: missing config path\n"),
        error.FileNotFound => try writer.print("error: configuration parse failed for {s}: referenced file not found\n", .{target}),
        error.InvalidConfigSyntax,
        error.InvalidIncludePattern,
        error.InvalidVariableInterpolation,
        => try writer.print("error: configuration parse failed for {s}; see the line-specific diagnostic above\n", .{target}),
        else => {
            if (isConfigValidationError(err)) {
                try writer.print("error: configuration validation failed for {s}: {}\n", .{ target, err });
            } else {
                try writer.print("error: unexpected internal error while checking configuration: {}\n", .{err});
            }
        },
    }
}

fn validationTargetDescription(options: CommonOptions, mode: ValidationMode) []const u8 {
    if (options.config_path) |path| return path;
    return switch (mode) {
        .check => CHECK_DEFAULT_CONFIG_PATH,
        .legacy => "<standard config search path>",
    };
}

fn configCommandExitCode(err: anyerror) u8 {
    if (isConfigValidationError(err)) return EXIT_CONFIG_INVALID;
    return EXIT_INTERNAL_ERROR;
}

fn isConfigValidationError(err: anyerror) bool {
    return switch (err) {
        error.ConfigPathNotFound,
        error.MissingConfigPath,
        error.FileNotFound,
        error.AccessDenied,
        error.InvalidConfigSyntax,
        error.InvalidIncludePattern,
        error.InvalidVariableInterpolation,
        error.InvalidConfigPort,
        error.InvalidConfigPath,
        error.InvalidConfigUrl,
        error.InvalidConfigEndpoint,
        error.InvalidConfigValue,
        error.InvalidConfigTlsVersion,
        error.InvalidServerBlockFormat,
        error.InvalidLocationBlockFormat,
        error.InvalidRewriteRuleFormat,
        error.InvalidRewriteRuleFlag,
        error.InvalidReturnRuleFormat,
        error.InvalidReturnRuleStatus,
        error.InvalidConditionalRuleFormat,
        error.InvalidConditionalVariable,
        error.InvalidInternalRedirectRuleFormat,
        error.InvalidNamedLocationFormat,
        error.InvalidMirrorRuleFormat,
        error.InvalidTlsSniCertFormat,
        error.InvalidUpstreamBaseUrlWeight,
        error.InvalidUpstreamBaseUrlWeightsCount,
        error.InvalidGeoCountryCode,
        error.InvalidAddHeaderFormat,
        error.InvalidFastcgiParamFormat,
        error.InvalidTokenHashLength,
        error.InvalidTokenHashHex,
        error.InvalidHealthStatusRange,
        error.InvalidHealthStatusOverride,
        // Appliance TLS credential preflight (#392): every class is an
        // operator-actionable configuration failure, not an internal error.
        error.MissingCertificateChain,
        error.MissingPrivateKey,
        error.CertificateFileTooLarge,
        error.PrivateKeyFileTooLarge,
        error.EmptyCertificateChain,
        error.TooManyCertificates,
        error.MalformedCertificatePem,
        error.AmbiguousCertificateInput,
        error.CertificateTooLarge,
        error.MalformedCertificateDer,
        error.MalformedPrivateKeyPem,
        error.AmbiguousPrivateKeyInput,
        error.MalformedPrivateKeyDer,
        error.UnsupportedPrivateKeyAlgorithm,
        error.UnsupportedPrivateKeyParameters,
        error.InvalidPrivateKeySize,
        error.InvalidPrivateKey,
        error.UnsupportedLeafKeyAlgorithm,
        error.KeyCertificateMismatch,
        error.CertificateFlightTooLarge,
        error.InvalidServerName,
        error.UnsupportedApplianceConfiguration,
        => true,
        else => false,
    };
}

/// Resolve the config path, load it from the environment, and validate it.
/// Returns an owned `EdgeConfig` (caller calls `deinit`). Shared by the
/// inspection commands.
fn loadValidatedConfig(allocator: std.mem.Allocator, options: CommonOptions) !edge_config.EdgeConfig {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);
    var cfg = try edge_config.loadFromEnv(allocator);
    errdefer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    return cfg;
}

/// Write the resolved routing table (one line per location block) to `writer`.
/// Pure over `location_blocks` so it is unit-testable without a full config.
fn writeRoutesSummary(writer: anytype, location_blocks: []const http.location_router.LocationBlock) !void {
    try writer.print("routes ({d})\n", .{location_blocks.len});
    for (location_blocks) |block| {
        try writer.print("  {s} {s}", .{ @tagName(block.match_type), block.pattern });
        if (block.priority > 0) try writer.print(" [priority {d}]", .{block.priority});
        try writer.writeAll(" -> ");
        switch (block.action) {
            .proxy_pass => |target| try writer.print("proxy_pass {s}", .{if (target.len > 0) target else "(upstream base url)"}),
            .fastcgi_pass => |target| try writer.print("fastcgi_pass {s}", .{target}),
            .return_response => |resp| try writer.print("return {d}", .{resp.status}),
            .rewrite => |rule| try writer.print("rewrite {s} ({s})", .{ rule.replacement, @tagName(rule.flag) }),
            .static_root => |root| try writer.print("static_root {s}", .{root.root}),
        }
        if (block.auth == .required) try writer.writeAll(" [auth: required]");
        try writer.writeAll("\n");
    }
}

/// Write the distinct upstream targets referenced by the routing table plus the
/// default upstream base URL. Pure over its inputs for unit testing.
fn writeUpstreamsSummary(writer: anytype, location_blocks: []const http.location_router.LocationBlock, upstream_base_url: []const u8) !void {
    try writer.writeAll("upstreams\n");
    if (upstream_base_url.len > 0) try writer.print("  base    {s}\n", .{upstream_base_url});
    for (location_blocks) |block| {
        switch (block.action) {
            .proxy_pass => |target| {
                if (target.len > 0) {
                    try writer.print("  proxy   {s} (route {s})\n", .{ target, block.pattern });
                } else if (upstream_base_url.len > 0) {
                    // A relative proxy_pass forwards to the default base URL;
                    // surface it so "which upstream does this route use?" is
                    // answerable from this command alone.
                    try writer.print("  proxy   {s} (route {s}, default base)\n", .{ upstream_base_url, block.pattern });
                }
            },
            .fastcgi_pass => |target| try writer.print("  fastcgi {s} (route {s})\n", .{ target, block.pattern }),
            else => {},
        }
    }
}

/// Compact upstream health-check + connection-pool configuration for the
/// `upstreams` command. Pure over its inputs for unit testing.
const UpstreamHealthInfo = struct {
    active_interval_ms: u64,
    active_path: []const u8,
    active_timeout_ms: u32,
    active_fail_threshold: u32,
    active_success_threshold: u32,
    passive_max_fails: u32,
    passive_fail_timeout_ms: u64,
    pool_enabled: bool,
    pool_max_idle_per_host: usize,
    pool_idle_timeout_ms: u64,
    pool_max_lifetime_ms: u64,
    pool_max_active_per_host: usize,
};

fn writeUpstreamHealthSummary(writer: anytype, info: UpstreamHealthInfo) !void {
    try writer.writeAll("health\n");
    if (info.active_interval_ms == 0) {
        try writer.writeAll("  active  disabled\n");
    } else {
        try writer.print("  active  path {s} interval {d}ms timeout {d}ms fail {d} success {d}\n", .{
            info.active_path,
            info.active_interval_ms,
            info.active_timeout_ms,
            info.active_fail_threshold,
            info.active_success_threshold,
        });
    }
    if (info.passive_max_fails == 0) {
        try writer.writeAll("  passive disabled\n");
    } else {
        try writer.print("  passive max_fails {d} fail_timeout {d}ms\n", .{ info.passive_max_fails, info.passive_fail_timeout_ms });
    }
    if (!info.pool_enabled) {
        try writer.writeAll("  pool    disabled\n");
    } else {
        try writer.print("  pool    max_idle_per_host {d} idle_timeout {d}ms max_lifetime {d}ms max_active_per_host {d}\n", .{
            info.pool_max_idle_per_host,
            info.pool_idle_timeout_ms,
            info.pool_max_lifetime_ms,
            info.pool_max_active_per_host,
        });
    }
}

test "writeRoutesSummary formats match type, action, priority and auth" {
    const blocks = [_]http.location_router.LocationBlock{
        .{ .match_type = .exact, .pattern = "/health", .priority = 0, .action = .{ .return_response = .{ .status = 200, .body = "ok" } } },
        .{ .match_type = .prefix_priority, .pattern = "/api/", .priority = 10, .action = .{ .proxy_pass = "http://backend:8080" }, .auth = .required },
    };
    var buf: [512]u8 = undefined;
    var fbs = compat.fixedBufferStream(&buf);
    try writeRoutesSummary(fbs.writer(), &blocks);
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "routes (2)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "exact /health -> return 200") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "prefix_priority /api/ [priority 10] -> proxy_pass http://backend:8080 [auth: required]") != null);
}

test "writeUpstreamsSummary lists base url and proxy/fastcgi targets" {
    const blocks = [_]http.location_router.LocationBlock{
        .{ .match_type = .prefix, .pattern = "/api/", .priority = 0, .action = .{ .proxy_pass = "http://backend:8080" } },
        .{ .match_type = .regex, .pattern = "\\.php$", .priority = 0, .action = .{ .fastcgi_pass = "unix:/run/php.sock" } },
        // Relative proxy_pass -> uses the default base URL.
        .{ .match_type = .prefix, .pattern = "/rel/", .priority = 0, .action = .{ .proxy_pass = "" } },
        .{ .match_type = .exact, .pattern = "/", .priority = 0, .action = .{ .return_response = .{ .status = 200, .body = "" } } },
    };
    var buf: [512]u8 = undefined;
    var fbs = compat.fixedBufferStream(&buf);
    try writeUpstreamsSummary(fbs.writer(), &blocks, "http://default:9000");
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "base    http://default:9000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "proxy   http://backend:8080 (route /api/)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "fastcgi unix:/run/php.sock") != null);
    // A relative proxy_pass is shown resolving to the default base.
    try std.testing.expect(std.mem.indexOf(u8, out, "proxy   http://default:9000 (route /rel/, default base)") != null);
    // return_response routes are not upstreams.
    try std.testing.expect(std.mem.indexOf(u8, out, "return") == null);
}

test "writeUpstreamHealthSummary shows active/passive/pool config and disabled states" {
    var buf: [512]u8 = undefined;
    {
        var fbs = compat.fixedBufferStream(&buf);
        try writeUpstreamHealthSummary(fbs.writer(), .{
            .active_interval_ms = 30000,
            .active_path = "/healthz",
            .active_timeout_ms = 2000,
            .active_fail_threshold = 3,
            .active_success_threshold = 2,
            .passive_max_fails = 3,
            .passive_fail_timeout_ms = 10000,
            .pool_enabled = true,
            .pool_max_idle_per_host = 32,
            .pool_idle_timeout_ms = 60000,
            .pool_max_lifetime_ms = 300000,
            .pool_max_active_per_host = 0,
        });
        const out = fbs.getWritten();
        try std.testing.expect(std.mem.indexOf(u8, out, "active  path /healthz interval 30000ms timeout 2000ms fail 3 success 2") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "passive max_fails 3 fail_timeout 10000ms") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "pool    max_idle_per_host 32") != null);
    }
    {
        var fbs = compat.fixedBufferStream(&buf);
        try writeUpstreamHealthSummary(fbs.writer(), std.mem.zeroInit(UpstreamHealthInfo, .{ .active_path = "" }));
        const out = fbs.getWritten();
        try std.testing.expect(std.mem.indexOf(u8, out, "active  disabled") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "passive disabled") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "pool    disabled") != null);
    }
}

fn executeRoutesCommand(allocator: std.mem.Allocator, options: CommonOptions) !void {
    var cfg = try loadValidatedConfig(allocator, options);
    defer cfg.deinit(allocator);
    var stdout_buf: [4096]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try writeRoutesSummary(&stdout, cfg.location_blocks);
    try stdout.flush();
}

fn executeUpstreamsCommand(allocator: std.mem.Allocator, options: CommonOptions) !void {
    var cfg = try loadValidatedConfig(allocator, options);
    defer cfg.deinit(allocator);
    var stdout_buf: [4096]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try writeUpstreamsSummary(&stdout, cfg.location_blocks, cfg.upstream_base_url);
    try writeUpstreamHealthSummary(&stdout, .{
        .active_interval_ms = cfg.upstream_active_health_interval_ms,
        .active_path = cfg.upstream_active_health_path,
        .active_timeout_ms = cfg.upstream_active_health_timeout_ms,
        .active_fail_threshold = cfg.upstream_active_health_fail_threshold,
        .active_success_threshold = cfg.upstream_active_health_success_threshold,
        .passive_max_fails = cfg.upstream_max_fails,
        .passive_fail_timeout_ms = cfg.upstream_fail_timeout_ms,
        .pool_enabled = cfg.upstream_pool_enabled,
        .pool_max_idle_per_host = cfg.upstream_pool_max_idle_per_host,
        .pool_idle_timeout_ms = cfg.upstream_pool_idle_timeout_ms,
        .pool_max_lifetime_ms = cfg.upstream_pool_max_lifetime_ms,
        .pool_max_active_per_host = cfg.upstream_pool_max_active_per_host,
    });
    try stdout.flush();
}

fn executePrintConfigCommand(allocator: std.mem.Allocator, options: CommonOptions) !void {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);

    var stdout_buf: [4096]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.writeAll("effective config\n");
    try writeConfigSummary(&stdout, resolved_config_path, &cfg);
    try stdout.flush();
}

fn executeStatusCommand(allocator: std.mem.Allocator, options: SignalOptions) !void {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.common.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);

    const pid_file_path = if (options.pid_file) |path| path else (cfg.pid_file);
    const pid = blk: {
        if (options.pid) |explicit_pid| break :blk explicit_pid;
        if (pid_file_path.len > 0 and pathExists(pid_file_path)) {
            break :blk try readPidFromFile(allocator, pid_file_path);
        }
        break :blk null;
    };
    const running = if (pid) |resolved_pid| try processExists(resolved_pid) else false;

    var stdout_buf: [4096]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.print("status: {s}\n", .{if (pid == null and pid_file_path.len == 0) "unknown" else if (running) "running" else "stopped"});
    if (pid) |resolved_pid| {
        try stdout.print("pid: {d}\n", .{resolved_pid});
    } else if (pid_file_path.len > 0) {
        try stdout.print("pid file: {s} (not present)\n", .{pid_file_path});
    } else {
        try stdout.writeAll("pid: unavailable\n");
        try stdout.writeAll("note: set `pid ...;` in config or pass `--pid` / `--pid-file` for process checks\n");
    }
    try writeConfigSummary(&stdout, resolved_config_path, &cfg);
    try stdout.flush();
}

/// Classify a `run` startup failure exactly like `tardi check` does — a
/// deterministic configuration error (including every
/// `appliance_credentials.Error` class the composition root can now
/// propagate unwrapped) reports the same message shape and
/// `EXIT_CONFIG_INVALID` exit code, rather than an opaque generic failure.
/// Post-startup errors (the server crashing after already accepting
/// connections) are comparatively rare in practice and still fall through to
/// the internal-error exit code with `@errorName`.
fn executeRunCommandOrExit(allocator: std.mem.Allocator, args: []const []const u8, options: RunOptions) !void {
    executeRunCommand(allocator, args, options) catch |err| {
        var stderr_buf: [2048]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try printConfigCommandError(&stderr, err, options.common, .legacy);
        try stderr.flush();
        std.process.exit(configCommandExitCode(err));
    };
}

fn executeRunCommand(allocator: std.mem.Allocator, args: []const []const u8, options: RunOptions) !void {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.common.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    const worker_mode = hasArg(args, "--worker");
    const worker_id = parseWorkerIdArg(args) orelse 0;

    if (options.daemon and !options.daemonized and !worker_mode) {
        try spawnDaemonizedProcess(allocator, resolved_config_path);
        return;
    }

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    edge_config.warnRiskyConfig(&cfg);
    try configureErrorLog(&cfg);
    try writePidFile(&cfg);
    defer removePidFile(&cfg);

    if (cfg.master_process_enabled and !worker_mode) {
        try runMaster(allocator, &cfg);
        return;
    }

    applyWorkerCpuAffinity(&cfg, worker_id) catch {}; // CPU affinity is optional; worker runs on any core if unavailable
    startWorkerRecycleTimer(&cfg);
    try edge_gateway.run(&cfg);
}

fn executeSignalCommand(
    allocator: std.mem.Allocator,
    label: []const u8,
    signal: std.posix.SIG,
    options: SignalOptions,
) !void {
    const pid = try resolveCommandPid(allocator, options);
    try std.posix.kill(pid, signal);
    var stdout_buf: [256]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.print("{s} signal sent to pid {d}\n", .{ label, pid });
    try stdout.flush();
}

fn writeConfigSummary(writer: anytype, resolved_config_path: ?[]const u8, cfg: *const edge_config.EdgeConfig) !void {
    try writer.print("config path: {s}\n", .{resolved_config_path orelse "<env/defaults only>"});
    try writer.print("listen: {s}:{d}\n", .{ cfg.listen_host, cfg.listen_port });
    try writer.print("tls: {s}\n", .{if (hasTlsConfig(cfg)) "enabled" else "disabled"});
    try writer.print("pid file: {s}\n", .{if (cfg.pid_file.len > 0) cfg.pid_file else "<disabled>"});
    try writer.print("doc root: {s}\n", .{if (cfg.doc_root.len > 0) cfg.doc_root else "<unset>"});
    try writer.print("server blocks: {d}\n", .{cfg.server_blocks.len});
    try writer.print("location blocks: {d}\n", .{countLocationBlocks(cfg)});
    try writer.print("upstream: {s}\n", .{if (cfg.upstream_base_url.len > 0) cfg.upstream_base_url else "<unset>"});
    try writer.print("metrics: {s}\n", .{if (cfg.metrics_path.len > 0) cfg.metrics_path else "<disabled>"});
    try writer.print("metrics auth: {s}\n", .{if (cfg.metrics_require_auth) "required" else "off"});
    try writer.print("workers: threads={d} processes={d} master={s} queue={d} per_worker_queue_depth={d}\n", .{
        cfg.worker_threads,
        cfg.worker_processes,
        if (cfg.master_process_enabled) "true" else "false",
        cfg.worker_queue_size,
        cfg.worker_max_queue_depth,
    });
    try writer.print("limits: active_connections={d} in_flight_requests={d} keep_alive_timeout_ms={d} request_total_timeout_ms={d} drain_timeout_ms={d}\n", .{
        cfg.max_active_connections,
        cfg.max_in_flight_requests,
        cfg.keep_alive_timeout_ms,
        cfg.request_total_timeout_ms,
        cfg.shutdown_drain_timeout_ms,
    });
    try writer.print("downstream_timeouts: tls_handshake_ms={d} header_ms={d} body_ms={d} write_ms={d}\n", .{
        cfg.tls_handshake_timeout_ms,
        cfg.request_limits.effectiveHeaderTimeout(),
        cfg.request_limits.effectiveBodyTimeout(),
        cfg.downstream_write_timeout_ms,
    });
    try writer.print("upstream_timeouts: attempt_ms={d} connect_ms={d} response_ms={d} budget_ms={d}\n", .{
        cfg.upstream_timeout_ms,
        cfg.upstream_connect_timeout_ms,
        cfg.upstream_response_timeout_ms,
        cfg.upstream_timeout_budget_ms,
    });
    try writer.print("protocols: http1={s} http2={s} http3={s} tls_http1_no_alpn_fallback={s}\n", .{
        if (cfg.http1_enabled) "on" else "off",
        if (cfg.http2_enabled) "on" else "off",
        if (cfg.http3_enabled) "on" else "off",
        if (cfg.tls_http1_no_alpn_fallback) "on" else "off",
    });
    try writer.print("rate limit rps: {d}\n", .{@as(i64, @intFromFloat(cfg.rate_limit_rps))});
}

fn countLocationBlocks(cfg: *const edge_config.EdgeConfig) usize {
    var total: usize = 0;
    for (cfg.server_blocks) |block| total += block.location_blocks.len;
    return total;
}

fn hasTlsConfig(cfg: *const edge_config.EdgeConfig) bool {
    return (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) or cfg.tls_sni_certs.len > 0 or cfg.tls_acme_enabled;
}

fn resolveCommandPid(allocator: std.mem.Allocator, options: SignalOptions) !std.posix.pid_t {
    if (options.pid) |pid| return pid;
    if (options.pid_file) |pid_file| return try readPidFromFile(allocator, pid_file);

    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.common.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    if (cfg.pid_file.len == 0) return error.MissingPidTarget;
    return try readPidFromFile(allocator, cfg.pid_file);
}

fn parsePid(value: []const u8) !std.posix.pid_t {
    const pid = try std.fmt.parseInt(std.posix.pid_t, value, 10);
    if (pid <= 0) return error.InvalidPid;
    return pid;
}

fn processExists(pid: std.posix.pid_t) !bool {
    const signal_zero: std.posix.SIG = @enumFromInt(0);
    std.posix.kill(pid, signal_zero) catch |err| switch (err) {
        error.PermissionDenied => return true,
        error.ProcessNotFound => return false,
        else => return err,
    };
    return true;
}

fn readPidFromFile(allocator: std.mem.Allocator, path: []const u8) !std.posix.pid_t {
    var file = try openFileAtPath(path, .{});
    defer file.close(compat.io());
    var file_buf: [256]u8 = undefined;
    var reader = file.reader(compat.io(), &file_buf);
    const raw = try reader.interface.allocRemaining(allocator, .limited(128));
    defer allocator.free(raw);
    return try parsePid(std.mem.trim(u8, raw, " \t\r\n"));
}

fn writeStarterConfig(options: ConfigInitOptions) !void {
    if (options.stdout) {
        var stdout_buf: [2048]u8 = undefined;
        var stdout = compat.stdoutWriter(&stdout_buf);
        try stdout.writeAll(starter_config);
        try stdout.flush();
        return;
    }

    if (!options.force and pathExists(options.output_path)) return error.PathAlreadyExists;
    try ensureParentPath(options.output_path);
    var file = try createFileAtPath(options.output_path, .{ .truncate = true, .read = false });
    defer file.close(compat.io());
    try file.writeStreamingAll(compat.io(), starter_config);
    var stdout_buf: [256]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.print("wrote starter config to {s}\n", .{options.output_path});
    try stdout.flush();
}

fn resolveValidationConfigPath(allocator: std.mem.Allocator, cli_path: ?[]const u8, mode: ValidationMode) !?[]u8 {
    if (cli_path) |path| return try requireConfigPath(allocator, path);
    return switch (mode) {
        .check => try requireConfigPath(allocator, CHECK_DEFAULT_CONFIG_PATH),
        .legacy => try resolveRuntimeConfigPath(allocator, null),
    };
}

fn resolveRuntimeConfigPath(allocator: std.mem.Allocator, cli_path: ?[]const u8) !?[]u8 {
    if (cli_path) |path| return try requireConfigPath(allocator, path);

    const env_path = compat.getEnvVarOwned(allocator, ENV_CONFIG_PATH) catch "";
    defer if (env_path.len > 0) allocator.free(env_path);
    if (env_path.len > 0) return try requireConfigPath(allocator, env_path);

    const search_paths = [_][]const u8{
        "tardigrade.conf",
        "config/tardigrade.conf",
        "/etc/tardigrade/tardigrade.conf",
    };
    for (search_paths) |candidate| {
        if (pathExists(candidate)) return try allocator.dupe(u8, candidate);
    }

    const home = compat.getEnvVarOwned(allocator, "HOME") catch "";
    defer if (home.len > 0) allocator.free(home);
    if (home.len > 0) {
        const home_candidate = try std.fmt.allocPrint(allocator, "{s}/.config/tardigrade/tardigrade.conf", .{home});
        defer allocator.free(home_candidate);
        if (pathExists(home_candidate)) return try allocator.dupe(u8, home_candidate);
    }

    return null;
}

fn requireConfigPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0) return error.MissingConfigPath;
    if (!pathExists(path)) return error.ConfigPathNotFound;
    return try allocator.dupe(u8, path);
}

fn setProcessEnv(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);
    if (setenv(name_z.ptr, value_z.ptr, 1) != 0) return error.SetEnvFailed;
}

fn spawnDaemonizedProcess(allocator: std.mem.Allocator, config_path: ?[]const u8) !void {
    const exe_path = try std.process.executablePathAlloc(compat.io(), allocator);
    defer allocator.free(exe_path);

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, exe_path);
    try argv.append(allocator, "run");
    if (config_path) |path| {
        try argv.append(allocator, "-c");
        try argv.append(allocator, path);
    }
    try argv.append(allocator, "--daemonized");

    const child = try std.process.spawn(compat.io(), .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    var stdout_buf: [256]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.print("started tardigrade in background (pid {d})\n", .{child.id.?});
    try stdout.flush();
}

fn pathExists(path: []const u8) bool {
    if (std.Io.Dir.path.isAbsolute(path)) {
        std.Io.Dir.accessAbsolute(compat.io(), path, .{}) catch return false;
        return true;
    }
    std.Io.Dir.cwd().access(compat.io(), path, .{}) catch return false;
    return true;
}

fn ensureParentPath(path: []const u8) !void {
    const parent = std.Io.Dir.path.dirname(path) orelse return;
    if (parent.len == 0 or std.mem.eql(u8, parent, ".")) return;
    if (std.Io.Dir.path.isAbsolute(parent)) {
        if (std.mem.eql(u8, parent, "/")) return;
        var root = try std.Io.Dir.openDirAbsolute(compat.io(), "/", .{});
        defer root.close(compat.io());
        try root.createDirPath(compat.io(), parent[1..]);
        return;
    }
    try std.Io.Dir.cwd().createDirPath(compat.io(), parent);
}

fn createFileAtPath(path: []const u8, flags: std.Io.Dir.CreateFileOptions) !std.Io.File {
    if (std.Io.Dir.path.isAbsolute(path)) return std.Io.Dir.createFileAbsolute(compat.io(), path, flags);
    return std.Io.Dir.cwd().createFile(compat.io(), path, flags);
}

fn openFileAtPath(path: []const u8, flags: std.Io.Dir.OpenFileOptions) !std.Io.File {
    if (std.Io.Dir.path.isAbsolute(path)) return std.Io.Dir.openFileAbsolute(compat.io(), path, flags);
    return std.Io.Dir.cwd().openFile(compat.io(), path, flags);
}

fn deleteFileAtPath(path: []const u8) !void {
    if (std.Io.Dir.path.isAbsolute(path)) return std.Io.Dir.deleteFileAbsolute(compat.io(), path);
    return std.Io.Dir.cwd().deleteFile(compat.io(), path);
}

fn openParentDirForPath(path: []const u8) !struct { dir: std.Io.Dir, basename: []const u8 } {
    const basename = std.Io.Dir.path.basename(path);
    const dirname = std.Io.Dir.path.dirname(path) orelse ".";
    const dir = if (std.Io.Dir.path.isAbsolute(path))
        try std.Io.Dir.openDirAbsolute(compat.io(), dirname, .{})
    else
        try std.Io.Dir.cwd().openDir(compat.io(), dirname, .{});
    return .{ .dir = dir, .basename = basename };
}

fn configureErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    const rotate_max_bytes = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_BYTES", 0);
    const rotate_max_files = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_FILES", 5);
    if (rotate_max_bytes > 0) {
        const stat = blk: {
            var existing = openFileAtPath(cfg.error_log_path, .{}) catch break :blk null;
            defer existing.close(compat.io());
            break :blk existing.stat(compat.io()) catch null;
        };
        if (stat != null and stat.?.size >= rotate_max_bytes) {
            var dir_info = try openParentDirForPath(cfg.error_log_path);
            defer dir_info.dir.close(compat.io());
            try rotateLogFiles(dir_info.dir, dir_info.basename, rotate_max_files);
        }
    }
    try ensureParentPath(cfg.error_log_path);
    var file = try createFileAtPath(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close(compat.io());
    _ = std.c.lseek(file.handle, 0, std.c.SEEK.END);
    _ = std.c.dup2(file.handle, std.Io.File.stderr().handle);
}

fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    try ensureParentPath(cfg.error_log_path);
    var file = try createFileAtPath(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close(compat.io());
    _ = std.c.lseek(file.handle, 0, std.c.SEEK.END);
    _ = std.c.dup2(file.handle, std.Io.File.stderr().handle);
}

fn parseIntEnv(comptime T: type, key: []const u8, default: T) T {
    const raw = compat.getEnvVarOwned(std.heap.page_allocator, key) catch return default;
    defer std.heap.page_allocator.free(raw);
    return std.fmt.parseInt(T, std.mem.trim(u8, raw, " \t\r\n"), 10) catch default;
}

fn rotateLogFiles(dir: std.Io.Dir, path: []const u8, max_files: usize) !void {
    if (max_files == 0) {
        dir.deleteFile(compat.io(), path) catch {}; // best-effort delete; max_files=0 discards the log regardless
        return;
    }
    const oldest = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, max_files });
    defer std.heap.page_allocator.free(oldest);
    dir.deleteFile(compat.io(), oldest) catch {}; // best-effort delete; oldest rotation slot may not exist yet

    var idx = max_files;
    while (idx > 1) : (idx -= 1) {
        const src = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, idx - 1 });
        defer std.heap.page_allocator.free(src);
        const dst = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, idx });
        defer std.heap.page_allocator.free(dst);
        dir.rename(src, dir, dst, compat.io()) catch {}; // best-effort rename; rotation continues even if a slot is missing
    }
    const first = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.1", .{path});
    defer std.heap.page_allocator.free(first);
    try dir.rename(path, dir, first, compat.io());
}

fn writePidFile(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.pid_file.len == 0) return;
    try ensureParentPath(cfg.pid_file);
    var file = try createFileAtPath(cfg.pid_file, .{ .truncate = true, .read = false });
    defer file.close(compat.io());
    var pid_buf: [32]u8 = undefined;
    var writer = file.writerStreaming(compat.io(), &pid_buf);
    try writer.interface.print("{d}\n", .{std.c.getpid()});
    try writer.flush();
}

fn removePidFile(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.pid_file.len == 0) return;
    deleteFileAtPath(cfg.pid_file) catch {}; // best-effort cleanup; stale pid file is harmless after process exit
}

fn hasArg(args: []const []const u8, target: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, target)) return true;
    }
    return false;
}

fn parseWorkerIdArg(args: []const []const u8) ?usize {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--worker-id") and i + 1 < args.len) {
            return std.fmt.parseInt(usize, args[i + 1], 10) catch 0;
        }
        if (std.mem.startsWith(u8, args[i], "--worker-id=")) {
            return std.fmt.parseInt(usize, args[i]["--worker-id=".len..], 10) catch 0;
        }
    }
    return null;
}

fn startWorkerRecycleTimer(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.worker_recycle_seconds == 0) return;
    const secs = cfg.worker_recycle_seconds;
    _ = std.Thread.spawn(.{}, struct {
        fn run(wait_secs: u32) void {
            const compat2 = @import("zig_compat.zig");
            std.Io.sleep(compat2.io(), std.Io.Duration.fromSeconds(@intCast(wait_secs)), .awake) catch {}; // interrupt wakes are fine; recycle fires immediately on wake
            http.shutdown.requestShutdown();
        }
    }.run, .{secs}) catch {}; // best-effort; worker continues without auto-recycle if thread spawn fails
}

fn runMaster(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !void {
    http.shutdown.installSignalHandlers();
    const exe_path = try std.process.executablePathAlloc(compat.io(), allocator);
    defer allocator.free(exe_path);
    const worker_count: usize = if (cfg.worker_processes == 0)
        (std.Thread.getCpuCount() catch 1)
    else
        @as(usize, @intCast(@max(cfg.worker_processes, 1)));
    var children = try allocator.alloc(std.process.Child, worker_count);
    defer allocator.free(children);

    for (0..worker_count) |i| {
        children[i] = try spawnWorker(allocator, exe_path, i);
    }

    while (!http.shutdown.isShutdownRequested()) {
        if (cfg.binary_upgrade_enabled and http.shutdown.consumeUpgradeRequested()) {
            _ = try spawnMasterUpgrade(exe_path);
            http.shutdown.requestShutdown();
            break;
        }
        if (http.shutdown.consumeReopenLogsRequested()) {
            reopenErrorLog(cfg) catch {}; // best-effort SIGHUP handler; stderr continues on the previous fd
        }

        for (0..worker_count) |i| {
            const pid = children[i].id orelse continue;
            const wait_pid = std.c.waitpid(pid, null, std.c.W.NOHANG);
            if (wait_pid == pid and !http.shutdown.isShutdownRequested()) {
                children[i] = try spawnWorker(allocator, exe_path, i);
            }
        }
        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(250), .awake) catch {}; // interrupt wakes are fine; master poll loop continues
    }

    for (0..worker_count) |i| {
        children[i].kill(compat.io());
        _ = children[i].wait(compat.io()) catch {}; // best-effort wait; process may have already exited
    }
}

fn spawnWorker(allocator: std.mem.Allocator, exe_path: []const u8, worker_id: usize) !std.process.Child {
    const id_str = try std.fmt.allocPrint(allocator, "{d}", .{worker_id});
    defer allocator.free(id_str);
    const argv = [_][]const u8{ exe_path, "--worker", "--worker-id", id_str };
    return try std.process.spawn(compat.io(), .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
}

fn spawnMasterUpgrade(exe_path: []const u8) !std.process.Child {
    const argv = [_][]const u8{exe_path};
    return try std.process.spawn(compat.io(), .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
}

fn applyWorkerCpuAffinity(cfg: *const edge_config.EdgeConfig, worker_id: usize) !void {
    if (cfg.worker_cpu_affinity.len == 0) return;
    if (@import("builtin").os.tag != .linux) return;
    var cpus_buf: [64]u32 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, cfg.worker_cpu_affinity, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (count >= cpus_buf.len) break;
        cpus_buf[count] = std.fmt.parseInt(u32, trimmed, 10) catch continue;
        count += 1;
    }
    if (count == 0) return;
    const cpu = cpus_buf[worker_id % count];
    try setLinuxCpuAffinity(cpu);
}

fn setLinuxCpuAffinity(cpu: u32) !void {
    if (@import("builtin").os.tag != .linux) {
        return error.CpuAffinityUnsupported;
    }
    const linux = struct {
        const cpu_set_bits = 1024;
        const CpuMaskWord = usize;
        const word_bits = @bitSizeOf(CpuMaskWord);
        const word_count = cpu_set_bits / word_bits;

        const CpuSet = extern struct {
            bits: [word_count]CpuMaskWord = [_]CpuMaskWord{0} ** word_count,
        };

        extern "c" fn getpid() std.c.pid_t;
        extern "c" fn sched_setaffinity(pid: std.c.pid_t, cpusetsize: usize, mask: *const CpuSet) c_int;
    };
    if (cpu >= linux.cpu_set_bits) {
        return error.CpuAffinityUnsupported;
    }
    var mask = linux.CpuSet{};
    const word_index: usize = @intCast(cpu / linux.word_bits);
    const bit_index = cpu % linux.word_bits;
    mask.bits[word_index] |= @as(linux.CpuMaskWord, 1) << @intCast(bit_index);
    if (linux.sched_setaffinity(linux.getpid(), @sizeOf(linux.CpuSet), &mask) != 0) {
        return error.CpuAffinityFailed;
    }
}

test {
    _ = @import("http.zig");
    _ = @import("edge_config.zig");
    _ = @import("edge_gateway.zig");
    _ = @import("gateway_protocol_policy.zig");
}

test "rotateLogFiles shifts generations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "error.log", .data = "latest" });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "error.log.1", .data = "older" });

    try rotateLogFiles(tmp.dir, "error.log", 3);

    _ = try tmp.dir.statFile(compat.io(), "error.log.1", .{});
    _ = try tmp.dir.statFile(compat.io(), "error.log.2", .{});
}

test "rotateLogFiles deletes source when max_files is zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "error.log", .data = "latest" });
    try rotateLogFiles(tmp.dir, "error.log", 0);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(compat.io(), "error.log", .{}));
}

test "parse run command supports legacy validate flag" {
    const cmd = try parseCliCommand(&.{ "--validate-config", "-c", "tardigrade.conf" });
    switch (cmd) {
        .validate => |options| try std.testing.expectEqualStrings("tardigrade.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parse config init command supports stdout" {
    const cmd = try parseCliCommand(&.{ "config", "init", "--stdout" });
    switch (cmd) {
        .config_init => |options| try std.testing.expect(options.stdout),
        else => return error.TestUnexpectedResult,
    }
}

test "parsePid accepts valid positive pid" {
    try std.testing.expectEqual(@as(std.posix.pid_t, 1234), try parsePid("1234"));
    try std.testing.expectEqual(@as(std.posix.pid_t, 1), try parsePid("1"));
}

test "parsePid rejects zero and negative pids" {
    try std.testing.expectError(error.InvalidPid, parsePid("0"));
    try std.testing.expectError(error.InvalidPid, parsePid("-5"));
}

test "parsePid rejects non-numeric input" {
    try std.testing.expectError(error.InvalidCharacter, parsePid("abc"));
    try std.testing.expectError(error.InvalidCharacter, parsePid("12px"));
}

test "readPidFromFile reads pid written to a temp file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a PID to a file using the compat dir wrapper
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "tardigrade.pid", .data = "42\n" });

    // Resolve absolute path so openFileAtPath can find it
    const abs = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, "tardigrade.pid");
    defer std.testing.allocator.free(abs);

    const pid = try readPidFromFile(std.testing.allocator, abs);
    try std.testing.expectEqual(@as(std.posix.pid_t, 42), pid);
}

test "rotateLogFiles preserves content in generation .1" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "app.log", .data = "current entry" });

    try rotateLogFiles(tmp.dir, "app.log", 2);

    const rotated = try compat.wrapDir(tmp.dir).readFileAlloc(std.testing.allocator, "app.log.1", 1024);
    defer std.testing.allocator.free(rotated);
    try std.testing.expectEqualStrings("current entry", rotated);
}

test "rotateLogFiles with max_files=1 evicts oldest generation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "app.log", .data = "new" });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "app.log.1", .data = "old" });

    try rotateLogFiles(tmp.dir, "app.log", 1);

    // .1 is replaced with the original log; old .1 is deleted
    const rotated = try compat.wrapDir(tmp.dir).readFileAlloc(std.testing.allocator, "app.log.1", 1024);
    defer std.testing.allocator.free(rotated);
    try std.testing.expectEqualStrings("new", rotated);
    // There must be no .2 file (max_files=1 means only one backup)
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(compat.io(), "app.log.2", .{}));
}

test "parseCliCommand default (no args) returns run command" {
    const cmd = try parseCliCommand(&.{});
    switch (cmd) {
        .run => {},
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand help flags" {
    for (&[_][]const u8{ "help", "-h", "--help" }) |flag| {
        const cmd = try parseCliCommand(&.{flag});
        try std.testing.expectEqual(CliCommand.help, cmd);
    }
}

test "parseCliCommand version" {
    const cmd = try parseCliCommand(&.{"version"});
    try std.testing.expectEqual(CliCommand.version, cmd);
}

test "parseCliCommand reload requires pid file option" {
    const cmd = try parseCliCommand(&.{ "reload", "--pid-file", "tardigrade.pid" });
    switch (cmd) {
        .reload => |s| try std.testing.expectEqualStrings("tardigrade.pid", s.pid_file.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand stop requires pid file option" {
    const cmd = try parseCliCommand(&.{ "stop", "--pid-file", "tardigrade.pid" });
    switch (cmd) {
        .stop => {},
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand status supports pid file option" {
    const cmd = try parseCliCommand(&.{ "status", "--pid-file", "tardigrade.pid" });
    switch (cmd) {
        .status => |s| try std.testing.expectEqualStrings("tardigrade.pid", s.pid_file.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand print-config supports config path" {
    const cmd = try parseCliCommand(&.{ "print-config", "-c", "tardigrade.conf" });
    switch (cmd) {
        .print_config => |options| try std.testing.expectEqualStrings("tardigrade.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand config print alias supports config path" {
    const cmd = try parseCliCommand(&.{ "config", "print", "--config", "tardigrade.conf" });
    switch (cmd) {
        .print_config => |options| try std.testing.expectEqualStrings("tardigrade.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "writeStarterConfig writes config content to absolute path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);
    const out_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/out.conf", .{abs});
    defer std.testing.allocator.free(out_path);

    try writeStarterConfig(.{ .output_path = out_path, .stdout = false });

    const written = try compat.wrapDir(tmp.dir).readFileAlloc(std.testing.allocator, "out.conf", 4096);
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.find(u8, written, "listen 8069") != null);
    try std.testing.expect(std.mem.find(u8, written, "pid /var/run/tardigrade.pid") != null);
}

test "writeStarterConfig returns error if file exists and force is false" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "out.conf", .data = "existing" });
    const abs = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);
    const out_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/out.conf", .{abs});
    defer std.testing.allocator.free(out_path);

    try std.testing.expectError(error.PathAlreadyExists, writeStarterConfig(.{ .output_path = out_path, .stdout = false }));
}

test "parseCliCommand check with no args returns check" {
    const cmd = try parseCliCommand(&.{"check"});
    switch (cmd) {
        .check => |options| try std.testing.expectEqual(@as(?[]const u8, null), options.config_path),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand check with positional config path" {
    const cmd = try parseCliCommand(&.{ "check", "my.conf" });
    switch (cmd) {
        .check => |options| try std.testing.expectEqualStrings("my.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand check with -c flag" {
    const cmd = try parseCliCommand(&.{ "check", "-c", "my.conf" });
    switch (cmd) {
        .check => |options| try std.testing.expectEqualStrings("my.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand check rejects multiple positional args" {
    try std.testing.expectError(error.TooManyArguments, parseCliCommand(&.{ "check", "a.conf", "b.conf" }));
}

test "parseCliCommand config validate with no args returns check" {
    const cmd = try parseCliCommand(&.{ "config", "validate" });
    switch (cmd) {
        .check => |options| try std.testing.expectEqual(@as(?[]const u8, null), options.config_path),
        else => return error.TestUnexpectedResult,
    }
}

test "parseCliCommand config validate with positional config path" {
    const cmd = try parseCliCommand(&.{ "config", "validate", "tardigrade.conf" });
    switch (cmd) {
        .check => |options| try std.testing.expectEqualStrings("tardigrade.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "check command default path is tardigrade.toml" {
    try std.testing.expectEqualStrings(CHECK_DEFAULT_CONFIG_PATH, validationTargetDescription(.{}, .check));
}

test "config command invalid input exits with config error code" {
    try std.testing.expectEqual(EXIT_CONFIG_INVALID, configCommandExitCode(error.InvalidConfigSyntax));
    try std.testing.expectEqual(EXIT_INTERNAL_ERROR, configCommandExitCode(error.OutOfMemory));
}
