//! Static reference metadata for the `tardi explain <field>` command (#163).
//!
//! This module is deliberately independent of `edge_config.zig` /
//! `http/config_file.zig` at runtime: it does not parse or load a config
//! file, inspect a running process, or read environment values. It only
//! describes the supported configuration surface so `explain` stays a fast,
//! deterministic, configuration-independent reference lookup as required by
//! #163 -- distinct from `print-config`, which reports the *effective*
//! configuration.

const std = @import("std");

pub const Context = enum {
    top_level,
    server,
    location,
    environment,

    fn label(self: Context) []const u8 {
        return switch (self) {
            .top_level => "top-level",
            .server => "server",
            .location => "location",
            .environment => "environment",
        };
    }
};

/// A compatibility spelling for one accepted value of an enum-typed entry,
/// e.g. `.{ .alias = "h1", .canonical = "http1" }` for `upstream_protocol`.
pub const ValueAlias = struct {
    alias: []const u8,
    canonical: []const u8,
};

pub const ConfigEntry = struct {
    name: []const u8,
    /// Short/legacy spellings that resolve to this entry, e.g. `proxy_pass`
    /// resolving to `location.proxy_pass`.
    aliases: []const []const u8 = &.{},
    contexts: []const Context,
    value_type: []const u8,
    default_value: ?[]const u8 = null,
    valid_values: []const []const u8 = &.{},
    value_aliases: []const ValueAlias = &.{},
    description: []const u8,
    example: ?[]const u8 = null,
    docs: []const []const u8 = &.{},
    /// Current/preferred environment variable name(s).
    env_vars: []const []const u8 = &.{},
    /// Deprecated-but-still-accepted environment variable name(s).
    legacy_env_vars: []const []const u8 = &.{},
};

const CTX_TOP = &[_]Context{.top_level};
const CTX_SERVER = &[_]Context{.server};
const CTX_LOCATION = &[_]Context{.location};
const CTX_TOP_SERVER = &[_]Context{ .top_level, .server };
const CTX_TOP_LOCATION = &[_]Context{ .top_level, .location };
const CTX_TOP_SERVER_LOCATION = &[_]Context{ .top_level, .server, .location };

pub const entries = [_]ConfigEntry{
    // ---- Core / process ------------------------------------------------
    .{
        .name = "worker_processes",
        .contexts = CTX_TOP,
        .value_type = "integer or \"auto\"",
        .default_value = "1",
        .valid_values = &.{ "0 or auto = autodetect CPU count", ">= 1 = explicit worker-process count" },
        .description = "Number of worker processes used by master-process supervision. `0` and `auto` both autodetect the CPU count.",
        .example = "worker_processes auto;",
        .env_vars = &.{"TARDIGRADE_WORKER_PROCESSES"},
        .docs = &.{"docs/CONCURRENCY.md"},
    },
    .{
        .name = "worker_connections",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (unlimited)",
        .valid_values = &.{">= 0"},
        .description = "nginx-style alias for the total active-connection cap; maps to the same underlying limit as max_active_connections.",
        .example = "worker_connections 1024;",
        .env_vars = &.{"TARDIGRADE_MAX_ACTIVE_CONNECTIONS"},
        .docs = &.{"docs/CONCURRENCY.md"},
    },
    .{
        .name = "pid",
        .contexts = CTX_TOP,
        .value_type = "path",
        .default_value = "none (no pid file written)",
        .description = "Path to write the running process's pid file, used by status/reload/stop.",
        .example = "pid /var/run/tardigrade.pid;",
        .env_vars = &.{"TARDIGRADE_PID_FILE"},
    },
    .{
        .name = "user",
        .contexts = CTX_TOP,
        .value_type = "string [group]",
        .default_value = "none (no privilege drop)",
        .description = "Target OS user (and optional group) to drop privileges to after binding listeners.",
        .example = "user www-data www-data;",
        .env_vars = &.{ "TARDIGRADE_RUN_USER", "TARDIGRADE_RUN_GROUP" },
    },
    .{
        .name = "error_log",
        .contexts = CTX_TOP,
        .value_type = "path [level]",
        .default_value = "stderr, level info",
        .valid_values = &.{ "debug", "info", "warn", "error" },
        .description = "Sets the error log destination and, optionally, the minimum log level in one directive.",
        .example = "error_log /var/log/tardigrade/error.log warn;",
        .env_vars = &.{ "TARDIGRADE_ERROR_LOG_PATH", "TARDIGRADE_LOG_LEVEL" },
        .docs = &.{"docs/OBSERVABILITY.md"},
    },
    .{
        .name = "include",
        .contexts = CTX_TOP,
        .value_type = "path or single-`*` suffix glob",
        .description = "Recursively parses and merges another config file, or files matched by the supported single-`*` suffix form such as `conf.d/*.conf`. General glob patterns such as `foo*.conf` are not supported.",
        .example = "include conf.d/*.conf;",
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "set",
        .contexts = CTX_TOP,
        .value_type = "$name value",
        .description = "Declares a config-parse-time variable substitutable via ${name} in later directive values.",
        .example = "set $backend 127.0.0.1:3000;\nlocation /api/ {\n    proxy_pass http://${backend};\n}",
        .docs = &.{"docs/CONFIGURATION.md"},
    },

    // ---- Listener / basic serving ---------------------------------------
    .{
        .name = "listen",
        .contexts = CTX_TOP,
        .value_type = "host[:port] | port [http2]",
        .default_value = "0.0.0.0:8069",
        .valid_values = &.{"port: 1-65535"},
        .description = "Sets the downstream address and/or port Tardigrade accepts connections on. A bare host (no colon, not a number) sets only the host, leaving the port at its other source/default; a trailing `http2` flag force-enables HTTP/2.",
        .example = "listen 8069;",
        .env_vars = &.{ "TARDIGRADE_LISTEN_HOST", "TARDIGRADE_LISTEN_PORT" },
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "server_name",
        .aliases = &.{"server.server_name"},
        .contexts = CTX_TOP_SERVER,
        .value_type = "hostname list",
        .default_value = "none (accepts any Host header)",
        .description = "Accepted Host header pattern(s) used for virtual-host matching.",
        .example = "server_name example.com www.example.com;",
        .env_vars = &.{"TARDIGRADE_SERVER_NAMES"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "root",
        .aliases = &.{ "location.root", "server.root" },
        .contexts = CTX_TOP_SERVER_LOCATION,
        .value_type = "path",
        .default_value = "none",
        .description = "Document root used for static file serving and try_files resolution.",
        .example = "root ./public;",
        .env_vars = &.{"TARDIGRADE_DOC_ROOT"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "try_files",
        .aliases = &.{ "location.try_files", "server.try_files" },
        .contexts = CTX_TOP_SERVER_LOCATION,
        .value_type = "space-separated candidate list",
        .default_value = "none",
        .description = "Ordered fallback list for serving static files, e.g. SPA-style index fallback.",
        .example = "try_files $uri /index.html;",
        .env_vars = &.{"TARDIGRADE_TRY_FILES"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },

    // ---- Server blocks ---------------------------------------------------
    .{
        .name = "server",
        .contexts = CTX_TOP,
        .value_type = "block",
        .description = "Defines a virtual-host scope with its own server_name, root, try_files, TLS credentials, upstream_base_url, and nested location {} blocks.",
        .example = "server {\n    server_name a.example.com;\n    root /srv/a;\n}",
        .env_vars = &.{"TARDIGRADE_SERVER_BLOCKS"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "server.tls_cert_path",
        .contexts = CTX_SERVER,
        .value_type = "path",
        .default_value = "none",
        .description = "Per-virtual-host TLS certificate path, used for SNI certificate selection inside a server {} block. Rejected outright by the appliance TLS profile, which supports exactly one TLS identity configured directly at the top level.",
        .example = "server {\n    tls_cert_path /etc/tls/a.pem;\n    tls_key_path /etc/tls/a.key;\n}",
        .docs = &.{"docs/BARE_APPLIANCE_TLS.md"},
    },
    .{
        .name = "server.tls_key_path",
        .contexts = CTX_SERVER,
        .value_type = "path",
        .default_value = "none",
        .description = "Per-virtual-host TLS private key path, paired with server.tls_cert_path. Rejected outright by the appliance TLS profile, which supports exactly one TLS identity configured directly at the top level.",
        .example = "server {\n    tls_cert_path /etc/tls/a.pem;\n    tls_key_path /etc/tls/a.key;\n}",
    },
    .{
        .name = "server.upstream_base_url",
        .contexts = CTX_SERVER,
        .value_type = "URL",
        .default_value = "none",
        .description = "Per-virtual-host upstream base URL override, used instead of the top-level upstream_base_url for requests matching this server block.",
        .example = "server {\n    upstream_base_url http://10.0.0.5:8080;\n}",
    },

    // ---- Routing / location ----------------------------------------------
    .{
        .name = "location",
        .contexts = CTX_TOP_SERVER,
        .value_type = "block",
        .description = "Route-matching block. Choose exactly one action family: proxy_pass, FastCGI/SCGI/uWSGI, return, rewrite, or static. Static locations may freely combine root/alias/index/autoindex/try_files with each other; modifiers such as error_page, auth, proxy_streaming, and early-data policy may coexist with any action family where applicable.",
        .example =
        \\location /path/ { ... }        # prefix match
        \\location = /exact { ... }      # exact match
        \\location ^~ /priority/ { ... } # priority prefix match
        \\location ~ <regex> { ... }     # regex match
        \\location ~* <regex> { ... }    # case-insensitive regex match
        ,
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "location.proxy_pass",
        .aliases = &.{"proxy_pass"},
        .contexts = CTX_LOCATION,
        .value_type = "URL or path",
        .default_value = "none",
        .description = "Proxies requests matching a location to an upstream URL.",
        .example = "location /api/ {\n    proxy_pass http://127.0.0.1:8080;\n}",
        .docs = &.{ "examples/reverse-proxy/README.md", "docs/PROXY_STREAMING.md" },
    },
    .{
        .name = "location.alias",
        .aliases = &.{"alias"},
        .contexts = CTX_LOCATION,
        .value_type = "path",
        .default_value = "none",
        .description = "Replaces the matched location prefix with this path instead of appending it (nginx alias semantics); takes precedence over `root` when both are set.",
        .example = "location /img/ {\n    alias /data/images/;\n}",
    },
    .{
        .name = "location.index",
        .aliases = &.{"index"},
        .contexts = CTX_LOCATION,
        .value_type = "filename",
        .default_value = "index.html",
        .description = "Directory index filename used when a static request resolves to a directory.",
        .example = "location / {\n    root ./public;\n    index index.htm;\n}",
    },
    .{
        .name = "location.autoindex",
        .aliases = &.{"autoindex"},
        .contexts = CTX_LOCATION,
        .value_type = "boolean",
        .default_value = "off",
        .valid_values = &.{ "on", "off" },
        .value_aliases = &.{
            .{ .alias = "true", .canonical = "on" },
            .{ .alias = "false", .canonical = "off" },
        },
        .description = "Enables directory listing generation when no index file is found.",
        .example = "location /files/ {\n    autoindex on;\n}",
    },
    .{
        .name = "location.return",
        .aliases = &.{"return"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "status [body]",
        .default_value = "none",
        .description = "Immediately returns a fixed status code and optional body. At top level it is encoded into a global rule list (TARDIGRADE_RETURN_RULES); inside a location it applies only to the matched route.",
        .example = "location = /health {\n    return 200 ok;\n}",
        .env_vars = &.{"TARDIGRADE_RETURN_RULES"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "location.rewrite",
        .aliases = &.{"rewrite"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "pattern replacement [flag]",
        .default_value = "flag: last",
        .valid_values = &.{"flags: last, break, redirect, permanent"},
        .description = "Rewrites the request URI according to pattern/replacement before continuing dispatch. At top level it is encoded into a global rule list (TARDIGRADE_REWRITE_RULES); inside a location it applies only to the matched route.",
        .example = "location /old/ {\n    rewrite ^/old/(.*)$ /new/$1 last;\n}",
        .env_vars = &.{"TARDIGRADE_REWRITE_RULES"},
    },
    .{
        .name = "location.error_page",
        .aliases = &.{"error_page"},
        .contexts = CTX_LOCATION,
        .value_type = "status [status ...] target",
        .default_value = "none (repeatable)",
        .description = "Maps one or more whitespace-separated status codes to a custom error response target for this location. Target must start with `/`, `http://`, or `https://`.",
        .example = "location / {\n    error_page 404 502 503 /error.html;\n}",
    },
    .{
        .name = "location.auth",
        .aliases = &.{"auth"},
        .contexts = CTX_LOCATION,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "required", "off" },
        .description = "Requires authentication for requests matching this location.",
        .example = "location /admin/ {\n    auth required;\n}",
    },
    .{
        .name = "proxy_streaming_mode",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "response", "full" },
        .value_aliases = &.{
            .{ .alias = "buffered", .canonical = "off" },
            .{ .alias = "responses", .canonical = "response" },
            .{ .alias = "request_response", .canonical = "full" },
            .{ .alias = "request-response", .canonical = "full" },
        },
        .description = "Global proxy streaming policy (off = fully buffered, response = stream response only, full = stream both directions). Overridable per-location via proxy_streaming.",
        .example = "proxy_streaming_mode response;",
        .env_vars = &.{"TARDIGRADE_PROXY_STREAMING_MODE"},
        .docs = &.{"docs/PROXY_STREAMING.md"},
    },
    .{
        .name = "location.proxy_streaming",
        .aliases = &.{ "proxy_streaming", "location.proxy_streaming_mode" },
        .contexts = CTX_LOCATION,
        .value_type = "enum",
        .default_value = "inherit (uses the global proxy_streaming_mode)",
        .valid_values = &.{ "inherit", "off", "response", "full" },
        .value_aliases = &.{
            .{ .alias = "buffered", .canonical = "off" },
            .{ .alias = "responses", .canonical = "response" },
            .{ .alias = "request_response", .canonical = "full" },
            .{ .alias = "request-response", .canonical = "full" },
        },
        .description = "Per-location override of the global proxy_streaming_mode policy (off = fully buffered, response = stream response only, full = stream both directions).",
        .example = "location /upload/ {\n    proxy_pass http://up;\n    proxy_streaming full;\n}",
        .docs = &.{"docs/PROXY_STREAMING.md"},
    },
    .{
        .name = "location.early_data",
        .aliases = &.{"early_data"},
        .contexts = CTX_LOCATION,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "replay_safe" },
        .value_aliases = &.{
            .{ .alias = "replay-safe", .canonical = "replay_safe" },
        },
        .description = "Marks whether TLS 0-RTT early data may reach this location; only safe for idempotent/replay-safe endpoints.",
        .example = "location /webhook/ {\n    early_data replay_safe;\n}",
        .docs = &.{"docs/QUIC_TLS.md"},
    },
    .{
        .name = "location.proxy_early_data",
        .aliases = &.{"proxy_early_data"},
        .contexts = CTX_LOCATION,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "rfc8470" },
        .value_aliases = &.{
            .{ .alias = "rfc-8470", .canonical = "rfc8470" },
        },
        .description = "Enables forwarding of TLS 0-RTT/early data to the proxied upstream per RFC 8470. Requires proxy_pass to be set on the same location.",
        .example = "location /idempotent/ {\n    proxy_pass http://up;\n    proxy_early_data rfc8470;\n}",
        .docs = &.{"docs/QUIC_TLS.md"},
    },
    .{
        .name = "location.proxy_set_header",
        .aliases = &.{"proxy_set_header"},
        .contexts = &[_]Context{ .server, .location },
        .value_type = "header-name value",
        .default_value = "none",
        .description = "Sets, overwrites or clears an upstream request header. Every client-sent and Tardigrade-generated instance of the name (any case) is removed first; an empty value (\"\") only removes it. Variables: $host, $http_host, $remote_addr (trusted client IP), $scheme, $proxy_add_x_forwarded_for, $request_id. A location with any proxy_set_header replaces the server block's list rather than merging. Content-Length, Transfer-Encoding, Early-Data and X-Tardigrade-* are rejected; hop-by-hop headers may only be cleared; Host cannot be cleared (an empty expansion falls back to the proxy_pass host).",
        .example = "location /realms/ekho/ {\n    proxy_pass http://keycloak:8080/realms/ekho/;\n    proxy_set_header Host auth.example.com;\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_set_header X-Forwarded-For $remote_addr;\n}",
        .docs = &.{ "docs/CONFIGURATION.md", "docs/PROXY_SECURITY.md" },
    },
    .{
        .name = "location.forward_auth",
        .aliases = &.{"forward_auth"},
        .contexts = CTX_LOCATION,
        .value_type = "url",
        .default_value = "none",
        .description = "External auth subrequest run before the location action. 2xx allows; a 4xx, or a 301/302/303/307/308 with a valid Location, is relayed to the client; 304, other 3xx, redirects without a Location, 1xx/5xx, timeouts, connect failures and malformed responses fail closed with forward_auth_failure_status. Allowed and denied responses are never shared-cacheable. On HTTP/2, a rewrite action in a forward_auth location is not supported (the request gets 404).",
        .example = "location /admin/ {\n    forward_auth http://127.0.0.1:4180/oauth2/auth;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.forward_auth_upstream_headers",
        .aliases = &.{"forward_auth_upstream_headers"},
        .contexts = CTX_LOCATION,
        .value_type = "header names",
        .default_value = "none",
        .description = "Auth-response headers copied onto the upstream request when forward_auth allows it. Client-supplied copies are always removed first. Tardigrade-owned headers cannot be named.",
        .example = "location /admin/ {\n    forward_auth http://127.0.0.1:4180/verify;\n    forward_auth_upstream_headers X-Auth-Request-User;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.forward_auth_client_headers",
        .aliases = &.{"forward_auth_client_headers"},
        .contexts = CTX_LOCATION,
        .value_type = "header names",
        .default_value = "none",
        .description = "Auth-response headers added to the client response: on allow, to whatever the location returns; on a relayed denial, in addition to Location (for a 301/302/303/307/308 redirect) and WWW-Authenticate (401). Repeated fields such as Set-Cookie are kept.",
        .example = "location /admin/ {\n    forward_auth http://127.0.0.1:4180/verify;\n    forward_auth_client_headers Set-Cookie;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.forward_auth_body",
        .aliases = &.{"forward_auth_body"},
        .contexts = CTX_LOCATION,
        .value_type = "bytes",
        .default_value = "off",
        .description = "Largest request body forwarded to the forward_auth service. When set, the subrequest is always a POST (an empty body is sent with Content-Length: 0); larger bodies get 413. off sends a bodyless GET; a non-zero limit disables upload streaming for the location.",
        .example = "location /api/ {\n    forward_auth http://127.0.0.1:4180/verify;\n    forward_auth_body 8192;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.forward_auth_timeout_ms",
        .aliases = &.{"forward_auth_timeout_ms"},
        .contexts = CTX_LOCATION,
        .value_type = "milliseconds",
        .default_value = "upstream response timeout, else 5000",
        .description = "Connect and response deadline for the forward_auth subrequest.",
        .example = "location /admin/ {\n    forward_auth http://127.0.0.1:4180/verify;\n    forward_auth_timeout_ms 500;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.forward_auth_failure_status",
        .aliases = &.{"forward_auth_failure_status"},
        .contexts = CTX_LOCATION,
        .value_type = "status",
        .default_value = "503",
        .valid_values = &.{ "401", "403", "500", "502", "503", "504" },
        .description = "Status returned when the forward_auth service cannot produce a decision (timeout, connect failure, 1xx/5xx, malformed response).",
        .example = "location /admin/ {\n    forward_auth http://127.0.0.1:4180/verify;\n    forward_auth_failure_status 502;\n    proxy_pass http://up;\n}",
        .docs = &.{"examples/forward-auth/README.md"},
    },
    .{
        .name = "location.proxy_websocket",
        .aliases = &.{"proxy_websocket"},
        .contexts = CTX_LOCATION,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "on" },
        .description = "Relays HTTP/1.1 WebSocket upgrades (RFC 6455) through this location's proxy_pass. The handshake runs every gate an ordinary request does (rate limits, ACLs, auth required, forward_auth, 0-RTT 425) before a fresh upstream connection is opened; a 101 with a correct Sec-WebSocket-Accept switches both hops to a byte tunnel, and any other answer is relayed as an ordinary response. Invalid handshakes get 400 (426 for an unsupported Sec-WebSocket-Version). Each tunnel holds one worker thread for its lifetime. Off (the default) strips Upgrade and never relays an upstream 101. HTTP/2 and HTTP/3 extended CONNECT are not supported; browsers use HTTP/1.1 for WebSockets.",
        .example = "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket on;\n}",
        .docs = &.{ "docs/CONFIGURATION.md", "examples/websocket-proxy/README.md" },
    },
    .{
        .name = "location.proxy_websocket_idle_timeout_ms",
        .aliases = &.{"proxy_websocket_idle_timeout_ms"},
        .contexts = CTX_LOCATION,
        .value_type = "milliseconds",
        .default_value = "60000",
        .valid_values = &.{"> 0"},
        .description = "Closes a WebSocket tunnel when no bytes move in either direction for this long. Applications that stay quiet longer must send pings.",
        .example = "location /ws/ {\n    proxy_pass http://up;\n    proxy_websocket on;\n    proxy_websocket_idle_timeout_ms 300000;\n}",
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "location.proxy_websocket_max_lifetime_ms",
        .aliases = &.{"proxy_websocket_max_lifetime_ms"},
        .contexts = CTX_LOCATION,
        .value_type = "milliseconds",
        .default_value = "0 (unlimited)",
        .valid_values = &.{">= 0"},
        .description = "Closes a WebSocket tunnel this long after it opened, whether or not it is busy.",
        .example = "location /ws/ {\n    proxy_pass http://up;\n    proxy_websocket on;\n    proxy_websocket_max_lifetime_ms 3600000;\n}",
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "location.proxy_websocket_reload",
        .aliases = &.{"proxy_websocket_reload"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "enum",
        .default_value = "preserve",
        .valid_values = &.{ "preserve", "drain" },
        .description = "What a successful hot reload does to WebSocket tunnels that are already open. preserve keeps them relaying under the configuration they were admitted with, even if their location was changed or removed. drain closes them proxy_websocket_reload_timeout_ms after the first reload that supersedes that configuration; later reloads do not extend the deadline, and failed reloads have no effect. Set at top level as the default and per location to override it. The policy and timeout come from the configuration a tunnel was admitted under. Graceful shutdown still closes every tunnel at its own drain deadline, whichever comes first.",
        .example = "proxy_websocket_reload drain;\nlocation /ws/ {\n    proxy_pass http://up;\n    proxy_websocket on;\n    proxy_websocket_reload preserve;\n}",
        .env_vars = &.{"TARDIGRADE_PROXY_WEBSOCKET_RELOAD"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/RELOAD_SHUTDOWN.md" },
    },
    .{
        .name = "location.proxy_websocket_reload_timeout_ms",
        .aliases = &.{"proxy_websocket_reload_timeout_ms"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "milliseconds",
        .default_value = "30000",
        .valid_values = &.{">= 0"},
        .description = "How long a drain-mode WebSocket tunnel keeps relaying after a reload supersedes its configuration, measured from that reload. 0 closes it at the reload. Top-level default, overridable per location.",
        .example = "location /ws/ {\n    proxy_pass http://up;\n    proxy_websocket on;\n    proxy_websocket_reload drain;\n    proxy_websocket_reload_timeout_ms 10000;\n}",
        .env_vars = &.{"TARDIGRADE_PROXY_WEBSOCKET_RELOAD_TIMEOUT_MS"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/RELOAD_SHUTDOWN.md" },
    },
    .{
        .name = "location.proxy_websocket_origins",
        .aliases = &.{"proxy_websocket_origins"},
        .contexts = CTX_LOCATION,
        .value_type = "origins",
        .default_value = "none (any origin)",
        .description = "Allowlist of browser origins (scheme://host[:port]) that may open a WebSocket here, to stop cross-site WebSocket hijacking. A handshake whose Origin is not listed gets 403 before the upstream is contacted. Handshakes without an Origin header (non-browser clients) are allowed.",
        .example = "location /ws/ {\n    proxy_pass http://up;\n    proxy_websocket on;\n    proxy_websocket_origins https://app.example.com;\n}",
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "location.proxy_response_stream_reload",
        .aliases = &.{"proxy_response_stream_reload"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "enum",
        .default_value = "preserve",
        .valid_values = &.{ "preserve", "drain" },
        .description = "What a successful hot reload does to long-lived streamed HTTP responses admitted under an older configuration generation. preserve leaves them open; drain schedules them from the first superseding reload. Set at top level as the default and on proxy_pass locations to override it. Failed reloads have no effect.",
        .example = "proxy_response_stream_reload drain;\nlocation /events/ {\n    proxy_pass http://up;\n    proxy_response_stream_reload preserve;\n}",
        .env_vars = &.{"TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/PROXY_STREAMING.md" },
    },
    .{
        .name = "location.proxy_response_stream_reload_timeout_ms",
        .aliases = &.{"proxy_response_stream_reload_timeout_ms"},
        .contexts = CTX_TOP_LOCATION,
        .value_type = "milliseconds",
        .default_value = "30000",
        .valid_values = &.{">= 0"},
        .description = "Drain window captured when a long-lived response stream is admitted, measured from the first successful reload that supersedes its configuration. 0 drains immediately. Top-level default, overridable on proxy_pass locations.",
        .example = "location /events/ {\n    proxy_pass http://up;\n    proxy_response_stream_reload drain;\n    proxy_response_stream_reload_timeout_ms 10000;\n}",
        .env_vars = &.{"TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD_TIMEOUT_MS"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/PROXY_STREAMING.md" },
    },

    // ---- TLS ---------------------------------------------------------------
    .{
        .name = "tls_cert_path",
        .contexts = CTX_TOP,
        .value_type = "path",
        .default_value = "none",
        .description = "Server TLS certificate chain path (PEM).",
        .example = "tls_cert_path /etc/tls/fullchain.pem;",
        .env_vars = &.{"TARDIGRADE_TLS_CERT_PATH"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/BARE_APPLIANCE_TLS.md" },
    },
    .{
        .name = "tls_key_path",
        .contexts = CTX_TOP,
        .value_type = "path",
        .default_value = "none",
        .description = "Server TLS private key path (PEM/PKCS#8).",
        .example = "tls_key_path /etc/tls/privkey.pem;",
        .env_vars = &.{"TARDIGRADE_TLS_KEY_PATH"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/BARE_APPLIANCE_TLS.md" },
    },
    .{
        .name = "tls_min_version",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "1.2 (general profile); 1.3 (appliance and native profiles)",
        .valid_values = &.{ "1.2", "1.3" },
        .description = "Minimum negotiated TLS protocol version. The native-TLS builds (appliance and native profiles) require 1.3 for both min and max.",
        .example = "tls_min_version 1.2;",
        .env_vars = &.{"TARDIGRADE_TLS_MIN_VERSION"},
        .docs = &.{"docs/TLS_INTEROP_MATRIX.md"},
    },
    .{
        .name = "tls_max_version",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "1.3",
        .valid_values = &.{"1.2, 1.3 (general profile); 1.3 only (appliance and native profiles -- must match tls_min_version)"},
        .description = "Maximum negotiated TLS protocol version.",
        .example = "tls_max_version 1.3;",
        .env_vars = &.{"TARDIGRADE_TLS_MAX_VERSION"},
        .docs = &.{"docs/TLS_INTEROP_MATRIX.md"},
    },
    .{
        .name = "tls_client_verify",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Requires and verifies client certificates (mTLS). Rejected by the native-TLS builds: true is not a valid value in appliance or native profile builds.",
        .example = "tls_client_verify true;",
        .env_vars = &.{"TARDIGRADE_TLS_CLIENT_VERIFY"},
        .docs = &.{"docs/PENTEST_PLAYBOOK.md"},
    },
    .{
        .name = "tls_client_verify_depth",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "3",
        .valid_values = &.{">= 0"},
        .description = "Maximum client certificate chain verification depth.",
        .example = "tls_client_verify_depth 5;",
        .env_vars = &.{"TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH"},
    },
    .{
        .name = "tls_ocsp_stapling",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables OCSP stapling responses. Not supported when the binary is built with the appliance or native TLS profiles.",
        .example = "tls_ocsp_stapling true;",
        .env_vars = &.{"TARDIGRADE_TLS_OCSP_STAPLING"},
        .docs = &.{"docs/PKI_REVOCATION.md"},
    },
    .{
        .name = "tls_native_resumption_mode",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "disabled",
        .valid_values = &.{ "disabled", "stateful", "stateless", "hybrid" },
        .description = "Native (pure-Zig) TLS/QUIC session resumption mode, distinct from the OpenSSL-facing tls_session_* settings.",
        .example = "tls_native_resumption_mode hybrid;",
        .env_vars = &.{"TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE"},
        .docs = &.{"docs/RESUMPTION_TEST_PLAN.md"},
    },

    // ---- Upstream configuration ---------------------------------------------
    .{
        .name = "upstream_base_url",
        .contexts = CTX_TOP,
        .value_type = "URL",
        .default_value = "http://127.0.0.1:8080",
        .description = "Default single-upstream proxy target used by locations with a relative or empty proxy_pass.",
        .example = "upstream_base_url http://127.0.0.1:8080;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_BASE_URL"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "upstream_base_urls",
        .contexts = CTX_TOP,
        .value_type = "comma-separated URL list",
        .default_value = "none",
        .description = "Multiple upstream targets for load-balancing, optionally paired with upstream_base_url_weights (which must match its length exactly if set).",
        .example = "# TARDIGRADE_UPSTREAM_BASE_URLS=http://a:8080,http://b:8080",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_BASE_URLS"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "upstream_lb_algorithm",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "round_robin",
        .valid_values = &.{ "round_robin", "least_connections", "ip_hash", "generic_hash", "random_two_choices" },
        .value_aliases = &.{
            .{ .alias = "round-robin", .canonical = "round_robin" },
            .{ .alias = "least-connections", .canonical = "least_connections" },
            .{ .alias = "ip-hash", .canonical = "ip_hash" },
            .{ .alias = "generic-hash", .canonical = "generic_hash" },
            .{ .alias = "random-two-choices", .canonical = "random_two_choices" },
        },
        .description = "Load-balancing algorithm across multiple upstream_base_urls.",
        .example = "upstream_lb_algorithm least-connections;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_LB_ALGORITHM"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_protocol",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "http1",
        .valid_values = &.{ "http1", "h2", "auto", "h2c" },
        .value_aliases = &.{
            .{ .alias = "h1", .canonical = "http1" },
            .{ .alias = "http/1.1", .canonical = "http1" },
            .{ .alias = "http2", .canonical = "h2" },
        },
        .description = "Selects the application protocol used when connecting to upstreams. http1 requires HTTP/1.1 for HTTPS; h2 requires HTTP/2 via ALPN; auto prefers h2 while allowing HTTP/1.1 fallback; h2c behaves like h2 for HTTPS upstreams (still requires HTTP/2 via ALPN) and additionally uses prior-knowledge cleartext HTTP/2 for plain-HTTP upstreams.",
        .example = "upstream_protocol h2;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROTOCOL"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_tls_verify",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Verifies TLS certificates presented by HTTPS upstream backends.",
        .example = "upstream_tls_verify false;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_TLS_VERIFY"},
        .docs = &.{"docs/PROXY_SECURITY.md"},
    },
    .{
        .name = "upstream_connect_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "5000",
        .valid_values = &.{">= 0 (0's fallback is path-dependent; see description)"},
        .description = "Configured TCP connect timeout for upstream connections. The streaming proxy path uses this value directly and falls back to upstream_timeout_ms only when it is 0. Buffered proxy attempts currently use their per-attempt upstream_timeout_ms bound for connect/write whenever that bound is nonzero; this knob is the fallback there only when the per-attempt bound is 0.",
        .example = "upstream_connect_timeout_ms 3000;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "upstream_response_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "0 (falls back to upstream_timeout_ms in the common case)",
        .valid_values = &.{">= 0 (when zero, fallback is path-dependent if upstream_timeout_ms is also zero; see description)"},
        .description = "Max time to wait for an upstream to begin responding (first byte / response head) after the request has been fully sent. Enforced across the buffered, streaming, and control-plane proxy paths and the h2 actor -- not limited to Unix socket upstreams. Normally falls back to upstream_timeout_ms when 0, but if upstream_timeout_ms is itself 0 the effective behavior differs by path (buffered falls back to its connect/send-phase bound; streaming can retain no read deadline).",
        .example = "upstream_response_timeout_ms 8000;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "upstream_retry_attempts",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "1",
        .valid_values = &.{">= 0 (0 and 1 are both clamped to 1 effective attempt; N permits at most N-1 retries)"},
        .description = "Maximum total upstream attempts for an eligible proxy request, not a retry count. 1 means one initial attempt and no retry; 3 permits at most two retries.",
        .example = "upstream_retry_attempts 3;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_retry_idempotent_only",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Restricts retries to idempotent methods (GET, HEAD, PUT, DELETE, OPTIONS, TRACE). POST and PATCH are never retried when this is enabled.",
        .example = "upstream_retry_idempotent_only false;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },

    // ---- Upstream pooling / health ------------------------------------------
    .{
        .name = "upstream_pool_enabled",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables the shared HTTP/1 manual connection pool, which covers plain-HTTP, TLS, Unix-socket HTTP, streaming, control-plane, and FastCGI upstreams. HTTP/2 upstreams use a separate always-on multiplexing pool and are not affected by this setting.",
        .example = "upstream_pool_enabled false;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_POOL_ENABLED"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_pool_max_idle_per_host",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "32",
        .valid_values = &.{">= 0 (0 disables idle connection caching in the shared H1/FastCGI pool)"},
        .description = "Maximum idle upstream connections cached per origin in the shared H1/FastCGI pool. A value of 0 means no connection is ever parked idle; the separate always-on H2 pool is unaffected.",
        .example = "upstream_pool_max_idle_per_host 64;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_pool_idle_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "90000",
        .valid_values = &.{">= 0 (0 disables idle-age eviction)"},
        .description = "Evicts an idle pooled upstream connection after this long unused. A value of 0 disables idle-age eviction; other causes (lifetime, health) can still close a pooled connection.",
        .example = "upstream_pool_idle_timeout_ms 60000;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_max_fails",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (disabled)",
        .valid_values = &.{">= 0"},
        .description = "Passive health threshold: marks an upstream failed after this many failed attempts. A value of 0 disables passive health tracking.",
        .example = "upstream_max_fails 3;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_MAX_FAILS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_fail_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "10000",
        .valid_values = &.{">= 0 (0 disables the passive unhealthy hold interval)"},
        .description = "Passive-health hold interval after a backend reaches upstream_max_fails before it becomes timer-eligible again. A value of 0 applies no passive quarantine delay; active-probe state can still keep the backend unroutable.",
        .example = "upstream_fail_timeout_ms 15000;",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_probe_interval_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "0 (disabled)",
        .valid_values = &.{">= 0"},
        .description = "Interval between active health probes. A value of 0 disables active checks.",
        .example = "# TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=5000",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS"},
        .legacy_env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_probe_path",
        .contexts = CTX_TOP,
        .value_type = "path",
        .default_value = "/",
        .description = "HTTP path requested by the active health-check probe.",
        .example = "# TARDIGRADE_UPSTREAM_PROBE_PATH=/healthz",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROBE_PATH"},
        .legacy_env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_probe_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "2000",
        .valid_values = &.{">= 0 (0 disables the explicit post-connect socket I/O timeout)"},
        .description = "Socket read/write timeout for active health probes after the connection is established. A value of 0 applies no explicit probe I/O deadline. The TCP connect phase itself is not currently bounded by this setting.",
        .example = "# TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS=1000",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS"},
        .legacy_env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_probe_fail_threshold",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "1",
        .valid_values = &.{">= 1 effective; 0 (and malformed values) are clamped to 1"},
        .description = "Consecutive active-probe failures required before marking a backend unhealthy. A configured 0 is coerced to the minimum effective threshold of 1.",
        .example = "# TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD=2",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD"},
        .legacy_env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_active_probe_success_threshold",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "1",
        .valid_values = &.{">= 1 effective; 0 (and malformed values) are clamped to 1"},
        .description = "Consecutive active-probe successes required before clearing an unhealthy backend. A configured 0 is coerced to the minimum effective threshold of 1.",
        .example = "# TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD=2",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },
    .{
        .name = "upstream_probe_success_status",
        .contexts = CTX_TOP,
        .value_type = "status or inclusive status range",
        .default_value = "200-299",
        .valid_values = &.{ "a single status, e.g. 204", "an inclusive range \"min-max\", e.g. 200-399" },
        .description = "Status code or inclusive status-code range considered a successful active health probe. Falls back to the default range if unparsable.",
        .example = "# TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS=200-399",
        .env_vars = &.{"TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS"},
        .legacy_env_vars = &.{"TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS"},
        .docs = &.{"docs/UPSTREAM_POOLING.md"},
    },

    // ---- HTTP/1, HTTP/2, HTTP/3 / QUIC ---------------------------------------
    .{
        .name = "http1_enabled",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables HTTP/1.1 listener support.",
        .example = "http1_enabled false;",
        .env_vars = &.{"TARDIGRADE_HTTP1_ENABLED"},
        .docs = &.{"docs/SUPPORT_MATRIX.md"},
    },
    .{
        .name = "http2_enabled",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables downstream HTTP/2 over TLS via ALPN. Also settable via the `listen ... http2;` flag. Plaintext downstream h2c is not supported; prior-knowledge h2c is only available for upstream connections via upstream_protocol.",
        .example = "http2_enabled false;",
        .env_vars = &.{"TARDIGRADE_HTTP2_ENABLED"},
        .docs = &.{"docs/SUPPORT_MATRIX.md"},
    },
    .{
        .name = "http3_enabled",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables the HTTP/3 (QUIC) listener.",
        .example = "http3_enabled true;",
        .env_vars = &.{"TARDIGRADE_HTTP3_ENABLED"},
        .docs = &.{ "docs/HTTP3_ROLLOUT.md", "docs/SUPPORT_MATRIX.md" },
    },
    .{
        .name = "quic_port",
        .contexts = CTX_TOP,
        .value_type = "port",
        .default_value = "443",
        .valid_values = &.{"1-65535"},
        .description = "UDP port for the QUIC/HTTP3 listener.",
        .example = "quic_port 8443;",
        .env_vars = &.{"TARDIGRADE_QUIC_PORT"},
        .docs = &.{"docs/HTTP3_ROLLOUT.md"},
    },
    .{
        .name = "http3_alt_svc",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "auto" },
        .description = "Controls whether Alt-Svc headers advertising HTTP/3 are emitted on HTTP/1.1 and HTTP/2 responses.",
        .example = "http3_alt_svc auto;",
        .env_vars = &.{"TARDIGRADE_HTTP3_ALT_SVC"},
        .docs = &.{"docs/HTTP3_ROLLOUT.md"},
    },
    .{
        .name = "http3_enable_0rtt",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables QUIC 0-RTT early data acceptance. Rejected by the appliance TLS profile when http3_enabled is true: true is not a valid value in appliance builds with HTTP/3 on.",
        .example = "http3_enable_0rtt true;",
        .env_vars = &.{"TARDIGRADE_HTTP3_ENABLE_0RTT"},
        .docs = &.{"docs/QUIC_TLS.md"},
    },
    .{
        .name = "http3_connection_migration",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables QUIC connection migration (path change) support. Rejected by the appliance TLS profile when http3_enabled is true: true is not a valid value in appliance builds with HTTP/3 on.",
        .example = "http3_connection_migration true;",
        .env_vars = &.{"TARDIGRADE_HTTP3_CONNECTION_MIGRATION"},
        .docs = &.{"docs/QUIC_TLS.md"},
    },
    .{
        .name = "http3_retry_policy",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "off",
        .valid_values = &.{ "off", "address_validation" },
        .value_aliases = &.{
            .{ .alias = "address-validation", .canonical = "address_validation" },
        },
        .description = "QUIC Retry-packet issuance policy, used for address-validation DDoS/amplification mitigation. address_validation is a general-profile value only; the appliance TLS profile requires off when http3_enabled is true.",
        .example = "http3_retry_policy address_validation;",
        .env_vars = &.{"TARDIGRADE_HTTP3_RETRY_POLICY"},
        .docs = &.{"docs/QUIC_TLS.md"},
    },
    .{
        .name = "http3_ecn",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Enables ECN marking on the QUIC listener. Self-disables per-path on unreliable feedback; this is an escape hatch to disable it outright.",
        .example = "http3_ecn false;",
        .env_vars = &.{"TARDIGRADE_HTTP3_ECN"},
        .docs = &.{"docs/QUIC_QLOG.md"},
    },

    // ---- Security / limits ----------------------------------------------------
    .{
        .name = "rate_limit_rps",
        .contexts = CTX_TOP,
        .value_type = "float",
        .default_value = "10",
        .valid_values = &.{">= 0 (0 disables rate limiting)"},
        .description = "Requests-per-second limit per client IP.",
        .example = "rate_limit_rps 50;",
        .env_vars = &.{"TARDIGRADE_RATE_LIMIT_RPS"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "rate_limit_burst",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "20",
        .valid_values = &.{">= 0"},
        .description = "Burst capacity for the token-bucket rate limiter.",
        .example = "rate_limit_burst 40;",
        .env_vars = &.{"TARDIGRADE_RATE_LIMIT_BURST"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "security_headers",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "true",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Adds standard security response headers to every response.",
        .example = "security_headers false;",
        .env_vars = &.{"TARDIGRADE_SECURITY_HEADERS"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "hsts_enabled",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Emits a Strict-Transport-Security header on HTTPS responses. Has no effect without TLS configured.",
        .example = "hsts_enabled true;",
        .env_vars = &.{"TARDIGRADE_HSTS_ENABLED"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "hsts_max_age",
        .contexts = CTX_TOP,
        .value_type = "integer seconds",
        .default_value = "31536000 (1 year)",
        .valid_values = &.{">= 0"},
        .description = "HSTS max-age directive value in seconds.",
        .example = "hsts_max_age 63072000;",
        .env_vars = &.{"TARDIGRADE_HSTS_MAX_AGE"},
    },
    .{
        .name = "max_body_size",
        .contexts = CTX_TOP,
        .value_type = "integer bytes",
        .default_value = "0 (uses the built-in default of 1MB)",
        .valid_values = &.{">= 0"},
        .description = "Maximum accepted request body size. A value of 0 does not mean unlimited -- it falls back to a built-in 1MB cap.",
        .example = "max_body_size 10485760;",
        .env_vars = &.{"TARDIGRADE_MAX_BODY_SIZE"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "max_uri_length",
        .contexts = CTX_TOP,
        .value_type = "integer bytes",
        .default_value = "0 (uses the built-in default of 8KB)",
        .valid_values = &.{">= 0"},
        .description = "Maximum accepted request URI length. A value of 0 does not mean unlimited -- it falls back to a built-in 8KB cap.",
        .example = "max_uri_length 4096;",
        .env_vars = &.{"TARDIGRADE_MAX_URI_LENGTH"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "max_header_count",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (uses the built-in default of 100)",
        .valid_values = &.{">= 0"},
        .description = "Maximum number of request headers accepted. A value of 0 does not mean unlimited -- it falls back to a built-in cap of 100.",
        .example = "max_header_count 50;",
        .env_vars = &.{"TARDIGRADE_MAX_HEADER_COUNT"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },
    .{
        .name = "max_header_size",
        .contexts = CTX_TOP,
        .value_type = "integer bytes",
        .default_value = "0 (uses the built-in default of 8KB)",
        .valid_values = &.{">= 0"},
        .description = "Maximum size of a single request header line. A value of 0 does not mean unlimited -- it falls back to a built-in 8KB cap.",
        .example = "max_header_size 4096;",
        .env_vars = &.{"TARDIGRADE_MAX_HEADER_SIZE"},
        .docs = &.{"docs/CONFIGURATION.md"},
    },

    // ---- Observability -----------------------------------------------------
    .{
        .name = "log_level",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "info",
        .valid_values = &.{ "debug", "info", "warn", "error" },
        .description = "Minimum log level emitted to the error log.",
        .example = "log_level warn;",
        .env_vars = &.{"TARDIGRADE_LOG_LEVEL"},
        .docs = &.{"docs/OBSERVABILITY.md"},
    },
    .{
        .name = "access_log_format",
        .contexts = CTX_TOP,
        .value_type = "enum",
        .default_value = "json",
        .valid_values = &.{ "json", "plain", "custom" },
        .description = "Access log output format. \"custom\" requires access_log_template to also be set.",
        .example = "access_log_format plain;",
        .env_vars = &.{"TARDIGRADE_ACCESS_LOG_FORMAT"},
        .docs = &.{"docs/OBSERVABILITY.md"},
    },
    .{
        .name = "metrics_path",
        .contexts = CTX_TOP,
        .value_type = "path",
        .default_value = "/status/metrics",
        .description = "Prometheus metrics route path. An empty value disables the metrics endpoint entirely.",
        .example = "metrics_path /metrics;",
        .env_vars = &.{"TARDIGRADE_METRICS_PATH"},
        .docs = &.{"docs/OBSERVABILITY.md"},
    },
    .{
        .name = "metrics_require_auth",
        .contexts = CTX_TOP,
        .value_type = "boolean",
        .default_value = "false",
        .valid_values = &.{ "true", "false" },
        .value_aliases = &.{.{ .alias = "1", .canonical = "true" }},
        .description = "Requires request authentication before serving the metrics endpoint.",
        .example = "metrics_require_auth true;",
        .env_vars = &.{"TARDIGRADE_METRICS_REQUIRE_AUTH"},
        .docs = &.{"docs/OBSERVABILITY.md"},
    },
    .{
        .name = "redact_headers",
        .contexts = CTX_TOP,
        .value_type = "comma-separated header name list",
        .default_value = "none (a built-in redaction list is used)",
        .description = "Header names that must never appear in log output.",
        .example = "# TARDIGRADE_REDACT_HEADERS=authorization,cookie,x-api-key",
        .env_vars = &.{"TARDIGRADE_REDACT_HEADERS"},
        .docs = &.{"docs/OBSERVABILITY.md"},
    },

    // ---- Timeouts / resource controls --------------------------------------
    .{
        .name = "keep_alive_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "5000",
        .valid_values = &.{">= 0 (0 disables the idle keep-alive timeout; parked connections are never reaped)"},
        .description = "Idle keep-alive timeout for client connections.",
        .example = "keep_alive_timeout_ms 10000;",
        .env_vars = &.{"TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "header_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "10000",
        .valid_values = &.{">= 0 (0 falls back to the built-in default of 10000ms)"},
        .description = "Client header read timeout.",
        .example = "header_timeout_ms 5000;",
        .env_vars = &.{"TARDIGRADE_HEADER_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "body_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "0 (falls back to the built-in default of 30000ms)",
        .valid_values = &.{">= 0 (0 falls back to the built-in default of 30000ms)"},
        .description = "Client body read timeout.",
        .example = "body_timeout_ms 15000;",
        .env_vars = &.{"TARDIGRADE_BODY_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "request_total_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "0 (disabled)",
        .valid_values = &.{">= 0 (0 disables the timeout)"},
        .description = "Overall per-request deadline covering auth, upstream, and response streaming.",
        .example = "request_total_timeout_ms 30000;",
        .env_vars = &.{"TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "tls_handshake_timeout_ms",
        .contexts = CTX_TOP,
        .value_type = "integer milliseconds",
        .default_value = "5000",
        .valid_values = &.{">= 0 (0 falls back to keep_alive_timeout_ms)"},
        .description = "TLS handshake completion timeout.",
        .example = "tls_handshake_timeout_ms 8000;",
        .env_vars = &.{"TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS"},
        .docs = &.{"docs/TIMEOUTS.md"},
    },
    .{
        .name = "max_active_connections",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (unlimited)",
        .valid_values = &.{">= 0"},
        .description = "Maximum total active client connections across all IPs.",
        .example = "max_active_connections 10000;",
        .env_vars = &.{"TARDIGRADE_MAX_ACTIVE_CONNECTIONS"},
        .docs = &.{"docs/CONCURRENCY.md"},
    },
    .{
        .name = "proxy_websocket_max_tunnels",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (a quarter of the descriptor soft limit, at most 4096)",
        .valid_values = &.{">= 0"},
        .description = "Maximum concurrent WebSocket tunnels per process. Established tunnels run on the WebSocket reactor threads, not on request workers; each one holds two sockets and two direction buffers. A handshake over the cap gets 503 before the upstream is contacted.",
        .example = "proxy_websocket_max_tunnels 10000;",
        .env_vars = &.{"TARDIGRADE_PROXY_WEBSOCKET_MAX_TUNNELS"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/CONCURRENCY.md" },
    },
    .{
        .name = "proxy_websocket_reactor_threads",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "0 (one per four CPUs, between 1 and 4)",
        .valid_values = &.{"0-64"},
        .description = "Threads that relay established WebSocket tunnels. Each thread owns many tunnels and sleeps in one poll over their sockets. Read at startup only; a reload that changes it is rejected and requires restart.",
        .example = "proxy_websocket_reactor_threads 2;",
        .env_vars = &.{"TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/CONCURRENCY.md" },
    },
    .{
        .name = "proxy_response_stream_max_active",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "256",
        .valid_values = &.{"> 0"},
        .description = "Process-wide cap on admitted long-lived streamed HTTP responses. Capacity is global and cannot be overridden per location; lowering it below the active count blocks new admissions until enough streams close.",
        .example = "proxy_response_stream_max_active 512;",
        .env_vars = &.{"TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE"},
        .docs = &.{ "docs/CONFIGURATION.md", "docs/PROXY_STREAMING.md" },
    },
    .{
        .name = "max_requests_per_connection",
        .contexts = CTX_TOP,
        .value_type = "integer",
        .default_value = "100",
        .valid_values = &.{">= 0 (0 = unlimited)"},
        .description = "Maximum requests served per client keep-alive connection.",
        .example = "max_requests_per_connection 1000;",
        .env_vars = &.{"TARDIGRADE_MAX_REQUESTS_PER_CONNECTION"},
    },
    .{
        .name = "max_connection_memory_bytes",
        .contexts = CTX_TOP,
        .value_type = "integer bytes",
        .default_value = "2097152 (2MB)",
        .valid_values = &.{">= 0 (0 = unlimited)"},
        .description = "Per-connection in-memory buffer cap.",
        .example = "max_connection_memory_bytes 4194304;",
        .env_vars = &.{"TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES"},
        .docs = &.{"docs/CONCURRENCY.md"},
    },

    // ---- Alternate upstream / proxy protocols -------------------------------
    // fastcgi_pass/scgi_pass/uwsgi_pass are recognized top-level and inside
    // location {} blocks (parseStatement / parseLocationStatement); they are
    // NOT among the directives parseServerStatement recognizes inside a
    // server {} block, so `server` is deliberately excluded from contexts.
    .{
        .name = "fastcgi_pass",
        .contexts = CTX_TOP_LOCATION,
        .value_type = "endpoint (host:port or unix:/path)",
        .default_value = "none",
        .description = "FastCGI upstream endpoint. A location-level fastcgi_pass installs a live dispatched route; the top-level/env form is parsed and validated but does not by itself install a route.",
        .example = "location ~ \\.php$ {\n    fastcgi_pass 127.0.0.1:9000;\n}",
        .env_vars = &.{"TARDIGRADE_FASTCGI_UPSTREAM"},
    },
    .{
        .name = "fastcgi_param",
        .contexts = CTX_TOP,
        .value_type = "NAME value",
        .default_value = "none (repeatable)",
        .description = "Injects a CGI variable into FastCGI requests. Value supports ${name} interpolation (config-parse-time variables or OS environment fallback); nginx-style bare $var expansion is not performed.",
        .example = "fastcgi_param APP_ENV production;",
        .env_vars = &.{"TARDIGRADE_FASTCGI_PARAMS"},
    },
    .{
        .name = "fastcgi_index",
        .contexts = CTX_TOP,
        .value_type = "filename",
        .default_value = "index.php",
        .description = "Default index script for directory-style FastCGI requests.",
        .example = "fastcgi_index index.php;",
        .env_vars = &.{"TARDIGRADE_FASTCGI_INDEX"},
    },
    .{
        .name = "scgi_pass",
        .contexts = CTX_TOP_LOCATION,
        .value_type = "endpoint",
        .default_value = "none",
        .description = "SCGI upstream endpoint. Parsed and lowered by the config loader, but the gateway does not currently install a live SCGI route from this setting.",
        .example = "scgi_pass 127.0.0.1:4100;",
        .env_vars = &.{"TARDIGRADE_SCGI_UPSTREAM"},
    },
    .{
        .name = "uwsgi_pass",
        .contexts = CTX_TOP_LOCATION,
        .value_type = "endpoint",
        .default_value = "none",
        .description = "uWSGI upstream endpoint. Parsed and lowered by the config loader, but the gateway does not currently install a live uWSGI route from this setting.",
        .example = "uwsgi_pass 127.0.0.1:4200;",
        .env_vars = &.{"TARDIGRADE_UWSGI_UPSTREAM"},
    },

    // ---- Secrets (never print the live value; see security regression tests) --
    .{
        .name = "jwt_secret",
        .contexts = CTX_TOP,
        .value_type = "secret string",
        .default_value = "unset",
        .description = "JWT signing secret used to validate bearer tokens for protected routes. Empty disables JWT auth.",
        .env_vars = &.{"TARDIGRADE_JWT_SECRET"},
    },
    .{
        .name = "trust_shared_secret",
        .contexts = CTX_TOP,
        .value_type = "secret string",
        .default_value = "unset",
        .description = "Shared secret used for upstream trust-header signing/verification. Empty disables the feature.",
        .env_vars = &.{"TARDIGRADE_TRUST_SHARED_SECRET"},
    },
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Resolve `query` (a directive/field name, a qualified `context.field` name,
/// a short unambiguous alias, or an environment variable name -- current or
/// legacy) to its canonical reference entry, case-insensitively.
const env_prefix = "TARDIGRADE_";

/// True when `name` (a canonical entry name such as "log_level") is the
/// same identifier as `env_suffix` (an env var name with the TARDIGRADE_
/// prefix stripped, such as "LOG_LEVEL") modulo case. Canonical names and
/// their directly-corresponding env vars always share underscore placement,
/// so a case-insensitive byte comparison is sufficient here.
fn canonicalMatchesEnvSuffix(name: []const u8, env_suffix: []const u8) bool {
    return eqlIgnoreCase(name, env_suffix);
}

/// Some real environment variables (e.g. TARDIGRADE_LOG_LEVEL,
/// TARDIGRADE_MAX_ACTIVE_CONNECTIONS) are legitimately listed on more than
/// one entry: a composite/legacy directive that also happens to set them
/// (error_log, worker_connections) alongside the entry whose canonical name
/// directly corresponds to that variable (log_level,
/// max_active_connections). When an env query is ambiguous like this,
/// resolution must prefer the entry whose name the variable is actually
/// named after, not whichever entry happens to appear first in `entries`.
fn lookupDirectEnvMatch(query: []const u8) ?*const ConfigEntry {
    if (!std.ascii.startsWithIgnoreCase(query, env_prefix)) return null;
    const suffix = query[env_prefix.len..];
    for (&entries) |*entry| {
        if (!canonicalMatchesEnvSuffix(entry.name, suffix)) continue;
        for (entry.env_vars) |env_var| {
            if (eqlIgnoreCase(env_var, query)) return entry;
        }
    }
    return null;
}

pub fn lookup(query: []const u8) ?*const ConfigEntry {
    for (&entries) |*entry| {
        if (eqlIgnoreCase(entry.name, query)) return entry;
    }
    for (&entries) |*entry| {
        for (entry.aliases) |alias| {
            if (eqlIgnoreCase(alias, query)) return entry;
        }
    }
    if (lookupDirectEnvMatch(query)) |entry| return entry;
    for (&entries) |*entry| {
        for (entry.env_vars) |env_var| {
            if (eqlIgnoreCase(env_var, query)) return entry;
        }
        for (entry.legacy_env_vars) |env_var| {
            if (eqlIgnoreCase(env_var, query)) return entry;
        }
    }
    return null;
}

fn writeContexts(writer: anytype, contexts: []const Context) !void {
    for (contexts, 0..) |ctx, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.writeAll(ctx.label());
    }
}

fn writeJoined(writer: anytype, items: []const []const u8) !void {
    for (items, 0..) |item, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.writeAll(item);
    }
}

/// Write a concise, operator-focused explanation of `entry` to `writer`.
/// Only sections meaningful for this entry are printed.
pub fn writeExplanation(writer: anytype, entry: *const ConfigEntry) !void {
    try writer.print("{s}\n", .{entry.name});
    try writer.print("  {s}\n\n", .{entry.description});

    try writer.print("Type: {s}\n", .{entry.value_type});
    if (entry.default_value) |default| try writer.print("Default: {s}\n", .{default});
    if (entry.valid_values.len > 0) {
        try writer.writeAll("Valid: ");
        try writeJoined(writer, entry.valid_values);
        try writer.writeAll("\n");
    }
    if (entry.value_aliases.len > 0) {
        try writer.writeAll("Aliases: ");
        for (entry.value_aliases, 0..) |value_alias, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("{s} -> {s}", .{ value_alias.alias, value_alias.canonical });
        }
        try writer.writeAll("\n");
    }
    try writer.writeAll("Context: ");
    try writeContexts(writer, entry.contexts);
    try writer.writeAll("\n");
    if (entry.env_vars.len > 0) {
        try writer.writeAll("Env: ");
        try writeJoined(writer, entry.env_vars);
        try writer.writeAll("\n");
    }
    if (entry.legacy_env_vars.len > 0) {
        try writer.writeAll("Legacy env: ");
        try writeJoined(writer, entry.legacy_env_vars);
        try writer.writeAll("\n");
    }

    if (entry.example) |example| {
        try writer.writeAll("\nExample:\n");
        var lines = std.mem.splitScalar(u8, example, '\n');
        while (lines.next()) |line| try writer.print("  {s}\n", .{line});
    }

    if (entry.docs.len > 0) {
        try writer.writeAll("\nDocs: ");
        try writeJoined(writer, entry.docs);
        try writer.writeAll("\n");
    }
}

/// Levenshtein edit distance, bounded to short field-name-length inputs.
fn editDistance(a: []const u8, b: []const u8) usize {
    const max_len = 64;
    const la = @min(a.len, max_len);
    const lb = @min(b.len, max_len);

    var prev: [max_len + 1]usize = undefined;
    var curr: [max_len + 1]usize = undefined;
    for (0..lb + 1) |j| prev[j] = j;

    for (1..la + 1) |i| {
        curr[0] = i;
        for (1..lb + 1) |j| {
            const cost: usize = if (std.ascii.toLower(a[i - 1]) == std.ascii.toLower(b[j - 1])) 0 else 1;
            const del = prev[j] + 1;
            const ins = curr[j - 1] + 1;
            const sub = prev[j - 1] + cost;
            curr[j] = @min(@min(del, ins), sub);
        }
        std.mem.swap([max_len + 1]usize, &prev, &curr);
    }
    return prev[lb];
}

/// Best-effort match score between `query` and `candidate` (both already
/// lowercased); lower is better; null means "not a plausible suggestion".
fn matchScore(query: []const u8, candidate: []const u8) ?usize {
    if (std.mem.eql(u8, query, candidate)) return 0;
    if (std.mem.startsWith(u8, candidate, query) or std.mem.startsWith(u8, query, candidate)) return 1;
    if (std.mem.indexOf(u8, candidate, query) != null or std.mem.indexOf(u8, query, candidate) != null) return 2;
    const dist = editDistance(query, candidate);
    if (dist <= 3) return 100 + dist;
    return null;
}

const max_suggestions = 3;

const Suggestion = struct {
    name: []const u8,
    score: usize,
};

fn bestEntryScore(query_lower: []const u8, entry: *const ConfigEntry, lower_buf: []u8) ?usize {
    var best: ?usize = null;
    const consider = struct {
        fn run(q: []const u8, candidate: []const u8, buf: []u8, current_best: *?usize) void {
            const len = @min(candidate.len, buf.len);
            for (candidate[0..len], 0..) |ch, i| buf[i] = std.ascii.toLower(ch);
            const score = matchScore(q, buf[0..len]) orelse return;
            if (current_best.* == null or score < current_best.*.?) current_best.* = score;
        }
    }.run;
    consider(query_lower, entry.name, lower_buf, &best);
    for (entry.aliases) |alias| consider(query_lower, alias, lower_buf, &best);
    return best;
}

/// Collect at most `max_suggestions` close-match canonical names for `query`,
/// most-relevant first. Deterministic and lightweight: prefix/substring
/// matches rank above bounded-edit-distance matches, ties break
/// alphabetically.
fn collectSuggestions(query: []const u8, out: *[max_suggestions]Suggestion) usize {
    var query_buf: [64]u8 = undefined;
    const qlen = @min(query.len, query_buf.len);
    for (query[0..qlen], 0..) |ch, i| query_buf[i] = std.ascii.toLower(ch);
    const query_lower = query_buf[0..qlen];

    var count: usize = 0;
    var lower_buf: [64]u8 = undefined;
    for (&entries) |*entry| {
        const score = bestEntryScore(query_lower, entry, &lower_buf) orelse continue;
        const candidate = Suggestion{ .name = entry.name, .score = score };

        if (count < max_suggestions) {
            out[count] = candidate;
            count += 1;
            var i = count - 1;
            while (i > 0 and (out[i - 1].score > out[i].score or
                (out[i - 1].score == out[i].score and std.mem.order(u8, out[i - 1].name, out[i].name) == .gt)))
            {
                std.mem.swap(Suggestion, &out[i - 1], &out[i]);
                i -= 1;
            }
        } else if (candidate.score < out[max_suggestions - 1].score) {
            out[max_suggestions - 1] = candidate;
            var i: usize = max_suggestions - 1;
            while (i > 0 and (out[i - 1].score > out[i].score or
                (out[i - 1].score == out[i].score and std.mem.order(u8, out[i - 1].name, out[i].name) == .gt)))
            {
                std.mem.swap(Suggestion, &out[i - 1], &out[i]);
                i -= 1;
            }
        }
    }
    return count;
}

/// Write an operator-facing "unknown field" error for `query`, plus up to 3
/// deterministic close-match suggestions when any are found.
pub fn writeUnknown(writer: anytype, query: []const u8) !void {
    try writer.print("error: unknown configuration field '{s}'\n", .{query});

    var suggestions: [max_suggestions]Suggestion = undefined;
    const count = collectSuggestions(query, &suggestions);
    if (count == 0) return;

    try writer.writeAll("\nDid you mean:\n");
    for (suggestions[0..count]) |suggestion| {
        try writer.print("  {s}\n", .{suggestion.name});
    }
}

// ============================================================================
// Tests
// ============================================================================

test "lookup resolves the canonical name" {
    const entry = lookup("listen") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("listen", entry.name);
}

test "lookup resolves a qualified block field" {
    const entry = lookup("location.proxy_pass") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("location.proxy_pass", entry.name);
}

test "lookup resolves an unqualified short alias" {
    const entry = lookup("proxy_pass") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("location.proxy_pass", entry.name);
}

test "lookup resolves the current and legacy environment variable names" {
    const primary = lookup("TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("upstream_probe_interval_ms", primary.name);

    const legacy = lookup("TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("upstream_probe_interval_ms", legacy.name);
}

test "lookup resolves the qualified server.server_name alias" {
    const entry = lookup("server.server_name") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server_name", entry.name);
}

fn hasContext(contexts: []const Context, target: Context) bool {
    for (contexts) |ctx| if (ctx == target) return true;
    return false;
}

test "return and rewrite report both their top-level and location contexts" {
    const ret = lookup("return").?;
    try std.testing.expect(hasContext(ret.contexts, .top_level));
    try std.testing.expect(hasContext(ret.contexts, .location));

    const rewrite = lookup("rewrite").?;
    try std.testing.expect(hasContext(rewrite.contexts, .top_level));
    try std.testing.expect(hasContext(rewrite.contexts, .location));
}

test "proxy_streaming_mode (global) and location.proxy_streaming report distinct defaults, contexts, and env vars" {
    const global = lookup("proxy_streaming_mode").?;
    try std.testing.expectEqualStrings("proxy_streaming_mode", global.name);
    try std.testing.expectEqualStrings("off", global.default_value.?);
    try std.testing.expectEqual(@as(usize, 1), global.contexts.len);
    try std.testing.expectEqual(Context.top_level, global.contexts[0]);
    try std.testing.expectEqualStrings("TARDIGRADE_PROXY_STREAMING_MODE", global.env_vars[0]);

    const location_override = lookup("proxy_streaming").?;
    try std.testing.expectEqualStrings("location.proxy_streaming", location_override.name);
    try std.testing.expectEqualStrings("inherit (uses the global proxy_streaming_mode)", location_override.default_value.?);
    try std.testing.expectEqual(@as(usize, 1), location_override.contexts.len);
    try std.testing.expectEqual(Context.location, location_override.contexts[0]);
    try std.testing.expectEqual(@as(usize, 0), location_override.env_vars.len);

    // The qualified long-form spelling still reaches the location entry,
    // not the global one.
    try std.testing.expectEqualStrings("location.proxy_streaming", lookup("location.proxy_streaming_mode").?.name);
}

test "response-stream lifecycle settings report cap and override contexts (#841)" {
    const cap = lookup("proxy_response_stream_max_active").?;
    try std.testing.expectEqualStrings("256", cap.default_value.?);
    try std.testing.expectEqual(Context.top_level, cap.contexts[0]);
    try std.testing.expectEqualStrings("TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE", cap.env_vars[0]);

    const reload = lookup("proxy_response_stream_reload").?;
    try std.testing.expectEqualStrings("location.proxy_response_stream_reload", reload.name);
    try std.testing.expect(hasContext(reload.contexts, .top_level));
    try std.testing.expect(hasContext(reload.contexts, .location));
    try std.testing.expectEqualStrings("TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD", reload.env_vars[0]);
}

test "location block reports its real parser contexts (top-level and server, not nested location)" {
    const entry = lookup("location").?;
    try std.testing.expectEqual(@as(usize, 2), entry.contexts.len);
    try std.testing.expectEqual(Context.top_level, entry.contexts[0]);
    try std.testing.expectEqual(Context.server, entry.contexts[1]);
}

test "lookup resolves the alternate-upstream directives by their current environment variable names" {
    const fastcgi = lookup("TARDIGRADE_FASTCGI_UPSTREAM") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("fastcgi_pass", fastcgi.name);

    const scgi = lookup("TARDIGRADE_SCGI_UPSTREAM") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("scgi_pass", scgi.name);

    const uwsgi = lookup("TARDIGRADE_UWSGI_UPSTREAM") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("uwsgi_pass", uwsgi.name);
}

test "lookup resolves the top-level return/rewrite rule-list environment variables" {
    const ret = lookup("TARDIGRADE_RETURN_RULES") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("location.return", ret.name);

    const rewrite = lookup("TARDIGRADE_REWRITE_RULES") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("location.rewrite", rewrite.name);
}

test "location.rewrite documents its accepted flag set" {
    const entry = lookup("rewrite").?;
    var found = false;
    for (entry.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "last") != null and
            std.mem.indexOf(u8, v, "break") != null and
            std.mem.indexOf(u8, v, "redirect") != null and
            std.mem.indexOf(u8, v, "permanent") != null) found = true;
    }
    try std.testing.expect(found);
}

test "env lookup prefers the entry whose canonical name directly matches over a composite/legacy entry sharing the same env var" {
    // TARDIGRADE_LOG_LEVEL is also advertised on error_log (which sets it
    // as a secondary effect of "error_log <path> <level>;"); the dedicated
    // log_level entry must win.
    try std.testing.expectEqualStrings("log_level", lookup("TARDIGRADE_LOG_LEVEL").?.name);

    // TARDIGRADE_MAX_ACTIVE_CONNECTIONS is also advertised on the
    // worker_connections nginx-style alias; the canonical entry must win.
    try std.testing.expectEqualStrings("max_active_connections", lookup("TARDIGRADE_MAX_ACTIVE_CONNECTIONS").?.name);

    // error_log and worker_connections must still resolve by their own
    // canonical names and still display the shared env var -- this policy
    // only changes which entry an *env-var* query resolves to.
    try std.testing.expectEqualStrings("error_log", lookup("error_log").?.name);
    try std.testing.expectEqualStrings("worker_connections", lookup("worker_connections").?.name);
}

test "upstream_probe_success_status documents the single-status form, not only a range" {
    const entry = lookup("upstream_probe_success_status").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "range") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "or") != null);
}

test "header_timeout_ms and body_timeout_ms document the actual RequestLimits fallback, not disabling the timeout" {
    for (&[_][]const u8{ "header_timeout_ms", "body_timeout_ms" }) |name| {
        const entry = lookup(name).?;
        var mentions_fallback = false;
        for (entry.valid_values) |v| {
            if (std.mem.indexOf(u8, v, "falls back") != null) mentions_fallback = true;
        }
        try std.testing.expect(mentions_fallback);
        for (entry.valid_values) |v| try std.testing.expect(std.mem.indexOf(u8, v, "disable") == null);
    }
}

test "upstream_retry_attempts describes a total-attempt budget, not a bare retry count" {
    const entry = lookup("upstream_retry_attempts").?;
    // The old description literally read "Number of upstream attempt
    // retries for proxy requests" -- i.e. it presented the field itself as
    // a retry count. The corrected description must not open that way.
    try std.testing.expect(!std.mem.startsWith(u8, entry.description, "Number of upstream attempt retries"));
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "total") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "one initial attempt") != null);
}

test "upstream_pool_enabled describes the shared HTTP/1 pool scope and the separate always-on h2 pool" {
    const entry = lookup("upstream_pool_enabled").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "TLS") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "FastCGI") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "HTTP/2") != null);
}

test "fastcgi_pass/scgi_pass/uwsgi_pass describe their live-dispatch differences" {
    const fastcgi = lookup("fastcgi_pass").?;
    try std.testing.expect(std.mem.indexOf(u8, fastcgi.description, "does not by itself install a route") != null);

    for (&[_][]const u8{ "scgi_pass", "uwsgi_pass" }) |name| {
        const entry = lookup(name).?;
        try std.testing.expect(std.mem.indexOf(u8, entry.description, "does not currently install a live") != null);
    }
}

test "fastcgi_param example uses the real ${name} interpolation syntax, not nginx bare-dollar variables" {
    const entry = lookup("fastcgi_param").?;
    const example = entry.example.?;
    try std.testing.expect(std.mem.indexOf(u8, example, "$document_root") == null);
    try std.testing.expect(std.mem.indexOf(u8, example, "$fastcgi_script_name") == null);
}

test "listen documents the bare-host form and the port range mapListenDirective actually accepts" {
    const entry = lookup("listen").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "host") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "bare host") != null);
    var has_range = false;
    for (entry.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "65535") != null) has_range = true;
    }
    try std.testing.expect(has_range);
}

test "worker_processes documents literal zero as CPU autodetection" {
    const entry = lookup("worker_processes").?;
    var zero_autodetect = false;
    for (entry.valid_values) |v| {
        const mentions_zero = std.mem.indexOf(u8, v, "0") != null;
        const mentions_autodetect = std.mem.indexOf(u8, v, "autodetect") != null;
        if (mentions_zero and mentions_autodetect) zero_autodetect = true;
    }
    try std.testing.expect(zero_autodetect);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "`0` and `auto`") != null);
}

test "include documents only the supported single-star suffix glob contract" {
    const entry = lookup("include").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "single-`*` suffix") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "foo*.conf") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "not supported") != null);
}

test "location.error_page documents whitespace-separated status codes" {
    const entry = lookup("error_page").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "status [status ...]") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.value_type, "status[,status") == null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "whitespace-separated") != null);
}

test "required integer timeout and resource entries retain explicit non-negative ranges" {
    const names = [_][]const u8{
        "upstream_connect_timeout_ms",
        "upstream_response_timeout_ms",
        "upstream_retry_attempts",
        "keep_alive_timeout_ms",
        "header_timeout_ms",
        "body_timeout_ms",
        "request_total_timeout_ms",
        "tls_handshake_timeout_ms",
        "max_requests_per_connection",
        "max_connection_memory_bytes",
    };
    for (names) |name| {
        const entry = lookup(name).?;
        var has_non_negative_range = false;
        for (entry.valid_values) |v| {
            if (std.mem.indexOf(u8, v, ">= 0") != null) has_non_negative_range = true;
        }
        try std.testing.expect(has_non_negative_range);
    }
}

test "location describes an action family, not a single mandatory action directive" {
    const entry = lookup("location").?;
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "action family") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "combine") != null);
    // The old wording claimed exactly one action *directive*; a valid
    // root+index+try_files static location combines three.
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "exactly one action directive") == null);
}

test "upstream_pool_max_idle_per_host and upstream_pool_idle_timeout_ms document their zero sentinels" {
    const max_idle = lookup("upstream_pool_max_idle_per_host").?;
    var max_idle_documents_zero = false;
    for (max_idle.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "disables idle connection caching") != null) max_idle_documents_zero = true;
    }
    try std.testing.expect(max_idle_documents_zero);

    const idle_timeout = lookup("upstream_pool_idle_timeout_ms").?;
    var idle_timeout_documents_zero = false;
    for (idle_timeout.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "disables idle-age eviction") != null) idle_timeout_documents_zero = true;
    }
    try std.testing.expect(idle_timeout_documents_zero);
}

test "upstream_probe_fail_threshold and upstream_active_probe_success_threshold document that 0 clamps to 1, not rejects" {
    for (&[_][]const u8{ "upstream_probe_fail_threshold", "upstream_active_probe_success_threshold" }) |name| {
        const entry = lookup(name).?;
        var documents_clamp = false;
        for (entry.valid_values) |v| {
            if (std.mem.indexOf(u8, v, "clamped to 1") != null) documents_clamp = true;
        }
        try std.testing.expect(documents_clamp);
    }
}

test "profile-dependent TLS and HTTP/3 entries note their appliance-profile restrictions" {
    const tls_max = lookup("tls_max_version").?;
    var tls_max_notes_appliance = false;
    for (tls_max.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "appliance") != null) tls_max_notes_appliance = true;
    }
    try std.testing.expect(tls_max_notes_appliance);

    try std.testing.expect(std.mem.indexOf(u8, lookup("tls_client_verify").?.description, "appliance") != null);
    try std.testing.expect(std.mem.indexOf(u8, lookup("server.tls_cert_path").?.description, "appliance") != null);
    try std.testing.expect(std.mem.indexOf(u8, lookup("server.tls_key_path").?.description, "appliance") != null);
    try std.testing.expect(std.mem.indexOf(u8, lookup("http3_enable_0rtt").?.description, "appliance") != null);
    try std.testing.expect(std.mem.indexOf(u8, lookup("http3_connection_migration").?.description, "appliance") != null);
    try std.testing.expect(std.mem.indexOf(u8, lookup("http3_retry_policy").?.description, "appliance") != null);
}

test "upstream_protocol's h2c explanation covers both HTTPS/ALPN behavior and plain-HTTP prior knowledge" {
    const entry = lookup("upstream_protocol").?;
    // h2c requires HTTP/2 via ALPN for HTTPS upstreams, same as h2 --
    // gateway_proxy.upstreamAlpnPolicy() maps both to .require_h2. It must
    // not read as "cleartext-only".
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "h2c behaves like h2 for HTTPS") != null);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "prior-knowledge cleartext HTTP/2 for plain-HTTP") != null);
}

test "upstream_fail_timeout_ms documents that 0 disables the passive unhealthy hold interval" {
    const entry = lookup("upstream_fail_timeout_ms").?;
    var documents_zero = false;
    for (entry.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "disables the passive unhealthy hold interval") != null) documents_zero = true;
    }
    try std.testing.expect(documents_zero);
}

test "upstream_probe_timeout_ms describes a post-connect socket timeout, not a whole-probe timeout, and documents its zero sentinel" {
    const entry = lookup("upstream_probe_timeout_ms").?;
    var documents_zero = false;
    for (entry.valid_values) |v| {
        if (std.mem.indexOf(u8, v, "disables the explicit post-connect socket I/O timeout") != null) documents_zero = true;
    }
    try std.testing.expect(documents_zero);
    try std.testing.expect(std.mem.indexOf(u8, entry.description, "connect phase") != null);
}

test "fastcgi_pass/scgi_pass/uwsgi_pass do not claim server-block support" {
    for (&[_][]const u8{ "fastcgi_pass", "scgi_pass", "uwsgi_pass" }) |name| {
        const entry = lookup(name).?;
        for (entry.contexts) |ctx| try std.testing.expect(ctx != .server);
    }
}

test "fastcgi_index reports the actual EdgeConfig default of index.php" {
    const entry = lookup("fastcgi_index").?;
    try std.testing.expectEqualStrings("index.php", entry.default_value.?);
}

test "quic_port rejects 0 as a valid value, matching parseConfigPort/validate" {
    const entry = lookup("quic_port").?;
    var found = false;
    for (entry.valid_values) |v| {
        try std.testing.expect(std.mem.indexOf(u8, v, "0-") == null);
        if (std.mem.eql(u8, v, "1-65535")) found = true;
    }
    try std.testing.expect(found);
}

test "every generic boolean entry documents true/false and no example uses the invalid nginx on/off spelling" {
    // location.autoindex has its own dedicated on/off parser (isLocationAutoindexValue-style
    // handling in config_file.zig) and is deliberately excluded: "on"/"off" really are the
    // accepted spellings there. Every other boolean-typed entry here goes through the generic
    // top-level directive path, which normalizes to EdgeConfig.parseBoolEnv() -- that function
    // only recognizes "true"/"1" as true, so a documented/example "on" would silently mean off.
    for (&entries) |*entry| {
        if (!std.mem.eql(u8, entry.value_type, "boolean")) continue;
        if (std.mem.eql(u8, entry.name, "location.autoindex")) continue;

        var has_true = false;
        var has_false = false;
        for (entry.valid_values) |v| {
            if (std.mem.eql(u8, v, "true")) has_true = true;
            if (std.mem.eql(u8, v, "false")) has_false = true;
        }
        try std.testing.expect(has_true and has_false);

        if (entry.example) |example| {
            try std.testing.expect(std.mem.indexOf(u8, example, " on;") == null);
            try std.testing.expect(std.mem.indexOf(u8, example, " off;") == null);
        }

        // EdgeConfig.parseBoolEnv() intentionally also accepts "1" as true
        // (docs/CONFIGURATION.md documents true/1 for permissive boolean
        // fields); the registry must not make that accepted compatibility
        // spelling look unsupported.
        var has_one_alias = false;
        for (entry.value_aliases) |alias| {
            if (std.mem.eql(u8, alias.alias, "1") and std.mem.eql(u8, alias.canonical, "true")) has_one_alias = true;
        }
        try std.testing.expect(has_one_alias);
    }
}

test "lookup is case-insensitive" {
    const lower = lookup("listen") orelse return error.TestUnexpectedResult;
    const upper = lookup("LISTEN") orelse return error.TestUnexpectedResult;
    const mixed = lookup("Listen") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(lower.name, upper.name);
    try std.testing.expectEqualStrings(lower.name, mixed.name);
}

test "lookup returns null for an unknown field" {
    try std.testing.expectEqual(@as(?*const ConfigEntry, null), lookup("does_not_exist"));
}

test "every registered canonical name is unique" {
    for (&entries, 0..) |*entry, i| {
        for (entries[i + 1 ..]) |*other| {
            try std.testing.expect(!eqlIgnoreCase(entry.name, other.name));
        }
    }
}

test "aliases do not collide with a different entry's canonical name or another entry's alias" {
    for (&entries, 0..) |*entry, i| {
        for (entry.aliases) |alias| {
            for (&entries, 0..) |*other, j| {
                if (i == j) continue;
                try std.testing.expect(!eqlIgnoreCase(alias, other.name));
                for (other.aliases) |other_alias| {
                    try std.testing.expect(!eqlIgnoreCase(alias, other_alias));
                }
            }
        }
    }
}

test "every entry has non-empty name, type, and description" {
    for (&entries) |*entry| {
        try std.testing.expect(entry.name.len > 0);
        try std.testing.expect(entry.value_type.len > 0);
        try std.testing.expect(entry.description.len > 0);
        try std.testing.expect(entry.contexts.len > 0);
    }
}

test "writeExplanation for listen contains type, default, and example" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("listen").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "Type") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Default") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "8069") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Example") != null);
}

test "writeExplanation for upstream_protocol lists enum values and aliases" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("upstream_protocol").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "http1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "h2") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "auto") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "h2c") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "h1 -> http1") != null);
}

test "writeExplanation for upstream_probe_interval_ms shows disabled sentinel and env aliases" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("upstream_probe_interval_ms").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "upstream_probe_interval_ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "0 (disabled)") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS") != null);
}

test "writeExplanation for location.proxy_pass mentions location and an example" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("location.proxy_pass").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "location") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "proxy_pass") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Example") != null);
}

test "writeExplanation represents profile-dependent tls_min_version truthfully" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("tls_min_version").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "general profile") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "appliance and native profiles") != null);
}

test "writeUnknown names the query and suggests a close match" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeUnknown(&out.writer, "upstream_probe_intervl_ms");
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "unknown configuration") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "upstream_probe_intervl_ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "upstream_probe_interval_ms") != null);
}

test "writeUnknown caps suggestions at 3" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeUnknown(&out.writer, "upstream_probe");
    const written = out.writer.buffered();
    var lines: usize = 0;
    var it = std.mem.splitScalar(u8, written, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "  ")) lines += 1;
    }
    try std.testing.expect(lines <= max_suggestions);
}

test "writeUnknown on a wildly unrelated query still returns cleanly with no suggestions" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeUnknown(&out.writer, "zzzzzzzzzzzzzzzzzzzz");
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "unknown configuration") != null);
}

test "explaining a secret field never includes a live secret value even if present in the process environment" {
    // Regression guard for #163: `explain` is a static reference lookup and
    // must never read process environment values. jwt_secret's entry has no
    // mechanism to read TARDIGRADE_JWT_SECRET at all, so assert the
    // rendered output positively excludes a sentinel value to catch any
    // future refactor that accidentally wires this through effective
    // config.
    //
    // This deliberately does NOT mutate the real process environment via
    // setenv/getenv: Zig unit tests for this whole project share one
    // process and this codebase's test suite spawns real OS threads
    // elsewhere (worker pools, listeners, etc.) that may concurrently touch
    // the environment via compat.getEnvVarOwned/parseBoolEnv -- glibc's
    // environ manipulation is not fully thread-safe against that, and a
    // prior version of this test that called setenv/unsetenv directly hung
    // `zig build test` under CI on ubuntu-24.04-arm. The real
    // "secret genuinely present in the environment" regression belongs to
    // a separate process instead: see the equivalent integration tests in
    // tests/integration.zig, which spawn the built `tardi explain
    // jwt_secret`/`trust_shared_secret` binaries against a real,
    // fully-isolated child environment.
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeExplanation(&out.writer, lookup("jwt_secret").?);
    const written = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "do-not-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "TARDIGRADE_JWT_SECRET") != null);
}

test "forward_auth reference text matches the relayed-status contract" {
    // Keep `tardi explain forward_auth` aligned with
    // gateway_forward_auth.isRelayableDenial: only 4xx and real redirects are
    // relayed; 304 and other 3xx fail closed.
    var found = false;
    for (entries) |field| {
        if (!std.mem.eql(u8, field.name, "location.forward_auth")) continue;
        found = true;
        inline for (.{ "301/302/303/307/308", "Location", "304", "fail closed" }) |needle| {
            try std.testing.expect(std.mem.find(u8, field.description, needle) != null);
        }
        try std.testing.expect(std.mem.find(u8, field.description, "3xx/4xx is relayed") == null);
    }
    try std.testing.expect(found);
}
