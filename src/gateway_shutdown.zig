//! Hot reload, shutdown-adjacent maintenance, and background probe helpers for
//! the edge gateway runtime. The main gateway loop owns event dispatch; this
//! module owns reload state mutation and timer-triggered maintenance work.

const compat = @import("zig_compat");
const std = @import("std");
const build_options = @import("build_options");
const http = @import("http.zig");
const tls_core = @import("tls_core");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gc = @import("gateway_connection.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;
const WorkerContext = gs.WorkerContext;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const computeHstsValue = gp.computeHstsValue;
const unixSocketPathFromEndpoint = gp.unixSocketPathFromEndpoint;
const uriComponentBytes = gp.uriComponentBytes;
const setSocketTimeoutMs = gc.setSocketTimeoutMs;

const PreparedReloadSecurity = struct {
    access_control: ?http.access_control.AccessControl,
    hsts_value: ?[]u8,

    fn init(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !PreparedReloadSecurity {
        var access_control: ?http.access_control.AccessControl = null;
        errdefer if (access_control) |*acl| acl.deinit();
        if (cfg.access_control_rules.len > 0) {
            access_control = try http.access_control.AccessControl.fromConfig(allocator, cfg.access_control_rules, .allow);
        }
        return .{
            .access_control = access_control,
            .hsts_value = try computeHstsValue(allocator, cfg),
        };
    }

    fn deinit(self: *PreparedReloadSecurity, allocator: std.mem.Allocator) void {
        if (self.access_control) |*acl| acl.deinit();
        if (self.hsts_value) |value| allocator.free(value);
        self.* = .{ .access_control = null, .hsts_value = null };
    }
};

pub fn hotReloadConfig(
    allocator: std.mem.Allocator,
    worker_ctx: *WorkerContext,
    state: *GatewayState,
    http3_dispatch_ctx: anytype,
) void {
    const now_ms = compat.milliTimestamp();
    state.metricsRecordReloadAttempt();
    state.logger.info(null, "configuration hot-reload starting", .{});
    const loaded = edge_config.loadFromEnv(allocator) catch |err| {
        const msg = std.fmt.bufPrint(&state.last_reload_error, "load failed: {}", .{err}) catch "load failed";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload failed during load: {}", .{err});
        return;
    };
    edge_config.validate(&loaded) catch |err| {
        var rejected = loaded;
        rejected.deinit(allocator);
        const msg = std.fmt.bufPrint(&state.last_reload_error, "validation rejected: {}", .{err}) catch "validation rejected";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload rejected by validation: {}", .{err});
        return;
    };
    edge_config.warnRiskyConfig(&loaded);
    const cfg_ptr = allocator.create(edge_config.EdgeConfig) catch {
        var rejected = loaded;
        rejected.deinit(allocator);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..19], "allocation failed  ");
        state.last_reload_error_len = 19;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload allocation failed", .{});
        return;
    };
    cfg_ptr.* = loaded;
    var prepared_security = PreparedReloadSecurity.init(allocator, cfg_ptr) catch |err| {
        cfg_ptr.deinit(allocator);
        allocator.destroy(cfg_ptr);
        const msg = std.fmt.bufPrint(&state.last_reload_error, "security policy preparation failed: {}", .{err}) catch "security policy preparation failed";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload rejected while preparing access control and HSTS: {}", .{err});
        return;
    };
    defer prepared_security.deinit(allocator);
    const prepared_version = worker_ctx.config_store.prepareOwned(cfg_ptr) catch {
        cfg_ptr.deinit(allocator);
        allocator.destroy(cfg_ptr);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..21], "bookkeeping failed   ");
        state.last_reload_error_len = 21;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload bookkeeping failed", .{});
        return;
    };

    {
        var current_lease = worker_ctx.config_store.acquire();
        const listener_shards_changed = listenerShardConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (listener_shards_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "listener shard topology changed; restart required", .{}) catch "listener shard topology changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_LISTENER_SHARDS changed; restart the process to change listener shard topology", .{});
            return;
        }
    }
    {
        // #368 Slice 3: the process-owned early-data replay store/gate are
        // constructed once in `edge_gateway.run()` from the startup config
        // and shared for the process lifetime — there is no in-place
        // rebuild path here (unlike `applyReloadedRuntimeConfig`'s simple
        // field copies), because rebuilding would discard replay history
        // and require a fresh startup-quarantine handoff. This check must
        // run before any runtime mutation below (`updateProtocolPolicy` and
        // everything after it) so a reload that fails this check never
        // partially applies: publishing a config that claims a different
        // replay mode/capacity than what is actually installed would be a
        // real security/observability divergence for this security-sensitive
        // setting, so reject the whole reload instead — the previous config,
        // and every other still-active runtime object, stay coherent.
        // Operators must restart to change replay mode or capacity.
        var current_lease = worker_ctx.config_store.acquire();
        const replay_config_changed = earlyDataReplayConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (replay_config_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "early-data replay mode/capacity changed; restart required", .{}) catch "early-data replay configuration changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE/_MAX_ENTRIES changed; restart the process to change replay mode or capacity (the process-owned replay store cannot be safely rebuilt without discarding replay history)", .{});
            return;
        }
    }
    {
        var current_lease = worker_ctx.config_store.acquire();
        const h3_listener_config_changed = http3ListenerConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (h3_listener_config_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "HTTP/3 listener configuration changed; restart required", .{}) catch "HTTP/3 listener configuration changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: HTTP/3 listener-owned configuration changed; restart the process to change http3_enabled, quic_port, migration, Retry, 0-RTT, datagram sizing, ECN, or observability artifact destinations", .{});
            return;
        }
    }
    {
        // The circuit breaker is process-owned state constructed once at
        // startup. Reloading its policy in place would require generation-safe
        // permit migration, so reject those changes and keep config/state
        // coherent until a restart installs the new policy.
        var current_lease = worker_ctx.config_store.acquire();
        const circuit_breaker_config_changed = circuitBreakerConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (circuit_breaker_config_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "circuit breaker configuration changed; restart required", .{}) catch "circuit breaker configuration changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_CB_THRESHOLD/_TIMEOUT_MS changed; restart the process to change circuit breaker policy", .{});
            return;
        }
    }
    {
        var current_lease = worker_ctx.config_store.acquire();
        const source_changed = (current_lease.cfg.tls_native_ticket_keys_path.len == 0) != (cfg_ptr.tls_native_ticket_keys_path.len == 0);
        current_lease.release();
        if (source_changed or (cfg_ptr.tls_native_ticket_keys_path.len > 0 and worker_ctx.resumption_runtime == null)) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "native ticket-key source changed; restart required", .{}) catch "native ticket-key source changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.metrics_mutex.lock();
            state.metrics.recordTicketKeyReload(.reload_rejected);
            state.metrics_mutex.unlock();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH source mode changed or no native resumption runtime exists; restart the process to switch persistent ticket-key ownership", .{});
            return;
        }
    }
    if (edge_config.is_appliance_tls_profile) {
        // Appliance TLS profile (#392): the identity is startup-loaded and a
        // hot reload must never silently accept changed credential inputs
        // while continuing to serve the old credentials. Reject the whole
        // reload when any credential-affecting field changes; the previous
        // configuration and provider remain active and coherent.
        //
        // Gate on the build-time profile, not `worker_ctx.appliance_credentials
        // != null`: a server that *started* without TLS configured (no owner
        // constructed) must still reject a reload that turns TLS on, rather
        // than publishing a TLS-marked config while `native_tls_provider`
        // stays null and new connections silently continue over plaintext.
        var current_lease = worker_ctx.config_store.acquire();
        const credential_config_changed = applianceCredentialConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (credential_config_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "appliance TLS credential configuration changed; restart required", .{}) catch "appliance TLS credential configuration changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: appliance TLS credential configuration (certificate/key path, tls_server_name, or SNI certificates) changed; restart the appliance to rotate credentials", .{});
            return;
        }
    }
    // #634 (#641 review): the native credential store and
    // `native_tls_provider` are created only when TLS files exist at
    // startup, and `startNewConnection` dispatches on that startup-fixed
    // optional. A reload that turns TLS on for a process that started
    // plaintext (or off for one that started with TLS) would therefore
    // publish a config the runtime cannot honor — "reload applied" while
    // new connections keep the old transport. Reject the topology change
    // outright before any runtime mutation; enabling or disabling TLS is
    // restart-owned. (On the appliance profile the credential-config check
    // above already rejects these same transitions with its own message;
    // this guard is the generic-native owner of the rule.)
    {
        var current_lease = worker_ctx.config_store.acquire();
        const tls_topology_changed = edge_config.hasTlsFiles(current_lease.cfg) != edge_config.hasTlsFiles(cfg_ptr);
        current_lease.release();
        if (tls_topology_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "enabling or disabling native TLS requires restart", .{}) catch "enabling or disabling native TLS requires restart";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_TLS_CERT_PATH/TARDIGRADE_TLS_KEY_PATH would enable or disable TLS on a running native-TLS process; the native credential owner is startup-fixed, so restart to change TLS topology (#634)", .{});
            return;
        }
    }
    // #629's mixed TLS-adapter/native-HTTP3 composition — stable TCP served
    // by the OpenSSL `TlsTerminator` while native HTTP/3 used its own
    // `NativeCredentialStore` — no longer exists: #649 retired the OpenSSL
    // production backend and the downstream terminator slot entirely, so
    // every credential owner is native.
    var prepared_native_credentials: ?http.native_tls_connection.NativeCredentialStore.PreparedReload = null;
    defer if (prepared_native_credentials) |*prepared| prepared.deinit();
    if (worker_ctx.native_credentials) |store| {
        var sni_specs = allocator.alloc(http.native_tls_connection.SniCertSpec, cfg_ptr.tls_sni_certs.len) catch {
            worker_ctx.config_store.destroyVersion(prepared_version);
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            @memcpy(state.last_reload_error[0..21], "bookkeeping failed   ");
            state.last_reload_error_len = 21;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload native TLS SNI allocation failed", .{});
            return;
        };
        defer allocator.free(sni_specs);
        for (cfg_ptr.tls_sni_certs, 0..) |sc, i| {
            sni_specs[i] = .{ .server_name = sc.server_name, .cert_path = sc.cert_path, .key_path = sc.key_path };
        }
        prepared_native_credentials = store.prepareReloadFromFiles(cfg_ptr.tls_cert_path, cfg_ptr.tls_key_path, sni_specs) catch |err| {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "native TLS credential reload failed: {}", .{err}) catch "native TLS credential reload failed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected by native TLS credential reload: {}", .{err});
            return;
        };
    }
    if (worker_ctx.resumption_runtime) |runtime| {
        if (cfg_ptr.tls_native_ticket_keys_path.len > 0) {
            runtime.loadPersistentTicketKeysFromFile(cfg_ptr.tls_native_ticket_keys_path) catch |err| {
                worker_ctx.config_store.destroyVersion(prepared_version);
                const msg = std.fmt.bufPrint(&state.last_reload_error, "native ticket-key reload failed: {s}", .{@errorName(err)}) catch "native ticket-key reload failed";
                state.reload_mutex.lock();
                state.last_reload_ok = false;
                state.last_reload_at_ms = now_ms;
                state.last_reload_error_len = msg.len;
                state.reload_mutex.unlock();
                state.metricsRecordReloadFailure();
                state.metrics_mutex.lock();
                state.metrics.recordTicketKeyReload(.reload_rejected);
                state.metrics_mutex.unlock();
                state.logger.warn(null, "config reload rejected by native TLS/QUIC persistent ticket-key reload: {s}", .{@errorName(err)});
                return;
            };
            state.metrics_mutex.lock();
            state.metrics.recordTicketKeyReload(.reload_accepted);
            state.metrics_mutex.unlock();
        }
    }
    if (worker_ctx.native_credentials) |store| {
        if (prepared_native_credentials) |*prepared| {
            store.commitPreparedReload(prepared) catch |err| {
                worker_ctx.config_store.destroyVersion(prepared_version);
                const msg = std.fmt.bufPrint(&state.last_reload_error, "native TLS credential publish failed: {}", .{err}) catch "native TLS credential publish failed";
                state.reload_mutex.lock();
                state.last_reload_ok = false;
                state.last_reload_at_ms = now_ms;
                state.last_reload_error_len = msg.len;
                state.reload_mutex.unlock();
                state.metricsRecordReloadFailure();
                state.logger.warn(null, "config reload rejected by native TLS credential publish: {}", .{err});
                return;
            };
            prepared_native_credentials = null;
        }
    }

    applyReloadedRuntimeConfig(cfg_ptr, state, &prepared_security);
    worker_ctx.config_store.installPrepared(prepared_version);
    http3_dispatch_ctx.cfg = cfg_ptr;
    http.access_log.deinit();
    http.access_log.init(allocator, .{
        .format = cfg_ptr.access_log_format,
        .custom_template = cfg_ptr.access_log_template,
        .min_status = cfg_ptr.access_log_min_status,
        .buffer_size_bytes = cfg_ptr.access_log_buffer_size,
        .syslog_udp_endpoint = cfg_ptr.access_log_syslog_udp,
        .redact_header_names = cfg_ptr.log_redact_headers,
    }) catch {}; // access log is best-effort; gateway continues without it
    state.reload_mutex.lock();
    state.last_reload_ok = true;
    state.last_reload_at_ms = now_ms;
    state.last_reload_error_len = 0;
    state.reload_mutex.unlock();
    state.metricsRecordReloadSuccess();
    state.logger.info(null, "configuration hot-reload applied", .{});
}

/// True when a proposed configuration changes any input that feeds the
/// startup-loaded appliance TLS credential (#392): certificate path, key
/// path, configured TLS server name, or the (necessarily empty) SNI
/// credential set.
pub fn applianceCredentialConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    if (!std.mem.eql(u8, current.tls_cert_path, proposed.tls_cert_path)) return true;
    if (!std.mem.eql(u8, current.tls_key_path, proposed.tls_key_path)) return true;
    if (!std.mem.eql(u8, current.tls_server_name, proposed.tls_server_name)) return true;
    if (current.tls_sni_certs.len != proposed.tls_sni_certs.len) return true;
    for (current.tls_sni_certs, proposed.tls_sni_certs) |a, b| {
        if (!std.mem.eql(u8, a.server_name, b.server_name)) return true;
        if (!std.mem.eql(u8, a.cert_path, b.cert_path)) return true;
        if (!std.mem.eql(u8, a.key_path, b.key_path)) return true;
    }
    return false;
}

// #649: retired `nativeCredentialPathsChanged` — it existed only to detect
// the #629 mixed OpenSSL-TCP/native-HTTP3 build, which no longer exists
// (the OpenSSL `TlsTerminator` it guarded against has been removed from
// every shipping build).

/// #368 Slice 3: true when a proposed configuration changes the
/// process-owned early-data replay store's mode or capacity. The store is
/// constructed once at startup and shared for the process lifetime (see
/// `edge_gateway.run()`); `hotReloadConfig` rejects the whole reload rather
/// than accept a published config that no longer matches the actually
/// installed store/gate.
pub fn earlyDataReplayConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.tls_native_early_data_replay_mode != proposed.tls_native_early_data_replay_mode or
        current.tls_native_early_data_replay_max_entries != proposed.tls_native_early_data_replay_max_entries;
}

pub fn http3ListenerConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.http3_enabled != proposed.http3_enabled or
        current.quic_port != proposed.quic_port or
        current.http3_enable_0rtt != proposed.http3_enable_0rtt or
        current.http3_connection_migration != proposed.http3_connection_migration or
        current.http3_retry_policy != proposed.http3_retry_policy or
        current.http3_max_datagram_size != proposed.http3_max_datagram_size or
        // #256-D: buffer sizes are socket state, set once on the live fd at
        // bind time. Changing them means a new socket, which is a listener
        // restart like every other knob here.
        current.http3_udp_recv_buffer_bytes != proposed.http3_udp_recv_buffer_bytes or
        current.http3_udp_send_buffer_bytes != proposed.http3_udp_send_buffer_bytes or
        // #256-E: same reasoning — the ECN receive option is set on the live
        // fd at bind time, and the transport's marking decision is fixed per
        // connection at creation.
        current.http3_ecn_enabled != proposed.http3_ecn_enabled or
        !std.mem.eql(u8, current.http3_qlog_dir, proposed.http3_qlog_dir) or
        !std.mem.eql(u8, current.http3_keylog_path, proposed.http3_keylog_path);
}

pub fn listenerShardConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.listener_shards != proposed.listener_shards;
}

pub fn circuitBreakerConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.cb_threshold != proposed.cb_threshold or
        current.cb_timeout_ms != proposed.cb_timeout_ms;
}

test "earlyDataReplayConfigChanged detects mode and capacity changes independently" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    try std.testing.expect(!earlyDataReplayConfigChanged(&base, &proposed));

    // disabled -> process_local
    proposed.tls_native_early_data_replay_mode = .process_local;
    try std.testing.expect(earlyDataReplayConfigChanged(&base, &proposed));
    proposed.tls_native_early_data_replay_mode = .disabled;
    try std.testing.expect(!earlyDataReplayConfigChanged(&base, &proposed));

    // process_local -> disabled (the reverse direction)
    base.tls_native_early_data_replay_mode = .process_local;
    try std.testing.expect(earlyDataReplayConfigChanged(&base, &proposed));
    base.tls_native_early_data_replay_mode = .disabled;
    try std.testing.expect(!earlyDataReplayConfigChanged(&base, &proposed));

    // Capacity-only change, mode held constant.
    proposed.tls_native_early_data_replay_max_entries = base.tls_native_early_data_replay_max_entries + 1;
    try std.testing.expect(earlyDataReplayConfigChanged(&base, &proposed));
    proposed.tls_native_early_data_replay_max_entries = base.tls_native_early_data_replay_max_entries;
    try std.testing.expect(!earlyDataReplayConfigChanged(&base, &proposed));
}

test "circuitBreakerConfigChanged treats threshold and timeout as restart-only" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    try std.testing.expect(!circuitBreakerConfigChanged(&base, &proposed));

    proposed.cb_threshold = base.cb_threshold + 1;
    try std.testing.expect(circuitBreakerConfigChanged(&base, &proposed));
    proposed.cb_threshold = base.cb_threshold;
    try std.testing.expect(!circuitBreakerConfigChanged(&base, &proposed));

    base.cb_threshold = 1;
    proposed.cb_threshold = 0;
    try std.testing.expect(circuitBreakerConfigChanged(&base, &proposed));
    proposed.cb_threshold = base.cb_threshold;
    try std.testing.expect(!circuitBreakerConfigChanged(&base, &proposed));

    base.cb_threshold = 0;
    proposed.cb_threshold = 1;
    try std.testing.expect(circuitBreakerConfigChanged(&base, &proposed));
    proposed.cb_threshold = base.cb_threshold;
    try std.testing.expect(!circuitBreakerConfigChanged(&base, &proposed));

    proposed.cb_timeout_ms = base.cb_timeout_ms + 1;
    try std.testing.expect(circuitBreakerConfigChanged(&base, &proposed));
}

test "http3ListenerConfigChanged permits advertisement-only reloads" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.http3_enabled = true;
    proposed.http3_enabled = true;
    proposed.http3_alt_svc = .auto;
    proposed.http3_alt_svc_max_age_seconds = base.http3_alt_svc_max_age_seconds + 1;
    try std.testing.expect(!http3ListenerConfigChanged(&base, &proposed));

    proposed.quic_port = base.quic_port + 1;
    try std.testing.expect(http3ListenerConfigChanged(&base, &proposed));
    proposed.quic_port = base.quic_port;

    proposed.http3_retry_policy = .address_validation;
    try std.testing.expect(http3ListenerConfigChanged(&base, &proposed));
    proposed.http3_retry_policy = base.http3_retry_policy;

    // #256-D: socket buffer sizes are applied to the live descriptor at bind
    // time. A reload cannot resize the socket the listener is already reading
    // from, so changing either target has to go through a restart rather than
    // being accepted and silently ignored.
    proposed.http3_udp_recv_buffer_bytes = base.http3_udp_recv_buffer_bytes + 4096;
    try std.testing.expect(http3ListenerConfigChanged(&base, &proposed));
    proposed.http3_udp_recv_buffer_bytes = base.http3_udp_recv_buffer_bytes;

    proposed.http3_udp_send_buffer_bytes = base.http3_udp_send_buffer_bytes + 4096;
    try std.testing.expect(http3ListenerConfigChanged(&base, &proposed));
    proposed.http3_udp_send_buffer_bytes = base.http3_udp_send_buffer_bytes;

    // #256-E: the ECN receive option is socket state too, and every live
    // connection's marking decision was made when it was created.
    proposed.http3_ecn_enabled = !base.http3_ecn_enabled;
    try std.testing.expect(http3ListenerConfigChanged(&base, &proposed));
}

test "listenerShardConfigChanged requires restart for listener topology changes" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.listener_shards = 1;
    proposed.listener_shards = 1;
    try std.testing.expect(!listenerShardConfigChanged(&base, &proposed));

    proposed.listener_shards = 4;
    try std.testing.expect(listenerShardConfigChanged(&base, &proposed));
}

test "computeReloadedHttp3Advertisement withdraws active auto advertisement when reloaded off" {
    const allocator = std.testing.allocator;
    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);

    cfg.http3_enabled = true;
    cfg.http3_alt_svc = .off;
    cfg.http3_alt_svc_max_age_seconds = 60;

    const withdrawal = computeReloadedHttp3Advertisement(&cfg, true, 8443, .advertising);
    try std.testing.expectEqual(http.http3_handler.Advertisement.clear, withdrawal);
    try std.testing.expectEqual(http.http3_runtime.EffectiveAdvertisementState.clearing, stateForHttp3Advertisement(true, true, withdrawal));

    const already_off = computeReloadedHttp3Advertisement(&cfg, true, 8443, .ready_advertisement_disabled);
    try std.testing.expectEqual(http.http3_handler.Advertisement.disabled, already_off);

    cfg.http3_alt_svc = .auto;
    const active = computeReloadedHttp3Advertisement(&cfg, true, 8443, .clearing);
    try std.testing.expectEqualDeep(http.http3_handler.Advertisement{ .active = .{ .port = 8443, .max_age_seconds = 60 } }, active);
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

// #649: retired "#368 Slice 3: hotReloadConfig rejects a combined
// replay+protocol-policy reload atomically..." — it drove a real
// `TlsTerminator.init()` (then in `http/tls_termination.zig`, since renamed
// to `http/upstream_tls.zig` and holding only the native upstream client) to
// prove ordering against the OpenSSL terminator specifically; that
// terminator, and the downstream `TlsTerminator`/`TlsConnection` type pair
// entirely, no longer exist in any shipping build.
// `earlyDataReplayConfigChanged` above still covers the ordering-independent
// comparator logic in every profile.

test "applianceCredentialConfigChanged detects credential-affecting fields" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    try std.testing.expect(!applianceCredentialConfigChanged(&base, &proposed));

    const original_cert = proposed.tls_cert_path;
    proposed.tls_cert_path = "/changed/cert.pem";
    try std.testing.expect(applianceCredentialConfigChanged(&base, &proposed));
    proposed.tls_cert_path = original_cert;

    const original_name = proposed.tls_server_name;
    proposed.tls_server_name = "changed.example.test";
    try std.testing.expect(applianceCredentialConfigChanged(&base, &proposed));
    proposed.tls_server_name = original_name;
}

test "applianceCredentialConfigChanged rejects plaintext-to-TLS and TLS-to-plaintext reloads" {
    const allocator = std.testing.allocator;

    // Server started without TLS configured (both paths empty, as
    // `loadFromEnv` defaults to when no TARDIGRADE_TLS_* env is set).
    var plaintext = try edge_config.loadFromEnv(allocator);
    defer plaintext.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), plaintext.tls_cert_path.len);
    try std.testing.expectEqual(@as(usize, 0), plaintext.tls_key_path.len);

    // Reloaded config now turns TLS on. `hotReloadConfig` must reject this
    // reload in the appliance profile regardless of whether the running
    // process ever constructed an `ApplianceCredentials` owner at startup —
    // there is no owner to safely graft new credentials onto at runtime.
    // Mutated fields are restored to their original owned allocations before
    // scope exit so the deferred `deinit()` frees the right pointers.
    var now_tls = try edge_config.loadFromEnv(allocator);
    defer now_tls.deinit(allocator);
    const now_tls_orig_cert = now_tls.tls_cert_path;
    const now_tls_orig_key = now_tls.tls_key_path;
    const now_tls_orig_name = now_tls.tls_server_name;
    now_tls.tls_cert_path = "/etc/appliance/tls.crt";
    now_tls.tls_key_path = "/etc/appliance/tls.key";
    now_tls.tls_server_name = "appliance.example.test";
    try std.testing.expect(applianceCredentialConfigChanged(&plaintext, &now_tls));
    now_tls.tls_cert_path = now_tls_orig_cert;
    now_tls.tls_key_path = now_tls_orig_key;
    now_tls.tls_server_name = now_tls_orig_name;

    // The reverse direction: a server that started with TLS configured must
    // also reject a reload that removes it (keeps serving the old,
    // still-valid credentials rather than silently going plaintext).
    var with_tls = try edge_config.loadFromEnv(allocator);
    defer with_tls.deinit(allocator);
    const with_tls_orig_cert = with_tls.tls_cert_path;
    const with_tls_orig_key = with_tls.tls_key_path;
    const with_tls_orig_name = with_tls.tls_server_name;
    with_tls.tls_cert_path = "/etc/appliance/tls.crt";
    with_tls.tls_key_path = "/etc/appliance/tls.key";
    with_tls.tls_server_name = "appliance.example.test";
    var now_plaintext = try edge_config.loadFromEnv(allocator);
    defer now_plaintext.deinit(allocator);
    try std.testing.expect(applianceCredentialConfigChanged(&with_tls, &now_plaintext));
    with_tls.tls_cert_path = with_tls_orig_cert;
    with_tls.tls_key_path = with_tls_orig_key;
    with_tls.tls_server_name = with_tls_orig_name;
}

// #649: retired the #629 mixed TLS-adapter/native-HTTP3 composition tests
// and their fixture helpers (`setupMixedFixture`, `MixedReloadHarness`,
// `LoadedIdentity`, `expectTcpLeaf`/`expectTcpSniLeaf`, ...) — the OpenSSL
// `TlsTerminator` those fixtures constructed no longer exists at all (not
// even as an inert stub; `WorkerContext` no longer has a `tls` field), so
// the scenario they proved (stable TCP and native HTTP/3 serving from two
// independent credential owners) can no longer occur.

fn applyReloadedRuntimeConfig(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    prepared_security: *PreparedReloadSecurity,
) void {
    // Warn when restart-only path/URL fields differ; they are NOT rebound here.
    if (!std.mem.eql(u8, state.session_store_path, cfg.session_store_path))
        state.logger.warn(null, "TARDIGRADE_SESSION_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.session_store_path, cfg.session_store_path });
    if (!std.mem.eql(u8, state.approval_store_path, cfg.approval_store_path))
        state.logger.warn(null, "TARDIGRADE_APPROVAL_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.approval_store_path, cfg.approval_store_path });
    if (!std.mem.eql(u8, state.approval_escalation_webhook, cfg.approval_escalation_webhook))
        state.logger.warn(null, "TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK changed on reload; restart required for new URL to take effect (active: '{s}', new: '{s}')", .{ state.approval_escalation_webhook, cfg.approval_escalation_webhook });
    if (!std.mem.eql(u8, state.transcript_store_path, cfg.transcript_store_path))
        state.logger.warn(null, "TARDIGRADE_TRANSCRIPT_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.transcript_store_path, cfg.transcript_store_path });

    state.rate_limiter_mutex.lock();
    if (state.rate_limiter) |*rl| rl.deinit();
    state.rate_limiter = if (cfg.rate_limit_rps > 0)
        http.rate_limiter.RateLimiter.init(state.allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
    else
        null;
    state.rate_limiter_mutex.unlock();

    state.proxy_cache_mutex.lock();
    if (state.proxy_cache_store) |*pc| pc.deinit();
    state.proxy_cache_store = if (cfg.proxy_cache_ttl_seconds > 0)
        http.idempotency.IdempotencyStore.init(state.allocator, cfg.proxy_cache_ttl_seconds)
    else
        null;
    state.proxy_cache_path = cfg.proxy_cache_path;
    state.proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds;
    state.proxy_cache_mutex.unlock();

    // Access control and HSTS are prepared before any reload mutation. Swap
    // them only on the successful commit path, preserving the old policy if
    // parsing or allocation failed.
    if (state.access_control) |*acl| acl.deinit();
    state.access_control = prepared_security.access_control;
    prepared_security.access_control = null;

    state.runtime_mutex.lock();
    state.add_headers = cfg.add_headers;
    const previous_h3_advertisement_state = state.http3_advertisement_state;
    if (state.http3_alt_svc) |value| state.allocator.free(value);
    const runtime_ready = if (state.http3_runtime) |runtime| runtime.snapshot().server_bootstrapped else false;
    const advertisement = computeReloadedHttp3Advertisement(
        cfg,
        runtime_ready,
        if (state.http3_runtime) |runtime| runtime.snapshot().quic_port else cfg.quic_port,
        previous_h3_advertisement_state,
    );
    state.http3_alt_svc = http.http3_handler.formatAdvertisement(state.allocator, advertisement) catch null;
    state.http3_advertisement_state = stateForHttp3Advertisement(cfg.http3_enabled, runtime_ready, advertisement);
    if (state.hsts_value.len > 0) state.allocator.free(state.hsts_value);
    state.hsts_value = prepared_security.hsts_value.?;
    prepared_security.hsts_value = null;
    state.security_headers = blk: {
        var s = if (cfg.security_headers_enabled)
            http.security_headers.SecurityHeaders.api
        else
            http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "", .cross_origin_opener_policy = "", .cross_origin_resource_policy = "" };
        s.strict_transport_security = state.hsts_value;
        break :blk s;
    };
    state.max_connections_per_ip = cfg.max_connections_per_ip;
    state.max_active_connections = cfg.max_active_connections;
    state.max_in_flight_requests = cfg.max_in_flight_requests;
    state.max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes;
    state.connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE;
    state.proxy_buffer_limits = cfg.proxy_buffer_limits;
    // Aggregate hard limits take effect immediately, at every scope and for
    // origins that already exist. The per-stream policy — and the HTTP/2
    // receive window derived from it — reaches connections opened after this
    // point: SETTINGS_INITIAL_WINDOW_SIZE is negotiated once per connection, so
    // a peer already holding credit is still judged by what it was granted.
    state.proxy_buffer_global_account.setHardLimit(cfg.proxy_buffer_limits.global_hard_limit);
    state.h2_pool.setProxyBufferLimits(cfg.proxy_buffer_limits);
    state.upstream_pool.setProxyBufferLimits(cfg.proxy_buffer_limits);
    state.tls_buffer_limits = cfg.tls_buffer_limits;
    state.compression_config = .{
        .enabled = cfg.compression_enabled,
        .min_size = cfg.compression_min_size,
        .brotli_enabled = cfg.compression_brotli_enabled,
        .brotli_quality = cfg.compression_brotli_quality,
    };
    state.logger.min_level = cfg.log_level;
    state.runtime_mutex.unlock();
}

fn computeReloadedHttp3Advertisement(
    cfg: *const edge_config.EdgeConfig,
    runtime_ready: bool,
    runtime_port: u16,
    previous_state: http.http3_runtime.EffectiveAdvertisementState,
) http.http3_handler.Advertisement {
    if (!cfg.http3_enabled or !runtime_ready) return .disabled;
    if (cfg.http3_alt_svc == .off) {
        return switch (previous_state) {
            .advertising, .clearing, .draining => .clear,
            else => .disabled,
        };
    }
    return .{ .active = .{
        .port = runtime_port,
        .max_age_seconds = cfg.http3_alt_svc_max_age_seconds,
    } };
}

fn stateForHttp3Advertisement(
    http3_enabled: bool,
    runtime_ready: bool,
    advertisement: http.http3_handler.Advertisement,
) http.http3_runtime.EffectiveAdvertisementState {
    return switch (advertisement) {
        .disabled => if (!http3_enabled) .disabled else if (!runtime_ready) .configured_unavailable else .ready_advertisement_disabled,
        .clear => .clearing,
        .active => .advertising,
    };
}

pub fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var fc = try compat.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer fc.close();
    _ = std.c.lseek(fc.file.handle, 0, std.c.SEEK.END);
    _ = std.c.dup2(fc.file.handle, std.Io.File.stderr().handle);
}

/// Refresh DNS-discovered upstreams when the refresh interval has elapsed.
/// Discovered addresses supplement the statically configured upstream pool
/// via GatewayState.dns_discovery; the selection functions read from both.
pub fn runDnsDiscoveryRefresh(_: *const edge_config.EdgeConfig, state: *GatewayState) void {
    const now_ms = http.event_loop.monotonicMs();
    if (state.dns_discovery.needsRefresh(now_ms)) {
        state.dns_discovery.refresh(now_ms);
    }
}

test "applyReloadedRuntimeConfig updates exported proxy buffer limits" {
    const allocator = std.testing.allocator;
    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    cfg.proxy_buffer_limits = .{
        .per_stream_low_watermark = 128 * 1024,
        .per_stream_high_watermark = 384 * 1024,
        .per_stream_hard_limit = 512 * 1024,
        .per_origin_hard_limit = 2 * 1024 * 1024,
        .global_hard_limit = 4 * 1024 * 1024,
    };
    cfg.tls_buffer_limits.outbound_ciphertext.high = cfg.tls_buffer_limits.outbound_ciphertext.low + 16;

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.rate_limiter_mutex = .{};
    state.rate_limiter = null;
    state.proxy_cache_mutex = .{};
    state.proxy_cache_store = null;
    state.proxy_cache_path = "";
    state.proxy_cache_ttl_seconds = 0;
    state.runtime_mutex = .{};
    state.access_control = null;
    // `metricsToPrometheus` (called below) locks this via `muxMetricsSnapshot`
    // — left uninitialized, `.lock()` on garbage memory hangs indefinitely
    // rather than failing loudly. This test was previously never compiled or
    // run at all (gateway_shutdown.zig was not wired into any `zig build
    // test` discovery path — see the `test { _ = @import(...) }` aggregator
    // in edge_gateway.zig), so this bug went unnoticed until that gap was
    // fixed.
    state.connection_mutex = .{};
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.add_headers = &.{};
    state.http3_alt_svc = null;
    state.http3_advertisement_state = .disabled;
    state.http3_runtime = null;
    state.hsts_value = "";
    state.security_headers = http.security_headers.SecurityHeaders.api;
    state.max_connections_per_ip = 0;
    state.max_active_connections = 0;
    state.max_in_flight_requests = 0;
    state.max_total_connection_memory_bytes = 0;
    state.connection_memory_estimate_bytes = MAX_REQUEST_SIZE;
    state.proxy_buffer_limits = http.proxy_buffer_account.Limits.defaults();
    // Rendered as a gauge by `metricsToPrometheus` below, and this state starts
    // as `undefined`, so it has to be initialized rather than inherited.
    state.proxy_buffer_global_account = http.proxy_buffer_account.Aggregate.init(.global, 0);
    state.tls_buffer_limits = @import("tls_core").encrypted_stream.BufferLimits.defaults();
    state.compression_config = .{};
    state.logger = http.logger.Logger.init(.info, "test");
    state.upstream_pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    defer state.upstream_pool.deinit();
    state.h2_pool = http.upstream_h2.H2ConnPool.init(allocator, .{});
    defer state.h2_pool.deinit();
    state.mux_subscriptions_by_device = std.StringHashMap(usize).init(allocator);
    defer state.mux_subscriptions_by_device.deinit();
    state.session_store_path = "";
    state.approval_store_path = "";
    state.approval_escalation_webhook = "";
    state.transcript_store_path = "";

    allocator.free(cfg.access_control_rules);
    cfg.access_control_rules = try allocator.dupe(u8, "deny 203.0.113.0/24");
    var prepared_security = try PreparedReloadSecurity.init(allocator, &cfg);
    defer prepared_security.deinit(allocator);
    applyReloadedRuntimeConfig(&cfg, &state, &prepared_security);
    defer if (state.access_control) |*acl| acl.deinit();
    defer if (state.hsts_value.len > 0) allocator.free(state.hsts_value);

    try std.testing.expectEqual(http.access_control.AccessResult.denied, state.access_control.?.check("203.0.113.4"));

    const prom = try state.metricsToPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_config_limit_bytes{direction=\"upstream_to_downstream\",scope=\"stream\",limit=\"high\"} 393216\n") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_buffer_config_limit_bytes{direction=\"upstream_to_downstream\",scope=\"global\",limit=\"hard\"} 4194304\n") != null);
    const tls_high = try std.fmt.allocPrint(allocator, "tardigrade_tls_buffer_config_limit_bytes{{queue=\"outbound_ciphertext\",limit=\"high\"}} {d}\n", .{cfg.tls_buffer_limits.outbound_ciphertext.high});
    defer allocator.free(tls_high);
    try std.testing.expect(std.mem.find(u8, prom, tls_high) != null);
}

/// Context passed to the background health-probe thread.
const HealthProbeTask = struct {
    state: *GatewayState,
    config_store: *ReloadableConfigStore,
    allocator: std.mem.Allocator,
};

/// Background thread that runs all active health probes without blocking the
/// main event loop. Clears GatewayState.health_probe_running on completion.
fn activeHealthProbeThread(task: *HealthProbeTask) void {
    const allocator = task.allocator;
    const state = task.state;
    const config_store = task.config_store;
    allocator.destroy(task);

    defer state.health_probe_running.store(false, .release);

    var cfg_lease = config_store.acquire();
    defer cfg_lease.release();
    const cfg = cfg_lease.cfg;

    if (cfg.upstream_base_urls.len > 0) {
        for (cfg.upstream_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, base_url);
        }
        for (cfg.upstream_backup_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, base_url);
        }
    } else {
        probeSingleUpstream(cfg, state, cfg.upstream_base_url);
    }

    for (cfg.upstream_chat_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_chat_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_commands_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_commands_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }

    // Also probe DNS-discovered upstreams when active health checks are enabled.
    if (state.dns_discovery.config.host.len > 0) {
        state.dns_discovery.mutex.lock();
        // Snapshot URLs under the discovery lock, then probe without it to avoid
        // blocking the discovery refresh thread.
        var discovered_buf: [32][]u8 = undefined;
        const n = @min(state.dns_discovery.urls.items.len, discovered_buf.len);
        for (state.dns_discovery.urls.items[0..n], 0..) |url, i| discovered_buf[i] = url;
        state.dns_discovery.mutex.unlock();
        for (discovered_buf[0..n]) |url| {
            probeSingleUpstream(cfg, state, url);
        }
    }

    state.metrics_mutex.lock();
    state.metrics.recordHealthProbeRun();
    state.metrics_mutex.unlock();
}

/// Schedule a background health-probe batch if one is not already running.
/// Returns immediately; actual probing runs in a detached thread so the main
/// event loop is never blocked by upstream HTTP round-trips.
pub fn runActiveHealthChecks(cfg: *const edge_config.EdgeConfig, state: *GatewayState, config_store: *ReloadableConfigStore) void {
    if (cfg.upstream_active_health_interval_ms == 0) return;

    const now_ms = http.event_loop.monotonicMs();
    if (state.next_active_health_probe_ms != 0 and now_ms < state.next_active_health_probe_ms) return;
    state.next_active_health_probe_ms = now_ms + cfg.upstream_active_health_interval_ms;

    // Skip if a previous batch is still in flight.
    if (state.health_probe_running.load(.acquire)) return;
    state.health_probe_running.store(true, .release);

    const task = state.allocator.create(HealthProbeTask) catch {
        state.health_probe_running.store(false, .release);
        return;
    };
    task.* = .{
        .state = state,
        .config_store = config_store,
        .allocator = state.allocator,
    };

    const thread = std.Thread.spawn(.{}, activeHealthProbeThread, .{task}) catch {
        state.health_probe_running.store(false, .release);
        state.allocator.destroy(task);
        return;
    };
    thread.detach();
}

const activeHealthConfig = gs.activeHealthConfig;

pub fn runProxyCacheMaintenance(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (cfg.proxy_cache_ttl_seconds == 0) return;
    const interval = cfg.proxy_cache_manager_interval_ms;
    if (interval == 0) return;
    const now_ms = http.event_loop.monotonicMs();
    if (state.next_proxy_cache_maintenance_ms != 0 and now_ms < state.next_proxy_cache_maintenance_ms) return;
    state.next_proxy_cache_maintenance_ms = now_ms + interval;

    state.proxy_cache_mutex.lock();
    defer state.proxy_cache_mutex.unlock();
    if (state.proxy_cache_store) |*store| {
        _ = store.cleanupExpired();
    }
}

fn probeSingleUpstream(cfg: *const edge_config.EdgeConfig, state: *GatewayState, base_url: []const u8) void {
    const health_cfg = activeHealthConfig(cfg, base_url);
    const probe_base = if (unixSocketPathFromEndpoint(base_url) != null) "http://localhost" else base_url;
    const probe_url = http.health_checker.buildProbeUrl(state.allocator, probe_base, health_cfg.path) catch |err| {
        state.logger.warn(null, "active health probe url build failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    defer state.allocator.free(probe_url);

    const uri = std.Uri.parse(probe_url) catch |err| {
        state.logger.warn(null, "active health probe uri parse failed for {s}: {}", .{ probe_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };

    if (unixSocketPathFromEndpoint(base_url)) |socket_path| {
        const status_code = probeUnixSocketUpstream(socket_path, uri, cfg.upstream_active_health_timeout_ms) catch |err| {
            state.logger.warn(null, "active health probe unix request failed for {s}: {}", .{ base_url, err });
            state.recordActiveProbeResult(cfg, base_url, false);
            return;
        };
        state.recordActiveProbeResult(cfg, base_url, health_cfg.statusIsHealthy(status_code));
        return;
    }

    const status_code = probeTcpHttpUpstream(state.allocator, uri, cfg.upstream_active_health_timeout_ms) catch |err| {
        state.logger.warn(null, "active health probe tcp request failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    state.recordActiveProbeResult(cfg, base_url, health_cfg.statusIsHealthy(status_code));
}

fn probeUnixSocketUpstream(socket_path: []const u8, uri: std.Uri, timeout_ms: u32) !u16 {
    var stream = try compat.connectUnixSocket(socket_path);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
    }

    var request_target_buf = std.array_list.Managed(u8).init(std.heap.page_allocator);
    defer request_target_buf.deinit();
    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    try request_target_buf.appendSlice(path_raw);
    if (uri.query) |query| {
        try request_target_buf.appendSlice("?");
        try request_target_buf.appendSlice(uriComponentBytes(query));
    }

    try stream.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{request_target_buf.items});

    var response_buf: [256]u8 = undefined;
    var used: usize = 0;
    while (used < response_buf.len) {
        const n = try stream.read(response_buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.find(u8, response_buf[0..used], "\r\n")) |line_end| {
            var parts = std.mem.splitScalar(u8, response_buf[0..line_end], ' ');
            _ = parts.next() orelse return error.InvalidHttpResponse;
            const status_str = parts.next() orelse return error.InvalidHttpResponse;
            return std.fmt.parseInt(u16, status_str, 10);
        }
    }

    return error.InvalidHttpResponse;
}

/// Probe a TCP/HTTP upstream with a bounded timeout, mirroring
/// probeUnixSocketUpstream but over a regular TCP connection. Uses a raw
/// socket so we can apply SO_RCVTIMEO and SO_SNDTIMEO before the HTTP
/// round-trip, preventing hung probes from blocking the health-check batch.
fn probeTcpHttpUpstream(allocator: std.mem.Allocator, uri: std.Uri, timeout_ms: u32) !u16 {
    const host = if (uri.host) |h| switch (h) {
        .raw => |r| r,
        .percent_encoded => |pe| pe,
    } else return error.InvalidHttpResponse;
    const port: u16 = if (uri.port) |p| p else 80;

    var stream = try compat.tcpConnectToHost(allocator, host, port);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
    }

    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    try stream.print("GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ path_raw, host });

    var response_buf: [256]u8 = undefined;
    var used: usize = 0;
    while (used < response_buf.len) {
        const n = try stream.read(response_buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.find(u8, response_buf[0..used], "\r\n")) |line_end| {
            var parts = std.mem.splitScalar(u8, response_buf[0..line_end], ' ');
            _ = parts.next() orelse return error.InvalidHttpResponse;
            const status_str = parts.next() orelse return error.InvalidHttpResponse;
            return std.fmt.parseInt(u16, status_str, 10);
        }
    }

    return error.InvalidHttpResponse;
}
