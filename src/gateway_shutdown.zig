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
const gpc = @import("gateway_proxy_cache.zig");
const acme_activation = @import("acme_activation.zig");

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
        var current_lease = worker_ctx.config_store.acquire();
        const reactor_threads_changed = websocketReactorConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (reactor_threads_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "WebSocket reactor thread count changed; restart required", .{}) catch "WebSocket reactor thread count changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS changed; restart the process to change WebSocket reactor topology", .{});
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
        // #881: the dedicated ACME HTTP-01 challenge listener is bound once
        // at startup, before the privilege drop, exactly like the main and
        // HTTP/3 listeners (design docs/ACME_AUTOMATIC_HTTPS.md §8.0). A
        // changed address needs a fresh bind, so reject the reload rather
        // than silently continuing to serve the old address.
        var current_lease = worker_ctx.config_store.acquire();
        const acme_http01_listener_config_changed = acmeHttp01ListenerConfigChanged(current_lease.cfg, cfg_ptr);
        current_lease.release();
        if (acme_http01_listener_config_changed) {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "ACME HTTP-01 challenge listener address changed; restart required", .{}) catch "ACME HTTP-01 challenge listener address changed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected: TARDIGRADE_TLS_ACME_HTTP01_LISTEN changed; restart the process to change the ACME HTTP-01 challenge listener address", .{});
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
        const tls_topology_changed = edge_config.usesNativeTls(current_lease.cfg) != edge_config.usesNativeTls(cfg_ptr);
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
        // #884: an ACME-enabled process must never reload through the
        // file-only path -- `prepareReloadFromFiles` carries no managed
        // bundle at all, and `commitPreparedReload` would then have to
        // choose between silently dropping every ACME-issued identity or
        // rejecting every routine reload outright
        // (`native_tls_connection.NativeCredentialStore.has_managed_bundles`).
        // Rebuilding the complete current managed set from disk and
        // republishing through `prepareReloadFromBundles` instead means an
        // ordinary SIGHUP reload (e.g. a changed header rule) and an ACME
        // publish compose correctly no matter which one happens to run
        // first.
        if (cfg_ptr.tls_acme_enabled) {
            if (reloadAcmeManagedCredentials(allocator, store, cfg_ptr, sni_specs)) |prepared| {
                prepared_native_credentials = prepared;
            } else |err| {
                // During an ACME-only first boot there is intentionally no
                // provider snapshot yet.  Do not turn an unrelated SIGHUP
                // into `EmptyCredentialSet`: retain that uninstalled
                // provider so TLS still fails closed, and let the bootstrap
                // worker publish a complete generation later using its lease
                // on the newly installed configuration.
                if (err == error.NoActiveCredentialSet) {
                    // Nothing to prepare or commit is the correct result.
                } else {
                    worker_ctx.config_store.destroyVersion(prepared_version);
                    const msg = std.fmt.bufPrint(&state.last_reload_error, "ACME-managed native TLS credential reload failed: {}", .{err}) catch "ACME-managed native TLS credential reload failed";
                    state.reload_mutex.lock();
                    state.last_reload_ok = false;
                    state.last_reload_at_ms = now_ms;
                    state.last_reload_error_len = msg.len;
                    state.reload_mutex.unlock();
                    state.metricsRecordReloadFailure();
                    state.logger.warn(null, "config reload rejected by ACME-managed native TLS credential reload: {}", .{err});
                    return;
                }
            }
        } else {
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
    }
    // #763: rotate downstream client trust anchors with the same
    // prepare-then-publish discipline as the server identity. A bundle that
    // fails to load rejects the whole reload and the serving generation keeps
    // verifying; connections already mid-handshake pin their own generation.
    var prepared_client_policies: ?tls_core.client_trust.PolicySet.Prepared = null;
    defer if (prepared_client_policies) |*prepared| prepared.deinit();
    if (worker_ctx.client_policies) |set| {
        prepared_client_policies = cfg_ptr.prepareClientPolicies(set) catch |err| {
            worker_ctx.config_store.destroyVersion(prepared_version);
            const msg = std.fmt.bufPrint(&state.last_reload_error, "client trust reload failed: {}", .{err}) catch "client trust reload failed";
            state.reload_mutex.lock();
            state.last_reload_ok = false;
            state.last_reload_at_ms = now_ms;
            state.last_reload_error_len = msg.len;
            state.reload_mutex.unlock();
            state.metricsRecordReloadFailure();
            state.logger.warn(null, "config reload rejected by client trust (mTLS CA bundle) reload: {}", .{err});
            return;
        };
    } else if (cfg_ptr.anyClientAuth()) {
        worker_ctx.config_store.destroyVersion(prepared_version);
        const msg = std.fmt.bufPrint(&state.last_reload_error, "client certificate verification requires native TLS", .{}) catch "client certificate verification requires native TLS";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload rejected: client certificate verification enabled without a native TLS listener; restart", .{});
        return;
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
            // The ACME bootstrap worker compares this stamp before it can
            // publish a snapshot assembled from an older manual mapping.
            prepared.manual_config_generation = prepared_version.generation;
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

    if (worker_ctx.client_policies) |set| {
        if (prepared_client_policies) |*prepared| {
            // The generation being installed owns one reference (TCP
            // connections take their policy table from the config they lease);
            // the set keeps the other for new QUIC connections.
            if (prepared.snapshot) |snapshot| gs.ReloadableConfigStore.setPreparedClientPolicies(prepared_version, snapshot.retain());
            set.commit(prepared);
        }
    }

    applyReloadedRuntimeConfig(cfg_ptr, prepared_version.generation, state, &prepared_security);
    // Transfer ACL ownership to the generation it belongs to BEFORE publishing
    // that generation, so no lease can ever observe the new config without its
    // matching ACL.
    gs.ReloadableConfigStore.setPreparedAccessControl(prepared_version, prepared_security.access_control);
    prepared_security.access_control = null;
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

/// Rebuilds the complete current managed (ACME) bundle set from disk and
/// prepares a bytes-based reload carrying it alongside `cfg_ptr`'s manual
/// default/SNI credentials (#884, design §7.1: "the managed bundle set is
/// rebuilt from all groups every publish"). Used in place of
/// `prepareReloadFromFiles` for every reload while `cfg_ptr.tls_acme_enabled`
/// is true, so an ordinary file-only-looking reload never has to contend
/// with `NativeCredentialStore.has_managed_bundles`'s file-only rejection.
fn reloadAcmeManagedCredentials(
    allocator: std.mem.Allocator,
    store: *http.native_tls_connection.NativeCredentialStore,
    cfg_ptr: *const edge_config.EdgeConfig,
    sni_specs: []const http.native_tls_connection.SniCertSpec,
) !http.native_tls_connection.NativeCredentialStore.PreparedReload {
    const group_list = http.acme.groups.parse(cfg_ptr.tls_acme_domains_spec) catch return error.InvalidAcmeDomains;
    var acme_state = try http.acme.state.StateDir.open(cfg_ptr.tls_acme_cert_dir);
    defer acme_state.close();
    var bundles = try acme_activation.loadManagedBundleSet(allocator, &acme_state, &group_list, compat.unixTimestamp());
    defer bundles.deinit();
    if (cfg_ptr.tls_cert_path.len == 0 and cfg_ptr.tls_key_path.len == 0 and sni_specs.len == 0 and bundles.slice().len == 0 and !store.hasActiveCredentials()) {
        return error.NoActiveCredentialSet;
    }
    return store.prepareReloadFromBundles(cfg_ptr.tls_cert_path, cfg_ptr.tls_key_path, sni_specs, bundles.slice());
}

test "reloadAcmeManagedCredentials republishes an active managed generation that prepareReloadFromFiles would reject outright (#884)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    const hostnames = [_][]const u8{"a.example.test"};
    var leaf = try http.acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, compat.unixTimestamp() - 3600, compat.unixTimestamp() + 365 * 24 * 3600);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();

    var store = http.native_tls_connection.NativeCredentialStore.init(allocator);
    defer store.deinit();
    {
        var acme_state = try http.acme.state.StateDir.open(state_dir);
        defer acme_state.close();
        var id_buf: [http.acme.groups.group_id_len]u8 = undefined;
        const group_id = http.acme.groups.groupId(&id_buf, &hostnames);
        _ = try http.acme.activate.verifyAndPersist(allocator, &acme_state, group_id, &leaf.key, leaf.pem, .{
            .hostnames = &hostnames,
            .now = compat.unixTimestamp(),
        });
    }
    // Install it so `store.has_managed_bundles` is true, exactly the state
    // a running process would already be in by the time an unrelated
    // reload (e.g. a changed header rule) comes in.
    const leaf_key_pem = try leaf.key.toPkcs8Pem(allocator);
    defer @import("crypto").secrets.secureZeroAndFree(allocator, leaf_key_pem);
    try store.reloadFromBundles("", "", &.{}, &.{.{ .hostnames = &hostnames, .chain_pem = leaf.pem, .key_pem = leaf_key_pem }});

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    cfg.tls_acme_enabled = true;
    allocator.free(cfg.tls_acme_cert_dir);
    cfg.tls_acme_cert_dir = try allocator.dupe(u8, state_dir);
    allocator.free(cfg.tls_acme_domains_spec);
    cfg.tls_acme_domains_spec = try allocator.dupe(u8, "a.example.test");

    // The file-only path a non-ACME reload uses rejects this outright: it
    // never carries a managed bundle and the active generation already has
    // one (`NativeCredentialStore.has_managed_bundles`).
    try std.testing.expectError(error.ManagedCredentialsActive, store.prepareReloadFromFiles("", "", &.{}));

    // The ACME-aware path rebuilds the complete managed set from disk and
    // republishes it instead, succeeding where the file-only path cannot.
    var prepared = try reloadAcmeManagedCredentials(allocator, &store, &cfg, &.{});
    defer prepared.deinit();
    try store.commitPreparedReload(&prepared);
}

test "reloadAcmeManagedCredentials permits an unrelated reload before the first ACME identity exists" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
    defer allocator.free(state_dir);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    cfg.tls_acme_enabled = true;
    allocator.free(cfg.tls_acme_cert_dir);
    cfg.tls_acme_cert_dir = try allocator.dupe(u8, state_dir);
    allocator.free(cfg.tls_acme_domains_spec);
    cfg.tls_acme_domains_spec = try allocator.dupe(u8, "a.example.test");

    var store = http.native_tls_connection.NativeCredentialStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(!store.hasActiveCredentials());
    try std.testing.expectError(error.NoActiveCredentialSet, reloadAcmeManagedCredentials(allocator, &store, &cfg, &.{}));
    // The uninstalled provider remains deliberately fail-closed; the caller
    // can publish the non-credential configuration generation independently.
    try std.testing.expectError(error.NoCredentialAvailable, store.provider().selectCredential(&.{
        .role = .server,
        .server_name = "a.example.test",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    }));
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
        // #763: client-auth policy is chosen per handshake from the shared
        // SNI-keyed policy set (H1, H2 and H3 alike), so it is hot-reloadable.
        !std.mem.eql(u8, current.http3_keylog_path, proposed.http3_keylog_path);
}

pub fn listenerShardConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.listener_shards != proposed.listener_shards;
}

/// The WebSocket reactor is process-owned and constructed once at startup.
pub fn websocketReactorConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.proxy_websocket_reactor_threads != proposed.proxy_websocket_reactor_threads;
}

pub fn circuitBreakerConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.cb_threshold != proposed.cb_threshold or
        current.cb_timeout_ms != proposed.cb_timeout_ms;
}

/// #881 (review #897): the dedicated HTTP-01 challenge listener binds once at
/// startup, before the privilege drop, and borrows `cfg.tls_acme_domains` for
/// its lifetime (`Listener.start`). A reload cannot rebind the listener nor
/// swap its borrowed host set in place, so any change to the listener's
/// address, enabled state, or managed-host set -- not just the address --
/// must reject the whole reload (§8.0); otherwise the published config would
/// advertise managed hosts the running listener's admission check never
/// learns about. `tls_acme_domains_spec` is the pre-normalization source of
/// `tls_acme_domains`, so comparing it also catches reordering/case changes
/// that resolve to the same validated set -- a conservative restart-required
/// classification, never a false negative.
///
/// The listener's per-IP admission cap (`max_connections_per_ip`) is in the
/// same boat: it is copied into the listener's own startup-owned pool state
/// once in `Listener.start` and is not reachable from the normal hot-reload
/// path, unlike the main accept path's `state.max_connections_per_ip`
/// (#897 review). Without this check, lowering the configured cap while ACME
/// is active would leave the main listener enforcing the new limit while the
/// challenge listener kept silently admitting up to the old one (and a raise
/// would leave it artificially under-limited) -- so a cap change while ACME
/// is enabled is restart-required too.
///
/// `acme_renewal.Worker` (#835, A5) is the same story: every renewal/CA/
/// state-directory field it holds (`renew_days_before_expiry`, `issue.*`,
/// `state_dir_path`) is captured once from the startup `cfg` when the
/// worker is constructed and never re-read, because the worker owns the
/// process-lifetime renewal thread and has no in-place field-rebuild path
/// (unlike `applyReloadedRuntimeConfig`'s simple copies). Accepting one of
/// these changes as "reload applied" while the worker keeps using the old
/// value would silently desynchronize the two -- most dangerously for
/// `tls_acme_cert_dir`/`tls_acme_directory_url`, where the worker could keep
/// issuing against a CA/state directory the rest of the process no longer
/// believes is authoritative.
pub fn acmeHttp01ListenerConfigChanged(
    current: *const edge_config.EdgeConfig,
    proposed: *const edge_config.EdgeConfig,
) bool {
    return current.tls_acme_enabled != proposed.tls_acme_enabled or
        !std.mem.eql(u8, current.tls_acme_http01_listen, proposed.tls_acme_http01_listen) or
        !std.mem.eql(u8, current.tls_acme_domains_spec, proposed.tls_acme_domains_spec) or
        current.tls_https_redirect != proposed.tls_https_redirect or
        (current.tls_acme_enabled and
            (current.max_connections_per_ip != proposed.max_connections_per_ip or
                current.tls_acme_renew_days_before_expiry != proposed.tls_acme_renew_days_before_expiry or
                current.tls_acme_agree_tos != proposed.tls_acme_agree_tos or
                current.tls_acme_eab_requested != proposed.tls_acme_eab_requested or
                !std.mem.eql(u8, current.tls_acme_directory_url, proposed.tls_acme_directory_url) or
                !std.mem.eql(u8, current.tls_acme_cert_dir, proposed.tls_acme_cert_dir) or
                !std.mem.eql(u8, current.tls_acme_account_key_path, proposed.tls_acme_account_key_path) or
                !std.mem.eql(u8, current.tls_acme_email, proposed.tls_acme_email) or
                !std.mem.eql(u8, current.tls_acme_ca_bundle_path, proposed.tls_acme_ca_bundle_path) or
                !std.mem.eql(u8, current.tls_acme_challenges, proposed.tls_acme_challenges)));
}

test "acmeHttp01ListenerConfigChanged detects an address change (#881)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    try std.testing.expect(!acmeHttp01ListenerConfigChanged(&base, &proposed));
    // `deinit` frees this field, so the replacement must be heap-owned too.
    allocator.free(proposed.tls_acme_http01_listen);
    proposed.tls_acme_http01_listen = try allocator.dupe(u8, "127.0.0.1:8080");
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));
}

test "acmeHttp01ListenerConfigChanged detects a managed-host set change (#897 review)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    allocator.free(proposed.tls_acme_domains_spec);
    proposed.tls_acme_domains_spec = try allocator.dupe(u8, "a.example.com");
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));
}

test "acmeHttp01ListenerConfigChanged detects an enabled-flag change (#897 review)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    proposed.tls_acme_enabled = !base.tls_acme_enabled;
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));
}

test "acmeHttp01ListenerConfigChanged rejects either redirect transition (#929 review)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.tls_acme_enabled = true;
    proposed.tls_acme_enabled = true;
    base.tls_https_redirect = false;
    proposed.tls_https_redirect = true;
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));

    base.tls_https_redirect = true;
    proposed.tls_https_redirect = false;
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));
}

test "acmeHttp01ListenerConfigChanged rejects a per-IP cap change while ACME is enabled, but not while disabled (#897 review)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.tls_acme_enabled = true;
    proposed.tls_acme_enabled = true;
    base.max_connections_per_ip = 64;
    proposed.max_connections_per_ip = 2;
    // Changing *only* the cap while ACME is active must still be seen as a
    // listener-affecting change: the dedicated listener's own pool would
    // otherwise keep enforcing the stale 64 limit after a reload lowers the
    // configured cap to 2, while the main accept path enforces 2.
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));

    // The same cap change is irrelevant when ACME is not enabled: there is
    // no dedicated listener holding a stale value to diverge from.
    base.tls_acme_enabled = false;
    proposed.tls_acme_enabled = false;
    try std.testing.expect(!acmeHttp01ListenerConfigChanged(&base, &proposed));
}

test "acmeHttp01ListenerConfigChanged rejects a renewal-worker-owned field change while ACME is enabled, but not while disabled (#931 review)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.tls_acme_enabled = true;
    proposed.tls_acme_enabled = true;

    // `acme_renewal.Worker` captures `renew_days_before_expiry` once at
    // startup and never re-reads it: accepting a SIGHUP that silently
    // changes the renewal window would make the reported config and the
    // worker's actual behavior diverge.
    base.tls_acme_renew_days_before_expiry = 30;
    proposed.tls_acme_renew_days_before_expiry = 7;
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));
    proposed.tls_acme_renew_days_before_expiry = 30;

    // The CA/account/state-directory settings are even more dangerous to
    // silently diverge: the worker would keep issuing against a CA or
    // state directory the rest of the process no longer believes is
    // authoritative.
    allocator.free(proposed.tls_acme_cert_dir);
    proposed.tls_acme_cert_dir = try allocator.dupe(u8, "/tmp/other-acme-state");
    try std.testing.expect(acmeHttp01ListenerConfigChanged(&base, &proposed));

    // The same changes are irrelevant when ACME is not enabled: there is no
    // running worker holding a stale value to diverge from.
    base.tls_acme_enabled = false;
    proposed.tls_acme_enabled = false;
    try std.testing.expect(!acmeHttp01ListenerConfigChanged(&base, &proposed));
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

test "http3ListenerConfigChanged leaves client-auth policy hot-reloadable (#763)" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);
    base.http3_enabled = true;
    proposed.http3_enabled = true;

    // optional -> required, enabled -> disabled: the policy is chosen per
    // handshake from the shared SNI-keyed set, so none of it needs a restart.
    base.tls_client_verify = true;
    base.tls_client_verify_optional = true;
    proposed.tls_client_verify = true;
    proposed.tls_client_verify_optional = false;
    try std.testing.expect(!http3ListenerConfigChanged(&base, &proposed));
    proposed.tls_client_verify = false;
    try std.testing.expect(!http3ListenerConfigChanged(&proposed, &base));
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

test "websocketReactorConfigChanged requires restart for reactor topology changes" {
    const allocator = std.testing.allocator;
    var base = try edge_config.loadFromEnv(allocator);
    defer base.deinit(allocator);
    var proposed = try edge_config.loadFromEnv(allocator);
    defer proposed.deinit(allocator);

    base.proxy_websocket_reactor_threads = 0;
    proposed.proxy_websocket_reactor_threads = 0;
    try std.testing.expect(!websocketReactorConfigChanged(&base, &proposed));

    proposed.proxy_websocket_reactor_threads = 2;
    try std.testing.expect(websocketReactorConfigChanged(&base, &proposed));

    base.proxy_websocket_reactor_threads = 2;
    try std.testing.expect(!websocketReactorConfigChanged(&base, &proposed));

    proposed.proxy_websocket_reactor_threads = 4;
    try std.testing.expect(websocketReactorConfigChanged(&base, &proposed));
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
    cache_generation: u64,
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

    // Stop and join stale-while-revalidate workers and drain disk leases
    // before replacing either tier. Publishing the new generation first
    // prevents old requests from acquiring another disk lease while reload
    // waits.
    state.proxyResponseCachePrepareReload(cache_generation);

    // #901: wholesale rebuild, same convention as proxy_cache_store above --
    // simpler and still bounded than trying to generation-tag entries across
    // a reload that may have changed routing/upstreams/TLS.
    state.proxy_response_cache_mutex.lock();
    if (state.proxy_response_cache) |*prc| prc.deinit();
    state.proxy_response_cache = null;
    if (state.proxy_response_cache_disk) |*disk| disk.deinit();
    state.proxy_response_cache_disk = null;
    state.proxy_response_cache_mutex.unlock();

    const replacement_memory_cache: ?gpc.ProxyResponseCache = if (cfg.proxy_cache_ttl_seconds > 0)
        gpc.ProxyResponseCache.init(state.allocator, .{
            .max_object_bytes = cfg.proxy_response_cache_max_object_bytes,
            .max_entries = cfg.proxy_response_cache_max_entries,
            .max_total_bytes = cfg.proxy_response_cache_max_total_bytes,
            .max_vary_variants = cfg.proxy_response_cache_max_vary_variants,
        })
    else
        null;
    // Open/reconcile outside the memory-cache mutex: startup directory I/O
    // cannot stall ordinary in-memory lookups.
    const replacement_disk_cache = gs.openProxyResponseCacheDisk(state.allocator, cfg);

    state.proxy_response_cache_mutex.lock();
    state.proxy_response_cache = replacement_memory_cache;
    state.proxy_response_cache_disk = replacement_disk_cache;
    state.proxy_response_cache_disk_accepting = true;
    state.proxy_response_cache_revalidation_cancel = http.cancellation.CancellationToken.init(0);
    state.proxy_response_cache_revalidation_max_concurrency.store(cfg.proxy_response_cache_revalidation_max_concurrency, .release);
    // Publish the new cache epoch in the same critical section as the swap.
    // A response still running on an older config lease can neither read nor
    // fill this cache after the lock is released.
    state.proxy_response_cache_generation = cache_generation;
    state.proxy_response_cache_mutex.unlock();

    // HSTS is prepared before any reload mutation and swapped only on the
    // successful commit path, preserving the old value if parsing or allocation
    // failed.
    //
    // The ACL is deliberately NOT swapped here. It is owned by the new
    // configuration version and handed over in `installReloadedAccessControl`,
    // so in-flight requests keep enforcing the ACL of the generation they
    // leased until that lease is released.

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
/// Resolution blocks (UDP timeouts), so it runs on the discovery's joinable
/// worker thread (`DnsDiscovery.startRefresh`); the event loop only schedules.
pub fn runDnsDiscoveryRefresh(_: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (!state.dns_discovery.enabled()) return;
    publishDiscoveryMetrics(state);
    const now_ms = http.event_loop.monotonicMs();
    if (!state.dns_discovery.needsRefresh(now_ms)) return;
    state.dns_discovery.startRefresh();
}

fn publishDiscoveryMetrics(state: *GatewayState) void {
    const disc = &state.dns_discovery;
    disc.mutex.lock();
    const stats: http.metrics.DiscoveryStats = .{
        .primary = disc.primaryCount(),
        .backup = disc.urls.items.len - disc.primaryCount(),
        .stale = disc.stale,
        .refresh_total = disc.refresh_total,
        .failures_total = disc.refresh_failures_total,
        .changes_total = disc.change_count,
    };
    disc.mutex.unlock();
    state.metrics_mutex.lock();
    state.metrics.discovery = stats;
    state.metrics_mutex.unlock();
}

test "applyReloadedRuntimeConfig atomically swaps proxy cache generation and updates buffer limits" {
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
    // Keep a real cache enabled across the two reload generations below.
    cfg.proxy_cache_ttl_seconds = 60;
    cfg.tls_buffer_limits.outbound_ciphertext.high = cfg.tls_buffer_limits.outbound_ciphertext.low + 16;

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.tunnel_reactor = null;
    state.acme_renewal_worker = null;
    state.rate_limiter_mutex = .{};
    state.rate_limiter = null;
    state.proxy_cache_mutex = .{};
    state.proxy_cache_store = null;
    state.proxy_cache_path = "";
    state.proxy_cache_ttl_seconds = 0;
    state.proxy_response_cache_mutex = .{};
    state.proxy_response_cache_mutation_lanes = @splat(.{});
    state.proxy_response_cache = null;
    state.proxy_response_cache_disk = null;
    state.proxy_response_cache_disk_accepting = true;
    state.proxy_response_cache_disk_inflight = 0;
    state.proxy_response_cache_condition = .{};
    state.proxy_response_cache_revalidation_locks = std.StringHashMap(void).init(allocator);
    defer state.proxy_response_cache_revalidation_locks.deinit();
    state.proxy_response_cache_revalidation_inflight = std.atomic.Value(u32).init(0);
    state.proxy_response_cache_revalidation_max_concurrency = std.atomic.Value(u32).init(0);
    state.proxy_response_cache_revalidation_cancel = http.cancellation.CancellationToken.init(0);
    state.runtime_mutex = .{};
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
    var first_security = try PreparedReloadSecurity.init(allocator, &cfg);
    defer first_security.deinit(allocator);
    applyReloadedRuntimeConfig(&cfg, 1, &state, &first_security);
    defer if (state.hsts_value.len > 0) allocator.free(state.hsts_value);
    defer if (state.proxy_response_cache) |*cache| cache.deinit();
    defer if (state.proxy_response_cache_disk) |*disk| disk.deinit();

    // The ACL now belongs to the configuration version rather than to
    // `GatewayState`; `applyReloadedRuntimeConfig` leaves `prepared_security`
    // holding it until the new generation is installed.
    try std.testing.expectEqual(
        http.access_control.AccessResult.denied,
        first_security.access_control.?.check("203.0.113.4"),
    );

    // Model a response from generation A reaching its cache-fill point only
    // after the live reload has installed generation B.  This is the exact
    // interleaving an upstream held mid-response creates: the stale fill
    // cannot populate B's new store, nor can a held A lease observe B's fill.
    const cache_headers: []const gpc.CacheHeaderView = &.{.{ .name = "Cache-Control", .value = "max-age=60" }};
    try state.proxyResponseCachePut(1_000, 1, "same-relative-target", .{
        .status_code = 200,
        .reason = "OK",
        .headers = cache_headers,
        .body = "origin-a",
        .ttl_seconds = 60,
    });
    var second_security = try PreparedReloadSecurity.init(allocator, &cfg);
    defer second_security.deinit(allocator);
    applyReloadedRuntimeConfig(&cfg, 2, &state, &second_security);
    try std.testing.expectError(error.ProxyResponseCacheGenerationMismatch, state.proxyResponseCachePut(1_001, 1, "same-relative-target", .{
        .status_code = 200,
        .reason = "OK",
        .headers = cache_headers,
        .body = "late-origin-a",
        .ttl_seconds = 60,
    }));
    try state.proxyResponseCachePut(1_002, 2, "same-relative-target", .{
        .status_code = 200,
        .reason = "OK",
        .headers = cache_headers,
        .body = "origin-b",
        .ttl_seconds = 60,
    });
    var cache_arena = std.heap.ArenaAllocator.init(allocator);
    defer cache_arena.deinit();
    try std.testing.expect((try state.proxyResponseCacheLookup(cache_arena.allocator(), 1, "same-relative-target", "same-relative-target", 1_003)) == null);
    const generation_b = (try state.proxyResponseCacheLookup(cache_arena.allocator(), 2, "same-relative-target", "same-relative-target", 1_003)).?;
    try std.testing.expectEqualStrings("origin-b", generation_b.body);

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

    // Also probe DNS-discovered upstreams (every priority group) when
    // active health checks are enabled.
    if (state.dns_discovery.enabled()) {
        // Copy the strings: the live set may be swapped while probing.
        const discovered: []const []const u8 = state.dns_discovery.copyUrls(state.allocator) catch &.{};
        defer {
            for (discovered) |u| state.allocator.free(u);
            if (discovered.len > 0) state.allocator.free(discovered);
        }
        for (discovered) |url| probeSingleUpstream(cfg, state, url);
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
