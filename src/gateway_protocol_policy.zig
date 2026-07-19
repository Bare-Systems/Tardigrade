const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

pub fn listenerPolicyFromConfig(cfg: *const edge_config.EdgeConfig) http.negotiated_dispatch.ListenerProtocolPolicy {
    return .{
        .http1_enabled = cfg.http1_enabled,
        .http2_enabled = cfg.http2_enabled,
        .allow_http1_without_alpn = cfg.tls_http1_no_alpn_fallback,
    };
}

test "listener policy follows acquired config lease across reload publication" {
    const std = @import("std");
    const gs = @import("gateway_state.zig");

    var cfg_a = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .http1_enabled = true,
        .http2_enabled = false,
        .tls_http1_no_alpn_fallback = true,
    });
    var cfg_b = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .http1_enabled = false,
        .http2_enabled = true,
        .tls_http1_no_alpn_fallback = false,
    });

    var store = try gs.ReloadableConfigStore.initBorrowed(std.testing.allocator, &cfg_a);
    defer store.deinit();

    var lease_a = store.acquire();
    defer lease_a.release();
    const policy_a = listenerPolicyFromConfig(lease_a.cfg);

    try store.retired.ensureUnusedCapacity(std.testing.allocator, 1);
    const version_b = try gs.ReloadableConfigStore.createBorrowedVersion(std.testing.allocator, &cfg_b);
    store.installPrepared(version_b);

    var lease_b = store.acquire();
    defer lease_b.release();
    const policy_b = listenerPolicyFromConfig(lease_b.cfg);

    try std.testing.expectEqual(http.tls_termination.NegotiatedProtocol.http1_1, try http.negotiated_dispatch.selectNegotiatedProtocol("http/1.1", policy_a));
    try std.testing.expectError(error.ProtocolDisabled, http.negotiated_dispatch.selectNegotiatedProtocol("h2", policy_a));
    try std.testing.expectEqual(http.tls_termination.NegotiatedProtocol.http2, try http.negotiated_dispatch.selectNegotiatedProtocol("h2", policy_b));
    try std.testing.expectError(error.ProtocolDisabled, http.negotiated_dispatch.selectNegotiatedProtocol("http/1.1", policy_b));
}
