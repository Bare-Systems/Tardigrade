//! `tardi acme-account` (#832, phase A2): the only consumer of the validated
//! automatic-HTTPS configuration before activation exists. It opens the ACME
//! state directory, loads the CA trust anchors, and creates or loads the
//! account — and stops there. It never requests an order or touches a
//! certificate. Available only in builds with `-Dacme-experimental`.
//!
//! Output is non-sensitive by construction: the account is identified by a
//! 4-byte fingerprint, failures by class and static error name.

const std = @import("std");
const acme = @import("http.zig").acme;
const acme_tls_dialer = @import("http.zig").acme_tls_dialer;
const edge_config = @import("edge_config.zig");
const compat = @import("zig_compat");

const client = acme.client;
const transport = acme.transport;

/// Heap-owned bundle so the session's borrowed transport outlives `open`.
pub const Opened = struct {
    allocator: std.mem.Allocator,
    transport: transport.Transport,
    session: *client.Session,

    pub fn close(self: *Opened) void {
        self.session.close();
        self.allocator.destroy(self);
    }
};

pub fn sessionConfig(cfg: *const edge_config.EdgeConfig) client.Config {
    return .{
        .directory_url = cfg.tls_acme_directory_url,
        .contact_email = cfg.tls_acme_email,
        .terms_of_service_agreed = cfg.tls_acme_agree_tos,
        .account_key_path = cfg.tls_acme_account_key_path,
    };
}

/// Open (create or load) the account for `cfg` over `dialer`.
pub fn openAccount(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    dialer: transport.Dialer,
    now_unix: i64,
) client.Error!*Opened {
    const opened = try allocator.create(Opened);
    errdefer allocator.destroy(opened);
    opened.allocator = allocator;
    opened.transport = .{ .allocator = allocator, .dialer = dialer };

    var state = try acme.state.StateDir.open(cfg.tls_acme_cert_dir);
    defer state.close();
    opened.session = try client.Session.open(allocator, &opened.transport, &state, sessionConfig(cfg), now_unix);
    return opened;
}

/// Run the command against the real CA: trust anchors are loaded first (a
/// missing system bundle is a startup error, not a first-use surprise).
pub fn execute(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, out: anytype) !void {
    const snapshot = transport.TrustAnchorSnapshot.load(allocator, cfg.tls_acme_ca_bundle_path) catch |err| {
        try out.print("acme-account: failed (class=transport, error={s}): CA trust anchors unavailable\n", .{@errorName(err)});
        return error.AcmeAccountFailed;
    };
    var dialer = acme_tls_dialer.TlsDialer.init(snapshot);
    snapshot.release(); // the dialer holds its own reference
    defer dialer.deinit();

    const opened = openAccount(allocator, cfg, dialer.dialer(), compat.unixTimestamp()) catch |err| {
        try out.print("acme-account: failed (class={s}, error={s})\n", .{ @tagName(client.classify(err)), @errorName(err) });
        return error.AcmeAccountFailed;
    };
    defer opened.close();
    try printSummary(out, opened.session);
}

pub fn printSummary(out: anytype, session: *client.Session) !void {
    const fp = session.client.kidFingerprint().?;
    try out.print("acme-account: ok ({s}) account={s}\n", .{ if (session.created) "created" else "loaded", fp });
}

// ---------------------------------------------------------------------------

const testing = std.testing;

fn baseConfig(allocator: std.mem.Allocator, state_dir: []const u8) !edge_config.EdgeConfig {
    var cfg = try edge_config.loadFromEnv(allocator);
    errdefer cfg.deinit(allocator);
    cfg.tls_acme_enabled = true;
    allocator.free(cfg.tls_acme_directory_url);
    cfg.tls_acme_directory_url = try allocator.dupe(u8, "https://ca.test/directory");
    cfg.tls_acme_agree_tos = true;
    allocator.free(cfg.tls_acme_cert_dir);
    cfg.tls_acme_cert_dir = try allocator.dupe(u8, state_dir);
    return cfg;
}

test "acme-account: creates then loads the account from a validated config (#832)" {
    const fake = acme.fake_ca;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(compat.io(), &buf);
    const state_path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
    defer testing.allocator.free(state_path);

    var cfg = try baseConfig(testing.allocator, state_path);
    defer cfg.deinit(testing.allocator);

    var ca = fake.FakeCa.init(testing.allocator);
    defer ca.deinit();

    var out_buf: [256]u8 = undefined;
    const first = try openAccount(testing.allocator, &cfg, ca.dialer(), 1_700_000_000);
    try testing.expect(first.session.created);
    var w1 = std.Io.Writer.fixed(&out_buf);
    try printSummary(&w1, first.session);
    try testing.expect(std.mem.startsWith(u8, w1.buffered(), "acme-account: ok (created) account="));
    // Output never carries URLs or key material.
    try testing.expect(std.mem.indexOf(u8, w1.buffered(), "https://") == null);
    try testing.expect(std.mem.indexOf(u8, w1.buffered(), "PRIVATE") == null);
    first.close();

    // Restart: loaded from state, no CA traffic needed.
    ca.script.refuse_dial = true;
    const requests = ca.log.items.len;
    const second = try openAccount(testing.allocator, &cfg, ca.dialer(), 1_700_000_100);
    defer second.close();
    try testing.expect(!second.session.created);
    try testing.expectEqual(requests, ca.log.items.len);
    try testing.expectEqual(@as(usize, 1), ca.accounts.items.len);
}
