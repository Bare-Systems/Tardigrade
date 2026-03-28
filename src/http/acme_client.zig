/// ACME (RFC 8555) client for automated TLS certificate issuance and renewal.
///
/// Supports:
/// - ECDSA P-256 account and domain keys
/// - HTTP-01 challenge fulfillment via ChallengeStore
/// - Certificate renewal based on expiry horizon
/// - Integration with the TLS terminator's cert directory
const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ec.h");
    @cInclude("openssl/ecdsa.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509v3.h");
    @cInclude("openssl/bn.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/crypto.h");
});

pub const AcmeError = error{
    OutOfMemory,
    KeyGenFailed,
    KeyLoadFailed,
    KeySaveFailed,
    JsonParseFailed,
    NetworkError,
    AcmeProtocolError,
    ChallengeFailed,
    CsrFailed,
    CertDownloadFailed,
    CertSaveFailed,
    CertNotYetDue,
};

// ---------------------------------------------------------------------------
// Challenge token store (HTTP-01)
// ---------------------------------------------------------------------------

/// Thread-safe store for HTTP-01 ACME challenge tokens.
/// The edge gateway reads from this store to serve
/// /.well-known/acme-challenge/<token> responses.
pub const ChallengeStore = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    tokens: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *ChallengeStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tokens.deinit();
    }

    pub fn put(self: *ChallengeStore, token: []const u8, key_auth: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);
        const owned_auth = try self.allocator.dupe(u8, key_auth);
        errdefer self.allocator.free(owned_auth);
        const gop = try self.tokens.getOrPut(owned_token);
        if (gop.found_existing) {
            self.allocator.free(gop.key_ptr.*);
            self.allocator.free(gop.value_ptr.*);
            gop.key_ptr.* = owned_token;
        }
        gop.value_ptr.* = owned_auth;
    }

    /// Returns an owned copy of the key authorization for the token, or null.
    /// Caller must free the returned slice.
    pub fn getCopy(self: *ChallengeStore, allocator: std.mem.Allocator, token: []const u8) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const val = self.tokens.get(token) orelse return null;
        return allocator.dupe(u8, val) catch null;
    }

    pub fn remove(self: *ChallengeStore, token: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.tokens.fetchRemove(token)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
    }
};

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

const b64url_enc = std.base64.url_safe_no_pad.Encoder;
const b64url_dec = std.base64.url_safe_no_pad.Decoder;

fn b64urlEncode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, b64url_enc.calcSize(data.len));
    return b64url_enc.encode(out, data);
}

// ---------------------------------------------------------------------------
// EC P-256 key helpers
// ---------------------------------------------------------------------------

/// Load an EC P-256 private key from a PEM file, or generate a new one and
/// persist it to the path.
fn loadOrGenerateEcKey(allocator: std.mem.Allocator, path: []const u8) AcmeError!*c.EC_KEY {
    // Try loading from file first.
    const path_z = std.heap.c_allocator.dupeZ(u8, path) catch return error.OutOfMemory;
    defer std.heap.c_allocator.free(path_z);

    const loaded = loadEcKeyFromFile(path_z);
    if (loaded) |key| return key;

    // Generate a new P-256 key.
    const key = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse return error.KeyGenFailed;
    errdefer c.EC_KEY_free(key);
    if (c.EC_KEY_generate_key(key) != 1) return error.KeyGenFailed;

    // Persist the key.
    const bio = c.BIO_new_file(path_z.ptr, "w") orelse return error.KeySaveFailed;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_ECPrivateKey(bio, key, null, null, 0, null, null) != 1) return error.KeySaveFailed;
    _ = allocator; // used for path_z allocation above
    return key;
}

fn loadEcKeyFromFile(path_z: [:0]const u8) ?*c.EC_KEY {
    const bio = c.BIO_new_file(path_z.ptr, "r") orelse return null;
    defer _ = c.BIO_free(bio);
    return c.PEM_read_bio_ECPrivateKey(bio, null, null, null);
}

/// Extract the public key X and Y coordinates (32 bytes each, big-endian).
fn ecKeyPublicCoords(key: *c.EC_KEY, x_out: *[32]u8, y_out: *[32]u8) AcmeError!void {
    const group = c.EC_KEY_get0_group(key) orelse return error.KeyGenFailed;
    const point = c.EC_KEY_get0_public_key(key) orelse return error.KeyGenFailed;
    const ctx = c.BN_CTX_new() orelse return error.OutOfMemory;
    defer c.BN_CTX_free(ctx);
    const bx = c.BN_new() orelse return error.OutOfMemory;
    defer c.BN_free(bx);
    const by = c.BN_new() orelse return error.OutOfMemory;
    defer c.BN_free(by);
    if (c.EC_POINT_get_affine_coordinates_GFp(group, point, bx, by, ctx) != 1) return error.KeyGenFailed;
    if (c.BN_bn2binpad(bx, x_out.ptr, 32) != 32) return error.KeyGenFailed;
    if (c.BN_bn2binpad(by, y_out.ptr, 32) != 32) return error.KeyGenFailed;
}

/// Build the canonical JWK JSON for an EC P-256 public key (lexicographic key order,
/// no whitespace — required for thumbprint computation).
fn buildJwk(allocator: std.mem.Allocator, key: *c.EC_KEY) ![]u8 {
    var x: [32]u8 = undefined;
    var y: [32]u8 = undefined;
    try ecKeyPublicCoords(key, &x, &y);
    const xb64 = try b64urlEncode(allocator, &x);
    defer allocator.free(xb64);
    const yb64 = try b64urlEncode(allocator, &y);
    defer allocator.free(yb64);
    // RFC 7638: keys MUST be sorted lexicographically.
    return std.fmt.allocPrint(allocator, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ xb64, yb64 });
}

/// Compute the JWK thumbprint: SHA-256(canonical_JWK) → base64url.
fn jwkThumbprint(allocator: std.mem.Allocator, key: *c.EC_KEY) ![]u8 {
    const jwk = try buildJwk(allocator, key);
    defer allocator.free(jwk);
    var digest: [32]u8 = undefined;
    _ = c.EVP_Digest(jwk.ptr, jwk.len, &digest, null, c.EVP_sha256(), null);
    return b64urlEncode(allocator, &digest);
}

// ---------------------------------------------------------------------------
// JWS signing
// ---------------------------------------------------------------------------

/// Sign `data` with ECDSA P-256 and return the raw R||S bytes (64 bytes).
fn ecdsaSignRaw(allocator: std.mem.Allocator, key: *c.EC_KEY, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    _ = c.EVP_Digest(data.ptr, data.len, &digest, null, c.EVP_sha256(), null);

    const sig: ?*c.ECDSA_SIG = c.ECDSA_do_sign(&digest, 32, key);
    if (sig == null) return error.AcmeProtocolError;
    defer c.ECDSA_SIG_free(sig);

    var r_ptr: ?*const c.BIGNUM = null;
    var s_ptr: ?*const c.BIGNUM = null;
    c.ECDSA_SIG_get0(sig, &r_ptr, &s_ptr);
    const r = r_ptr orelse return error.AcmeProtocolError;
    const s = s_ptr orelse return error.AcmeProtocolError;

    const out = try allocator.alloc(u8, 64);
    if (c.BN_bn2binpad(r, out.ptr, 32) != 32) {
        allocator.free(out);
        return error.AcmeProtocolError;
    }
    if (c.BN_bn2binpad(s, out.ptr + 32, 32) != 32) {
        allocator.free(out);
        return error.AcmeProtocolError;
    }
    return out;
}

const JwsContext = struct {
    /// Account key
    key: *c.EC_KEY,
    /// Account URL (empty = not yet registered, use `jwk` in header)
    account_url: []const u8,
    /// ACME replay nonce
    nonce: []const u8,
};

/// Build a signed JWS flat JSON object for the given URL and payload.
/// `payload` is the raw bytes to sign; pass empty slice for POST-as-GET.
fn buildJws(allocator: std.mem.Allocator, jws_ctx: *const JwsContext, url: []const u8, payload: []const u8) ![]u8 {
    // Protected header
    const protected_json = blk: {
        if (jws_ctx.account_url.len == 0) {
            // New account: embed JWK
            const jwk = try buildJwk(allocator, jws_ctx.key);
            defer allocator.free(jwk);
            break :blk try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES256\",\"nonce\":\"{s}\",\"url\":\"{s}\",\"jwk\":{s}}}", .{ jws_ctx.nonce, url, jwk });
        } else {
            break :blk try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES256\",\"nonce\":\"{s}\",\"url\":\"{s}\",\"kid\":\"{s}\"}}", .{ jws_ctx.nonce, url, jws_ctx.account_url });
        }
    };
    defer allocator.free(protected_json);

    const protected_b64 = try b64urlEncode(allocator, protected_json);
    defer allocator.free(protected_b64);

    const payload_b64 = if (payload.len == 0) try allocator.dupe(u8, "") else try b64urlEncode(allocator, payload);
    defer allocator.free(payload_b64);

    // Signing input: protected_b64 + "." + payload_b64
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_b64, payload_b64 });
    defer allocator.free(signing_input);

    const sig_raw = try ecdsaSignRaw(allocator, jws_ctx.key, signing_input);
    defer allocator.free(sig_raw);
    const sig_b64 = try b64urlEncode(allocator, sig_raw);
    defer allocator.free(sig_b64);

    return std.fmt.allocPrint(allocator, "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}", .{ protected_b64, payload_b64, sig_b64 });
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const AcmeResponse = struct {
    allocator: std.mem.Allocator,
    status: std.http.Status,
    location: ?[]u8,
    replay_nonce: ?[]u8,
    body: []u8,

    fn deinit(self: *AcmeResponse) void {
        if (self.location) |l| self.allocator.free(l);
        if (self.replay_nonce) |n| self.allocator.free(n);
        self.allocator.free(self.body);
    }
};

fn acmeRequest(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    method: std.http.Method,
    url: []const u8,
    body_opt: ?[]const u8,
) AcmeError!AcmeResponse {
    const uri = std.Uri.parse(url) catch return error.NetworkError;
    var server_header_buf: [8192]u8 = undefined;
    const extra: []const std.http.Header = if (body_opt != null)
        &.{.{ .name = "Content-Type", .value = "application/jose+json" }}
    else
        &.{};
    var req = client.open(method, uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = extra,
        .keep_alive = false,
    }) catch return error.NetworkError;
    defer req.deinit();
    if (body_opt) |body| {
        req.transfer_encoding = .{ .content_length = body.len };
    }
    req.send() catch return error.NetworkError;
    if (body_opt) |body| req.writeAll(body) catch return error.NetworkError;
    req.finish() catch return error.NetworkError;
    req.wait() catch return error.NetworkError;

    var body_list = std.ArrayList(u8).init(allocator);
    errdefer body_list.deinit();
    req.reader().readAllArrayList(&body_list, 512 * 1024) catch return error.NetworkError;

    var location: ?[]u8 = null;
    var replay_nonce: ?[]u8 = null;
    var header_it = req.response.iterateHeaders();
    while (header_it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "location")) {
            location = allocator.dupe(u8, h.value) catch null;
        } else if (std.ascii.eqlIgnoreCase(h.name, "replay-nonce")) {
            replay_nonce = allocator.dupe(u8, h.value) catch null;
        }
    }
    return .{
        .allocator = allocator,
        .status = req.response.status,
        .location = location,
        .replay_nonce = replay_nonce,
        .body = try body_list.toOwnedSlice(),
    };
}

fn fetchNonce(allocator: std.mem.Allocator, client: *std.http.Client, new_nonce_url: []const u8) AcmeError![]u8 {
    var resp = try acmeRequest(allocator, client, .HEAD, new_nonce_url, null);
    defer resp.deinit();
    const nonce = resp.replay_nonce orelse return error.AcmeProtocolError;
    const owned = allocator.dupe(u8, nonce) catch return error.OutOfMemory;
    resp.replay_nonce = null; // prevent double-free
    return owned;
}

// ---------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------

fn buildCsr(allocator: std.mem.Allocator, domains: []const []const u8, domain_key: *c.EC_KEY) ![]u8 {
    if (domains.len == 0) return error.CsrFailed;

    const pkey = c.EVP_PKEY_new() orelse return error.CsrFailed;
    defer c.EVP_PKEY_free(pkey);
    // EVP_PKEY_assign_EC_KEY increments the refcount of domain_key
    if (c.EVP_PKEY_assign_EC_KEY(pkey, c.EC_KEY_dup(domain_key)) != 1) return error.CsrFailed;

    const req = c.X509_REQ_new() orelse return error.CsrFailed;
    defer c.X509_REQ_free(req);
    if (c.X509_REQ_set_version(req, 0) != 1) return error.CsrFailed;
    if (c.X509_REQ_set_pubkey(req, pkey) != 1) return error.CsrFailed;

    // Set CN to the first domain
    const name = c.X509_REQ_get_subject_name(req);
    const cn_z = try std.heap.c_allocator.dupeZ(u8, domains[0]);
    defer std.heap.c_allocator.free(cn_z);
    if (c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_UTF8, cn_z.ptr, -1, -1, 0) != 1) return error.CsrFailed;

    // Build SANs extension
    var san_buf = std.ArrayList(u8).init(allocator);
    defer san_buf.deinit();
    for (domains, 0..) |domain, i| {
        if (i > 0) try san_buf.appendSlice(", ");
        try san_buf.appendSlice("DNS:");
        try san_buf.appendSlice(domain);
    }
    try san_buf.append(0); // null terminate for OpenSSL

    const san_z: [:0]const u8 = san_buf.items[0 .. san_buf.items.len - 1 :0];
    const san_ext = c.X509V3_EXT_conf_nid(null, null, c.NID_subject_alt_name, san_z.ptr) orelse return error.CsrFailed;
    defer c.X509_EXTENSION_free(san_ext);

    const exts = c.sk_X509_EXTENSION_new_null() orelse return error.CsrFailed;
    defer c.sk_X509_EXTENSION_pop_free(exts, c.X509_EXTENSION_free);
    if (c.sk_X509_EXTENSION_push(exts, san_ext) == 0) return error.CsrFailed;
    if (c.X509_REQ_add_extensions(req, exts) != 1) return error.CsrFailed;

    // Sign
    if (c.X509_REQ_sign(req, pkey, c.EVP_sha256()) == 0) return error.CsrFailed;

    // DER encode
    var der_buf: ?[*]u8 = null;
    const der_len = c.i2d_X509_REQ(req, &der_buf);
    if (der_len <= 0 or der_buf == null) return error.CsrFailed;
    defer std.c.free(der_buf);

    return allocator.dupe(u8, der_buf.?[0..@intCast(der_len)]);
}

// ---------------------------------------------------------------------------
// Certificate expiry check
// ---------------------------------------------------------------------------

/// Returns the number of days until the certificate at `cert_path` expires,
/// or null if the file does not exist or cannot be parsed.
pub fn daysUntilExpiry(cert_path: []const u8) ?i64 {
    const path_z = std.heap.c_allocator.dupeZ(u8, cert_path) catch return null;
    defer std.heap.c_allocator.free(path_z);
    const bio = c.BIO_new_file(path_z.ptr, "r") orelse return null;
    defer _ = c.BIO_free(bio);
    const cert: ?*c.X509 = c.PEM_read_bio_X509(bio, null, null, null);
    if (cert == null) return null;
    defer c.X509_free(cert);

    const not_after = c.X509_get0_notAfter(cert) orelse return null;
    const diff = c.ASN1_TIME_diff(null, null, null, not_after);
    // diff is days; negative means already expired
    return @as(i64, diff);
}

// ---------------------------------------------------------------------------
// ACME state machine
// ---------------------------------------------------------------------------

pub const AcmeOptions = struct {
    allocator: std.mem.Allocator,
    /// ACME directory URL (e.g. Let's Encrypt v2 production or staging).
    directory_url: []const u8,
    /// Domains to request a certificate for.
    domains: []const []const u8,
    /// Contact email for ACME account.
    email: []const u8,
    /// Path to persist/load the ECDSA account private key.
    account_key_path: []const u8,
    /// Directory where certificate (<domain>.crt) and key (<domain>.key) files are stored.
    cert_dir: []const u8,
    /// How many days before expiry to trigger renewal.
    renew_days_before_expiry: u32,
    /// HTTP-01 challenge token store shared with the edge gateway.
    challenge_store: *ChallengeStore,
    /// Maximum seconds to wait for ACME challenge validation.
    challenge_timeout_s: u32 = 120,
};

/// Run one ACME cycle: check whether a certificate needs to be issued/renewed,
/// and if so perform the full ACME flow.  Returns `error.CertNotYetDue` when
/// the existing certificate has more than `renew_days_before_expiry` days left.
pub fn runOnce(opts: AcmeOptions) AcmeError!void {
    const allocator = opts.allocator;
    if (opts.domains.len == 0) return error.AcmeProtocolError;

    // Determine output paths based on first domain name.
    const cert_path = std.fmt.allocPrint(allocator, "{s}/{s}.crt", .{ opts.cert_dir, opts.domains[0] }) catch return error.OutOfMemory;
    defer allocator.free(cert_path);
    const key_path = std.fmt.allocPrint(allocator, "{s}/{s}.key", .{ opts.cert_dir, opts.domains[0] }) catch return error.OutOfMemory;
    defer allocator.free(key_path);

    // Check if renewal is due.
    if (daysUntilExpiry(cert_path)) |days| {
        if (days > @as(i64, opts.renew_days_before_expiry)) return error.CertNotYetDue;
    }

    // Load or generate account key.
    const account_key = try loadOrGenerateEcKey(allocator, opts.account_key_path);
    defer c.EC_KEY_free(account_key);

    // Generate a fresh domain key for this certificate.
    const domain_key = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse return error.KeyGenFailed;
    defer c.EC_KEY_free(domain_key);
    if (c.EC_KEY_generate_key(domain_key) != 1) return error.KeyGenFailed;

    // HTTP client for ACME server communication.
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    // Step 1: Fetch ACME directory.
    var dir_resp = acmeRequest(allocator, &http_client, .GET, opts.directory_url, null) catch return error.NetworkError;
    defer dir_resp.deinit();
    if (dir_resp.status != .ok) return error.AcmeProtocolError;

    var dir_parsed = std.json.parseFromSlice(std.json.Value, allocator, dir_resp.body, .{ .ignore_unknown_fields = true }) catch return error.JsonParseFailed;
    defer dir_parsed.deinit();
    const dir_obj = dir_parsed.value.object;

    const new_account_url = dir_obj.get("newAccount") orelse return error.AcmeProtocolError;
    const new_order_url = dir_obj.get("newOrder") orelse return error.AcmeProtocolError;
    const new_nonce_url = dir_obj.get("newNonce") orelse return error.AcmeProtocolError;
    if (new_account_url != .string or new_order_url != .string or new_nonce_url != .string) return error.AcmeProtocolError;

    // Step 2: Register / find account.
    var nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
    defer allocator.free(nonce);

    var jws_ctx = JwsContext{
        .key = account_key,
        .account_url = "",
        .nonce = nonce,
    };

    const contact_json = std.fmt.allocPrint(allocator, "{{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:{s}\"]}}", .{opts.email}) catch return error.OutOfMemory;
    defer allocator.free(contact_json);
    const acct_jws = try buildJws(allocator, &jws_ctx, new_account_url.string, contact_json);
    defer allocator.free(acct_jws);

    var acct_resp = acmeRequest(allocator, &http_client, .POST, new_account_url.string, acct_jws) catch return error.NetworkError;
    defer acct_resp.deinit();
    if (@intFromEnum(acct_resp.status) < 200 or @intFromEnum(acct_resp.status) >= 300) return error.AcmeProtocolError;
    const account_url = acct_resp.location orelse return error.AcmeProtocolError;
    const owned_account_url = allocator.dupe(u8, account_url) catch return error.OutOfMemory;
    defer allocator.free(owned_account_url);
    jws_ctx.account_url = owned_account_url;
    if (acct_resp.replay_nonce) |new_nonce| {
        allocator.free(nonce);
        nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
        jws_ctx.nonce = nonce;
    }

    // Step 3: Create order.
    var ids_buf = std.ArrayList(u8).init(allocator);
    defer ids_buf.deinit();
    try ids_buf.appendSlice("[");
    for (opts.domains, 0..) |domain, i| {
        if (i > 0) try ids_buf.appendSlice(",");
        try ids_buf.writer().print("{{\"type\":\"dns\",\"value\":\"{s}\"}}", .{domain});
    }
    try ids_buf.appendSlice("]");
    const order_payload = std.fmt.allocPrint(allocator, "{{\"identifiers\":{s}}}", .{ids_buf.items}) catch return error.OutOfMemory;
    defer allocator.free(order_payload);

    // Refresh nonce
    allocator.free(nonce);
    nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
    jws_ctx.nonce = nonce;

    const order_jws = try buildJws(allocator, &jws_ctx, new_order_url.string, order_payload);
    defer allocator.free(order_jws);

    var order_resp = acmeRequest(allocator, &http_client, .POST, new_order_url.string, order_jws) catch return error.NetworkError;
    defer order_resp.deinit();
    if (@intFromEnum(order_resp.status) < 200 or @intFromEnum(order_resp.status) >= 300) return error.AcmeProtocolError;
    const order_url = order_resp.location orelse return error.AcmeProtocolError;
    const owned_order_url = allocator.dupe(u8, order_url) catch return error.OutOfMemory;
    defer allocator.free(owned_order_url);
    if (order_resp.replay_nonce) |new_nonce| {
        allocator.free(nonce);
        nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
        jws_ctx.nonce = nonce;
    }

    var order_parsed = std.json.parseFromSlice(std.json.Value, allocator, order_resp.body, .{ .ignore_unknown_fields = true }) catch return error.JsonParseFailed;
    defer order_parsed.deinit();
    const order_obj = order_parsed.value.object;
    const authz_urls_val = order_obj.get("authorizations") orelse return error.AcmeProtocolError;
    if (authz_urls_val != .array) return error.AcmeProtocolError;
    const finalize_val = order_obj.get("finalize") orelse return error.AcmeProtocolError;
    if (finalize_val != .string) return error.AcmeProtocolError;
    const finalize_url = finalize_val.string;

    // Step 4: Fulfill HTTP-01 challenges for each authorization.
    const thumbprint = try jwkThumbprint(allocator, account_key);
    defer allocator.free(thumbprint);

    for (authz_urls_val.array.items) |authz_url_val| {
        if (authz_url_val != .string) return error.AcmeProtocolError;
        const authz_url = authz_url_val.string;

        // GET authorization (POST-as-GET with empty payload)
        allocator.free(nonce);
        nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
        jws_ctx.nonce = nonce;
        const authz_jws = try buildJws(allocator, &jws_ctx, authz_url, "");
        defer allocator.free(authz_jws);
        var authz_resp = acmeRequest(allocator, &http_client, .POST, authz_url, authz_jws) catch return error.NetworkError;
        defer authz_resp.deinit();
        if (authz_resp.replay_nonce) |new_nonce| {
            allocator.free(nonce);
            nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
            jws_ctx.nonce = nonce;
        }

        var authz_parsed = std.json.parseFromSlice(std.json.Value, allocator, authz_resp.body, .{ .ignore_unknown_fields = true }) catch return error.JsonParseFailed;
        defer authz_parsed.deinit();
        const authz_obj = authz_parsed.value.object;
        const challenges_val = authz_obj.get("challenges") orelse return error.AcmeProtocolError;
        if (challenges_val != .array) return error.AcmeProtocolError;

        // Find the HTTP-01 challenge.
        var challenge_token: ?[]const u8 = null;
        var challenge_url: ?[]const u8 = null;
        for (challenges_val.array.items) |ch_val| {
            if (ch_val != .object) continue;
            const ch = ch_val.object;
            const type_val = ch.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "http-01")) continue;
            const token_val = ch.get("token") orelse continue;
            const url_val = ch.get("url") orelse continue;
            if (token_val == .string and url_val == .string) {
                challenge_token = token_val.string;
                challenge_url = url_val.string;
                break;
            }
        }
        if (challenge_token == null or challenge_url == null) return error.ChallengeFailed;

        // key_auth = token + "." + thumbprint
        const key_auth = std.fmt.allocPrint(allocator, "{s}.{s}", .{ challenge_token.?, thumbprint }) catch return error.OutOfMemory;
        defer allocator.free(key_auth);

        // Publish challenge token to the store so the gateway can serve it.
        opts.challenge_store.put(challenge_token.?, key_auth) catch return error.OutOfMemory;
        defer opts.challenge_store.remove(challenge_token.?);

        // Notify ACME server that the challenge is ready.
        allocator.free(nonce);
        nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
        jws_ctx.nonce = nonce;
        const ch_ready_jws = try buildJws(allocator, &jws_ctx, challenge_url.?, "{}");
        defer allocator.free(ch_ready_jws);
        var ch_ready_resp = acmeRequest(allocator, &http_client, .POST, challenge_url.?, ch_ready_jws) catch return error.NetworkError;
        defer ch_ready_resp.deinit();
        if (ch_ready_resp.replay_nonce) |new_nonce| {
            allocator.free(nonce);
            nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
            jws_ctx.nonce = nonce;
        }

        // Poll the authorization until valid or timeout.
        const deadline = std.time.milliTimestamp() + @as(i64, opts.challenge_timeout_s) * 1000;
        while (true) {
            std.time.sleep(2_000_000_000); // 2 seconds
            allocator.free(nonce);
            nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
            jws_ctx.nonce = nonce;
            const poll_jws = try buildJws(allocator, &jws_ctx, authz_url, "");
            defer allocator.free(poll_jws);
            var poll_resp = acmeRequest(allocator, &http_client, .POST, authz_url, poll_jws) catch return error.NetworkError;
            defer poll_resp.deinit();
            if (poll_resp.replay_nonce) |new_nonce| {
                allocator.free(nonce);
                nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
                jws_ctx.nonce = nonce;
            }
            var poll_parsed = std.json.parseFromSlice(std.json.Value, allocator, poll_resp.body, .{ .ignore_unknown_fields = true }) catch return error.JsonParseFailed;
            defer poll_parsed.deinit();
            const status_val = poll_parsed.value.object.get("status") orelse break;
            if (status_val == .string) {
                if (std.mem.eql(u8, status_val.string, "valid")) break;
                if (std.mem.eql(u8, status_val.string, "invalid")) return error.ChallengeFailed;
            }
            if (std.time.milliTimestamp() > deadline) return error.ChallengeFailed;
        }
    }

    // Step 5: Generate CSR for all domains.
    const csr_der = try buildCsr(allocator, opts.domains, domain_key);
    defer allocator.free(csr_der);
    const csr_b64 = try b64urlEncode(allocator, csr_der);
    defer allocator.free(csr_b64);

    // Step 6: Finalize the order.
    const finalize_payload = std.fmt.allocPrint(allocator, "{{\"csr\":\"{s}\"}}", .{csr_b64}) catch return error.OutOfMemory;
    defer allocator.free(finalize_payload);
    allocator.free(nonce);
    nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
    jws_ctx.nonce = nonce;
    const fin_jws = try buildJws(allocator, &jws_ctx, finalize_url, finalize_payload);
    defer allocator.free(fin_jws);
    var fin_resp = acmeRequest(allocator, &http_client, .POST, finalize_url, fin_jws) catch return error.NetworkError;
    defer fin_resp.deinit();
    if (@intFromEnum(fin_resp.status) < 200 or @intFromEnum(fin_resp.status) >= 300) return error.AcmeProtocolError;
    if (fin_resp.replay_nonce) |new_nonce| {
        allocator.free(nonce);
        nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
        jws_ctx.nonce = nonce;
    }

    // Poll the order until the certificate URL is available.
    const order_deadline = std.time.milliTimestamp() + 120_000;
    var cert_url: ?[]u8 = null;
    defer if (cert_url) |u| allocator.free(u);
    while (cert_url == null) {
        std.time.sleep(2_000_000_000);
        allocator.free(nonce);
        nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
        jws_ctx.nonce = nonce;
        const ord_poll_jws = try buildJws(allocator, &jws_ctx, owned_order_url, "");
        defer allocator.free(ord_poll_jws);
        var ord_poll_resp = acmeRequest(allocator, &http_client, .POST, owned_order_url, ord_poll_jws) catch return error.NetworkError;
        defer ord_poll_resp.deinit();
        if (ord_poll_resp.replay_nonce) |new_nonce| {
            allocator.free(nonce);
            nonce = allocator.dupe(u8, new_nonce) catch return error.OutOfMemory;
            jws_ctx.nonce = nonce;
        }
        var ord_parsed = std.json.parseFromSlice(std.json.Value, allocator, ord_poll_resp.body, .{ .ignore_unknown_fields = true }) catch return error.JsonParseFailed;
        defer ord_parsed.deinit();
        const cert_url_val = ord_parsed.value.object.get("certificate");
        if (cert_url_val != null and cert_url_val.? == .string) {
            cert_url = allocator.dupe(u8, cert_url_val.?.string) catch return error.OutOfMemory;
            break;
        }
        if (std.time.milliTimestamp() > order_deadline) return error.CertDownloadFailed;
    }

    // Step 7: Download the certificate chain.
    allocator.free(nonce);
    nonce = try fetchNonce(allocator, &http_client, new_nonce_url.string);
    jws_ctx.nonce = nonce;
    const dl_jws = try buildJws(allocator, &jws_ctx, cert_url.?, "");
    defer allocator.free(dl_jws);
    var dl_resp = acmeRequest(allocator, &http_client, .POST, cert_url.?, dl_jws) catch return error.NetworkError;
    defer dl_resp.deinit();
    if (dl_resp.status != .ok) return error.CertDownloadFailed;

    // Step 8: Atomically save the certificate and private key to disk.
    std.fs.cwd().makePath(opts.cert_dir) catch {};
    const tmp_cert = std.fmt.allocPrint(allocator, "{s}.tmp", .{cert_path}) catch return error.OutOfMemory;
    defer allocator.free(tmp_cert);
    std.fs.cwd().writeFile(.{ .sub_path = tmp_cert, .data = dl_resp.body }) catch return error.CertSaveFailed;
    std.fs.cwd().rename(tmp_cert, cert_path) catch return error.CertSaveFailed;

    // Write domain private key in PEM.
    const domain_bio = c.BIO_new(c.BIO_s_mem()) orelse return error.CertSaveFailed;
    defer _ = c.BIO_free(domain_bio);
    if (c.PEM_write_bio_ECPrivateKey(domain_bio, domain_key, null, null, 0, null, null) != 1) return error.CertSaveFailed;
    var key_ptr: ?[*]u8 = null;
    const key_len = c.BIO_get_mem_data(domain_bio, &key_ptr);
    if (key_len <= 0 or key_ptr == null) return error.CertSaveFailed;
    const tmp_key = std.fmt.allocPrint(allocator, "{s}.tmp", .{key_path}) catch return error.OutOfMemory;
    defer allocator.free(tmp_key);
    std.fs.cwd().writeFile(.{ .sub_path = tmp_key, .data = key_ptr.?[0..@intCast(key_len)] }) catch return error.CertSaveFailed;
    std.fs.cwd().rename(tmp_key, key_path) catch return error.CertSaveFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ChallengeStore put/getCopy/remove" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    try store.put("abc123", "abc123.thumbprint");
    const val = store.getCopy(allocator, "abc123").?;
    defer allocator.free(val);
    try std.testing.expectEqualStrings("abc123.thumbprint", val);

    store.remove("abc123");
    try std.testing.expect(store.getCopy(allocator, "abc123") == null);
}

test "b64urlEncode round-trip" {
    const allocator = std.testing.allocator;
    const data = "hello world";
    const encoded = try b64urlEncode(allocator, data);
    defer allocator.free(encoded);
    const decoded_len = try b64url_dec.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    _ = try b64url_dec.decode(decoded, encoded);
    try std.testing.expectEqualStrings(data, decoded);
}

test "EC P-256 key generation and JWK thumbprint" {
    const allocator = std.testing.allocator;
    const key = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse return error.KeyGenFailed;
    defer c.EC_KEY_free(key);
    try std.testing.expect(c.EC_KEY_generate_key(key) == 1);

    const tp = try jwkThumbprint(allocator, key);
    defer allocator.free(tp);
    // Thumbprint should be 43 bytes of base64url (32 bytes SHA-256 → 43 chars base64url-no-pad)
    try std.testing.expectEqual(@as(usize, 43), tp.len);
}
