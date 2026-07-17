//! Provider-neutral trust-anchor store for the pure-Zig PKI path (#346).
//!
//! The validator and path builder consume immutable `[]const x509.Certificate`
//! anchor snapshots only; no platform-native or foreign-library handle leaks
//! into this surface. Future system-store adapters can satisfy `Provider` by
//! materializing the same owned snapshot contract.

const std = @import("std");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

pub const Limits = struct {
    loader: pem.Limits = .{},
    parser: x509.Limits = .{},
    /// Maximum unique anchors retained after exact-DER deduplication.
    max_anchors: usize = 256,
};

pub const default_limits: Limits = .{};

pub const Error = pem.Error || x509.Error || error{
    NoTrustAnchors,
    TooManyAnchors,
    NonCaAnchor,
};

pub const FileError = Error || std.Io.File.OpenError || std.Io.File.Reader.Error;

pub const BufferInput = union(enum) {
    pem: []const u8,
    der: []const u8,
};

pub const FileInput = union(enum) {
    pem: []const u8,
    der: []const u8,
};

/// One immutable trust-anchor snapshot. Parsed certificates borrow the owned
/// DER bytes in `owned_certs`; callers release both together via `deinit`.
pub const Snapshot = struct {
    owned_certs: []pem.Certificate,
    parsed_anchors: []x509.Certificate,
    parser_limits: x509.Limits,

    pub fn loadBuffers(
        allocator: std.mem.Allocator,
        inputs: []const BufferInput,
        limits: Limits,
    ) Error!Snapshot {
        var owned_certs: std.ArrayList(pem.Certificate) = .empty;
        errdefer deinitOwnedArrayList(&owned_certs, allocator);
        var parsed_anchors: std.ArrayList(x509.Certificate) = .empty;
        errdefer deinitParsedArrayList(&parsed_anchors, allocator);

        for (inputs) |input| {
            switch (input) {
                .pem => |pem_text| {
                    var chain = try pem.loadChainPem(allocator, pem_text, limits.loader);
                    try appendPemChain(allocator, &owned_certs, &parsed_anchors, &chain, limits);
                },
                .der => |der_bytes| {
                    const certificate = try pem.loadCertificateDer(allocator, der_bytes, limits.loader);
                    try appendOwnedCertificate(
                        allocator,
                        &owned_certs,
                        &parsed_anchors,
                        certificate,
                        limits,
                    );
                },
            }
        }

        if (parsed_anchors.items.len == 0) return error.NoTrustAnchors;
        return finishSnapshot(allocator, &owned_certs, &parsed_anchors, limits.parser);
    }

    pub fn loadFiles(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        inputs: []const FileInput,
        limits: Limits,
    ) FileError!Snapshot {
        var owned_certs: std.ArrayList(pem.Certificate) = .empty;
        errdefer deinitOwnedArrayList(&owned_certs, allocator);
        var parsed_anchors: std.ArrayList(x509.Certificate) = .empty;
        errdefer deinitParsedArrayList(&parsed_anchors, allocator);

        for (inputs) |input| {
            switch (input) {
                .pem => |sub_path| {
                    var chain = try pem.loadChainPemFile(allocator, io, dir, sub_path, limits.loader);
                    try appendPemChain(allocator, &owned_certs, &parsed_anchors, &chain, limits);
                },
                .der => |sub_path| {
                    const certificate = try pem.loadCertificateDerFile(allocator, io, dir, sub_path, limits.loader);
                    try appendOwnedCertificate(
                        allocator,
                        &owned_certs,
                        &parsed_anchors,
                        certificate,
                        limits,
                    );
                },
            }
        }

        if (parsed_anchors.items.len == 0) return error.NoTrustAnchors;
        return finishSnapshot(allocator, &owned_certs, &parsed_anchors, limits.parser);
    }

    pub fn anchors(self: *const Snapshot) []const x509.Certificate {
        return self.parsed_anchors;
    }

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        for (self.parsed_anchors) |*certificate| certificate.deinit(allocator);
        allocator.free(self.parsed_anchors);
        for (self.owned_certs) |*certificate| certificate.deinit(allocator);
        allocator.free(self.owned_certs);
        self.* = undefined;
    }

    fn clone(self: *const Snapshot, allocator: std.mem.Allocator) Error!Snapshot {
        var owned_certs: std.ArrayList(pem.Certificate) = .empty;
        errdefer deinitOwnedArrayList(&owned_certs, allocator);
        var parsed_anchors: std.ArrayList(x509.Certificate) = .empty;
        errdefer deinitParsedArrayList(&parsed_anchors, allocator);

        for (self.owned_certs) |certificate| {
            const der_copy = try allocator.dupe(u8, certificate.der);
            const owned = pem.Certificate{ .der = der_copy };
            try appendOwnedCertificate(
                allocator,
                &owned_certs,
                &parsed_anchors,
                owned,
                .{
                    .loader = .{},
                    .parser = self.parser_limits,
                    .max_anchors = self.parsed_anchors.len,
                },
            );
        }

        return finishSnapshot(allocator, &owned_certs, &parsed_anchors, self.parser_limits);
    }
};

/// Trust-store interface for future platform-native adapters. Implementations
/// provide immutable snapshots with the same ownership rules as `Snapshot`.
pub const Provider = struct {
    context: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        snapshot: *const fn (context: *const anyopaque, allocator: std.mem.Allocator) Error!Snapshot,
    };

    pub fn snapshot(self: Provider, allocator: std.mem.Allocator) Error!Snapshot {
        return self.vtable.snapshot(self.context, allocator);
    }
};

/// Practical PEM/DER-backed trust store. Reload swaps the current bundle, and
/// every acquired snapshot owns its bytes so in-flight validation survives.
pub const BundleStore = struct {
    current: Snapshot,

    pub fn initBuffers(
        allocator: std.mem.Allocator,
        inputs: []const BufferInput,
        limits: Limits,
    ) Error!BundleStore {
        return .{ .current = try Snapshot.loadBuffers(allocator, inputs, limits) };
    }

    pub fn initFiles(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        inputs: []const FileInput,
        limits: Limits,
    ) FileError!BundleStore {
        return .{ .current = try Snapshot.loadFiles(allocator, io, dir, inputs, limits) };
    }

    pub fn deinit(self: *BundleStore, allocator: std.mem.Allocator) void {
        self.current.deinit(allocator);
        self.* = undefined;
    }

    pub fn provider(self: *const BundleStore) Provider {
        return .{ .context = self, .vtable = &provider_vtable };
    }

    pub fn snapshot(self: *const BundleStore, allocator: std.mem.Allocator) Error!Snapshot {
        return self.current.clone(allocator);
    }

    pub fn reloadBuffers(
        self: *BundleStore,
        allocator: std.mem.Allocator,
        inputs: []const BufferInput,
        limits: Limits,
    ) Error!void {
        const next = try Snapshot.loadBuffers(allocator, inputs, limits);
        self.current.deinit(allocator);
        self.current = next;
    }

    pub fn reloadFiles(
        self: *BundleStore,
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        inputs: []const FileInput,
        limits: Limits,
    ) FileError!void {
        const next = try Snapshot.loadFiles(allocator, io, dir, inputs, limits);
        self.current.deinit(allocator);
        self.current = next;
    }

    const provider_vtable = Provider.VTable{
        .snapshot = providerSnapshot,
    };

    fn providerSnapshot(context: *const anyopaque, allocator: std.mem.Allocator) Error!Snapshot {
        const self: *const BundleStore = @ptrCast(@alignCast(context));
        return self.snapshot(allocator);
    }
};

fn appendOwnedCertificate(
    allocator: std.mem.Allocator,
    owned_certs: *std.ArrayList(pem.Certificate),
    parsed_anchors: *std.ArrayList(x509.Certificate),
    certificate: pem.Certificate,
    limits: Limits,
) Error!void {
    var owned = certificate;
    if (containsDer(owned_certs.items, owned.der)) {
        owned.deinit(allocator);
        return;
    }
    if (owned_certs.items.len >= limits.max_anchors) {
        owned.deinit(allocator);
        return error.TooManyAnchors;
    }

    var parsed = x509.Certificate.parse(allocator, owned.der, limits.parser) catch |err| {
        owned.deinit(allocator);
        return err;
    };
    if (!isCaAnchor(&parsed)) {
        parsed.deinit(allocator);
        owned.deinit(allocator);
        return error.NonCaAnchor;
    }

    owned_certs.append(allocator, owned) catch |err| {
        parsed.deinit(allocator);
        owned.deinit(allocator);
        return err;
    };
    parsed_anchors.append(allocator, parsed) catch |err| {
        parsed.deinit(allocator);
        return err;
    };
}

fn appendPemChain(
    allocator: std.mem.Allocator,
    owned_certs: *std.ArrayList(pem.Certificate),
    parsed_anchors: *std.ArrayList(x509.Certificate),
    chain: *pem.CertificateChain,
    limits: Limits,
) Error!void {
    var transferred: usize = 0;
    errdefer {
        for (chain.certificates[transferred..]) |*certificate| certificate.deinit(allocator);
        allocator.free(chain.certificates);
    }

    for (chain.certificates, 0..) |*certificate, index| {
        const owned = certificate.*;
        certificate.* = undefined;
        transferred = index + 1;
        try appendOwnedCertificate(allocator, owned_certs, parsed_anchors, owned, limits);
    }

    allocator.free(chain.certificates);
}

fn containsDer(owned_certs: []const pem.Certificate, der_bytes: []const u8) bool {
    for (owned_certs) |certificate| {
        if (std.mem.eql(u8, certificate.der, der_bytes)) return true;
    }
    return false;
}

fn isCaAnchor(certificate: *const x509.Certificate) bool {
    const constraints = certificate.basicConstraints() orelse return false;
    return constraints.is_ca;
}

fn finishSnapshot(
    allocator: std.mem.Allocator,
    owned_certs: *std.ArrayList(pem.Certificate),
    parsed_anchors: *std.ArrayList(x509.Certificate),
    parser_limits: x509.Limits,
) Error!Snapshot {
    const owned_slice = try owned_certs.toOwnedSlice(allocator);
    errdefer {
        for (owned_slice) |*certificate| certificate.deinit(allocator);
        allocator.free(owned_slice);
    }
    const parsed_slice = try parsed_anchors.toOwnedSlice(allocator);
    return .{
        .owned_certs = owned_slice,
        .parsed_anchors = parsed_slice,
        .parser_limits = parser_limits,
    };
}

fn deinitOwnedArrayList(list: *std.ArrayList(pem.Certificate), allocator: std.mem.Allocator) void {
    for (list.items) |*certificate| certificate.deinit(allocator);
    list.deinit(allocator);
}

fn deinitParsedArrayList(list: *std.ArrayList(x509.Certificate), allocator: std.mem.Allocator) void {
    for (list.items) |*certificate| certificate.deinit(allocator);
    list.deinit(allocator);
}
