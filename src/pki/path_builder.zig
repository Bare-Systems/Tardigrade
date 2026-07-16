//! Deterministic X.509 candidate-path construction (#344).
//!
//! Builds candidate certification paths from a leaf certificate,
//! peer-supplied intermediates, and configured trust anchors. This is path
//! *discovery* only (RFC 4158 territory): no signature is verified, no
//! validity period, key usage, name constraint, or Basic Constraints rule is
//! applied, and no path is accepted — every returned path is a candidate for
//! RFC 5280 validation (#324-G) to check in order. AIA fetching is out of
//! scope; only the caller-provided certificate pools are searched.
//!
//! ## Matching and ranking rules
//!
//! A certificate C is a candidate issuer of X exactly when C's subject Name
//! equals X's issuer Name byte-for-byte (`Name.raw`, RFC 5280 §7.1 binary
//! comparison — DER makes this the normalized form). AKI/SKI key identifiers
//! never veto a candidate (real-world AKIs are wrong often enough that
//! RFC 4158 §2.4.2 treats them as sorting hints); they only rank it.
//! Sibling candidates are tried in this documented, total order:
//!
//! 1. Key-identifier agreement: X's AKI keyIdentifier equals C's SKI, then
//!    either identifier absent, then both present but different.
//! 2. Source: trust anchors before peer-supplied intermediates.
//! 3. Ascending input index (position in the caller's slice).
//!
//! Paths are emitted in depth-first order under that sibling ordering, so
//! the full enumeration is a pure function of the inputs and limits.
//!
//! ## Anchors, cycles, and duplicates
//!
//! Trust anchors terminate paths and are never extended or traversed as
//! intermediates; a cross-signed root reaches a second anchor only through a
//! peer-supplied (or caller-pooled) cross-certificate. Each pool is
//! deduplicated by exact DER (first occurrence wins), and a certificate
//! never appears twice in one path (byte-exact loop detection), which makes
//! duplicate and cyclic inputs terminate deterministically.
//!
//! ## Bounds
//!
//! `Limits` caps input pool sizes, path length, per-node fanout (applied
//! after ranking, so the kept candidates are the best-ranked ones), the
//! total number of issuer candidates examined, and the number of returned
//! paths. Exceeding a search bound never aborts work already done: found
//! paths are returned with `truncated = true`. With zero paths found,
//! `error.NoCandidatePath` means the bounded search space was provably
//! exhausted, while `error.SearchLimitExceeded` means a limit stopped
//! enumeration first. This error set deliberately contains no
//! parser/signature/policy variants — inputs are already-parsed #341 views
//! and no cryptographic or policy judgement happens here.

const std = @import("std");
const x509 = @import("x509.zig");

/// Configurable search resource bounds.
pub const Limits = struct {
    /// Maximum certificates in one path, counting the leaf and the anchor.
    max_path_len: usize = 8,
    /// Maximum candidate paths returned.
    max_paths: usize = 8,
    /// Maximum peer-supplied intermediates accepted (pre-deduplication).
    max_intermediates: usize = 64,
    /// Maximum trust anchors accepted (pre-deduplication).
    max_anchors: usize = 256,
    /// Maximum candidate issuers kept per certificate after ranking.
    max_fanout: usize = 8,
    /// Total issuer candidates examined across the whole search — the
    /// global work bound that defeats adversarial chain explosions.
    max_candidate_visits: usize = 256,
};

pub const default_limits: Limits = .{};

pub const Error = error{
    /// The trust-anchor set is empty: a configuration defect, distinct from
    /// a search that ran and found nothing.
    NoTrustAnchors,
    /// An input pool exceeds `max_intermediates`/`max_anchors`.
    CountLimitExceeded,
    /// The bounded search space was fully enumerated and contains no path
    /// from the leaf to any trust anchor.
    NoCandidatePath,
    /// A search limit (depth, fanout, or visit budget) stopped enumeration
    /// before any path was found; a path may exist beyond the limits.
    SearchLimitExceeded,
    OutOfMemory,
};

/// Where a path element came from, so validation can apply anchor-specific
/// rules (RFC 5280 §6.1.1(d) trust anchor information) to the right element.
pub const Source = enum { leaf, intermediate, anchor };

pub const Element = struct {
    /// Borrowed from the corresponding `build` input; valid while that
    /// input outlives the result.
    certificate: *const x509.Certificate,
    source: Source,
    /// Index into the input slice named by `source` (always 0 for the leaf).
    input_index: usize,
};

/// One candidate certification path, leaf first, trust anchor last (always
/// at least two elements). Candidate means unvalidated: #324-G decides
/// whether it is acceptable.
pub const Path = struct {
    elements: []const Element,

    pub fn leaf(self: *const Path) *const Element {
        return &self.elements[0];
    }

    pub fn anchor(self: *const Path) *const Element {
        return &self.elements[self.elements.len - 1];
    }
};

/// Result of a build: candidate paths in deterministic enumeration order.
/// Path memory is arena-owned; certificates remain borrowed from the caller.
pub const CandidatePaths = struct {
    paths: []const Path,
    /// True when a limit (path length, fanout, visit budget, or `max_paths`)
    /// cut enumeration short, so paths beyond the returned set may exist.
    truncated: bool,

    arena_state: std.heap.ArenaAllocator.State,

    pub fn deinit(self: *CandidatePaths, allocator: std.mem.Allocator) void {
        self.arena_state.promote(allocator).deinit();
        self.* = undefined;
    }
};

/// Build candidate paths from `leaf` through `intermediates` to `anchors`.
/// All certificate inputs are borrowed and must outlive the returned value;
/// free the result with `deinit` using the same `allocator`.
pub fn build(
    allocator: std.mem.Allocator,
    leaf: *const x509.Certificate,
    intermediates: []const x509.Certificate,
    anchors: []const x509.Certificate,
    limits: Limits,
) Error!CandidatePaths {
    if (anchors.len == 0) return error.NoTrustAnchors;
    if (intermediates.len > limits.max_intermediates) return error.CountLimitExceeded;
    if (anchors.len > limits.max_anchors) return error.CountLimitExceeded;

    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var search = Search{
        .arena = arena,
        .limits = limits,
        .anchor_pool = try Pool.build(arena, anchors),
        .intermediate_pool = try Pool.build(arena, intermediates),
        .visit_budget = limits.max_candidate_visits,
    };

    var path: std.ArrayList(Element) = .empty;
    try path.append(arena, .{ .certificate = leaf, .source = .leaf, .input_index = 0 });

    var paths: std.ArrayList(Path) = .empty;

    // One frame per path element; frame i enumerates the issuer candidates
    // of path element i. Iterative traversal keeps stack depth independent
    // of the input, and `max_path_len` bounds both structures.
    var stack: std.ArrayList(Frame) = .empty;
    if (limits.max_path_len >= 2 and limits.max_paths >= 1) {
        try stack.append(arena, .{ .candidates = try search.gatherCandidates(leaf, path.items) });
    } else {
        // No room for even [leaf, anchor], or no room to return one: pure
        // limit truncation, not proof of absence.
        search.truncated = true;
    }

    while (stack.items.len > 0) {
        const frame = &stack.items[stack.items.len - 1];
        if (frame.next >= frame.candidates.len) {
            _ = stack.pop();
            _ = path.pop();
            continue;
        }
        const candidate = frame.candidates[frame.next];
        frame.next += 1;

        switch (candidate.source) {
            .anchor => {
                // Guaranteed by the push conditions below; kept as a local
                // guard so the depth bound cannot rot at a distance.
                if (path.items.len + 1 > limits.max_path_len) {
                    search.truncated = true;
                    continue;
                }
                const elements = try arena.alloc(Element, path.items.len + 1);
                @memcpy(elements[0..path.items.len], path.items);
                elements[path.items.len] = candidate.element();
                try paths.append(arena, .{ .elements = elements });
                if (paths.items.len >= limits.max_paths) {
                    if (pendingWorkRemains(stack.items)) search.truncated = true;
                    break;
                }
            },
            .intermediate => {
                // Extending must leave room for at least a terminating
                // anchor after this intermediate.
                if (path.items.len + 2 > limits.max_path_len) {
                    search.truncated = true;
                    continue;
                }
                try path.append(arena, candidate.element());
                const candidates = try search.gatherCandidates(candidate.entry.certificate, path.items);
                try stack.append(arena, .{ .candidates = candidates });
            },
            // Only anchors and intermediates are pooled.
            .leaf => unreachable,
        }
    }

    if (paths.items.len == 0) {
        return if (search.truncated) error.SearchLimitExceeded else error.NoCandidatePath;
    }

    const result = CandidatePaths{
        .paths = paths.items,
        .truncated = search.truncated,
        .arena_state = arena_inst.state,
    };
    return result;
}

/// RFC 4158 §2.4.2-style key-identifier hint. Order matters: lower values
/// are tried first.
const KeyIdAgreement = enum(u2) {
    /// Child AKI keyIdentifier and candidate SKI both present and equal.
    match = 0,
    /// Either identifier absent — no evidence either way.
    unknown = 1,
    /// Both present but different. Still a candidate (AKIs are unreliable
    /// in the wild), just tried last.
    mismatch = 2,
};

const Entry = struct {
    certificate: *const x509.Certificate,
    input_index: usize,
};

/// A deduplicated certificate pool indexed by subject for issuer lookup.
const Pool = struct {
    /// Sorted by (subject `Name.raw`, input index); unique by exact DER.
    entries: []const Entry,

    fn build(arena: std.mem.Allocator, certificates: []const x509.Certificate) Error!Pool {
        var entries: std.ArrayList(Entry) = .empty;
        input: for (certificates, 0..) |*certificate, input_index| {
            // Duplicate certificates (byte-identical DER) collapse to their
            // first occurrence so they cannot multiply candidate paths.
            for (entries.items) |existing| {
                if (std.mem.eql(u8, existing.certificate.raw, certificate.raw)) continue :input;
            }
            try entries.append(arena, .{ .certificate = certificate, .input_index = input_index });
        }
        std.mem.sort(Entry, entries.items, {}, entryLessThan);
        return .{ .entries = entries.items };
    }

    fn entryLessThan(_: void, a: Entry, b: Entry) bool {
        return switch (std.mem.order(u8, a.certificate.subject.raw, b.certificate.subject.raw)) {
            .lt => true,
            .gt => false,
            .eq => a.input_index < b.input_index,
        };
    }

    /// All entries whose subject equals `issuer_raw`, in input order.
    fn matchSubject(self: *const Pool, issuer_raw: []const u8) []const Entry {
        var low: usize = 0;
        var high: usize = self.entries.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (std.mem.order(u8, self.entries[mid].certificate.subject.raw, issuer_raw) == .lt) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        var end = low;
        while (end < self.entries.len and
            std.mem.eql(u8, self.entries[end].certificate.subject.raw, issuer_raw))
        {
            end += 1;
        }
        return self.entries[low..end];
    }
};

const Candidate = struct {
    entry: Entry,
    source: Source,
    agreement: KeyIdAgreement,

    fn element(self: *const Candidate) Element {
        return .{
            .certificate = self.entry.certificate,
            .source = self.source,
            .input_index = self.entry.input_index,
        };
    }
};

const Frame = struct {
    candidates: []const Candidate,
    next: usize = 0,
};

const Search = struct {
    arena: std.mem.Allocator,
    limits: Limits,
    anchor_pool: Pool,
    intermediate_pool: Pool,
    /// Remaining issuer candidates this search may examine.
    visit_budget: usize,
    truncated: bool = false,

    /// Collect, rank, and bound the issuer candidates of `child`, skipping
    /// certificates already on `current_path`.
    fn gatherCandidates(
        self: *Search,
        child: *const x509.Certificate,
        current_path: []const Element,
    ) Error![]const Candidate {
        const child_keyid: ?[]const u8 = if (child.authorityKeyIdentifier()) |aki|
            aki.key_identifier
        else
            null;

        var candidates: std.ArrayList(Candidate) = .empty;
        try self.collect(&candidates, &self.anchor_pool, .anchor, child, child_keyid, current_path);
        try self.collect(&candidates, &self.intermediate_pool, .intermediate, child, child_keyid, current_path);

        std.mem.sort(Candidate, candidates.items, {}, candidateLessThan);
        if (candidates.items.len > self.limits.max_fanout) {
            self.truncated = true;
            candidates.shrinkRetainingCapacity(self.limits.max_fanout);
        }
        return candidates.items;
    }

    fn collect(
        self: *Search,
        out: *std.ArrayList(Candidate),
        pool: *const Pool,
        source: Source,
        child: *const x509.Certificate,
        child_keyid: ?[]const u8,
        current_path: []const Element,
    ) Error!void {
        for (pool.matchSubject(child.issuer.raw)) |entry| {
            if (self.visit_budget == 0) {
                self.truncated = true;
                return;
            }
            self.visit_budget -= 1;
            if (onPath(current_path, entry.certificate)) continue;
            try out.append(self.arena, .{
                .entry = entry,
                .source = source,
                .agreement = keyIdAgreement(child_keyid, entry.certificate),
            });
        }
    }
};

fn keyIdAgreement(child_keyid: ?[]const u8, issuer: *const x509.Certificate) KeyIdAgreement {
    const child_id = child_keyid orelse return .unknown;
    const issuer_id = issuer.subjectKeyIdentifier() orelse return .unknown;
    return if (std.mem.eql(u8, child_id, issuer_id)) .match else .mismatch;
}

fn candidateLessThan(_: void, a: Candidate, b: Candidate) bool {
    if (a.agreement != b.agreement) return @intFromEnum(a.agreement) < @intFromEnum(b.agreement);
    if (a.source != b.source) return a.source == .anchor;
    return a.entry.input_index < b.entry.input_index;
}

fn onPath(current_path: []const Element, certificate: *const x509.Certificate) bool {
    for (current_path) |element| {
        if (element.certificate == certificate) return true;
        if (std.mem.eql(u8, element.certificate.raw, certificate.raw)) return true;
    }
    return false;
}

fn pendingWorkRemains(frames: []const Frame) bool {
    for (frames) |frame| {
        if (frame.next < frame.candidates.len) return true;
    }
    return false;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
