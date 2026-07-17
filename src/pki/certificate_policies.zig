//! Bounded RFC 5280 §6.1 certificate-policy processing (#345) using the
//! RFC 9618 valid_policy_graph in place of the obsolete exponential
//! valid_policy_tree.
//!
//! Paths are supplied leaf-first, anchor-last.  Processing follows the RFC's
//! logical direction: the certificate directly below the configured anchor is
//! certificate 1 and the target is certificate n.  The configured anchor is
//! trust input — its own certificatePolicies, policyMappings,
//! policyConstraints, and inhibitAnyPolicy extensions are never implicit
//! local policy (RFC 5280 §6.2).  Diagnostics keep leaf-first indices.
//!
//! ## Graph representation
//!
//! The graph is one flat node array indexed by integers, partitioned into
//! depths (`depth_offsets`).  A node stores its valid_policy OID, a unique
//! expected-policy set, and unique parent indices into the previous depth.
//! RFC 9618 invariants hold by construction: at most one node exists per
//! (depth, OID) pair, merged parents replace duplicated subtrees, and every
//! edge connects adjacent depths.  Growth is therefore linear in the number
//! of asserted policies and mappings, never exponential, and every dimension
//! (nodes per depth, total nodes, edges, expected entries, operations) has an
//! explicit configurable bound whose exhaustion is a structured rejection.
//!
//! ## Qualifiers
//!
//! Policy qualifiers are not returned to callers, as RFC 9618 §4.2 permits
//! for applications that do not use them.  Their syntax is still enforced by
//! the #341 parser, and a critical certificatePolicies extension carrying an
//! unrecognized qualifier form fails closed here rather than being silently
//! treated as understood.  CPS URIs are never fetched; user notices are
//! never displayed; qualifier bytes never appear in failures.

const std = @import("std");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const x509 = @import("x509.zig");

const wk = oid.well_known;

/// Every collection and repeated operation in this module has an explicit
/// caller-configurable bound.  Parser bounds (`x509.Limits`) apply first.
pub const Limits = struct {
    maximum_path_length: usize = 8,
    maximum_policies_per_certificate: usize = 32,
    maximum_mappings_per_certificate: usize = 32,
    maximum_user_initial_policies: usize = 32,
    /// Also bounds the graph depth together with `maximum_path_length`.
    maximum_nodes_per_depth: usize = 64,
    maximum_total_nodes: usize = 512,
    /// Total parent references across all nodes.
    maximum_total_edges: usize = 4096,
    /// Total expected-policy entries ever inserted across all nodes.
    maximum_expected_policies: usize = 4096,
    maximum_output_policies: usize = 64,
    /// Global budget for OID comparisons and node scans.
    maximum_operations: usize = 1 << 20,
};

pub const InitialPolicySet = union(enum) {
    /// The special value any-policy: the user accepts whatever policies the
    /// authorities constrain the path to.
    any_policy,
    /// Explicit user-initial policies, borrowed for the validation call.
    /// anyPolicy and duplicate members are configuration errors.  An empty
    /// slice means no policy is acceptable to the user: the
    /// user-constrained output is always empty, so combining it with
    /// `initial_explicit_policy = true` rejects every path.
    explicit: []const oid.ObjectIdentifier,
};

/// RFC 5280 §6.1.1 policy-related initial inputs.  The defaults reproduce
/// ordinary TLS validation: no required policy, mapping permitted, anyPolicy
/// permitted.
pub const Config = struct {
    user_initial_policy_set: InitialPolicySet = .any_policy,
    initial_explicit_policy: bool = false,
    initial_policy_mapping_inhibit: bool = false,
    initial_any_policy_inhibit: bool = false,
    limits: Limits = .{},
};

/// Which part of RFC 5280 §6.1 processing a failure occurred in.
pub const Stage = enum {
    configuration,
    certificate_policies,
    policy_mappings,
    counters,
    wrap_up,
};

pub const FailureReason = enum {
    invalid_policy_configuration,
    certificate_policy_invalid,
    certificate_policy_required,
    certificate_policy_unsupported_qualifier,
    policy_mapping_invalid,
    policy_constraints_invalid,
    inhibit_any_policy_invalid,
    resource_limit_exceeded,
    out_of_memory,
};

pub const Failure = struct {
    reason: FailureReason,
    stage: Stage,
    /// Leaf-first index; null for configuration and allocation failures.
    certificate_index: ?usize = null,
    /// Value copies, never borrowed attacker-controlled bytes.
    extension_oid: ?oid.ObjectIdentifier = null,
    policy_oid: ?oid.ObjectIdentifier = null,
    /// RFC graph depth (0 at the anchor side, n at the target).
    graph_depth: ?usize = null,
};

/// Constrained policy outputs (RFC 9618 §5.5 / X.509 §12.2).  Both slices
/// hold unique OIDs sorted by numeric component order; the special anyPolicy
/// OID appears explicitly when the authorities or user place no constraint.
/// Qualifiers are deliberately omitted (RFC 9618 §4.2).  The deprecated
/// valid_policy_tree / policy graph is never returned.
pub const PolicyResult = struct {
    authority_constrained: []const oid.ObjectIdentifier,
    user_constrained: []const oid.ObjectIdentifier,

    pub fn deinit(self: *PolicyResult, allocator: std.mem.Allocator) void {
        allocator.free(self.authority_constrained);
        allocator.free(self.user_constrained);
        self.* = undefined;
    }
};

pub const Result = union(enum) {
    /// Slices are owned by the caller's allocator; free with
    /// `PolicyResult.deinit` (or `ValidationResult.deinit` downstream).
    accepted: PolicyResult,
    rejected: Failure,
};

/// Deterministic work counters for bounding proofs in tests.
pub const Stats = struct {
    total_nodes: usize = 0,
    total_edges: usize = 0,
    expected_entries: usize = 0,
    operations: usize = 0,
};

/// Process the policy extensions of one already-structurally-validated
/// candidate path.  The last element is the configured anchor and is not a
/// path certificate.  The only caller-visible allocations are the accepted
/// output slices; every rejection path frees all internal state.
pub fn validatePath(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    config: Config,
) Result {
    var stats: Stats = .{};
    return validatePathWithStats(allocator, path, config, &stats);
}

pub fn validatePathWithStats(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    config: Config,
    stats: *Stats,
) Result {
    if (validateConfig(config)) |failure| return .{ .rejected = failure };
    if (path.elements.len < 2) {
        return .{ .rejected = .{
            .reason = .invalid_policy_configuration,
            .stage = .configuration,
        } };
    }
    if (path.elements.len > config.limits.maximum_path_length) {
        return .{ .rejected = .{
            .reason = .resource_limit_exceeded,
            .stage = .configuration,
        } };
    }

    var state = State.init(allocator, config.limits, stats);
    defer state.deinit();

    const outcome = run(&state, path, config) catch |err| switch (err) {
        error.OutOfMemory => return .{ .rejected = .{
            .reason = .out_of_memory,
            .stage = .configuration,
        } },
        error.ResourceLimitExceeded => return .{ .rejected = .{
            .reason = .resource_limit_exceeded,
            .stage = .configuration,
            .certificate_index = state.current_leaf_index,
            .graph_depth = state.current_depth,
        } },
    };
    return outcome;
}

const Error = error{ OutOfMemory, ResourceLimitExceeded };

fn validateConfig(config: Config) ?Failure {
    switch (config.user_initial_policy_set) {
        .any_policy => return null,
        .explicit => |user_policies| {
            if (user_policies.len > config.limits.maximum_user_initial_policies) {
                return .{ .reason = .resource_limit_exceeded, .stage = .configuration };
            }
            for (user_policies, 0..) |*policy, index| {
                // anyPolicy inside an explicit set would be ambiguous with
                // the `.any_policy` variant; reject rather than guess.
                if (policy.eqlComponents(&wk.any_policy)) {
                    return .{
                        .reason = .invalid_policy_configuration,
                        .stage = .configuration,
                        .policy_oid = policy.*,
                    };
                }
                for (user_policies[0..index]) |*earlier| {
                    if (earlier.eql(policy)) {
                        return .{
                            .reason = .invalid_policy_configuration,
                            .stage = .configuration,
                            .policy_oid = policy.*,
                        };
                    }
                }
            }
            return null;
        },
    }
}

fn run(state: *State, path: path_builder.Path, config: Config) Error!Result {
    // RFC path: certificate 1 is directly below the anchor, certificate n is
    // the target.  Leaf-first index of RFC certificate i is n - i.
    const n = path.elements.len - 1;

    try state.initRoot();

    var explicit_policy: usize = if (config.initial_explicit_policy) 0 else n + 1;
    var policy_mapping: usize = if (config.initial_policy_mapping_inhibit) 0 else n + 1;
    var inhibit_any_policy: usize = if (config.initial_any_policy_inhibit) 0 else n + 1;

    var i: usize = 1;
    while (i <= n) : (i += 1) {
        const leaf_index = n - i;
        state.current_leaf_index = leaf_index;
        state.current_depth = i;
        const certificate = path.elements[leaf_index].certificate;
        const is_target = i == n;
        const self_issued = certificate.isSelfIssued();

        if (checkPolicyExtensions(certificate, leaf_index, is_target, i, config.limits)) |failure| {
            return .{ .rejected = failure };
        }

        // RFC 5280 §6.1.3 (d): process certificatePolicies against the graph.
        if (certificate.certificatePolicies()) |policies| {
            if (!state.graphIsNull()) {
                try state.beginDepth();
                const allow_any = inhibit_any_policy > 0 or (!is_target and self_issued);
                try processCertificatePolicies(state, policies, i, allow_any);
                try state.prune(i);
            }
        } else {
            // §6.1.3 (e): absent certificatePolicies nulls the graph.
            state.setNull();
        }

        // §6.1.3 (f).
        if (explicit_policy == 0 and state.graphIsNull()) {
            return .{ .rejected = .{
                .reason = .certificate_policy_required,
                .stage = .certificate_policies,
                .certificate_index = leaf_index,
                .graph_depth = i,
            } };
        }

        if (!is_target) {
            // §6.1.4 (a)/(b): policy mappings, using the pre-update counter.
            if (certificate.policyMappings()) |mappings| {
                if (!state.graphIsNull()) {
                    try processPolicyMappings(state, mappings, i, policy_mapping);
                }
            }

            // §6.1.4 (h): decrement counters unless self-issued.
            if (!self_issued) {
                if (explicit_policy > 0) explicit_policy -= 1;
                if (policy_mapping > 0) policy_mapping -= 1;
                if (inhibit_any_policy > 0) inhibit_any_policy -= 1;
            }

            // §6.1.4 (i)/(j): apply smaller constraint values.
            if (certificate.policyConstraints()) |constraints| {
                if (constraints.require_explicit_policy) |value| {
                    explicit_policy = @min(explicit_policy, value);
                }
                if (constraints.inhibit_policy_mapping) |value| {
                    policy_mapping = @min(policy_mapping, value);
                }
            }
            if (certificate.inhibitAnyPolicy()) |value| {
                inhibit_any_policy = @min(inhibit_any_policy, value);
            }
        }
    }

    // RFC 5280 §6.1.5 wrap-up.
    state.current_depth = n;
    if (explicit_policy > 0) explicit_policy -= 1;
    const target = path.elements[0].certificate;
    if (target.policyConstraints()) |constraints| {
        if (constraints.require_explicit_policy) |value| {
            if (value == 0) explicit_policy = 0;
        }
    }

    var outputs = try computeOutputs(state, config, n);

    // RFC 9618 §5.5 final check: explicit_policy > 0 or a nonempty
    // user-constrained set.
    if (explicit_policy == 0 and outputs.user_constrained.len == 0) {
        outputs.deinit(state.allocator);
        return .{ .rejected = .{
            .reason = .certificate_policy_required,
            .stage = .wrap_up,
            .certificate_index = 0,
            .graph_depth = n,
        } };
    }
    return .{ .accepted = outputs };
}

/// Structural and criticality rules for the policy extensions of one path
/// certificate.  A malformed or unsupported critical policy extension
/// rejects the path; it never silently erases policy state.
fn checkPolicyExtensions(
    certificate: *const x509.Certificate,
    leaf_index: usize,
    is_target: bool,
    depth: usize,
    limits: Limits,
) ?Failure {
    if (certificate.findExtension(&wk.certificate_policies)) |extension| {
        if (extension.parsed != .certificate_policies) {
            return policyExtensionFailure(.certificate_policy_invalid, .certificate_policies, leaf_index, depth, &wk.certificate_policies);
        }
        const policies = extension.parsed.certificate_policies;
        if (policies.len == 0) {
            return policyExtensionFailure(.certificate_policy_invalid, .certificate_policies, leaf_index, depth, &wk.certificate_policies);
        }
        if (policies.len > limits.maximum_policies_per_certificate) {
            return policyExtensionFailure(.resource_limit_exceeded, .certificate_policies, leaf_index, depth, &wk.certificate_policies);
        }
        for (policies, 0..) |*info, index| {
            // The #341 parser rejects duplicates; re-check defensively for
            // caller-constructed certificate views.
            for (policies[0..index]) |*earlier| {
                if (earlier.policy.eql(&info.policy)) {
                    var failure = policyExtensionFailure(.certificate_policy_invalid, .certificate_policies, leaf_index, depth, &wk.certificate_policies);
                    failure.policy_oid = info.policy;
                    return failure;
                }
            }
            if (extension.critical) {
                // A critical extension must not treat unrecognized qualifier
                // forms as understood (RFC 5280 §4.2.1.4).
                for (info.qualifiers) |*qualifier| {
                    if (qualifier.form == .unrecognized) {
                        var failure = policyExtensionFailure(.certificate_policy_unsupported_qualifier, .certificate_policies, leaf_index, depth, &wk.certificate_policies);
                        failure.policy_oid = info.policy;
                        return failure;
                    }
                }
            }
        }
    }

    if (certificate.findExtension(&wk.policy_mappings)) |extension| {
        if (extension.parsed != .policy_mappings) {
            return policyExtensionFailure(.policy_mapping_invalid, .policy_mappings, leaf_index, depth, &wk.policy_mappings);
        }
        // Policy mappings are meaningful only on CA certificates that issue
        // further path certificates; RFC 5280 §6.1 never processes them on
        // the target.
        if (is_target) {
            return policyExtensionFailure(.policy_mapping_invalid, .policy_mappings, leaf_index, depth, &wk.policy_mappings);
        }
        const mappings = extension.parsed.policy_mappings;
        if (mappings.len == 0) {
            return policyExtensionFailure(.policy_mapping_invalid, .policy_mappings, leaf_index, depth, &wk.policy_mappings);
        }
        if (mappings.len > limits.maximum_mappings_per_certificate) {
            return policyExtensionFailure(.resource_limit_exceeded, .policy_mappings, leaf_index, depth, &wk.policy_mappings);
        }
        for (mappings) |*mapping| {
            // Parser-enforced; defensive for caller-constructed views.
            if (mapping.issuer_domain_policy.eqlComponents(&wk.any_policy) or
                mapping.subject_domain_policy.eqlComponents(&wk.any_policy))
            {
                var failure = policyExtensionFailure(.policy_mapping_invalid, .policy_mappings, leaf_index, depth, &wk.policy_mappings);
                failure.policy_oid = oid.ObjectIdentifier.fromComponents(&wk.any_policy) catch unreachable;
                return failure;
            }
        }
    }

    if (certificate.findExtension(&wk.policy_constraints)) |extension| {
        if (extension.parsed != .policy_constraints) {
            return policyExtensionFailure(.policy_constraints_invalid, .counters, leaf_index, depth, &wk.policy_constraints);
        }
        // RFC 5280 §4.2.1.11: conforming CAs MUST mark policyConstraints
        // critical; a noncritical instance fails closed.
        if (!extension.critical) {
            return policyExtensionFailure(.policy_constraints_invalid, .counters, leaf_index, depth, &wk.policy_constraints);
        }
        const constraints = extension.parsed.policy_constraints;
        if (constraints.require_explicit_policy == null and constraints.inhibit_policy_mapping == null) {
            return policyExtensionFailure(.policy_constraints_invalid, .counters, leaf_index, depth, &wk.policy_constraints);
        }
    }

    if (certificate.findExtension(&wk.inhibit_any_policy)) |extension| {
        if (extension.parsed != .inhibit_any_policy) {
            return policyExtensionFailure(.inhibit_any_policy_invalid, .counters, leaf_index, depth, &wk.inhibit_any_policy);
        }
        // RFC 5280 §4.2.1.14: MUST be critical, and the extension is defined
        // for certificates issued to CAs; it never belongs on the target
        // end-entity certificate.
        if (!extension.critical) {
            return policyExtensionFailure(.inhibit_any_policy_invalid, .counters, leaf_index, depth, &wk.inhibit_any_policy);
        }
        const is_ca = if (certificate.basicConstraints()) |constraints| constraints.is_ca else false;
        if (!is_ca) {
            return policyExtensionFailure(.inhibit_any_policy_invalid, .counters, leaf_index, depth, &wk.inhibit_any_policy);
        }
    }

    return null;
}

fn policyExtensionFailure(
    reason: FailureReason,
    stage: Stage,
    leaf_index: usize,
    depth: usize,
    extension_components: []const u32,
) Failure {
    return .{
        .reason = reason,
        .stage = stage,
        .certificate_index = leaf_index,
        // Compile-time well-known OIDs only; always within component bounds.
        .extension_oid = oid.ObjectIdentifier.fromComponents(extension_components) catch unreachable,
        .graph_depth = depth,
    };
}

/// RFC 5280 §6.1.3 (d)(1) and (d)(2) as replaced by RFC 9618 §5.3.
fn processCertificatePolicies(
    state: *State,
    policies: []const x509.PolicyInformation,
    depth: usize,
    allow_any_policy: bool,
) Error!void {
    // (d)(1): each non-anyPolicy policy creates at most one node at this
    // depth, with all matching parents merged.
    for (policies) |*info| {
        if (info.is_any_policy) continue;
        try addMatchedNode(state, depth, &info.policy);
    }

    // (d)(2): a permitted anyPolicy stands in for every expected policy not
    // already asserted.
    var contains_any_policy = false;
    for (policies) |*info| {
        if (info.is_any_policy) contains_any_policy = true;
    }
    if (contains_any_policy and allow_any_policy) {
        const parent_range = state.depthRange(depth - 1);
        var parent_index = parent_range.start;
        while (parent_index < parent_range.end) : (parent_index += 1) {
            if (!state.nodes.items[parent_index].alive) continue;
            const expected_len = state.nodes.items[parent_index].expected.items.len;
            var expected_index: usize = 0;
            while (expected_index < expected_len) : (expected_index += 1) {
                const expected_policy = state.nodes.items[parent_index].expected.items[expected_index];
                try state.charge(1);
                if (state.findNode(depth, &expected_policy) != null) continue;
                try addMatchedNode(state, depth, &expected_policy);
            }
        }
    }
}

/// One (d)(1)/(d)(2) node creation: parents are every live node at the
/// previous depth whose expected set contains the policy; with no such
/// parent, the previous depth's anyPolicy node when it exists; otherwise
/// the policy is dropped.
fn addMatchedNode(state: *State, depth: usize, policy: *const oid.ObjectIdentifier) Error!void {
    const parent_range = state.depthRange(depth - 1);
    const node_index = blk: {
        if (state.findNode(depth, policy)) |existing| break :blk existing;
        break :blk try state.createNode(depth, policy);
    };

    var matched = false;
    var parent_index = parent_range.start;
    while (parent_index < parent_range.end) : (parent_index += 1) {
        const parent = &state.nodes.items[parent_index];
        if (!parent.alive) continue;
        if (try state.expectedContains(parent, policy)) {
            matched = true;
            try state.addParent(node_index, parent_index);
        }
    }
    if (matched) return;

    if (state.findAnyPolicyNode(depth - 1)) |any_parent| {
        try state.addParent(node_index, any_parent);
        return;
    }

    // No parent expects this policy and no anyPolicy node exists: the
    // freshly created node (if any) is unreachable and removed again.
    const node = &state.nodes.items[node_index];
    if (node.parents.items.len == 0) node.alive = false;
}

/// RFC 5280 §6.1.4 (b) as replaced by RFC 9618 §5.4.
fn processPolicyMappings(
    state: *State,
    mappings: []const x509.PolicyMapping,
    depth: usize,
    policy_mapping: usize,
) Error!void {
    const processed = try state.arena.allocator().alloc(bool, mappings.len);
    @memset(processed, false);

    for (mappings, 0..) |*mapping, mapping_index| {
        if (processed[mapping_index]) continue;

        // Group every subjectDomainPolicy for this issuerDomainPolicy,
        // deduplicating identical pairs deterministically (first
        // occurrence wins; order is the extension's encoding order).
        var subjects: std.ArrayList(oid.ObjectIdentifier) = .empty;
        for (mappings[mapping_index..], mapping_index..) |*candidate, candidate_index| {
            try state.charge(1);
            if (!candidate.issuer_domain_policy.eql(&mapping.issuer_domain_policy)) continue;
            processed[candidate_index] = true;
            var duplicate = false;
            for (subjects.items) |*existing| {
                try state.charge(1);
                if (existing.eql(&candidate.subject_domain_policy)) duplicate = true;
            }
            if (!duplicate) {
                try subjects.append(state.arena.allocator(), candidate.subject_domain_policy);
            }
        }

        if (policy_mapping > 0) {
            if (state.findNode(depth, &mapping.issuer_domain_policy)) |node_index| {
                // (b)(1): replace the node's expected set with the mapped
                // subject policies.
                try state.replaceExpected(node_index, subjects.items);
            } else if (state.findAnyPolicyNode(depth)) |any_node_index| {
                // (b)(2): materialize the issuer policy as a child of the
                // previous depth's anyPolicy node.  That parent exists and
                // is alive by the RFC 9618 anyPolicy-chain invariant.
                const any_parent = state.nodes.items[any_node_index].parents.items[0];
                const node_index = try state.createNode(depth, &mapping.issuer_domain_policy);
                try state.addParent(node_index, any_parent);
                try state.replaceExpected(node_index, subjects.items);
            }
        } else {
            // (b)(3): mapping inhibited — delete the issuer-domain node and
            // prune ancestors that no longer reach this depth.
            if (state.findNode(depth, &mapping.issuer_domain_policy)) |node_index| {
                state.nodes.items[node_index].alive = false;
                try state.prune(depth);
            }
        }
    }
}

/// RFC 9618 §5.5 step (g): authority- and user-constrained policy sets.
fn computeOutputs(state: *State, config: Config, n: usize) Error!PolicyResult {
    const arena = state.arena.allocator();
    var authority: std.ArrayList(oid.ObjectIdentifier) = .empty;

    if (!state.graphIsNull()) {
        // (g)(2): nodes whose valid_policy is not anyPolicy and whose only
        // parent is an anyPolicy node, at any depth.  All live nodes reach
        // depth n after pruning, so no dead branches contribute.
        var depth: usize = 1;
        while (depth <= n) : (depth += 1) {
            const range = state.depthRange(depth);
            var node_index = range.start;
            while (node_index < range.end) : (node_index += 1) {
                const node = &state.nodes.items[node_index];
                try state.charge(1);
                if (!node.alive or node.is_any_policy) continue;
                if (node.parents.items.len != 1) continue;
                if (!state.nodes.items[node.parents.items[0]].is_any_policy) continue;
                try appendUnique(state, &authority, arena, &node.policy);
            }
        }
        // (g)(3): a surviving anyPolicy node at depth n joins the set.
        if (state.findAnyPolicyNode(n) != null) {
            const any_policy_oid = oid.ObjectIdentifier.fromComponents(&wk.any_policy) catch unreachable;
            try appendUnique(state, &authority, arena, &any_policy_oid);
        }
    }

    // (g)(5)/(g)(6): the user-constrained set starts as the authority set
    // and is intersected with an explicit user-initial-policy-set, with a
    // final authority anyPolicy expanding into the requested policies.
    var user: std.ArrayList(oid.ObjectIdentifier) = .empty;
    switch (config.user_initial_policy_set) {
        .any_policy => {
            try user.appendSlice(arena, authority.items);
        },
        .explicit => |user_policies| {
            var authority_has_any_policy = false;
            for (authority.items) |*policy| {
                try state.charge(1);
                if (policy.eqlComponents(&wk.any_policy)) {
                    authority_has_any_policy = true;
                    continue;
                }
                for (user_policies) |*user_policy| {
                    try state.charge(1);
                    if (user_policy.eql(policy)) {
                        try user.append(arena, policy.*);
                        break;
                    }
                }
            }
            if (authority_has_any_policy) {
                for (user_policies) |*user_policy| {
                    try appendUnique(state, &user, arena, user_policy);
                }
            }
        },
    }

    if (authority.items.len > config.limits.maximum_output_policies or
        user.items.len > config.limits.maximum_output_policies)
    {
        return error.ResourceLimitExceeded;
    }

    std.mem.sort(oid.ObjectIdentifier, authority.items, {}, oidLessThan);
    std.mem.sort(oid.ObjectIdentifier, user.items, {}, oidLessThan);

    const authority_owned = try state.allocator.dupe(oid.ObjectIdentifier, authority.items);
    errdefer state.allocator.free(authority_owned);
    const user_owned = try state.allocator.dupe(oid.ObjectIdentifier, user.items);
    return .{
        .authority_constrained = authority_owned,
        .user_constrained = user_owned,
    };
}

fn appendUnique(
    state: *State,
    list: *std.ArrayList(oid.ObjectIdentifier),
    arena: std.mem.Allocator,
    policy: *const oid.ObjectIdentifier,
) Error!void {
    for (list.items) |*existing| {
        try state.charge(1);
        if (existing.eql(policy)) return;
    }
    try list.append(arena, policy.*);
}

fn oidLessThan(_: void, a: oid.ObjectIdentifier, b: oid.ObjectIdentifier) bool {
    const a_components = a.components();
    const b_components = b.components();
    const shared = @min(a_components.len, b_components.len);
    for (a_components[0..shared], b_components[0..shared]) |left, right| {
        if (left != right) return left < right;
    }
    return a_components.len < b_components.len;
}

const Node = struct {
    policy: oid.ObjectIdentifier,
    is_any_policy: bool,
    /// Unique expected-policy OIDs (RFC 9618: exactly {anyPolicy} for
    /// anyPolicy nodes).
    expected: std.ArrayList(oid.ObjectIdentifier),
    /// Unique indices of parent nodes; always at the previous depth.
    parents: std.ArrayList(usize),
    alive: bool,
};

const DepthRange = struct { start: usize, end: usize };

const State = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    limits: Limits,
    stats: *Stats,
    nodes: std.ArrayList(Node) = .empty,
    /// depth_offsets[d] is the index of the first node at depth d.
    depth_offsets: std.ArrayList(usize) = .empty,
    graph_null: bool = false,
    current_leaf_index: ?usize = null,
    current_depth: ?usize = null,

    fn init(allocator: std.mem.Allocator, limits: Limits, stats: *Stats) State {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .limits = limits,
            .stats = stats,
        };
    }

    fn deinit(self: *State) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn charge(self: *State, operations: usize) Error!void {
        self.stats.operations = std.math.add(usize, self.stats.operations, operations) catch
            return error.ResourceLimitExceeded;
        if (self.stats.operations > self.limits.maximum_operations) {
            return error.ResourceLimitExceeded;
        }
    }

    fn initRoot(self: *State) Error!void {
        const arena = self.arena.allocator();
        try self.depth_offsets.append(arena, 0);
        const any_policy_oid = oid.ObjectIdentifier.fromComponents(&wk.any_policy) catch unreachable;
        _ = try self.createNode(0, &any_policy_oid);
    }

    fn graphIsNull(self: *const State) bool {
        return self.graph_null;
    }

    fn setNull(self: *State) void {
        self.graph_null = true;
    }

    fn beginDepth(self: *State) Error!void {
        try self.depth_offsets.append(self.arena.allocator(), self.nodes.items.len);
    }

    fn depthRange(self: *const State, depth: usize) DepthRange {
        const start = self.depth_offsets.items[depth];
        const end = if (depth + 1 < self.depth_offsets.items.len)
            self.depth_offsets.items[depth + 1]
        else
            self.nodes.items.len;
        return .{ .start = start, .end = end };
    }

    fn currentDepthIndex(self: *const State) usize {
        return self.depth_offsets.items.len - 1;
    }

    fn findNode(self: *State, depth: usize, policy: *const oid.ObjectIdentifier) ?usize {
        const range = self.depthRange(depth);
        var index = range.start;
        while (index < range.end) : (index += 1) {
            self.stats.operations += 1;
            const node = &self.nodes.items[index];
            if (node.alive and node.policy.eql(policy)) return index;
        }
        return null;
    }

    fn findAnyPolicyNode(self: *State, depth: usize) ?usize {
        const range = self.depthRange(depth);
        var index = range.start;
        while (index < range.end) : (index += 1) {
            self.stats.operations += 1;
            const node = &self.nodes.items[index];
            if (node.alive and node.is_any_policy) return index;
        }
        return null;
    }

    /// Create a node at the current frontier depth.  Callers guarantee no
    /// live duplicate exists (RFC 9618: one node per OID per depth).
    fn createNode(self: *State, depth: usize, policy: *const oid.ObjectIdentifier) Error!usize {
        if (self.currentDepthIndex() != depth) return error.ResourceLimitExceeded;
        const range = self.depthRange(depth);
        if (range.end - range.start >= self.limits.maximum_nodes_per_depth) {
            return error.ResourceLimitExceeded;
        }
        if (self.nodes.items.len >= self.limits.maximum_total_nodes) {
            return error.ResourceLimitExceeded;
        }
        const is_any = policy.eqlComponents(&wk.any_policy);
        try self.nodes.append(self.arena.allocator(), .{
            .policy = policy.*,
            .is_any_policy = is_any,
            .expected = .empty,
            .parents = .empty,
            .alive = true,
        });
        self.stats.total_nodes += 1;
        const node_index = self.nodes.items.len - 1;
        // Default expected_policy_set is {P-OID}; mappings may replace it
        // later.  anyPolicy nodes always expect exactly {anyPolicy}.
        try self.appendExpected(&self.nodes.items[node_index], policy);
        return node_index;
    }

    fn appendExpected(self: *State, node: *Node, policy: *const oid.ObjectIdentifier) Error!void {
        self.stats.expected_entries += 1;
        if (self.stats.expected_entries > self.limits.maximum_expected_policies) {
            return error.ResourceLimitExceeded;
        }
        try node.expected.append(self.arena.allocator(), policy.*);
    }

    fn replaceExpected(self: *State, node_index: usize, policies: []const oid.ObjectIdentifier) Error!void {
        const node = &self.nodes.items[node_index];
        node.expected.clearRetainingCapacity();
        for (policies) |*policy| {
            try self.appendExpected(node, policy);
        }
    }

    fn expectedContains(self: *State, node: *const Node, policy: *const oid.ObjectIdentifier) Error!bool {
        for (node.expected.items) |*expected| {
            try self.charge(1);
            if (expected.eql(policy)) return true;
        }
        return false;
    }

    fn addParent(self: *State, node_index: usize, parent_index: usize) Error!void {
        const node = &self.nodes.items[node_index];
        for (node.parents.items) |existing| {
            try self.charge(1);
            if (existing == parent_index) return;
        }
        self.stats.total_edges += 1;
        if (self.stats.total_edges > self.limits.maximum_total_edges) {
            return error.ResourceLimitExceeded;
        }
        try node.parents.append(self.arena.allocator(), parent_index);
    }

    /// RFC 9618 §5.3 (d)(3) / §5.4 (b)(3)(ii): iteratively delete nodes at
    /// depth `frontier - 1` and below without live children.  Descending one
    /// depth at a time visits each node once, so no repeat passes are
    /// needed, and an emptied frontier nulls the graph.
    fn prune(self: *State, frontier: usize) Error!void {
        if (self.graph_null) return;
        var depth = frontier;
        while (depth > 0) {
            depth -= 1;
            const range = self.depthRange(depth);
            const child_range = self.depthRange(depth + 1);
            var index = range.start;
            while (index < range.end) : (index += 1) {
                const node = &self.nodes.items[index];
                if (!node.alive) continue;
                var has_live_child = false;
                var child_index = child_range.start;
                while (child_index < child_range.end) : (child_index += 1) {
                    const child = &self.nodes.items[child_index];
                    if (!child.alive) continue;
                    for (child.parents.items) |parent_index| {
                        try self.charge(1);
                        if (parent_index == index) {
                            has_live_child = true;
                            break;
                        }
                    }
                    if (has_live_child) break;
                }
                if (!has_live_child) node.alive = false;
            }
        }

        const frontier_range = self.depthRange(frontier);
        var live_frontier = false;
        var index = frontier_range.start;
        while (index < frontier_range.end) : (index += 1) {
            if (self.nodes.items[index].alive) live_frontier = true;
        }
        if (!live_frontier) self.setNull();
    }
};

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
