//! Bounded RFC 5280 / RFC 9618 certificate-policy validation.
//!
//! The policy state is a directed acyclic graph with one node per policy OID
//! per depth. Nodes contain integer parent indices into `nodes`; a converging
//! mapping therefore adds another parent reference instead of copying the
//! node and all of its descendants. With the configured node, edge, expected
//! policy, parent-reference, depth, and operation limits, growth is
//! polynomial and attacker-controlled recursive tree expansion is impossible.
//!
//! Policy qualifiers are parsed and validated by `x509.zig`, but are omitted
//! from the result as permitted by RFC 9618. CPS URIs are never fetched and
//! user notices are never displayed.

const std = @import("std");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const x509 = @import("x509.zig");

const wk = oid.well_known;

pub const InitialPolicySet = union(enum) {
    any_policy,
    /// Borrowed for the validation call. Empty means the caller accepts no
    /// policy; validation can still succeed while explicit policy is not
    /// required, with an empty user-constrained result.
    explicit: []const oid.ObjectIdentifier,
};

pub const Limits = struct {
    maximum_policy_oids_per_certificate: usize = 32,
    maximum_policy_qualifiers_per_policy: usize = 16,
    maximum_qualifier_encoded_length: usize = 4096,
    maximum_policy_mappings_per_certificate: usize = 64,
    maximum_graph_depth: usize = 8,
    maximum_nodes_per_depth: usize = 64,
    maximum_total_nodes: usize = 257,
    maximum_total_edges: usize = 4096,
    maximum_expected_policy_entries: usize = 4096,
    maximum_parent_references: usize = 4096,
    maximum_user_initial_policies: usize = 64,
    maximum_output_policies: usize = 128,
    maximum_operations: usize = 100_000,
};

pub const Configuration = struct {
    user_initial_policy_set: InitialPolicySet = .any_policy,
    initial_explicit_policy: bool = false,
    initial_policy_mapping_inhibit: bool = false,
    initial_any_policy_inhibit: bool = false,
    limits: Limits = .{},
};

pub const Stage = enum {
    configuration,
    policy,
    mapping,
    counter,
    wrap_up,
};

pub const FailureReason = enum {
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
    /// Leaf-first index, null for configuration or allocation failures.
    certificate_index: ?usize,
    extension_oid: ?oid.ObjectIdentifier = null,
    policy_oid: ?oid.ObjectIdentifier = null,
    graph_depth: ?usize = null,
    stage: Stage,
};

pub const PolicyResult = struct {
    /// Owned, unique, lexicographically ordered OID value copies.
    authority_constrained: []const oid.ObjectIdentifier,
    /// Owned, unique, lexicographically ordered OID value copies.
    user_constrained: []const oid.ObjectIdentifier,
    /// Deterministic accounting for the bounded graph run. This is useful for
    /// capacity planning and for proving that mapping convergence does not
    /// silently expand into a tree.
    resource_usage: ResourceUsage,

    pub fn deinit(self: *PolicyResult, allocator: std.mem.Allocator) void {
        allocator.free(self.authority_constrained);
        allocator.free(self.user_constrained);
        self.* = undefined;
    }
};

pub const ResourceUsage = struct {
    graph_nodes: usize,
    graph_edges: usize,
    expected_policy_entries: usize,
    parent_references: usize,
    operations: usize,
};

pub const Outcome = union(enum) {
    success: PolicyResult,
    failure: Failure,
};

const Node = struct {
    depth: usize,
    valid_policy: oid.ObjectIdentifier,
    expected: std.ArrayList(oid.ObjectIdentifier) = .empty,
    parents: std.ArrayList(usize) = .empty,
    alive: bool = true,
};

const RunError = error{ Rejected, OutOfMemory };

const Engine = struct {
    arena: std.mem.Allocator,
    output_allocator: std.mem.Allocator,
    path: path_builder.Path,
    config: Configuration,
    nodes: std.ArrayList(Node) = .empty,
    failure: ?Failure = null,
    operations: usize = 0,
    total_edges: usize = 0,
    total_expected_entries: usize = 0,
    total_parent_references: usize = 0,
    graph_active: bool = true,
    explicit_policy: usize = 0,
    policy_mapping: usize = 0,
    inhibit_any_policy: usize = 0,

    fn run(self: *Engine) RunError!PolicyResult {
        const path_certificates = self.path.elements.len - 1;
        if (path_certificates > self.config.limits.maximum_graph_depth) {
            return self.reject(.resource_limit_exceeded, null, null, null, null, .configuration);
        }
        try self.validateConfiguration();

        const initial_counter = std.math.add(usize, path_certificates, 1) catch
            return self.reject(.resource_limit_exceeded, null, null, null, null, .configuration);
        self.explicit_policy = if (self.config.initial_explicit_policy) 0 else initial_counter;
        self.policy_mapping = if (self.config.initial_policy_mapping_inhibit) 0 else initial_counter;
        self.inhibit_any_policy = if (self.config.initial_any_policy_inhibit) 0 else initial_counter;

        const any_policy = oid.ObjectIdentifier.fromComponents(&wk.any_policy) catch unreachable;
        try self.addNode(0, any_policy, &.{any_policy}, &.{}, null, .configuration);

        var depth: usize = 1;
        while (depth <= path_certificates) : (depth += 1) {
            const certificate_index = path_certificates - depth;
            const certificate = self.path.elements[certificate_index].certificate;
            try self.validateExtensionProfile(certificate, certificate_index, depth, depth == path_certificates);
            try self.processCertificatePolicies(certificate, certificate_index, depth, path_certificates);

            if (self.explicit_policy == 0 and !self.graph_active) {
                return self.reject(
                    .certificate_policy_required,
                    certificate_index,
                    &wk.certificate_policies,
                    null,
                    depth,
                    .policy,
                );
            }

            if (depth < path_certificates) {
                try self.processMappings(certificate, certificate_index, depth);
                if (!certificate.isSelfIssued()) {
                    decrement(&self.explicit_policy);
                    decrement(&self.policy_mapping);
                    decrement(&self.inhibit_any_policy);
                }
                if (certificate.policyConstraints()) |constraints| {
                    if (constraints.require_explicit_policy) |value| {
                        self.explicit_policy = @min(self.explicit_policy, value);
                    }
                    if (constraints.inhibit_policy_mapping) |value| {
                        self.policy_mapping = @min(self.policy_mapping, value);
                    }
                }
                if (certificate.inhibitAnyPolicy()) |value| {
                    self.inhibit_any_policy = @min(self.inhibit_any_policy, value);
                }
            } else {
                decrement(&self.explicit_policy);
                if (certificate.policyConstraints()) |constraints| {
                    if (constraints.require_explicit_policy == 0) self.explicit_policy = 0;
                }
            }
        }

        return self.wrapUp(path_certificates);
    }

    fn validateConfiguration(self: *Engine) RunError!void {
        switch (self.config.user_initial_policy_set) {
            .any_policy => {},
            .explicit => |policies| {
                if (policies.len > self.config.limits.maximum_user_initial_policies) {
                    return self.reject(.resource_limit_exceeded, null, null, null, null, .configuration);
                }
                for (policies, 0..) |policy, index| {
                    if (policy.eqlComponents(&wk.any_policy)) {
                        return self.reject(.certificate_policy_invalid, null, null, &policy, null, .configuration);
                    }
                    for (policies[0..index]) |earlier| {
                        try self.charge(1, null, null, .configuration);
                        if (policy.eql(&earlier)) {
                            return self.reject(.certificate_policy_invalid, null, null, &policy, null, .configuration);
                        }
                    }
                }
            },
        }
    }

    fn validateExtensionProfile(
        self: *Engine,
        certificate: *const x509.Certificate,
        certificate_index: usize,
        depth: usize,
        is_target: bool,
    ) RunError!void {
        if (certificate.findExtension(&wk.certificate_policies)) |extension| {
            const policies = extension.parsed.certificate_policies;
            if (policies.len == 0) {
                return self.reject(.certificate_policy_invalid, certificate_index, &wk.certificate_policies, null, depth, .policy);
            }
            if (policies.len > self.config.limits.maximum_policy_oids_per_certificate) {
                return self.reject(.resource_limit_exceeded, certificate_index, &wk.certificate_policies, null, depth, .policy);
            }
            for (policies, 0..) |policy, index| {
                for (policies[0..index]) |earlier| {
                    try self.charge(1, certificate_index, depth, .policy);
                    if (policy.policy.eql(&earlier.policy)) {
                        return self.reject(.certificate_policy_invalid, certificate_index, &wk.certificate_policies, &policy.policy, depth, .policy);
                    }
                }
                if (policy.qualifiers.len > self.config.limits.maximum_policy_qualifiers_per_policy) {
                    return self.reject(.resource_limit_exceeded, certificate_index, &wk.certificate_policies, &policy.policy, depth, .policy);
                }
                for (policy.qualifiers) |qualifier| {
                    if (qualifier.value_raw.len > self.config.limits.maximum_qualifier_encoded_length) {
                        return self.reject(.resource_limit_exceeded, certificate_index, &wk.certificate_policies, &policy.policy, depth, .policy);
                    }
                    if (qualifier.kind == .unsupported and (extension.critical or policy.policy.eqlComponents(&wk.any_policy))) {
                        return self.reject(
                            .certificate_policy_unsupported_qualifier,
                            certificate_index,
                            &wk.certificate_policies,
                            &policy.policy,
                            depth,
                            .policy,
                        );
                    }
                }
            }
        }

        if (certificate.findExtension(&wk.policy_mappings)) |extension| {
            const mappings = extension.parsed.policy_mappings;
            const constraints = certificate.basicConstraints();
            if (is_target or constraints == null or !constraints.?.is_ca or mappings.len == 0) {
                return self.reject(.policy_mapping_invalid, certificate_index, &wk.policy_mappings, null, depth, .mapping);
            }
            if (mappings.len > self.config.limits.maximum_policy_mappings_per_certificate) {
                return self.reject(.resource_limit_exceeded, certificate_index, &wk.policy_mappings, null, depth, .mapping);
            }
            for (mappings, 0..) |mapping, index| {
                if (mapping.issuer_domain_policy.eqlComponents(&wk.any_policy) or
                    mapping.subject_domain_policy.eqlComponents(&wk.any_policy))
                {
                    const offending = if (mapping.issuer_domain_policy.eqlComponents(&wk.any_policy))
                        mapping.issuer_domain_policy
                    else
                        mapping.subject_domain_policy;
                    return self.reject(.policy_mapping_invalid, certificate_index, &wk.policy_mappings, &offending, depth, .mapping);
                }
                for (mappings[0..index]) |earlier| {
                    try self.charge(1, certificate_index, depth, .mapping);
                    if (mapping.issuer_domain_policy.eql(&earlier.issuer_domain_policy) and
                        mapping.subject_domain_policy.eql(&earlier.subject_domain_policy))
                    {
                        return self.reject(.policy_mapping_invalid, certificate_index, &wk.policy_mappings, &mapping.issuer_domain_policy, depth, .mapping);
                    }
                }
            }
        }

        if (certificate.findExtension(&wk.policy_constraints)) |extension| {
            const constraints = certificate.basicConstraints();
            if (!extension.critical or constraints == null or !constraints.?.is_ca) {
                return self.reject(.policy_constraints_invalid, certificate_index, &wk.policy_constraints, null, depth, .counter);
            }
            const parsed = extension.parsed.policy_constraints;
            if (parsed.require_explicit_policy == null and parsed.inhibit_policy_mapping == null) {
                return self.reject(.policy_constraints_invalid, certificate_index, &wk.policy_constraints, null, depth, .counter);
            }
        }

        if (certificate.findExtension(&wk.inhibit_any_policy)) |extension| {
            const constraints = certificate.basicConstraints();
            if (!extension.critical or constraints == null or !constraints.?.is_ca) {
                return self.reject(.inhibit_any_policy_invalid, certificate_index, &wk.inhibit_any_policy, null, depth, .counter);
            }
        }
    }

    fn processCertificatePolicies(
        self: *Engine,
        certificate: *const x509.Certificate,
        certificate_index: usize,
        depth: usize,
        path_certificates: usize,
    ) RunError!void {
        const policies = certificate.certificatePolicies() orelse {
            self.graph_active = false;
            for (self.nodes.items) |*node| node.alive = false;
            return;
        };
        if (!self.graph_active) return;

        var any_policy_info: ?x509.PolicyInformation = null;
        for (policies) |policy| {
            if (policy.policy.eqlComponents(&wk.any_policy)) {
                any_policy_info = policy;
                continue;
            }
            var parents: std.ArrayList(usize) = .empty;
            for (self.nodes.items, 0..) |node, node_index| {
                if (!node.alive or node.depth != depth - 1) continue;
                if (try self.nodeExpects(node_index, &policy.policy, certificate_index, depth)) {
                    try self.appendUniqueParent(&parents, node_index, certificate_index, depth);
                }
            }
            if (parents.items.len == 0) {
                if (try self.findAliveNode(depth - 1, &wk.any_policy, certificate_index, depth, .policy)) |any_parent| {
                    try self.appendUniqueParent(&parents, any_parent, certificate_index, depth);
                }
            }
            if (parents.items.len != 0) {
                try self.addNode(depth, policy.policy, &.{policy.policy}, parents.items, certificate_index, .policy);
            }
        }

        if (any_policy_info != null and
            (self.inhibit_any_policy > 0 or (depth < path_certificates and certificate.isSelfIssued())))
        {
            var expected: std.ArrayList(oid.ObjectIdentifier) = .empty;
            for (self.nodes.items, 0..) |node, node_index| {
                if (!node.alive or node.depth != depth - 1) continue;
                for (node.expected.items) |candidate| {
                    try self.appendUniqueOid(&expected, candidate, certificate_index, depth, .policy);
                }
                _ = node_index;
            }
            for (expected.items) |candidate| {
                if (try self.findAliveNodeOid(depth, &candidate, certificate_index, depth, .policy) != null) continue;
                var parents: std.ArrayList(usize) = .empty;
                for (self.nodes.items, 0..) |node, node_index| {
                    if (!node.alive or node.depth != depth - 1) continue;
                    if (try self.nodeExpects(node_index, &candidate, certificate_index, depth)) {
                        try self.appendUniqueParent(&parents, node_index, certificate_index, depth);
                    }
                }
                if (parents.items.len != 0) try self.addNode(depth, candidate, &.{candidate}, parents.items, certificate_index, .policy);
            }
        }

        try self.pruneAncestors(depth, certificate_index, .policy);
        self.graph_active = try self.hasAliveAtDepth(depth, certificate_index, .policy);
    }

    fn processMappings(
        self: *Engine,
        certificate: *const x509.Certificate,
        certificate_index: usize,
        depth: usize,
    ) RunError!void {
        const mappings = certificate.policyMappings() orelse return;
        var processed_issuers: std.ArrayList(oid.ObjectIdentifier) = .empty;
        for (mappings) |mapping| {
            if (try self.containsOid(processed_issuers.items, &mapping.issuer_domain_policy, certificate_index, depth, .mapping)) continue;
            try processed_issuers.append(self.arena, mapping.issuer_domain_policy);

            var subjects: std.ArrayList(oid.ObjectIdentifier) = .empty;
            for (mappings) |candidate| {
                try self.charge(1, certificate_index, depth, .mapping);
                if (candidate.issuer_domain_policy.eql(&mapping.issuer_domain_policy)) {
                    try self.appendUniqueOid(&subjects, candidate.subject_domain_policy, certificate_index, depth, .mapping);
                }
            }

            if (self.policy_mapping > 0) {
                if (try self.findAliveNodeOid(depth, &mapping.issuer_domain_policy, certificate_index, depth, .mapping)) |node_index| {
                    try self.replaceExpected(node_index, subjects.items, certificate_index, depth);
                } else if (try self.findAliveNode(depth, &wk.any_policy, certificate_index, depth, .mapping)) |_| {
                    const any_parent = try self.findAliveNode(depth - 1, &wk.any_policy, certificate_index, depth, .mapping) orelse continue;
                    try self.addNode(depth, mapping.issuer_domain_policy, subjects.items, &.{any_parent}, certificate_index, .mapping);
                }
            } else if (try self.findAliveNodeOid(depth, &mapping.issuer_domain_policy, certificate_index, depth, .mapping)) |node_index| {
                self.nodes.items[node_index].alive = false;
                try self.pruneAncestors(depth, certificate_index, .mapping);
                self.graph_active = try self.hasAliveAtDepth(depth, certificate_index, .mapping);
            }
        }
    }

    fn wrapUp(self: *Engine, depth: usize) RunError!PolicyResult {
        var authority: std.ArrayList(oid.ObjectIdentifier) = .empty;
        if (self.graph_active) {
            for (self.nodes.items) |node| {
                if (!node.alive) continue;
                var include = node.valid_policy.eqlComponents(&wk.any_policy) and node.depth == depth;
                if (!node.valid_policy.eqlComponents(&wk.any_policy) and node.parents.items.len == 1) {
                    const parent = self.nodes.items[node.parents.items[0]];
                    include = parent.alive and parent.valid_policy.eqlComponents(&wk.any_policy);
                }
                if (include) try self.appendOutput(&authority, node.valid_policy);
            }
        }

        var user: std.ArrayList(oid.ObjectIdentifier) = .empty;
        switch (self.config.user_initial_policy_set) {
            .any_policy => {
                for (authority.items) |policy| try self.appendOutput(&user, policy);
            },
            .explicit => |requested| {
                var authority_has_any = false;
                for (authority.items) |policy| {
                    if (policy.eqlComponents(&wk.any_policy)) {
                        authority_has_any = true;
                    } else if (try self.containsOid(requested, &policy, null, depth, .wrap_up)) {
                        try self.appendOutput(&user, policy);
                    }
                }
                if (authority_has_any) {
                    for (requested) |policy| try self.appendOutput(&user, policy);
                }
            },
        }

        std.mem.sort(oid.ObjectIdentifier, authority.items, {}, oidLessThan);
        std.mem.sort(oid.ObjectIdentifier, user.items, {}, oidLessThan);
        if (self.explicit_policy == 0 and user.items.len == 0) {
            return self.reject(.certificate_policy_required, 0, &wk.certificate_policies, null, depth, .wrap_up);
        }

        const authority_owned = self.output_allocator.dupe(oid.ObjectIdentifier, authority.items) catch return error.OutOfMemory;
        errdefer self.output_allocator.free(authority_owned);
        const user_owned = self.output_allocator.dupe(oid.ObjectIdentifier, user.items) catch return error.OutOfMemory;
        return .{
            .authority_constrained = authority_owned,
            .user_constrained = user_owned,
            .resource_usage = .{
                .graph_nodes = self.nodes.items.len,
                .graph_edges = self.total_edges,
                .expected_policy_entries = self.total_expected_entries,
                .parent_references = self.total_parent_references,
                .operations = self.operations,
            },
        };
    }

    fn addNode(
        self: *Engine,
        depth: usize,
        valid_policy: oid.ObjectIdentifier,
        expected: []const oid.ObjectIdentifier,
        parents: []const usize,
        certificate_index: ?usize,
        stage: Stage,
    ) RunError!void {
        if (self.nodes.items.len >= self.config.limits.maximum_total_nodes) {
            return self.reject(.resource_limit_exceeded, certificate_index, null, &valid_policy, depth, stage);
        }
        var depth_count: usize = 0;
        for (self.nodes.items) |node| {
            if (node.depth != depth) continue;
            depth_count += 1;
            if (node.valid_policy.eql(&valid_policy)) {
                return self.reject(.certificate_policy_invalid, certificate_index, null, &valid_policy, depth, stage);
            }
        }
        if (depth_count >= self.config.limits.maximum_nodes_per_depth) {
            return self.reject(.resource_limit_exceeded, certificate_index, null, &valid_policy, depth, stage);
        }
        if (expected.len == 0 or (depth > 0 and parents.len == 0)) {
            return self.reject(.certificate_policy_invalid, certificate_index, null, &valid_policy, depth, stage);
        }
        try self.reserveExpected(expected.len, certificate_index, depth, stage);
        try self.reserveParents(parents.len, certificate_index, depth, stage);
        var node = Node{ .depth = depth, .valid_policy = valid_policy };
        try node.expected.appendSlice(self.arena, expected);
        try node.parents.appendSlice(self.arena, parents);
        try self.nodes.append(self.arena, node);
    }

    fn replaceExpected(
        self: *Engine,
        node_index: usize,
        expected: []const oid.ObjectIdentifier,
        certificate_index: usize,
        depth: usize,
    ) RunError!void {
        if (expected.len == 0) return self.reject(.policy_mapping_invalid, certificate_index, &wk.policy_mappings, null, depth, .mapping);
        try self.reserveExpected(expected.len, certificate_index, depth, .mapping);
        self.nodes.items[node_index].expected.clearRetainingCapacity();
        try self.nodes.items[node_index].expected.appendSlice(self.arena, expected);
    }

    fn appendUniqueParent(
        self: *Engine,
        list: *std.ArrayList(usize),
        parent: usize,
        certificate_index: usize,
        depth: usize,
    ) RunError!void {
        for (list.items) |existing| {
            try self.charge(1, certificate_index, depth, .policy);
            if (existing == parent) return;
        }
        if (list.items.len >= self.config.limits.maximum_parent_references or
            list.items.len >= self.config.limits.maximum_total_edges)
        {
            return self.reject(.resource_limit_exceeded, certificate_index, null, null, depth, .policy);
        }
        try list.append(self.arena, parent);
    }

    fn appendUniqueOid(
        self: *Engine,
        list: *std.ArrayList(oid.ObjectIdentifier),
        value: oid.ObjectIdentifier,
        certificate_index: ?usize,
        depth: usize,
        stage: Stage,
    ) RunError!void {
        if (try self.containsOid(list.items, &value, certificate_index, depth, stage)) return;
        try list.append(self.arena, value);
    }

    fn appendOutput(self: *Engine, list: *std.ArrayList(oid.ObjectIdentifier), value: oid.ObjectIdentifier) RunError!void {
        if (try self.containsOid(list.items, &value, null, null, .wrap_up)) return;
        if (list.items.len >= self.config.limits.maximum_output_policies) {
            return self.reject(.resource_limit_exceeded, 0, null, &value, null, .wrap_up);
        }
        try list.append(self.arena, value);
    }

    fn nodeExpects(
        self: *Engine,
        node_index: usize,
        policy: *const oid.ObjectIdentifier,
        certificate_index: usize,
        depth: usize,
    ) RunError!bool {
        return self.containsOid(self.nodes.items[node_index].expected.items, policy, certificate_index, depth, .policy);
    }

    fn containsOid(
        self: *Engine,
        values: []const oid.ObjectIdentifier,
        value: *const oid.ObjectIdentifier,
        certificate_index: ?usize,
        depth: ?usize,
        stage: Stage,
    ) RunError!bool {
        for (values) |candidate| {
            try self.charge(1, certificate_index, depth, stage);
            if (candidate.eql(value)) return true;
        }
        return false;
    }

    fn findAliveNode(
        self: *Engine,
        depth: usize,
        components: []const u32,
        certificate_index: ?usize,
        failure_depth: usize,
        stage: Stage,
    ) RunError!?usize {
        for (self.nodes.items, 0..) |node, index| {
            if (!node.alive or node.depth != depth) continue;
            try self.charge(1, certificate_index, failure_depth, stage);
            if (node.valid_policy.eqlComponents(components)) return index;
        }
        return null;
    }

    fn findAliveNodeOid(
        self: *Engine,
        depth: usize,
        value: *const oid.ObjectIdentifier,
        certificate_index: ?usize,
        failure_depth: usize,
        stage: Stage,
    ) RunError!?usize {
        for (self.nodes.items, 0..) |node, index| {
            if (!node.alive or node.depth != depth) continue;
            try self.charge(1, certificate_index, failure_depth, stage);
            if (node.valid_policy.eql(value)) return index;
        }
        return null;
    }

    fn hasAliveAtDepth(self: *Engine, depth: usize, certificate_index: usize, stage: Stage) RunError!bool {
        for (self.nodes.items) |node| {
            try self.charge(1, certificate_index, depth, stage);
            if (node.alive and node.depth == depth) return true;
        }
        return false;
    }

    fn pruneAncestors(self: *Engine, current_depth: usize, certificate_index: usize, stage: Stage) RunError!void {
        var child_depth = current_depth;
        while (child_depth > 0) : (child_depth -= 1) {
            const parent_depth = child_depth - 1;
            for (self.nodes.items, 0..) |node, parent_index| {
                if (!node.alive or node.depth != parent_depth) continue;
                var has_child = false;
                for (self.nodes.items) |candidate| {
                    if (!candidate.alive or candidate.depth != child_depth) continue;
                    for (candidate.parents.items) |candidate_parent| {
                        try self.charge(1, certificate_index, current_depth, stage);
                        if (candidate_parent == parent_index) {
                            has_child = true;
                            break;
                        }
                    }
                    if (has_child) break;
                }
                if (!has_child) self.nodes.items[parent_index].alive = false;
            }
        }
    }

    fn reserveExpected(self: *Engine, count: usize, certificate_index: ?usize, depth: usize, stage: Stage) RunError!void {
        if (count > self.config.limits.maximum_expected_policy_entries -| self.total_expected_entries) {
            return self.reject(.resource_limit_exceeded, certificate_index, null, null, depth, stage);
        }
        self.total_expected_entries += count;
    }

    fn reserveParents(self: *Engine, count: usize, certificate_index: ?usize, depth: usize, stage: Stage) RunError!void {
        if (count > self.config.limits.maximum_parent_references -| self.total_parent_references or
            count > self.config.limits.maximum_total_edges -| self.total_edges)
        {
            return self.reject(.resource_limit_exceeded, certificate_index, null, null, depth, stage);
        }
        self.total_parent_references += count;
        self.total_edges += count;
    }

    fn charge(self: *Engine, count: usize, certificate_index: ?usize, depth: ?usize, stage: Stage) RunError!void {
        if (count > self.config.limits.maximum_operations -| self.operations) {
            return self.reject(.resource_limit_exceeded, certificate_index, null, null, depth, stage);
        }
        self.operations += count;
    }

    fn reject(
        self: *Engine,
        reason: FailureReason,
        certificate_index: ?usize,
        extension_components: ?[]const u32,
        policy_oid: ?*const oid.ObjectIdentifier,
        depth: ?usize,
        stage: Stage,
    ) RunError {
        self.failure = .{
            .reason = reason,
            .certificate_index = certificate_index,
            .extension_oid = if (extension_components) |components|
                oid.ObjectIdentifier.fromComponents(components) catch null
            else
                null,
            .policy_oid = if (policy_oid) |value| value.* else null,
            .graph_depth = depth,
            .stage = stage,
        };
        return error.Rejected;
    }
};

pub fn validatePath(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    config: Configuration,
) Outcome {
    if (path.elements.len < 2) return .{ .failure = .{
        .reason = .certificate_policy_invalid,
        .certificate_index = null,
        .stage = .configuration,
    } };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var engine = Engine{
        .arena = arena.allocator(),
        .output_allocator = allocator,
        .path = path,
        .config = config,
    };
    const result = engine.run() catch |err| return .{ .failure = switch (err) {
        error.Rejected => engine.failure.?,
        error.OutOfMemory => .{
            .reason = .out_of_memory,
            .certificate_index = null,
            .stage = .configuration,
        },
    } };
    return .{ .success = result };
}

fn decrement(value: *usize) void {
    if (value.* > 0) value.* -= 1;
}

fn oidLessThan(_: void, a: oid.ObjectIdentifier, b: oid.ObjectIdentifier) bool {
    const a_components = a.components();
    const b_components = b.components();
    const shared = @min(a_components.len, b_components.len);
    for (a_components[0..shared], b_components[0..shared]) |a_component, b_component| {
        if (a_component != b_component) return a_component < b_component;
    }
    return a_components.len < b_components.len;
}

const testing = std.testing;

test "OID output ordering is lexical and stable" {
    const one = try oid.ObjectIdentifier.fromComponents(&.{ 1, 2, 3 });
    const two = try oid.ObjectIdentifier.fromComponents(&.{ 1, 2, 3, 4 });
    const three = try oid.ObjectIdentifier.fromComponents(&.{ 1, 2, 4 });
    try testing.expect(oidLessThan({}, one, two));
    try testing.expect(oidLessThan({}, two, three));
}

test {
    testing.refAllDecls(@This());
}
