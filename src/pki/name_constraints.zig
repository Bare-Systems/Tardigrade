//! Bounded RFC 5280 Name Constraints processing (#345).
//!
//! Paths are supplied leaf-first, anchor-last.  Processing walks from the
//! certificate below the anchor toward the leaf: inherited state is checked
//! before the current CA contributes its own constraints.  Thus an extension
//! never constrains its own certificate.  Configured-anchor extensions remain
//! trust input and are deliberately not inherited.
//!
//! Permitted subtrees from one CA are an OR group.  Groups introduced by
//! different CAs are all required (AND).  Excluded subtrees are one cumulative
//! union and are checked first.  State is independent for directoryName,
//! dNSName, rfc822Name, URI, IPv4, and IPv6 names.

const std = @import("std");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const x509 = @import("x509.zig");

const wk = oid.well_known;

pub const Form = enum {
    directory_name,
    dns_name,
    rfc822_name,
    uri,
    ip_address,
};

pub const ConstraintKind = enum { permitted, excluded };

pub const FailureReason = enum {
    violation,
    unsupported,
    resource_limit_exceeded,
    out_of_memory,
};

pub const Failure = struct {
    reason: FailureReason,
    certificate_index: ?usize,
    constraint_kind: ?ConstraintKind = null,
    name_form: ?Form = null,
    constraint_certificate_index: ?usize = null,
};

/// Every collection and repeated operation performed by this module has an
/// explicit caller-configurable bound.  Parser bounds still apply before
/// these validation bounds.
pub const Limits = struct {
    maximum_path_length: usize = 8,
    maximum_permitted_groups_per_form: usize = 8,
    maximum_permitted_subtrees: usize = 64,
    maximum_excluded_subtrees: usize = 64,
    maximum_names_per_certificate: usize = 128,
    maximum_comparisons: usize = 4096,
    /// Bounds directoryName values parsed from SANs and constraints.  The
    /// subject DN is already parsed by `x509.Certificate.parse`.
    maximum_directory_name_parses: usize = 64,
    /// Bound the two allocation-driving dimensions of every parsed
    /// directoryName. Together with `maximum_directory_name_parses`, these
    /// cap total parsing allocation and normalization work.
    maximum_directory_name_rdns: usize = 32,
    maximum_directory_name_attributes_per_rdn: usize = 8,
    /// Bounds both URI storage examined and the linear host parser work.
    maximum_uri_length: usize = 2048,
};

const Constraint = union(Form) {
    directory_name: x509.Name,
    dns_name: []const u8,
    rfc822_name: []const u8,
    uri: []const u8,
    ip_address: []const u8,
};

const Entry = struct {
    constraint: Constraint,
    introduced_by: usize,
};

const Group = struct {
    form: Form,
    start: usize,
    len: usize,
    introduced_by: usize,
};

const Presented = union(Form) {
    directory_name: *const x509.Name,
    dns_name: PresentedDns,
    rfc822_name: []const u8,
    /// Parsed DNS host, not the complete URI.
    uri: []const u8,
    ip_address: []const u8,
};

const PresentedDns = union(enum) {
    exact: []const u8,
    /// Base below a complete left-most wildcard label. For
    /// `*.example.com`, this stores `example.com`.
    wildcard: []const u8,
};

const State = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    arena: std.heap.ArenaAllocator,
    permitted_groups: std.ArrayList(Group) = .empty,
    permitted: std.ArrayList(Entry) = .empty,
    excluded: std.ArrayList(Entry) = .empty,
    comparisons: usize = 0,
    directory_name_parses: usize = 0,

    fn init(allocator: std.mem.Allocator, limits: Limits) State {
        return .{
            .allocator = allocator,
            .limits = limits,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    fn deinit(self: *State) void {
        self.permitted_groups.deinit(self.allocator);
        self.permitted.deinit(self.allocator);
        self.excluded.deinit(self.allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    fn resourceFailure(certificate_index: ?usize) Failure {
        return .{ .reason = .resource_limit_exceeded, .certificate_index = certificate_index };
    }

    fn unsupportedFailure(certificate_index: usize) Failure {
        return .{
            .reason = .unsupported,
            .certificate_index = certificate_index,
            .constraint_certificate_index = certificate_index,
        };
    }

    fn consumeDirectoryParse(self: *State, certificate_index: usize) ?Failure {
        if (self.directory_name_parses >= self.limits.maximum_directory_name_parses) {
            return resourceFailure(certificate_index);
        }
        self.directory_name_parses += 1;
        return null;
    }

    fn consumeName(count: *usize, maximum: usize, certificate_index: usize) ?Failure {
        if (count.* >= maximum) return resourceFailure(certificate_index);
        count.* += 1;
        return null;
    }

    fn consumeComparison(self: *State, certificate_index: usize) ?Failure {
        if (self.comparisons >= self.limits.maximum_comparisons) {
            return resourceFailure(certificate_index);
        }
        self.comparisons += 1;
        return null;
    }

    fn incorporate(self: *State, certificate: *const x509.Certificate, certificate_index: usize) ?Failure {
        const extension = certificate.findExtension(&wk.name_constraints) orelse return null;
        // RFC 5280 requires Name Constraints to be critical and present only
        // on CAs.  The path validator calls this only for intermediates, but
        // retain the CA check for caller-constructed typed views.
        if (!extension.critical) return unsupportedFailure(certificate_index);
        const basic = certificate.basicConstraints() orelse return unsupportedFailure(certificate_index);
        if (!basic.is_ca) return unsupportedFailure(certificate_index);
        if (extension.parsed != .name_constraints) return unsupportedFailure(certificate_index);

        const constraints = extension.parsed.name_constraints;
        if (constraints.permitted.len == 0 and constraints.excluded.len == 0) {
            return unsupportedFailure(certificate_index);
        }
        if (constraints.permitted.len > self.limits.maximum_permitted_subtrees -| self.permitted.items.len) {
            return resourceFailure(certificate_index);
        }
        if (constraints.excluded.len > self.limits.maximum_excluded_subtrees -| self.excluded.items.len) {
            return resourceFailure(certificate_index);
        }

        for (constraints.permitted) |subtree| {
            if (formOf(subtree.base) == null) return unsupportedFailure(certificate_index);
        }
        for (constraints.excluded) |subtree| {
            if (formOf(subtree.base) == null) return unsupportedFailure(certificate_index);
        }

        inline for (std.meta.tags(Form)) |form| {
            var count: usize = 0;
            for (constraints.permitted) |subtree| {
                if (formOf(subtree.base).? == form) count += 1;
            }
            if (count != 0) {
                var existing_groups: usize = 0;
                for (self.permitted_groups.items) |group| {
                    if (group.form == form) existing_groups += 1;
                }
                if (existing_groups >= self.limits.maximum_permitted_groups_per_form) {
                    return resourceFailure(certificate_index);
                }
                const start = self.permitted.items.len;
                for (constraints.permitted) |subtree| {
                    if (formOf(subtree.base).? != form) continue;
                    const parsed = self.parseConstraint(subtree.base, certificate_index) catch |err| {
                        return failureFromParseError(err, certificate_index);
                    };
                    self.permitted.append(self.allocator, .{
                        .constraint = parsed,
                        .introduced_by = certificate_index,
                    }) catch return outOfMemory(certificate_index);
                }
                self.permitted_groups.append(self.allocator, .{
                    .form = form,
                    .start = start,
                    .len = count,
                    .introduced_by = certificate_index,
                }) catch return outOfMemory(certificate_index);
            }
        }

        for (constraints.excluded) |subtree| {
            const parsed = self.parseConstraint(subtree.base, certificate_index) catch |err| {
                return failureFromParseError(err, certificate_index);
            };
            self.excluded.append(self.allocator, .{
                .constraint = parsed,
                .introduced_by = certificate_index,
            }) catch return outOfMemory(certificate_index);
        }
        return null;
    }

    const ParseError = error{ Malformed, ResourceLimit, OutOfMemory };

    fn parseConstraint(self: *State, base: x509.GeneralName, certificate_index: usize) ParseError!Constraint {
        return switch (base) {
            .directory_name => |raw| blk: {
                if (self.consumeDirectoryParse(certificate_index)) |_| return error.ResourceLimit;
                const parsed = x509.parseNameRaw(self.arena.allocator(), raw, self.directoryNameLimits()) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.CountLimitExceeded => return error.ResourceLimit,
                    else => return error.Malformed,
                };
                break :blk .{ .directory_name = parsed };
            },
            .dns_name => |name| blk: {
                validateDnsConstraint(name) catch return error.Malformed;
                break :blk .{ .dns_name = name };
            },
            .rfc822_name => |name| blk: {
                validateEmailConstraint(name) catch return error.Malformed;
                break :blk .{ .rfc822_name = name };
            },
            .uniform_resource_identifier => |name| blk: {
                validateUriConstraint(name) catch return error.Malformed;
                break :blk .{ .uri = name };
            },
            .ip_address => |network| blk: {
                validateIpConstraint(network) catch return error.Malformed;
                break :blk .{ .ip_address = network };
            },
            else => error.Malformed,
        };
    }

    fn directoryNameLimits(self: *const State) x509.Limits {
        return .{
            .max_name_rdns = self.limits.maximum_directory_name_rdns,
            .max_name_attributes = self.limits.maximum_directory_name_attributes_per_rdn,
        };
    }

    fn checkCertificate(self: *State, certificate: *const x509.Certificate, certificate_index: usize) ?Failure {
        var names_examined: usize = 0;

        if (!certificate.subject.isEmpty() and self.hasState(.directory_name)) {
            if (consumeName(&names_examined, self.limits.maximum_names_per_certificate, certificate_index)) |failed| return failed;
            if (self.checkPresented(.{ .directory_name = &certificate.subject }, certificate_index)) |failed| return failed;
        }

        const subject_alt_names = certificate.subjectAltName();
        if (subject_alt_names == null and self.hasState(.rfc822_name)) {
            for (certificate.subject.rdns) |rdn| {
                for (rdn.attributes) |*attribute| {
                    if (!attribute.type.eqlComponents(&wk.email_address)) continue;
                    if (consumeName(&names_examined, self.limits.maximum_names_per_certificate, certificate_index)) |failed| return failed;
                    if (attribute.value_tag.class != .universal or attribute.value_tag.constructed or attribute.value_tag.number != 22) {
                        return violation(certificate_index, .rfc822_name, null, null);
                    }
                    validateMailbox(attribute.value) catch return violation(certificate_index, .rfc822_name, null, null);
                    if (self.checkPresented(.{ .rfc822_name = attribute.value }, certificate_index)) |failed| return failed;
                }
            }
        }

        if (subject_alt_names) |names| {
            for (names) |name| {
                const form = formOf(name) orelse continue;
                if (!self.hasState(form)) continue;
                if (consumeName(&names_examined, self.limits.maximum_names_per_certificate, certificate_index)) |failed| return failed;
                const presented = self.preparePresented(name, certificate_index) catch |err| switch (err) {
                    error.ResourceLimit => return resourceFailure(certificate_index),
                    error.OutOfMemory => return outOfMemory(certificate_index),
                    error.Malformed => return violation(certificate_index, form, null, null),
                };
                if (self.checkPresented(presented, certificate_index)) |failed| return failed;
            }
        }
        return null;
    }

    fn preparePresented(self: *State, name: x509.GeneralName, certificate_index: usize) ParseError!Presented {
        return switch (name) {
            .directory_name => |raw| blk: {
                if (self.consumeDirectoryParse(certificate_index)) |_| return error.ResourceLimit;
                const parsed = x509.parseNameRaw(self.arena.allocator(), raw, self.directoryNameLimits()) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.CountLimitExceeded => return error.ResourceLimit,
                    else => return error.Malformed,
                };
                const stored = self.arena.allocator().create(x509.Name) catch return error.OutOfMemory;
                stored.* = parsed;
                break :blk .{ .directory_name = stored };
            },
            .dns_name => |value| blk: {
                break :blk .{ .dns_name = parsePresentedDns(value) catch return error.Malformed };
            },
            .rfc822_name => |value| blk: {
                validateMailbox(value) catch return error.Malformed;
                break :blk .{ .rfc822_name = value };
            },
            .uniform_resource_identifier => |value| .{
                .uri = uriHost(value, self.limits.maximum_uri_length) catch |err| switch (err) {
                    error.ResourceLimit => return error.ResourceLimit,
                    error.Malformed => return error.Malformed,
                },
            },
            .ip_address => |value| blk: {
                if (value.len != 4 and value.len != 16) return error.Malformed;
                break :blk .{ .ip_address = value };
            },
            else => error.Malformed,
        };
    }

    fn hasState(self: *const State, form: Form) bool {
        for (self.permitted_groups.items) |group| if (group.form == form) return true;
        for (self.excluded.items) |entry| if (std.meta.activeTag(entry.constraint) == form) return true;
        return false;
    }

    fn checkPresented(self: *State, presented: Presented, certificate_index: usize) ?Failure {
        const form = std.meta.activeTag(presented);
        for (self.excluded.items) |entry| {
            if (std.meta.activeTag(entry.constraint) != form) continue;
            if (self.consumeComparison(certificate_index)) |failed| return failed;
            if (matches(presented, entry.constraint, .excluded)) {
                return violation(certificate_index, form, .excluded, entry.introduced_by);
            }
        }

        for (self.permitted_groups.items) |group| {
            if (group.form != form) continue;
            var matched = false;
            for (self.permitted.items[group.start .. group.start + group.len]) |entry| {
                if (self.consumeComparison(certificate_index)) |failed| return failed;
                if (matches(presented, entry.constraint, .permitted)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return violation(certificate_index, form, .permitted, group.introduced_by);
        }
        return null;
    }
};

/// Validate Name Constraints for a structurally valid leaf-first path.
pub fn validatePath(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    limits: Limits,
) ?Failure {
    if (path.elements.len > limits.maximum_path_length) return State.resourceFailure(null);
    if (path.elements.len < 2) return .{ .reason = .unsupported, .certificate_index = null };

    var state = State.init(allocator, limits);
    defer state.deinit();

    const anchor_index = path.elements.len - 1;
    var certificate_index = anchor_index;
    while (certificate_index > 0) {
        certificate_index -= 1;
        const certificate = path.elements[certificate_index].certificate;
        const is_final_target = certificate_index == 0;

        // A self-issued intermediate bypasses inherited checking, but it is
        // still processed below so its constraints affect later certificates.
        if (is_final_target or !certificate.isSelfIssued()) {
            if (state.checkCertificate(certificate, certificate_index)) |failed| return failed;
        }

        if (certificate.findExtension(&wk.name_constraints) != null) {
            if (is_final_target) return State.unsupportedFailure(certificate_index);
            if (state.incorporate(certificate, certificate_index)) |failed| return failed;
        }
    }
    return null;
}

fn formOf(name: x509.GeneralName) ?Form {
    return switch (name) {
        .directory_name => .directory_name,
        .dns_name => .dns_name,
        .rfc822_name => .rfc822_name,
        .uniform_resource_identifier => .uri,
        .ip_address => .ip_address,
        else => null,
    };
}

fn failureFromParseError(err: State.ParseError, certificate_index: usize) Failure {
    return switch (err) {
        error.Malformed => State.unsupportedFailure(certificate_index),
        error.ResourceLimit => State.resourceFailure(certificate_index),
        error.OutOfMemory => outOfMemory(certificate_index),
    };
}

fn outOfMemory(certificate_index: ?usize) Failure {
    return .{ .reason = .out_of_memory, .certificate_index = certificate_index };
}

fn violation(
    certificate_index: usize,
    form: Form,
    kind: ?ConstraintKind,
    introduced_by: ?usize,
) Failure {
    return .{
        .reason = .violation,
        .certificate_index = certificate_index,
        .constraint_kind = kind,
        .name_form = form,
        .constraint_certificate_index = introduced_by,
    };
}

fn matches(name: Presented, constraint: Constraint, kind: ConstraintKind) bool {
    return switch (name) {
        .directory_name => |subject| subject.isWithinSubtree(&constraint.directory_name),
        .dns_name => |dns| dnsConstraintMatches(dns, constraint.dns_name, kind),
        .rfc822_name => |mailbox| emailWithin(mailbox, constraint.rfc822_name),
        .uri => |host| uriHostWithin(host, constraint.uri),
        .ip_address => |address| ipWithin(address, constraint.ip_address),
    };
}

const NameError = error{Malformed};

fn validateDnsName(name: []const u8) NameError!void {
    if (name.len == 0 or name.len > 253 or name[0] == '.' or name[name.len - 1] == '.') return error.Malformed;
    var label_start: usize = 0;
    for (name, 0..) |byte, index| {
        if (byte == '.') {
            try validateDnsLabel(name[label_start..index]);
            label_start = index + 1;
        } else if (!std.ascii.isAlphanumeric(byte) and byte != '-') {
            return error.Malformed;
        }
    }
    try validateDnsLabel(name[label_start..]);
}

fn validateDnsLabel(label: []const u8) NameError!void {
    if (label.len == 0 or label.len > 63) return error.Malformed;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.Malformed;
}

fn validateDnsConstraint(constraint: []const u8) NameError!void {
    const domain = if (constraint.len != 0 and constraint[0] == '.') constraint[1..] else constraint;
    try validateDnsName(domain);
}

fn parsePresentedDns(raw: []const u8) NameError!PresentedDns {
    const name = if (raw.len > 0 and raw[raw.len - 1] == '.') raw[0 .. raw.len - 1] else raw;
    if (std.mem.startsWith(u8, name, "*.")) {
        const base = name[2..];
        try validateDnsName(base);
        var labels = std.mem.splitScalar(u8, base, '.');
        var label_count: usize = 0;
        while (labels.next()) |_| label_count += 1;
        if (label_count < 2) return error.Malformed;
        return .{ .wildcard = base };
    }
    if (std.mem.indexOfScalar(u8, name, '*') != null) return error.Malformed;
    try validateDnsName(name);
    return .{ .exact = name };
}

fn dnsConstraintMatches(name: PresentedDns, constraint: []const u8, kind: ConstraintKind) bool {
    return switch (name) {
        .exact => |exact| dnsWithin(exact, constraint),
        .wildcard => |base| wildcardDnsMatches(base, constraint, kind),
    };
}

fn wildcardDnsMatches(base: []const u8, constraint: []const u8, kind: ConstraintKind) bool {
    const leading_dot = constraint[0] == '.';
    const domain = if (leading_dot) constraint[1..] else constraint;
    return switch (kind) {
        // Every name represented by `*.base` must be inside a permitted
        // subtree. That holds exactly when the wildcard base is the subtree
        // base or one of its descendants; leading-dot constraints still
        // include the wildcard's one-label descendants when the bases match.
        .permitted => dnsWithin(base, domain),
        // An exclusion rejects when its set intersects any name represented
        // by the wildcard. A strict leading-dot exclusion rooted at a direct
        // child does not intersect: the wildcard contains that child itself,
        // but not names below it.
        .excluded => dnsWithin(base, domain) or
            (isDirectDnsChild(domain, base) and !leading_dot),
    };
}

fn isDirectDnsChild(child: []const u8, parent: []const u8) bool {
    if (child.len <= parent.len or child[child.len - parent.len - 1] != '.') return false;
    if (!std.ascii.eqlIgnoreCase(child[child.len - parent.len ..], parent)) return false;
    return std.mem.indexOfScalar(u8, child[0 .. child.len - parent.len - 1], '.') == null;
}

fn dnsWithin(name: []const u8, constraint: []const u8) bool {
    // RFC 5280's ordinary dNSName subtree includes the base and descendants.
    // For OpenSSL compatibility, a leading dot means descendants only; this
    // behavior is locked by the independent differential fixtures.
    const leading_dot = constraint[0] == '.';
    const domain = if (leading_dot) constraint[1..] else constraint;
    if (!leading_dot and std.ascii.eqlIgnoreCase(name, domain)) return true;
    return name.len > domain.len and
        name[name.len - domain.len - 1] == '.' and
        std.ascii.eqlIgnoreCase(name[name.len - domain.len ..], domain);
}

const LocalPart = union(enum) {
    dot_string: []const u8,
    /// Content between the quotes, with quoted-pair escapes retained. They
    /// are decoded only by `LocalPartIterator`, so parsing allocates nothing.
    quoted_string: []const u8,
};

const Mailbox = struct {
    local: LocalPart,
    host: []const u8,
};

fn splitMailbox(value: []const u8) NameError!Mailbox {
    if (value.len < 3) return error.Malformed;

    var local: LocalPart = undefined;
    var at: usize = undefined;
    if (value[0] == '"') {
        var index: usize = 1;
        while (index < value.len) {
            const byte = value[index];
            if (byte == '\\') {
                if (index + 1 >= value.len or !isQuotedPairByte(value[index + 1])) return error.Malformed;
                index += 2;
                continue;
            }
            if (byte == '"') {
                at = index + 1;
                if (at >= value.len or value[at] != '@') return error.Malformed;
                local = .{ .quoted_string = value[1..index] };
                break;
            }
            if (!isQtextSmtp(byte)) return error.Malformed;
            index += 1;
        } else return error.Malformed;
    } else {
        at = std.mem.indexOfScalar(u8, value, '@') orelse return error.Malformed;
        const raw_local = value[0..at];
        try validateDotString(raw_local);
        local = .{ .dot_string = raw_local };
    }

    if (at + 1 >= value.len) return error.Malformed;
    const host = value[at + 1 ..];
    // A second raw '@' is invalid in both the host and an unquoted local part.
    if (std.mem.indexOfScalar(u8, host, '@') != null) return error.Malformed;
    try validateDnsName(host);
    return .{ .local = local, .host = host };
}

fn validateDotString(local: []const u8) NameError!void {
    if (local.len == 0) return error.Malformed;
    var atoms = std.mem.splitScalar(u8, local, '.');
    while (atoms.next()) |atom| {
        if (atom.len == 0) return error.Malformed;
        for (atom) |byte| if (!isAtext(byte)) return error.Malformed;
    }
}

fn isAtext(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

fn isQtextSmtp(byte: u8) bool {
    return (byte >= 32 and byte <= 33) or (byte >= 35 and byte <= 91) or (byte >= 93 and byte <= 126);
}

fn isQuotedPairByte(byte: u8) bool {
    return byte >= 32 and byte <= 126;
}

const LocalPartIterator = struct {
    raw: []const u8,
    quoted: bool,
    index: usize = 0,

    fn init(local: LocalPart) LocalPartIterator {
        return switch (local) {
            .dot_string => |raw| .{ .raw = raw, .quoted = false },
            .quoted_string => |raw| .{ .raw = raw, .quoted = true },
        };
    }

    fn next(self: *LocalPartIterator) ?u8 {
        if (self.index >= self.raw.len) return null;
        var byte = self.raw[self.index];
        self.index += 1;
        if (self.quoted and byte == '\\') {
            byte = self.raw[self.index];
            self.index += 1;
        }
        return byte;
    }
};

fn localPartsEqual(a: LocalPart, b: LocalPart) bool {
    var a_iterator = LocalPartIterator.init(a);
    var b_iterator = LocalPartIterator.init(b);
    while (true) {
        const a_byte = a_iterator.next();
        const b_byte = b_iterator.next();
        if (a_byte != b_byte) return false;
        if (a_byte == null) return true;
    }
}

fn validateMailbox(value: []const u8) NameError!void {
    _ = try splitMailbox(value);
}

fn validateEmailConstraint(value: []const u8) NameError!void {
    if (std.mem.indexOfScalar(u8, value, '@') != null) {
        try validateMailbox(value);
    } else {
        try validateDnsConstraint(value);
    }
}

fn emailWithin(mailbox: []const u8, constraint: []const u8) bool {
    const parsed = splitMailbox(mailbox) catch return false;
    if (std.mem.indexOfScalar(u8, constraint, '@') != null) {
        const expected = splitMailbox(constraint) catch return false;
        return localPartsEqual(parsed.local, expected.local) and std.ascii.eqlIgnoreCase(parsed.host, expected.host);
    }
    if (constraint[0] == '.') {
        const domain = constraint[1..];
        return parsed.host.len > domain.len and
            parsed.host[parsed.host.len - domain.len - 1] == '.' and
            std.ascii.eqlIgnoreCase(parsed.host[parsed.host.len - domain.len ..], domain);
    }
    return std.ascii.eqlIgnoreCase(parsed.host, constraint);
}

fn validateUriConstraint(value: []const u8) NameError!void {
    try validateDnsConstraint(value);
}

const UriError = error{ Malformed, ResourceLimit };

fn uriHost(uri: []const u8, maximum_length: usize) UriError![]const u8 {
    if (uri.len > maximum_length) return error.ResourceLimit;
    const colon = std.mem.indexOfScalar(u8, uri, ':') orelse return error.Malformed;
    if (colon == 0) return error.Malformed;
    if (!std.ascii.isAlphabetic(uri[0])) return error.Malformed;
    for (uri[1..colon]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '-' and byte != '.') return error.Malformed;
    }
    if (colon + 2 >= uri.len or uri[colon + 1] != '/' or uri[colon + 2] != '/') return error.Malformed;

    const authority_start = colon + 3;
    var authority_end = uri.len;
    for (uri[authority_start..], authority_start..) |byte, index| {
        if (byte == '/' or byte == '?' or byte == '#') {
            authority_end = index;
            break;
        }
    }
    var authority = uri[authority_start..authority_end];
    if (authority.len == 0) return error.Malformed;
    if (std.mem.indexOfScalar(u8, authority, '@')) |at| {
        if (std.mem.indexOfScalar(u8, authority[at + 1 ..], '@') != null) return error.Malformed;
        validateUserinfo(authority[0..at]) catch return error.Malformed;
        authority = authority[at + 1 ..];
    }
    if (authority.len == 0 or authority[0] == '[') return error.Malformed;

    var host = authority;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |port_separator| {
        const port = authority[port_separator + 1 ..];
        if (port.len == 0) return error.Malformed;
        for (port) |byte| if (!std.ascii.isDigit(byte)) return error.Malformed;
        host = authority[0..port_separator];
    }
    if (isIpv4Literal(host)) return error.Malformed;
    validateDnsName(host) catch return error.Malformed;
    return host;
}

fn validateUserinfo(userinfo: []const u8) NameError!void {
    var index: usize = 0;
    while (index < userinfo.len) {
        const byte = userinfo[index];
        if (byte == '%') {
            if (index + 2 >= userinfo.len or
                !std.ascii.isHex(userinfo[index + 1]) or
                !std.ascii.isHex(userinfo[index + 2])) return error.Malformed;
            index += 3;
            continue;
        }
        const allowed = std.ascii.isAlphanumeric(byte) or switch (byte) {
            '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':' => true,
            else => false,
        };
        if (!allowed) return error.Malformed;
        index += 1;
    }
}

fn isIpv4Literal(host: []const u8) bool {
    var dots: usize = 0;
    if (host.len == 0) return false;
    for (host) |byte| {
        if (byte == '.') {
            dots += 1;
        } else if (!std.ascii.isDigit(byte)) {
            return false;
        }
    }
    return dots == 3;
}

fn uriHostWithin(host: []const u8, constraint: []const u8) bool {
    // URI constraints without a leading dot are exact hosts. A leading dot
    // permits one or more labels below the named domain (RFC 5280 §4.2.1.10).
    if (constraint[0] != '.') return std.ascii.eqlIgnoreCase(host, constraint);
    const domain = constraint[1..];
    return host.len > domain.len and
        host[host.len - domain.len - 1] == '.' and
        std.ascii.eqlIgnoreCase(host[host.len - domain.len ..], domain);
}

fn validateIpConstraint(network: []const u8) NameError!void {
    if (network.len != 8 and network.len != 32) return error.Malformed;
    const half = network.len / 2;
    const address = network[0..half];
    const mask = network[half..];
    // This implementation's explicit CIDR policy requires a contiguous mask
    // and canonical base address (all host bits zero).
    var saw_zero = false;
    for (mask) |byte| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            const set = byte & bit != 0;
            if (saw_zero and set) return error.Malformed;
            if (!set) saw_zero = true;
        }
    }
    for (address, mask) |address_byte, mask_byte| {
        if (address_byte & ~mask_byte != 0) return error.Malformed;
    }
}

fn ipWithin(address: []const u8, network: []const u8) bool {
    if (network.len != address.len * 2) return false;
    const base = network[0..address.len];
    const mask = network[address.len..];
    for (address, base, mask) |actual, expected, mask_byte| {
        if (actual & mask_byte != expected & mask_byte) return false;
    }
    return true;
}

test "DNS constraints use label boundaries and leading-dot subdomains only" {
    try std.testing.expect(dnsWithin("example.com", "example.com"));
    try std.testing.expect(dnsWithin("www.example.com", "example.com"));
    try std.testing.expect(!dnsWithin("badexample.com", "example.com"));
    try std.testing.expect(dnsWithin("www.example.com", ".example.com"));
    try std.testing.expect(!dnsWithin("example.com", ".example.com"));
    try std.testing.expect(dnsWithin("WWW.Example.COM", "example.com"));
}

test "wildcard DNS constraints use permitted-subset and excluded-intersection semantics" {
    const wildcard = try parsePresentedDns("*.example.com");
    try std.testing.expect(dnsConstraintMatches(wildcard, "example.com", .permitted));
    try std.testing.expect(dnsConstraintMatches(wildcard, ".example.com", .permitted));
    try std.testing.expect(!dnsConstraintMatches(wildcard, "foo.example.com", .permitted));
    try std.testing.expect(dnsConstraintMatches(wildcard, "foo.example.com", .excluded));
    try std.testing.expect(!dnsConstraintMatches(wildcard, ".foo.example.com", .excluded));
    try std.testing.expect(dnsConstraintMatches(wildcard, ".example.com", .excluded));

    try std.testing.expectError(error.Malformed, parsePresentedDns("*"));
    try std.testing.expectError(error.Malformed, parsePresentedDns("a.*.example.com"));
    try std.testing.expectError(error.Malformed, parsePresentedDns("f*o.example.com"));
    try std.testing.expectError(error.Malformed, parsePresentedDns("*.com"));
}

test "email constraints preserve local-part case and distinguish host from domain" {
    try std.testing.expect(emailWithin("root@example.com", "root@example.com"));
    try std.testing.expect(!emailWithin("ROOT@example.com", "root@example.com"));
    try std.testing.expect(emailWithin("any@EXAMPLE.com", "example.com"));
    try std.testing.expect(!emailWithin("any@sub.example.com", "example.com"));
    try std.testing.expect(emailWithin("any@sub.example.com", ".example.com"));
    try std.testing.expect(!emailWithin("any@example.com", ".example.com"));
    try std.testing.expect(emailWithin("\"root\"@example.com", "root@example.com"));
    try std.testing.expect(emailWithin("\"ro\\ot\"@example.com", "root@example.com"));
    try std.testing.expect(emailWithin("\"a@b\"@example.com", "example.com"));
    try std.testing.expectError(error.Malformed, validateMailbox(".a@example.com"));
    try std.testing.expectError(error.Malformed, validateMailbox("a..b@example.com"));
    try std.testing.expectError(error.Malformed, validateMailbox("a.@example.com"));
    try std.testing.expectError(error.Malformed, validateMailbox("a(b)@example.com"));
}

test "URI host parsing is bounded and constraints distinguish exact hosts from domains" {
    try std.testing.expectEqualStrings("api.example.com", try uriHost("https://user@api.example.com:8443/a?b#c", 256));
    try std.testing.expectEqualStrings("api.example.com", try uriHost("https://user:pa%73s@api.example.com/a", 256));
    try std.testing.expect(uriHostWithin("api.example.com", "api.example.com"));
    try std.testing.expect(!uriHostWithin("sub.api.example.com", "api.example.com"));
    try std.testing.expect(uriHostWithin("sub.example.com", ".example.com"));
    try std.testing.expectError(error.Malformed, uriHost("urn:example:test", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://[2001:db8::1]/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://192.0.2.1/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://bad@@api.example.com/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://bad user@api.example.com/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://bad\x1fuser@api.example.com/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://bad%ZZ@api.example.com/", 256));
    try std.testing.expectError(error.ResourceLimit, uriHost("https://example.com/", 4));
}

test "IP constraints support IPv4 and IPv6 prefixes and reject malformed masks" {
    const v4_network = [_]u8{ 192, 0, 2, 0, 255, 255, 255, 0 };
    try validateIpConstraint(&v4_network);
    try std.testing.expect(ipWithin(&.{ 192, 0, 2, 0 }, &v4_network));
    try std.testing.expect(ipWithin(&.{ 192, 0, 2, 255 }, &v4_network));
    try std.testing.expect(!ipWithin(&.{ 192, 0, 3, 0 }, &v4_network));

    const v4_host = [_]u8{ 192, 0, 2, 7, 255, 255, 255, 255 };
    try validateIpConstraint(&v4_host);
    try std.testing.expect(ipWithin(&.{ 192, 0, 2, 7 }, &v4_host));
    try std.testing.expect(!ipWithin(&.{ 192, 0, 2, 6 }, &v4_host));

    const all_v6 = [_]u8{0} ** 32;
    try validateIpConstraint(&all_v6);
    try std.testing.expect(ipWithin(&([_]u8{0xaa} ** 16), &all_v6));

    const bad_mask = [_]u8{ 192, 0, 2, 0, 255, 0, 255, 0 };
    try std.testing.expectError(error.Malformed, validateIpConstraint(&bad_mask));
    const host_bits = [_]u8{ 192, 0, 2, 1, 255, 255, 255, 0 };
    try std.testing.expectError(error.Malformed, validateIpConstraint(&host_bits));
}
