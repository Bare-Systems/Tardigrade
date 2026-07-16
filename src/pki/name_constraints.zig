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
    dns_name: []const u8,
    rfc822_name: []const u8,
    /// Parsed DNS host, not the complete URI.
    uri: []const u8,
    ip_address: []const u8,
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

        if (self.hasState(.rfc822_name)) {
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

        if (certificate.subjectAltName()) |names| {
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
                validateDnsName(value) catch return error.Malformed;
                break :blk .{ .dns_name = value };
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
            if (matches(presented, entry.constraint)) {
                return violation(certificate_index, form, .excluded, entry.introduced_by);
            }
        }

        for (self.permitted_groups.items) |group| {
            if (group.form != form) continue;
            var matched = false;
            for (self.permitted.items[group.start .. group.start + group.len]) |entry| {
                if (self.consumeComparison(certificate_index)) |failed| return failed;
                if (matches(presented, entry.constraint)) {
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

fn matches(name: Presented, constraint: Constraint) bool {
    return switch (name) {
        .directory_name => |subject| subject.isWithinSubtree(&constraint.directory_name),
        .dns_name => |dns| dnsWithin(dns, constraint.dns_name),
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

fn splitMailbox(value: []const u8) NameError!struct { local: []const u8, host: []const u8 } {
    const at = std.mem.lastIndexOfScalar(u8, value, '@') orelse return error.Malformed;
    if (at == 0 or at + 1 == value.len) return error.Malformed;
    const local = value[0..at];
    if (std.mem.indexOfScalar(u8, local, '@') != null) return error.Malformed;
    for (local) |byte| {
        if (byte < 0x21 or byte > 0x7e) return error.Malformed;
    }
    const host = value[at + 1 ..];
    try validateDnsName(host);
    return .{ .local = local, .host = host };
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
        return std.mem.eql(u8, parsed.local, expected.local) and std.ascii.eqlIgnoreCase(parsed.host, expected.host);
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
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
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

test "email constraints preserve local-part case and distinguish host from domain" {
    try std.testing.expect(emailWithin("root@example.com", "root@example.com"));
    try std.testing.expect(!emailWithin("ROOT@example.com", "root@example.com"));
    try std.testing.expect(emailWithin("any@EXAMPLE.com", "example.com"));
    try std.testing.expect(!emailWithin("any@sub.example.com", "example.com"));
    try std.testing.expect(emailWithin("any@sub.example.com", ".example.com"));
    try std.testing.expect(!emailWithin("any@example.com", ".example.com"));
}

test "URI host parsing is bounded and constraints distinguish exact hosts from domains" {
    try std.testing.expectEqualStrings("api.example.com", try uriHost("https://user@api.example.com:8443/a?b#c", 256));
    try std.testing.expect(uriHostWithin("api.example.com", "api.example.com"));
    try std.testing.expect(!uriHostWithin("sub.api.example.com", "api.example.com"));
    try std.testing.expect(uriHostWithin("sub.example.com", ".example.com"));
    try std.testing.expectError(error.Malformed, uriHost("urn:example:test", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://[2001:db8::1]/", 256));
    try std.testing.expectError(error.Malformed, uriHost("https://192.0.2.1/", 256));
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
