//! OBJECT IDENTIFIER decoding for X.509 (#339).

const std = @import("std");

pub const Error = error{
    MalformedOid,
    OidComponentOverflow,
    OidComponentLimit,
};

pub const max_components = 32;

pub const ObjectIdentifier = struct {
    storage: [max_components]u32 = undefined,
    len: usize = 0,

    pub fn components(self: *const ObjectIdentifier) []const u32 {
        return self.storage[0..self.len];
    }

    pub fn fromComponents(values: []const u32) Error!ObjectIdentifier {
        if (values.len > max_components) return error.OidComponentLimit;
        var oid: ObjectIdentifier = .{};
        @memcpy(oid.storage[0..values.len], values);
        oid.len = values.len;
        return oid;
    }

    pub fn eql(self: *const ObjectIdentifier, other: *const ObjectIdentifier) bool {
        return std.mem.eql(u32, self.components(), other.components());
    }

    pub fn eqlComponents(self: *const ObjectIdentifier, values: []const u32) bool {
        return std.mem.eql(u32, self.components(), values);
    }
};

/// Decode DER OID content (value bytes only, not the TLV wrapper).
pub fn decode(content: []const u8, component_limit: usize) Error!ObjectIdentifier {
    if (content.len == 0) return error.MalformedOid;
    if (component_limit < 2) return error.OidComponentLimit;
    if (component_limit > max_components) return error.OidComponentLimit;

    var oid: ObjectIdentifier = .{};

    var i: usize = 0;
    const first = try decodeBase128(content, &i);
    const first_arc: u32 = if (first < 40) 0 else if (first < 80) 1 else 2;
    const second_arc: u32 = if (first < 40) first else if (first < 80) first - 40 else first - 80;
    if (first_arc < 2 and second_arc >= 40) return error.MalformedOid;
    oid.storage[0] = first_arc;
    oid.storage[1] = second_arc;
    oid.len = 2;

    while (i < content.len) {
        if (oid.len >= component_limit) return error.OidComponentLimit;
        const decoded = try decodeBase128(content, &i);
        oid.storage[oid.len] = decoded;
        oid.len += 1;
    }

    return oid;
}

fn decodeBase128(content: []const u8, index: *usize) Error!u32 {
    var value: u32 = 0;
    var continuation_bytes: usize = 0;
    while (index.* < content.len) {
        const b = content[index.*];
        index.* += 1;
        const chunk: u32 = b & 0x7f;
        if (value > (std.math.maxInt(u32) >> 7)) return error.OidComponentOverflow;
        value = (value << 7) | chunk;
        if (b & 0x80 == 0) {
            if (value < 128 and continuation_bytes > 0) return error.MalformedOid;
            return value;
        }
        if (value == 0 and chunk == 0) return error.MalformedOid;
        continuation_bytes += 1;
        if (continuation_bytes > 4) return error.OidComponentOverflow;
    }
    return error.MalformedOid;
}

/// Encode OID components to canonical DER content bytes.
pub fn encodeComponents(components: []const u32, out: []u8) Error!usize {
    if (components.len < 2) return error.MalformedOid;
    if (components[0] > 2) return error.MalformedOid;
    if (components[0] < 2 and components[1] >= 40) return error.MalformedOid;

    const first_combined = components[0] * 40 + components[1];
    var written = try encodeBase128(first_combined, out);

    for (components[2..]) |component| {
        const n = try encodeBase128(component, out[written..]);
        written += n;
    }
    return written;
}

fn encodeBase128(value: u32, out: []u8) Error!usize {
    if (value == 0) {
        if (out.len == 0) return error.MalformedOid;
        out[0] = 0;
        return 1;
    }
    var stack: [5]u8 = undefined;
    var tmp = value;
    var count: usize = 0;
    while (tmp > 0) : (count += 1) {
        stack[count] = @intCast(tmp & 0x7f);
        tmp >>= 7;
    }
    if (out.len < count) return error.MalformedOid;
    var i: usize = 0;
    while (i < count - 1) : (i += 1) {
        out[i] = stack[count - 1 - i] | 0x80;
    }
    out[count - 1] = stack[0];
    return count;
}

/// Well-known directory / PKIX OIDs used in tests and later #341.
pub const well_known = struct {
    pub const rsa_encryption = [_]u32{ 1, 2, 840, 113549, 1, 1, 1 };
    pub const common_name = [_]u32{ 2, 5, 4, 3 };
    pub const organization = [_]u32{ 2, 5, 4, 10 };
    pub const country = [_]u32{ 2, 5, 4, 6 };
    pub const subject_alt_name = [_]u32{ 2, 5, 29, 17 };
    pub const basic_constraints = [_]u32{ 2, 5, 29, 19 };
    pub const key_usage = [_]u32{ 2, 5, 29, 15 };
    pub const ext_key_usage = [_]u32{ 2, 5, 29, 37 };
    pub const server_auth = [_]u32{ 1, 3, 6, 1, 5, 5, 7, 3, 1 };
};

const testing = std.testing;

test "decode and encode known OIDs" {
    var buf: [32]u8 = undefined;
    const rsa_der = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    const n_rsa = try encodeComponents(&well_known.rsa_encryption, &buf);
    try testing.expectEqualSlices(u8, &rsa_der, buf[0..n_rsa]);
    const rsa = try decode(buf[0..n_rsa], 32);
    try testing.expectEqual(@as(usize, 7), rsa.len);
    for (rsa.components(), 0..) |component, i| {
        try testing.expectEqual(well_known.rsa_encryption[i], component);
    }

    const cn_der = [_]u8{ 0x55, 0x04, 0x03 };
    const n_cn = try encodeComponents(&well_known.common_name, &buf);
    try testing.expectEqualSlices(u8, &cn_der, buf[0..n_cn]);
    const cn = try decode(buf[0..n_cn], 32);
    try testing.expectEqual(@as(usize, 4), cn.len);
    for (cn.components(), 0..) |component, i| {
        try testing.expectEqual(well_known.common_name[i], component);
    }
}

test "decode and encode multi-octet first subidentifier" {
    var buf: [16]u8 = undefined;
    const components = [_]u32{ 2, 999, 3 };
    const n = try encodeComponents(&components, &buf);
    try testing.expectEqualSlices(u8, &.{ 0x88, 0x37, 0x03 }, buf[0..n]);
    const decoded = try decode(buf[0..n], 3);
    try testing.expect(decoded.eqlComponents(&components));
}

test "decode rejects limits below mandatory first two OID arcs" {
    try testing.expectError(error.OidComponentLimit, decode(&.{0x55}, 0));
    try testing.expectError(error.OidComponentLimit, decode(&.{0x55}, 1));
}

test {
    testing.refAllDecls(@This());
}
