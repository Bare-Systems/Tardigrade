const std = @import("std");

/// HPACK Huffman decoding (RFC 7541 §5.2 / Appendix B).
///
/// HTTP/2 clients (curl/nghttp2, browsers, h2load) Huffman-encode most HPACK
/// header strings, so a gateway that cannot decode the Huffman representation
/// rejects essentially every real request with a COMPRESSION_ERROR. This module
/// decodes the canonical static Huffman code into raw bytes.
///
/// The code table below is the canonical RFC 7541 Appendix B table, stored as
/// left-aligned 32-bit codewords (the most-significant `nbits` bits hold the
/// code). The right-aligned codeword is `code >> (32 - nbits)`, which preserves
/// leading zeros under the explicit `nbits` width.
const HuffSym = struct { code: u32, nbits: u8 };

/// Symbol index 256 is the EOS marker; it must never appear in a decoded
/// stream and is only used to define the padding bit pattern (all ones).
const EOS_SYMBOL: i16 = 256;

const huff_table = [257]HuffSym{
    .{ .code = 0xffc00000, .nbits = 13 },
    .{ .code = 0xffffb000, .nbits = 23 },
    .{ .code = 0xfffffe20, .nbits = 28 },
    .{ .code = 0xfffffe30, .nbits = 28 },
    .{ .code = 0xfffffe40, .nbits = 28 },
    .{ .code = 0xfffffe50, .nbits = 28 },
    .{ .code = 0xfffffe60, .nbits = 28 },
    .{ .code = 0xfffffe70, .nbits = 28 },
    .{ .code = 0xfffffe80, .nbits = 28 },
    .{ .code = 0xffffea00, .nbits = 24 },
    .{ .code = 0xfffffff0, .nbits = 30 },
    .{ .code = 0xfffffe90, .nbits = 28 },
    .{ .code = 0xfffffea0, .nbits = 28 },
    .{ .code = 0xfffffff4, .nbits = 30 },
    .{ .code = 0xfffffeb0, .nbits = 28 },
    .{ .code = 0xfffffec0, .nbits = 28 },
    .{ .code = 0xfffffed0, .nbits = 28 },
    .{ .code = 0xfffffee0, .nbits = 28 },
    .{ .code = 0xfffffef0, .nbits = 28 },
    .{ .code = 0xffffff00, .nbits = 28 },
    .{ .code = 0xffffff10, .nbits = 28 },
    .{ .code = 0xffffff20, .nbits = 28 },
    .{ .code = 0xfffffff8, .nbits = 30 },
    .{ .code = 0xffffff30, .nbits = 28 },
    .{ .code = 0xffffff40, .nbits = 28 },
    .{ .code = 0xffffff50, .nbits = 28 },
    .{ .code = 0xffffff60, .nbits = 28 },
    .{ .code = 0xffffff70, .nbits = 28 },
    .{ .code = 0xffffff80, .nbits = 28 },
    .{ .code = 0xffffff90, .nbits = 28 },
    .{ .code = 0xffffffa0, .nbits = 28 },
    .{ .code = 0xffffffb0, .nbits = 28 },
    .{ .code = 0x50000000, .nbits = 6 },
    .{ .code = 0xfe000000, .nbits = 10 },
    .{ .code = 0xfe400000, .nbits = 10 },
    .{ .code = 0xffa00000, .nbits = 12 },
    .{ .code = 0xffc80000, .nbits = 13 },
    .{ .code = 0x54000000, .nbits = 6 },
    .{ .code = 0xf8000000, .nbits = 8 },
    .{ .code = 0xff400000, .nbits = 11 },
    .{ .code = 0xfe800000, .nbits = 10 },
    .{ .code = 0xfec00000, .nbits = 10 },
    .{ .code = 0xf9000000, .nbits = 8 },
    .{ .code = 0xff600000, .nbits = 11 },
    .{ .code = 0xfa000000, .nbits = 8 },
    .{ .code = 0x58000000, .nbits = 6 },
    .{ .code = 0x5c000000, .nbits = 6 },
    .{ .code = 0x60000000, .nbits = 6 },
    .{ .code = 0x00000000, .nbits = 5 },
    .{ .code = 0x08000000, .nbits = 5 },
    .{ .code = 0x10000000, .nbits = 5 },
    .{ .code = 0x64000000, .nbits = 6 },
    .{ .code = 0x68000000, .nbits = 6 },
    .{ .code = 0x6c000000, .nbits = 6 },
    .{ .code = 0x70000000, .nbits = 6 },
    .{ .code = 0x74000000, .nbits = 6 },
    .{ .code = 0x78000000, .nbits = 6 },
    .{ .code = 0x7c000000, .nbits = 6 },
    .{ .code = 0xb8000000, .nbits = 7 },
    .{ .code = 0xfb000000, .nbits = 8 },
    .{ .code = 0xfff80000, .nbits = 15 },
    .{ .code = 0x80000000, .nbits = 6 },
    .{ .code = 0xffb00000, .nbits = 12 },
    .{ .code = 0xff000000, .nbits = 10 },
    .{ .code = 0xffd00000, .nbits = 13 },
    .{ .code = 0x84000000, .nbits = 6 },
    .{ .code = 0xba000000, .nbits = 7 },
    .{ .code = 0xbc000000, .nbits = 7 },
    .{ .code = 0xbe000000, .nbits = 7 },
    .{ .code = 0xc0000000, .nbits = 7 },
    .{ .code = 0xc2000000, .nbits = 7 },
    .{ .code = 0xc4000000, .nbits = 7 },
    .{ .code = 0xc6000000, .nbits = 7 },
    .{ .code = 0xc8000000, .nbits = 7 },
    .{ .code = 0xca000000, .nbits = 7 },
    .{ .code = 0xcc000000, .nbits = 7 },
    .{ .code = 0xce000000, .nbits = 7 },
    .{ .code = 0xd0000000, .nbits = 7 },
    .{ .code = 0xd2000000, .nbits = 7 },
    .{ .code = 0xd4000000, .nbits = 7 },
    .{ .code = 0xd6000000, .nbits = 7 },
    .{ .code = 0xd8000000, .nbits = 7 },
    .{ .code = 0xda000000, .nbits = 7 },
    .{ .code = 0xdc000000, .nbits = 7 },
    .{ .code = 0xde000000, .nbits = 7 },
    .{ .code = 0xe0000000, .nbits = 7 },
    .{ .code = 0xe2000000, .nbits = 7 },
    .{ .code = 0xe4000000, .nbits = 7 },
    .{ .code = 0xfc000000, .nbits = 8 },
    .{ .code = 0xe6000000, .nbits = 7 },
    .{ .code = 0xfd000000, .nbits = 8 },
    .{ .code = 0xffd80000, .nbits = 13 },
    .{ .code = 0xfffe0000, .nbits = 19 },
    .{ .code = 0xffe00000, .nbits = 13 },
    .{ .code = 0xfff00000, .nbits = 14 },
    .{ .code = 0x88000000, .nbits = 6 },
    .{ .code = 0xfffa0000, .nbits = 15 },
    .{ .code = 0x18000000, .nbits = 5 },
    .{ .code = 0x8c000000, .nbits = 6 },
    .{ .code = 0x20000000, .nbits = 5 },
    .{ .code = 0x90000000, .nbits = 6 },
    .{ .code = 0x28000000, .nbits = 5 },
    .{ .code = 0x94000000, .nbits = 6 },
    .{ .code = 0x98000000, .nbits = 6 },
    .{ .code = 0x9c000000, .nbits = 6 },
    .{ .code = 0x30000000, .nbits = 5 },
    .{ .code = 0xe8000000, .nbits = 7 },
    .{ .code = 0xea000000, .nbits = 7 },
    .{ .code = 0xa0000000, .nbits = 6 },
    .{ .code = 0xa4000000, .nbits = 6 },
    .{ .code = 0xa8000000, .nbits = 6 },
    .{ .code = 0x38000000, .nbits = 5 },
    .{ .code = 0xac000000, .nbits = 6 },
    .{ .code = 0xec000000, .nbits = 7 },
    .{ .code = 0xb0000000, .nbits = 6 },
    .{ .code = 0x40000000, .nbits = 5 },
    .{ .code = 0x48000000, .nbits = 5 },
    .{ .code = 0xb4000000, .nbits = 6 },
    .{ .code = 0xee000000, .nbits = 7 },
    .{ .code = 0xf0000000, .nbits = 7 },
    .{ .code = 0xf2000000, .nbits = 7 },
    .{ .code = 0xf4000000, .nbits = 7 },
    .{ .code = 0xf6000000, .nbits = 7 },
    .{ .code = 0xfffc0000, .nbits = 15 },
    .{ .code = 0xff800000, .nbits = 11 },
    .{ .code = 0xfff40000, .nbits = 14 },
    .{ .code = 0xffe80000, .nbits = 13 },
    .{ .code = 0xffffffc0, .nbits = 28 },
    .{ .code = 0xfffe6000, .nbits = 20 },
    .{ .code = 0xffff4800, .nbits = 22 },
    .{ .code = 0xfffe7000, .nbits = 20 },
    .{ .code = 0xfffe8000, .nbits = 20 },
    .{ .code = 0xffff4c00, .nbits = 22 },
    .{ .code = 0xffff5000, .nbits = 22 },
    .{ .code = 0xffff5400, .nbits = 22 },
    .{ .code = 0xffffb200, .nbits = 23 },
    .{ .code = 0xffff5800, .nbits = 22 },
    .{ .code = 0xffffb400, .nbits = 23 },
    .{ .code = 0xffffb600, .nbits = 23 },
    .{ .code = 0xffffb800, .nbits = 23 },
    .{ .code = 0xffffba00, .nbits = 23 },
    .{ .code = 0xffffbc00, .nbits = 23 },
    .{ .code = 0xffffeb00, .nbits = 24 },
    .{ .code = 0xffffbe00, .nbits = 23 },
    .{ .code = 0xffffec00, .nbits = 24 },
    .{ .code = 0xffffed00, .nbits = 24 },
    .{ .code = 0xffff5c00, .nbits = 22 },
    .{ .code = 0xffffc000, .nbits = 23 },
    .{ .code = 0xffffee00, .nbits = 24 },
    .{ .code = 0xffffc200, .nbits = 23 },
    .{ .code = 0xffffc400, .nbits = 23 },
    .{ .code = 0xffffc600, .nbits = 23 },
    .{ .code = 0xffffc800, .nbits = 23 },
    .{ .code = 0xfffee000, .nbits = 21 },
    .{ .code = 0xffff6000, .nbits = 22 },
    .{ .code = 0xffffca00, .nbits = 23 },
    .{ .code = 0xffff6400, .nbits = 22 },
    .{ .code = 0xffffcc00, .nbits = 23 },
    .{ .code = 0xffffce00, .nbits = 23 },
    .{ .code = 0xffffef00, .nbits = 24 },
    .{ .code = 0xffff6800, .nbits = 22 },
    .{ .code = 0xfffee800, .nbits = 21 },
    .{ .code = 0xfffe9000, .nbits = 20 },
    .{ .code = 0xffff6c00, .nbits = 22 },
    .{ .code = 0xffff7000, .nbits = 22 },
    .{ .code = 0xffffd000, .nbits = 23 },
    .{ .code = 0xffffd200, .nbits = 23 },
    .{ .code = 0xfffef000, .nbits = 21 },
    .{ .code = 0xffffd400, .nbits = 23 },
    .{ .code = 0xffff7400, .nbits = 22 },
    .{ .code = 0xffff7800, .nbits = 22 },
    .{ .code = 0xfffff000, .nbits = 24 },
    .{ .code = 0xfffef800, .nbits = 21 },
    .{ .code = 0xffff7c00, .nbits = 22 },
    .{ .code = 0xffffd600, .nbits = 23 },
    .{ .code = 0xffffd800, .nbits = 23 },
    .{ .code = 0xffff0000, .nbits = 21 },
    .{ .code = 0xffff0800, .nbits = 21 },
    .{ .code = 0xffff8000, .nbits = 22 },
    .{ .code = 0xffff1000, .nbits = 21 },
    .{ .code = 0xffffda00, .nbits = 23 },
    .{ .code = 0xffff8400, .nbits = 22 },
    .{ .code = 0xffffdc00, .nbits = 23 },
    .{ .code = 0xffffde00, .nbits = 23 },
    .{ .code = 0xfffea000, .nbits = 20 },
    .{ .code = 0xffff8800, .nbits = 22 },
    .{ .code = 0xffff8c00, .nbits = 22 },
    .{ .code = 0xffff9000, .nbits = 22 },
    .{ .code = 0xffffe000, .nbits = 23 },
    .{ .code = 0xffff9400, .nbits = 22 },
    .{ .code = 0xffff9800, .nbits = 22 },
    .{ .code = 0xffffe200, .nbits = 23 },
    .{ .code = 0xfffff800, .nbits = 26 },
    .{ .code = 0xfffff840, .nbits = 26 },
    .{ .code = 0xfffeb000, .nbits = 20 },
    .{ .code = 0xfffe2000, .nbits = 19 },
    .{ .code = 0xffff9c00, .nbits = 22 },
    .{ .code = 0xffffe400, .nbits = 23 },
    .{ .code = 0xffffa000, .nbits = 22 },
    .{ .code = 0xfffff600, .nbits = 25 },
    .{ .code = 0xfffff880, .nbits = 26 },
    .{ .code = 0xfffff8c0, .nbits = 26 },
    .{ .code = 0xfffff900, .nbits = 26 },
    .{ .code = 0xfffffbc0, .nbits = 27 },
    .{ .code = 0xfffffbe0, .nbits = 27 },
    .{ .code = 0xfffff940, .nbits = 26 },
    .{ .code = 0xfffff100, .nbits = 24 },
    .{ .code = 0xfffff680, .nbits = 25 },
    .{ .code = 0xfffe4000, .nbits = 19 },
    .{ .code = 0xffff1800, .nbits = 21 },
    .{ .code = 0xfffff980, .nbits = 26 },
    .{ .code = 0xfffffc00, .nbits = 27 },
    .{ .code = 0xfffffc20, .nbits = 27 },
    .{ .code = 0xfffff9c0, .nbits = 26 },
    .{ .code = 0xfffffc40, .nbits = 27 },
    .{ .code = 0xfffff200, .nbits = 24 },
    .{ .code = 0xffff2000, .nbits = 21 },
    .{ .code = 0xffff2800, .nbits = 21 },
    .{ .code = 0xfffffa00, .nbits = 26 },
    .{ .code = 0xfffffa40, .nbits = 26 },
    .{ .code = 0xffffffd0, .nbits = 28 },
    .{ .code = 0xfffffc60, .nbits = 27 },
    .{ .code = 0xfffffc80, .nbits = 27 },
    .{ .code = 0xfffffca0, .nbits = 27 },
    .{ .code = 0xfffec000, .nbits = 20 },
    .{ .code = 0xfffff300, .nbits = 24 },
    .{ .code = 0xfffed000, .nbits = 20 },
    .{ .code = 0xffff3000, .nbits = 21 },
    .{ .code = 0xffffa400, .nbits = 22 },
    .{ .code = 0xffff3800, .nbits = 21 },
    .{ .code = 0xffff4000, .nbits = 21 },
    .{ .code = 0xffffe600, .nbits = 23 },
    .{ .code = 0xffffa800, .nbits = 22 },
    .{ .code = 0xffffac00, .nbits = 22 },
    .{ .code = 0xfffff700, .nbits = 25 },
    .{ .code = 0xfffff780, .nbits = 25 },
    .{ .code = 0xfffff400, .nbits = 24 },
    .{ .code = 0xfffff500, .nbits = 24 },
    .{ .code = 0xfffffa80, .nbits = 26 },
    .{ .code = 0xffffe800, .nbits = 23 },
    .{ .code = 0xfffffac0, .nbits = 26 },
    .{ .code = 0xfffffcc0, .nbits = 27 },
    .{ .code = 0xfffffb00, .nbits = 26 },
    .{ .code = 0xfffffb40, .nbits = 26 },
    .{ .code = 0xfffffce0, .nbits = 27 },
    .{ .code = 0xfffffd00, .nbits = 27 },
    .{ .code = 0xfffffd20, .nbits = 27 },
    .{ .code = 0xfffffd40, .nbits = 27 },
    .{ .code = 0xfffffd60, .nbits = 27 },
    .{ .code = 0xffffffe0, .nbits = 28 },
    .{ .code = 0xfffffd80, .nbits = 27 },
    .{ .code = 0xfffffda0, .nbits = 27 },
    .{ .code = 0xfffffdc0, .nbits = 27 },
    .{ .code = 0xfffffde0, .nbits = 27 },
    .{ .code = 0xfffffe00, .nbits = 27 },
    .{ .code = 0xfffffb80, .nbits = 26 },
    .{ .code = 0xfffffffc, .nbits = 30 },
};

const NONE: u16 = 0xffff;

const HuffNode = struct {
    children: [2]u16 = .{ NONE, NONE },
    sym: i16 = -1,
    depth: u8 = 0,
    all_ones: bool = true,
};

/// A complete prefix code over 257 leaves needs 256 internal nodes
/// (2*L - 1 = 513 total). Round up for headroom.
const HUFF_TREE_CAP = 600;

/// Decoding trie built at comptime from `huff_table`. Building here doubles as
/// validation: a prefix collision would assign a symbol to an interior node and
/// surface as a decode failure in the accompanying tests.
const huff_tree = buildHuffTree();

fn buildHuffTree() [HUFF_TREE_CAP]HuffNode {
    @setEvalBranchQuota(1_000_000);
    var nodes = [_]HuffNode{.{}} ** HUFF_TREE_CAP;
    var count: u16 = 1; // node 0 is the root
    for (huff_table, 0..) |entry, sym| {
        const code = entry.code >> @as(u5, @intCast(32 - entry.nbits));
        var cur: u16 = 0;
        var bit_i: u8 = 0;
        while (bit_i < entry.nbits) : (bit_i += 1) {
            const shift: u5 = @intCast(entry.nbits - 1 - bit_i);
            const bit: u1 = @intCast((code >> shift) & 1);
            if (nodes[cur].children[bit] == NONE) {
                nodes[count] = .{
                    .depth = nodes[cur].depth + 1,
                    .all_ones = nodes[cur].all_ones and (bit == 1),
                };
                nodes[cur].children[bit] = count;
                count += 1;
            }
            cur = nodes[cur].children[bit];
        }
        nodes[cur].sym = @intCast(sym);
    }
    return nodes;
}

/// Decode an HPACK Huffman-encoded byte string (RFC 7541 §5.2) into the raw
/// header octets. Caller owns the returned slice.
pub fn decodeAlloc(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var node: u16 = 0;
    for (src) |byte| {
        var i: u4 = 0;
        while (i < 8) : (i += 1) {
            const shift: u3 = @intCast(7 - i);
            const bit: u1 = @intCast((byte >> shift) & 1);
            const next = huff_tree[node].children[bit];
            if (next == NONE) return error.InvalidHuffmanCode;
            node = next;
            const sym = huff_tree[node].sym;
            if (sym >= 0) {
                // An explicit EOS symbol inside the stream is a decode error.
                if (sym == EOS_SYMBOL) return error.InvalidHuffmanCode;
                try out.append(allocator, @intCast(sym));
                node = 0;
            }
        }
    }

    // Trailing bits must be the most-significant bits of the EOS code (all
    // ones) and shorter than a full byte (RFC 7541 §5.2). A non-ones remainder
    // or padding of 8+ bits is malformed.
    if (node != 0) {
        if (!huff_tree[node].all_ones or huff_tree[node].depth >= 8) {
            return error.InvalidHuffmanCode;
        }
    }

    return out.toOwnedSlice(allocator);
}

test "huffman decode www.example.com (RFC 7541 C.4.1)" {
    const allocator = std.testing.allocator;
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    const decoded = try decodeAlloc(allocator, encoded[0..]);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("www.example.com", decoded);
}

test "huffman decode no-cache (RFC 7541 C.4.2)" {
    const allocator = std.testing.allocator;
    const encoded = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    const decoded = try decodeAlloc(allocator, encoded[0..]);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("no-cache", decoded);
}

test "huffman decode custom-key / custom-value (RFC 7541 C.4.3)" {
    const allocator = std.testing.allocator;
    const key = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
    const dk = try decodeAlloc(allocator, key[0..]);
    defer allocator.free(dk);
    try std.testing.expectEqualStrings("custom-key", dk);

    const val = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf };
    const dv = try decodeAlloc(allocator, val[0..]);
    defer allocator.free(dv);
    try std.testing.expectEqualStrings("custom-value", dv);
}

test "huffman decode response values (RFC 7541 C.6.1)" {
    const allocator = std.testing.allocator;

    // "302"
    const s302 = [_]u8{ 0x64, 0x02 };
    const d302 = try decodeAlloc(allocator, s302[0..]);
    defer allocator.free(d302);
    try std.testing.expectEqualStrings("302", d302);

    // "private"
    const priv = [_]u8{ 0xae, 0xc3, 0x77, 0x1a, 0x4b };
    const dpriv = try decodeAlloc(allocator, priv[0..]);
    defer allocator.free(dpriv);
    try std.testing.expectEqualStrings("private", dpriv);

    // "Mon, 21 Oct 2013 20:13:21 GMT"
    const date = [_]u8{
        0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
        0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d,
        0x1b, 0xff,
    };
    const ddate = try decodeAlloc(allocator, date[0..]);
    defer allocator.free(ddate);
    try std.testing.expectEqualStrings("Mon, 21 Oct 2013 20:13:21 GMT", ddate);

    // "https://www.example.com"
    const loc = [_]u8{
        0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97,
        0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
    };
    const dloc = try decodeAlloc(allocator, loc[0..]);
    defer allocator.free(dloc);
    try std.testing.expectEqualStrings("https://www.example.com", dloc);
}

test "huffman decode empty string" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAlloc(allocator, &[_]u8{});
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "huffman rejects bad padding (non-ones remainder)" {
    const allocator = std.testing.allocator;
    // "0" is code 00000 (5 bits); pad with zeros instead of ones -> invalid.
    const bad = [_]u8{0x00};
    try std.testing.expectError(error.InvalidHuffmanCode, decodeAlloc(allocator, bad[0..]));
}

test "huffman rejects EOS in stream" {
    const allocator = std.testing.allocator;
    // 30 one-bits (EOS) followed by ones: 0xff 0xff 0xff 0xff -> 32 ones,
    // first 30 form EOS which is illegal inside a string.
    const bad = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(error.InvalidHuffmanCode, decodeAlloc(allocator, bad[0..]));
}

test "fuzz: decodeAlloc never panics on arbitrary byte sequences" {
    try std.testing.fuzz({}, fuzzHuffmanDecodeAlloc, .{
        .corpus = &.{
            // RFC 7541 Appendix C: Huffman-encoded "www.example.com"
            "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
            // RFC 7541 Appendix C: Huffman-encoded "no-cache"
            "\xa8\xeb\x10\x64\x9c\xbf",
            "\xff\xff\xff\xff", // EOS pattern (invalid)
            "",
        },
    });
}

fn fuzzHuffmanDecodeAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    const result = decodeAlloc(allocator, buf[0..len]) catch return;
    defer allocator.free(result);
}
