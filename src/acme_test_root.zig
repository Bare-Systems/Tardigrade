//! Root of the dedicated `zig build test-acme` gate (#832). Lives in `src/`
//! so the module can reach both `acme/` and the native TLS dialer in `http/`.

const std = @import("std");

test {
    _ = @import("acme/root.zig");
    _ = @import("acme/csr.zig");
    _ = @import("http/acme_tls_dialer.zig");
    _ = @import("http/acme_challenge_store.zig");
}

/// Production (non-test) text of a source file: everything before its first
/// test-support or test declaration.
fn productionText(source: []const u8) []const u8 {
    var end = source.len;
    for ([_][]const u8{ "\nconst testing = ", "\ntest \"", "\nconst TempState", "\nfn fuzz" }) |marker| {
        if (std.mem.indexOf(u8, source, marker)) |at| end = @min(end, at);
    }
    return source[0..end];
}

test "ACME implementation stays behind the native compat boundary (#832)" {
    const files = .{
        .{ "acme/account.zig", @embedFile("acme/account.zig") },
        .{ "acme/csr.zig", @embedFile("acme/csr.zig") },
        .{ "acme/names.zig", @embedFile("acme/names.zig") },
        .{ "acme/contact.zig", @embedFile("acme/contact.zig") },
        .{ "acme/client.zig", @embedFile("acme/client.zig") },
        .{ "acme/json_limits.zig", @embedFile("acme/json_limits.zig") },
        .{ "acme/state.zig", @embedFile("acme/state.zig") },
        .{ "acme/transport.zig", @embedFile("acme/transport.zig") },
        .{ "acme/url.zig", @embedFile("acme/url.zig") },
        .{ "http/acme_tls_dialer.zig", @embedFile("http/acme_tls_dialer.zig") },
        .{ "http/acme_challenge_store.zig", @embedFile("http/acme_challenge_store.zig") },
    };
    // Direct libc/POSIX calls belong in zig_compat.zig; no foreign crypto or
    // C interop anywhere in the ACME implementation.
    const forbidden = [_][]const u8{ "std.c.", "std.posix.", "@c" ++ "Import", "@c" ++ "Include", "open" ++ "ssl", "OPEN" ++ "SSL", "lib" ++ "crypto", "extern \"" ++ "c\"" };
    inline for (files) |entry| {
        const text = productionText(entry[1]);
        try std.testing.expect(text.len > 200);
        for (forbidden) |needle| {
            if (std.mem.indexOf(u8, text, needle)) |at| {
                std.debug.print("{s}: forbidden `{s}` at byte {d}\n", .{ entry[0], needle, at });
                return error.AcmeCompatBoundaryViolation;
            }
        }
    }
}
