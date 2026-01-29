// HTTP module - HTTP/1.1 protocol implementation

pub const Method = @import("http/method.zig").Method;
pub const Version = @import("http/version.zig").Version;
pub const Headers = @import("http/headers.zig").Headers;
pub const Request = @import("http/request.zig").Request;
pub const Uri = @import("http/request.zig").Uri;
pub const ParseError = @import("http/request.zig").ParseError;
pub const Status = @import("http/status.zig").Status;
pub const Response = @import("http/response.zig").Response;

pub const headers = @import("http/headers.zig");
pub const request = @import("http/request.zig");
pub const status = @import("http/status.zig");
pub const response = @import("http/response.zig");
pub const autoindex = @import("http/autoindex.zig");
pub const dates = @import("http/dates.zig");

// Re-export constants
pub const MAX_HEADERS = headers.MAX_HEADERS;
pub const MAX_HEADER_SIZE = headers.MAX_HEADER_SIZE;
pub const MAX_REQUEST_LINE_SIZE = request.MAX_REQUEST_LINE_SIZE;
pub const DEFAULT_MAX_BODY_SIZE = request.DEFAULT_MAX_BODY_SIZE;
pub const SERVER_NAME = response.SERVER_NAME;
pub const SERVER_VERSION = response.SERVER_VERSION;

test {
    // Run all tests in submodules
    @import("std").testing.refAllDecls(@This());
}
