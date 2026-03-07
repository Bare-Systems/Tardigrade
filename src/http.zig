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
pub const etag = @import("http/etag.zig");
pub const correlation = @import("http/correlation_id.zig");
pub const auth = @import("http/auth.zig");
pub const rate_limiter = @import("http/rate_limiter.zig");
pub const security_headers = @import("http/security_headers.zig");
pub const request_context = @import("http/request_context.zig");
pub const api_router = @import("http/api_router.zig");
pub const idempotency = @import("http/idempotency.zig");
pub const session = @import("http/session.zig");
pub const command = @import("http/command.zig");
pub const access_control = @import("http/access_control.zig");
pub const request_limits = @import("http/request_limits.zig");
pub const basic_auth = @import("http/basic_auth.zig");
pub const logger = @import("http/logger.zig");
pub const cache_control = @import("http/cache_control.zig");
pub const compression = @import("http/compression.zig");
pub const metrics = @import("http/metrics.zig");
pub const shutdown = @import("http/shutdown.zig");
pub const circuit_breaker = @import("http/circuit_breaker.zig");
pub const access_log = @import("http/access_log.zig");
pub const event_loop = @import("http/event_loop.zig");

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
