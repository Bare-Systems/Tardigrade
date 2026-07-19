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
pub const range = @import("http/range.zig");
pub const static_file = @import("http/static_file.zig");
pub const correlation = @import("http/correlation_id.zig");
pub const auth = @import("http/auth.zig");
pub const rate_limiter = @import("http/rate_limiter.zig");
pub const security_headers = @import("http/security_headers.zig");
pub const request_context = @import("http/request_context.zig");
pub const cancellation = @import("http/cancellation.zig");
pub const request_lifecycle = @import("http/request_lifecycle.zig");
pub const api_router = @import("http/api_router.zig");
pub const idempotency = @import("http/idempotency.zig");
pub const session = @import("http/session.zig");
pub const session_store_file = @import("http/session_store_file.zig");
pub const command = @import("http/command.zig");
pub const access_control = @import("http/access_control.zig");
pub const request_limits = @import("http/request_limits.zig");
pub const basic_auth = @import("http/basic_auth.zig");
pub const jwt = @import("http/jwt.zig");
pub const logger = @import("http/logger.zig");
pub const cache_control = @import("http/cache_control.zig");
pub const compression = @import("http/compression.zig");
pub const metrics = @import("http/metrics.zig");
pub const shutdown = @import("http/shutdown.zig");
pub const health_checker = @import("http/health_checker.zig");
pub const circuit_breaker = @import("http/circuit_breaker.zig");
pub const access_log = @import("http/access_log.zig");
pub const event_loop = @import("http/event_loop.zig");
pub const worker_pool = @import("http/worker_pool.zig");
pub const buffer_pool = @import("http/buffer_pool.zig");
pub const proxy_buffer_account = @import("http/proxy_buffer_account.zig");
pub const keepalive_park = @import("http/keepalive_park.zig");
pub const encrypted_stream_connection = @import("http/encrypted_stream_connection.zig");
pub const negotiated_dispatch = @import("http/negotiated_dispatch.zig");
pub const native_tls_connection = @import("http/native_tls_connection.zig");
pub const downstream_connection = @import("http/downstream_connection.zig");
pub const upstream_pool = @import("http/upstream_pool.zig");
/// TLS termination backend selected by `-Dtls-profile` (#379): the OpenSSL
/// adapter in the general profile, a no-OpenSSL stub in the Bare Systems
/// appliance profile. The swap happens in `http/tls_backend.zig` — at the
/// module graph, not at runtime — so an appliance binary never analyzes
/// `@cImport("openssl/...")` and cannot silently fall back to the C adapter.
pub const tls_termination = @import("http/tls_backend.zig");
/// ACME client backend selected by `-Dtls-profile` (#379): OpenSSL-backed in
/// the general profile, a no-OpenSSL stub in the appliance profile. Selected
/// at the module graph so the appliance never links OpenSSL through ACME.
pub const acme_client = @import("http/acme_backend.zig");
pub const hpack = @import("http/hpack.zig");
pub const http2_frame = @import("http/http2_frame.zig");
pub const http2_stream = @import("http/http2_stream.zig");
pub const upstream_h2 = @import("http/upstream_h2.zig");
pub const stream_transport = @import("stream_transport");
pub const quic = @import("quic");
pub const http3_handler = @import("http/http3_handler.zig");
pub const http3_session = @import("http/http3_session.zig");
pub const http3_runtime = @import("http/http3_runtime.zig");
pub const websocket = @import("http/websocket.zig");
pub const event_hub = @import("http/event_hub.zig");
pub const rewrite = @import("http/rewrite.zig");
pub const location_router = @import("http/location_router.zig");
pub const fastcgi = @import("http/fastcgi.zig");
pub const uwsgi = @import("http/uwsgi.zig");
pub const scgi = @import("http/scgi.zig");
pub const memcached = @import("http/memcached.zig");
pub const config_file = @import("http/config_file.zig");
pub const secrets = @import("http/secrets.zig");
pub const approval_store = @import("http/approval_store.zig");
pub const transcript_store = @import("http/transcript_store.zig");
pub const trace_context = @import("http/trace_context.zig");
pub const dns_discovery = @import("http/dns_discovery.zig");

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
