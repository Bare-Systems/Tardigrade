# Simple Server - Zig nginx Replacement

## Project Vision

Build a high-performance HTTP server in Zig as a complete replacement for nginx. This project aims to replicate nginx's core functionality while leveraging Zig's safety, performance, and simplicity.

## Current State

Minimal HTTP server serving static files from `public/` directory on port 8069. Recent releases have significantly extended functionality:

- RFC-compliant HTTP/1.1 request parser (methods, URI/path+query, headers, Content-Length bodies)
- HEAD request support
- MIME type detection for many common file types
- Structured logging via `std.log`
- Modular HTTP response builder (`src/http/response.zig`) and HTTP status module (`src/http/status.zig`)
- Responses automatically include `Date` and `Server` headers; `Content-Length` now calculated by the response builder
- Method Not Allowed (405) responses include an `Allow` header

Core constraints still apply: single-threaded blocking I/O, no async/event loop or worker pool, and limited production hardening (see Known Issues).

## Development Commands

```bash
# Build
zig build

# Build and run
zig build run

# Run tests
zig build test

# Build optimized release
zig build -Doptimize=ReleaseFast
```

## Development Workflow

For each feature:
1. Create a branch: `git checkout -b feature/feature-name`
2. Create `changes/feature-name.md` with scope and test plan
3. Implement the feature
4. Test thoroughly (manual + automated)
5. Update documentation
6. Commit and push: `git push -u origin feature/feature-name`

---

# COMPLETE NGINX FEATURE PARITY ROADMAP

Based on comprehensive research of nginx capabilities, here is everything needed for full replacement.

## PHASE 1: Core HTTP Server Foundation
**Priority: CRITICAL - Must complete first**

### 1.1 HTTP/1.1 Protocol Compliance
- [x] Full request parser (method, URI, version, headers, body)
- [x] Request line parsing with proper validation
- [x] Header parsing (case-insensitive, multi-line values)
- [x] Request body handling (Content-Length, chunked)
- [x] Response builder with status codes (1xx-5xx)
- [x] Proper header generation (Date, Server, Content-Length, etc.)
- [x] Connection: keep-alive / close handling
- [x] HTTP method support: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS

### 1.2 Static File Serving
- [x] MIME type detection (50+ common types)
- [x] Directory index (index.html, index.htm)
 - [x] Directory listing (autoindex)
- [x] Range requests (partial content, byte ranges)
 - [x] Last-Modified and If-Modified-Since

- [ ] Custom error pages (400, 401, 403, 404, 500, 502, 503, 504)
- [ ] Error logging with levels
- [ ] Graceful error responses

Resolved: custom error pages implemented and samples added under `public/errors/`.

### 1.4 Basic Logging
- [ ] Access log (combined format)
- [ ] Error log with severity levels
- [ ] Timestamps and request IDs
- [ ] Log rotation support

---

## PHASE 2: Async I/O & Performance
**Priority: HIGH - Required for production use**

### 2.1 Event Loop
- [ ] epoll (Linux) / kqueue (macOS/BSD) abstraction
- [ ] Non-blocking socket I/O
- [ ] Event-driven connection handling
- [ ] Timer management for timeouts

### 2.2 Connection Management
- [ ] Connection pooling
- [ ] Keep-alive with configurable timeout
- [ ] Request pipelining
- [ ] Connection limits per IP
- [ ] Graceful connection draining

### 2.3 Worker Model
- [ ] Multi-threaded worker pool
- [ ] Thread-safe shared state
- [ ] Work stealing / load balancing between workers
- [ ] Graceful shutdown with connection draining

### 2.4 Memory Management
- [ ] Arena allocators for request scope
- [ ] Buffer pooling
- [ ] Zero-copy where possible
- [ ] Memory limits per connection

---

## PHASE 3: Configuration System
**Priority: HIGH - Needed for flexibility**

### 3.1 Configuration File Parser
- [ ] keep-alive integration tests (low priority)
- [ ] nginx-like syntax OR YAML/TOML
- [ ] Include directive for modular configs
- [ ] Variable interpolation
- [ ] Syntax validation with helpful errors

### 3.2 Core Directives
- [ ] worker_processes
- [ ] worker_connections
- [ ] error_log
- [ ] pid file
- [ ] user/group (privilege dropping)

### 3.3 HTTP Block Directives
- [ ] server blocks (virtual hosts)
- [ ] listen (address:port, ssl, http2)
- [ ] server_name (wildcards, regex)
- [ ] root / alias
- [ ] location blocks (prefix, exact, regex)
- [ ] try_files
- [ ] return / rewrite
- [ ] if conditionals (limited)

### 3.4 Hot Reload
- [ ] SIGHUP configuration reload
- [ ] Zero-downtime reload
- [ ] Configuration validation before apply

---

## PHASE 4: Reverse Proxy
**Priority: HIGH - Core nginx use case**

### 4.1 Basic Proxying
- [ ] proxy_pass directive
- [ ] Backend connection pooling
- [ ] Request/response streaming
- [ ] Header manipulation (add, remove, modify)
- [ ] X-Forwarded-For, X-Real-IP
- [ ] X-Forwarded-Proto, X-Forwarded-Host
- [ ] Host header rewriting

### 4.2 Upstream Management
- [ ] upstream blocks
- [ ] Multiple backend servers
- [ ] Server weights
- [ ] Backup servers
- [ ] max_fails / fail_timeout

### 4.3 Load Balancing Algorithms
- [ ] Round-robin (default)
- [ ] Least connections
- [ ] IP hash (session persistence)
- [ ] Generic hash
- [ ] Random with two choices

### 4.4 Health Checks
- [ ] Passive health checks (mark failed on errors)
- [ ] Active health checks (periodic probes)
- [ ] Configurable thresholds
- [ ] Slow start for recovered servers

### 4.5 Proxy Protocol Support
- [ ] Protocol v1 and v2
- [ ] Extracting real client IP

---

## PHASE 5: Caching
**Priority: MEDIUM - Performance optimization**

### 5.1 Proxy Cache
- [ ] proxy_cache_path (disk-based)
- [ ] Cache key configuration
- [ ] Cache validity rules
- [ ] Cache bypass conditions
- [ ] Cache purging

### 5.2 Advanced Caching
- [ ] Stale content serving (stale-while-revalidate)
- [ ] Cache locking (single request populates)
- [ ] Background cache updates
- [ ] Cache manager process
- [ ] Memory + disk tiered caching

### 5.3 Browser Caching
- [ ] Expires header
- [ ] Cache-Control header
- [ ] ETag/Last-Modified validation

---

## PHASE 6: Security Features
**Priority: HIGH - Required for production**

### 6.1 Access Control
- [ ] allow/deny directives (IP-based)
- [ ] CIDR notation support
- [ ] Geo-based blocking (via external data)

### 6.2 Rate Limiting
- [ ] limit_req (request rate)
- [ ] limit_conn (connection count)
- [ ] Configurable zones and keys
- [ ] Burst handling
- [ ] Custom rejection responses

### 6.3 Authentication
- [ ] HTTP Basic Auth
- [ ] Auth request (subrequest-based)
- [ ] JWT validation (optional module)

### 6.4 Request Validation
- [ ] Request body size limits (client_max_body_size)
- [ ] Header count/size limits
- [ ] URI length limits
- [ ] Timeout enforcement (client_body_timeout, etc.)

### 6.5 Security Headers
- [ ] add_header directive
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] Content-Security-Policy
- [ ] Strict-Transport-Security

---

## PHASE 7: TLS/SSL
**Priority: HIGH - Required for HTTPS**

### 7.1 Basic TLS
- [ ] TLS termination
- [ ] Certificate and key loading
- [ ] TLS 1.2 / 1.3 support
- [ ] Cipher suite configuration
- [ ] Protocol version selection

### 7.2 Advanced TLS
- [ ] SNI (Server Name Indication)
- [ ] Multiple certificates per server
- [ ] Session resumption (session cache)
- [ ] Session tickets
- [ ] OCSP stapling

### 7.3 Client Certificates
- [ ] Client certificate verification
- [ ] Certificate chain validation
- [ ] CRL checking

### 7.4 Certificate Management
- [ ] Dynamic certificate loading
- [ ] ACME/Let's Encrypt integration (optional)

---

## PHASE 8: HTTP/2 & HTTP/3
**Priority: MEDIUM - Modern protocol support**

### 8.1 HTTP/2
- [ ] HPACK header compression
- [ ] Stream multiplexing
- [ ] Server push
- [ ] Priority handling
- [ ] Flow control
- [ ] HTTP/2 to HTTP/1.1 backend translation

### 8.2 HTTP/3 (QUIC)
- [ ] QUIC protocol implementation
- [ ] 0-RTT connection establishment
- [ ] Connection migration
- [ ] QPACK header compression

---

## PHASE 9: WebSocket Support
**Priority: MEDIUM - Real-time applications**

### 9.1 WebSocket Proxying
- [ ] Upgrade header handling
- [ ] Connection upgrade to WebSocket
- [ ] Bidirectional proxying
- [ ] WebSocket over TLS (wss://)

### 9.2 WebSocket Features
- [ ] Ping/pong handling
- [ ] Connection timeouts
- [ ] Load balancing (sticky sessions)

---

## PHASE 10: Compression
**Priority: MEDIUM - Bandwidth optimization**

### 10.1 Response Compression
- [ ] gzip compression
- [ ] gzip_static (pre-compressed files)
- [ ] Brotli compression
- [ ] Compression level configuration
- [ ] MIME type filtering
- [ ] Minimum size threshold

### 10.2 Decompression
- [ ] gunzip for backends that don't support it

---

## PHASE 11: Advanced Features
**Priority: LOW - Nice to have**

### 11.1 URL Rewriting
- [ ] rewrite directive (regex-based)
- [ ] Rewrite flags (last, break, redirect, permanent)
- [ ] return directive
- [ ] Conditional rewriting

### 11.2 Request Processing
- [ ] Sub-requests
- [ ] Internal redirects
- [ ] Named locations
- [ ] Mirror requests

### 11.3 Backend Protocols
- [ ] FastCGI proxy
- [ ] uWSGI proxy
- [ ] SCGI proxy
- [ ] gRPC proxy
- [ ] Memcached integration

### 11.4 Mail Proxy (Optional)
- [ ] SMTP proxy
- [ ] IMAP proxy
- [ ] POP3 proxy

### 11.5 TCP/UDP Proxy (Stream Module)
- [ ] Generic TCP proxying
- [ ] UDP proxying
- [ ] Stream SSL termination

---

## PHASE 12: Observability
**Priority: MEDIUM - Production operations**

### 12.1 Logging
- [ ] Custom log formats
- [ ] Conditional logging
- [ ] JSON log format
- [ ] Access log buffering
- [ ] Syslog integration

### 12.2 Metrics
- [ ] Stub status endpoint
- [ ] Connection statistics
- [ ] Request statistics
- [ ] Upstream health status
- [ ] Prometheus metrics export (optional)

### 12.3 Debugging
- [ ] Debug logging
- [ ] Request tracing
- [ ] Error categorization

---

## PHASE 13: Production Hardening
**Priority: HIGH - Before production deployment**

### 13.1 Process Management
- [ ] Master/worker process model
- [ ] Graceful shutdown (SIGTERM/SIGQUIT)
- [ ] Binary upgrade (SIGUSR2)
- [ ] Worker process recycling
- [ ] CPU affinity

### 13.2 Resource Limits
- [ ] File descriptor limits
- [ ] Worker connection limits
- [ ] Memory limits
- [ ] Request queue limits

### 13.3 Privilege Management
- [ ] Run as unprivileged user
- [ ] Privilege dropping after bind
- [ ] Chroot support (optional)

---

# IMPLEMENTATION PRIORITY ORDER

## Tier 1: MVP (Usable HTTP Server)
1. HTTP/1.1 request parser
2. Response builder with proper headers
3. MIME type detection
4. Error responses (400, 404, 405, 500)
5. Keep-alive connections
6. Basic logging

## Tier 2: Production Static Server
7. Async I/O (epoll/kqueue)
8. Worker threads
9. Configuration file
10. Virtual hosts (server blocks)
11. Location routing
12. TLS termination
13. Access logging
14. Graceful shutdown

## Tier 3: Reverse Proxy
15. Basic proxy_pass
16. Upstream blocks
17. Load balancing (round-robin)
18. Health checks
19. Header manipulation
20. Proxy caching

## Tier 4: Security & Rate Limiting
21. Rate limiting
22. Connection limits
23. IP allow/deny
24. Request size limits
25. Security headers

## Tier 5: Advanced Features
26. HTTP/2
27. WebSocket proxy
28. Compression (gzip)
29. URL rewriting
30. HTTP/3 (QUIC)

---

# TESTING STRATEGY

## Unit Tests
- HTTP parser edge cases
- Header parsing
- MIME type detection
- Configuration parsing
- URL routing logic

## Integration Tests
- Full HTTP request/response cycles
- Keep-alive behavior
- Error handling
- TLS handshakes
- Proxy forwarding

- [ ] Socket-level keep-alive integration test (deferred): spawn server, open a single TCP connection and verify multiple requests reuse the same connection. Schedule after keep-alive implementation stabilizes.

## Load Tests
- Requests per second (wrk, hey)
- Concurrent connections
- Memory usage under load
- Latency percentiles

## Conformance Tests
- HTTP/1.1 RFC compliance
- TLS protocol compliance
- HTTP/2 h2spec tests

## Security Tests
- Path traversal attempts
- Header injection
- Request smuggling
- Malformed requests

---

# PERFORMANCE TARGETS

| Metric | Target | nginx Reference |
|--------|--------|-----------------|
| Static file RPS (1 worker) | 50,000+ | ~60,000 |
| Memory per idle connection | <4KB | ~2.5KB |
| Latency p99 (static) | <1ms | <1ms |
| Max concurrent connections | 10,000+ | 10,000+ |
| TLS handshakes/sec | 5,000+ | ~8,000 |

---

# CURRENT KNOWN ISSUES

- Single-threaded blocking I/O (no epoll/kqueue abstraction or worker threads yet)
- No request size limits configured (client_max_body_size not enforced)
- No timeout enforcement (client_body_timeout, client_header_timeout, etc.)
- Limited configuration system (no nginx-like config yet)
- No TLS termination (HTTPS) or certificate management

Resolved (recent releases):
- Naive HTTP parsing — replaced by RFC-compliant HTTP/1.1 parser
- Hardcoded `Content-Type` — MIME type detection implemented
- Path traversal vulnerability — path traversal protection implemented
- No logging — structured logging added

---

# REFERENCES

- [nginx documentation](https://nginx.org/en/docs/)
- [HTTP/1.1 RFC 7230-7235](https://tools.ietf.org/html/rfc7230)
- [HTTP/2 RFC 7540](https://tools.ietf.org/html/rfc7540)
- [Zig std.net documentation](https://ziglang.org/documentation/master/std/#std.net)
- [nginx architecture blog](https://www.nginx.com/blog/inside-nginx-how-we-designed-for-performance-scale/)

---

# AGENT INSTRUCTIONS

When implementing features:

1. **Follow the workflow**: Branch → changes/doc → implement → test → commit
2. **One feature at a time**: Complete and test before moving on
3. **Test thoroughly**: Both automated and manual with curl
4. **Update this doc**: Mark checkboxes as features complete
5. **Keep it building**: Never commit broken code
6. **Security first**: Validate all inputs, prevent path traversal
7. **Handle errors**: No panics in production paths

## Contributing to the Plan

To propose roadmap changes or add new work items, create a `changes/` document describing the proposal (overview, scope, files to change, testing plan, and acceptance criteria) and open a pull request that includes the `changes/` file and any suggested updates to `PLAN.md`. Discuss and iterate on the PR until merged — `PLAN.md` is the single source of truth for roadmap priorities.
