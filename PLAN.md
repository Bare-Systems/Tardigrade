# Tardigrade - Zig nginx Replacement

## Project Vision

Build a high-performance HTTP server in Zig as a complete replacement for nginx while also acting as the secure gateway and runtime edge for Bare Labs services.

The project has two parallel goals:

1. nginx parity — full high-performance HTTP server functionality
2. Agent Gateway — a secure edge gateway for BearClaw and Panda clients

Tardigrade should eventually function as:

- HTTP server
- reverse proxy
- API gateway
- event stream broker
- TLS termination point
- Bare Labs service mesh edge

## Updated Architecture Role

Panda (iOS app)
      |
      | HTTPS / WebSocket / SSE
      v
Tardigrade (gateway / runtime edge)
      |
      v
BearClaw
      |
      |- Koala
      |- Polar
      |- Kodiak
      |- Ursa
      |- Bear Arms

Responsibilities:

Component | Responsibility
---|---
Panda | client UI / secure device
Tardigrade | secure gateway + runtime
BearClaw | agent brain
Other services | internal tools

## COMPLETE NGINX FEATURE PARITY ROADMAP

Keep the existing roadmap content, but reorganize phases so a gateway MVP happens early.

## PHASE 0: Gateway Foundations (NEW)
Priority: CRITICAL

These features allow Tardigrade to become the Panda/BearClaw gateway early.

### 0.1 Identity & Authentication
- [ ] Bearer token authentication
- [ ] Device identity registration
- [ ] Public/private key device authentication
- [ ] Auth middleware pipeline
- [ ] Request auth context propagation
- [ ] Token validation hooks
- [ ] Token expiration / refresh logic

### 0.2 Session Management
- [ ] Session token issuance
- [ ] Session storage abstraction
- [ ] Device session tracking
- [ ] Revocation support

### 0.3 API Gateway Core
- [ ] JSON request validation
- [ ] API version routing
- [ ] Correlation IDs
- [ ] Idempotency key support
- [ ] Request metadata injection

### 0.4 Agent Command Routing
- [ ] structured command routing
- [ ] upstream request envelope
- [ ] authenticated request forwarding
- [ ] request auditing

## PHASE 1: Core HTTP Server Foundation

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

### 1.3 Error pages
- [ ] Custom error pages (400, 401, 403, 404, 500, 502, 503, 504)
- [ ] Error logging with levels
- [ ] Graceful error responses

Resolved: custom error pages implemented and samples added under `public/errors/`.

### 1.4 Basic Logging
- [x] Access log (combined format)
- [ ] Error log with severity levels
- [ ] Timestamps and request IDs
- [ ] Log rotation support

## PHASE 2: Async I/O & Performance

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

## PHASE 3: Configuration System

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

### 3.5 Secret Management (NEW)
- [ ] encrypted secret storage
- [ ] environment overrides
- [ ] runtime secret reload
- [ ] key rotation support

Secrets may include:

- TLS keys
- auth signing keys
- upstream API credentials
- service tokens

## PHASE 4: Reverse Proxy

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

### 4.6 Service Trust Model (NEW)
- [ ] trusted upstream configuration
- [ ] signed upstream headers
- [ ] auth context forwarding
- [ ] upstream identity verification

### 4.7 Unix Socket Upstreams (NEW)
- [ ] unix domain socket backends
- [ ] local IPC routing
- [ ] socket-based load balancing

## PHASE 5: Caching

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

## PHASE 6: Security Features

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

### 6.6 Policy Engine (NEW)
- [ ] route-level policy evaluation
- [ ] device-based restrictions
- [ ] per-user scopes
- [ ] approval-required routes
- [ ] time-based policy rules

## PHASE 7: TLS / SSL

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

## PHASE 8: HTTP/2 & HTTP/3

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

## PHASE 9: WebSocket & Event Streaming

### 9.1 WebSocket Proxying
- [ ] upgrade handling
- [ ] bidirectional proxying
- [ ] wss support

### 9.2 WebSocket Runtime
- [ ] ping/pong
- [ ] idle timeout
- [ ] load balancing

### 9.3 Server-Sent Events (NEW)
- [ ] SSE protocol support
- [ ] long-lived stream connections
- [ ] reconnect tokens
- [ ] stream backpressure

### 9.4 Event Fanout (NEW)
- [ ] event broadcast to subscribers
- [ ] topic-based subscriptions
- [ ] event buffering
- [ ] slow client protection

## PHASE 10: Compression

### 10.1 Response Compression
- [ ] gzip compression
- [ ] gzip_static (pre-compressed files)
- [ ] Brotli compression
- [ ] Compression level configuration
- [ ] MIME type filtering
- [ ] Minimum size threshold

### 10.2 Decompression
- [ ] gunzip for backends that don't support it

## PHASE 11: Advanced Features

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

## PHASE 12: Observability

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

### 12.4 Admin API
- [ ] route inspection
- [ ] active connections
- [ ] stream status
- [ ] upstream health
- [ ] loaded certificates
- [ ] auth/device registry

## PHASE 13: Production Hardening

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

### 13.4 Resilience Features (NEW)
- [ ] circuit breakers
- [ ] retry policies
- [ ] timeout budgets
- [ ] overload protection
- [ ] request queue management

## PHASE 14: Real-Time Messaging Gateway (NEW)

This phase enables Tardigrade to function as the Panda/BearClaw gateway.

### 14.1 Command Protocol
- [ ] structured command envelopes
- [ ] command lifecycle tracking
- [ ] async command completion

### 14.2 Stream Multiplexing
- [ ] multiplex multiple streams
- [ ] command + event streams
- [ ] per-device stream isolation

### 14.3 Approval Workflows
- [ ] approval request routing
- [ ] approval response handling
- [ ] timeout escalation

## IMPLEMENTATION PRIORITY ORDER

Tier 1: Gateway MVP

1. HTTP parser
2. Response builder
3. Async I/O
4. TLS termination
5. Reverse proxy
6. WebSocket support
7. Authentication middleware
8. Basic configuration
9. Request size limits
10. Connection timeouts

At this stage Panda -> Tardigrade -> BearClaw communication works.

Tier 2: Production Gateway

11. Logging
12. Request IDs
13. device identity
14. policy engine
15. SSE streaming
16. admin API
17. graceful shutdown

Tier 3: Nginx Parity Core

18. full config system
19. virtual hosts
20. location routing
21. upstream pools
22. load balancing
23. caching

Tier 4: Security & Performance

24. rate limiting
25. connection limits
26. security headers
27. compression
28. circuit breakers

Tier 5: Advanced Protocols

29. HTTP/2
30. HTTP/3
31. advanced proxy protocols