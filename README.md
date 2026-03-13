<h1 align="center">Tardigrade</h1>

<p align="center">
  High-performance Zig edge gateway and HTTP server for static delivery, reverse proxying,
  protocol bridging, and realtime event transport.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/zig-0.14.1%2B-f7a41d?style=flat-square" alt="Zig 0.14.1+">
  <img src="https://img.shields.io/badge/license-Apache%202.0-7cb518?style=flat-square" alt="Apache 2.0">
  <img src="https://img.shields.io/badge/protocols-HTTP%2F1.1%20%2B%20HTTP%2F2%20%2B%20HTTP%2F3-6c5ce7?style=flat-square" alt="HTTP protocols">
  <img src="https://img.shields.io/badge/interfaces-REST%20%2B%20WebSocket%20%2B%20SSE-118ab2?style=flat-square" alt="Interfaces">
</p>

---

Tardigrade is a Zig service runtime with two primary roles:

- **HTTP server** for static assets, conditional requests, range responses, location routing, custom error pages, and TLS termination.
- **Edge gateway** for authenticated APIs, upstream health checks, HTTP/3, protocol bridges (FastCGI, SCGI, uWSGI, gRPC, memcached), mail relays, and realtime mux/SSE streams.

The current codebase includes:

- HTTP/1.1, HTTP/2, and opt-in HTTP/3 via `ngtcp2`/`nghttp3`
- reverse proxying with retries, cache, health checks, and hot reload
- WebSocket chat/command paths plus multiplexed mux channels with replay and backpressure handling
- approval workflows, session/device auth, and policy-gated command execution
- FastCGI, SCGI, uWSGI, SMTP, IMAP, and POP3 relay support

Breaking behavior is tracked in [CHANGELOG.md](./CHANGELOG.md). Work history and implementation notes live under `changes/`.

## Features

- **Zig-first runtime**: Built on Zig 0.14.1 with predictable memory ownership and low overhead
- **Gateway routing**: Health, metrics, chat, commands, approvals, sessions, cache purge, and admin routes
- **Protocol breadth**: Static files, reverse proxy, HTTP/2, HTTP/3, WebSocket, SSE, FastCGI, SCGI, uWSGI, and mail relay paths
- **Operational controls**: Hot reload, active upstream health checks, TLS/SNI, config validation, access logging, and graceful shutdown
- **Realtime delivery**: Multiplexed WebSocket channels with device scoping, overflow protection, and replay support

## Quick Start

### Prerequisites

- [Zig](https://ziglang.org/) 0.14.1 or later

### Build and Run

```bash
# Clone the repository
git clone https://github.com/Bare-Labs/Tardigrade.git
cd Tardigrade

# Build and run
zig build run
```

The server starts on `http://localhost:8069` by default.

### Install latest Linux binary

```bash
curl -fsSL -o tardigrade-linux-x86_64.tar.gz \
  https://github.com/Bare-Labs/Tardigrade/releases/latest/download/tardigrade-linux-x86_64.tar.gz
tar -xzf tardigrade-linux-x86_64.tar.gz
chmod +x tardigrade
./tardigrade
```

## Configuration

Tardigrade supports both environment-variable configuration and nginx-style config files.

Core generic capabilities include:

- listeners, TLS, HTTP/2, and opt-in HTTP/3
- `server` and `location` blocks
- static roots, `try_files`, `rewrite`, `return`, `error_page`, and `autoindex`
- reverse proxying, upstream pools, retries, active health checks, and proxy caching
- FastCGI, SCGI, uWSGI, gRPC, memcached, mail, and stream proxy backends
- access logging, graceful shutdown, hot reload, and config validation

Config file notes:

- statements end with `;`
- basic directive: `listen_port 8069;`
- explicit env-style directive: `TARDIGRADE_LOG_LEVEL debug;`
- variables: `set $base /etc/tardigrade;` with `${base}` interpolation
- include support: `include conf.d/*.conf;`
- environment variables override config-file values

### Environment Variables

#### Listener, TLS, and HTTP

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_LISTEN_HOST` | Listener bind address | `0.0.0.0` |
| `TARDIGRADE_LISTEN_PORT` | Listener TCP port | `8069` |
| `TARDIGRADE_TLS_CERT_PATH` | PEM certificate path | empty |
| `TARDIGRADE_TLS_KEY_PATH` | PEM private key path | empty |
| `TARDIGRADE_TLS_MIN_VERSION` | Minimum TLS version | `1.2` |
| `TARDIGRADE_TLS_MAX_VERSION` | Maximum TLS version | `1.3` |
| `TARDIGRADE_TLS_CIPHER_LIST` | OpenSSL cipher list for TLS <= 1.2 | empty |
| `TARDIGRADE_TLS_CIPHER_SUITES` | OpenSSL cipher suites for TLS 1.3 | empty |
| `TARDIGRADE_TLS_SNI_CERTS` | SNI cert mapping `host:cert:key|...` | empty |
| `TARDIGRADE_TLS_SESSION_CACHE` | Enable TLS session cache | `true` |
| `TARDIGRADE_TLS_SESSION_CACHE_SIZE` | Session cache target entry count | `20480` |
| `TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS` | TLS session resumption timeout | `300` |
| `TARDIGRADE_TLS_SESSION_TICKETS` | Enable TLS session tickets | `true` |
| `TARDIGRADE_TLS_OCSP_STAPLING` | Enable static OCSP stapling | `false` |
| `TARDIGRADE_TLS_OCSP_RESPONSE_PATH` | DER OCSP response file path | empty |
| `TARDIGRADE_TLS_CLIENT_CA_PATH` | CA bundle for client certificate verification | empty |
| `TARDIGRADE_TLS_CLIENT_VERIFY` | Require and verify client certificates | `false` |
| `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH` | Maximum client certificate chain depth | `3` |
| `TARDIGRADE_TLS_CRL_PATH` | PEM CRL file path | empty |
| `TARDIGRADE_TLS_CRL_CHECK` | Enable CRL checks | `false` |
| `TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS` | TLS asset reload poll interval | `5000` |
| `TARDIGRADE_TLS_ACME_ENABLED` | Enable ACME-style cert directory discovery | `false` |
| `TARDIGRADE_TLS_ACME_CERT_DIR` | Directory containing `<host>.crt` and `<host>.key` files | empty |
| `TARDIGRADE_HTTP2_ENABLED` | Enable HTTP/2 on TLS listeners | `true` |
| `TARDIGRADE_HTTP3_ENABLED` | Enable HTTP/3 runtime | `false` |
| `TARDIGRADE_QUIC_PORT` | UDP QUIC listener port | `443` |
| `TARDIGRADE_HTTP3_ENABLE_0RTT` | Allow 0-RTT handling in HTTP/3 foundation logic | `false` |
| `TARDIGRADE_HTTP3_CONNECTION_MIGRATION` | Allow QUIC connection migration updates | `false` |
| `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` | Target maximum QUIC datagram size | `1350` |
| `TARDIGRADE_PROXY_PROTOCOL` | PROXY protocol mode for plaintext listeners | `off` |
| `TARDIGRADE_VALIDATE_CONFIG_ONLY` | Validate config and exit without serving | empty |

#### Trust, Upstreams, and Proxying

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_TRUST_GATEWAY_ID` | Gateway identity sent in trusted upstream headers | `tardigrade-edge` |
| `TARDIGRADE_TRUST_SHARED_SECRET` | Shared secret for signed upstream trust headers | empty |
| `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` | Allowed trusted upstream identities or hosts | empty |
| `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY` | Require trusted upstream identity verification | `false` |
| `TARDIGRADE_UPSTREAM_BASE_URL` | Primary upstream base URL | `http://127.0.0.1:8080` |
| `TARDIGRADE_UPSTREAM_BASE_URLS` | Comma-separated primary upstream URLs | empty |
| `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` | Weights aligned with `TARDIGRADE_UPSTREAM_BASE_URLS` | empty |
| `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` | Backup upstream base URLs | empty |
| `TARDIGRADE_UPSTREAM_LB_ALGORITHM` | Upstream load-balancing algorithm | `round_robin` |
| `TARDIGRADE_UPSTREAM_TIMEOUT_MS` | Per-attempt upstream timeout | `10000` |
| `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` | Stream non-200 upstream responses directly | `false` |
| `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` | Upstream attempts per request | `1` |
| `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` | Total timeout budget across retries | `0` |
| `TARDIGRADE_UPSTREAM_MAX_FAILS` | Passive unhealthy threshold | `0` |
| `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS` | Passive failure cooldown window | `10000` |
| `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS` | Active upstream probe interval | `0` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS` | Legacy alias for active upstream probe interval | `0` |
| `TARDIGRADE_UPSTREAM_PROBE_PATH` | Active upstream probe path | `/` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH` | Legacy alias for active upstream probe path | `/` |
| `TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS` | Active upstream probe timeout | `2000` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS` | Legacy alias for active upstream probe timeout | `2000` |
| `TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD` | Consecutive active probe failures before unhealthy | `1` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD` | Legacy alias for active upstream probe failure threshold | `1` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD` | Consecutive active probe successes before healthy | `1` |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS` | Accepted active probe status range | `200-299` |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS` | Legacy alias for accepted active probe status range | `200-299` |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS_OVERRIDES` | Per-upstream active probe success-status overrides | empty |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS_OVERRIDES` | Legacy alias for per-upstream active probe success-status overrides | empty |
| `TARDIGRADE_UPSTREAM_SLOW_START_MS` | Recovered-backend ramp window | `0` |
| `TARDIGRADE_CB_THRESHOLD` | Circuit-breaker trip threshold | `0` |
| `TARDIGRADE_CB_TIMEOUT_MS` | Circuit-breaker open timeout | `30000` |
| `TARDIGRADE_PROXY_CACHE_TTL_SECONDS` | In-memory proxy cache TTL | `0` |
| `TARDIGRADE_PROXY_CACHE_PATH` | Optional disk proxy cache path | empty |
| `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE` | Proxy cache key template | `method:path:payload_sha256` |
| `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS` | Stale serving window after TTL expiry | `0` |
| `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS` | Cache lock wait timeout | `250` |
| `TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS` | Cache maintenance interval | `30000` |
| `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED` | Gunzip upstream gzip responses before downstream negotiation | `true` |
| `TARDIGRADE_MIRROR_RULES` | Semicolon-separated mirror dispatch rules | empty |

#### Authentication and Access Control

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_BASIC_AUTH_HASHES` | Lowercase SHA-256 hashes of `user:password` | empty |
| `TARDIGRADE_AUTH_TOKEN_HASHES` | Lowercase SHA-256 hashes of accepted bearer tokens | empty |
| `TARDIGRADE_SESSION_STORE_PATH` | Optional JSON file for persisted gateway sessions | empty |
| `TARDIGRADE_TRANSCRIPT_STORE_PATH` | Optional NDJSON file for persisted gateway chat/command transcripts | empty |

#### Request Handling, Limits, and Connection Management

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_RATE_LIMIT_RPS` | Per-IP rate limit requests per second | `10` |
| `TARDIGRADE_RATE_LIMIT_BURST` | Rate limiter burst capacity | `20` |
| `TARDIGRADE_SECURITY_HEADERS` | Enable default security headers | `true` |
| `TARDIGRADE_IDEMPOTENCY_TTL` | Idempotency cache TTL in seconds | `300` |
| `TARDIGRADE_GEO_BLOCKED_COUNTRIES` | Comma-separated blocked ISO country codes | empty |
| `TARDIGRADE_GEO_COUNTRY_HEADER` | Header used to read country code | `CF-IPCountry` |
| `TARDIGRADE_ACCESS_CONTROL` | IP access-control rules | empty |
| `TARDIGRADE_MAX_BODY_SIZE` | Maximum request body size in bytes | `0` |
| `TARDIGRADE_MAX_URI_LENGTH` | Maximum request URI length | `0` |
| `TARDIGRADE_MAX_HEADER_COUNT` | Maximum request header count | `0` |
| `TARDIGRADE_MAX_HEADER_SIZE` | Maximum total request header bytes | `0` |
| `TARDIGRADE_BODY_TIMEOUT_MS` | Request body read timeout | `0` |
| `TARDIGRADE_HEADER_TIMEOUT_MS` | Request header read timeout | `0` |
| `TARDIGRADE_FD_SOFT_LIMIT` | Desired process soft file-descriptor limit | `0` |
| `TARDIGRADE_LIMIT_CONN_PER_IP` | Alias for per-IP connection cap | empty |
| `TARDIGRADE_MAX_CONNECTIONS_PER_IP` | Per-IP connection cap | `0` |
| `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | Global active connection cap | `0` |
| `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` | Keep-alive idle timeout | `5000` |
| `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` | Max requests served on one keep-alive connection | `100` |
| `TARDIGRADE_CONNECTION_POOL_SIZE` | Cached connection-session pool size | `256` |
| `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` | Max retained memory per active connection | `2097152` |
| `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` | Global estimated connection memory cap | `0` |

#### Routing, Config, Static, and Secrets

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_REWRITE_RULES` | Semicolon-separated rewrite rules | empty |
| `TARDIGRADE_RETURN_RULES` | Semicolon-separated return rules | empty |
| `TARDIGRADE_CONDITIONAL_RULES` | Semicolon-separated inline conditional rules | empty |
| `TARDIGRADE_LOCATION_BLOCKS` | Serialized location block definitions | empty |
| `TARDIGRADE_LOCATION_ERROR_PAGES` | Serialized location error-page rules | empty |
| `TARDIGRADE_INTERNAL_REDIRECT_RULES` | Internal redirect rules | empty |
| `TARDIGRADE_NAMED_LOCATIONS` | Named location mappings | empty |
| `TARDIGRADE_SERVER_NAMES` | Listener-level accepted host patterns | empty |
| `TARDIGRADE_SERVER_BLOCKS` | Serialized server block definitions | empty |
| `TARDIGRADE_DOC_ROOT` | Static fallback document root | empty |
| `TARDIGRADE_TRY_FILES` | Comma-separated `try_files` candidates | empty |
| `TARDIGRADE_CONFIG_PATH` | nginx-style config file path | empty |
| `TARDIGRADE_SECRETS_PATH` | Secrets override file path | empty |
| `TARDIGRADE_SECRET_KEYS` | Hex keys for `ENC:` secret values | empty |

#### Backend, Mail, and Stream Protocol Bridges

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_FASTCGI_UPSTREAM` | FastCGI upstream endpoint | empty |
| `TARDIGRADE_FASTCGI_PARAMS` | Additional FastCGI params | empty |
| `TARDIGRADE_FASTCGI_INDEX` | Default FastCGI index file | `index.php` |
| `TARDIGRADE_UWSGI_UPSTREAM` | uWSGI upstream endpoint | empty |
| `TARDIGRADE_SCGI_UPSTREAM` | SCGI upstream endpoint | empty |
| `TARDIGRADE_GRPC_UPSTREAM` | gRPC upstream URL | empty |
| `TARDIGRADE_MEMCACHED_UPSTREAM` | Memcached upstream endpoint | empty |
| `TARDIGRADE_SMTP_UPSTREAM` | SMTP upstream endpoint | empty |
| `TARDIGRADE_IMAP_UPSTREAM` | IMAP upstream endpoint | empty |
| `TARDIGRADE_POP3_UPSTREAM` | POP3 upstream endpoint | empty |
| `TARDIGRADE_TCP_PROXY_UPSTREAM` | Stream TCP upstream endpoint | empty |
| `TARDIGRADE_UDP_PROXY_UPSTREAM` | Stream UDP upstream endpoint | empty |
| `TARDIGRADE_STREAM_SSL_TERMINATION` | Enable stream SSL-termination mode indicator | `false` |
| `TARDIGRADE_CORRELATION_ID` | Internal correlation ID env forwarded to protocol bridge subprocess-style backends | empty |

#### Logging, Compression, and Process Model

| Name | Description | Default |
|---|---|---|
| `TARDIGRADE_ADD_HEADERS` | Additional response headers as `Name: Value` entries | empty |
| `TARDIGRADE_ACCESS_LOG_FORMAT` | Access log format | `json` |
| `TARDIGRADE_ACCESS_LOG_TEMPLATE` | Custom access-log template | empty |
| `TARDIGRADE_ACCESS_LOG_MIN_STATUS` | Minimum status code required for access-log emission | `0` |
| `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` | Access-log buffer size in bytes | `0` |
| `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP` | Syslog UDP endpoint | empty |
| `TARDIGRADE_LOG_LEVEL` | Error-log level | `info` |
| `TARDIGRADE_ERROR_LOG_PATH` | Error-log destination path | empty |
| `TARDIGRADE_LOG_ROTATE_MAX_BYTES` | Rotate error log at startup above this size | `0` |
| `TARDIGRADE_LOG_ROTATE_MAX_FILES` | Number of rotated error-log generations to keep | `5` |
| `TARDIGRADE_COMPRESSION_ENABLED` | Enable response compression | `true` |
| `TARDIGRADE_COMPRESSION_MIN_SIZE` | Minimum body size to compress | `256` |
| `TARDIGRADE_COMPRESSION_BROTLI_ENABLED` | Enable Brotli compression | `true` |
| `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` | Brotli quality level | `5` |
| `TARDIGRADE_PID_FILE` | PID file path | empty |
| `TARDIGRADE_RUN_USER` | Numeric uid for privilege drop | empty |
| `TARDIGRADE_RUN_GROUP` | Numeric gid for privilege drop | empty |
| `TARDIGRADE_REQUIRE_UNPRIVILEGED_USER` | Fail startup if still running as uid 0 after privilege-drop flow | `false` |
| `TARDIGRADE_CHROOT_DIR` | Optional chroot directory | empty |
| `TARDIGRADE_WORKER_THREADS` | Worker thread count, `0` uses runtime default | `0` |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | Worker queue depth | `1024` |
| `TARDIGRADE_MASTER_PROCESS` | Enable master-worker process supervision | `false` |
| `TARDIGRADE_WORKER_PROCESSES` | Worker process count in master mode | `1` |
| `TARDIGRADE_BINARY_UPGRADE` | Enable `SIGUSR2` binary upgrade handoff | `true` |
| `TARDIGRADE_WORKER_RECYCLE_SECONDS` | Worker recycle interval | `0` |
| `TARDIGRADE_WORKER_CPU_AFFINITY` | Linux CPU affinity list for workers | empty |

## Examples

Example deployment bundles live under `examples/`.

- Generic static/reverse-proxy deployments can be built directly from the core directives.
- Product-specific API layouts belong in example bundles, not in the default project description.
- An application-facing gateway example is available under `examples/`.

## Testing

```bash
zig build test
zig build test-integration
```

### Build for Production

```bash
# Build optimized release binary
zig build -Doptimize=ReleaseFast

# Run the binary directly
./zig-out/bin/tardigrade
```

## Usage

### Serving Static Files

Place your files in the `public/` directory:

```
public/
├── index.html      # Served at /
├── css/
│   └── style.css   # Served at /css/style.css
├── js/
│   └── app.js      # Served at /js/app.js
└── images/
    └── logo.png    # Served at /images/logo.png
```

Directory index behavior: requests to a directory will serve `index.html` or `index.htm` if present. Directories requested without a trailing slash will be redirected with `301 Moved Permanently` to the trailing-slash form (for correct relative asset resolution).

### Example Requests

```bash
# Get the index page
curl http://localhost:8069/

# Get a specific file
curl http://localhost:8069/css/style.css

# HEAD request (headers only)
curl -I http://localhost:8069/

# Check response headers
curl -v http://localhost:8069/
```

### Response Headers

All responses include:
- `Date`: Current timestamp in RFC 7231 format
- `Server`: Server identification (tardigrade/0.4.1)
- `Content-Type`: Automatically detected from file extension
- `Content-Length`: Size of response body

## Supported MIME Types

| Extension | Content-Type |
|-----------|--------------|
| .html, .htm | text/html; charset=utf-8 |
| .css | text/css; charset=utf-8 |
| .js | text/javascript; charset=utf-8 |
| .json | application/json |
| .png | image/png |
| .jpg, .jpeg | image/jpeg |
| .gif | image/gif |
| .svg | image/svg+xml |
| .pdf | application/pdf |
| .wasm | application/wasm |
| ... | (30+ types supported) |

## HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | OK - File served successfully |
| 400 | Bad Request - Malformed HTTP request |
| 403 | Forbidden - Path traversal attempt blocked |
| 404 | Not Found - File does not exist |
| 405 | Method Not Allowed - Only GET/HEAD supported |
| 413 | Payload Too Large - Request body exceeds limit |
| 414 | URI Too Long - Request URI exceeds limit |
| 431 | Request Header Fields Too Large |
| 500 | Internal Server Error |
| 501 | Not Implemented - Unknown HTTP method |
| 505 | HTTP Version Not Supported |

## Project Status

This project is under active development. See [CHANGELOG.md](CHANGELOG.md) for recent changes.

### Roadmap

Note: See [PLAN.md](PLAN.md) for the full roadmap and prioritized work.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

This project is open source and available under the MIT License.
