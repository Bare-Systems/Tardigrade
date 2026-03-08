# Tardigrade

A high-performance HTTP server written in Zig, designed as a modern replacement for nginx.

## Features

- **Fast**: Built with Zig for predictable performance and low memory usage
- **Static File Serving**: Serves files from a configurable directory with proper MIME types
- **HTTP/1.1 Compliant**: Full request parsing with header support
- **Keep-Alive Connections**: Persistent connections for improved performance
- **30+ MIME Types**: Automatic content-type detection for common file extensions
- **Security**: Path traversal protection, request size limits

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

## BearClaw Edge Gateway MVP

Tardigrade now supports an edge-gateway path for BearClaw:
- `GET /health`
- `POST /v1/chat` (Bearer auth required)

Environment variables:
- `TARDIGRADE_LISTEN_HOST` (default `0.0.0.0`)
- `TARDIGRADE_LISTEN_PORT` (default `8069`)
- `TARDIGRADE_TLS_CERT_PATH` (PEM certificate path; enables TLS termination when paired with key)
- `TARDIGRADE_TLS_KEY_PATH` (PEM private key path; enables TLS termination when paired with cert)
- `TARDIGRADE_PROXY_PROTOCOL` (default `off`; supported: `off`, `auto`, `v1`, `v2`; applies to plaintext listeners for extracting client IP from PROXY headers)
- `TARDIGRADE_TRUST_GATEWAY_ID` (default `tardigrade-edge`; gateway identity sent in trusted upstream headers)
- `TARDIGRADE_TRUST_SHARED_SECRET` (default empty; shared secret enabling signed upstream trust headers)
- `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` (default empty; optional comma-separated upstream identities/hosts allowed for trusted upstream verification)
- `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY` (default `false`; when true, upstream identity must match trusted identities and trust secret must be configured)
- `TARDIGRADE_UPSTREAM_BASE_URL` (default `http://127.0.0.1:8080`)
- `TARDIGRADE_UPSTREAM_BASE_URLS` (default empty; optional comma-separated upstream base URLs used for proxy load balancing/failover)
- Upstream endpoint values support TCP URLs (`http://host:port`) and Unix socket endpoints (`unix:/path/to/socket.sock` or `unix:///path/to/socket.sock`) for local IPC routing.
- `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` (default empty; optional comma-separated positive integer weights aligned with `TARDIGRADE_UPSTREAM_BASE_URLS`)
- `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` (default empty; optional comma-separated backup upstream base URLs used when primaries are unavailable)
- `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS` (default empty; optional comma-separated upstream block for `/v1/chat`; falls back to global upstream pool when unset)
- `TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS` (default empty; optional weights aligned with `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS`)
- `TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS` (default empty; optional backup upstreams for `/v1/chat` block)
- `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS` (default empty; optional comma-separated upstream block for `/v1/commands`; falls back to global upstream pool when unset)
- `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS` (default empty; optional weights aligned with `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS`)
- `TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS` (default empty; optional backup upstreams for `/v1/commands` block)
- `TARDIGRADE_UPSTREAM_LB_ALGORITHM` (default `round_robin`; supported: `round_robin`, `least_connections`, `ip_hash`, `generic_hash`, `random_two_choices`)
- `TARDIGRADE_PROXY_PASS_CHAT` (default `/v1/chat`; absolute URL or path target)
- `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` (default empty; absolute URL or path prefix used before command upstream subpaths)
- `TARDIGRADE_AUTH_TOKEN_HASHES` (comma-separated lowercase SHA-256 token hashes)
- `TARDIGRADE_MAX_MESSAGE_CHARS` (default `4000`)
- `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` (default `5000`; idle timeout for keep-alive client connections)
- `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` (default `100`; max requests served before closing keep-alive connection)
- `TARDIGRADE_CONNECTION_POOL_SIZE` (default `256`; max cached connection-session objects reused by workers)
- `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` (default `0`; global active client connection cap; `0` disables)
- `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` (default `2097152`; max memory retained per active connection for request/proxy buffering)
- `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` (default `0`; global estimated memory cap across active connections; `0` disables)
- `TARDIGRADE_FD_SOFT_LIMIT` (default `0`; desired process soft file-descriptor limit; best-effort on supported Unix platforms)
- `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` (default `false`; when enabled, streams non-200 upstream responses directly instead of mapping to gateway error envelopes)
- `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` (default `1`; number of upstream attempts per proxy request; when multiple upstream base URLs are configured, attempts rotate across them)
- `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` (default `0`; total timeout budget across all upstream attempts; `0` disables budget enforcement)
- `TARDIGRADE_UPSTREAM_MAX_FAILS` (default `0`; passive health threshold; `0` disables passive unhealthy marking)
- `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS` (default `10000`; cooldown window before a failed upstream is retried)
- `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS` (default `0`; periodic active probe interval; `0` disables active probes)
- `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH` (default `/health`; path used for active health probes)
- `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_TIMEOUT_MS` (default `2000`; per-probe timeout)
- `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD` (default `1`; consecutive active probe failures required before marking unhealthy)
- `TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD` (default `1`; consecutive active probe successes required before clearing unhealthy state)
- `TARDIGRADE_UPSTREAM_SLOW_START_MS` (default `0`; recovered-backend ramp window before full traffic share; `0` disables slow-start)

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
