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
- `TARDIGRADE_UPSTREAM_BASE_URL` (default `http://127.0.0.1:8080`)
- `TARDIGRADE_PROXY_PASS_CHAT` (default `/v1/chat`; absolute URL or path target)
- `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` (default empty; absolute URL or path prefix used before command upstream subpaths)
- `TARDIGRADE_AUTH_TOKEN_HASHES` (comma-separated lowercase SHA-256 token hashes)
- `TARDIGRADE_MAX_MESSAGE_CHARS` (default `4000`)

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
