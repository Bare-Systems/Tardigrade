# Simple HTTP Server

A minimal HTTP server written in Zig that serves static files from a `public` directory.

## Features

- Serves static files from a `public` directory
- Handles basic HTTP GET requests
- Supports serving HTML files
- Simple and lightweight implementation

## Prerequisites

- Zig 0.14.1 or later

## Project Structure

```
.
├── src/
│   └── main.zig    # Main server implementation
├── public/         # Directory for static files
│   └── index.html  # Default page served at root
└── README.md
```

## Building and Running

Build and run the server:
```bash
zig build run
```

The server will start listening on `0.0.0.0:8069`.

## Usage

Once the server is running, you can access it through your web browser or using curl:

```bash
# Access the root page
curl http://localhost:8069/

# Access other files in the public directory
curl http://localhost:8069/other-file.html
```

## Implementation Details

- The server listens on port 8069
- Supports basic HTTP GET requests
- Serves files from the `public` directory
- Returns 404 for non-existent files
- Returns 405 for non-GET requests

## License

This project is open source and available under the MIT License. 