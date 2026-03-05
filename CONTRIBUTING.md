# Contributing to Tardigrade

Thank you for your interest in contributing! This document provides guidelines and information for developers.

## Development Setup

### Prerequisites

- [Zig](https://ziglang.org/) 0.14.1 or later
- Git
- curl (for manual testing)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/Bare-Labs/Tardigrade.git
cd Tardigrade

# Build and run tests
zig build test

# Build and run the server
zig build run
```

### Development Commands

```bash
# Build (debug)
zig build

# Build (release)
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Build and run
zig build run
```

## Project Architecture

```
src/
├── main.zig              # Entry point, server loop, connection handling
├── http.zig              # HTTP module root (re-exports submodules)
└── http/
    ├── method.zig        # HTTP method enum (GET, POST, etc.)
    ├── version.zig       # HTTP version (1.0, 1.1)
    ├── headers.zig       # Header parsing and storage
    ├── request.zig       # Request parser
    ├── status.zig        # HTTP status codes
    └── response.zig      # Response builder
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `method.zig` | HTTP method enum with parsing and properties |
| `version.zig` | HTTP version parsing (1.0, 1.1) |
| `headers.zig` | Case-insensitive header storage with size limits |
| `request.zig` | Full HTTP/1.1 request parser |
| `status.zig` | All HTTP status codes with reason phrases |
| `response.zig` | Response builder with auto-generated headers |

## Code Style Guidelines

### General

- Use Zig idioms: prefer `errdefer`, handle all errors explicitly
- Avoid `@panic` in production code paths - return errors instead
- Use `std.log` for logging with appropriate levels
- Keep allocations explicit - prefer stack when possible
- Use arena allocators for request-scoped allocations
- Document public functions with doc comments (`///`)

### Error Handling

```zig
fn doThing() !void {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.log.err("Failed to open {s}: {}", .{ path, err });
        return err;
    };
    defer file.close();
    // ...
}
```

### Memory Management

```zig
// Request-scoped allocation with arena
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();
const req_alloc = arena.allocator();
// All request allocations use req_alloc, freed automatically at end
```

## Development Workflow

### Adding a New Feature

1. **Create a branch**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/feature-name
   ```

2. **Create a changes document**
   ```bash
   # Create changes/feature-name.md with:
   # - Overview of the feature
   # - Scope of changes
   # - Files to be modified
   # - Testing plan
   # - Acceptance criteria
   ```

3. **Implement the feature**
   - Write tests alongside implementation
   - Keep changes focused and minimal
   - Follow existing code patterns

4. **Test thoroughly**
   ```bash
   # Run unit tests
   zig build test

   # Manual testing with curl
   ./zig-out/bin/tardigrade &
   curl -v http://localhost:8069/
   ```

5. **Update documentation**
   - Update CHANGELOG.md with version and date
   - Update README.md if user-facing changes
   - Add doc comments to new public APIs

6. **Commit and push**
   ```bash
   git add .
   git commit -m "Brief description of changes"
   git push -u origin feature/feature-name
   ```

### Commit Message Format

```
Brief summary (50 chars or less)

- Detailed point 1
- Detailed point 2
- Detailed point 3
```

## Testing

### Unit Tests

Write tests in the same file as the implementation:

```zig
test "parse simple GET request" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/", req.uri.path);
}
```

### Manual Testing

```bash
# Start the server
./zig-out/bin/tardigrade &

# Basic GET
curl -v http://localhost:8069/

# HEAD request
curl -I http://localhost:8069/

# 404 test
curl -v http://localhost:8069/nonexistent

# Method not allowed
curl -v -X POST http://localhost:8069/

# Kill the server
pkill tardigrade
```

### Test Coverage Goals

- Unit tests for all parser edge cases
- Integration tests for HTTP request/response cycles
- Error handling paths tested
- Security tests (path traversal, malformed requests)

### Troubleshooting tests

When everything passes `zig build test` can appear to print nothing. To force a summary of all test results, run:

```bash
zig build test --summary all
```

## Security Considerations

When contributing, please ensure:

- **Validate all inputs**: Check sizes, formats, and boundaries
- **Prevent path traversal**: Block `..` in file paths
- **Limit resource usage**: Enforce max header/body sizes
- **Handle errors gracefully**: Never panic on user input
- **No sensitive data in logs**: Avoid logging request bodies

## Performance Guidelines

- Minimize allocations in hot paths
- Use stack buffers where size is bounded
- Consider zero-copy techniques for file serving
- Profile before optimizing

## Project Roadmap

See PLAN.md for the complete nginx feature parity roadmap and contribution instructions.

## Contributing to the Plan

If you'd like to propose roadmap changes or additions, follow these steps:

1. Create a `changes/` document for your proposal (e.g. `changes/feature-name.md`) that includes:
   - Overview of the feature
   - Scope and files to change
   - Testing plan and acceptance criteria

2. Open a pull request that includes your `changes/` document and any updates to `PLAN.md` to reflect the proposed status.

3. Discuss and iterate on the PR until it is merged. The `PLAN.md` is the single source of truth for roadmap priorities.

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Include reproduction steps for bugs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
