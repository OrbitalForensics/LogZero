# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LogZero is a high-performance, modular timeline generator for processing logs and artifacts into normalized, structured event timelines. It's a DFIR (Digital Forensics and Incident Response) tool designed for field use by analysts.

## Build and Development Commands

```bash
# Build the GUI application (recommended)
./bin/wails.exe build           # Windows
wails build                     # macOS/Linux (if wails is in PATH)

# The built executable will be at:
# - Windows: build/bin/logzero.exe
# - macOS/Linux: build/bin/logzero

# Run the GUI application
./build/bin/logzero.exe         # Just double-click or run - no flags needed!

# CLI Mode (for scripting/automation)
./build/bin/logzero.exe --input <path> --output <file> --format jsonl

# API Server Mode (headless)
./build/bin/logzero.exe --api-only --port 8765

# Development mode (hot reload)
./bin/wails.exe dev

# Run tests
go test ./...
go test ./parsers -v  # Run parser tests with verbose output
```

## Usage Examples

```bash
# Process a single log file
./logzero.exe --input /path/to/auth.log --output timeline.jsonl --format jsonl

# Process an entire directory of logs
./logzero.exe --input /path/to/logs/ --output timeline.jsonl --format jsonl

# Output formats: jsonl (default), csv, sqlite
./logzero.exe --input logs/ --output timeline.csv --format csv
./logzero.exe --input logs/ --output timeline.db --format sqlite
```

## Architecture Overview

LogZero follows a clean, layered architecture with concurrent processing:

### Core Components

1. **Event Normalization** (`core/event.go`): All log types are normalized to a unified `core.Event` structure with fields like timestamp, source, event_type, user, host, message, and future AI/ML fields (tags, score, summary).

2. **Parser System** (`parsers/`): Modular interface-based parsers. Each parser implements:
   - `Parse(filePath string) ([]*core.Event, error)`
   - `CanParse(filePath string) bool`

   **Supported Parsers:**
   - Linux Syslog (RFC 3164, RFC 5424)
   - Windows Event Logs (EVTX, CBS, WindowsUpdate)
   - Web Access Logs (Apache, Nginx Combined Log Format)
   - IIS Logs (W3C Extended)
   - Zeek Network Logs (conn.log, dns.log, http.log, etc.)
   - Firewall Logs (Windows Firewall, iptables/UFW, Cisco ASA)
   - Cloud Logs (AWS CloudTrail, Azure Activity, GCP Audit)
   - macOS Logs (Unified, Install, ASL)
   - PowerShell Logs (Transcript, Script Block)
   - JSON/JSONL event logs
   - Generic timestamped log files

3. **Output System** (`output/`): Writers implementing a common interface for CSV, JSONL, and SQLite formats. All writers implement:
   - `Write(events []*core.Event) error`
   - `Close() error`

4. **Concurrent Processing** (`internal/processor/`): Worker pool pattern using goroutines with context-based cancellation and atomic progress tracking.

5. **GUI** (`frontend/` + `app_wails.go`): Wails-based cross-platform GUI with React frontend.

6. **API Server** (`api/server.go`): RESTful HTTP server with Server-Sent Events for real-time progress updates.

### Key Design Patterns

- **Factory Pattern**: `parsers.GetParserForFile()` and `output.GetWriter()` for dynamic component selection
- **Worker Pool**: Concurrent file processing with configurable goroutine pool
- **Context Cancellation**: Graceful shutdown across all components
- **Interface-Based Design**: All parsers and writers implement standard interfaces

## Adding New Features

### Adding a New Parser

1. Create a new file in `parsers/` (e.g., `parsers/myformat.go`)
2. Implement the `Parser` interface
3. Register the parser in `parsers/parser.go`'s `GetParserForFile()` function
4. Add test cases in `parsers/manual_verification_test.go`

### Adding a New Output Format

1. Create a new file in `output/` (e.g., `output/myformat.go`)
2. Implement the `Writer` interface
3. Register the writer in `output/writer.go`'s `GetWriter()` function

## Testing Patterns

Tests use table-driven patterns with temporary file creation:

```go
func TestMyParser(t *testing.T) {
    tests := []struct {
        name     string
        content  string
        expected *core.Event
    }{...}

    // Create temp file, parse, and verify
}
```

## Performance

LogZero is optimized for high-throughput processing:
- **~800,000 events/second** throughput
- Handles 100,000+ entry files in under 500ms
- Concurrent processing of multiple files
- Memory-efficient streaming for large files

## Important Considerations

- **Wails Build**: Always use `wails build` for production builds (not `go build`)
- **CGO Dependency**: SQLite features require CGO
- **Thread Safety**: Use mutexes for shared resources and atomic operations for counters
- **Error Handling**: Always wrap errors with context using `fmt.Errorf()`
- **Resource Cleanup**: Always defer Close() for files, database connections, and writers
- **Progress Updates**: Use atomic operations for concurrent progress tracking
- **GOPATH**: Do NOT place the project inside GOPATH - use Go modules
