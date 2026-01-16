# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LogZero is a high-performance, modular timeline generator for processing logs and artifacts into normalized, structured event timelines. It's a DFIR (Digital Forensics and Incident Response) tool designed for field use by analysts.

## Build and Development Commands

```bash
# Required environment setup (if building in GOPATH)
# Windows PowerShell:
$env:GO111MODULE="on"
$env:GOPATH="$env:USERPROFILE\go"

# macOS/Linux:
export GO111MODULE=on

# Install dependencies
go mod tidy
cd frontend && npm install && cd ..

# Build the application (uses Wails)
wails build

# Or use the build script (Windows)
powershell -ExecutionPolicy Bypass -File build.ps1

# Run the application
./build/bin/logzero.exe     # GUI mode (default)
./build/bin/logzero.exe --input <path> --output <path> --format jsonl  # CLI mode
./build/bin/logzero.exe --api-only --port 8765  # API server mode

# Run tests
go test ./...
go test ./parsers -v  # Run parser tests with verbose output
```

## Architecture Overview

LogZero follows a clean, layered architecture with concurrent processing:

### Core Components

1. **Event Normalization** (`core/event.go`): All log types are normalized to a unified `core.Event` structure with fields like timestamp, source, event_type, user, host, message.

2. **Parser System** (`parsers/`): Modular interface-based parsers. Each parser implements:
   - `Parse(filePath string) ([]*core.Event, error)`
   - `CanParse(filePath string) bool`

   Current parsers include: EVTX, JSON, Linux syslog, Windows logs, web logs, IIS, PowerShell, Zeek, macOS logs, cloud platform logs (AWS/Azure/GCP), browser history, CSV artifacts, XML formats, firewall logs, and generic log files.

3. **Output System** (`output/`): Writers implementing a common interface for CSV, JSONL, and SQLite formats. All writers implement:
   - `Write(events []*core.Event) error`
   - `Close() error`

4. **Concurrent Processing** (`internal/processor/`): Worker pool pattern using goroutines with context-based cancellation and atomic progress tracking.

5. **GUI** (`app_wails.go` + `frontend/`): Wails v2 desktop application with React + Tailwind CSS frontend.

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

## Important Considerations

- **GO111MODULE**: Must be set to "on" when building in a GOPATH directory
- **GOPATH**: Should be set to user's go directory, not the project directory
- **CGO Dependency**: SQLite features require CGO
- **Thread Safety**: Use mutexes for shared resources and atomic operations for counters
- **Error Handling**: Always wrap errors with context using `fmt.Errorf()`
- **Resource Cleanup**: Always defer Close() for files, database connections, and writers
- **Progress Updates**: Use atomic operations for concurrent progress tracking
