# LogZero

LogZero is a high-performance, modular timeline generator for processing logs and artifacts into normalized, structured event timelines. It's designed to be blazingly fast, modular, and ready for field use by analysts.

## Features

- **Point-and-Click GUI** - Just run the application, no command-line flags required
- **High Performance** - Processes ~800,000 events per second
- **15+ Log Format Support** - Automatically detects and parses multiple log types
- **Multiple Output Formats** - JSONL, CSV, and SQLite with proper indexing
- **Normalized Events** - All logs are converted to a consistent structure
- **Chronological Sorting** - Events are sorted by timestamp
- **Cross-Platform** - Windows, macOS, and Linux support
- **Offline Operation** - Fully functional without network connectivity

## Supported Log Formats

| Category | Formats |
|----------|---------|
| **Linux** | Syslog (RFC 3164, RFC 5424), auth.log, messages |
| **Windows** | EVTX, CBS.log, WindowsUpdate.log, PowerShell Transcripts |
| **Web Servers** | Apache/Nginx Access Logs, IIS (W3C Extended) |
| **Network** | Zeek/Bro (conn, dns, http, ssl, files logs) |
| **Firewall** | Windows Firewall, iptables/UFW, Cisco ASA |
| **Cloud** | AWS CloudTrail, Azure Activity Log, GCP Cloud Audit |
| **macOS** | Unified Log, Install.log, Apple System Log (ASL) |
| **Generic** | JSON/JSONL arrays, timestamped text logs |

## Quick Start

### Download & Run

1. Download the latest release for your platform
2. Run `logzero.exe` (Windows) or `logzero` (macOS/Linux)
3. Use the GUI to select input files/folders and generate timelines

**That's it!** No command-line flags required for basic usage.

### CLI Usage (Optional)

```bash
# Process a directory of logs
./logzero --input /path/to/logs --output timeline.jsonl --format jsonl

# Process a single file
./logzero --input auth.log --output timeline.csv --format csv

# Output to SQLite database
./logzero --input logs/ --output timeline.db --format sqlite
```

### API Server Mode

```bash
./logzero --api-only --port 8765
```

## Building from Source

### Prerequisites

- Go 1.21+
- Node.js 18+
- C Compiler (for SQLite support)
  - Windows: MinGW-w64 or TDM-GCC
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: GCC (`sudo apt install gcc`)

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/LogZero.git
cd LogZero

# Install Wails CLI (if not already installed)
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Build the application
wails build

# The executable will be at build/bin/logzero.exe (Windows) or build/bin/logzero (macOS/Linux)
```

### Development Mode

```bash
# Run with hot reload
wails dev
```

## Usage

### GUI Mode (Default)

1. Launch the application (double-click or run from terminal)
2. Select an input file or directory
3. Choose an output format and location
4. Click "Process" to start
5. View real-time progress and results

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input` | Input file or directory | (none) |
| `--output` | Output file path | (none) |
| `--format` | Output format: `jsonl`, `csv`, `sqlite` | `jsonl` |
| `--api-only` | Run in API server mode (no GUI) | `false` |
| `--port` | API server port | `8765` |

## Architecture

```
LogZero/
├── api/          # HTTP API server
├── app/          # Application logic
├── core/         # Event structures and interfaces
├── frontend/     # React-based GUI (Wails)
├── internal/     # Internal utilities
├── output/       # Output writers (CSV, JSONL, SQLite)
├── parsers/      # Log format parsers
└── main.go       # Entry point
```

### Operational Modes

1. **GUI Mode (Default)** - Wails-based desktop application with React frontend
2. **CLI Mode** - Direct processing with `--input` and `--output` flags
3. **API Mode** - Headless server with REST API and SSE progress updates

## Event Structure

All events are normalized to a consistent structure:

```json
{
  "timestamp": "2025-01-18T10:30:00Z",
  "source": "auth.log",
  "event_type": "Syslog",
  "event_id": 1,
  "user": "admin",
  "host": "webserver01",
  "message": "Accepted publickey for admin from 192.168.1.50 port 54321",
  "path": "/var/log/auth.log"
}
```

## Performance

Benchmarked with 888,008 events across 38 files of mixed formats:

| Metric | Value |
|--------|-------|
| **Throughput** | ~800,000 events/sec |
| **Processing Time** | 1.1 seconds |
| **Memory** | Streaming (low footprint) |

Individual parser performance (100,000 events each):

| Parser | Events/sec |
|--------|------------|
| Generic Log | 717,000 |
| Web Access | 505,000 |
| Windows Firewall | 413,000 |
| IIS | 373,000 |
| Zeek | 313,000 |
| JSON | 299,000 |
| CloudTrail | 208,000 |

## API Endpoints

When running in API mode (`--api-only`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config` | POST | Set configuration |
| `/api/start` | POST | Start processing |
| `/api/stop` | POST | Stop processing |
| `/api/status` | GET | Get current status |
| `/api/progress` | GET | SSE progress stream |
| `/api/shutdown` | POST | Graceful shutdown |

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT License - See [LICENSE](LICENSE) for details.
