# LogZero

LogZero is a high-performance, modular timeline generator for processing logs and artifacts into normalized, structured event timelines. It's designed for DFIR (Digital Forensics and Incident Response) analysts.

## Features

- **High Performance**: Uses goroutines for parallel file processing
- **Modern GUI**: Wails-based desktop application with React frontend
- **Comprehensive Parser Support**:
  - Windows: Event Logs (.evtx), Firewall, Text Logs, Prefetch, Scheduled Tasks
  - Linux/Unix: Syslog, iptables/UFW logs
  - macOS: Unified Log, Install Log, ASL
  - Web Servers: Apache/Nginx, IIS W3C Extended
  - Network Security: Zeek/Bro, Cisco ASA
  - Cloud Platforms: AWS CloudTrail, Azure Activity, GCP Audit
  - PowerShell: Transcripts, Script Block logs
  - Browser Forensics: Chrome/Edge, Firefox, Safari history
  - Artifacts: CSV exports (MFTECmd, Plaso, KAPE), Sysmon XML, JSON/JSONL
- **Multiple Output Formats**: CSV, JSONL, SQLite
- **Normalized Event Structure**: Consistent structure across all log types
- **Multi-file Selection**: Select and process multiple files at once
- **Real-time Progress**: Live progress updates during processing
- **Offline Operation**: Fully functional without network connectivity

## Installation

### Prerequisites

- **Go 1.22+**: [golang.org](https://golang.org/dl/)
- **Node.js 18+**: [nodejs.org](https://nodejs.org/)
- **Wails CLI**: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **C Compiler**: Required for SQLite support (MinGW on Windows, Xcode on macOS, gcc on Linux)

### Building

```bash
# Clone the repository
git clone https://github.com/yourusername/LogZero.git
cd LogZero

# Set environment (if building in GOPATH)
# Windows PowerShell:
$env:GO111MODULE="on"
$env:GOPATH="$env:USERPROFILE\go"

# macOS/Linux:
export GO111MODULE=on

# Build the application
wails build

# The executable will be in build/bin/
```

### Running

```bash
# GUI Mode (default)
./build/bin/logzero.exe

# CLI Mode - process files directly
./build/bin/logzero.exe --input /path/to/logs --output /path/to/output --format jsonl

# API Server Mode - headless operation
./build/bin/logzero.exe --api-only --port 8765
```

## Usage

1. Launch LogZero
2. Click "Select Files" to choose log files to process
3. Click "Add More Files" to add additional files
4. Select an output directory
5. Choose output format (JSONL, CSV, or SQLite)
6. Click "Start Processing"

## Architecture

```
LogZero/
├── main.go              # Application entry point
├── app_wails.go         # Wails GUI bindings
├── core/                # Core event structures
├── parsers/             # Input parsers (evtx, json, log, etc.)
├── output/              # Output writers (csv, jsonl, sqlite)
├── api/                 # HTTP API server
├── app/                 # Application configuration
├── internal/            # Internal utilities
│   ├── processor/       # File processing engine
│   ├── logger/          # Logging utilities
│   ├── logrotate/       # Log rotation
│   ├── retry/           # Retry logic
│   └── securestorage/   # Connection info storage
└── frontend/            # React + Tailwind frontend
    └── src/
        └── App.jsx      # Main UI component
```

## Event Structure

All events are normalized to a consistent structure:

```json
{
  "timestamp": "2024-04-21T03:21:00Z",
  "source": "Security.evtx",
  "event_type": "Logon",
  "event_id": 4624,
  "user": "jdoe",
  "host": "WIN-MACHINE",
  "message": "Successful login",
  "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
}
```

## API Endpoints (Headless Mode)

- `POST /api/config`: Set configuration options
- `POST /api/start`: Start processing
- `POST /api/stop`: Stop processing
- `GET /api/status`: Get current status
- `GET /api/progress`: SSE endpoint for real-time progress
- `POST /api/shutdown`: Graceful shutdown

## License

MIT License
