package parsers

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"LogZero/core"
)

// fileHeaderCache caches file headers to avoid repeated I/O during parser detection
type fileHeaderCache struct {
	mu      sync.Mutex
	headers map[string][]string // file path -> first N lines
}

var headerCache = &fileHeaderCache{
	headers: make(map[string][]string),
}

// maxHeaderLines is the number of lines to read for parser detection
const maxHeaderLines = 50

// getFileHeader returns the first N lines of a file, using cache if available
func getFileHeader(filePath string) ([]string, error) {
	headerCache.mu.Lock()
	defer headerCache.mu.Unlock()

	// Check cache first
	if lines, ok := headerCache.headers[filePath]; ok {
		return lines, nil
	}

	// Read file header
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Use reasonable buffer for header scanning
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	var lines []string
	for i := 0; i < maxHeaderLines && scanner.Scan(); i++ {
		lines = append(lines, truncateLine(scanner.Text()))
	}

	// Cache the result
	headerCache.headers[filePath] = lines

	return lines, nil
}

// clearFileHeaderCache clears the header cache (call after parsing is complete)
func clearFileHeaderCache() {
	headerCache.mu.Lock()
	defer headerCache.mu.Unlock()
	headerCache.headers = make(map[string][]string)
}

// Common errors
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrParsingFailed     = errors.New("failed to parse file")
)

// MaxLineLength is the maximum line length to process with regex patterns
// Lines exceeding this length are truncated before regex matching to prevent ReDoS
const MaxLineLength = 65536 // 64KB

// truncateLine truncates a line to MaxLineLength to prevent ReDoS attacks
func truncateLine(line string) string {
	if len(line) > MaxLineLength {
		return line[:MaxLineLength]
	}
	return line
}

// estimateLineCapacity estimates the number of lines in a file based on size
// Uses avgBytesPerLine as the expected average line length
// Returns a minimum of 100 to avoid very small allocations
func estimateLineCapacity(filePath string, avgBytesPerLine int64) int {
	info, err := os.Stat(filePath)
	if err != nil {
		return 100 // Default minimum capacity
	}
	if avgBytesPerLine <= 0 {
		avgBytesPerLine = 100 // Default bytes per line
	}
	estimated := int(info.Size() / avgBytesPerLine)
	if estimated < 100 {
		return 100
	}
	// Cap at 1 million to prevent excessive allocation for huge files
	if estimated > 1000000 {
		return 1000000
	}
	return estimated
}

// Parser defines the interface for all file parsers
type Parser interface {
	// Parse parses a file and returns a slice of events
	Parse(filePath string) ([]*core.Event, error)

	// CanParse checks if this parser can handle the given file
	CanParse(filePath string) bool
}

// GetParserForFile returns the appropriate parser for the given file
func GetParserForFile(filePath string) (Parser, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".evtx":
		return &EvtxParser{}, nil
	case ".pf": // Prefetch
		return &PrefetchParser{}, nil
	}

	// Check for XML-based logs and artifacts (before other specific parsers)
	if ext == ".xml" {
		// Windows Event XML (from wevtutil or Get-WinEvent -AsXML)
		windowsXMLParser := &WindowsXMLEventParser{}
		if windowsXMLParser.CanParse(filePath) {
			return windowsXMLParser, nil
		}

		// Scheduled Task XML
		scheduledTaskParser := &ScheduledTaskXMLParser{}
		if scheduledTaskParser.CanParse(filePath) {
			return scheduledTaskParser, nil
		}

		// Sysmon Configuration or Events XML
		sysmonParser := &SysmonXMLParser{}
		if sysmonParser.CanParse(filePath) {
			return sysmonParser, nil
		}

		// Fall back to generic XML parser
		return &GenericXMLParser{}, nil
	}

	// Check for cloud platform logs (before generic JSON parser)
	// These have specific JSON structures that need specialized parsing
	if ext == ".json" || ext == ".jsonl" {
		// AWS CloudTrail
		cloudTrailParser := &CloudTrailParser{}
		if cloudTrailParser.CanParse(filePath) {
			return cloudTrailParser, nil
		}

		// Azure Activity Log
		azureParser := &AzureActivityParser{}
		if azureParser.CanParse(filePath) {
			return azureParser, nil
		}

		// GCP Cloud Audit Log
		gcpParser := &GCPAuditParser{}
		if gcpParser.CanParse(filePath) {
			return gcpParser, nil
		}

		// Fall back to generic JSON parser for other JSON files
		if ext == ".json" {
			return &JsonParser{}, nil
		}
	}

	// Check for browser history databases (SQLite)
	// Must be before other checks as these files may have no extension
	browserHistoryParser := &BrowserHistoryParser{}
	if browserHistoryParser.CanParse(filePath) {
		return browserHistoryParser, nil
	}

	// Check for specific file patterns
	baseName := strings.ToLower(filepath.Base(filePath))
	if strings.Contains(baseName, "shellbag") {
		return &ShellbagsParser{}, nil
	}

	// Check for rotated logs (e.g., app.log.1)
	if strings.Contains(baseName, ".log.") {
		return &LogParser{}, nil
	}

	// Check for PowerShell Transcript files
	psTranscriptParser := &PowerShellTranscriptParser{}
	if psTranscriptParser.CanParse(filePath) {
		return psTranscriptParser, nil
	}

	// Check for PowerShell Script Block logs
	psScriptBlockParser := &PowerShellScriptBlockParser{}
	if psScriptBlockParser.CanParse(filePath) {
		return psScriptBlockParser, nil
	}

	// Check for macOS Install Log (before unified log due to more specific filename)
	macInstallParser := &MacOSInstallLogParser{}
	if macInstallParser.CanParse(filePath) {
		return macInstallParser, nil
	}

	// Check for macOS ASL (Apple System Log) - legacy format
	macASLParser := &MacOSASLParser{}
	if macASLParser.CanParse(filePath) {
		return macASLParser, nil
	}

	// Check for macOS Unified Log (from `log show` command)
	macUnifiedParser := &MacOSUnifiedLogParser{}
	if macUnifiedParser.CanParse(filePath) {
		return macUnifiedParser, nil
	}

	// Check for IIS Logs (must be before generic Web Access Logs)
	iisParser := &IISParser{}
	if iisParser.CanParse(filePath) {
		return iisParser, nil
	}

	// Check for Zeek (Bro) Network Logs
	zeekParser := &ZeekParser{}
	if zeekParser.CanParse(filePath) {
		return zeekParser, nil
	}

	// Check for Web Access Logs
	webParser := &WebAccessParser{}
	if webParser.CanParse(filePath) {
		return webParser, nil
	}

	// Check for Linux Syslog
	syslogParser := &LinuxSyslogParser{}
	if syslogParser.CanParse(filePath) {
		return syslogParser, nil
	}

	// Check for Windows Text Logs
	winTextParser := &WindowsTextParser{}
	if winTextParser.CanParse(filePath) {
		return winTextParser, nil
	}

	// Check for Windows Firewall logs
	winFirewallParser := &WindowsFirewallParser{}
	if winFirewallParser.CanParse(filePath) {
		return winFirewallParser, nil
	}

	// Check for iptables/UFW logs
	iptablesParser := &IptablesParser{}
	if iptablesParser.CanParse(filePath) {
		return iptablesParser, nil
	}

	// Check for Cisco ASA logs
	ciscoASAParser := &CiscoASAParser{}
	if ciscoASAParser.CanParse(filePath) {
		return ciscoASAParser, nil
	}

	// Check for CSV artifact files (low priority - check after specific parsers)
	csvParser := &CSVArtifactParser{}
	if csvParser.CanParse(filePath) {
		return csvParser, nil
	}

	// Fallback: If it has no extension or an unknown extension, treat it as a log file
	// This ensures "any type of log file" can be entered as requested
	return &LogParser{}, nil
}
