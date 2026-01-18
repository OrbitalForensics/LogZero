package parsers

import (
	"errors"
	"path/filepath"
	"strings"

	"LogZero/core"
)

// Common errors
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrParsingFailed     = errors.New("failed to parse file")
)

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
