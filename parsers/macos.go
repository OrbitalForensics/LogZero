package parsers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"LogZero/core"
)

// Pre-compiled regex patterns for macOS log formats
var (
	// Unified Log format: 2023-04-21 15:30:45.123456-0700  localhost kernel[0]: (AppleUSBHostController) message
	// Format: timestamp  hostname  process[pid]: (subsystem) message
	// The timestamp can have microseconds and timezone offset
	unifiedLogPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)\s+(\S+)\s+([^\[]+)\[(\d+)\]:\s+(?:\(([^)]+)\)\s+)?(.*)$`)

	// Unified Log without subsystem: 2023-04-21 15:30:45.123456-0700  localhost kernel[0]: message
	unifiedLogNoSubsystemPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)\s+(\S+)\s+([^\[]+)\[(\d+)\]:\s+(.*)$`)

	// Install.log format: 2023-04-21 15:30:45-07 localhost softwareupdate[1234]: message
	// Similar to unified but with different timezone format (hyphen separator)
	installLogPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})([+-]\d{2})\s+(\S+)\s+([^\[]+)\[(\d+)\]:\s+(.*)$`)

	// ASL format: Apr 21 15:30:45 hostname process[1234] <Notice>: Message text here
	aslPattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[]+)\[(\d+)\]\s+<([^>]+)>:\s+(.*)$`)

	// ASL format without PID: Apr 21 15:30:45 hostname process <Notice>: Message
	aslNoPIDPattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+<([^>]+)>:\s+(.*)$`)
)

// MacOSUnifiedLogParser implements the Parser interface for macOS Unified Logs
// These are typically exported using the `log show` command
type MacOSUnifiedLogParser struct{}

// CanParse checks if this parser can handle the given file
func (p *MacOSUnifiedLogParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))

	// Check for common unified log export filenames
	if strings.Contains(baseName, "unified") ||
		strings.Contains(baseName, "logshow") ||
		strings.Contains(baseName, "log_show") ||
		strings.HasPrefix(baseName, "system_logs") {
		return true
	}

	// Check file content for unified log format signature
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Check first 10 lines for unified log pattern
	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := scanner.Text()
		if unifiedLogPattern.MatchString(line) || unifiedLogNoSubsystemPattern.MatchString(line) {
			return true
		}
	}

	return false
}

// Parse parses a macOS Unified Log file and returns a slice of events
func (p *MacOSUnifiedLogParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	lineNum := 0
	source := filepath.Base(filePath)
	parsedCount := 0
	rawCount := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event *core.Event

		// Try unified log pattern with subsystem first
		if matches := unifiedLogPattern.FindStringSubmatch(line); matches != nil {
			timestamp := parseUnifiedTimestamp(matches[1])
			host := matches[2]
			process := strings.TrimSpace(matches[3])
			pid, _ := strconv.Atoi(matches[4])
			subsystem := matches[5]
			message := matches[6]

			// Build message with subsystem if present
			var fullMessage string
			if subsystem != "" {
				fullMessage = fmt.Sprintf("[%s(%d)] (%s) %s", process, pid, subsystem, message)
			} else {
				fullMessage = fmt.Sprintf("[%s(%d)] %s", process, pid, message)
			}

			event = core.NewEvent(
				timestamp,
				source,
				"UnifiedLog",
				lineNum,
				"", // User
				host,
				fullMessage,
				filePath,
			)
			parsedCount++
		} else if matches := unifiedLogNoSubsystemPattern.FindStringSubmatch(line); matches != nil {
			// Try unified log pattern without subsystem
			timestamp := parseUnifiedTimestamp(matches[1])
			host := matches[2]
			process := strings.TrimSpace(matches[3])
			pid, _ := strconv.Atoi(matches[4])
			message := matches[5]

			event = core.NewEvent(
				timestamp,
				source,
				"UnifiedLog",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s(%d)] %s", process, pid, message),
				filePath,
			)
			parsedCount++
		} else {
			// Fallback to raw event
			event = core.NewEvent(
				time.Now().UTC(),
				source,
				"UnifiedLogRaw",
				lineNum,
				"",
				"",
				line,
				filePath,
			)
			rawCount++
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed macOS Unified Log: %s (parsed: %d, raw: %d, total: %d events)\n",
		filePath, parsedCount, rawCount, len(events))
	return events, nil
}

// MacOSInstallLogParser implements the Parser interface for macOS install.log files
type MacOSInstallLogParser struct{}

// CanParse checks if this parser can handle the given file
func (p *MacOSInstallLogParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return baseName == "install.log" ||
		strings.HasPrefix(baseName, "install.log.") ||
		strings.Contains(baseName, "installer.log")
}

// Parse parses a macOS install.log file and returns a slice of events
func (p *MacOSInstallLogParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	lineNum := 0
	source := filepath.Base(filePath)
	parsedCount := 0
	rawCount := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event *core.Event

		// Try install.log pattern: 2023-04-21 15:30:45-07 localhost softwareupdate[1234]: message
		if matches := installLogPattern.FindStringSubmatch(line); matches != nil {
			// Parse timestamp with short timezone format
			timeStr := matches[1]
			tzOffset := matches[2] + "00" // Convert -07 to -0700
			timestamp := parseInstallLogTimestamp(timeStr, tzOffset)

			host := matches[3]
			process := strings.TrimSpace(matches[4])
			pid, _ := strconv.Atoi(matches[5])
			message := matches[6]

			event = core.NewEvent(
				timestamp,
				source,
				"InstallLog",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s(%d)] %s", process, pid, message),
				filePath,
			)
			parsedCount++
		} else if matches := unifiedLogNoSubsystemPattern.FindStringSubmatch(line); matches != nil {
			// Fallback to unified log pattern (some install logs may use this format)
			timestamp := parseUnifiedTimestamp(matches[1])
			host := matches[2]
			process := strings.TrimSpace(matches[3])
			pid, _ := strconv.Atoi(matches[4])
			message := matches[5]

			event = core.NewEvent(
				timestamp,
				source,
				"InstallLog",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s(%d)] %s", process, pid, message),
				filePath,
			)
			parsedCount++
		} else {
			// Fallback to raw event
			event = core.NewEvent(
				time.Now().UTC(),
				source,
				"InstallLogRaw",
				lineNum,
				"",
				"",
				line,
				filePath,
			)
			rawCount++
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed macOS Install Log: %s (parsed: %d, raw: %d, total: %d events)\n",
		filePath, parsedCount, rawCount, len(events))
	return events, nil
}

// MacOSASLParser implements the Parser interface for Apple System Log (legacy ASL) files
type MacOSASLParser struct{}

// CanParse checks if this parser can handle the given file
func (p *MacOSASLParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))

	// Check for common ASL/system log filenames
	if baseName == "system.log" ||
		strings.HasPrefix(baseName, "system.log.") ||
		strings.Contains(baseName, "asl") ||
		baseName == "secure.log" ||
		strings.HasPrefix(baseName, "secure.log.") {
		return true
	}

	// Check file content for ASL format signature
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Check first 10 lines for ASL pattern
	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := scanner.Text()
		if aslPattern.MatchString(line) || aslNoPIDPattern.MatchString(line) {
			return true
		}
	}

	return false
}

// Parse parses a macOS ASL file and returns a slice of events
func (p *MacOSASLParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	lineNum := 0
	source := filepath.Base(filePath)
	now := time.Now()
	currentYear := now.Year()
	currentMonth := now.Month()
	parsedCount := 0
	rawCount := 0

	// Track the last timestamp to detect year boundary crossings
	var lastTimestamp time.Time

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event *core.Event

		// Try ASL pattern with PID: Apr 21 15:30:45 hostname process[1234] <Notice>: message
		if matches := aslPattern.FindStringSubmatch(line); matches != nil {
			timestamp := parseASLTimestamp(matches[1], currentYear, currentMonth, now, &lastTimestamp)
			host := matches[2]
			process := strings.TrimSpace(matches[3])
			pid, _ := strconv.Atoi(matches[4])
			level := matches[5]
			message := matches[6]

			event = core.NewEvent(
				timestamp,
				source,
				"ASL",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s(%d)] <%s> %s", process, pid, level, message),
				filePath,
			)
			parsedCount++
		} else if matches := aslNoPIDPattern.FindStringSubmatch(line); matches != nil {
			// Try ASL pattern without PID
			timestamp := parseASLTimestamp(matches[1], currentYear, currentMonth, now, &lastTimestamp)
			host := matches[2]
			process := strings.TrimSpace(matches[3])
			level := matches[4]
			message := matches[5]

			event = core.NewEvent(
				timestamp,
				source,
				"ASL",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s] <%s> %s", process, level, message),
				filePath,
			)
			parsedCount++
		} else {
			// Fallback to raw event
			event = core.NewEvent(
				time.Now().UTC(),
				source,
				"ASLRaw",
				lineNum,
				"",
				"",
				line,
				filePath,
			)
			rawCount++
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed macOS ASL: %s (parsed: %d, raw: %d, total: %d events)\n",
		filePath, parsedCount, rawCount, len(events))
	return events, nil
}

// parseUnifiedTimestamp parses timestamps from macOS Unified Logs
// Handles formats like: 2023-04-21 15:30:45.123456-0700
func parseUnifiedTimestamp(timeStr string) time.Time {
	// Try various formats from most specific to least specific
	formats := []string{
		"2006-01-02 15:04:05.999999-0700", // Full format with microseconds and timezone
		"2006-01-02 15:04:05.999999",       // With microseconds, no timezone
		"2006-01-02 15:04:05-0700",         // No microseconds, with timezone
		"2006-01-02 15:04:05",              // Basic format
	}

	for _, format := range formats {
		if timestamp, err := time.Parse(format, timeStr); err == nil {
			return timestamp
		}
	}

	// Fallback to current time
	return time.Now().UTC()
}

// parseInstallLogTimestamp parses timestamps from macOS install.log
// Handles format: 2023-04-21 15:30:45 with separate timezone like -0700
func parseInstallLogTimestamp(timeStr, tzOffset string) time.Time {
	fullTimeStr := timeStr + tzOffset
	formats := []string{
		"2006-01-02 15:04:05-0700",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if timestamp, err := time.Parse(format, fullTimeStr); err == nil {
			return timestamp
		}
	}

	// Try without timezone
	if timestamp, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
		return timestamp
	}

	return time.Now().UTC()
}

// parseASLTimestamp parses timestamps from ASL format (without year)
// Handles format: Apr 21 15:30:45
func parseASLTimestamp(timeStr string, currentYear int, currentMonth time.Month, now time.Time, lastTimestamp *time.Time) time.Time {
	// Parse: Apr 21 15:30:45
	fullTimeStr := fmt.Sprintf("%d %s", currentYear, timeStr)
	timestamp, err := time.Parse("2006 Jan  2 15:04:05", fullTimeStr)
	if err != nil {
		// Try alternate format with single-digit day
		timestamp, err = time.Parse("2006 Jan 2 15:04:05", fullTimeStr)
	}
	if err != nil {
		return time.Now().UTC()
	}

	// Year boundary detection (same logic as Linux syslog parser):
	// 1. If current month is Jan/Feb and log month is Nov/Dec, use previous year
	// 2. If this timestamp is more than 6 months in the future, use previous year
	logMonth := timestamp.Month()

	if currentMonth <= time.February && logMonth >= time.November {
		// We're in early year but log is from late year - must be previous year
		timestamp = timestamp.AddDate(-1, 0, 0)
	} else if timestamp.After(now.AddDate(0, 6, 0)) {
		// Timestamp is more than 6 months in the future - must be previous year
		timestamp = timestamp.AddDate(-1, 0, 0)
	}

	// Additional check: if timestamps go backwards significantly (>30 days),
	// we might have crossed a year boundary incorrectly
	if lastTimestamp != nil && !lastTimestamp.IsZero() && timestamp.Before(lastTimestamp.AddDate(0, 0, -30)) {
		// Large backwards jump - likely year boundary issue
		// Re-evaluate: if adding a year makes it closer to last timestamp, do that
		timestampPlusYear := timestamp.AddDate(1, 0, 0)
		if timestampPlusYear.Sub(*lastTimestamp).Abs() < timestamp.Sub(*lastTimestamp).Abs() {
			timestamp = timestampPlusYear
		}
	}

	*lastTimestamp = timestamp
	return timestamp
}
