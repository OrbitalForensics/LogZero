package parsers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"LogZero/core"
)

// LinuxSyslogParser implements the Parser interface for Linux Syslog files
type LinuxSyslogParser struct{}

// Common regex patterns for Syslog
var (
	// RFC 3164: Jan 01 12:00:00 hostname app[123]: message
	// Note: Year is missing in RFC 3164, so we'll have to guess or assume current year
	rfc3164Pattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$`)

	// RFC 5424: 2023-01-01T12:00:00Z hostname app[123]: message (simplified)
	rfc5424Pattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(\S+)\s+([^:]+):\s+(.*)$`)
)

// CanParse checks if this parser can handle the given file
func (p *LinuxSyslogParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	// Common syslog filenames
	if baseName == "syslog" || baseName == "auth.log" || baseName == "kern.log" || baseName == "messages" || baseName == "user.log" {
		return true
	}
	// Check for rotated logs like syslog.1, auth.log.1.gz (if we supported gz)
	if strings.Contains(baseName, "syslog.") || strings.Contains(baseName, "auth.log.") || strings.Contains(baseName, "kern.log.") {
		return true
	}
	return false
}

// Parse parses a syslog file and returns a slice of events
func (p *LinuxSyslogParser) Parse(filePath string) ([]*core.Event, error) {
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

	// Track the last timestamp to detect year boundary crossings
	var lastTimestamp time.Time

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event *core.Event

		// Try RFC 5424 first (ISO timestamp)
		if matches := rfc5424Pattern.FindStringSubmatch(line); matches != nil {
			timestamp, err := time.Parse(time.RFC3339, matches[1])
			if err != nil {
				timestamp = time.Now().UTC()
			}
			host := matches[2]
			proc := matches[3]
			msg := matches[4]

			lastTimestamp = timestamp
			event = core.NewEvent(
				timestamp,
				source,
				"Syslog",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s] %s", proc, msg),
				filePath,
			)
		} else if matches := rfc3164Pattern.FindStringSubmatch(line); matches != nil {
			// RFC 3164 (No year)
			// Parse: Jan 01 12:00:00
			// Handle year boundary: if we're in Jan and see Dec dates, use previous year
			// Similarly, if log month is ahead of current month, it's likely from previous year
			timeStr := fmt.Sprintf("%d %s", currentYear, matches[1])
			timestamp, err := time.Parse("2006 Jan  2 15:04:05", timeStr)
			if err != nil {
				// Try alternate format with single-digit day
				timestamp, err = time.Parse("2006 Jan 2 15:04:05", timeStr)
			}
			if err != nil {
				timestamp = time.Now().UTC()
			} else {
				// Year boundary detection:
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
				if !lastTimestamp.IsZero() && timestamp.Before(lastTimestamp.AddDate(0, 0, -30)) {
					// Large backwards jump - likely year boundary issue
					// Re-evaluate: if adding a year makes it closer to last timestamp, do that
					timestampPlusYear := timestamp.AddDate(1, 0, 0)
					if timestampPlusYear.Sub(lastTimestamp).Abs() < timestamp.Sub(lastTimestamp).Abs() {
						timestamp = timestampPlusYear
					}
				}
			}

			lastTimestamp = timestamp
			host := matches[2]
			proc := matches[3]
			msg := matches[4]

			event = core.NewEvent(
				timestamp,
				source,
				"Syslog",
				lineNum,
				"", // User
				host,
				fmt.Sprintf("[%s] %s", proc, msg),
				filePath,
			)
		} else {
			// Fallback to simple line
			event = core.NewEvent(
				time.Now().UTC(),
				source,
				"SyslogRaw",
				lineNum,
				"",
				"",
				line,
				filePath,
			)
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed Syslog file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}
