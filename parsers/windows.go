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

// WindowsTextParser implements the Parser interface for text-based Windows logs
type WindowsTextParser struct{}

// Common regex patterns for Windows Text Logs
var (
	// CBS/WindowsUpdate format: 2023-01-01 12:00:00 Info ...
	// Matches: Date Time Type ...
	winTextPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+(\S+)\s+(.*)$`)

	// Alternative format (sometimes seen in older logs or different locales)
	// 2023/01/01 12:00:00
	winTextPattern2 = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)
)

// CanParse checks if this parser can handle the given file
func (p *WindowsTextParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return baseName == "cbs.log" ||
		strings.Contains(baseName, "windowsupdate") ||
		strings.Contains(baseName, "setupapi") ||
		strings.Contains(baseName, "dism")
}

// Parse parses a Windows text log file and returns a slice of events
func (p *WindowsTextParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	// Pre-allocate slice with estimated capacity (avg 150 bytes per Windows log line)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 150))
	lineNum := 0
	source := filepath.Base(filePath)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Truncate line before regex matching to prevent ReDoS
		lineForRegex := truncateLine(line)

		var event *core.Event

		// Try standard format (Comma separator likely in CBS)
		// CBS.log example: 2023-04-21 15:30:45, Info                  Cbs    Starting TrustedInstaller...
		matches := winTextPattern.FindStringSubmatch(lineForRegex)

		if matches == nil {
			// Try space separated
			// WindowsUpdate.log might be different depending on version
			matches = winTextPattern2.FindStringSubmatch(lineForRegex)
		}

		if matches != nil {
			timeStr := matches[1]
			logType := matches[2]
			msg := matches[3]

			// Try parsing time with both separators
			timestamp, err := time.Parse("2006-01-02 15:04:05", timeStr)
			if err != nil {
				timestamp, err = time.Parse("2006/01/02 15:04:05", timeStr)
				if err != nil {
					timestamp = time.Now().UTC()
				}
			}

			event = core.NewEvent(
				timestamp,
				source,
				"WindowsLog",
				lineNum,
				"", // User often not in these logs
				"", // Host implicit
				fmt.Sprintf("[%s] %s", logType, msg),
				filePath,
			)
		} else {
			// Fallback
			event = core.NewEvent(
				time.Now().UTC(),
				source,
				"WindowsLogRaw",
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

	fmt.Printf("Parsed Windows Log file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}
