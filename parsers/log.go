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

// LogParser implements the Parser interface for plaintext log files
type LogParser struct{}

// Common timestamp patterns in logs
var timestampPatterns = []*regexp.Regexp{
	// ISO8601 / RFC3339
	regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))`),
	// Common log format: 2023-04-21 15:30:45
	regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`),
	// Apache/Nginx format: 21/Apr/2023:15:30:45 +0000
	regexp.MustCompile(`(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})`),
	// Windows format: 4/21/2023 3:30:45 PM
	regexp.MustCompile(`(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))`),
}

// Timestamp format strings corresponding to the patterns above
var timestampFormats = []string{
	time.RFC3339,
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"1/2/2006 3:04:05 PM",
}

// CanParse checks if this parser can handle the given file
func (p *LogParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".log" || ext == ".txt" || ext == ".out" || ext == ".err" ||
		ext == ".audit" || ext == ".trace" || strings.Contains(filepath.Base(filePath), ".log.")
}

// Parse parses a log file and returns a slice of events
func (p *LogParser) Parse(filePath string) ([]*core.Event, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	lineNum := 0

	// Extract the source name from the file path
	source := filepath.Base(filePath)

	// Process each line
	var detectedPatternIndex = -1

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		var timestamp time.Time
		var timeStr string

		// If we haven't detected the format yet, try all patterns
		if detectedPatternIndex == -1 {
			timestamp, timeStr, detectedPatternIndex = extractTimestampWithDetection(line)
		} else {
			// Use the detected pattern
			timestamp, timeStr = extractTimestampWithPattern(line, detectedPatternIndex)
		}

		if timestamp.IsZero() {
			// Don't use time.Now() as fallback - affects forensic timeline accuracy
			// Leave timestamp as zero to indicate unparseable timestamp
		}

		// Extract the message (remove the timestamp part if found)
		message := line
		if timeStr != "" {
			message = strings.Replace(line, timeStr, "", 1)
			message = strings.TrimSpace(message)
		}

		// Create a new event
		event := core.NewEvent(
			timestamp,
			source,
			"LogEntry",
			lineNum, // Use line number as event ID
			"",      // User is unknown
			"",      // Host is unknown
			message,
			filePath,
		)

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed log file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// extractTimestampWithDetection tries to extract a timestamp and returns the detected pattern index
func extractTimestampWithDetection(line string) (time.Time, string, int) {
	for i, pattern := range timestampPatterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			timeStr := matches[1]
			timestamp, err := time.Parse(timestampFormats[i], timeStr)
			if err == nil {
				return timestamp.UTC(), timeStr, i
			}
		}
	}

	return time.Time{}, "", -1
}

// extractTimestampWithPattern extracts a timestamp using a specific pattern index
func extractTimestampWithPattern(line string, patternIndex int) (time.Time, string) {
	if patternIndex < 0 || patternIndex >= len(timestampPatterns) {
		return time.Time{}, ""
	}

	pattern := timestampPatterns[patternIndex]
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		timeStr := matches[1]
		timestamp, err := time.Parse(timestampFormats[patternIndex], timeStr)
		if err == nil {
			return timestamp.UTC(), timeStr
		}
	}

	return time.Time{}, ""
}
