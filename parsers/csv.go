package parsers

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"LogZero/core"
)

// CSVArtifactParser implements the Parser interface for CSV files from DFIR tools
type CSVArtifactParser struct{}

// Known timestamp column names (case-insensitive matching)
var csvTimestampColumns = []string{
	// Generic timestamp columns
	"timestamp", "datetime", "time", "date", "eventtime", "event_time",
	"start_time", "end_time", "starttime", "endtime",
	// MFTECmd columns
	"created0x10", "modified0x10", "lastrecordchange0x10", "lastaccess0x10",
	"created0x30", "modified0x30", "lastrecordchange0x30", "lastaccess0x30",
	"created", "modified", "lastaccess", "lastmodified", "last_modified",
	// Browser forensics
	"visit_time", "last_visit_time", "lastvisittime", "visittime",
	"access_time", "accesstime",
	// Plaso/log2timeline
	"datetime", "date_time",
	// KAPE and other tools
	"creationtime", "creation_time", "modificationtime", "modification_time",
	"lastaccesstime", "last_access_time", "writetime", "write_time",
	// Windows Event specific
	"timecreated", "time_created", "systemtime", "system_time",
	// Registry
	"lastwritetime", "last_write_time",
}

// Known message/content column names (case-insensitive matching)
var csvMessageColumns = []string{
	// Generic message columns
	"message", "msg", "description", "desc", "data", "content", "details",
	// File system
	"path", "filepath", "file_path", "fullpath", "full_path",
	"filename", "file_name", "name", "parentpath", "parent_path",
	// Browser forensics
	"url", "title", "pagetitle", "page_title",
	// Command/process
	"command", "commandline", "command_line", "cmd", "arguments", "args",
	// Plaso specific
	"source_long", "display_name", "parser",
	// Network
	"source_ip", "dest_ip", "destination", "source", "target",
	// Registry
	"valuename", "value_name", "keypath", "key_path", "valuedata", "value_data",
	// Other descriptive
	"action", "operation", "event", "activity", "type", "status",
}

// Known source/type columns for better event categorization
var csvSourceColumns = []string{
	"source", "source_long", "parser", "log_source", "logsource",
	"category", "type", "event_type", "eventtype",
}

// Known user columns
var csvUserColumns = []string{
	"user", "username", "user_name", "account", "accountname", "account_name",
	"owner", "sid", "usersid", "user_sid",
}

// Known host columns
var csvHostColumns = []string{
	"host", "hostname", "host_name", "computer", "computername", "computer_name",
	"machine", "machinename", "machine_name", "workstation", "server",
}

// Timestamp formats to try when parsing
var csvTimestampFormats = []string{
	// ISO8601 / RFC3339 variations
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.000Z07:00",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05.0000000",

	// Common log format with space separator
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05.0000000",
	"2006-01-02 15:04:05.000000",
	"2006-01-02 15:04:05.00000000",

	// US format (MM/DD/YYYY)
	"1/2/2006 15:04:05",
	"1/2/2006 3:04:05 PM",
	"01/02/2006 15:04:05",
	"01/02/2006 3:04:05 PM",

	// EU format (DD/MM/YYYY)
	"02/01/2006 15:04:05",
	"2/1/2006 15:04:05",

	// Date only formats
	"2006-01-02",
	"01/02/2006",
	"02/01/2006",

	// Windows FILETIME string format (handled separately if numeric)
}

// CanParse checks if this parser can handle the given file
func (p *CSVArtifactParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".csv"
}

// Parse parses a CSV file and returns a slice of events
func (p *CSVArtifactParser) Parse(filePath string) ([]*core.Event, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read entire file to handle BOM and detect delimiter
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Strip UTF-8 BOM if present
	content = stripBOM(content)

	// Detect delimiter (comma or semicolon)
	delimiter := detectDelimiter(content)

	// Create CSV reader
	reader := csv.NewReader(bytes.NewReader(content))
	reader.Comma = delimiter
	reader.LazyQuotes = true   // Be lenient with quotes
	reader.TrimLeadingSpace = true

	// Read header row
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Normalize headers to lowercase for matching
	normalizedHeaders := make([]string, len(headers))
	for i, h := range headers {
		normalizedHeaders[i] = strings.ToLower(strings.TrimSpace(h))
	}

	// Find relevant column indices
	timestampCols := findColumnIndices(normalizedHeaders, csvTimestampColumns)
	messageCols := findColumnIndices(normalizedHeaders, csvMessageColumns)
	sourceCols := findColumnIndices(normalizedHeaders, csvSourceColumns)
	userCols := findColumnIndices(normalizedHeaders, csvUserColumns)
	hostCols := findColumnIndices(normalizedHeaders, csvHostColumns)

	// If no timestamp column found, warn but continue
	if len(timestampCols) == 0 {
		fmt.Printf("Warning: No timestamp column detected in %s\n", filePath)
	}

	// If no message column found, we'll use all non-timestamp columns
	if len(messageCols) == 0 {
		// Use all columns except timestamp columns as message
		for i := range normalizedHeaders {
			if !containsInt(timestampCols, i) {
				messageCols = append(messageCols, i)
			}
		}
	}

	// Count total rows for pre-allocation (read all records)
	allRecords, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV records: %w", err)
	}

	// Pre-allocate events slice
	events := make([]*core.Event, 0, len(allRecords))

	source := filepath.Base(filePath)
	rowNum := 1 // Start at 1 (header was row 0)

	// Track detected timestamp format for performance
	detectedFormat := ""

	for _, record := range allRecords {
		rowNum++

		// Skip empty rows
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}

		// Extract timestamp from the first available timestamp column
		var timestamp time.Time
		for _, colIdx := range timestampCols {
			if colIdx < len(record) {
				val := strings.TrimSpace(record[colIdx])
				if val != "" && val != "-" {
					timestamp, detectedFormat = parseTimestamp(val, detectedFormat)
					if !timestamp.IsZero() {
						break
					}
				}
			}
		}

		// Build message from message columns
		var messageParts []string
		for _, colIdx := range messageCols {
			if colIdx < len(record) {
				val := strings.TrimSpace(record[colIdx])
				if val != "" && val != "-" {
					// Include column name for context if multiple columns
					if len(messageCols) > 1 {
						messageParts = append(messageParts, fmt.Sprintf("%s=%s", headers[colIdx], val))
					} else {
						messageParts = append(messageParts, val)
					}
				}
			}
		}
		message := strings.Join(messageParts, " | ")

		// Extract source/type if available
		eventType := "CSVRecord"
		for _, colIdx := range sourceCols {
			if colIdx < len(record) {
				val := strings.TrimSpace(record[colIdx])
				if val != "" && val != "-" {
					eventType = val
					break
				}
			}
		}

		// Extract user if available
		user := ""
		for _, colIdx := range userCols {
			if colIdx < len(record) {
				val := strings.TrimSpace(record[colIdx])
				if val != "" && val != "-" {
					user = val
					break
				}
			}
		}

		// Extract host if available
		host := ""
		for _, colIdx := range hostCols {
			if colIdx < len(record) {
				val := strings.TrimSpace(record[colIdx])
				if val != "" && val != "-" {
					host = val
					break
				}
			}
		}

		// Create event
		event := core.NewEvent(
			timestamp,
			source,
			eventType,
			rowNum,
			user,
			host,
			message,
			filePath,
		)

		events = append(events, event)
	}

	// Print summary showing which columns were used
	printColumnSummary(filePath, headers, timestampCols, messageCols, sourceCols, userCols, hostCols, len(events))

	return events, nil
}

// stripBOM removes UTF-8 BOM from the beginning of content
func stripBOM(content []byte) []byte {
	// UTF-8 BOM: 0xEF, 0xBB, 0xBF
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return content[3:]
	}
	return content
}

// detectDelimiter auto-detects whether the CSV uses comma or semicolon
func detectDelimiter(content []byte) rune {
	// Read first line to detect delimiter
	reader := bufio.NewReader(bytes.NewReader(content))
	firstLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return ',' // Default to comma
	}

	commaCount := strings.Count(firstLine, ",")
	semicolonCount := strings.Count(firstLine, ";")

	if semicolonCount > commaCount {
		return ';'
	}
	return ','
}

// findColumnIndices finds indices of columns matching known names
func findColumnIndices(headers []string, knownNames []string) []int {
	var indices []int
	for i, header := range headers {
		for _, name := range knownNames {
			if header == name || strings.Contains(header, name) {
				indices = append(indices, i)
				break
			}
		}
	}
	return indices
}

// containsInt checks if a slice contains an integer
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// parseTimestamp attempts to parse a timestamp string using various formats
func parseTimestamp(value string, preferredFormat string) (time.Time, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, preferredFormat
	}

	// Try preferred format first if we have one
	if preferredFormat != "" {
		if t, err := time.Parse(preferredFormat, value); err == nil {
			return t.UTC(), preferredFormat
		}
	}

	// Try Unix epoch (numeric timestamp)
	if isNumeric(value) {
		if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
			// Determine if seconds, milliseconds, or microseconds
			if epoch > 1e15 {
				// Microseconds
				return time.Unix(0, epoch*int64(time.Microsecond)).UTC(), "unix_micro"
			} else if epoch > 1e12 {
				// Milliseconds
				return time.Unix(0, epoch*int64(time.Millisecond)).UTC(), "unix_milli"
			} else if epoch > 1e9 {
				// Seconds
				return time.Unix(epoch, 0).UTC(), "unix_sec"
			}
		}

		// Try Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
		if filetime, err := strconv.ParseInt(value, 10, 64); err == nil {
			if filetime > 116444736000000000 && filetime < 200000000000000000 {
				// Looks like FILETIME range
				// Convert to Unix: subtract Windows epoch offset and convert to nanoseconds
				const windowsEpochDiff = 116444736000000000 // 100-ns intervals between 1601 and 1970
				unixNano := (filetime - windowsEpochDiff) * 100
				return time.Unix(0, unixNano).UTC(), "filetime"
			}
		}
	}

	// Try all known formats
	for _, format := range csvTimestampFormats {
		if t, err := time.Parse(format, value); err == nil {
			return t.UTC(), format
		}
	}

	// Try with timezone suffix handling
	// Some tools output timestamps like "2023-04-21 15:30:45 +00:00"
	if strings.Contains(value, " +") || strings.Contains(value, " -") {
		// Try parsing with timezone
		formats := []string{
			"2006-01-02 15:04:05 -07:00",
			"2006-01-02 15:04:05 -0700",
			"2006-01-02 15:04:05.000 -07:00",
			"2006-01-02 15:04:05.000 -0700",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, value); err == nil {
				return t.UTC(), format
			}
		}
	}

	return time.Time{}, preferredFormat
}

// isNumeric checks if a string contains only numeric characters
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// printColumnSummary prints a summary of detected columns
func printColumnSummary(filePath string, headers []string, timestampCols, messageCols, sourceCols, userCols, hostCols []int, eventCount int) {
	fmt.Printf("Parsed CSV file: %s (found %d events)\n", filePath, eventCount)
	fmt.Printf("  Column mapping summary:\n")

	if len(timestampCols) > 0 {
		names := getColumnNames(headers, timestampCols)
		fmt.Printf("    Timestamp columns: %s\n", strings.Join(names, ", "))
	} else {
		fmt.Printf("    Timestamp columns: (none detected)\n")
	}

	if len(messageCols) > 0 {
		names := getColumnNames(headers, messageCols)
		if len(names) > 5 {
			fmt.Printf("    Message columns: %s, ... (%d total)\n", strings.Join(names[:5], ", "), len(names))
		} else {
			fmt.Printf("    Message columns: %s\n", strings.Join(names, ", "))
		}
	}

	if len(sourceCols) > 0 {
		names := getColumnNames(headers, sourceCols)
		fmt.Printf("    Source/Type columns: %s\n", strings.Join(names, ", "))
	}

	if len(userCols) > 0 {
		names := getColumnNames(headers, userCols)
		fmt.Printf("    User columns: %s\n", strings.Join(names, ", "))
	}

	if len(hostCols) > 0 {
		names := getColumnNames(headers, hostCols)
		fmt.Printf("    Host columns: %s\n", strings.Join(names, ", "))
	}
}

// getColumnNames returns the original header names for given indices
func getColumnNames(headers []string, indices []int) []string {
	var names []string
	for _, idx := range indices {
		if idx < len(headers) {
			names = append(names, headers[idx])
		}
	}
	return names
}
