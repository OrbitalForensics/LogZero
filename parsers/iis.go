package parsers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"LogZero/core"
)

// IISParser implements the Parser interface for Microsoft IIS W3C Extended Log Format
type IISParser struct{}

// CanParse checks if this parser can handle the given file
// IIS logs are typically:
// - Located in inetpub paths or W3SVC folders
// - Named with u_ex prefix (e.g., u_ex230421.log)
// - .log files in IIS-related directories
func (p *IISParser) CanParse(filePath string) bool {
	lowerPath := strings.ToLower(filePath)
	baseName := strings.ToLower(filepath.Base(filePath))

	// Check for u_ex prefix (IIS default naming: u_exYYMMDD.log)
	if strings.HasPrefix(baseName, "u_ex") && strings.HasSuffix(baseName, ".log") {
		return true
	}

	// Check for inetpub paths
	if strings.Contains(lowerPath, "inetpub") && strings.HasSuffix(baseName, ".log") {
		return true
	}

	// Check for W3SVC folders (IIS log folder pattern)
	if strings.Contains(lowerPath, "w3svc") && strings.HasSuffix(baseName, ".log") {
		return true
	}

	return false
}

// Parse parses an IIS W3C Extended Log Format file and returns a slice of events
func (p *IISParser) Parse(filePath string) ([]*core.Event, error) {
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

	// Field mapping - will be populated from #Fields directive
	var fieldNames []string
	fieldIndex := make(map[string]int)

	// Counters for summary
	parsedCount := 0
	skippedCount := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Handle directive lines (start with #)
		if strings.HasPrefix(line, "#") {
			// Parse #Fields directive to get column order
			if strings.HasPrefix(line, "#Fields:") {
				fieldsStr := strings.TrimPrefix(line, "#Fields:")
				fieldsStr = strings.TrimSpace(fieldsStr)
				fieldNames = strings.Fields(fieldsStr)

				// Build field index map for quick lookup
				fieldIndex = make(map[string]int)
				for i, name := range fieldNames {
					fieldIndex[name] = i
				}
			}
			// Skip other directives (#Software:, #Version:, #Date:, etc.)
			skippedCount++
			continue
		}

		// If we haven't seen a #Fields directive yet, skip data lines
		if len(fieldNames) == 0 {
			skippedCount++
			continue
		}

		// Parse data line
		fields := strings.Fields(line)
		if len(fields) < len(fieldNames) {
			// Malformed line - fewer fields than expected
			skippedCount++
			continue
		}

		// Extract timestamp from date and time fields
		timestamp := p.extractTimestamp(fields, fieldIndex)

		// Extract client IP (c-ip)
		clientIP := p.getFieldValue(fields, fieldIndex, "c-ip")

		// Extract method (cs-method)
		method := p.getFieldValue(fields, fieldIndex, "cs-method")

		// Extract URI stem (cs-uri-stem)
		uriStem := p.getFieldValue(fields, fieldIndex, "cs-uri-stem")

		// Extract URI query (cs-uri-query)
		uriQuery := p.getFieldValue(fields, fieldIndex, "cs-uri-query")

		// Extract status code (sc-status)
		statusStr := p.getFieldValue(fields, fieldIndex, "sc-status")
		status, _ := strconv.Atoi(statusStr)

		// Extract username (cs-username)
		username := p.getFieldValue(fields, fieldIndex, "cs-username")

		// Extract user agent (cs(User-Agent))
		userAgent := p.getFieldValue(fields, fieldIndex, "cs(User-Agent)")

		// Extract server IP (s-ip)
		serverIP := p.getFieldValue(fields, fieldIndex, "s-ip")

		// Extract server port (s-port)
		serverPort := p.getFieldValue(fields, fieldIndex, "s-port")

		// Extract time taken (time-taken) in milliseconds
		timeTakenStr := p.getFieldValue(fields, fieldIndex, "time-taken")
		timeTaken, _ := strconv.Atoi(timeTakenStr)

		// Extract substatus (sc-substatus)
		subStatus := p.getFieldValue(fields, fieldIndex, "sc-substatus")

		// Extract win32 status (sc-win32-status)
		win32Status := p.getFieldValue(fields, fieldIndex, "sc-win32-status")

		// Build the message
		var msgParts []string
		msgParts = append(msgParts, fmt.Sprintf("%s %s", method, uriStem))

		if uriQuery != "" {
			msgParts = append(msgParts, fmt.Sprintf("?%s", uriQuery))
		}

		msgParts = append(msgParts, fmt.Sprintf("(Status: %d", status))

		if subStatus != "" && subStatus != "0" {
			msgParts[len(msgParts)-1] += fmt.Sprintf(".%s", subStatus)
		}
		msgParts[len(msgParts)-1] += ")"

		if timeTaken > 0 {
			msgParts = append(msgParts, fmt.Sprintf("[%dms]", timeTaken))
		}

		if win32Status != "" && win32Status != "0" {
			msgParts = append(msgParts, fmt.Sprintf("Win32: %s", win32Status))
		}

		if userAgent != "" {
			// Truncate long user agents for readability
			if len(userAgent) > 100 {
				userAgent = userAgent[:100] + "..."
			}
			msgParts = append(msgParts, fmt.Sprintf("UA: %s", userAgent))
		}

		message := strings.Join(msgParts, " ")

		// Build host info (server IP:port if available)
		host := clientIP
		if serverIP != "" && serverPort != "" {
			host = fmt.Sprintf("%s -> %s:%s", clientIP, serverIP, serverPort)
		} else if serverIP != "" {
			host = fmt.Sprintf("%s -> %s", clientIP, serverIP)
		}

		event := core.NewEvent(
			timestamp,
			source,
			"IISAccess",
			lineNum,
			username,
			host,
			message,
			filePath,
		)

		events = append(events, event)
		parsedCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed IIS log file: %s (parsed %d events, skipped %d lines)\n", filePath, parsedCount, skippedCount)
	return events, nil
}

// extractTimestamp combines date and time fields into a timestamp
func (p *IISParser) extractTimestamp(fields []string, fieldIndex map[string]int) time.Time {
	dateStr := p.getFieldValue(fields, fieldIndex, "date")
	timeStr := p.getFieldValue(fields, fieldIndex, "time")

	if dateStr == "" || timeStr == "" {
		// Return zero time if date or time is missing
		return time.Time{}
	}

	// IIS uses ISO 8601 format: YYYY-MM-DD HH:MM:SS
	combined := fmt.Sprintf("%s %s", dateStr, timeStr)

	// Try parsing with different layouts
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, combined); err == nil {
			// IIS logs are in UTC
			return t.UTC()
		}
	}

	// Return zero time if parsing fails
	return time.Time{}
}

// getFieldValue retrieves a field value by name, returning empty string for "-" or missing fields
func (p *IISParser) getFieldValue(fields []string, fieldIndex map[string]int, fieldName string) string {
	idx, ok := fieldIndex[fieldName]
	if !ok || idx >= len(fields) {
		return ""
	}

	value := fields[idx]
	if value == "-" {
		return ""
	}

	return value
}
