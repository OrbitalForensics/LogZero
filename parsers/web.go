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

// WebAccessParser implements the Parser interface for Apache/Nginx access logs
type WebAccessParser struct{}

// Common regex patterns for Web Access Logs
var (
	// Combined Log Format: 127.0.0.1 - - [21/Apr/2023:15:30:45 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
	clfPattern = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?.*$`)
)

// CanParse checks if this parser can handle the given file
func (p *WebAccessParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return baseName == "access.log" ||
		strings.HasPrefix(baseName, "access.log.") ||
		strings.Contains(baseName, "apache") ||
		strings.Contains(baseName, "nginx")
}

// Parse parses a web access log file and returns a slice of events
func (p *WebAccessParser) Parse(filePath string) ([]*core.Event, error) {
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

	// Apache format: 02/Jan/2006:15:04:05 -0700
	const timeLayout = "02/Jan/2006:15:04:05 -0700"

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse Line
		matches := clfPattern.FindStringSubmatch(line)

		var event *core.Event
		if matches != nil {
			remoteHost := matches[1]
			// identity := matches[2]
			user := matches[3]
			if user == "-" {
				user = ""
			}
			timeStr := matches[4]
			request := matches[5] // method path protocol
			statusStr := matches[6]
			// sizeStr := matches[7]

			// Optional fields if Combined format
			// referer := ""
			// userAgent := ""
			// if len(matches) > 8 {
			// 	referer = matches[8]
			// 	userAgent = matches[9]
			// }

			timestamp, err := time.Parse(timeLayout, timeStr)
			// Don't use time.Now() as fallback - affects forensic timeline accuracy
			// Leave timestamp as zero value if parsing fails
			_ = err // Acknowledge potential parse error, timestamp stays zero

			status, _ := strconv.Atoi(statusStr)

			// Extract method and path from request
			reqParts := strings.Split(request, " ")
			method := ""
			path := ""
			if len(reqParts) > 0 {
				method = reqParts[0]
			}
			if len(reqParts) > 1 {
				path = reqParts[1]
			}

			msg := fmt.Sprintf("%s %s (Status: %d)", method, path, status)

			event = core.NewEvent(
				timestamp,
				source,
				"WebAccess",
				lineNum,
				user,
				remoteHost,
				msg,
				filePath,
			)
		} else {
			// Fallback for unparseable lines
			// Use zero time to indicate unparseable timestamp for forensic accuracy
			event = core.NewEvent(
				time.Time{},
				source,
				"WebAccessRaw",
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

	fmt.Printf("Parsed Web Access file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}
