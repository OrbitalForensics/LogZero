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

// PowerShellTranscriptParser implements the Parser interface for PowerShell transcript files
type PowerShellTranscriptParser struct{}

// PowerShellScriptBlockParser implements the Parser interface for PowerShell Script Block logs
type PowerShellScriptBlockParser struct{}

// Regex patterns for PowerShell transcript parsing
var (
	// Transcript header patterns
	transcriptStartPattern   = regexp.MustCompile(`^\*{20,}$`)
	transcriptHeaderMarker   = regexp.MustCompile(`(?i)^Windows PowerShell transcript start`)
	transcriptEndMarker      = regexp.MustCompile(`(?i)^Windows PowerShell transcript end`)
	transcriptStartTime      = regexp.MustCompile(`(?i)^Start time:\s*(\d{14})`)
	transcriptEndTime        = regexp.MustCompile(`(?i)^End time:\s*(\d{14})`)
	transcriptUsername       = regexp.MustCompile(`(?i)^Username:\s*(.+)$`)
	transcriptRunAsUser      = regexp.MustCompile(`(?i)^RunAs User:\s*(.+)$`)
	transcriptMachine        = regexp.MustCompile(`(?i)^Machine:\s*([^\s(]+)`)
	transcriptHostApp        = regexp.MustCompile(`(?i)^Host Application:\s*(.+)$`)
	transcriptPromptPattern  = regexp.MustCompile(`^PS\s+([A-Za-z]:\\[^>]*|/)>\s*(.*)$`)

	// Script Block log patterns (from EVTX exports or text dumps)
	scriptBlockTextPattern    = regexp.MustCompile(`(?i)<ScriptBlockText>(.+?)</ScriptBlockText>`)
	scriptBlockMessageNumber  = regexp.MustCompile(`(?i)MessageNumber[=:]\s*(\d+)`)
	scriptBlockMessageTotal   = regexp.MustCompile(`(?i)MessageTotal[=:]\s*(\d+)`)
	scriptBlockTimestamp      = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)`)
	scriptBlockPath           = regexp.MustCompile(`(?i)Path[=:]\s*["']?([^"'\s]+)["']?`)

	// Alternative timestamp format for Script Block logs: 2023-04-21 15:30:45
	scriptBlockTimestamp2 = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)
)

// CanParse checks if this parser can handle the given file as a PowerShell transcript
func (p *PowerShellTranscriptParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))

	// Check filename for transcript indicator
	if strings.Contains(baseName, "transcript") {
		return true
	}

	// Check file content for PowerShell transcript markers
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	maxLinesToCheck := 10

	for scanner.Scan() && lineCount < maxLinesToCheck {
		line := scanner.Text()
		lineCount++

		// Look for PowerShell transcript header markers
		if transcriptStartPattern.MatchString(line) || transcriptHeaderMarker.MatchString(line) {
			return true
		}
	}

	return false
}

// Parse parses a PowerShell transcript file and returns a slice of events
func (p *PowerShellTranscriptParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	// Transcript metadata
	var startTime time.Time
	var endTime time.Time
	var username string
	var runAsUser string
	var machine string
	var hostApplication string

	// State tracking
	inHeader := false
	headerParsed := false
	lineNum := 0
	commandNum := 0

	// For tracking multi-line output
	var currentCommand string
	var commandOutput strings.Builder

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Detect header/footer sections (marked by asterisk lines)
		if transcriptStartPattern.MatchString(line) {
			if !headerParsed {
				inHeader = true
			}
			continue
		}

		// Parse header content
		if inHeader && !headerParsed {
			if transcriptHeaderMarker.MatchString(line) {
				continue
			}
			if transcriptEndMarker.MatchString(line) {
				// This is actually the footer, skip
				inHeader = false
				continue
			}

			// Extract start time
			if matches := transcriptStartTime.FindStringSubmatch(line); matches != nil {
				startTime = parseTranscriptTimestamp(matches[1])
				continue
			}

			// Extract end time (might appear in footer)
			if matches := transcriptEndTime.FindStringSubmatch(line); matches != nil {
				endTime = parseTranscriptTimestamp(matches[1])
				continue
			}

			// Extract username
			if matches := transcriptUsername.FindStringSubmatch(line); matches != nil {
				username = strings.TrimSpace(matches[1])
				continue
			}

			// Extract RunAs user
			if matches := transcriptRunAsUser.FindStringSubmatch(line); matches != nil {
				runAsUser = strings.TrimSpace(matches[1])
				continue
			}

			// Extract machine name
			if matches := transcriptMachine.FindStringSubmatch(line); matches != nil {
				machine = strings.TrimSpace(matches[1])
				continue
			}

			// Extract host application
			if matches := transcriptHostApp.FindStringSubmatch(line); matches != nil {
				hostApplication = strings.TrimSpace(matches[1])
				continue
			}

			// Check if we've hit another asterisk line (end of header)
			if line == "" || strings.HasPrefix(line, "PS ") {
				inHeader = false
				headerParsed = true
			}
			continue
		}

		// Skip footer detection
		if transcriptEndMarker.MatchString(line) {
			continue
		}

		// Extract end time from footer
		if matches := transcriptEndTime.FindStringSubmatch(line); matches != nil {
			endTime = parseTranscriptTimestamp(matches[1])
			continue
		}

		// Parse command prompts
		if matches := transcriptPromptPattern.FindStringSubmatch(line); matches != nil {
			// Save previous command if exists
			if currentCommand != "" {
				commandNum++
				event := p.createCommandEvent(
					startTime,
					source,
					commandNum,
					username,
					runAsUser,
					machine,
					hostApplication,
					currentCommand,
					strings.TrimSpace(commandOutput.String()),
					filePath,
				)
				events = append(events, event)
				commandOutput.Reset()
			}

			// Start new command
			currentCommand = strings.TrimSpace(matches[2])
			continue
		}

		// If we have a current command, collect output
		if currentCommand != "" && line != "" {
			if commandOutput.Len() > 0 {
				commandOutput.WriteString("\n")
			}
			commandOutput.WriteString(line)
		}
	}

	// Don't forget the last command
	if currentCommand != "" {
		commandNum++
		event := p.createCommandEvent(
			startTime,
			source,
			commandNum,
			username,
			runAsUser,
			machine,
			hostApplication,
			currentCommand,
			strings.TrimSpace(commandOutput.String()),
			filePath,
		)
		events = append(events, event)
	}

	// Create a session start event with metadata
	if !startTime.IsZero() {
		sessionEvent := core.NewEvent(
			startTime,
			source,
			"PowerShellTranscriptStart",
			0,
			username,
			machine,
			fmt.Sprintf("PowerShell session started. Host: %s, RunAs: %s", hostApplication, runAsUser),
			filePath,
		)
		// Insert at the beginning
		events = append([]*core.Event{sessionEvent}, events...)
	}

	// Create a session end event
	if !endTime.IsZero() {
		sessionEndEvent := core.NewEvent(
			endTime,
			source,
			"PowerShellTranscriptEnd",
			0,
			username,
			machine,
			fmt.Sprintf("PowerShell session ended. Duration: %v", endTime.Sub(startTime)),
			filePath,
		)
		events = append(events, sessionEndEvent)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed PowerShell Transcript: %s (found %d events, %d commands)\n", filePath, len(events), commandNum)
	return events, nil
}

// createCommandEvent creates an event for a PowerShell command
func (p *PowerShellTranscriptParser) createCommandEvent(
	sessionTime time.Time,
	source string,
	commandNum int,
	username string,
	runAsUser string,
	machine string,
	hostApp string,
	command string,
	output string,
	filePath string,
) *core.Event {
	// Build detailed message
	var msgBuilder strings.Builder
	msgBuilder.WriteString(fmt.Sprintf("Command: %s", command))
	if output != "" {
		// Truncate output if too long
		if len(output) > 500 {
			output = output[:500] + "...[truncated]"
		}
		msgBuilder.WriteString(fmt.Sprintf(" | Output: %s", output))
	}

	// Use session time as base (transcript doesn't have per-command timestamps)
	user := username
	if runAsUser != "" && runAsUser != username {
		user = fmt.Sprintf("%s (RunAs: %s)", username, runAsUser)
	}

	return core.NewEvent(
		sessionTime,
		source,
		"PowerShellCommand",
		commandNum,
		user,
		machine,
		msgBuilder.String(),
		filePath,
	)
}

// parseTranscriptTimestamp parses the timestamp format used in PowerShell transcripts
// Format: YYYYMMDDHHmmss (e.g., 20230421153045)
func parseTranscriptTimestamp(timeStr string) time.Time {
	if len(timeStr) != 14 {
		return time.Time{}
	}

	timestamp, err := time.Parse("20060102150405", timeStr)
	if err != nil {
		return time.Time{}
	}

	return timestamp.UTC()
}

// CanParse checks if this parser can handle the given file as a PowerShell Script Block log
func (p *PowerShellScriptBlockParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))

	// Check filename patterns
	if strings.Contains(baseName, "scriptblock") ||
		strings.Contains(baseName, "script-block") ||
		strings.Contains(baseName, "powershell-operational") ||
		strings.Contains(baseName, "4104") { // Event ID 4104 is Script Block Logging
		return true
	}

	// Check file content for Script Block markers
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	maxLinesToCheck := 50

	for scanner.Scan() && lineCount < maxLinesToCheck {
		line := scanner.Text()
		lineCount++

		// Look for Script Block log markers
		if strings.Contains(line, "ScriptBlockText") ||
			strings.Contains(line, "MessageNumber") ||
			strings.Contains(line, "ScriptBlockId") {
			return true
		}
	}

	return false
}

// Parse parses a PowerShell Script Block log file and returns a slice of events
func (p *PowerShellScriptBlockParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long script blocks
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)
	lineNum := 0
	scriptBlockCount := 0

	// For multi-line script block assembly
	var currentBlock strings.Builder
	var currentTimestamp time.Time
	var currentMessageNumber int
	var currentMessageTotal int
	var currentPath string
	inScriptBlock := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		// Try to extract timestamp
		if matches := scriptBlockTimestamp.FindStringSubmatch(line); matches != nil {
			ts, err := time.Parse(time.RFC3339, matches[1])
			if err == nil {
				currentTimestamp = ts.UTC()
			}
		} else if matches := scriptBlockTimestamp2.FindStringSubmatch(line); matches != nil {
			ts, err := time.Parse("2006-01-02 15:04:05", matches[1])
			if err == nil {
				currentTimestamp = ts.UTC()
			}
		}

		// Extract message number
		if matches := scriptBlockMessageNumber.FindStringSubmatch(line); matches != nil {
			fmt.Sscanf(matches[1], "%d", &currentMessageNumber)
		}

		// Extract message total
		if matches := scriptBlockMessageTotal.FindStringSubmatch(line); matches != nil {
			fmt.Sscanf(matches[1], "%d", &currentMessageTotal)
		}

		// Extract script path if present
		if matches := scriptBlockPath.FindStringSubmatch(line); matches != nil {
			currentPath = matches[1]
		}

		// Check for XML-style ScriptBlockText
		if matches := scriptBlockTextPattern.FindStringSubmatch(line); matches != nil {
			// Single-line script block in XML
			scriptBlockCount++
			scriptContent := decodeXMLEntities(matches[1])

			event := p.createScriptBlockEvent(
				currentTimestamp,
				source,
				scriptBlockCount,
				currentMessageNumber,
				currentMessageTotal,
				scriptContent,
				currentPath,
				filePath,
			)
			events = append(events, event)

			// Reset state
			currentMessageNumber = 0
			currentMessageTotal = 0
			currentPath = ""
			continue
		}

		// Check for start of multi-line ScriptBlockText
		if strings.Contains(line, "<ScriptBlockText>") && !strings.Contains(line, "</ScriptBlockText>") {
			inScriptBlock = true
			// Extract content after the opening tag
			idx := strings.Index(line, "<ScriptBlockText>")
			if idx >= 0 {
				currentBlock.WriteString(line[idx+17:])
			}
			continue
		}

		// Check for end of multi-line ScriptBlockText
		if inScriptBlock && strings.Contains(line, "</ScriptBlockText>") {
			// Extract content before the closing tag
			idx := strings.Index(line, "</ScriptBlockText>")
			if idx > 0 {
				currentBlock.WriteString(line[:idx])
			}

			scriptBlockCount++
			scriptContent := decodeXMLEntities(currentBlock.String())

			event := p.createScriptBlockEvent(
				currentTimestamp,
				source,
				scriptBlockCount,
				currentMessageNumber,
				currentMessageTotal,
				scriptContent,
				currentPath,
				filePath,
			)
			events = append(events, event)

			// Reset state
			inScriptBlock = false
			currentBlock.Reset()
			currentMessageNumber = 0
			currentMessageTotal = 0
			currentPath = ""
			continue
		}

		// Continue collecting multi-line script block
		if inScriptBlock {
			if currentBlock.Len() > 0 {
				currentBlock.WriteString("\n")
			}
			currentBlock.WriteString(line)
			continue
		}

		// Handle plain text script block logs (non-XML format)
		// Look for patterns like "ScriptBlockText: <script content>"
		if strings.HasPrefix(strings.TrimSpace(line), "ScriptBlockText:") {
			scriptBlockCount++
			content := strings.TrimPrefix(strings.TrimSpace(line), "ScriptBlockText:")
			content = strings.TrimSpace(content)

			event := p.createScriptBlockEvent(
				currentTimestamp,
				source,
				scriptBlockCount,
				currentMessageNumber,
				currentMessageTotal,
				content,
				currentPath,
				filePath,
			)
			events = append(events, event)

			// Reset state
			currentMessageNumber = 0
			currentMessageTotal = 0
			currentPath = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Parsed PowerShell Script Block log: %s (found %d events, %d script blocks)\n", filePath, len(events), scriptBlockCount)
	return events, nil
}

// createScriptBlockEvent creates an event for a PowerShell script block
func (p *PowerShellScriptBlockParser) createScriptBlockEvent(
	timestamp time.Time,
	source string,
	blockNum int,
	messageNumber int,
	messageTotal int,
	scriptContent string,
	scriptPath string,
	filePath string,
) *core.Event {
	// Build message
	var msgBuilder strings.Builder

	// Add fragment info if this is part of a multi-part script
	if messageTotal > 1 {
		msgBuilder.WriteString(fmt.Sprintf("[Part %d/%d] ", messageNumber, messageTotal))
	}

	// Add script path if available
	if scriptPath != "" {
		msgBuilder.WriteString(fmt.Sprintf("Path: %s | ", scriptPath))
	}

	// Add script content (truncate if too long)
	content := strings.TrimSpace(scriptContent)
	if len(content) > 1000 {
		content = content[:1000] + "...[truncated]"
	}
	msgBuilder.WriteString(fmt.Sprintf("Script: %s", content))

	// Use current time if no timestamp was found
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	return core.NewEvent(
		timestamp,
		source,
		"PowerShellScriptBlock",
		4104, // Event ID 4104 is the standard Script Block Logging event
		"",   // User typically extracted separately
		"",   // Host typically extracted separately
		msgBuilder.String(),
		filePath,
	)
}

// decodeXMLEntities decodes common XML entities in script block text
func decodeXMLEntities(s string) string {
	replacer := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&amp;", "&",
		"&quot;", "\"",
		"&apos;", "'",
		"&#10;", "\n",
		"&#13;", "\r",
		"&#9;", "\t",
	)
	return replacer.Replace(s)
}
