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

// Pre-compiled regex patterns for firewall logs
var (
	// Windows Firewall log pattern
	// Format: Date Time Action Protocol Src-IP Dst-IP Src-Port Dst-Port Size TcpFlags TcpSyn TcpAck TcpWin IcmpType IcmpCode Info Path
	// Example: 2023-04-21 15:30:45 DROP TCP 192.168.1.100 10.0.0.50 54321 443 0 - 0 0 0 - - - RECEIVE
	windowsFirewallPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\d+|-)\s+(\d+|-)\s+(.*)$`)

	// iptables/UFW log pattern from syslog
	// Example: Apr 21 15:30:45 hostname kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.50 ...
	iptablesPattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+\[([^\]]+)\]\s+(.*)$`)

	// iptables field extraction patterns
	iptablesSrcPattern   = regexp.MustCompile(`SRC=(\S+)`)
	iptablesDstPattern   = regexp.MustCompile(`DST=(\S+)`)
	iptablesSptPattern   = regexp.MustCompile(`SPT=(\d+)`)
	iptablesDptPattern   = regexp.MustCompile(`DPT=(\d+)`)
	iptablesProtoPattern = regexp.MustCompile(`PROTO=(\w+)`)
	iptablesInPattern    = regexp.MustCompile(`IN=(\S*)`)
	iptablesOutPattern   = regexp.MustCompile(`OUT=(\S*)`)

	// Cisco ASA log pattern
	// Example: Apr 21 2023 15:30:45: %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.100/54321 (192.168.1.100/54321) to inside:10.0.0.50/443 (10.0.0.50/443)
	ciscoASAPattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}):\s+%ASA-(\d)-(\d+):\s+(.*)$`)

	// Cisco ASA connection patterns for extracting IPs and ports
	// Built/Teardown patterns: for interface:IP/port to interface:IP/port
	ciscoASAConnPattern = regexp.MustCompile(`(?:for|from)\s+(\S+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+).*?(?:to)\s+(\S+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)`)

	// Cisco ASA denied patterns: src IP:port dst IP:port or similar
	ciscoASADeniedPattern = regexp.MustCompile(`(?:src|from)\s+(?:\S+:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d+))?.*?(?:dst|to)\s+(?:\S+:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d+))?`)
)

// WindowsFirewallParser implements the Parser interface for Windows Firewall logs (pfirewall.log)
type WindowsFirewallParser struct{}

// CanParse checks if this parser can handle the given file
func (p *WindowsFirewallParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return baseName == "pfirewall.log" ||
		strings.Contains(baseName, "firewall") && strings.HasSuffix(baseName, ".log")
}

// Parse parses a Windows Firewall log file and returns a slice of events
func (p *WindowsFirewallParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	// Pre-allocate slice with estimated capacity (avg 200 bytes per firewall log line)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 200))
	lineNum := 0
	source := filepath.Base(filePath)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines and comment/header lines
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Truncate line before regex matching to prevent ReDoS
		lineForRegex := truncateLine(line)

		var event *core.Event

		matches := windowsFirewallPattern.FindStringSubmatch(lineForRegex)
		if matches != nil {
			dateStr := matches[1]
			timeStr := matches[2]
			action := strings.ToUpper(matches[3])
			protocol := strings.ToUpper(matches[4])
			srcIP := matches[5]
			dstIP := matches[6]
			srcPort := matches[7]
			dstPort := matches[8]
			remainder := matches[9]

			// Parse timestamp
			timestamp, err := time.Parse("2006-01-02 15:04:05", dateStr+" "+timeStr)
			if err != nil {
				timestamp = time.Time{}
			}

			// Extract direction from remainder if present (SEND/RECEIVE)
			direction := ""
			remainderUpper := strings.ToUpper(remainder)
			if strings.Contains(remainderUpper, "RECEIVE") {
				direction = "RECEIVE"
			} else if strings.Contains(remainderUpper, "SEND") {
				direction = "SEND"
			}

			// Build message
			msg := fmt.Sprintf("%s %s %s:%s -> %s:%s", action, protocol, srcIP, srcPort, dstIP, dstPort)
			if direction != "" {
				msg += " (" + direction + ")"
			}

			event = core.NewEvent(
				timestamp,
				source,
				"WindowsFirewall",
				lineNum,
				"",    // User not typically in firewall logs
				"",    // Host is implicit (local machine)
				msg,
				filePath,
			)
		} else {
			// Fallback for unparseable lines - create raw event
			event = core.NewEvent(
				time.Time{},
				source,
				"WindowsFirewallRaw",
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

	fmt.Printf("Parsed Windows Firewall file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// IptablesParser implements the Parser interface for Linux iptables/netfilter logs
type IptablesParser struct{}

// CanParse checks if this parser can handle the given file
func (p *IptablesParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	// Common iptables/UFW log locations
	return baseName == "ufw.log" ||
		strings.Contains(baseName, "iptables") ||
		strings.Contains(baseName, "firewall") ||
		strings.Contains(baseName, "netfilter")
}

// Parse parses an iptables/UFW log file and returns a slice of events
func (p *IptablesParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	// Pre-allocate slice with estimated capacity (avg 200 bytes per firewall log line)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 200))
	lineNum := 0
	source := filepath.Base(filePath)
	currentYear := time.Now().Year()

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		// Truncate line before regex matching to prevent ReDoS
		lineForRegex := truncateLine(line)

		var event *core.Event

		matches := iptablesPattern.FindStringSubmatch(lineForRegex)
		if matches != nil {
			timestampStr := matches[1]
			hostname := matches[2]
			action := matches[3] // e.g., "UFW BLOCK", "UFW ALLOW"
			details := matches[4]

			// Parse timestamp (RFC 3164 format without year)
			timeStr := fmt.Sprintf("%d %s", currentYear, timestampStr)
			timestamp, err := time.Parse("2006 Jan  2 15:04:05", timeStr)
			if err != nil {
				timestamp, err = time.Parse("2006 Jan 2 15:04:05", timeStr)
				if err != nil {
					timestamp = time.Time{}
				}
			}

			// Extract connection details
			srcIP := extractField(iptablesSrcPattern, details)
			dstIP := extractField(iptablesDstPattern, details)
			srcPort := extractField(iptablesSptPattern, details)
			dstPort := extractField(iptablesDptPattern, details)
			protocol := extractField(iptablesProtoPattern, details)
			inIface := extractField(iptablesInPattern, details)
			outIface := extractField(iptablesOutPattern, details)

			// Determine direction
			direction := ""
			if inIface != "" && outIface == "" {
				direction = "IN"
			} else if outIface != "" && inIface == "" {
				direction = "OUT"
			} else if inIface != "" && outIface != "" {
				direction = "FORWARD"
			}

			// Build message
			var msgParts []string
			msgParts = append(msgParts, "["+action+"]")
			if protocol != "" {
				msgParts = append(msgParts, protocol)
			}
			if srcIP != "" {
				srcStr := srcIP
				if srcPort != "" {
					srcStr += ":" + srcPort
				}
				msgParts = append(msgParts, srcStr)
			}
			msgParts = append(msgParts, "->")
			if dstIP != "" {
				dstStr := dstIP
				if dstPort != "" {
					dstStr += ":" + dstPort
				}
				msgParts = append(msgParts, dstStr)
			}
			if direction != "" {
				msgParts = append(msgParts, "("+direction+")")
			}

			msg := strings.Join(msgParts, " ")

			event = core.NewEvent(
				timestamp,
				source,
				"Iptables",
				lineNum,
				"",       // User not in iptables logs
				hostname,
				msg,
				filePath,
			)
		} else {
			// Fallback for unparseable lines - create raw event
			event = core.NewEvent(
				time.Time{},
				source,
				"IptablesRaw",
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

	fmt.Printf("Parsed Iptables file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// extractField extracts a field value from log details using the given pattern
func extractField(pattern *regexp.Regexp, details string) string {
	if matches := pattern.FindStringSubmatch(details); matches != nil && len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// CiscoASAParser implements the Parser interface for Cisco ASA firewall logs
type CiscoASAParser struct{}

// CanParse checks if this parser can handle the given file
func (p *CiscoASAParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return strings.Contains(baseName, "asa") ||
		strings.Contains(baseName, "cisco") ||
		strings.Contains(baseName, "pix")
}

// Parse parses a Cisco ASA log file and returns a slice of events
func (p *CiscoASAParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle long log lines
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	// Pre-allocate slice with estimated capacity (avg 200 bytes per firewall log line)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 200))
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

		matches := ciscoASAPattern.FindStringSubmatch(lineForRegex)
		if matches != nil {
			timestampStr := matches[1]
			severity := matches[2]
			msgID := matches[3]
			message := matches[4]

			// Parse timestamp: Apr 21 2023 15:30:45
			timestamp, err := time.Parse("Jan 2 2006 15:04:05", timestampStr)
			if err != nil {
				// Try alternate format with padded day
				timestamp, err = time.Parse("Jan  2 2006 15:04:05", timestampStr)
				if err != nil {
					timestamp = time.Time{}
				}
			}

			// Determine action based on message content and message ID
			action := determineASAAction(msgID, message)

			// Extract connection details
			srcIP, srcPort, dstIP, dstPort, protocol := extractASAConnectionDetails(message)

			// Build formatted message
			var msgParts []string
			msgParts = append(msgParts, fmt.Sprintf("[ASA-%s-%s]", severity, msgID))
			msgParts = append(msgParts, action)
			if protocol != "" {
				msgParts = append(msgParts, protocol)
			}
			if srcIP != "" {
				srcStr := srcIP
				if srcPort != "" {
					srcStr += ":" + srcPort
				}
				msgParts = append(msgParts, srcStr)
			}
			if dstIP != "" {
				msgParts = append(msgParts, "->")
				dstStr := dstIP
				if dstPort != "" {
					dstStr += ":" + dstPort
				}
				msgParts = append(msgParts, dstStr)
			}

			// Include original message for context
			msgParts = append(msgParts, "-", message)

			msg := strings.Join(msgParts, " ")

			// Convert message ID to integer for event ID
			eventID, _ := strconv.Atoi(msgID)

			event = core.NewEvent(
				timestamp,
				source,
				"CiscoASA",
				eventID,
				"",    // User not typically in ASA logs
				"",    // Host implicit
				msg,
				filePath,
			)
		} else {
			// Fallback for unparseable lines - create raw event
			event = core.NewEvent(
				time.Time{},
				source,
				"CiscoASARaw",
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

	fmt.Printf("Parsed Cisco ASA file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// determineASAAction determines the action (ALLOW/DENY/etc) from ASA message ID and content
func determineASAAction(msgID string, message string) string {
	msgUpper := strings.ToUpper(message)

	// Common ASA message IDs and their meanings
	switch msgID {
	case "302013", "302014", "302015", "302016": // Built/Teardown connections
		if strings.Contains(msgUpper, "BUILT") {
			return "ALLOW"
		}
		if strings.Contains(msgUpper, "TEARDOWN") {
			return "CLOSE"
		}
	case "106001", "106006", "106007", "106014", "106015", "106023": // Denied
		return "DENY"
	case "106100": // ACL permit/deny
		if strings.Contains(msgUpper, "PERMITTED") {
			return "ALLOW"
		}
		if strings.Contains(msgUpper, "DENIED") {
			return "DENY"
		}
	case "313001", "313004", "313005": // ICMP denied
		return "DENY"
	case "710003", "710005": // Access denied
		return "DENY"
	}

	// Fallback to content-based detection
	if strings.Contains(msgUpper, "DENIED") || strings.Contains(msgUpper, "DENY") {
		return "DENY"
	}
	if strings.Contains(msgUpper, "PERMITTED") || strings.Contains(msgUpper, "PERMIT") || strings.Contains(msgUpper, "BUILT") {
		return "ALLOW"
	}
	if strings.Contains(msgUpper, "TEARDOWN") {
		return "CLOSE"
	}
	if strings.Contains(msgUpper, "DROP") {
		return "DROP"
	}

	return "INFO"
}

// extractASAConnectionDetails extracts IP addresses, ports, and protocol from ASA message
func extractASAConnectionDetails(message string) (srcIP, srcPort, dstIP, dstPort, protocol string) {
	msgUpper := strings.ToUpper(message)

	// Extract protocol
	if strings.Contains(msgUpper, "TCP") {
		protocol = "TCP"
	} else if strings.Contains(msgUpper, "UDP") {
		protocol = "UDP"
	} else if strings.Contains(msgUpper, "ICMP") {
		protocol = "ICMP"
	}

	// Try connection pattern first (Built/Teardown messages)
	if matches := ciscoASAConnPattern.FindStringSubmatch(message); matches != nil {
		srcIP = matches[2]
		srcPort = matches[3]
		dstIP = matches[5]
		dstPort = matches[6]
		return
	}

	// Try denied pattern (various deny messages)
	if matches := ciscoASADeniedPattern.FindStringSubmatch(message); matches != nil {
		srcIP = matches[1]
		if len(matches) > 2 {
			srcPort = matches[2]
		}
		if len(matches) > 3 {
			dstIP = matches[3]
		}
		if len(matches) > 4 {
			dstPort = matches[4]
		}
		return
	}

	return
}
