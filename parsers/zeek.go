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

// ZeekParser implements the Parser interface for Zeek (formerly Bro) network log files
type ZeekParser struct{}

// CanParse checks if this parser can handle the given file
func (p *ZeekParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	dirPath := strings.ToLower(filepath.Dir(filePath))

	// Check if file is in a zeek or bro directory
	if strings.Contains(dirPath, "zeek") || strings.Contains(dirPath, "bro") {
		if strings.HasSuffix(baseName, ".log") {
			return true
		}
	}

	// Check for common Zeek log filenames
	zeekLogTypes := []string{
		"conn.log", "dns.log", "http.log", "ssl.log", "files.log",
		"x509.log", "dhcp.log", "ssh.log", "smtp.log", "ftp.log",
		"notice.log", "weird.log", "dpd.log", "known_hosts.log",
		"known_services.log", "software.log", "pe.log", "ntp.log",
		"rdp.log", "smb_mapping.log", "smb_files.log", "dce_rpc.log",
		"ntlm.log", "kerberos.log", "sip.log", "snmp.log", "tunnel.log",
	}
	for _, logType := range zeekLogTypes {
		if baseName == logType {
			return true
		}
	}

	// For .log files, check if the file has Zeek headers
	if strings.HasSuffix(baseName, ".log") {
		return p.hasZeekHeaders(filePath)
	}

	return false
}

// hasZeekHeaders checks if a file contains Zeek-specific header lines
func (p *ZeekParser) hasZeekHeaders(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	hasFields := false
	hasSeparator := false

	// Check the first 15 lines for Zeek headers
	for scanner.Scan() && lineCount < 15 {
		lineCount++
		line := scanner.Text()

		if strings.HasPrefix(line, "#separator") {
			hasSeparator = true
		}
		if strings.HasPrefix(line, "#fields") {
			hasFields = true
		}
		if hasSeparator && hasFields {
			return true
		}
	}

	return false
}

// Parse parses a Zeek log file and returns a slice of events
func (p *ZeekParser) Parse(filePath string) ([]*core.Event, error) {
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
	source := filepath.Base(filePath)

	// Zeek header metadata
	var separator string = "\t" // Default separator
	var fields []string
	var logPath string // The #path value (conn, dns, http, etc.)
	var emptyField string = "(empty)"
	var unsetField string = "-"

	lineNum := 0
	dataLineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Process header lines
		if strings.HasPrefix(line, "#") {
			p.parseHeaderLine(line, &separator, &fields, &logPath, &emptyField, &unsetField)
			continue
		}

		// Parse data lines
		if len(fields) == 0 {
			// No fields header found yet, skip data lines
			continue
		}

		dataLineNum++
		values := strings.Split(line, separator)

		// Build a map of field name to value
		fieldMap := make(map[string]string)
		for i, field := range fields {
			if i < len(values) {
				val := values[i]
				// Treat empty and unset fields as empty strings
				if val == emptyField || val == unsetField {
					val = ""
				}
				fieldMap[field] = val
			}
		}

		// Extract timestamp
		timestamp := p.parseTimestamp(fieldMap["ts"])

		// Extract common fields
		origHost := fieldMap["id.orig_h"]
		respHost := fieldMap["id.resp_h"]
		origPort := fieldMap["id.orig_p"]
		respPort := fieldMap["id.resp_p"]

		// Determine event type based on log path
		eventType := p.getEventType(logPath)

		// Build message based on log type
		message := p.buildMessage(logPath, fieldMap, origHost, origPort, respHost, respPort)

		// Determine host (use originating host as the primary identifier)
		host := origHost
		if host == "" {
			host = fieldMap["host"] // fallback for some log types
		}

		event := core.NewEvent(
			timestamp,
			source,
			eventType,
			dataLineNum,
			"",   // User is typically not available in Zeek logs
			host,
			message,
			filePath,
		)

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Print summary
	fmt.Printf("Parsed Zeek %s file: %s (found %d events)\n", logPath, filePath, len(events))
	return events, nil
}

// parseHeaderLine parses a Zeek header line and updates the metadata
func (p *ZeekParser) parseHeaderLine(line string, separator *string, fields *[]string, logPath *string, emptyField *string, unsetField *string) {
	if strings.HasPrefix(line, "#separator ") {
		// Handle separator (e.g., #separator \x09)
		sepValue := strings.TrimPrefix(line, "#separator ")
		*separator = p.unescapeSeparator(sepValue)
	} else if strings.HasPrefix(line, "#fields") {
		// Parse field names using current separator
		// The line format is: #fields<sep>field1<sep>field2...
		parts := strings.Split(line, *separator)
		if len(parts) > 1 {
			*fields = parts[1:] // Skip the "#fields" part
		}
	} else if strings.HasPrefix(line, "#path") {
		// Parse log path (e.g., #path conn)
		parts := strings.Split(line, *separator)
		if len(parts) > 1 {
			*logPath = parts[1]
		}
	} else if strings.HasPrefix(line, "#empty_field") {
		parts := strings.Split(line, *separator)
		if len(parts) > 1 {
			*emptyField = parts[1]
		}
	} else if strings.HasPrefix(line, "#unset_field") {
		parts := strings.Split(line, *separator)
		if len(parts) > 1 {
			*unsetField = parts[1]
		}
	}
	// Ignore other header lines (#set_separator, #open, #close, #types)
}

// unescapeSeparator converts Zeek separator escape sequences to actual characters
func (p *ZeekParser) unescapeSeparator(sep string) string {
	// Handle \x09 (tab) and other hex escapes
	if strings.HasPrefix(sep, "\\x") && len(sep) >= 4 {
		hexVal := sep[2:4]
		if val, err := strconv.ParseInt(hexVal, 16, 32); err == nil {
			return string(rune(val))
		}
	}
	return sep
}

// parseTimestamp parses a Zeek timestamp (Unix epoch with microseconds)
func (p *ZeekParser) parseTimestamp(tsStr string) time.Time {
	if tsStr == "" {
		return time.Time{}
	}

	// Zeek timestamps are Unix epoch with microseconds (e.g., 1682087445.123456)
	parts := strings.Split(tsStr, ".")
	if len(parts) == 0 {
		return time.Time{}
	}

	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}
	}

	var nanos int64 = 0
	if len(parts) > 1 {
		// Pad or truncate to 9 digits for nanoseconds
		microStr := parts[1]
		// Zeek typically uses 6 decimal places (microseconds)
		// Pad to 9 for nanoseconds
		for len(microStr) < 9 {
			microStr += "0"
		}
		if len(microStr) > 9 {
			microStr = microStr[:9]
		}
		nanos, _ = strconv.ParseInt(microStr, 10, 64)
	}

	return time.Unix(seconds, nanos).UTC()
}

// getEventType returns the event type based on the Zeek log path
func (p *ZeekParser) getEventType(logPath string) string {
	eventTypes := map[string]string{
		"conn":           "ZeekConnection",
		"dns":            "ZeekDNS",
		"http":           "ZeekHTTP",
		"ssl":            "ZeekSSL",
		"files":          "ZeekFiles",
		"x509":           "ZeekX509",
		"dhcp":           "ZeekDHCP",
		"ssh":            "ZeekSSH",
		"smtp":           "ZeekSMTP",
		"ftp":            "ZeekFTP",
		"notice":         "ZeekNotice",
		"weird":          "ZeekWeird",
		"dpd":            "ZeekDPD",
		"known_hosts":    "ZeekKnownHosts",
		"known_services": "ZeekKnownServices",
		"software":       "ZeekSoftware",
		"pe":             "ZeekPE",
		"ntp":            "ZeekNTP",
		"rdp":            "ZeekRDP",
		"smb_mapping":    "ZeekSMBMapping",
		"smb_files":      "ZeekSMBFiles",
		"dce_rpc":        "ZeekDCERPC",
		"ntlm":           "ZeekNTLM",
		"kerberos":       "ZeekKerberos",
		"sip":            "ZeekSIP",
		"snmp":           "ZeekSNMP",
		"tunnel":         "ZeekTunnel",
	}

	if eventType, ok := eventTypes[logPath]; ok {
		return eventType
	}
	return "ZeekLog"
}

// buildMessage constructs a meaningful message based on the log type
func (p *ZeekParser) buildMessage(logPath string, fields map[string]string, origHost, origPort, respHost, respPort string) string {
	// Build connection string if available
	connStr := ""
	if origHost != "" && respHost != "" {
		connStr = fmt.Sprintf("%s:%s -> %s:%s", origHost, origPort, respHost, respPort)
	} else if origHost != "" {
		connStr = origHost
	}

	switch logPath {
	case "conn":
		proto := fields["proto"]
		service := fields["service"]
		connState := fields["conn_state"]
		duration := fields["duration"]

		msg := connStr
		if proto != "" {
			msg += fmt.Sprintf(" [%s]", strings.ToUpper(proto))
		}
		if service != "" {
			msg += fmt.Sprintf(" service=%s", service)
		}
		if connState != "" {
			msg += fmt.Sprintf(" state=%s", connState)
		}
		if duration != "" {
			msg += fmt.Sprintf(" duration=%ss", duration)
		}
		return msg

	case "dns":
		query := fields["query"]
		qtype := fields["qtype_name"]
		answers := fields["answers"]
		rcode := fields["rcode_name"]

		msg := connStr
		if query != "" {
			msg += fmt.Sprintf(" query=%s", query)
		}
		if qtype != "" {
			msg += fmt.Sprintf(" type=%s", qtype)
		}
		if answers != "" {
			msg += fmt.Sprintf(" answers=[%s]", answers)
		}
		if rcode != "" && rcode != "NOERROR" {
			msg += fmt.Sprintf(" rcode=%s", rcode)
		}
		return msg

	case "http":
		method := fields["method"]
		host := fields["host"]
		uri := fields["uri"]
		statusCode := fields["status_code"]
		userAgent := fields["user_agent"]

		msg := connStr
		if method != "" {
			msg += fmt.Sprintf(" %s", method)
		}
		if host != "" {
			msg += fmt.Sprintf(" http://%s%s", host, uri)
		} else if uri != "" {
			msg += fmt.Sprintf(" %s", uri)
		}
		if statusCode != "" {
			msg += fmt.Sprintf(" [%s]", statusCode)
		}
		if userAgent != "" {
			msg += fmt.Sprintf(" UA=%s", userAgent)
		}
		return msg

	case "ssl":
		serverName := fields["server_name"]
		subject := fields["subject"]
		issuer := fields["issuer"]
		version := fields["version"]

		msg := connStr
		if serverName != "" {
			msg += fmt.Sprintf(" SNI=%s", serverName)
		}
		if version != "" {
			msg += fmt.Sprintf(" ver=%s", version)
		}
		if subject != "" {
			msg += fmt.Sprintf(" subject=%s", subject)
		}
		if issuer != "" {
			msg += fmt.Sprintf(" issuer=%s", issuer)
		}
		return msg

	case "files":
		filename := fields["filename"]
		mimeType := fields["mime_type"]
		totalBytes := fields["total_bytes"]
		md5 := fields["md5"]
		sha1 := fields["sha1"]
		sha256 := fields["sha256"]

		msg := connStr
		if filename != "" {
			msg += fmt.Sprintf(" file=%s", filename)
		}
		if mimeType != "" {
			msg += fmt.Sprintf(" type=%s", mimeType)
		}
		if totalBytes != "" {
			msg += fmt.Sprintf(" size=%s", totalBytes)
		}
		// Include hash if available (prefer SHA256)
		if sha256 != "" {
			msg += fmt.Sprintf(" sha256=%s", sha256)
		} else if sha1 != "" {
			msg += fmt.Sprintf(" sha1=%s", sha1)
		} else if md5 != "" {
			msg += fmt.Sprintf(" md5=%s", md5)
		}
		return msg

	case "notice":
		note := fields["note"]
		noticeMsg := fields["msg"]
		sub := fields["sub"]

		msg := connStr
		if note != "" {
			msg += fmt.Sprintf(" [%s]", note)
		}
		if noticeMsg != "" {
			msg += fmt.Sprintf(" %s", noticeMsg)
		}
		if sub != "" {
			msg += fmt.Sprintf(" (%s)", sub)
		}
		return msg

	case "ssh":
		version := fields["version"]
		authSuccess := fields["auth_success"]
		client := fields["client"]
		server := fields["server"]

		msg := connStr + " [SSH]"
		if version != "" {
			msg += fmt.Sprintf(" ver=%s", version)
		}
		if authSuccess != "" {
			if authSuccess == "T" {
				msg += " auth=SUCCESS"
			} else if authSuccess == "F" {
				msg += " auth=FAILED"
			}
		}
		if client != "" {
			msg += fmt.Sprintf(" client=%s", client)
		}
		if server != "" {
			msg += fmt.Sprintf(" server=%s", server)
		}
		return msg

	case "dhcp":
		macAddr := fields["mac"]
		assignedIP := fields["assigned_ip"]
		leaseTime := fields["lease_time"]
		hostname := fields["host_name"]

		msg := connStr
		if macAddr != "" {
			msg += fmt.Sprintf(" MAC=%s", macAddr)
		}
		if assignedIP != "" {
			msg += fmt.Sprintf(" assigned=%s", assignedIP)
		}
		if hostname != "" {
			msg += fmt.Sprintf(" hostname=%s", hostname)
		}
		if leaseTime != "" {
			msg += fmt.Sprintf(" lease=%ss", leaseTime)
		}
		return msg

	case "x509":
		certSubject := fields["certificate.subject"]
		certIssuer := fields["certificate.issuer"]
		certSerial := fields["certificate.serial"]

		msg := ""
		if certSubject != "" {
			msg += fmt.Sprintf("subject=%s", certSubject)
		}
		if certIssuer != "" {
			msg += fmt.Sprintf(" issuer=%s", certIssuer)
		}
		if certSerial != "" {
			msg += fmt.Sprintf(" serial=%s", certSerial)
		}
		return strings.TrimSpace(msg)

	case "kerberos":
		cname := fields["client"]
		sname := fields["service"]
		success := fields["success"]
		errorMsg := fields["error_msg"]

		msg := connStr + " [Kerberos]"
		if cname != "" {
			msg += fmt.Sprintf(" client=%s", cname)
		}
		if sname != "" {
			msg += fmt.Sprintf(" service=%s", sname)
		}
		if success != "" {
			if success == "T" {
				msg += " SUCCESS"
			} else if success == "F" {
				msg += " FAILED"
				if errorMsg != "" {
					msg += fmt.Sprintf(" (%s)", errorMsg)
				}
			}
		}
		return msg

	case "ntlm":
		username := fields["username"]
		hostname := fields["hostname"]
		domainname := fields["domainname"]
		success := fields["success"]

		msg := connStr + " [NTLM]"
		if domainname != "" && username != "" {
			msg += fmt.Sprintf(" user=%s\\%s", domainname, username)
		} else if username != "" {
			msg += fmt.Sprintf(" user=%s", username)
		}
		if hostname != "" {
			msg += fmt.Sprintf(" host=%s", hostname)
		}
		if success != "" {
			if success == "T" {
				msg += " SUCCESS"
			} else if success == "F" {
				msg += " FAILED"
			}
		}
		return msg

	case "smtp":
		mailfrom := fields["mailfrom"]
		rcptto := fields["rcptto"]
		subject := fields["subject"]
		lastReply := fields["last_reply"]

		msg := connStr + " [SMTP]"
		if mailfrom != "" {
			msg += fmt.Sprintf(" from=%s", mailfrom)
		}
		if rcptto != "" {
			msg += fmt.Sprintf(" to=%s", rcptto)
		}
		if subject != "" {
			msg += fmt.Sprintf(" subject=%s", subject)
		}
		if lastReply != "" {
			msg += fmt.Sprintf(" reply=%s", lastReply)
		}
		return msg

	case "ftp":
		user := fields["user"]
		password := fields["password"]
		command := fields["command"]
		arg := fields["arg"]
		replyCode := fields["reply_code"]
		replyMsg := fields["reply_msg"]

		msg := connStr + " [FTP]"
		if user != "" {
			msg += fmt.Sprintf(" user=%s", user)
		}
		if command != "" {
			msg += fmt.Sprintf(" %s", command)
			if arg != "" {
				msg += fmt.Sprintf(" %s", arg)
			}
		}
		if replyCode != "" {
			msg += fmt.Sprintf(" [%s", replyCode)
			if replyMsg != "" {
				msg += fmt.Sprintf(" %s", replyMsg)
			}
			msg += "]"
		}
		// Note: password field is typically empty for security
		_ = password
		return msg

	case "weird":
		name := fields["name"]
		addl := fields["addl"]

		msg := connStr
		if name != "" {
			msg += fmt.Sprintf(" [WEIRD:%s]", name)
		}
		if addl != "" {
			msg += fmt.Sprintf(" %s", addl)
		}
		return msg

	case "rdp":
		cookie := fields["cookie"]
		result := fields["result"]
		securityProto := fields["security_protocol"]

		msg := connStr + " [RDP]"
		if cookie != "" {
			msg += fmt.Sprintf(" cookie=%s", cookie)
		}
		if securityProto != "" {
			msg += fmt.Sprintf(" security=%s", securityProto)
		}
		if result != "" {
			msg += fmt.Sprintf(" result=%s", result)
		}
		return msg

	default:
		// Generic message for unknown log types
		if connStr != "" {
			return connStr
		}
		// Build message from all non-empty fields
		var parts []string
		for k, v := range fields {
			if v != "" && k != "ts" && k != "uid" {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
		}
		if len(parts) > 5 {
			parts = parts[:5] // Limit to first 5 fields
		}
		return strings.Join(parts, " ")
	}
}
