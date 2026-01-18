package parsers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LogZero/core"
)

// ============================================================================
// AWS CloudTrail Parser
// ============================================================================

// CloudTrailParser implements the Parser interface for AWS CloudTrail JSON logs
type CloudTrailParser struct{}

// CanParse checks if this parser can handle the given file
func (p *CloudTrailParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check filename patterns
	if strings.Contains(baseName, "cloudtrail") {
		return true
	}

	// For JSON files, peek at content to detect CloudTrail structure
	if ext == ".json" || ext == ".jsonl" {
		return p.detectCloudTrailContent(filePath)
	}

	return false
}

// detectCloudTrailContent checks if file contains CloudTrail-specific fields
func (p *CloudTrailParser) detectCloudTrailContent(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first 4KB to detect content type
	buf := make([]byte, 4096)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	content := string(buf[:n])
	// CloudTrail has "Records" array or individual events with eventSource/eventName
	return strings.Contains(content, "\"eventSource\"") &&
		strings.Contains(content, "\"eventName\"") &&
		strings.Contains(content, "\"awsRegion\"")
}

// Parse parses a CloudTrail log file and returns a slice of events
func (p *CloudTrailParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	// Try to detect file format (JSON array, wrapped Records, or JSONL)
	decoder := json.NewDecoder(file)

	token, err := decoder.Token()
	if err != nil {
		// Might be JSONL format, try line-by-line
		file.Seek(0, 0)
		return p.parseJSONL(file, filePath, source)
	}

	if delim, ok := token.(json.Delim); ok {
		if delim == '[' {
			// Plain JSON array
			events, err = p.parseJSONArray(decoder, filePath, source)
		} else if delim == '{' {
			// Could be single object or CloudTrail wrapper with "Records" array
			file.Seek(0, 0)
			events, err = p.parseCloudTrailWrapper(file, filePath, source)
		}
	}

	if err != nil {
		return nil, err
	}

	fmt.Printf("Parsed CloudTrail file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// parseJSONL parses newline-delimited JSON format
func (p *CloudTrailParser) parseJSONL(file *os.File, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	scanner := bufio.NewScanner(file)
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var rawEvent map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rawEvent); err != nil {
			continue
		}

		event := p.processCloudTrailEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return events, nil
}

// parseJSONArray parses a JSON array of CloudTrail events
func (p *CloudTrailParser) parseJSONArray(decoder *json.Decoder, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	lineNum := 0

	for decoder.More() {
		lineNum++
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			continue
		}

		event := p.processCloudTrailEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	// Consume closing bracket
	decoder.Token()
	return events, nil
}

// parseCloudTrailWrapper handles CloudTrail files with "Records" wrapper
func (p *CloudTrailParser) parseCloudTrailWrapper(file *os.File, filePath, source string) ([]*core.Event, error) {
	var wrapper struct {
		Records []map[string]interface{} `json:"Records"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&wrapper); err != nil {
		// Not a wrapper format, try as single event
		file.Seek(0, 0)
		decoder = json.NewDecoder(file)
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			return nil, fmt.Errorf("failed to decode CloudTrail JSON: %w", err)
		}
		events := make([]*core.Event, 0)
		if event := p.processCloudTrailEvent(rawEvent, filePath, source, 1); event != nil {
			events = append(events, event)
		}
		return events, nil
	}

	events := make([]*core.Event, 0, len(wrapper.Records))
	for i, rawEvent := range wrapper.Records {
		if event := p.processCloudTrailEvent(rawEvent, filePath, source, i+1); event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

// processCloudTrailEvent extracts forensic fields from a CloudTrail event
func (p *CloudTrailParser) processCloudTrailEvent(rawEvent map[string]interface{}, filePath, source string, eventID int) *core.Event {
	// Extract timestamp (eventTime format: "2023-04-21T15:30:45Z")
	timestamp := time.Time{}
	if tsVal, ok := rawEvent["eventTime"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, tsVal); err == nil {
			timestamp = parsed
		}
	}

	// Extract event source and name for event type
	eventSource := getStringField(rawEvent, "eventSource")
	eventName := getStringField(rawEvent, "eventName")
	eventType := "CloudTrail"
	if eventSource != "" || eventName != "" {
		eventType = fmt.Sprintf("CloudTrail:%s:%s", eventSource, eventName)
	}

	// Extract user from userIdentity nested structure
	user := ""
	if userIdentity, ok := rawEvent["userIdentity"].(map[string]interface{}); ok {
		if userName := getStringField(userIdentity, "userName"); userName != "" {
			user = userName
		} else if arn := getStringField(userIdentity, "arn"); arn != "" {
			user = arn
		} else if principalId := getStringField(userIdentity, "principalId"); principalId != "" {
			user = principalId
		}
	}

	// Extract source IP as host
	host := getStringField(rawEvent, "sourceIPAddress")

	// Extract AWS region
	awsRegion := getStringField(rawEvent, "awsRegion")

	// Build message with key forensic fields
	var msgParts []string
	if eventName != "" {
		msgParts = append(msgParts, fmt.Sprintf("Action: %s", eventName))
	}
	if eventSource != "" {
		msgParts = append(msgParts, fmt.Sprintf("Service: %s", eventSource))
	}
	if awsRegion != "" {
		msgParts = append(msgParts, fmt.Sprintf("Region: %s", awsRegion))
	}
	if host != "" {
		msgParts = append(msgParts, fmt.Sprintf("SourceIP: %s", host))
	}

	// Include error information if present
	if errorCode := getStringField(rawEvent, "errorCode"); errorCode != "" {
		msgParts = append(msgParts, fmt.Sprintf("Error: %s", errorCode))
	}
	if errorMessage := getStringField(rawEvent, "errorMessage"); errorMessage != "" {
		msgParts = append(msgParts, fmt.Sprintf("ErrorMsg: %s", errorMessage))
	}

	message := strings.Join(msgParts, " | ")

	return core.NewEvent(
		timestamp,
		source,
		eventType,
		eventID,
		user,
		host,
		message,
		filePath,
	)
}

// ============================================================================
// Azure Activity Log Parser
// ============================================================================

// AzureActivityParser implements the Parser interface for Azure Activity Log JSON exports
type AzureActivityParser struct{}

// CanParse checks if this parser can handle the given file
func (p *AzureActivityParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check filename patterns
	if strings.Contains(baseName, "azure") || strings.Contains(baseName, "activitylog") {
		return true
	}

	// For JSON files, peek at content to detect Azure Activity Log structure
	if ext == ".json" || ext == ".jsonl" {
		return p.detectAzureContent(filePath)
	}

	return false
}

// detectAzureContent checks if file contains Azure Activity Log-specific fields
func (p *AzureActivityParser) detectAzureContent(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 4096)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	content := string(buf[:n])
	// Azure Activity Log has resourceId, operationName, and category fields
	return strings.Contains(content, "\"resourceId\"") &&
		strings.Contains(content, "\"operationName\"")
}

// Parse parses an Azure Activity Log file and returns a slice of events
func (p *AzureActivityParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	decoder := json.NewDecoder(file)

	token, err := decoder.Token()
	if err != nil {
		// Might be JSONL format
		file.Seek(0, 0)
		return p.parseJSONL(file, filePath, source)
	}

	if delim, ok := token.(json.Delim); ok {
		if delim == '[' {
			events, err = p.parseJSONArray(decoder, filePath, source)
		} else if delim == '{' {
			// Could be Azure export with "value" array or single event
			file.Seek(0, 0)
			events, err = p.parseAzureWrapper(file, filePath, source)
		}
	}

	if err != nil {
		return nil, err
	}

	fmt.Printf("Parsed Azure Activity Log file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// parseJSONL parses newline-delimited JSON format
func (p *AzureActivityParser) parseJSONL(file *os.File, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	scanner := bufio.NewScanner(file)
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var rawEvent map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rawEvent); err != nil {
			continue
		}

		event := p.processAzureEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return events, nil
}

// parseJSONArray parses a JSON array of Azure Activity events
func (p *AzureActivityParser) parseJSONArray(decoder *json.Decoder, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	lineNum := 0

	for decoder.More() {
		lineNum++
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			continue
		}

		event := p.processAzureEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	decoder.Token()
	return events, nil
}

// parseAzureWrapper handles Azure export files with "value" wrapper
func (p *AzureActivityParser) parseAzureWrapper(file *os.File, filePath, source string) ([]*core.Event, error) {
	var wrapper struct {
		Value []map[string]interface{} `json:"value"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&wrapper); err != nil {
		// Not a wrapper format, try as single event
		file.Seek(0, 0)
		decoder = json.NewDecoder(file)
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			return nil, fmt.Errorf("failed to decode Azure Activity Log JSON: %w", err)
		}
		events := make([]*core.Event, 0)
		if event := p.processAzureEvent(rawEvent, filePath, source, 1); event != nil {
			events = append(events, event)
		}
		return events, nil
	}

	// Check if wrapper.Value is populated
	if len(wrapper.Value) > 0 {
		events := make([]*core.Event, 0, len(wrapper.Value))
		for i, rawEvent := range wrapper.Value {
			if event := p.processAzureEvent(rawEvent, filePath, source, i+1); event != nil {
				events = append(events, event)
			}
		}
		return events, nil
	}

	// If no "value" array, the whole object might be a single event
	file.Seek(0, 0)
	decoder = json.NewDecoder(file)
	var rawEvent map[string]interface{}
	if err := decoder.Decode(&rawEvent); err != nil {
		return nil, fmt.Errorf("failed to decode Azure Activity Log JSON: %w", err)
	}
	events := make([]*core.Event, 0)
	if event := p.processAzureEvent(rawEvent, filePath, source, 1); event != nil {
		events = append(events, event)
	}
	return events, nil
}

// processAzureEvent extracts forensic fields from an Azure Activity Log event
func (p *AzureActivityParser) processAzureEvent(rawEvent map[string]interface{}, filePath, source string, eventID int) *core.Event {
	// Extract timestamp (ISO8601 format)
	timestamp := time.Time{}
	for _, tsField := range []string{"time", "eventTimestamp", "submissionTimestamp"} {
		if tsVal, ok := rawEvent[tsField].(string); ok && tsVal != "" {
			if parsed, err := time.Parse(time.RFC3339, tsVal); err == nil {
				timestamp = parsed
				break
			}
			// Try alternate ISO8601 formats
			if parsed, err := time.Parse("2006-01-02T15:04:05.9999999Z", tsVal); err == nil {
				timestamp = parsed
				break
			}
		}
	}

	// Extract operation name for event type
	operationName := getStringField(rawEvent, "operationName")
	category := getStringField(rawEvent, "category")
	eventType := "AzureActivity"
	if operationName != "" {
		eventType = fmt.Sprintf("Azure:%s", operationName)
	}

	// Extract user/caller from identity nested structure
	user := ""
	if identity, ok := rawEvent["identity"].(map[string]interface{}); ok {
		if claims, ok := identity["claims"].(map[string]interface{}); ok {
			if name := getStringField(claims, "name"); name != "" {
				user = name
			} else if upn := getStringField(claims, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"); upn != "" {
				user = upn
			}
		}
	}
	// Fallback to caller field
	if user == "" {
		user = getStringField(rawEvent, "caller")
	}

	// Extract caller IP as host
	host := getStringField(rawEvent, "callerIpAddress")

	// Extract resource ID
	resourceId := getStringField(rawEvent, "resourceId")

	// Extract result type
	resultType := getStringField(rawEvent, "resultType")

	// Build message with key forensic fields
	var msgParts []string
	if operationName != "" {
		msgParts = append(msgParts, fmt.Sprintf("Operation: %s", operationName))
	}
	if category != "" {
		msgParts = append(msgParts, fmt.Sprintf("Category: %s", category))
	}
	if resourceId != "" {
		// Truncate long resource IDs
		if len(resourceId) > 100 {
			resourceId = "..." + resourceId[len(resourceId)-97:]
		}
		msgParts = append(msgParts, fmt.Sprintf("Resource: %s", resourceId))
	}
	if resultType != "" {
		msgParts = append(msgParts, fmt.Sprintf("Result: %s", resultType))
	}
	if host != "" {
		msgParts = append(msgParts, fmt.Sprintf("CallerIP: %s", host))
	}

	message := strings.Join(msgParts, " | ")

	return core.NewEvent(
		timestamp,
		source,
		eventType,
		eventID,
		user,
		host,
		message,
		filePath,
	)
}

// ============================================================================
// GCP Cloud Audit Log Parser
// ============================================================================

// GCPAuditParser implements the Parser interface for GCP Cloud Audit Logs JSON
type GCPAuditParser struct{}

// CanParse checks if this parser can handle the given file
func (p *GCPAuditParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check filename patterns
	if strings.Contains(baseName, "gcp") || strings.Contains(baseName, "cloudaudit") ||
		strings.Contains(baseName, "google") || strings.Contains(baseName, "stackdriver") {
		return true
	}

	// For JSON files, peek at content to detect GCP Audit Log structure
	if ext == ".json" || ext == ".jsonl" {
		return p.detectGCPContent(filePath)
	}

	return false
}

// detectGCPContent checks if file contains GCP Audit Log-specific fields
func (p *GCPAuditParser) detectGCPContent(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 4096)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	content := string(buf[:n])
	// GCP Audit Log has protoPayload structure
	return strings.Contains(content, "\"protoPayload\"") ||
		(strings.Contains(content, "\"methodName\"") && strings.Contains(content, "\"serviceName\""))
}

// Parse parses a GCP Audit Log file and returns a slice of events
func (p *GCPAuditParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	decoder := json.NewDecoder(file)

	token, err := decoder.Token()
	if err != nil {
		// Might be JSONL format
		file.Seek(0, 0)
		return p.parseJSONL(file, filePath, source)
	}

	if delim, ok := token.(json.Delim); ok {
		if delim == '[' {
			events, err = p.parseJSONArray(decoder, filePath, source)
		} else if delim == '{' {
			file.Seek(0, 0)
			events, err = p.parseGCPWrapper(file, filePath, source)
		}
	}

	if err != nil {
		return nil, err
	}

	fmt.Printf("Parsed GCP Audit Log file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// parseJSONL parses newline-delimited JSON format
func (p *GCPAuditParser) parseJSONL(file *os.File, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	scanner := bufio.NewScanner(file)
	const maxScannerBuffer = 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var rawEvent map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rawEvent); err != nil {
			continue
		}

		event := p.processGCPEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return events, nil
}

// parseJSONArray parses a JSON array of GCP Audit events
func (p *GCPAuditParser) parseJSONArray(decoder *json.Decoder, filePath, source string) ([]*core.Event, error) {
	events := make([]*core.Event, 0)
	lineNum := 0

	for decoder.More() {
		lineNum++
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			continue
		}

		event := p.processGCPEvent(rawEvent, filePath, source, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	decoder.Token()
	return events, nil
}

// parseGCPWrapper handles GCP export files (single event or wrapper)
func (p *GCPAuditParser) parseGCPWrapper(file *os.File, filePath, source string) ([]*core.Event, error) {
	// GCP exports might have entries array
	var wrapper struct {
		Entries []map[string]interface{} `json:"entries"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&wrapper); err != nil {
		// Not a wrapper format, try as single event
		file.Seek(0, 0)
		decoder = json.NewDecoder(file)
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			return nil, fmt.Errorf("failed to decode GCP Audit Log JSON: %w", err)
		}
		events := make([]*core.Event, 0)
		if event := p.processGCPEvent(rawEvent, filePath, source, 1); event != nil {
			events = append(events, event)
		}
		return events, nil
	}

	// Check if wrapper.Entries is populated
	if len(wrapper.Entries) > 0 {
		events := make([]*core.Event, 0, len(wrapper.Entries))
		for i, rawEvent := range wrapper.Entries {
			if event := p.processGCPEvent(rawEvent, filePath, source, i+1); event != nil {
				events = append(events, event)
			}
		}
		return events, nil
	}

	// If no "entries" array, the whole object might be a single event
	file.Seek(0, 0)
	decoder = json.NewDecoder(file)
	var rawEvent map[string]interface{}
	if err := decoder.Decode(&rawEvent); err != nil {
		return nil, fmt.Errorf("failed to decode GCP Audit Log JSON: %w", err)
	}
	events := make([]*core.Event, 0)
	if event := p.processGCPEvent(rawEvent, filePath, source, 1); event != nil {
		events = append(events, event)
	}
	return events, nil
}

// processGCPEvent extracts forensic fields from a GCP Audit Log event
func (p *GCPAuditParser) processGCPEvent(rawEvent map[string]interface{}, filePath, source string, eventID int) *core.Event {
	// Extract timestamp
	timestamp := time.Time{}
	if tsVal, ok := rawEvent["timestamp"].(string); ok && tsVal != "" {
		if parsed, err := time.Parse(time.RFC3339, tsVal); err == nil {
			timestamp = parsed
		} else if parsed, err := time.Parse(time.RFC3339Nano, tsVal); err == nil {
			timestamp = parsed
		}
	}
	// Fallback to receiveTimestamp
	if timestamp.IsZero() {
		if tsVal, ok := rawEvent["receiveTimestamp"].(string); ok && tsVal != "" {
			if parsed, err := time.Parse(time.RFC3339, tsVal); err == nil {
				timestamp = parsed
			}
		}
	}

	// Extract protoPayload fields
	var methodName, serviceName, user, callerIP string

	if protoPayload, ok := rawEvent["protoPayload"].(map[string]interface{}); ok {
		methodName = getStringField(protoPayload, "methodName")
		serviceName = getStringField(protoPayload, "serviceName")

		// Extract principal email from authenticationInfo
		if authInfo, ok := protoPayload["authenticationInfo"].(map[string]interface{}); ok {
			user = getStringField(authInfo, "principalEmail")
		}

		// Extract caller IP from requestMetadata
		if reqMeta, ok := protoPayload["requestMetadata"].(map[string]interface{}); ok {
			callerIP = getStringField(reqMeta, "callerIp")
		}
	}

	// Build event type
	eventType := "GCPAudit"
	if serviceName != "" || methodName != "" {
		eventType = fmt.Sprintf("GCP:%s:%s", serviceName, methodName)
	}

	// Extract resource information
	resourceType := ""
	resourceName := ""
	if resource, ok := rawEvent["resource"].(map[string]interface{}); ok {
		resourceType = getStringField(resource, "type")
		if labels, ok := resource["labels"].(map[string]interface{}); ok {
			// Try common label fields
			for _, labelKey := range []string{"instance_id", "bucket_name", "project_id", "cluster_name"} {
				if val := getStringField(labels, labelKey); val != "" {
					resourceName = val
					break
				}
			}
		}
	}

	// Build message with key forensic fields
	var msgParts []string
	if methodName != "" {
		msgParts = append(msgParts, fmt.Sprintf("Method: %s", methodName))
	}
	if serviceName != "" {
		msgParts = append(msgParts, fmt.Sprintf("Service: %s", serviceName))
	}
	if resourceType != "" {
		msgParts = append(msgParts, fmt.Sprintf("ResourceType: %s", resourceType))
	}
	if resourceName != "" {
		msgParts = append(msgParts, fmt.Sprintf("Resource: %s", resourceName))
	}
	if callerIP != "" {
		msgParts = append(msgParts, fmt.Sprintf("CallerIP: %s", callerIP))
	}

	// Include severity if available
	if severity := getStringField(rawEvent, "severity"); severity != "" {
		msgParts = append(msgParts, fmt.Sprintf("Severity: %s", severity))
	}

	message := strings.Join(msgParts, " | ")

	return core.NewEvent(
		timestamp,
		source,
		eventType,
		eventID,
		user,
		callerIP,
		message,
		filePath,
	)
}

// ============================================================================
// Helper Functions
// ============================================================================

// getStringField safely extracts a string field from a map
func getStringField(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}
