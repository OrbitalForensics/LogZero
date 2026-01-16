package parsers

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"LogZero/core"
)

// ============================================================================
// Windows XML Event Parser
// ============================================================================

// WindowsXMLEventParser implements the Parser interface for exported Windows
// Event Logs in XML format (from wevtutil or Get-WinEvent -AsXML)
type WindowsXMLEventParser struct{}

// XML structures for Windows Event Log format
type windowsXMLEvents struct {
	XMLName xml.Name          `xml:"Events"`
	Events  []windowsXMLEvent `xml:"Event"`
}

type windowsXMLEvent struct {
	XMLName   xml.Name             `xml:"Event"`
	System    windowsXMLSystem     `xml:"System"`
	EventData windowsXMLEventData  `xml:"EventData"`
	UserData  windowsXMLUserData   `xml:"UserData"`
}

type windowsXMLSystem struct {
	Provider    windowsXMLProvider `xml:"Provider"`
	EventID     int                `xml:"EventID"`
	Version     int                `xml:"Version"`
	Level       int                `xml:"Level"`
	Task        int                `xml:"Task"`
	Opcode      int                `xml:"Opcode"`
	Keywords    string             `xml:"Keywords"`
	TimeCreated windowsXMLTime     `xml:"TimeCreated"`
	EventRecordID int64            `xml:"EventRecordID"`
	Correlation windowsXMLCorrelation `xml:"Correlation"`
	Execution   windowsXMLExecution   `xml:"Execution"`
	Channel     string             `xml:"Channel"`
	Computer    string             `xml:"Computer"`
	Security    windowsXMLSecurity `xml:"Security"`
}

type windowsXMLProvider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type windowsXMLTime struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type windowsXMLCorrelation struct {
	ActivityID string `xml:"ActivityID,attr"`
}

type windowsXMLExecution struct {
	ProcessID uint32 `xml:"ProcessID,attr"`
	ThreadID  uint32 `xml:"ThreadID,attr"`
}

type windowsXMLSecurity struct {
	UserID string `xml:"UserID,attr"`
}

type windowsXMLEventData struct {
	Data []windowsXMLData `xml:"Data"`
}

type windowsXMLUserData struct {
	InnerXML string `xml:",innerxml"`
}

type windowsXMLData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// CanParse checks if this parser can handle the given file
func (p *WindowsXMLEventParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".xml" {
		return false
	}

	// Check file content for Windows Event Log XML structure
	return p.detectWindowsEventXML(filePath)
}

// detectWindowsEventXML checks if file contains Windows Event Log XML structure
func (p *WindowsXMLEventParser) detectWindowsEventXML(filePath string) bool {
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

	// Look for Windows Event Log XML markers
	// Can be wrapped in <Events> or standalone <Event>
	hasEventSchema := strings.Contains(content, "http://schemas.microsoft.com/win/2004/08/events/event")
	hasEventElement := strings.Contains(content, "<Event") && strings.Contains(content, "<System>")

	return hasEventSchema || hasEventElement
}

// Parse parses a Windows Event Log XML file and returns a slice of events
func (p *WindowsXMLEventParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	source := filepath.Base(filePath)

	// Try streaming parse for large files with multiple events
	decoder := xml.NewDecoder(file)

	// Track counts for summary
	eventCount := 0
	errorCount := 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Try to continue on parse errors
			errorCount++
			continue
		}

		// Look for Event start elements
		if se, ok := token.(xml.StartElement); ok {
			if se.Name.Local == "Event" {
				var xmlEvent windowsXMLEvent
				if err := decoder.DecodeElement(&xmlEvent, &se); err != nil {
					errorCount++
					continue
				}

				event := p.convertWindowsXMLEvent(&xmlEvent, source, filePath, eventCount+1)
				if event != nil {
					events = append(events, event)
					eventCount++
				}
			}
		}
	}

	// Print summary
	fmt.Printf("Parsed Windows Event XML file: %s (found %d events", filePath, len(events))
	if errorCount > 0 {
		fmt.Printf(", %d parse errors", errorCount)
	}
	fmt.Println(")")

	return events, nil
}

// convertWindowsXMLEvent converts a parsed XML event to core.Event
func (p *WindowsXMLEventParser) convertWindowsXMLEvent(xmlEvent *windowsXMLEvent, source, filePath string, index int) *core.Event {
	if xmlEvent == nil {
		return nil
	}

	// Parse timestamp
	timestamp := time.Now().UTC()
	if xmlEvent.System.TimeCreated.SystemTime != "" {
		// Try multiple timestamp formats
		formats := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.9999999Z",
			"2006-01-02T15:04:05.999999999Z",
			"2006-01-02T15:04:05Z",
		}
		for _, format := range formats {
			if parsed, err := time.Parse(format, xmlEvent.System.TimeCreated.SystemTime); err == nil {
				timestamp = parsed
				break
			}
		}
	}

	// Extract event type from channel or provider
	eventType := "WindowsEventXML"
	if xmlEvent.System.Channel != "" {
		eventType = xmlEvent.System.Channel
	} else if xmlEvent.System.Provider.Name != "" {
		eventType = xmlEvent.System.Provider.Name
	}

	// Extract user from Security UserID
	user := xmlEvent.System.Security.UserID

	// Extract host from Computer
	host := xmlEvent.System.Computer

	// Build message from EventData
	message := p.buildEventMessage(xmlEvent)

	return core.NewEvent(
		timestamp,
		source,
		eventType,
		xmlEvent.System.EventID,
		user,
		host,
		message,
		filePath,
	)
}

// buildEventMessage creates a human-readable message from event data
func (p *WindowsXMLEventParser) buildEventMessage(xmlEvent *windowsXMLEvent) string {
	var parts []string

	// Add Event ID and Provider
	parts = append(parts, fmt.Sprintf("EventID: %d", xmlEvent.System.EventID))
	if xmlEvent.System.Provider.Name != "" {
		parts = append(parts, fmt.Sprintf("Provider: %s", xmlEvent.System.Provider.Name))
	}

	// Add level description
	levelDesc := p.getLevelDescription(xmlEvent.System.Level)
	if levelDesc != "" {
		parts = append(parts, fmt.Sprintf("Level: %s", levelDesc))
	}

	// Extract EventData fields
	if len(xmlEvent.EventData.Data) > 0 {
		var dataFields []string
		for _, data := range xmlEvent.EventData.Data {
			if data.Name != "" && data.Value != "" {
				// Limit value length for readability
				value := strings.TrimSpace(data.Value)
				if len(value) > 100 {
					value = value[:97] + "..."
				}
				dataFields = append(dataFields, fmt.Sprintf("%s=%s", data.Name, value))
			}
		}
		if len(dataFields) > 0 {
			parts = append(parts, strings.Join(dataFields, ", "))
		}
	}

	return strings.Join(parts, " | ")
}

// getLevelDescription converts numeric level to description
func (p *WindowsXMLEventParser) getLevelDescription(level int) string {
	switch level {
	case 0:
		return "LogAlways"
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 5:
		return "Verbose"
	default:
		return ""
	}
}

// ============================================================================
// Scheduled Task XML Parser
// ============================================================================

// ScheduledTaskXMLParser implements the Parser interface for Windows Scheduled Task XML files
type ScheduledTaskXMLParser struct{}

// XML structures for Scheduled Task format
type scheduledTask struct {
	XMLName          xml.Name                `xml:"Task"`
	Version          string                  `xml:"version,attr"`
	RegistrationInfo taskRegistrationInfo    `xml:"RegistrationInfo"`
	Triggers         taskTriggers            `xml:"Triggers"`
	Principals       taskPrincipals          `xml:"Principals"`
	Settings         taskSettings            `xml:"Settings"`
	Actions          taskActions             `xml:"Actions"`
}

type taskRegistrationInfo struct {
	Date        string `xml:"Date"`
	Author      string `xml:"Author"`
	Description string `xml:"Description"`
	URI         string `xml:"URI"`
	Source      string `xml:"Source"`
}

type taskTriggers struct {
	LogonTrigger      []taskLogonTrigger      `xml:"LogonTrigger"`
	CalendarTrigger   []taskCalendarTrigger   `xml:"CalendarTrigger"`
	TimeTrigger       []taskTimeTrigger       `xml:"TimeTrigger"`
	BootTrigger       []taskBootTrigger       `xml:"BootTrigger"`
	IdleTrigger       []taskIdleTrigger       `xml:"IdleTrigger"`
	EventTrigger      []taskEventTrigger      `xml:"EventTrigger"`
	RegistrationTrigger []taskRegistrationTrigger `xml:"RegistrationTrigger"`
}

type taskLogonTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
	UserId        string `xml:"UserId"`
}

type taskCalendarTrigger struct {
	Enabled          string               `xml:"Enabled"`
	StartBoundary    string               `xml:"StartBoundary"`
	ScheduleByDay    *taskScheduleByDay   `xml:"ScheduleByDay"`
	ScheduleByWeek   *taskScheduleByWeek  `xml:"ScheduleByWeek"`
	ScheduleByMonth  *taskScheduleByMonth `xml:"ScheduleByMonth"`
}

type taskScheduleByDay struct {
	DaysInterval int `xml:"DaysInterval"`
}

type taskScheduleByWeek struct {
	WeeksInterval int    `xml:"WeeksInterval"`
	DaysOfWeek    string `xml:",innerxml"`
}

type taskScheduleByMonth struct {
	Months     string `xml:",innerxml"`
	DaysOfMonth string `xml:",innerxml"`
}

type taskTimeTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
}

type taskBootTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
	Delay         string `xml:"Delay"`
}

type taskIdleTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
}

type taskEventTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
	Subscription  string `xml:"Subscription"`
}

type taskRegistrationTrigger struct {
	Enabled       string `xml:"Enabled"`
	StartBoundary string `xml:"StartBoundary"`
}

type taskPrincipals struct {
	Principal []taskPrincipal `xml:"Principal"`
}

type taskPrincipal struct {
	ID        string `xml:"id,attr"`
	UserId    string `xml:"UserId"`
	GroupId   string `xml:"GroupId"`
	RunLevel  string `xml:"RunLevel"`
	LogonType string `xml:"LogonType"`
}

type taskSettings struct {
	MultipleInstancesPolicy string `xml:"MultipleInstancesPolicy"`
	DisallowStartIfOnBatteries string `xml:"DisallowStartIfOnBatteries"`
	StopIfGoingOnBatteries  string `xml:"StopIfGoingOnBatteries"`
	AllowHardTerminate      string `xml:"AllowHardTerminate"`
	StartWhenAvailable      string `xml:"StartWhenAvailable"`
	RunOnlyIfNetworkAvailable string `xml:"RunOnlyIfNetworkAvailable"`
	Enabled                 string `xml:"Enabled"`
	Hidden                  string `xml:"Hidden"`
	RunOnlyIfIdle           string `xml:"RunOnlyIfIdle"`
	WakeToRun               string `xml:"WakeToRun"`
	ExecutionTimeLimit      string `xml:"ExecutionTimeLimit"`
	Priority                int    `xml:"Priority"`
}

type taskActions struct {
	Context string       `xml:"Context,attr"`
	Exec    []taskExec   `xml:"Exec"`
	ComHandler []taskComHandler `xml:"ComHandler"`
}

type taskExec struct {
	Command          string `xml:"Command"`
	Arguments        string `xml:"Arguments"`
	WorkingDirectory string `xml:"WorkingDirectory"`
}

type taskComHandler struct {
	ClassId string `xml:"ClassId"`
	Data    string `xml:"Data"`
}

// CanParse checks if this parser can handle the given file
func (p *ScheduledTaskXMLParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".xml" {
		return false
	}

	// Check file content for Scheduled Task XML structure
	return p.detectScheduledTaskXML(filePath)
}

// detectScheduledTaskXML checks if file contains Scheduled Task XML structure
func (p *ScheduledTaskXMLParser) detectScheduledTaskXML(filePath string) bool {
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

	// Look for Scheduled Task XML markers
	hasTaskSchema := strings.Contains(content, "http://schemas.microsoft.com/windows/2004/02/mit/task")
	hasTaskElement := strings.Contains(content, "<Task") &&
		(strings.Contains(content, "<RegistrationInfo") || strings.Contains(content, "<Actions"))

	return hasTaskSchema || hasTaskElement
}

// Parse parses a Scheduled Task XML file and returns a slice of events
func (p *ScheduledTaskXMLParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read entire file for scheduled task (usually small)
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var task scheduledTask
	if err := xml.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("failed to parse scheduled task XML: %w", err)
	}

	events := p.convertScheduledTask(&task, filePath)

	fmt.Printf("Parsed Scheduled Task XML file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// convertScheduledTask converts a parsed Scheduled Task to core.Event(s)
func (p *ScheduledTaskXMLParser) convertScheduledTask(task *scheduledTask, filePath string) []*core.Event {
	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	source := filepath.Base(filePath)

	// Parse registration date for timestamp
	timestamp := time.Now().UTC()
	if task.RegistrationInfo.Date != "" {
		formats := []string{
			time.RFC3339,
			"2006-01-02T15:04:05",
			"2006-01-02T15:04:05.9999999",
		}
		for _, format := range formats {
			if parsed, err := time.Parse(format, task.RegistrationInfo.Date); err == nil {
				timestamp = parsed
				break
			}
		}
	}

	// Extract user from Author or Principal
	user := task.RegistrationInfo.Author
	if user == "" && len(task.Principals.Principal) > 0 {
		user = task.Principals.Principal[0].UserId
		if user == "" {
			user = task.Principals.Principal[0].GroupId
		}
	}

	// Create event for task registration
	regEvent := core.NewEvent(
		timestamp,
		source,
		"ScheduledTask:Registration",
		0,
		user,
		"",
		p.buildRegistrationMessage(task),
		filePath,
	)
	events = append(events, regEvent)

	// Create events for each action (forensically important)
	for i, exec := range task.Actions.Exec {
		actionEvent := core.NewEvent(
			timestamp,
			source,
			"ScheduledTask:Action",
			i+1,
			user,
			"",
			p.buildExecMessage(&exec, task.RegistrationInfo.URI),
			filePath,
		)
		events = append(events, actionEvent)
	}

	// Create events for COM handlers (potential persistence)
	for i, com := range task.Actions.ComHandler {
		comEvent := core.NewEvent(
			timestamp,
			source,
			"ScheduledTask:COMHandler",
			i+1,
			user,
			"",
			fmt.Sprintf("COM Handler ClassId: %s | Data: %s", com.ClassId, com.Data),
			filePath,
		)
		events = append(events, comEvent)
	}

	// Create events for triggers (useful for understanding persistence)
	triggerEvents := p.extractTriggerEvents(task, timestamp, source, user, filePath)
	events = append(events, triggerEvents...)

	return events
}

// buildRegistrationMessage creates a message for task registration
func (p *ScheduledTaskXMLParser) buildRegistrationMessage(task *scheduledTask) string {
	var parts []string

	if task.RegistrationInfo.URI != "" {
		parts = append(parts, fmt.Sprintf("URI: %s", task.RegistrationInfo.URI))
	}
	if task.RegistrationInfo.Author != "" {
		parts = append(parts, fmt.Sprintf("Author: %s", task.RegistrationInfo.Author))
	}
	if task.RegistrationInfo.Description != "" {
		desc := task.RegistrationInfo.Description
		if len(desc) > 100 {
			desc = desc[:97] + "..."
		}
		parts = append(parts, fmt.Sprintf("Description: %s", desc))
	}

	// Add run level from principal
	if len(task.Principals.Principal) > 0 {
		if task.Principals.Principal[0].RunLevel != "" {
			parts = append(parts, fmt.Sprintf("RunLevel: %s", task.Principals.Principal[0].RunLevel))
		}
	}

	// Add enabled status
	if task.Settings.Enabled != "" {
		parts = append(parts, fmt.Sprintf("Enabled: %s", task.Settings.Enabled))
	}
	if task.Settings.Hidden != "" {
		parts = append(parts, fmt.Sprintf("Hidden: %s", task.Settings.Hidden))
	}

	return strings.Join(parts, " | ")
}

// buildExecMessage creates a message for an Exec action
func (p *ScheduledTaskXMLParser) buildExecMessage(exec *taskExec, uri string) string {
	var parts []string

	if uri != "" {
		parts = append(parts, fmt.Sprintf("Task: %s", uri))
	}
	if exec.Command != "" {
		parts = append(parts, fmt.Sprintf("Command: %s", exec.Command))
	}
	if exec.Arguments != "" {
		args := exec.Arguments
		if len(args) > 200 {
			args = args[:197] + "..."
		}
		parts = append(parts, fmt.Sprintf("Arguments: %s", args))
	}
	if exec.WorkingDirectory != "" {
		parts = append(parts, fmt.Sprintf("WorkingDir: %s", exec.WorkingDirectory))
	}

	return strings.Join(parts, " | ")
}

// extractTriggerEvents creates events for each trigger type
func (p *ScheduledTaskXMLParser) extractTriggerEvents(task *scheduledTask, timestamp time.Time, source, user, filePath string) []*core.Event {
	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	eventID := 100 // Start trigger events at ID 100

	// Logon triggers
	for _, trigger := range task.Triggers.LogonTrigger {
		msg := fmt.Sprintf("Logon Trigger | Enabled: %s | StartBoundary: %s", trigger.Enabled, trigger.StartBoundary)
		if trigger.UserId != "" {
			msg += fmt.Sprintf(" | UserId: %s", trigger.UserId)
		}
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:LogonTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Boot triggers
	for _, trigger := range task.Triggers.BootTrigger {
		msg := fmt.Sprintf("Boot Trigger | Enabled: %s | Delay: %s", trigger.Enabled, trigger.Delay)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:BootTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Calendar triggers
	for _, trigger := range task.Triggers.CalendarTrigger {
		msg := fmt.Sprintf("Calendar Trigger | Enabled: %s | StartBoundary: %s", trigger.Enabled, trigger.StartBoundary)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:CalendarTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Time triggers
	for _, trigger := range task.Triggers.TimeTrigger {
		msg := fmt.Sprintf("Time Trigger | Enabled: %s | StartBoundary: %s", trigger.Enabled, trigger.StartBoundary)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:TimeTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Event triggers (often used in malware)
	for _, trigger := range task.Triggers.EventTrigger {
		msg := fmt.Sprintf("Event Trigger | Enabled: %s | Subscription: %s", trigger.Enabled, trigger.Subscription)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:EventTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Registration triggers
	for _, trigger := range task.Triggers.RegistrationTrigger {
		msg := fmt.Sprintf("Registration Trigger | Enabled: %s | StartBoundary: %s", trigger.Enabled, trigger.StartBoundary)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:RegistrationTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	// Idle triggers
	for _, trigger := range task.Triggers.IdleTrigger {
		msg := fmt.Sprintf("Idle Trigger | Enabled: %s | StartBoundary: %s", trigger.Enabled, trigger.StartBoundary)
		events = append(events, core.NewEvent(timestamp, source, "ScheduledTask:IdleTrigger", eventID, user, "", msg, filePath))
		eventID++
	}

	return events
}

// ============================================================================
// Sysmon XML Parser
// ============================================================================

// SysmonXMLParser implements the Parser interface for Sysmon configuration
// and exported Sysmon events in XML format
type SysmonXMLParser struct{}

// XML structures for Sysmon configuration
type sysmonConfig struct {
	XMLName           xml.Name          `xml:"Sysmon"`
	SchemaVersion     string            `xml:"schemaversion,attr"`
	HashAlgorithms    string            `xml:"HashAlgorithms>Hashing"`
	EventFiltering    sysmonEventFilter `xml:"EventFiltering"`
}

type sysmonEventFilter struct {
	RuleGroups []sysmonRuleGroup `xml:"RuleGroup"`
	// Direct rules (older config format)
	ProcessCreate      []sysmonRule `xml:"ProcessCreate"`
	FileCreateTime     []sysmonRule `xml:"FileCreateTime"`
	NetworkConnect     []sysmonRule `xml:"NetworkConnect"`
	ProcessTerminate   []sysmonRule `xml:"ProcessTerminate"`
	DriverLoad         []sysmonRule `xml:"DriverLoad"`
	ImageLoad          []sysmonRule `xml:"ImageLoad"`
	CreateRemoteThread []sysmonRule `xml:"CreateRemoteThread"`
	RawAccessRead      []sysmonRule `xml:"RawAccessRead"`
	ProcessAccess      []sysmonRule `xml:"ProcessAccess"`
	FileCreate         []sysmonRule `xml:"FileCreate"`
	RegistryEvent      []sysmonRule `xml:"RegistryEvent"`
	FileCreateStreamHash []sysmonRule `xml:"FileCreateStreamHash"`
	PipeEvent          []sysmonRule `xml:"PipeEvent"`
	WmiEvent           []sysmonRule `xml:"WmiEvent"`
	DnsQuery           []sysmonRule `xml:"DnsQuery"`
	FileDelete         []sysmonRule `xml:"FileDelete"`
	ClipboardChange    []sysmonRule `xml:"ClipboardChange"`
	ProcessTampering   []sysmonRule `xml:"ProcessTampering"`
	FileDeleteDetected []sysmonRule `xml:"FileDeleteDetected"`
}

type sysmonRuleGroup struct {
	Name           string       `xml:"name,attr"`
	GroupRelation  string       `xml:"groupRelation,attr"`
	ProcessCreate  []sysmonRule `xml:"ProcessCreate"`
	NetworkConnect []sysmonRule `xml:"NetworkConnect"`
	// Add other event types as needed
}

type sysmonRule struct {
	OnMatch   string            `xml:"onmatch,attr"`
	Condition []sysmonCondition `xml:",any"`
}

type sysmonCondition struct {
	XMLName   xml.Name `xml:""`
	Condition string   `xml:"condition,attr"`
	Value     string   `xml:",chardata"`
}

// CanParse checks if this parser can handle the given file
func (p *SysmonXMLParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".xml" {
		return false
	}

	// Check file content for Sysmon XML structure
	return p.detectSysmonXML(filePath)
}

// detectSysmonXML checks if file contains Sysmon XML structure
func (p *SysmonXMLParser) detectSysmonXML(filePath string) bool {
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

	// Look for Sysmon config markers
	hasSysmonRoot := strings.Contains(content, "<Sysmon")
	hasSysmonSchema := strings.Contains(content, "schemaversion")
	hasEventFiltering := strings.Contains(content, "<EventFiltering")

	// Or look for Sysmon event markers (Provider Name)
	hasSysmonProvider := strings.Contains(content, "Microsoft-Windows-Sysmon")

	return (hasSysmonRoot && (hasSysmonSchema || hasEventFiltering)) || hasSysmonProvider
}

// Parse parses a Sysmon XML file and returns a slice of events
func (p *SysmonXMLParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read first portion to determine file type
	buf := make([]byte, 4096)
	n, err := file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read file header: %w", err)
	}

	content := string(buf[:n])

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}

	// Determine if this is a config file or exported events
	if strings.Contains(content, "<Sysmon") && strings.Contains(content, "<EventFiltering") {
		return p.parseSysmonConfig(file, filePath)
	} else if strings.Contains(content, "Microsoft-Windows-Sysmon") || strings.Contains(content, "<Event") {
		return p.parseSysmonEvents(file, filePath)
	}

	return nil, fmt.Errorf("unable to determine Sysmon XML type")
}

// parseSysmonConfig parses a Sysmon configuration file
func (p *SysmonXMLParser) parseSysmonConfig(file *os.File, filePath string) ([]*core.Event, error) {
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var config sysmonConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse Sysmon config XML: %w", err)
	}

	events := p.convertSysmonConfig(&config, filePath)

	fmt.Printf("Parsed Sysmon Config XML file: %s (found %d configuration events)\n", filePath, len(events))
	return events, nil
}

// convertSysmonConfig converts a Sysmon configuration to events
func (p *SysmonXMLParser) convertSysmonConfig(config *sysmonConfig, filePath string) []*core.Event {
	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	source := filepath.Base(filePath)
	timestamp := time.Now().UTC()

	// Get file modification time as approximate config time
	if fi, err := os.Stat(filePath); err == nil {
		timestamp = fi.ModTime().UTC()
	}

	// Create event for overall config
	configEvent := core.NewEvent(
		timestamp,
		source,
		"SysmonConfig:Settings",
		0,
		"",
		"",
		fmt.Sprintf("Sysmon Configuration | SchemaVersion: %s | HashAlgorithms: %s",
			config.SchemaVersion, config.HashAlgorithms),
		filePath,
	)
	events = append(events, configEvent)

	// Track rule counts for summary
	eventID := 1
	ruleCount := 0

	// Process RuleGroups
	for _, rg := range config.EventFiltering.RuleGroups {
		for _, rule := range rg.ProcessCreate {
			events = append(events, p.createRuleEvent(timestamp, source, filePath, "ProcessCreate", rg.Name, rule, eventID))
			eventID++
			ruleCount++
		}
		for _, rule := range rg.NetworkConnect {
			events = append(events, p.createRuleEvent(timestamp, source, filePath, "NetworkConnect", rg.Name, rule, eventID))
			eventID++
			ruleCount++
		}
	}

	// Process direct rules (old format)
	directRules := map[string][]sysmonRule{
		"ProcessCreate":      config.EventFiltering.ProcessCreate,
		"NetworkConnect":     config.EventFiltering.NetworkConnect,
		"FileCreate":         config.EventFiltering.FileCreate,
		"RegistryEvent":      config.EventFiltering.RegistryEvent,
		"DnsQuery":           config.EventFiltering.DnsQuery,
		"ImageLoad":          config.EventFiltering.ImageLoad,
		"DriverLoad":         config.EventFiltering.DriverLoad,
		"ProcessAccess":      config.EventFiltering.ProcessAccess,
		"CreateRemoteThread": config.EventFiltering.CreateRemoteThread,
		"FileDelete":         config.EventFiltering.FileDelete,
	}

	for eventType, rules := range directRules {
		for _, rule := range rules {
			events = append(events, p.createRuleEvent(timestamp, source, filePath, eventType, "", rule, eventID))
			eventID++
			ruleCount++
		}
	}

	return events
}

// createRuleEvent creates an event from a Sysmon rule
func (p *SysmonXMLParser) createRuleEvent(timestamp time.Time, source, filePath, eventType, groupName string, rule sysmonRule, eventID int) *core.Event {
	var msgParts []string

	if groupName != "" {
		msgParts = append(msgParts, fmt.Sprintf("RuleGroup: %s", groupName))
	}
	msgParts = append(msgParts, fmt.Sprintf("OnMatch: %s", rule.OnMatch))

	// Extract conditions
	for _, cond := range rule.Condition {
		if cond.Value != "" {
			condStr := fmt.Sprintf("%s", cond.XMLName.Local)
			if cond.Condition != "" {
				condStr += fmt.Sprintf("[%s]", cond.Condition)
			}
			condStr += fmt.Sprintf("=%s", cond.Value)
			msgParts = append(msgParts, condStr)
		}
	}

	return core.NewEvent(
		timestamp,
		source,
		fmt.Sprintf("SysmonConfig:%s", eventType),
		eventID,
		"",
		"",
		strings.Join(msgParts, " | "),
		filePath,
	)
}

// parseSysmonEvents parses exported Sysmon events in Windows Event XML format
func (p *SysmonXMLParser) parseSysmonEvents(file *os.File, filePath string) ([]*core.Event, error) {
	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	source := filepath.Base(filePath)

	// Use streaming parser for potentially large event exports
	decoder := xml.NewDecoder(file)

	eventCount := 0
	errorCount := 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			errorCount++
			continue
		}

		if se, ok := token.(xml.StartElement); ok {
			if se.Name.Local == "Event" {
				var xmlEvent windowsXMLEvent
				if err := decoder.DecodeElement(&xmlEvent, &se); err != nil {
					errorCount++
					continue
				}

				// Only process Sysmon events
				if strings.Contains(xmlEvent.System.Provider.Name, "Sysmon") {
					event := p.convertSysmonEvent(&xmlEvent, source, filePath, eventCount+1)
					if event != nil {
						events = append(events, event)
						eventCount++
					}
				}
			}
		}
	}

	fmt.Printf("Parsed Sysmon Events XML file: %s (found %d events", filePath, len(events))
	if errorCount > 0 {
		fmt.Printf(", %d parse errors", errorCount)
	}
	fmt.Println(")")

	return events, nil
}

// convertSysmonEvent converts a parsed Sysmon XML event to core.Event
func (p *SysmonXMLParser) convertSysmonEvent(xmlEvent *windowsXMLEvent, source, filePath string, index int) *core.Event {
	if xmlEvent == nil {
		return nil
	}

	// Parse timestamp
	timestamp := time.Now().UTC()
	if xmlEvent.System.TimeCreated.SystemTime != "" {
		formats := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.9999999Z",
		}
		for _, format := range formats {
			if parsed, err := time.Parse(format, xmlEvent.System.TimeCreated.SystemTime); err == nil {
				timestamp = parsed
				break
			}
		}
	}

	// Map Sysmon Event IDs to event types
	eventType := p.getSysmonEventType(xmlEvent.System.EventID)

	// Extract user from EventData
	user := ""
	host := xmlEvent.System.Computer

	// Build message from EventData - extract Sysmon-specific fields
	message := p.buildSysmonMessage(xmlEvent)

	// Try to extract user from EventData
	for _, data := range xmlEvent.EventData.Data {
		if data.Name == "User" {
			user = strings.TrimSpace(data.Value)
			break
		}
	}

	return core.NewEvent(
		timestamp,
		source,
		eventType,
		xmlEvent.System.EventID,
		user,
		host,
		message,
		filePath,
	)
}

// getSysmonEventType maps Sysmon Event IDs to human-readable types
func (p *SysmonXMLParser) getSysmonEventType(eventID int) string {
	eventTypes := map[int]string{
		1:  "Sysmon:ProcessCreate",
		2:  "Sysmon:FileCreateTime",
		3:  "Sysmon:NetworkConnect",
		4:  "Sysmon:ServiceStateChange",
		5:  "Sysmon:ProcessTerminate",
		6:  "Sysmon:DriverLoad",
		7:  "Sysmon:ImageLoad",
		8:  "Sysmon:CreateRemoteThread",
		9:  "Sysmon:RawAccessRead",
		10: "Sysmon:ProcessAccess",
		11: "Sysmon:FileCreate",
		12: "Sysmon:RegistryCreate",
		13: "Sysmon:RegistrySetValue",
		14: "Sysmon:RegistryRename",
		15: "Sysmon:FileCreateStreamHash",
		16: "Sysmon:ConfigChange",
		17: "Sysmon:PipeCreated",
		18: "Sysmon:PipeConnected",
		19: "Sysmon:WmiFilter",
		20: "Sysmon:WmiConsumer",
		21: "Sysmon:WmiBinding",
		22: "Sysmon:DnsQuery",
		23: "Sysmon:FileDelete",
		24: "Sysmon:ClipboardChange",
		25: "Sysmon:ProcessTampering",
		26: "Sysmon:FileDeleteDetected",
		27: "Sysmon:FileBlockExecutable",
		28: "Sysmon:FileBlockShredding",
		255: "Sysmon:Error",
	}

	if eventType, ok := eventTypes[eventID]; ok {
		return eventType
	}
	return fmt.Sprintf("Sysmon:Event%d", eventID)
}

// buildSysmonMessage creates a message from Sysmon event data
func (p *SysmonXMLParser) buildSysmonMessage(xmlEvent *windowsXMLEvent) string {
	var parts []string

	// Key fields to extract based on event type
	keyFields := map[string]bool{
		"Image":              true,
		"CommandLine":        true,
		"ParentImage":        true,
		"ParentCommandLine":  true,
		"TargetFilename":     true,
		"DestinationIp":      true,
		"DestinationPort":    true,
		"DestinationHostname": true,
		"SourceIp":           true,
		"SourcePort":         true,
		"Hashes":             true,
		"TargetObject":       true,
		"QueryName":          true,
		"QueryResults":       true,
		"Signed":             true,
		"Signature":          true,
		"User":               true,
		"ProcessGuid":        true,
		"ProcessId":          true,
		"SourceProcessGuid":  true,
		"TargetProcessGuid":  true,
	}

	for _, data := range xmlEvent.EventData.Data {
		if data.Name != "" && data.Value != "" && keyFields[data.Name] {
			value := strings.TrimSpace(data.Value)
			// Truncate long values
			if len(value) > 150 {
				value = value[:147] + "..."
			}
			parts = append(parts, fmt.Sprintf("%s=%s", data.Name, value))
		}
	}

	if len(parts) == 0 {
		return fmt.Sprintf("Sysmon Event ID: %d", xmlEvent.System.EventID)
	}

	return strings.Join(parts, " | ")
}

// ============================================================================
// Generic XML Parser (fallback)
// ============================================================================

// GenericXMLParser implements the Parser interface for generic XML files
type GenericXMLParser struct{}

// CanParse checks if this parser can handle the given file
func (p *GenericXMLParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".xml"
}

// Parse parses a generic XML file and attempts to extract events
func (p *GenericXMLParser) Parse(filePath string) ([]*core.Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Pre-allocate slice with estimated capacity (avg 1KB per XML event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 1024))
	source := filepath.Base(filePath)

	// Get file modification time for timestamp
	timestamp := time.Now().UTC()
	if fi, err := os.Stat(filePath); err == nil {
		timestamp = fi.ModTime().UTC()
	}

	// Use streaming parser to extract elements
	decoder := xml.NewDecoder(file)
	elementCount := 0
	depth := 0
	var currentPath []string

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Try to continue on errors
			continue
		}

		switch t := token.(type) {
		case xml.StartElement:
			depth++
			currentPath = append(currentPath, t.Name.Local)

			// Create an event for each significant element (depth 2-3)
			if depth >= 2 && depth <= 3 {
				elementCount++

				// Extract attributes
				var attrs []string
				for _, attr := range t.Attr {
					attrs = append(attrs, fmt.Sprintf("%s=%s", attr.Name.Local, attr.Value))
				}

				message := fmt.Sprintf("Element: %s", strings.Join(currentPath, "/"))
				if len(attrs) > 0 {
					message += " | Attributes: " + strings.Join(attrs, ", ")
				}

				event := core.NewEvent(
					timestamp,
					source,
					"XMLElement",
					elementCount,
					"",
					"",
					message,
					filePath,
				)
				events = append(events, event)
			}

		case xml.EndElement:
			depth--
			if len(currentPath) > 0 {
				currentPath = currentPath[:len(currentPath)-1]
			}
		}

		// Limit events for very large files
		if elementCount >= 10000 {
			break
		}
	}

	fmt.Printf("Parsed Generic XML file: %s (found %d elements)\n", filePath, len(events))
	return events, nil
}

// ============================================================================
// Helper Functions for XML Parsing
// ============================================================================

// parseXMLTimestamp attempts to parse various XML timestamp formats
func parseXMLTimestamp(timeStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05.999999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
	}

	for _, format := range formats {
		if parsed, err := time.Parse(format, timeStr); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timeStr)
}

// detectXMLType attempts to identify the type of XML file from content
func detectXMLType(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() && lineCount < 20 {
		line := scanner.Text()
		lineCount++

		if strings.Contains(line, "http://schemas.microsoft.com/win/2004/08/events/event") {
			return "windows_event"
		}
		if strings.Contains(line, "http://schemas.microsoft.com/windows/2004/02/mit/task") {
			return "scheduled_task"
		}
		if strings.Contains(line, "<Sysmon") {
			return "sysmon_config"
		}
		if strings.Contains(line, "Microsoft-Windows-Sysmon") {
			return "sysmon_event"
		}
	}

	return "generic"
}

// getXMLIntAttribute extracts an integer attribute from an XML element
func getXMLIntAttribute(attrs []xml.Attr, name string) int {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			if val, err := strconv.Atoi(attr.Value); err == nil {
				return val
			}
		}
	}
	return 0
}

// getXMLStringAttribute extracts a string attribute from an XML element
func getXMLStringAttribute(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
