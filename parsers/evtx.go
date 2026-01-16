package parsers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"

	"LogZero/core"
)

// Local path definitions for EVTX elements not in the library
var (
	ComputerPath = evtx.Path("/Event/System/Computer")
	ProviderPath = evtx.Path("/Event/System/Provider/Name")
	LevelPath    = evtx.Path("/Event/System/Level")
)

// EvtxParser implements the Parser interface for Windows Event Log (.evtx) files
type EvtxParser struct{}

// CanParse checks if this parser can handle the given file
func (p *EvtxParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".evtx"
}

// Parse parses an EVTX file and returns a slice of events
func (p *EvtxParser) Parse(filePath string) ([]*core.Event, error) {
	// Open the EVTX file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open EVTX file: %w", err)
	}
	defer file.Close()

	// Parse the EVTX file
	ef, err := evtx.New(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EVTX file: %w", err)
	}

	// Pre-allocate slice with estimated capacity (avg 2KB per EVTX event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 2048))
	source := filepath.Base(filePath)

	// Iterate through all events in the EVTX file
	for e := range ef.FastEvents() {
		// Extract event data from the golang-evtx event structure
		event := p.convertEvtxEvent(e, source, filePath)
		if event != nil {
			events = append(events, event)
		}
	}

	fmt.Printf("Parsed EVTX file: %s (found %d events)\n", filePath, len(events))
	return events, nil
}

// convertEvtxEvent converts a golang-evtx event to our core.Event type
func (p *EvtxParser) convertEvtxEvent(e *evtx.GoEvtxMap, source, filePath string) *core.Event {
	if e == nil {
		return nil
	}

	// Extract timestamp
	timestamp := time.Now().UTC()
	if systemTime, err := e.GetTime(&evtx.SystemTimePath); err == nil {
		timestamp = systemTime
	}

	// Extract Event ID
	eventID := 0
	if eid, err := e.GetInt(&evtx.EventIDPath); err == nil {
		eventID = int(eid)
	}

	// Extract computer (host) name
	host := ""
	if computer, err := e.GetString(&ComputerPath); err == nil {
		host = computer
	}

	// Extract provider/channel as event type
	eventType := "WindowsEvent"
	if channel, err := e.GetString(&evtx.ChannelPath); err == nil {
		eventType = channel
	}

	// Extract user information if available
	user := ""
	if userID, err := e.GetString(&evtx.UserIDPath); err == nil {
		user = userID
	}

	// Build message from event data
	message := p.buildEventMessage(e, eventID)

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

// buildEventMessage creates a human-readable message from event data
func (p *EvtxParser) buildEventMessage(e *evtx.GoEvtxMap, eventID int) string {
	// Try to get task category or level for additional context
	level := ""
	if lvl, err := e.GetString(&LevelPath); err == nil {
		level = lvl
	}

	// Try to extract EventData content for detailed message
	message := fmt.Sprintf("Event ID: %d", eventID)
	if level != "" {
		message = fmt.Sprintf("[%s] %s", level, message)
	}

	// Try to get provider name for context
	if provider, err := e.GetString(&ProviderPath); err == nil {
		message = fmt.Sprintf("%s (Provider: %s)", message, provider)
	}

	return message
}
