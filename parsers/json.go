package parsers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LogZero/core"
)

// JsonParser implements the Parser interface for JSON files
type JsonParser struct{}

// CanParse checks if this parser can handle the given file
func (p *JsonParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".json"
}

// Parse parses a JSON file and returns a slice of events
func (p *JsonParser) Parse(filePath string) ([]*core.Event, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Pre-allocate slice with estimated capacity (avg 500 bytes per JSON event)
	events := make([]*core.Event, 0, estimateLineCapacity(filePath, 500))
	decoder := json.NewDecoder(file)

	// Check the first token to see if it's an array or object
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to read first token: %w", err)
	}

	// Helper function to process a single raw event
	processEvent := func(rawEvent map[string]interface{}) {
		// Extract fields from the raw event with safe type assertions
		timestamp := time.Now().UTC() // Default to current time

		// Safely extract timestamp
		if tsVal, ok := rawEvent["timestamp"]; ok {
			if tsStr, ok := tsVal.(string); ok {
				if parsedTime, err := time.Parse(time.RFC3339, tsStr); err == nil {
					timestamp = parsedTime
				}
			}
		}

		source := filepath.Base(filePath)

		eventType := "Unknown"
		if val, ok := rawEvent["event_type"].(string); ok {
			eventType = val
		}

		eventID := 0
		if val, ok := rawEvent["event_id"].(float64); ok {
			eventID = int(val)
		} else if val, ok := rawEvent["event_id"].(int); ok {
			eventID = val
		}

		user := ""
		if val, ok := rawEvent["user"].(string); ok {
			user = val
		}

		host := ""
		if val, ok := rawEvent["host"].(string); ok {
			host = val
		}

		message := ""
		if val, ok := rawEvent["message"].(string); ok {
			message = val
		}

		path := filePath

		// Create a new event
		event := core.NewEvent(
			timestamp,
			source,
			eventType,
			eventID,
			user,
			host,
			message,
			path,
		)

		events = append(events, event)
	}

	if delim, ok := token.(json.Delim); ok && delim == '[' {
		// It's an array, iterate through elements
		for decoder.More() {
			var rawEvent map[string]interface{}
			if err := decoder.Decode(&rawEvent); err != nil {
				// Log error but try to continue (don't include file path in log)
				log.Printf("Warning: skipping malformed JSON event: %v", err)
				continue
			}
			processEvent(rawEvent)
		}

		// Consume closing bracket
		if _, err := decoder.Token(); err != nil {
			// Just log, not fatal if we got the data
			log.Printf("Warning: error reading JSON closing bracket: %v", err)
		}
	} else if delim, ok := token.(json.Delim); ok && delim == '{' {
		// It's a single object (or maybe NDJSON/JSONL if we supported that here, but for now assume single object)
		// We already consumed the opening brace, so we need to decode the rest into a map
		// But decoder.Decode expects the full value.
		// Since we consumed '{', we can't easily use Decode(&map) directly on the *rest* without hacks.
		// A better approach for single object:
		// Re-create a new decoder with a MultiReader that puts the '{' back, OR just handle it.

		// Actually, standard library decoder doesn't support "unreading" a token easily for Decode.
		// Strategy: Create a new decoder from the start of file for the single object case.
		// This is rare (usually logs are arrays or lines), so seeking back is acceptable.

		if _, err := file.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("cannot seek file to parse single object: %w", err)
		}

		decoder = json.NewDecoder(file)
		var rawEvent map[string]interface{}
		if err := decoder.Decode(&rawEvent); err != nil {
			return nil, fmt.Errorf("failed to decode single JSON object: %w", err)
		}
		processEvent(rawEvent)
	} else {
		return nil, fmt.Errorf("unexpected JSON structure: starts with %v", token)
	}

	log.Printf("Parsed JSON file: %s (found %d events)", filepath.Base(filePath), len(events))
	return events, nil
}
