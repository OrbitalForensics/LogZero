package core

import (
	"time"
)

// Event represents a normalized timeline event
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	EventType string    `json:"event_type"`
	EventID   int       `json:"event_id"`
	User      string    `json:"user"`
	Host      string    `json:"host"`
	Message   string    `json:"message"`
	Path      string    `json:"path"`
	// Additional fields for future AI use
	Tags    []string `json:"tags,omitempty"`
	Score   float64  `json:"score,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

// NewEvent creates a new timeline event with the given parameters
func NewEvent(
	timestamp time.Time,
	source string,
	eventType string,
	eventID int,
	user string,
	host string,
	message string,
	path string,
) *Event {
	return &Event{
		Timestamp: timestamp,
		Source:    source,
		EventType: eventType,
		EventID:   eventID,
		User:      user,
		Host:      host,
		Message:   message,
		Path:      path,
		Tags:      []string{},
		Score:     0.0,
		Summary:   "",
	}
}

// Events is a slice of Event pointers that can be sorted by timestamp
type Events []*Event

// Implement sort.Interface for Events
func (e Events) Len() int           { return len(e) }
func (e Events) Less(i, j int) bool { return e[i].Timestamp.Before(e[j].Timestamp) }
func (e Events) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }