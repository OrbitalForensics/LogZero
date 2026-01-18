package output

import (
	"errors"
	"fmt"
	"strings"

	"LogZero/core"
)

// Common errors
var (
	ErrUnsupportedFormat = errors.New("unsupported output format")
	ErrWritingFailed     = errors.New("failed to write output")
)

// Writer defines the interface for all output writers
type Writer interface {
	// Write writes the events to the output
	Write(events []*core.Event) error
	
	// Close closes the writer and performs any necessary cleanup
	Close() error
}

// GetWriter returns the appropriate writer for the given format
func GetWriter(format, outputPath string) (Writer, error) {
	format = strings.ToLower(format)
	
	switch format {
	case "csv":
		return NewCSVWriter(outputPath)
	case "jsonl":
		return NewJSONLWriter(outputPath)
	case "sqlite":
		return NewSQLiteWriter(outputPath)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
}