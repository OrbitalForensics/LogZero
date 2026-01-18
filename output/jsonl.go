package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"LogZero/core"
)

// JSONLWriter implements the Writer interface for JSON Lines output
type JSONLWriter struct {
	mu          sync.Mutex
	file        *os.File
	writer      *bufio.Writer
	recordCount int // Track records written for batched flushing
}

// NewJSONLWriter creates a new JSON Lines writer
func NewJSONLWriter(outputPath string) (*JSONLWriter, error) {
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSONL file: %w", err)
	}

	writer := bufio.NewWriter(file)

	return &JSONLWriter{
		file:        file,
		writer:      writer,
		recordCount: 0,
	}, nil
}

// Write writes the events to the JSON Lines file
func (w *JSONLWriter) Write(events []*core.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, event := range events {
		// Marshal event to JSON
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event to JSON: %w", err)
		}

		// Write JSON line
		if _, err := w.writer.Write(data); err != nil {
			return fmt.Errorf("failed to write JSON line: %w", err)
		}

		// Write newline
		if err := w.writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}

		w.recordCount++

		// Flush every 100 records for better performance
		if w.recordCount%100 == 0 {
			if err := w.writer.Flush(); err != nil {
				return fmt.Errorf("failed to flush JSONL writer: %w", err)
			}
		}
	}

	return nil
}

// Close closes the JSON Lines writer
func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush JSONL writer: %w", err)
	}

	return w.file.Close()
}
