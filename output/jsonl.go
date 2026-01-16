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
	encoder     *json.Encoder // Reusable encoder for better performance
	recordCount int           // Track records written for batched flushing
}

// NewJSONLWriter creates a new JSON Lines writer
func NewJSONLWriter(outputPath string) (*JSONLWriter, error) {
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSONL file: %w", err)
	}

	// Use 64KB buffer for better I/O performance (default is 4KB)
	writer := bufio.NewWriterSize(file, 64*1024)

	// Create reusable encoder that writes directly to the buffered writer
	encoder := json.NewEncoder(writer)
	// Disable HTML escaping for better performance and cleaner output
	encoder.SetEscapeHTML(false)

	return &JSONLWriter{
		file:        file,
		writer:      writer,
		encoder:     encoder,
		recordCount: 0,
	}, nil
}

// Write writes the events to the JSON Lines file
func (w *JSONLWriter) Write(events []*core.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, event := range events {
		// Use the reusable encoder - it automatically adds newlines
		if err := w.encoder.Encode(event); err != nil {
			return fmt.Errorf("failed to encode event to JSON: %w", err)
		}

		w.recordCount++

		// Flush every 10000 records to reduce syscall overhead
		// With 64KB buffer, this mostly happens automatically via buffer overflow
		if w.recordCount%10000 == 0 {
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
