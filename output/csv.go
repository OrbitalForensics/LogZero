package output

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"LogZero/core"
)

// CSVWriter implements the Writer interface for CSV output
type CSVWriter struct {
	mu          sync.Mutex
	file        *os.File
	bufWriter   *bufio.Writer
	writer      *csv.Writer
	recordCount int // Track records written for batched flushing
}

// NewCSVWriter creates a new CSV writer
func NewCSVWriter(outputPath string) (*CSVWriter, error) {
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	// Use 64KB buffer for better I/O performance
	bufWriter := bufio.NewWriterSize(file, 64*1024)
	writer := csv.NewWriter(bufWriter)

	// Write header row
	header := []string{
		"timestamp",
		"source",
		"event_type",
		"event_id",
		"user",
		"host",
		"message",
		"path",
		"tags",
		"score",
		"summary",
	}

	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	return &CSVWriter{
		file:        file,
		bufWriter:   bufWriter,
		writer:      writer,
		recordCount: 0,
	}, nil
}

// Write writes the events to the CSV file
func (w *CSVWriter) Write(events []*core.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, event := range events {
		// Convert event to CSV record
		record := []string{
			event.Timestamp.Format("2006-01-02T15:04:05Z07:00"), // RFC3339 format
			event.Source,
			event.EventType,
			strconv.Itoa(event.EventID),
			event.User,
			event.Host,
			event.Message,
			event.Path,
			formatTags(event.Tags),
			strconv.FormatFloat(event.Score, 'f', 2, 64),
			event.Summary,
		}

		if err := w.writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}

		w.recordCount++

		// Flush every 10000 records to reduce syscall overhead
		if w.recordCount%10000 == 0 {
			w.writer.Flush()
			if err := w.writer.Error(); err != nil {
				return fmt.Errorf("failed to flush CSV writer: %w", err)
			}
		}
	}

	return nil
}

// Close closes the CSV writer
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Flush the CSV writer first
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		w.file.Close()
		return fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	// Flush the buffer writer
	if err := w.bufWriter.Flush(); err != nil {
		w.file.Close()
		return fmt.Errorf("failed to flush buffer: %w", err)
	}

	return w.file.Close()
}

// formatTags formats a slice of tags as a comma-separated string
func formatTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}

	// Use strings.Join for efficient concatenation
	return strings.Join(tags, ",")
}
