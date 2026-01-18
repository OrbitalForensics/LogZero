package processor

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"LogZero/core"
	"LogZero/output"
	"LogZero/parsers"
)

// Progress represents the current progress of processing
type Progress struct {
	FilesProcessed  int
	EventsProcessed int
}

// Processor handles the concurrent processing of files
type Processor struct {
	numWorkers           int
	writer               output.Writer
	totalEventsProcessed int64 // Total number of events processed
}

// NewProcessor creates a new processor with the specified number of workers
func NewProcessor(writer output.Writer, numWorkers int) *Processor {
	// If numWorkers is not specified, use the number of CPU cores
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	return &Processor{
		numWorkers:           numWorkers,
		writer:               writer,
		totalEventsProcessed: 0,
	}
}

// ProcessPath processes a file or directory path
func (p *Processor) ProcessPath(inputPath string) error {
	// Use ProcessPathWithContext with a background context
	return p.ProcessPathWithContext(context.Background(), inputPath, nil, 0, "")
}

// ProcessPathWithContext processes a file or directory path with context and progress reporting
func (p *Processor) ProcessPathWithContext(ctx context.Context, inputPath string, progressChan chan<- Progress, bufferSize int, filterPattern string) error {
	// Check if the input path exists
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to access input path: %w", err)
	}

	// Pre-compile regex pattern if specified (do this once, not per-file)
	var filterRegex *regexp.Regexp
	if filterPattern != "" {
		var compileErr error
		filterRegex, compileErr = regexp.Compile(filterPattern)
		if compileErr != nil {
			return fmt.Errorf("invalid filter pattern: %w", compileErr)
		}
	}

	// Process a single file or a directory
	if !info.IsDir() {
		return p.processFileWithContext(ctx, inputPath, progressChan, filterRegex)
	}

	// Process a directory
	return p.processDirectoryWithContext(ctx, inputPath, progressChan, bufferSize, filterPattern)
}

// processFile processes a single file
func (p *Processor) processFile(filePath string) error {
	// Use processFileWithContext with a background context
	return p.processFileWithContext(context.Background(), filePath, nil, nil)
}

// processFileWithContext processes a single file with context and progress reporting
// filterRegex should be pre-compiled by the caller for performance
func (p *Processor) processFileWithContext(ctx context.Context, filePath string, progressChan chan<- Progress, filterRegex *regexp.Regexp) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Continue processing
	}

	// Get the appropriate parser for the file
	parser, err := parsers.GetParserForFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to get parser for file %s: %w", filePath, err)
	}

	// Parse the file
	events, err := parser.Parse(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}

	// Apply filter if specified (using pre-compiled regex)
	if filterRegex != nil {
		filteredEvents := make([]*core.Event, 0, len(events))
		for _, event := range events {
			// Simple string matching for now
			if filterRegex.MatchString(event.User) || filterRegex.MatchString(event.Host) ||
				filterRegex.MatchString(event.Message) || filterRegex.MatchString(event.Source) {
				filteredEvents = append(filteredEvents, event)
			}
		}
		events = filteredEvents
	}

	// Sort events chronologically
	sort.Sort(core.Events(events))

	// Write events to output
	if err := p.writer.Write(events); err != nil {
		return fmt.Errorf("failed to write events: %w", err)
	}

	// Update total events processed
	atomic.AddInt64(&p.totalEventsProcessed, int64(len(events)))

	// Report progress if channel is provided
	if progressChan != nil {
		progressChan <- Progress{
			FilesProcessed:  1,
			EventsProcessed: len(events),
		}
	}

	return nil
}

// processDirectory processes a directory recursively
func (p *Processor) processDirectory(dirPath string) error {
	// Use processDirectoryWithContext with a background context
	return p.processDirectoryWithContext(context.Background(), dirPath, nil, 0, "")
}

// ProcessingErrors collects multiple errors that occurred during processing
type ProcessingErrors struct {
	Errors []error
	mu     sync.Mutex
}

// Add adds an error to the collection
func (pe *ProcessingErrors) Add(err error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.Errors = append(pe.Errors, err)
}

// HasErrors returns true if any errors were collected
func (pe *ProcessingErrors) HasErrors() bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return len(pe.Errors) > 0
}

// Error implements the error interface
func (pe *ProcessingErrors) Error() string {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if len(pe.Errors) == 0 {
		return ""
	}
	if len(pe.Errors) == 1 {
		return pe.Errors[0].Error()
	}
	return fmt.Sprintf("%d errors occurred during processing; first error: %v", len(pe.Errors), pe.Errors[0])
}

// Count returns the number of errors
func (pe *ProcessingErrors) Count() int {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return len(pe.Errors)
}

// processDirectoryWithContext processes a directory recursively with context and progress reporting
func (p *Processor) processDirectoryWithContext(ctx context.Context, dirPath string, progressChan chan<- Progress, bufferSize int, filterPattern string) error {
	// Use default buffer size if not specified
	if bufferSize <= 0 {
		bufferSize = 100
	}

	// Create a channel for file paths
	filesChan := make(chan string, bufferSize)

	// Create a thread-safe error collector instead of channel to avoid deadlock
	processingErrors := &ProcessingErrors{}

	// Create atomic counters for progress reporting
	var filesProcessed int64
	var eventsProcessed int64
	var filesSkipped int64

	// Create a wait group for workers
	var wg sync.WaitGroup

	// Create a context that can be cancelled
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	// Pre-compile regex pattern if specified (do this once, not in each worker)
	var filterRegex *regexp.Regexp
	if filterPattern != "" {
		var err error
		filterRegex, err = regexp.Compile(filterPattern)
		if err != nil {
			return fmt.Errorf("invalid filter pattern: %w", err)
		}
	}

	// Start worker goroutines
	for i := 0; i < p.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Check for context cancellation
				select {
				case <-workerCtx.Done():
					return
				case filePath, ok := <-filesChan:
					if !ok {
						return
					}

					// Try to get a parser for the file
					parser, err := parsers.GetParserForFile(filePath)
					if err != nil {
						// Skip files that don't have a parser
						if err == parsers.ErrUnsupportedFormat {
							atomic.AddInt64(&filesSkipped, 1)
							continue
						}
						processingErrors.Add(fmt.Errorf("failed to get parser for file %s: %w", filePath, err))
						continue
					}

					// Parse the file
					events, err := parser.Parse(filePath)
					if err != nil {
						processingErrors.Add(fmt.Errorf("failed to parse file %s: %w", filePath, err))
						continue
					}

					// Apply filter if specified (use pre-compiled regex)
					if filterRegex != nil {
						filteredEvents := make([]*core.Event, 0, len(events))
						for _, event := range events {
							// Simple string matching for now
							if filterRegex.MatchString(event.User) || filterRegex.MatchString(event.Host) ||
								filterRegex.MatchString(event.Message) || filterRegex.MatchString(event.Source) {
								filteredEvents = append(filteredEvents, event)
							}
						}
						events = filteredEvents
					}

					// Sort events chronologically
					sort.Sort(core.Events(events))

					// Write events to output
					if err := p.writer.Write(events); err != nil {
						processingErrors.Add(fmt.Errorf("failed to write events from %s: %w", filePath, err))
						continue
					}

					// Update progress counters
					atomic.AddInt64(&filesProcessed, 1)
					atomic.AddInt64(&eventsProcessed, int64(len(events)))

					// Update total events processed
					atomic.AddInt64(&p.totalEventsProcessed, int64(len(events)))

					// Report progress if channel is provided
					if progressChan != nil {
						select {
						case progressChan <- Progress{
							FilesProcessed:  int(atomic.LoadInt64(&filesProcessed)),
							EventsProcessed: int(atomic.LoadInt64(&eventsProcessed)),
						}:
						default:
							// Don't block if channel is full
						}
					}

					log.Printf("Processed file: %s (%d events)", filePath, len(events))
				}
			}
		}()
	}

	// Walk the directory and send file paths to the channel
	var walkErr error
	walkErr = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Continue processing
		}

		if err != nil {
			// Log but don't fail on individual file errors during walk
			log.Printf("Warning: error accessing %s: %v", path, err)
			return nil
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Send file path to channel (with cancellation support)
		select {
		case filesChan <- path:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})

	// Close the files channel when done
	close(filesChan)

	// Wait for all workers to finish
	wg.Wait()

	// Check for walk errors first
	if walkErr != nil && walkErr != context.Canceled {
		return fmt.Errorf("failed to walk directory: %w", walkErr)
	}

	// Check for context cancellation
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Log summary
	log.Printf("Processing complete: %d files processed, %d skipped, %d errors",
		atomic.LoadInt64(&filesProcessed),
		atomic.LoadInt64(&filesSkipped),
		processingErrors.Count())

	// Return accumulated errors if any
	if processingErrors.HasErrors() {
		return processingErrors
	}

	return nil
}

// GetTotalEventsProcessed returns the total number of events processed
func (p *Processor) GetTotalEventsProcessed() int {
	return int(atomic.LoadInt64(&p.totalEventsProcessed))
}
