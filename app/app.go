package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"LogZero/internal/logger"
	"LogZero/internal/processor"
	"LogZero/output"
)

// ProcessStatus represents the status of the processing operation
type ProcessStatus struct {
	Status       string `json:"status"`
	ParsedEvents int    `json:"parsed_events"`
	DurationMs   int64  `json:"duration_ms"`
	Error        string `json:"error,omitempty"`
}

// ProgressCallback is a function that receives progress updates
type ProgressCallback func(filesProcessed, totalFiles, eventsProcessed int)

// App represents the LogZero application
type App struct {
	Config *Config
	proc   *processor.Processor
	writer output.Writer
}

// New creates a new LogZero application instance
func New(config *Config) *App {
	return &App{
		Config: config,
	}
}

// Initialize initializes the application
func (a *App) Initialize() error {
	// Initialize logger
	logger.Init(a.Config.Verbose, a.Config.Silent)

	// Log startup information
	logger.Info("LogZero initializing...")
	logger.Info("Input path: %s", a.Config.InputPath)
	logger.Info("Output path: %s", a.Config.OutputPath)
	logger.Info("Format: %s", a.Config.Format)

	// Validate input path
	if err := a.validateInputPath(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// Validate output path
	if err := a.validateOutputPath(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOutput, err)
	}

	// Create output writer
	var err error
	a.writer, err = output.GetWriter(a.Config.Format, a.Config.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output writer: %w", err)
	}

	// Create processor with configured number of workers
	a.proc = processor.NewProcessor(a.writer, a.Config.Workers)

	return nil
}

// Process processes the input path and writes the results to the output path
func (a *App) Process(ctx context.Context, progressCallback ProgressCallback) (*ProcessStatus, error) {
	startTime := time.Now()

	// Count files if processing a directory
	var totalFiles int
	inputInfo, _ := os.Stat(a.Config.InputPath)
	if inputInfo.IsDir() {
		var err error
		totalFiles, err = a.countFiles(a.Config.InputPath)
		if err != nil {
			logger.Warn("Failed to count files: %v", err)
		} else {
			logger.Info("Found %d files to process", totalFiles)
		}
	}

	// Create a progress channel
	progressChan := make(chan processor.Progress, 10)
	defer close(progressChan)

	// Start a goroutine to handle progress updates
	if progressCallback != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case progress, ok := <-progressChan:
					if !ok {
						return
					}
					progressCallback(progress.FilesProcessed, totalFiles, progress.EventsProcessed)
				}
			}
		}()
	}

	// Process with context and progress reporting
	err := a.proc.ProcessPathWithContext(ctx, a.Config.InputPath, progressChan, a.Config.BufferSize, a.Config.FilterPattern)

	// Check for errors or cancellation
	if err != nil {
		if ctx.Err() == context.Canceled {
			logger.Info("Processing was interrupted")
			return &ProcessStatus{
				Status:       "interrupted",
				ParsedEvents: a.proc.GetTotalEventsProcessed(),
				DurationMs:   time.Since(startTime).Milliseconds(),
				Error:        "Processing was interrupted",
			}, ctx.Err()
		}
		logger.Error("Failed to process input path: %v", err)
		return &ProcessStatus{
			Status:       "error",
			ParsedEvents: a.proc.GetTotalEventsProcessed(),
			DurationMs:   time.Since(startTime).Milliseconds(),
			Error:        err.Error(),
		}, err
	}

	// Log completion information
	duration := time.Since(startTime)
	logger.Info("Processing completed in %v", duration)

	// Return status
	return &ProcessStatus{
		Status:       "success",
		ParsedEvents: a.proc.GetTotalEventsProcessed(),
		DurationMs:   duration.Milliseconds(),
	}, nil
}

// Cleanup performs cleanup operations
func (a *App) Cleanup() error {
	if a.writer != nil {
		return a.writer.Close()
	}
	return nil
}

// validateInputPath validates the input path
func (a *App) validateInputPath() error {
	_, err := os.Stat(a.Config.InputPath)
	return err
}

// validateOutputPath validates the output path
func (a *App) validateOutputPath() error {
	outputDir := filepath.Dir(a.Config.OutputPath)
	if _, err := os.Stat(outputDir); err != nil {
		if os.IsNotExist(err) {
			// Try to create the output directory
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
			return nil
		}
		return err
	}
	return nil
}

// countFiles counts the number of files in a directory recursively
func (a *App) countFiles(dirPath string) (int, error) {
	count := 0
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}
