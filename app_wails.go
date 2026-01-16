package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"LogZero/internal/processor"
	"LogZero/output"
)

// App struct for Wails bindings
type App struct {
	ctx          context.Context
	cancelFunc   context.CancelFunc
	isProcessing bool
	mu           sync.Mutex
}

// NewApp creates a new App instance
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// SelectInputFiles opens a multi-file selection dialog
func (a *App) SelectInputFiles() ([]string, error) {
	return wailsruntime.OpenMultipleFilesDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Log Files",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "All Supported Files", Pattern: "*.*"},
			{DisplayName: "Event Logs", Pattern: "*.evtx"},
			{DisplayName: "Log Files", Pattern: "*.log;*.txt"},
			{DisplayName: "JSON Files", Pattern: "*.json;*.jsonl"},
			{DisplayName: "CSV Files", Pattern: "*.csv"},
			{DisplayName: "XML Files", Pattern: "*.xml"},
			{DisplayName: "SQLite Databases", Pattern: "*.sqlite;*.db"},
		},
	})
}

// SelectOutputFolder opens a folder selection dialog for output directory
func (a *App) SelectOutputFolder() (string, error) {
	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Output Directory",
	})
}

// StartProcessing begins processing logs from multiple files
func (a *App) StartProcessing(inputFiles []string, outputDir, format string) error {
	a.mu.Lock()
	if a.isProcessing {
		a.mu.Unlock()
		return fmt.Errorf("processing already in progress")
	}
	a.isProcessing = true
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel

	go a.runProcessingMultiple(ctx, inputFiles, outputDir, format)
	return nil
}

// StopProcessing stops the current processing
func (a *App) StopProcessing() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancelFunc != nil {
		a.cancelFunc()
		a.cancelFunc = nil
	}
	a.isProcessing = false
	return nil
}

// runProcessingMultiple performs log processing on multiple files
func (a *App) runProcessingMultiple(ctx context.Context, inputFiles []string, outputDir, format string) {
	defer func() {
		a.mu.Lock()
		a.isProcessing = false
		a.mu.Unlock()
	}()

	emit := func(event string, data interface{}) {
		wailsruntime.EventsEmit(a.ctx, event, data)
	}

	logError := func(msg string) { emit("error", msg) }
	logWarning := func(msg string) { emit("warning", msg) }

	if len(inputFiles) == 0 {
		logError("No input files selected")
		return
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logError(fmt.Sprintf("Cannot create output directory: %v", err))
		return
	}

	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	var ext string
	switch format {
	case "csv":
		ext = ".csv"
	case "sqlite":
		ext = ".db"
	default:
		ext = ".jsonl"
	}
	outputPath := filepath.Join(outputDir, fmt.Sprintf("timeline_%s%s", timestamp, ext))
	emit("log", fmt.Sprintf("Output file: %s", outputPath))

	// Create writer
	writer, err := output.GetWriter(format, outputPath)
	if err != nil {
		logError(fmt.Sprintf("Cannot create output writer: %v", err))
		return
	}
	defer writer.Close()

	emit("log", fmt.Sprintf("Processing %d files with %d workers", len(inputFiles), runtime.NumCPU()))

	// Progress tracking
	progressChan := make(chan processor.Progress, 100)
	startTime := time.Now()
	totalFiles := len(inputFiles)

	// Progress reporter goroutine
	go func() {
		for p := range progressChan {
			var percent float64
			if totalFiles > 0 {
				percent = float64(p.FilesProcessed) / float64(totalFiles) * 100
			}
			emit("progress", map[string]interface{}{
				"files":   p.FilesProcessed,
				"events":  p.EventsProcessed,
				"percent": percent,
			})
		}
	}()

	// Process each file
	proc := processor.NewProcessor(writer, runtime.NumCPU())

	for _, inputFile := range inputFiles {
		if ctx.Err() == context.Canceled {
			break
		}

		// Validate file exists
		if _, err := os.Stat(inputFile); err != nil {
			emit("warning", fmt.Sprintf("Skipping inaccessible file: %s", inputFile))
			continue
		}

		err = proc.ProcessPathWithContext(ctx, inputFile, progressChan, 100, "")
		if err != nil && ctx.Err() != context.Canceled {
			emit("warning", fmt.Sprintf("Error processing %s: %v", filepath.Base(inputFile), err))
		}
	}

	close(progressChan)

	if ctx.Err() == context.Canceled {
		logWarning("Processing cancelled by user")
		return
	}

	elapsed := time.Since(startTime)
	total := proc.GetTotalEventsProcessed()

	emit("log", fmt.Sprintf("Completed: %d events processed in %v", total, elapsed.Round(time.Millisecond)))

	// Final progress update
	emit("progress", map[string]interface{}{
		"files":   totalFiles,
		"events":  total,
		"percent": 100.0,
	})

	emit("complete", nil)
}
