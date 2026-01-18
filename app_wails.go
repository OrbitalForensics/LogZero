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
	"LogZero/parsers"
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

// SelectInputFolder opens a folder selection dialog
func (a *App) SelectInputFolder() (string, error) {
	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Input Folder",
	})
}

// SelectOutputFile opens a file save dialog based on format
func (a *App) SelectOutputFile(format string) (string, error) {
	var filters []wailsruntime.FileFilter

	switch format {
	case "csv":
		filters = []wailsruntime.FileFilter{{DisplayName: "CSV Files", Pattern: "*.csv"}}
	case "sqlite":
		filters = []wailsruntime.FileFilter{{DisplayName: "SQLite Database", Pattern: "*.db"}}
	default:
		filters = []wailsruntime.FileFilter{{DisplayName: "JSONL Files", Pattern: "*.jsonl"}}
	}

	return wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:   "Save Output File",
		Filters: filters,
	})
}

// StartProcessing begins processing logs
func (a *App) StartProcessing(inputPath, outputPath, format string) error {
	a.mu.Lock()
	if a.isProcessing {
		a.mu.Unlock()
		return fmt.Errorf("processing already in progress")
	}
	a.isProcessing = true
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel

	go a.runProcessing(ctx, inputPath, outputPath, format)
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

// runProcessing performs the actual log processing
func (a *App) runProcessing(ctx context.Context, inputPath, outputPath, format string) {
	defer func() {
		a.mu.Lock()
		a.isProcessing = false
		a.mu.Unlock()
	}()

	emit := func(event string, data interface{}) {
		wailsruntime.EventsEmit(a.ctx, event, data)
	}

	log := func(msg string) { emit("log", msg) }
	logError := func(msg string) { emit("error", msg) }
	logWarning := func(msg string) { emit("warning", msg) }

	// Validate input
	info, err := os.Stat(inputPath)
	if err != nil {
		logError(fmt.Sprintf("Cannot access input path: %v", err))
		return
	}

	// Create output directory
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		logError(fmt.Sprintf("Cannot create output directory: %v", err))
		return
	}

	// Create writer
	writer, err := output.GetWriter(format, outputPath)
	if err != nil {
		logError(fmt.Sprintf("Cannot create output writer: %v", err))
		return
	}
	defer writer.Close()

	log(fmt.Sprintf("Starting with %d workers", runtime.NumCPU()))

	// Count files for progress
	var totalFiles int
	if info.IsDir() {
		filepath.Walk(inputPath, func(path string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				if _, e := parsers.GetParserForFile(path); e == nil {
					totalFiles++
				}
			}
			return nil
		})
		log(fmt.Sprintf("Found %d parseable files", totalFiles))
	} else {
		totalFiles = 1
	}

	// Progress tracking
	progressChan := make(chan processor.Progress, 100)
	startTime := time.Now()

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

	// Run processor
	proc := processor.NewProcessor(writer, runtime.NumCPU())
	err = proc.ProcessPathWithContext(ctx, inputPath, progressChan, 100, "")
	close(progressChan)

	if ctx.Err() == context.Canceled {
		logWarning("Processing cancelled by user")
		return
	}

	if err != nil {
		logError(fmt.Sprintf("Processing error: %v", err))
		return
	}

	elapsed := time.Since(startTime)
	total := proc.GetTotalEventsProcessed()

	log(fmt.Sprintf("Completed: %d events processed in %v", total, elapsed.Round(time.Millisecond)))

	// Final progress update
	emit("progress", map[string]interface{}{
		"files":   totalFiles,
		"events":  total,
		"percent": 100.0,
	})

	emit("complete", nil)
}
