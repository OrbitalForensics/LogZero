package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"LogZero/api"
	"LogZero/app"
	"LogZero/internal/logger"
	"LogZero/internal/logrotate"
	"LogZero/internal/retry"
	"LogZero/internal/securestorage"
)

//go:embed all:frontend/dist
var assets embed.FS

// getAssets returns the frontend assets with the correct subdirectory
func getAssets() fs.FS {
	fsys, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		panic(err)
	}
	return fsys
}

// Exit codes
const (
	ExitSuccess     = 0
	ExitErrorServer = 6
)

// Command-line flags
var (
	// Common flags
	logFile              = flag.String("log-file", "", "Path to log file (if empty, logs to stdout)")
	logMaxSize           = flag.Int("log-max-size", 100, "Maximum size of log file in megabytes before rotation")
	logMaxAge            = flag.Int("log-max-age", 7, "Maximum age of log file in days before rotation")
	logMaxBackups        = flag.Int("log-max-backups", 5, "Maximum number of old log files to retain")
	logCompress          = flag.Bool("log-compress", true, "Compress rotated log files")

	// API server flags
	apiOnly              = flag.Bool("api-only", false, "Run in API server mode only (no GUI)")
	apiPort              = flag.Int("port", 8765, "Port to use for API server")
	shutdownTimeout      = flag.Int("shutdown-timeout", 15, "Timeout in seconds for graceful shutdown")
	cleanupThreshold     = flag.Int("cleanup-threshold", 24, "Threshold in hours for cleaning up stale connection files")
	cleanupInterval      = flag.Int("cleanup-interval", 1, "Interval in hours for periodic cleanup of stale connection files")
	retryMaxAttempts     = flag.Int("retry-max-attempts", 5, "Maximum number of retry attempts for file operations")
	retryInitialBackoff  = flag.Int("retry-initial-backoff", 100, "Initial backoff in milliseconds for retry operations")
	retryMaxBackoff      = flag.Int("retry-max-backoff", 5000, "Maximum backoff in milliseconds for retry operations")
	useSecureStorage     = flag.Bool("use-secure-storage", false, "Use platform-specific secure storage for connection info (disabled by default)")

	// Processing flags
	inputPath            = flag.String("input", "", "Path to input file or directory")
	outputPath           = flag.String("output", "", "Path to output file")
	format               = flag.String("format", "jsonl", "Output format (csv, jsonl, sqlite)")
)

func main() {
	// Parse basic flags
	flag.Parse()

	// Initialize logger
	initLogger()

	// Check if we should run in CLI mode (direct processing)
	if *inputPath != "" && *outputPath != "" {
		// Run in CLI mode (direct processing)
		runCLIMode()
		return
	}

	// Check if we should run in API-only mode
	if *apiOnly {
		// Run in API mode
		runAPIServer(*apiPort)
		return
	}

	// Default: Run in GUI mode with Wails
	runWailsApp()
}

// runWailsApp starts the Wails-based GUI application
func runWailsApp() {
	// Create the app instance
	appInstance := NewApp()

	// Create the Wails application
	err := wails.Run(&options.App{
		Title:  "LogZero - Timeline Generator",
		Width:  1280,
		Height: 800,
		MinWidth: 900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: getAssets(),
		},
		BackgroundColour: &options.RGBA{R: 13, G: 13, B: 15, A: 1},
		OnStartup:        appInstance.startup,
		Bind: []interface{}{
			appInstance,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: true,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
		},
	})

	if err != nil {
		logger.Error("Failed to start application: %v", err)
		os.Exit(1)
	}
}

// runCLIMode runs LogZero in CLI mode (direct processing)
func runCLIMode() {
	logger.Info("Starting LogZero in CLI mode")
	logger.Info("Input path: %s", *inputPath)
	logger.Info("Output path: %s", *outputPath)
	logger.Info("Format: %s", *format)

	// Create configuration
	config := app.NewDefaultConfig()
	config.InputPath = *inputPath
	config.OutputPath = *outputPath
	config.Format = *format

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Invalid configuration: %v", err)
		os.Exit(1)
	}

	// Create and initialize application
	application := app.New(config)
	if err := application.Initialize(); err != nil {
		logger.Error("Failed to initialize: %v", err)
		os.Exit(1)
	}

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		logger.Info("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Process with progress reporting
	logger.Info("Starting processing...")
	status, err := application.Process(ctx, func(filesProcessed, totalFiles, eventsProcessed int) {
		var percentage float64 = 0
		if totalFiles > 0 {
			percentage = float64(filesProcessed) / float64(totalFiles) * 100
		}
		logger.Info("Progress: %d/%d files, %d events, %.2f%%", 
			filesProcessed, totalFiles, eventsProcessed, percentage)
	})

	// Check for errors
	if err != nil {
		if ctx.Err() == context.Canceled {
			logger.Info("Processing was interrupted")
			os.Exit(1)
		}
		logger.Error("Processing failed: %v", err)
		os.Exit(1)
	}

	// Log completion
	logger.Info("Processing completed successfully")
	logger.Info("Parsed %d events in %d ms", status.ParsedEvents, status.DurationMs)

	// Cleanup
	if err := application.Cleanup(); err != nil {
		logger.Error("Cleanup failed: %v", err)
	}
}

// runAPIServer starts the API server for headless operation
func runAPIServer(port int) {
	logger.Info("Starting LogZero in API mode on port %d", port)

	// Create the API server
	server := api.NewServer(port)

	// Get port for API connections
	actualPort := server.GetPort()

	// Prepare connection info
	tempDir := api.GetTempDir()

	// Create connection info struct (without auth token)
	connInfo := securestorage.ConnectionInfo{
		Port:      actualPort,
		AuthToken: "", // No auth token needed
		Ready:     false, // Will be updated to true after full initialization
	}

	// Always use file-based storage for simplicity
	storage := securestorage.NewFileStorage(tempDir)

	// Configure retry logic
	retryConfig := retry.RetryConfig{
		MaxAttempts:        *retryMaxAttempts,
		InitialBackoff:     time.Duration(*retryInitialBackoff) * time.Millisecond,
		MaxBackoff:         time.Duration(*retryMaxBackoff) * time.Millisecond,
		BackoffFactor:      2.0,
		RandomizationFactor: 0.5,
	}

	// Start server initialization in a goroutine for parallel processing
	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrChan <- err
		}
		close(serverErrChan)
	}()

	// While server is initializing, write connection info
	// so clients can connect as soon as possible
	err := retry.WithRetryConfig("store connection info", retryConfig, func() error {
		return storage.Store(connInfo)
	})

	if err != nil {
		logger.Error("Failed to store connection info after multiple attempts: %v", err)
		os.Exit(ExitErrorServer)
	}

	logger.Info("Initial connection info stored successfully")

	// Start periodic cleanup of stale connection files
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()

	go periodicCleanup(cleanupCtx, tempDir, time.Duration(*cleanupInterval)*time.Hour, time.Duration(*cleanupThreshold)*time.Hour)

	// Wait for server initialization to complete or fail
	if err := <-serverErrChan; err != nil {
		logger.Error("Failed to start API server: %v", err)
		os.Exit(ExitErrorServer)
	}

	// Update connection info to indicate server is ready
	connInfo.Ready = true

	err = retry.WithRetryConfig("update connection info", retryConfig, func() error {
		return storage.Store(connInfo)
	})

	if err != nil {
		logger.Error("Failed to update connection info after multiple attempts: %v", err)
		// Not fatal, continue
	} else {
		logger.Info("Updated connection info with ready=true")
	}

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Wait for termination signal
	sig := <-signalChan
	logger.Info("Received signal: %v", sig)
	logger.Info("Shutting down API server...")

	// Create a context with timeout for graceful shutdown
	shutdownTimeoutDuration := time.Duration(*shutdownTimeout) * time.Second
	logger.Info("Initiating graceful shutdown with %d second timeout...", *shutdownTimeout)

	// Stop the server with the configured timeout
	if err := server.Stop(shutdownTimeoutDuration); err != nil {
		logger.Error("Error during server shutdown: %v", err)
		os.Exit(ExitErrorServer)
	}

	// Clean up connection info
	err = retry.WithRetryConfig("delete connection info", retryConfig, func() error {
		return storage.Delete()
	})

	if err != nil {
		logger.Error("Failed to delete connection info: %v", err)
		// Not fatal, continue
	}

	logger.Info("Server shutdown complete")
}

// initLogger initializes the logger with rotation if log file is specified
func initLogger() {
	if *logFile == "" {
		// Use default logger without rotation
		logger.Init(false, false)
		return
	}

	// Configure log rotation
	rotateConfig := logrotate.Config{
		MaxSize:    *logMaxSize,
		MaxAge:     *logMaxAge,
		MaxBackups: *logMaxBackups,
		Compress:   *logCompress,
		LocalTime:  true,
	}

	// Create log writer with rotation
	logWriter := logrotate.NewWriter(*logFile, rotateConfig)

	// Create multi-writer to log to both file and stdout
	multiWriter := logrotate.MultiWriter(logWriter, os.Stdout)

	// Initialize logger with custom writer
	logger.Init(false, false)
	logger.SetOutput(multiWriter)
}

// periodicCleanup runs cleanup of stale connection files periodically
func periodicCleanup(ctx context.Context, dirPath string, interval, threshold time.Duration) {
	// Run cleanup immediately
	cleanupStaleFiles(dirPath, threshold)

	// Set up ticker for periodic cleanup
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupStaleFiles(dirPath, threshold)
		}
	}
}

// cleanupStaleFiles removes stale connection files older than the threshold
func cleanupStaleFiles(dirPath string, threshold time.Duration) {
	// Read all files in the directory
	files, err := os.ReadDir(dirPath)
	if err != nil {
		logger.Error("Failed to read directory for cleanup: %v", err)
		return
	}

	// Current time for age comparison
	now := time.Now()

	// Check each file
	for _, file := range files {
		// Skip directories
		if file.IsDir() {
			continue
		}

		// Only process connection files and temp files
		name := file.Name()
		if name == "logzero_connection.json" || 
		   name == "logzero_connection.json.tmp" ||
		   (len(name) > 4 && name[len(name)-4:] == ".tmp") {

			// Get file info for timestamp
			filePath := filepath.Join(dirPath, name)
			info, err := os.Stat(filePath)
			if err != nil {
				continue // Skip if we can't stat the file
			}

			// Remove files older than threshold
			if now.Sub(info.ModTime()) > threshold {
				os.Remove(filePath)
				logger.Info("Cleaned up stale file: %s (age: %v)", name, now.Sub(info.ModTime()))
			}
		}
	}
}
