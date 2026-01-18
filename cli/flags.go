package cli

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// SupportedFormats defines the output formats supported by LogZero
var SupportedFormats = []string{"csv", "jsonl", "sqlite"}

// Config holds the command-line configuration for LogZero
type Config struct {
	InputPath      string
	OutputPath     string
	Format         string
	Verbose        bool
	Workers        int    // Number of worker goroutines
	BufferSize     int    // Size of the buffer for file processing
	FilterPattern  string // Pattern to filter events
	Silent         bool   // Disable all console output except errors
	JSONStatus     bool   // Output JSON status block to stdout
}

// ParseFlags parses command-line flags and returns a Config
func ParseFlags() (*Config, error) {
	config := &Config{}

	// Define flags
	flag.StringVar(&config.InputPath, "input", "", "Path to input file or directory")
	flag.StringVar(&config.OutputPath, "output", "", "Path for output file")
	flag.StringVar(&config.Format, "format", "jsonl", "Output format (csv, jsonl, sqlite)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.IntVar(&config.Workers, "workers", runtime.NumCPU(), "Number of worker goroutines")
	flag.IntVar(&config.BufferSize, "buffer-size", 1000, "Size of the buffer for file processing")
	flag.StringVar(&config.FilterPattern, "filter", "", "Pattern to filter events (e.g., 'user:admin')")
	flag.BoolVar(&config.Silent, "silent", false, "Disable all console output except errors")
	flag.BoolVar(&config.JSONStatus, "json-status", false, "Output JSON status block to stdout")

	// Parse flags
	flag.Parse()

	// Validate required flags
	if config.InputPath == "" {
		return nil, fmt.Errorf("--input flag is required")
	}

	if config.OutputPath == "" {
		return nil, fmt.Errorf("--output flag is required")
	}

	// Validate format
	config.Format = strings.ToLower(config.Format)
	validFormat := false
	for _, format := range SupportedFormats {
		if config.Format == format {
			validFormat = true
			break
		}
	}

	if !validFormat {
		return nil, fmt.Errorf("unsupported format: %s (supported formats: %s)", 
			config.Format, strings.Join(SupportedFormats, ", "))
	}

	// Validate workers
	if config.Workers <= 0 {
		config.Workers = runtime.NumCPU()
	}

	// Validate buffer size
	if config.BufferSize <= 0 {
		config.BufferSize = 1000
	}

	return config, nil
}

// PrintUsage prints the usage information for LogZero
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "LogZero - High-performance timeline generator\n\n")
	fmt.Fprintf(os.Stderr, "Usage: logzero --input <path> --output <path> --format <format> [options]\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}
