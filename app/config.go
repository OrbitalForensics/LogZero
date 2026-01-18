package app

import (
	"errors"
	"runtime"
	"strings"
)

// Common errors
var (
	ErrUnsupportedFormat = errors.New("unsupported output format")
	ErrInvalidInput      = errors.New("invalid input path")
	ErrInvalidOutput     = errors.New("invalid output path")
	ErrProcessingFailed  = errors.New("processing failed")
)

// SupportedFormats defines the output formats supported by LogZero
var SupportedFormats = []string{"csv", "jsonl", "sqlite"}

// Config holds the configuration for LogZero
type Config struct {
	// Input/Output settings
	InputPath      string
	OutputPath     string
	Format         string

	// Processing settings
	Workers        int    // Number of worker goroutines
	BufferSize     int    // Size of the buffer for file processing
	FilterPattern  string // Pattern to filter events

	// UI settings
	Verbose        bool   // Enable verbose logging
	Silent         bool   // Disable all console output except errors
	JSONStatus     bool   // Output JSON status block to stdout
}

// NewDefaultConfig creates a new Config with default values
func NewDefaultConfig() *Config {
	return &Config{
		Format:     "jsonl",
		Workers:    runtime.NumCPU(),
		BufferSize: 1000,
		Verbose:    false,
		Silent:     false,
		JSONStatus: false,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate format
	c.Format = strings.ToLower(c.Format)
	validFormat := false
	for _, format := range SupportedFormats {
		if c.Format == format {
			validFormat = true
			break
		}
	}

	if !validFormat {
		return ErrUnsupportedFormat
	}

	// Validate workers
	if c.Workers <= 0 {
		c.Workers = runtime.NumCPU()
	}

	// Validate buffer size
	if c.BufferSize <= 0 {
		c.BufferSize = 1000
	}

	return nil
}
