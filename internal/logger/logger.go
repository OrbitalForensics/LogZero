package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

var (
	// Default logger
	defaultLogger *log.Logger

	// Verbose mode
	verbose bool

	// Silent mode
	silent bool
)

// Init initializes the logger
func Init(verboseMode bool, silentMode bool) {
	verbose = verboseMode
	silent = silentMode

	// Create a logger that writes to stdout
	defaultLogger = log.New(os.Stdout, "", log.LstdFlags)

	// Set the default logger for the standard log package
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)
}

// SetOutput sets the output destination for the logger
func SetOutput(w io.Writer) {
	defaultLogger.SetOutput(w)
	log.SetOutput(w)
}

// Info logs an informational message
func Info(format string, v ...interface{}) {
	if !silent {
		defaultLogger.Printf("[INFO] "+format, v...)
	}
}

// Debug logs a debug message (only in verbose mode)
func Debug(format string, v ...interface{}) {
	if verbose && !silent {
		defaultLogger.Printf("[DEBUG] "+format, v...)
	}
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	if !silent {
		defaultLogger.Printf("[WARN] "+format, v...)
	}
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	defaultLogger.Printf("[ERROR] "+format, v...)
}

// Fatal logs a fatal error message and exits
func Fatal(format string, v ...interface{}) {
	defaultLogger.Fatalf("[FATAL] "+format, v...)
}

// IsVerbose returns true if verbose mode is enabled
func IsVerbose() bool {
	return verbose
}

// IsSilent returns true if silent mode is enabled
func IsSilent() bool {
	return silent
}

// PrintProgress prints a progress message
func PrintProgress(current, total int, message string) {
	if !silent {
		if total > 0 {
			percentage := float64(current) / float64(total) * 100
			fmt.Printf("\r%s: %.1f%% (%d/%d)", message, percentage, current, total)
		} else {
			fmt.Printf("\r%s: %d", message, current)
		}
	}
}
