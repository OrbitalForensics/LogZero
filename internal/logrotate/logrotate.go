package logrotate

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/natefinch/lumberjack"
)

// DefaultConfig provides default configuration for log rotation
var DefaultConfig = Config{
	MaxSize:    100, // megabytes
	MaxAge:     7,   // days
	MaxBackups: 5,
	Compress:   true,
	LocalTime:  true,
}

// Config configures the log rotation behavior
type Config struct {
	// MaxSize is the maximum size in megabytes of the log file before it gets rotated
	MaxSize int

	// MaxAge is the maximum number of days to retain old log files
	MaxAge int

	// MaxBackups is the maximum number of old log files to retain
	MaxBackups int

	// Compress determines if the rotated log files should be compressed using gzip
	Compress bool

	// LocalTime determines if the time used for formatting the timestamps in
	// backup files is the computer's local time
	LocalTime bool
}

// Writer is a wrapper around lumberjack.Logger that implements io.Writer
type Writer struct {
	logger *lumberjack.Logger
	mu     sync.Mutex
}

// NewWriter creates a new log writer with rotation
func NewWriter(filename string, config Config) *Writer {
	// Ensure the directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// If we can't create the directory, log to stderr
		return &Writer{
			logger: nil,
		}
	}

	return &Writer{
		logger: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    config.MaxSize,
			MaxAge:     config.MaxAge,
			MaxBackups: config.MaxBackups,
			Compress:   config.Compress,
			LocalTime:  config.LocalTime,
		},
	}
}

// Write implements io.Writer
func (w *Writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.logger == nil {
		// If logger is nil, write to stderr
		return os.Stderr.Write(p)
	}

	return w.logger.Write(p)
}

// Close implements io.Closer
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.logger == nil {
		return nil
	}

	return w.logger.Close()
}

// MultiWriter creates a writer that duplicates its writes to all the provided writers
func MultiWriter(writers ...io.Writer) io.Writer {
	return io.MultiWriter(writers...)
}