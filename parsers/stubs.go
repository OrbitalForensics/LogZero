package parsers

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LogZero/core"

	_ "github.com/mattn/go-sqlite3"
)

// buildSQLiteConnectionString safely builds a SQLite connection string
// by properly encoding the file path to prevent URI parameter injection
func buildSQLiteConnectionString(dbPath string, readOnly bool) string {
	// URL-encode the path to prevent injection of additional parameters
	// Note: We need to handle the path specially for SQLite URI format
	encodedPath := url.PathEscape(dbPath)

	// On Windows, we need to handle drive letters specially
	// SQLite expects file:///C:/path for absolute Windows paths
	if len(dbPath) > 1 && dbPath[1] == ':' {
		// Windows absolute path - use file:/// prefix
		encodedPath = "/" + strings.ReplaceAll(dbPath, "\\", "/")
		encodedPath = url.PathEscape(encodedPath)
	}

	mode := "rw"
	if readOnly {
		mode = "ro"
	}

	return fmt.Sprintf("file:%s?mode=%s", encodedPath, mode)
}

// Browser type constants
type browserType int

const (
	browserUnknown browserType = iota
	browserChrome              // Chromium-based: Chrome, Edge, Chromium
	browserFirefox             // Mozilla Firefox
	browserSafari              // Apple Safari
)

// Time conversion constants
const (
	// WebKit timestamp: microseconds since 1601-01-01
	// To convert to Unix: (microseconds / 1000000) - 11644473600
	webkitEpochOffset = 11644473600

	// PRTime (Firefox): microseconds since 1970-01-01
	// To convert to Unix: microseconds / 1000000

	// Mac Absolute Time: seconds since 2001-01-01
	// To convert to Unix: seconds + 978307200
	macAbsoluteEpochOffset = 978307200
)

// Errors for unsupported parser formats
// These parsers are planned for future implementation
var (
	ErrPrefetchNotSupported  = errors.New("prefetch file parsing is not yet implemented - this format requires specialized binary parsing")
	ErrShellbagsNotSupported = errors.New("shellbags parsing is not yet implemented - this format requires Windows registry parsing")
)

// PrefetchParser implements the Parser interface for Windows Prefetch files
// NOTE: This is a placeholder - real implementation requires parsing the Prefetch binary format
type PrefetchParser struct{}

// CanParse checks if this parser can handle the given file
func (p *PrefetchParser) CanParse(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".pf"
}

// Parse returns an error indicating Prefetch parsing is not yet supported
// Future implementation should parse the Prefetch binary format to extract:
// - Executable name and path
// - Run count
// - Last run times (up to 8)
// - Files and directories accessed
func (p *PrefetchParser) Parse(filePath string) ([]*core.Event, error) {
	return nil, ErrPrefetchNotSupported
}

// ShellbagsParser implements the Parser interface for Windows Shellbags
// NOTE: This is a placeholder - real implementation requires Windows registry parsing
type ShellbagsParser struct{}

// CanParse checks if this parser can handle the given file
func (p *ShellbagsParser) CanParse(filePath string) bool {
	baseName := strings.ToLower(filepath.Base(filePath))
	return strings.Contains(baseName, "shellbag")
}

// Parse returns an error indicating Shellbags parsing is not yet supported
// Future implementation should parse exported registry data to extract:
// - Folder paths accessed by user
// - Timestamps of folder access
// - Folder view settings
func (p *ShellbagsParser) Parse(filePath string) ([]*core.Event, error) {
	return nil, ErrShellbagsNotSupported
}

// BrowserHistoryParser implements the Parser interface for browser history SQLite databases
// Supports Chrome/Edge (Chromium-based), Firefox, and Safari
type BrowserHistoryParser struct{}

// CanParse checks if this parser can handle the given file
// Detection is based on filename and path patterns:
// - Chrome/Edge: filename "History" (no extension) in path containing "Chrome", "Edge", or "Chromium"
// - Firefox: filename "places.sqlite" in path containing "Firefox" or "Mozilla"
// - Safari: filename "History.db" in path containing "Safari"
func (p *BrowserHistoryParser) CanParse(filePath string) bool {
	return p.detectBrowserType(filePath) != browserUnknown
}

// detectBrowserType determines which browser the history file belongs to
func (p *BrowserHistoryParser) detectBrowserType(filePath string) browserType {
	baseName := strings.ToLower(filepath.Base(filePath))
	pathLower := strings.ToLower(filePath)

	// Chrome/Edge/Chromium: filename "History" (no extension) in Chromium path
	if baseName == "history" {
		if strings.Contains(pathLower, "chrome") ||
			strings.Contains(pathLower, "edge") ||
			strings.Contains(pathLower, "chromium") {
			return browserChrome
		}
	}

	// Firefox: filename "places.sqlite" in Mozilla/Firefox path
	if baseName == "places.sqlite" {
		if strings.Contains(pathLower, "firefox") ||
			strings.Contains(pathLower, "mozilla") {
			return browserFirefox
		}
	}

	// Safari: filename "History.db" in Safari path
	if baseName == "history.db" {
		if strings.Contains(pathLower, "safari") {
			return browserSafari
		}
	}

	return browserUnknown
}

// Parse parses a browser history SQLite database and returns a slice of events
func (p *BrowserHistoryParser) Parse(filePath string) ([]*core.Event, error) {
	browserType := p.detectBrowserType(filePath)
	if browserType == browserUnknown {
		return nil, fmt.Errorf("unable to detect browser type for file: %s", filePath)
	}

	// Try to open database directly first, copy to temp if locked
	dbPath, tempFile, err := p.prepareDatabase(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare database: %w", err)
	}

	// Clean up temp file if created
	if tempFile != "" {
		defer os.Remove(tempFile)
	}

	// Open database in read-only mode with safe connection string
	db, err := sql.Open("sqlite3", buildSQLiteConnectionString(dbPath, true))
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}
	defer db.Close()

	// Parse based on browser type
	var events []*core.Event
	switch browserType {
	case browserChrome:
		events, err = p.parseChrome(db, filePath)
	case browserFirefox:
		events, err = p.parseFirefox(db, filePath)
	case browserSafari:
		events, err = p.parseSafari(db, filePath)
	default:
		return nil, fmt.Errorf("unsupported browser type")
	}

	if err != nil {
		return nil, err
	}

	// Print summary
	browserName := p.getBrowserName(browserType)
	fmt.Printf("Parsed %s history file: %s (found %d events)\n", browserName, filePath, len(events))

	return events, nil
}

// prepareDatabase prepares the database for reading
// If the database is locked, it copies to a temp file
func (p *BrowserHistoryParser) prepareDatabase(filePath string) (string, string, error) {
	// First try to open directly with safe connection string
	db, err := sql.Open("sqlite3", buildSQLiteConnectionString(filePath, true))
	if err == nil {
		// Test if we can actually query
		err = db.Ping()
		db.Close()
		if err == nil {
			return filePath, "", nil
		}
	}

	// Database might be locked, copy to temp file
	tempFile, err := p.copyToTemp(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to copy locked database to temp: %w", err)
	}

	return tempFile, tempFile, nil
}

// copyToTemp copies the database file to a temporary location
func (p *BrowserHistoryParser) copyToTemp(filePath string) (string, error) {
	// Create temp file with same extension
	ext := filepath.Ext(filePath)
	if ext == "" {
		ext = ".db"
	}

	tempFile, err := os.CreateTemp("", "logzero_browser_*"+ext)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Open source file
	srcFile, err := os.Open(filePath)
	if err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Copy contents
	_, err = io.Copy(tempFile, srcFile)
	tempFile.Close()
	if err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("failed to copy database: %w", err)
	}

	return tempPath, nil
}

// parseChrome parses Chrome/Edge/Chromium history database
func (p *BrowserHistoryParser) parseChrome(db *sql.DB, filePath string) ([]*core.Event, error) {
	query := `
		SELECT urls.url, urls.title, visits.visit_time, urls.visit_count
		FROM urls
		JOIN visits ON urls.id = visits.url
		ORDER BY visits.visit_time
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query Chrome history: %w", err)
	}
	defer rows.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	for rows.Next() {
		var url string
		var title sql.NullString
		var visitTime int64
		var visitCount int

		if err := rows.Scan(&url, &title, &visitTime, &visitCount); err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: failed to scan Chrome row: %v\n", err)
			continue
		}

		// Convert WebKit timestamp to Unix time
		timestamp := p.webkitToTime(visitTime)

		// Build title string
		titleStr := ""
		if title.Valid {
			titleStr = title.String
		}

		// Create message
		message := p.buildVisitMessage(titleStr, url, visitCount)

		event := core.NewEvent(
			timestamp,
			source,
			"BrowserHistory",
			0, // No specific event ID
			"", // User unknown from history alone
			"", // Host unknown
			message,
			filePath,
		)

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating Chrome rows: %w", err)
	}

	return events, nil
}

// parseFirefox parses Firefox places.sqlite database
func (p *BrowserHistoryParser) parseFirefox(db *sql.DB, filePath string) ([]*core.Event, error) {
	query := `
		SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date, moz_places.visit_count
		FROM moz_places
		JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
		ORDER BY moz_historyvisits.visit_date
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query Firefox history: %w", err)
	}
	defer rows.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	for rows.Next() {
		var url string
		var title sql.NullString
		var visitDate int64
		var visitCount int

		if err := rows.Scan(&url, &title, &visitDate, &visitCount); err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: failed to scan Firefox row: %v\n", err)
			continue
		}

		// Convert PRTime (microseconds since Unix epoch) to Unix time
		timestamp := p.prtimeToTime(visitDate)

		// Build title string
		titleStr := ""
		if title.Valid {
			titleStr = title.String
		}

		// Create message
		message := p.buildVisitMessage(titleStr, url, visitCount)

		event := core.NewEvent(
			timestamp,
			source,
			"BrowserHistory",
			0, // No specific event ID
			"", // User unknown from history alone
			"", // Host unknown
			message,
			filePath,
		)

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating Firefox rows: %w", err)
	}

	return events, nil
}

// parseSafari parses Safari History.db database
func (p *BrowserHistoryParser) parseSafari(db *sql.DB, filePath string) ([]*core.Event, error) {
	query := `
		SELECT history_items.url, history_visits.visit_time, history_items.visit_count
		FROM history_items
		JOIN history_visits ON history_items.id = history_visits.history_item
		ORDER BY history_visits.visit_time
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query Safari history: %w", err)
	}
	defer rows.Close()

	events := make([]*core.Event, 0)
	source := filepath.Base(filePath)

	for rows.Next() {
		var url string
		var visitTime float64 // Safari uses float for timestamp
		var visitCount int

		if err := rows.Scan(&url, &visitTime, &visitCount); err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: failed to scan Safari row: %v\n", err)
			continue
		}

		// Convert Mac Absolute Time to Unix time
		timestamp := p.macAbsoluteToTime(visitTime)

		// Safari doesn't store titles in History.db, extract from URL
		titleStr := p.extractTitleFromURL(url)

		// Create message
		message := p.buildVisitMessage(titleStr, url, visitCount)

		event := core.NewEvent(
			timestamp,
			source,
			"BrowserHistory",
			0, // No specific event ID
			"", // User unknown from history alone
			"", // Host unknown
			message,
			filePath,
		)

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating Safari rows: %w", err)
	}

	return events, nil
}

// webkitToTime converts WebKit timestamp (microseconds since 1601-01-01) to time.Time
func (p *BrowserHistoryParser) webkitToTime(microseconds int64) time.Time {
	// Convert to seconds and adjust for epoch difference
	unixSeconds := (microseconds / 1000000) - webkitEpochOffset
	return time.Unix(unixSeconds, 0).UTC()
}

// prtimeToTime converts PRTime (microseconds since 1970-01-01) to time.Time
func (p *BrowserHistoryParser) prtimeToTime(microseconds int64) time.Time {
	// Convert microseconds to seconds and nanoseconds
	seconds := microseconds / 1000000
	nanos := (microseconds % 1000000) * 1000
	return time.Unix(seconds, nanos).UTC()
}

// macAbsoluteToTime converts Mac Absolute Time (seconds since 2001-01-01) to time.Time
func (p *BrowserHistoryParser) macAbsoluteToTime(seconds float64) time.Time {
	// Add offset to convert to Unix timestamp
	unixSeconds := int64(seconds) + macAbsoluteEpochOffset
	// Handle fractional seconds
	nanos := int64((seconds - float64(int64(seconds))) * 1e9)
	return time.Unix(unixSeconds, nanos).UTC()
}

// buildVisitMessage creates a formatted message for a browser visit event
func (p *BrowserHistoryParser) buildVisitMessage(title, url string, visitCount int) string {
	if title != "" {
		return fmt.Sprintf("Visited: %s - %s (visit count: %d)", title, url, visitCount)
	}
	return fmt.Sprintf("Visited: %s (visit count: %d)", url, visitCount)
}

// extractTitleFromURL extracts a title-like string from a URL when title is not available
func (p *BrowserHistoryParser) extractTitleFromURL(url string) string {
	// Try to extract domain as a simple title
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")

	// Get just the domain part
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// getBrowserName returns a human-readable name for the browser type
func (p *BrowserHistoryParser) getBrowserName(bt browserType) string {
	switch bt {
	case browserChrome:
		return "Chrome/Edge"
	case browserFirefox:
		return "Firefox"
	case browserSafari:
		return "Safari"
	default:
		return "Unknown"
	}
}
