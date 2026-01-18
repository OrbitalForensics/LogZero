package output

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"LogZero/core"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// SQLiteWriter implements the Writer interface for SQLite output
type SQLiteWriter struct {
	mu         sync.Mutex
	db         *sql.DB
	insertStmt *sql.Stmt
	tx         *sql.Tx
	batchSize  int
	count      int
}

// NewSQLiteWriter creates a new SQLite writer
func NewSQLiteWriter(outputPath string) (*SQLiteWriter, error) {
	// Open database connection
	db, err := sql.Open("sqlite3", outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Create table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		source TEXT NOT NULL,
		event_type TEXT NOT NULL,
		event_id INTEGER NOT NULL,
		user TEXT,
		host TEXT,
		message TEXT,
		path TEXT,
		tags TEXT,
		score REAL,
		summary TEXT
	);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create events table: %w", err)
	}

	// Create index on timestamp for faster queries
	createIndexSQL := `
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
	`

	if _, err := db.Exec(createIndexSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create timestamp index: %w", err)
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Prepare insert statement
	insertSQL := `
	INSERT INTO events (
		timestamp, source, event_type, event_id, user, host, message, path, tags, score, summary
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("failed to prepare insert statement: %w", err)
	}

	return &SQLiteWriter{
		db:         db,
		insertStmt: stmt,
		tx:         tx,
		batchSize:  1000, // Commit every 1000 events
		count:      0,
	}, nil
}

// Write writes the events to the SQLite database
func (w *SQLiteWriter) Write(events []*core.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, event := range events {
		// Format tags as comma-separated string
		tagsStr := formatTags(event.Tags)

		// Insert event into database
		_, err := w.insertStmt.Exec(
			event.Timestamp.Format(time.RFC3339),
			event.Source,
			event.EventType,
			event.EventID,
			event.User,
			event.Host,
			event.Message,
			event.Path,
			tagsStr,
			event.Score,
			event.Summary,
		)

		if err != nil {
			return fmt.Errorf("failed to insert event: %w", err)
		}

		w.count++

		// Commit transaction and start a new one every batchSize events
		if w.count >= w.batchSize {
			if err := w.commitAndStartNewTransaction(); err != nil {
				return err
			}
		}
	}

	return nil
}

// commitAndStartNewTransaction commits the current transaction and starts a new one
func (w *SQLiteWriter) commitAndStartNewTransaction() error {
	// Commit current transaction
	if err := w.tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Begin new transaction
	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Prepare new insert statement
	stmt, err := tx.Prepare(`
	INSERT INTO events (
		timestamp, source, event_type, event_id, user, host, message, path, tags, score, summary
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`)

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}

	// Update writer state
	w.tx = tx
	w.insertStmt = stmt
	w.count = 0

	return nil
}

// Close closes the SQLite writer
func (w *SQLiteWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close prepared statement
	if w.insertStmt != nil {
		w.insertStmt.Close()
	}

	// Commit final transaction
	if w.tx != nil {
		if err := w.tx.Commit(); err != nil {
			w.db.Close()
			return fmt.Errorf("failed to commit final transaction: %w", err)
		}
	}

	// Close database connection
	if w.db != nil {
		if err := w.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}

	return nil
}
