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
	insertStmt *sql.Stmt // Base prepared statement at db level
	txStmt     *sql.Stmt // Transaction-wrapped statement for optimal performance
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

	// Apply performance PRAGMAs for bulk insert optimization
	// These settings trade durability for speed during bulk loading
	pragmas := []string{
		"PRAGMA synchronous = OFF",      // Don't wait for disk sync
		"PRAGMA journal_mode = MEMORY",  // Keep journal in memory
		"PRAGMA cache_size = -64000",    // 64MB cache (negative = KB)
		"PRAGMA temp_store = MEMORY",    // Keep temp tables in memory
		"PRAGMA locking_mode = EXCLUSIVE", // Exclusive lock for better performance
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %s: %w", pragma, err)
		}
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

	// NOTE: Index creation is deferred to Close() for better bulk insert performance

	// Prepare insert statement at db level (reusable across transactions)
	insertSQL := `
	INSERT INTO events (
		timestamp, source, event_type, event_id, user, host, message, path, tags, score, summary
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	stmt, err := db.Prepare(insertSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare insert statement: %w", err)
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		stmt.Close()
		db.Close()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Wrap the prepared statement for this transaction for optimal performance
	txStmt := tx.Stmt(stmt)

	return &SQLiteWriter{
		db:         db,
		insertStmt: stmt,
		txStmt:     txStmt,
		tx:         tx,
		batchSize:  10000, // Commit every 10000 events (larger batches with PRAGMAs)
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

		// Insert event into database using transaction-wrapped statement
		_, err := w.txStmt.Exec(
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
	// Close the transaction-wrapped statement (it becomes invalid after commit)
	if w.txStmt != nil {
		w.txStmt.Close()
	}

	// Commit current transaction
	if err := w.tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Begin new transaction
	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Wrap the prepared statement for the new transaction
	txStmt := tx.Stmt(w.insertStmt)

	// Update writer state
	w.tx = tx
	w.txStmt = txStmt
	w.count = 0

	return nil
}

// Close closes the SQLite writer
func (w *SQLiteWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close transaction-wrapped statement
	if w.txStmt != nil {
		w.txStmt.Close()
	}

	// Close base prepared statement
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

	// Create index after all inserts are complete (much faster than indexing during insert)
	if w.db != nil {
		createIndexSQL := `
		CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
		`
		if _, err := w.db.Exec(createIndexSQL); err != nil {
			w.db.Close()
			return fmt.Errorf("failed to create timestamp index: %w", err)
		}

		// Reset PRAGMAs to safe defaults before closing
		if _, err := w.db.Exec("PRAGMA synchronous = NORMAL"); err != nil {
			// Log but don't fail - data is already safely written
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
