package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"LogZero/app"
)

// Server represents the API server for LogZero
type Server struct {
	httpServer     *http.Server
	application    *app.App
	config         *app.Config
	processMutex   sync.Mutex
	isProcessing   bool
	cancelFunc     context.CancelFunc
	progressChan   chan ProgressUpdate
	port           int
	shutdownSignal chan struct{}
	// Authentication
	authToken string // Bearer token for API authentication
	// Resource limiting
	requestSemaphore chan struct{} // Semaphore to limit concurrent requests
	maxConcurrent    int           // Maximum number of concurrent requests
	// Client registry for SSE broadcasting
	clients      map[chan ProgressUpdate]struct{}
	clientsMutex sync.RWMutex
}

// ProgressUpdate represents a progress update from the processing
type ProgressUpdate struct {
	FilesProcessed  int     `json:"files_processed"`
	TotalFiles      int     `json:"total_files"`
	EventsProcessed int     `json:"events_processed"`
	Percentage      float64 `json:"percentage"`
	Status          string  `json:"status"`
}

// ConfigRequest represents a configuration request from the client
type ConfigRequest struct {
	InputPath     string `json:"input_path"`
	OutputPath    string `json:"output_path"`
	Format        string `json:"format"`
	Workers       int    `json:"workers,omitempty"`
	BufferSize    int    `json:"buffer_size,omitempty"`
	FilterPattern string `json:"filter_pattern,omitempty"`
	Verbose       bool   `json:"verbose,omitempty"`
	Silent        bool   `json:"silent,omitempty"`
}

// StatusResponse represents the status response
type StatusResponse struct {
	Status          string  `json:"status"`
	IsProcessing    bool    `json:"is_processing"`
	FilesProcessed  int     `json:"files_processed,omitempty"`
	TotalFiles      int     `json:"total_files,omitempty"`
	EventsProcessed int     `json:"events_processed,omitempty"`
	Percentage      float64 `json:"percentage,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// NewServer creates a new API server
func NewServer(port int) *Server {
	// Determine reasonable defaults for resource limits
	// Use number of CPUs as a baseline for concurrent requests
	maxConcurrent := runtime.NumCPU() * 2
	if maxConcurrent < 4 {
		maxConcurrent = 4 // Minimum of 4 concurrent requests
	}

	// Generate a cryptographically secure authentication token
	authToken := generateSecureToken(32)

	return &Server{
		config:           app.NewDefaultConfig(),
		port:             port,
		authToken:        authToken,
		progressChan:     make(chan ProgressUpdate, 100),
		shutdownSignal:   make(chan struct{}),
		requestSemaphore: make(chan struct{}, maxConcurrent),
		maxConcurrent:    maxConcurrent,
		clients:          make(map[chan ProgressUpdate]struct{}),
	}
}

// generateSecureToken generates a cryptographically secure random token
// Panics if crypto/rand fails, as this indicates a critical system problem
func generateSecureToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// crypto/rand failure is extremely rare and indicates serious system issues
		// (e.g., /dev/urandom unavailable). Do not continue with insecure token.
		panic(fmt.Sprintf("CRITICAL: Failed to generate secure token: %v", err))
	}
	return hex.EncodeToString(bytes)
}

// Start starts the API server
func (s *Server) Start() error {
	router := http.NewServeMux()

	// Register API endpoints with authentication
	router.HandleFunc("/api/config", s.authMiddleware(s.resourceLimitMiddleware(s.handleConfig)))
	router.HandleFunc("/api/start", s.authMiddleware(s.resourceLimitMiddleware(s.handleStart)))
	router.HandleFunc("/api/stop", s.authMiddleware(s.resourceLimitMiddleware(s.handleStop)))
	router.HandleFunc("/api/status", s.authMiddleware(s.resourceLimitMiddleware(s.handleStatus)))
	router.HandleFunc("/api/progress", s.authMiddleware(s.resourceLimitMiddleware(s.handleProgress)))
	router.HandleFunc("/api/shutdown", s.authMiddleware(s.resourceLimitMiddleware(s.handleShutdown)))

	// Health endpoint does not require authentication (for load balancer health checks)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// Create HTTP server with timeouts for better resource management
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Set a reasonable maximum header size to prevent memory exhaustion
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start HTTP server
	go func() {
		log.Printf("Starting LogZero API server on http://127.0.0.1:%d", s.port)

		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start progress broadcaster
	go s.broadcastProgress()

	return nil
}

// Stop stops the API server with an optional timeout
func (s *Server) Stop(timeout ...time.Duration) error {
	// Signal the shutdown
	close(s.shutdownSignal)

	// Stop any running process
	s.stopProcessing()

	// Default timeout is 10 seconds, but can be overridden
	shutdownTimeout := 10 * time.Second
	if len(timeout) > 0 && timeout[0] > 0 {
		shutdownTimeout = timeout[0]
	}

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Log the shutdown timeout
	log.Printf("Shutting down server with %v timeout", shutdownTimeout)

	// Shutdown the HTTP server
	return s.httpServer.Shutdown(ctx)
}

// GetAuthToken returns the authentication token for API access
func (s *Server) GetAuthToken() string {
	return s.authToken
}

// GetPort returns the server port
func (s *Server) GetPort() int {
	return s.port
}

// resourceLimitMiddleware limits the number of concurrent requests
func (s *Server) resourceLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try to acquire a semaphore slot
		select {
		case s.requestSemaphore <- struct{}{}:
			// Acquired a slot, continue processing
			defer func() {
				// Release the slot when done
				<-s.requestSemaphore
			}()
			next(w, r)
		default:
			// No slots available, return 429 Too Many Requests
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Too many requests, please try again later", http.StatusTooManyRequests)
		}
	}
}

// authMiddleware validates the Bearer token for API requests
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token format
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "Invalid authorization format, expected Bearer token", http.StatusUnauthorized)
			return
		}

		// Extract and validate the token using constant-time comparison
		token := authHeader[len(bearerPrefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed
		next(w, r)
	}
}

// validatePath checks for path traversal attempts and validates the path is safe
func validatePath(path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	// Check for null bytes (can be used to bypass checks)
	if strings.ContainsRune(path, '\x00') {
		return errors.New("invalid path")
	}

	// Check for path traversal patterns in original input
	if strings.Contains(path, "..") {
		return errors.New("invalid path")
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Double-check after cleaning
	if strings.Contains(cleaned, "..") {
		return errors.New("invalid path")
	}

	// Get absolute path
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return errors.New("invalid path")
	}

	// Resolve any symlinks to get the real path
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the path doesn't exist yet (for output), check the parent directory
		parentDir := filepath.Dir(abs)
		realParent, parentErr := filepath.EvalSymlinks(parentDir)
		if parentErr != nil {
			// Parent doesn't exist either - that's okay for new output paths
			// Just validate the path doesn't try to escape
			realPath = abs
		} else {
			// Reconstruct the path with the real parent
			realPath = filepath.Join(realParent, filepath.Base(abs))
		}
	}

	// Check that the resolved path doesn't contain traversal after symlink resolution
	if strings.Contains(realPath, "..") {
		return errors.New("invalid path")
	}

	// Block access to sensitive system directories
	lowerPath := strings.ToLower(realPath)
	sensitivePatterns := []string{
		// Unix/Linux sensitive paths
		"/etc/", "/var/", "/root/", "/proc/", "/sys/", "/dev/",
		"/.ssh", "/.gnupg", "/.aws", "/.azure", "/.config",
		"/private/etc", // macOS
		// Windows sensitive paths (case-insensitive due to lowerPath)
		"\\windows\\system32", "\\windows\\syswow64", "\\program files",
		"\\programdata", "\\appdata\\roaming", "\\appdata\\local",
		"\\.ssh", "\\.gnupg", "\\.aws", "\\.azure",
		"\\ntuser.dat", "\\sam", "\\security", "\\system", "\\software",
		// Credential stores
		"credential", "password", "secret", ".key", ".pem", ".p12",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerPath, pattern) {
			return errors.New("access to system directories not allowed")
		}
	}

	return nil
}

// handleConfig handles the configuration endpoint
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Parse request body
	var configReq ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&configReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate paths to prevent path traversal attacks
	// Use generic error messages to avoid leaking path information
	if err := validatePath(configReq.InputPath); err != nil {
		log.Printf("Invalid input path rejected: %v", err) // Log detailed error server-side
		http.Error(w, "Invalid input path", http.StatusBadRequest)
		return
	}
	if err := validatePath(configReq.OutputPath); err != nil {
		log.Printf("Invalid output path rejected: %v", err) // Log detailed error server-side
		http.Error(w, "Invalid output path", http.StatusBadRequest)
		return
	}

	// Lock to prevent concurrent configuration changes
	s.processMutex.Lock()
	defer s.processMutex.Unlock()

	// Check if processing is in progress
	if s.isProcessing {
		http.Error(w, "Cannot change configuration while processing", http.StatusConflict)
		return
	}

	// Update configuration
	s.config = &app.Config{
		InputPath:     configReq.InputPath,
		OutputPath:    configReq.OutputPath,
		Format:        configReq.Format,
		Workers:       configReq.Workers,
		BufferSize:    configReq.BufferSize,
		FilterPattern: configReq.FilterPattern,
		Verbose:       configReq.Verbose,
		Silent:        configReq.Silent,
		JSONStatus:    true, // Always use JSON status for API
	}

	// Validate configuration
	if err := s.config.Validate(); err != nil {
		log.Printf("Configuration validation failed: %v", err) // Log detailed error server-side
		http.Error(w, "Invalid configuration", http.StatusBadRequest)
		return
	}

	// Return success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
	})
}

// handleStart handles the start endpoint
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Lock to prevent concurrent starts
	s.processMutex.Lock()
	defer s.processMutex.Unlock()

	// Check if processing is already in progress
	if s.isProcessing {
		http.Error(w, "Processing already in progress", http.StatusConflict)
		return
	}

	// Create and initialize the application
	s.application = app.New(s.config)
	if err := s.application.Initialize(); err != nil {
		log.Printf("Application initialization failed: %v", err) // Log detailed error server-side
		http.Error(w, "Failed to initialize processing", http.StatusInternalServerError)
		return
	}

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFunc = cancel

	// Set processing flag
	s.isProcessing = true

	// Start processing in a goroutine
	go func() {
		defer func() {
			// Reset processing state when done
			s.processMutex.Lock()
			s.isProcessing = false
			s.cancelFunc = nil
			s.processMutex.Unlock()

			// Cleanup application
			if s.application != nil {
				if err := s.application.Cleanup(); err != nil {
					log.Printf("Error during cleanup: %v", err)
				}
			}
		}()

		// Define progress callback
		progressCallback := func(filesProcessed, totalFiles, eventsProcessed int) {
			var percentage float64 = 0
			if totalFiles > 0 {
				percentage = float64(filesProcessed) / float64(totalFiles) * 100
			}

			// Send progress update
			select {
			case s.progressChan <- ProgressUpdate{
				FilesProcessed:  filesProcessed,
				TotalFiles:      totalFiles,
				EventsProcessed: eventsProcessed,
				Percentage:      percentage,
				Status:          "processing",
			}:
			default:
				// Channel buffer is full, skip this update
			}
		}

		// Process the input
		status, err := s.application.Process(ctx, progressCallback)

		// Send final progress update
		var finalStatus string
		var errorMsg string
		if err != nil {
			if ctx.Err() == context.Canceled {
				finalStatus = "interrupted"
				errorMsg = "Processing was interrupted"
			} else {
				finalStatus = "error"
				errorMsg = err.Error()
			}
		} else {
			finalStatus = "success"
		}

		// Create final progress update with error message if applicable
		update := ProgressUpdate{
			FilesProcessed:  status.ParsedEvents, // Use parsed events as a proxy for files processed
			TotalFiles:      0,                   // We don't know the total files at this point
			EventsProcessed: status.ParsedEvents,
			Percentage:      100,
			Status:          finalStatus,
		}

		// Log the error message
		if errorMsg != "" {
			log.Printf("Processing completed with status: %s, error: %s", finalStatus, errorMsg)
		}

		// Send the update
		s.progressChan <- update
	}()

	// Return success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "started",
	})
}

// handleStop handles the stop endpoint
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Stop the processing
	stopped := s.stopProcessing()

	// Return status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{
		"stopped": stopped,
	})
}

// handleStatus handles the status endpoint
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Lock to prevent race conditions
	s.processMutex.Lock()
	isProcessing := s.isProcessing
	s.processMutex.Unlock()

	// Return status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(StatusResponse{
		Status:       "ok",
		IsProcessing: isProcessing,
	})
}

// handleProgress handles the progress endpoint (Server-Sent Events)
func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set headers for SSE
	// Note: No CORS header - API is localhost-only and requires authentication
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create a channel for this client
	clientChan := make(chan ProgressUpdate, 10)

	// Register this client to receive broadcasts
	s.registerClient(clientChan)
	defer s.unregisterClient(clientChan)

	// Send initial progress update
	initialUpdate := ProgressUpdate{
		FilesProcessed:  0,
		TotalFiles:      0,
		EventsProcessed: 0,
		Percentage:      0,
		Status:          "idle",
	}
	s.processMutex.Lock()
	if s.isProcessing {
		initialUpdate.Status = "processing"
	}
	s.processMutex.Unlock()

	// Send initial update
	fmt.Fprintf(w, "data: %s\n\n", mustMarshalJSON(initialUpdate))
	w.(http.Flusher).Flush()

	// Create a done channel for client disconnect
	done := r.Context().Done()

	// Subscribe to progress updates
	for {
		select {
		case <-done:
			return
		case <-s.shutdownSignal:
			return
		case update := <-clientChan:
			// Send update to client
			fmt.Fprintf(w, "data: %s\n\n", mustMarshalJSON(update))
			w.(http.Flusher).Flush()
		}
	}
}

// registerClient adds a client channel to the broadcast registry
func (s *Server) registerClient(ch chan ProgressUpdate) {
	s.clientsMutex.Lock()
	s.clients[ch] = struct{}{}
	s.clientsMutex.Unlock()
}

// unregisterClient removes a client channel from the broadcast registry
func (s *Server) unregisterClient(ch chan ProgressUpdate) {
	s.clientsMutex.Lock()
	delete(s.clients, ch)
	s.clientsMutex.Unlock()
}

// handleShutdown handles the shutdown endpoint
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Return success immediately
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "shutting_down",
	})

	// Shutdown the server in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond) // Small delay to allow response to be sent
		s.Stop()
	}()
}

// stopProcessing stops any running processing
func (s *Server) stopProcessing() bool {
	s.processMutex.Lock()
	defer s.processMutex.Unlock()

	if s.isProcessing && s.cancelFunc != nil {
		s.cancelFunc()
		return true
	}
	return false
}

// broadcastProgress broadcasts progress updates to all connected SSE clients
func (s *Server) broadcastProgress() {
	for {
		select {
		case <-s.shutdownSignal:
			return
		case update := <-s.progressChan:
			// Log the progress
			log.Printf("Progress: %d/%d files, %d events, %.2f%%",
				update.FilesProcessed, update.TotalFiles, update.EventsProcessed, update.Percentage)

			// Broadcast to all connected clients
			s.clientsMutex.RLock()
			for clientChan := range s.clients {
				// Non-blocking send to avoid blocking on slow clients
				select {
				case clientChan <- update:
					// Successfully sent
				default:
					// Client buffer full, skip this update for this client
					// The client will receive the next update
				}
			}
			s.clientsMutex.RUnlock()
		}
	}
}

// mustMarshalJSON marshals an object to JSON and handles errors gracefully
func mustMarshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		// Log the error but don't crash the server
		log.Printf("Error marshaling JSON: %v", err)
		// Return a simple error JSON instead
		return `{"error":"Internal server error during JSON serialization"}`
	}
	return string(data)
}

// GetTempDir returns a temporary directory that works across platforms
// and cleans up stale connection files
func GetTempDir() string {
	// Use the system temp directory as a base
	tempBase := os.TempDir()

	// Create a LogZero-specific subdirectory
	logZeroTemp := filepath.Join(tempBase, "LogZero")

	// Set appropriate permissions based on platform
	// Windows doesn't use the same permission bits as Unix systems
	var dirMode os.FileMode = 0755
	if runtime.GOOS == "windows" {
		// On Windows, ensure the directory is accessible to the current user
		dirMode = 0700
	}

	// Ensure the directory exists with appropriate permissions
	if err := os.MkdirAll(logZeroTemp, dirMode); err != nil {
		log.Printf("Failed to create temp directory: %v", err)
		// Fall back to system temp if we can't create our directory
		return tempBase
	}

	// Clean up stale connection files in the background
	go cleanupStaleConnectionFiles(logZeroTemp)

	return logZeroTemp
}

// cleanupStaleConnectionFiles removes old connection files
// that might have been left from previous runs
func cleanupStaleConnectionFiles(dirPath string) {
	// Read all files in the directory
	files, err := os.ReadDir(dirPath)
	if err != nil {
		log.Printf("Failed to read temp directory for cleanup: %v", err)
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

			// Remove files older than 1 hour
			if now.Sub(info.ModTime()) > time.Hour {
				os.Remove(filePath)
				log.Printf("Cleaned up stale connection file: %s", name)
			}
		}
	}
}
