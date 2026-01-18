package securestorage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	// ServiceName is the name of the service used for keyring storage
	ServiceName = "LogZero"

	// DefaultUsername is the default username used for keyring storage
	DefaultUsername = "connection_info"
)

var (
	// ErrSecureStorageUnavailable is returned when secure storage is not available
	ErrSecureStorageUnavailable = errors.New("secure storage is not available")
)

// ConnectionInfo represents the connection information
type ConnectionInfo struct {
	Port      int    `json:"port"`
	AuthToken string `json:"auth_token"`
	Ready     bool   `json:"ready"`
}

// Storage represents a secure storage interface
type Storage interface {
	// Store stores the connection info securely
	Store(info ConnectionInfo) error

	// Load loads the connection info from secure storage
	Load() (ConnectionInfo, error)

	// Delete deletes the connection info from secure storage
	Delete() error

	// IsAvailable returns true if secure storage is available
	IsAvailable() bool
}

// NewStorage creates a new secure storage instance
// It tries to use platform-specific secure storage first,
// and falls back to file-based storage if not available
func NewStorage(tempDir string) Storage {
	// Try platform-specific secure storage first
	secureStorage := newSecureKeyringStorage()

	// Check if secure storage is available
	if secureStorage.IsAvailable() {
		return secureStorage
	}

	// Fall back to file-based storage
	return newFileStorage(tempDir)
}

// secureKeyringStorage implements Storage using platform-specific secure storage
type secureKeyringStorage struct {
	available bool
}

// newSecureKeyringStorage creates a new secure keyring storage
func newSecureKeyringStorage() *secureKeyringStorage {
	// Check if keyring is available by attempting a simple operation
	available := true

	// Try to delete any existing entry (ignore errors)
	_ = keyring.Delete(ServiceName, DefaultUsername)

	// Try to set and get a test value
	testValue := fmt.Sprintf("test-%d", time.Now().UnixNano())
	err := keyring.Set(ServiceName, DefaultUsername, testValue)
	if err != nil {
		available = false
	} else {
		// Try to retrieve the value
		retrievedValue, err := keyring.Get(ServiceName, DefaultUsername)
		if err != nil || retrievedValue != testValue {
			available = false
		}

		// Clean up
		_ = keyring.Delete(ServiceName, DefaultUsername)
	}

	return &secureKeyringStorage{
		available: available,
	}
}

// Store stores the connection info in the secure keyring
func (s *secureKeyringStorage) Store(info ConnectionInfo) error {
	if !s.available {
		return ErrSecureStorageUnavailable
	}

	// Marshal the connection info to JSON
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal connection info: %w", err)
	}

	// Store in the keyring
	err = keyring.Set(ServiceName, DefaultUsername, string(data))
	if err != nil {
		return fmt.Errorf("failed to store in secure keyring: %w", err)
	}

	return nil
}

// Load loads the connection info from the secure keyring
func (s *secureKeyringStorage) Load() (ConnectionInfo, error) {
	var info ConnectionInfo

	if !s.available {
		return info, ErrSecureStorageUnavailable
	}

	// Get from the keyring
	data, err := keyring.Get(ServiceName, DefaultUsername)
	if err != nil {
		return info, fmt.Errorf("failed to load from secure keyring: %w", err)
	}

	// Unmarshal the connection info
	err = json.Unmarshal([]byte(data), &info)
	if err != nil {
		return info, fmt.Errorf("failed to unmarshal connection info: %w", err)
	}

	return info, nil
}

// Delete deletes the connection info from the secure keyring
func (s *secureKeyringStorage) Delete() error {
	if !s.available {
		return ErrSecureStorageUnavailable
	}

	// Delete from the keyring
	err := keyring.Delete(ServiceName, DefaultUsername)
	if err != nil {
		return fmt.Errorf("failed to delete from secure keyring: %w", err)
	}

	return nil
}

// IsAvailable returns true if secure keyring storage is available
func (s *secureKeyringStorage) IsAvailable() bool {
	return s.available
}

// fileStorage implements Storage using file-based storage
type fileStorage struct {
	filePath string
}

// newFileStorage creates a new file-based storage (internal use)
func newFileStorage(tempDir string) *fileStorage {
	return &fileStorage{
		filePath: filepath.Join(tempDir, "logzero_connection.json"),
	}
}

// NewFileStorage creates a new file-based storage (exported for direct use)
func NewFileStorage(tempDir string) Storage {
	return newFileStorage(tempDir)
}

// Store stores the connection info in a file
func (s *fileStorage) Store(info ConnectionInfo) error {
	// Marshal the connection info to JSON
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal connection info: %w", err)
	}

	// Write to file atomically to prevent corruption
	// First write to a temporary file, then rename it
	tempFile := s.filePath + ".tmp"

	// Set appropriate file permissions
	var fileMode os.FileMode = 0600
	if runtime.GOOS == "windows" {
		// On Windows, ensure the file is accessible to the current user
		fileMode = 0600
	}

	if err := os.WriteFile(tempFile, data, fileMode); err != nil {
		return fmt.Errorf("failed to write connection info: %w", err)
	}

	// Rename the temp file to the final file (atomic operation)
	if err := os.Rename(tempFile, s.filePath); err != nil {
		os.Remove(tempFile) // Clean up the temp file
		return fmt.Errorf("failed to finalize connection info: %w", err)
	}

	return nil
}

// Load loads the connection info from a file
func (s *fileStorage) Load() (ConnectionInfo, error) {
	var info ConnectionInfo

	// Read the file
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return info, fmt.Errorf("failed to read connection info: %w", err)
	}

	// Unmarshal the connection info
	err = json.Unmarshal(data, &info)
	if err != nil {
		return info, fmt.Errorf("failed to unmarshal connection info: %w", err)
	}

	return info, nil
}

// Delete deletes the connection info file
func (s *fileStorage) Delete() error {
	err := os.Remove(s.filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete connection info: %w", err)
	}

	return nil
}

// IsAvailable returns true if file-based storage is available
func (s *fileStorage) IsAvailable() bool {
	// File-based storage is always available
	return true
}
