package securestorage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

// fileStorage implements Storage using file-based storage with encryption
type fileStorage struct {
	filePath string
	saltPath string
	key      []byte // Derived encryption key
	keyOnce  sync.Once
	keyError error
}

// saltSize is the size of the random salt in bytes
const saltSize = 32

// getOrCreateSalt reads the salt from file or creates a new one
func getOrCreateSalt(saltPath string) ([]byte, error) {
	// Try to read existing salt
	salt, err := os.ReadFile(saltPath)
	if err == nil && len(salt) == saltSize {
		return salt, nil
	}

	// Generate new random salt
	salt = make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Write salt to file with restrictive permissions
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return nil, fmt.Errorf("failed to write salt file: %w", err)
	}

	return salt, nil
}

// getMachineIdentifiers collects machine-specific identifiers for key derivation
func getMachineIdentifiers() string {
	var identifiers []string

	// Hostname
	hostname, _ := os.Hostname()
	if hostname != "" {
		identifiers = append(identifiers, hostname)
	}

	// User-specific identifier (home directory path is unique per user)
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		identifiers = append(identifiers, homeDir)
	}

	// Try to get machine ID (platform-specific)
	machineID := getMachineID()
	if machineID != "" {
		identifiers = append(identifiers, machineID)
	}

	// Combine all identifiers
	combined := ""
	for _, id := range identifiers {
		combined += id + "|"
	}
	return combined
}

// getMachineID attempts to read a machine-specific identifier
func getMachineID() string {
	// Try common locations for machine ID
	locations := []string{
		"/etc/machine-id",          // Linux (systemd)
		"/var/lib/dbus/machine-id", // Linux (older systems)
	}

	for _, path := range locations {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return string(data)
		}
	}

	return ""
}

// deriveKey derives a machine-specific encryption key using HKDF-style expansion
// with a random salt stored in a file for better security
func (s *fileStorage) deriveKey() ([]byte, error) {
	// Get or create random salt
	salt, err := getOrCreateSalt(s.saltPath)
	if err != nil {
		return nil, err
	}

	// Get machine-specific identifiers
	machineInfo := getMachineIdentifiers()

	// Use HMAC-SHA256 for key derivation (simplified HKDF extract)
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(machineInfo))
	h.Write([]byte("LogZero-FileStorage-v2")) // Version identifier
	prk := h.Sum(nil)

	// HKDF expand step
	h = hmac.New(sha256.New, prk)
	h.Write([]byte("encryption-key"))
	h.Write([]byte{0x01}) // Counter
	key := h.Sum(nil)

	return key, nil
}

// encrypt encrypts data using AES-GCM
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the encrypted data to nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// newFileStorage creates a new file-based storage (internal use)
func newFileStorage(tempDir string) *fileStorage {
	return &fileStorage{
		filePath: filepath.Join(tempDir, "logzero_connection.enc"),
		saltPath: filepath.Join(tempDir, "logzero_key.salt"),
	}
}

// NewFileStorage creates a new file-based storage (exported for direct use)
func NewFileStorage(tempDir string) Storage {
	return newFileStorage(tempDir)
}

// getKey returns the encryption key, deriving it lazily on first use
func (s *fileStorage) getKey() ([]byte, error) {
	s.keyOnce.Do(func() {
		s.key, s.keyError = s.deriveKey()
	})
	return s.key, s.keyError
}

// Store stores the connection info in an encrypted file
func (s *fileStorage) Store(info ConnectionInfo) error {
	// Get encryption key
	key, err := s.getKey()
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Marshal the connection info to JSON
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal connection info: %w", err)
	}

	// Encrypt the data
	encrypted, err := encrypt(key, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt connection info: %w", err)
	}

	// Encode as base64 for safe file storage
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	// Write to file atomically to prevent corruption
	// First write to a temporary file, then rename it
	tempFile := s.filePath + ".tmp"

	// Set appropriate file permissions
	var fileMode os.FileMode = 0600
	if runtime.GOOS == "windows" {
		// On Windows, ensure the file is accessible to the current user
		fileMode = 0600
	}

	if err := os.WriteFile(tempFile, []byte(encoded), fileMode); err != nil {
		return fmt.Errorf("failed to write connection info: %w", err)
	}

	// Rename the temp file to the final file (atomic operation)
	if err := os.Rename(tempFile, s.filePath); err != nil {
		os.Remove(tempFile) // Clean up the temp file
		return fmt.Errorf("failed to finalize connection info: %w", err)
	}

	return nil
}

// Load loads the connection info from an encrypted file
func (s *fileStorage) Load() (ConnectionInfo, error) {
	var info ConnectionInfo

	// Get encryption key
	key, err := s.getKey()
	if err != nil {
		return info, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Read the file
	encoded, err := os.ReadFile(s.filePath)
	if err != nil {
		return info, fmt.Errorf("failed to read connection info: %w", err)
	}

	// Decode from base64
	encrypted, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return info, fmt.Errorf("failed to decode connection info: %w", err)
	}

	// Decrypt the data
	data, err := decrypt(key, encrypted)
	if err != nil {
		return info, fmt.Errorf("failed to decrypt connection info: %w", err)
	}

	// Unmarshal the connection info
	err = json.Unmarshal(data, &info)
	if err != nil {
		return info, fmt.Errorf("failed to unmarshal connection info: %w", err)
	}

	return info, nil
}

// Delete deletes the connection info file and salt file
func (s *fileStorage) Delete() error {
	// Delete the encrypted connection info file
	err := os.Remove(s.filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete connection info: %w", err)
	}

	// Also delete the salt file (optional, but good for cleanup)
	// A new salt will be generated on next use
	_ = os.Remove(s.saltPath)

	return nil
}

// IsAvailable returns true if file-based storage is available
func (s *fileStorage) IsAvailable() bool {
	// File-based storage is always available
	return true
}
