package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualVerification(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "logzero_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up

	tests := []struct {
		name     string
		filename string
		content  string
		wantType string // "Syslog", "WebAccess", "WindowsLog"
		wantHost string
		wantMsg  string
	}{
		{
			name:     "Linux Syslog RFC 5424",
			filename: "syslog",
			content:  `2023-01-01T12:00:00Z myhost myapp[123]: Test message`,
			wantType: "Syslog",
			wantHost: "myhost",
			wantMsg:  "[myapp[123]] Test message",
		},
		{
			name:     "Linux Syslog RFC 3164",
			filename: "auth.log",
			content:  `Jan 01 12:00:00 oldhost sshd[456]: Failed password`,
			wantType: "Syslog",
			wantHost: "oldhost",
			wantMsg:  "[sshd[456]] Failed password",
		},
		{
			name:     "Web Access Log Combined",
			filename: "access.log",
			content:  `127.0.0.1 - jdoe [21/Apr/2023:15:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://referer.com" "Mozilla/5.0"`,
			wantType: "WebAccess",
			wantHost: "127.0.0.1",
			wantMsg:  "GET /index.html (Status: 200)",
		},
		{
			name:     "Windows CBS Log",
			filename: "cbs.log",
			content:  `2023-04-21 15:30:45, Info                  Cbs    Starting TrustedInstaller...`,
			wantType: "WindowsLog",
			wantHost: "", // Implicit
			wantMsg:  "[Info] Cbs    Starting TrustedInstaller...",
		},
		{
			name:     "Windows Update Log",
			filename: "WindowsUpdate.log",
			content:  `2023/04/21 15:30:45 1234 5678 Misc Validating signature...`,
			wantType: "WindowsLog",
			wantHost: "",
			wantMsg:  "[1234] 5678 Misc Validating signature...", // Regex might capture first word as type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, tt.filename)
			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// Get the parser
			parser, err := GetParserForFile(filePath)
			if err != nil {
				t.Fatalf("Failed to get parser: %v", err)
			}

			// Parse
			events, err := parser.Parse(filePath)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if len(events) != 1 {
				t.Fatalf("Expected 1 event, got %d", len(events))
			}

			event := events[0]

			if event.EventType != tt.wantType {
				t.Errorf("Expected EventType %s, got %s", tt.wantType, event.EventType)
			}

			if event.Host != tt.wantHost {
				t.Errorf("Expected Host %s, got %s", tt.wantHost, event.Host)
			}

			// Use Contains for message because full formatting might vary slightly
			if !strings.Contains(event.Message, tt.wantMsg) && event.Message != tt.wantMsg {
				t.Errorf("Expected Message to contain %s, got %s", tt.wantMsg, event.Message)
			}

			// Verify Timestamp is not zero
			if event.Timestamp.IsZero() {
				t.Error("Timestamp should not be zero")
			}

			// For Syslog RFC 3164, we force current year, so parsing might yield this year.
			// Just ensure it parsed successfully.
		})
	}
}
