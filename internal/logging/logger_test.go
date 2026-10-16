package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogLevels(t *testing.T) {
	levels := []struct {
		name       string
		levelStr   string
		expectPass bool
	}{
		{"debug", "debug", true},
		{"DEBUG", "DEBUG", true},
		{"info", "info", true},
		{"warn", "warn", true},
		{"error", "error", true},
		{"invalid", "unknown", false},
	}

	for _, tt := range levels {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger, err := New(tt.levelStr, buf)
			if tt.expectPass {
				if err != nil {
					t.Fatalf("unexpected error for %q: %v", tt.levelStr, err)
				}
				if logger == nil {
					t.Fatalf("expected non-nil logger for %q", tt.levelStr)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error for invalid level %q, got nil", tt.levelStr)
				}
			}
		})
	}
}

func TestDebugFiltering(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := New("info", buf)
	if err != nil {
		t.Fatalf("failed to create info logger: %v", err)
	}

	logger.Debug("invisible debug message")
	if strings.Contains(buf.String(), "invisible debug message") {
		t.Error("debug message should not be output when level is info")
	}

	logger.Info("visible info message")
	if !strings.Contains(buf.String(), "visible info message") {
		t.Error("info message should be output when level is info")
	}
}
