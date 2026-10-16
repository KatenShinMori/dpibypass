package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// New creates a structured slog.Logger configured with the specified log level.
// Output defaults to os.Stderr if w is nil.
//
// Privacy and safety invariant:
// Handlers and callers must NEVER log sensitive application payloads, complete HTTP URLs,
// authorization tokens, or cookies. Logging is restricted to operational lifecycle events,
// domain destinations, strategy names, failure classifications, and timing.
func New(levelStr string, w io.Writer) (*slog.Logger, error) {
	if w == nil {
		w = os.Stderr
	}

	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q; expected debug, info, warn, or error", levelStr)
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(w, opts)
	return slog.New(handler), nil
}
