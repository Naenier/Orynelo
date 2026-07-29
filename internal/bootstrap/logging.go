package bootstrap

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Naenier/opsdoctor/internal/platform"
	"github.com/Naenier/opsdoctor/internal/redaction"
)

// Logging owns the application logger, dynamic level, and optional log file.
type Logging struct {
	Logger *slog.Logger
	level  *slog.LevelVar
	file   *os.File
}

// NewLogging opens a private JSON log and installs mandatory redaction.
func NewLogging(path, level string) (*Logging, error) {
	file, err := platform.OpenLogFile(path)
	if err != nil {
		return nil, err
	}
	runtime, err := newLogging(file, level)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	runtime.file = file
	return runtime, nil
}

func newLogging(writer io.Writer, level string) (*Logging, error) {
	levelVar := new(slog.LevelVar)
	runtime := &Logging{level: levelVar}
	if err := runtime.SetLevel(level); err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: levelVar})
	runtime.Logger = slog.New(redaction.NewHandler(handler))
	return runtime, nil
}

// SetLevel changes the minimum emitted level.
func (l *Logging) SetLevel(value string) error {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("log level must be debug, info, warn, or error, got %q", value)
	}
	l.level.Set(level)
	return nil
}

// Close flushes and closes the log file.
func (l *Logging) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
