// Package config loads, validates, and safely persists Orynelo settings.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/platform"
	"gopkg.in/yaml.v3"
)

const (
	// SchemaVersion is the current YAML configuration schema.
	SchemaVersion = application.ConfigSchemaVersion

	maxConfigBytes = 1 << 20
)

// InvalidError identifies configuration content that the user can correct.
// Filesystem and other runtime failures remain ordinary errors.
type InvalidError struct {
	Err error
}

func (e *InvalidError) Error() string {
	if e == nil || e.Err == nil {
		return "invalid configuration"
	}
	return e.Err.Error()
}

// Unwrap returns the underlying configuration parsing error.
func (e *InvalidError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsInvalid reports whether an error represents malformed or invalid
// configuration content.
func IsInvalid(err error) bool {
	var invalid *InvalidError
	return errors.As(err, &invalid)
}

func invalid(err error) error {
	return &InvalidError{Err: err}
}

// Configuration data belongs to the inward-facing application layer. Aliases
// keep the config package focused on its filesystem/YAML adapter role while
// preserving the public names used by the composition roots and UIs.
type Config = application.Config
type DiagnosticsConfig = application.DiagnosticsConfig
type NetworkConfig = application.NetworkConfig
type HistoryConfig = application.HistoryConfig
type AppearanceConfig = application.AppearanceConfig
type LoggingConfig = application.LoggingConfig

// Default returns a complete, validated configuration.
func Default() Config {
	return application.DefaultConfig()
}

// Load reads a YAML file. A missing file returns defaults so first launch does
// not require a write.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspect configuration %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, invalid(fmt.Errorf("configuration %q is not a regular file", path))
	}
	if info.Size() > maxConfigBytes {
		return Config{}, invalid(fmt.Errorf("configuration %q exceeds %d bytes", path, maxConfigBytes))
	}

	cfg := Default()
	decoder := yaml.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, invalid(fmt.Errorf("decode configuration %q: %w", path, err))
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, invalid(fmt.Errorf(
				"decode configuration %q: multiple YAML documents are not allowed",
				path,
			))
		}
		return Config{}, invalid(fmt.Errorf("decode configuration %q: %w", path, err))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, invalid(fmt.Errorf("validate configuration %q: %w", path, err))
	}
	return cfg, nil
}

// Save validates and atomically replaces a YAML configuration file. The
// temporary file lives beside the destination so rename remains on one
// filesystem.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	content, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if len(content) > maxConfigBytes {
		return fmt.Errorf("encoded configuration exceeds %d bytes", maxConfigBytes)
	}

	dir := filepath.Dir(path)
	if err := platform.EnsurePrivateDir(dir); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary configuration in %q: %w", dir, err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary configuration: %w", err)
	}
	if err := replace(tempPath, path); err != nil {
		return fmt.Errorf("replace configuration %q: %w", path, err)
	}
	committed = true

	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open configuration directory for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync configuration directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close configuration directory: %w", closeErr)
		}
	}
	return nil
}

func replace(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}

	// Windows does not replace an existing destination with os.Rename. This
	// fallback is not fully atomic, but the source has already been synced and
	// remains recoverable until the destination is removed.
	if _, err := os.Lstat(destination); err != nil {
		return err
	}
	if err := os.Remove(destination); err != nil {
		return err
	}
	return os.Rename(source, destination)
}

// LoadDefault loads configuration from the current platform path.
func LoadDefault() (Config, error) {
	paths, err := platform.DefaultPaths()
	if err != nil {
		return Config{}, err
	}
	return Load(paths.ConfigFile)
}

// SaveDefault saves configuration to the current platform path.
func SaveDefault(cfg Config) error {
	paths, err := platform.DefaultPaths()
	if err != nil {
		return err
	}
	return Save(paths.ConfigFile, cfg)
}

// Store binds configuration operations to a path, which is convenient for
// application-layer dependency injection.
type Store struct {
	path string
}

// NewStore returns a path-bound configuration store.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// DefaultStore returns a store using the current platform configuration path.
func DefaultStore() (*Store, error) {
	paths, err := platform.DefaultPaths()
	if err != nil {
		return nil, err
	}
	return NewStore(paths.ConfigFile), nil
}

// Path returns the configuration file path.
func (s *Store) Path() string {
	return s.path
}

// Load reads this store.
func (s *Store) Load() (Config, error) {
	return Load(s.path)
}

// Save writes this store.
func (s *Store) Save(cfg Config) error {
	return Save(s.path, cfg)
}
