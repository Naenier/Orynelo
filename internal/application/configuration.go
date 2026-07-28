package application

import (
	"fmt"
	"strings"
	"time"
)

const (
	// ConfigSchemaVersion is the current user-configuration schema.
	ConfigSchemaVersion = "1"
)

// Config contains settings consumed by the application layer. Infrastructure
// adapters are responsible for loading and persisting this value.
type Config struct {
	SchemaVersion string            `yaml:"schemaVersion"`
	Diagnostics   DiagnosticsConfig `yaml:"diagnostics"`
	Network       NetworkConfig     `yaml:"network"`
	History       HistoryConfig     `yaml:"history"`
	Appearance    AppearanceConfig  `yaml:"appearance"`
	Logging       LoggingConfig     `yaml:"logging"`
}

// DiagnosticsConfig controls diagnostic defaults.
type DiagnosticsConfig struct {
	DefaultTimeout              time.Duration `yaml:"defaultTimeout"`
	CheckTimeout                time.Duration `yaml:"checkTimeout"`
	MaxRedirects                int           `yaml:"maxRedirects"`
	PreferredIPVersion          string        `yaml:"preferredIPVersion"`
	CertificateWarningThreshold time.Duration `yaml:"certificateWarningThreshold"`
}

// NetworkConfig controls proxy use and the outbound HTTP user agent.
type NetworkConfig struct {
	UseSystemProxy bool   `yaml:"useSystemProxy"`
	UserAgent      string `yaml:"userAgent"`
}

// HistoryConfig controls local diagnostic history retention.
type HistoryConfig struct {
	Enabled    bool `yaml:"enabled"`
	MaxEntries int  `yaml:"maxEntries"`
}

// AppearanceConfig controls the desktop theme.
type AppearanceConfig struct {
	Theme string `yaml:"theme"`
}

// LoggingConfig controls application logging.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// DefaultConfig returns a complete, validated configuration.
func DefaultConfig() Config {
	return Config{
		SchemaVersion: ConfigSchemaVersion,
		Diagnostics: DiagnosticsConfig{
			DefaultTimeout:              15 * time.Second,
			CheckTimeout:                5 * time.Second,
			MaxRedirects:                10,
			PreferredIPVersion:          "auto",
			CertificateWarningThreshold: 30 * 24 * time.Hour,
		},
		Network: NetworkConfig{
			UseSystemProxy: true,
			UserAgent:      "OpsDoctor",
		},
		History: HistoryConfig{
			Enabled:    true,
			MaxEntries: 200,
		},
		Appearance: AppearanceConfig{Theme: "system"},
		Logging:    LoggingConfig{Level: "info"},
	}
}

// Validate checks configuration values before they reach diagnostic or GUI
// code.
func (c Config) Validate() error {
	var problems []string

	if c.SchemaVersion != ConfigSchemaVersion {
		problems = append(problems, fmt.Sprintf("schemaVersion must be %q", ConfigSchemaVersion))
	}
	if c.Diagnostics.DefaultTimeout <= 0 || c.Diagnostics.DefaultTimeout > 24*time.Hour {
		problems = append(problems, "diagnostics.defaultTimeout must be greater than zero and at most 24h")
	}
	if c.Diagnostics.CheckTimeout <= 0 || c.Diagnostics.CheckTimeout > c.Diagnostics.DefaultTimeout {
		problems = append(problems, "diagnostics.checkTimeout must be greater than zero and no longer than defaultTimeout")
	}
	if c.Diagnostics.MaxRedirects < 0 || c.Diagnostics.MaxRedirects > 50 {
		problems = append(problems, "diagnostics.maxRedirects must be between 0 and 50")
	}
	switch c.Diagnostics.PreferredIPVersion {
	case "auto", "4", "6":
	default:
		problems = append(problems, `diagnostics.preferredIPVersion must be "auto", "4", or "6"`)
	}
	if c.Diagnostics.CertificateWarningThreshold < 0 ||
		c.Diagnostics.CertificateWarningThreshold > 365*24*time.Hour {
		problems = append(
			problems,
			"diagnostics.certificateWarningThreshold must be between 0 and 8760h",
		)
	}
	if len(c.Network.UserAgent) > 256 || containsControl(c.Network.UserAgent) {
		problems = append(problems, "network.userAgent must be at most 256 characters and contain no control characters")
	}
	if c.History.MaxEntries < 1 || c.History.MaxEntries > 10_000 {
		problems = append(problems, "history.maxEntries must be between 1 and 10000")
	}
	switch c.Appearance.Theme {
	case "system", "light", "dark":
	default:
		problems = append(problems, `appearance.theme must be "system", "light", or "dark"`)
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, `logging.level must be "debug", "info", "warn", or "error"`)
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
