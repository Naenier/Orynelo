package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultValid(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate() error = %v", err)
	}
	if cfg.History.MaxEntries != 200 {
		t.Errorf("History.MaxEntries = %d, want 200", cfg.History.MaxEntries)
	}
	if cfg.Diagnostics.MaxRedirects != 10 {
		t.Errorf("Diagnostics.MaxRedirects = %d, want 10", cfg.Diagnostics.MaxRedirects)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "schema",
			mutate: func(c *Config) { c.SchemaVersion = "2" },
			want:   "schemaVersion",
		},
		{
			name:   "timeout",
			mutate: func(c *Config) { c.Diagnostics.DefaultTimeout = 0 },
			want:   "defaultTimeout",
		},
		{
			name:   "check timeout",
			mutate: func(c *Config) { c.Diagnostics.CheckTimeout = c.Diagnostics.DefaultTimeout + time.Second },
			want:   "checkTimeout",
		},
		{
			name:   "redirects",
			mutate: func(c *Config) { c.Diagnostics.MaxRedirects = 51 },
			want:   "maxRedirects",
		},
		{
			name:   "IP preference",
			mutate: func(c *Config) { c.Diagnostics.PreferredIPVersion = "ipv7" },
			want:   "preferredIPVersion",
		},
		{
			name:   "user agent injection",
			mutate: func(c *Config) { c.Network.UserAgent = "OpsDoctor\r\nX-Evil: yes" },
			want:   "userAgent",
		},
		{
			name:   "history",
			mutate: func(c *Config) { c.History.MaxEntries = 0 },
			want:   "maxEntries",
		},
		{
			name:   "theme",
			mutate: func(c *Config) { c.Appearance.Theme = "blue" },
			want:   "theme",
		},
		{
			name:   "log level",
			mutate: func(c *Config) { c.Logging.Level = "trace" },
			want:   "logging.level",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	cfg := Default()
	cfg.Diagnostics.DefaultTimeout = 42 * time.Second
	cfg.Network.UserAgent = "OpsDoctor test"
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got != cfg {
		t.Fatalf("Load() = %#v, want %#v", got, cfg)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(content), "defaultTimeout: 42s") {
		t.Errorf("saved YAML does not contain a readable duration:\n%s", content)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("permissions = %o, want 600", got)
		}
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got != Default() {
		t.Fatalf("Load(missing) = %#v, want defaults", got)
	}
}

func TestLoadMergesDefaultsAndRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("schemaVersion: \"1\"\nhistory:\n  maxEntries: 50\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.History.MaxEntries != 50 || !got.History.Enabled {
		t.Fatalf("Load() did not merge defaults: %#v", got.History)
	}

	if err := os.WriteFile(path, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil for an unknown field")
	} else if !IsInvalid(err) {
		t.Fatalf("Load() error = %T %v, want InvalidError", err, err)
	}
}

func TestSaveRejectsInvalidWithoutReplacingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg := Default()
	cfg.History.MaxEntries = 0
	if err := Save(path, cfg); err == nil {
		t.Fatal("Save() error = nil, want validation error")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "original" {
		t.Fatalf("invalid Save() changed existing file to %q", content)
	}
}
