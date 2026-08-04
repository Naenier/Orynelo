// Package platform provides operating-system-specific filesystem locations and
// small, cross-platform infrastructure helpers.
package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	appDirUnix = "orynelo"
	appDirGUI  = "Orynelo"
)

// Paths contains every persistent file location used by Orynelo.
type Paths struct {
	ConfigDir    string
	DataDir      string
	StateDir     string
	ConfigFile   string
	DatabaseFile string
	LogFile      string
}

// LookupEnv is compatible with os.LookupEnv and makes path resolution
// deterministic in tests.
type LookupEnv func(string) (string, bool)

// DefaultPaths resolves paths for the current user and operating system.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve user home directory: %w", err)
	}

	return PathsFor(runtime.GOOS, home, os.LookupEnv)
}

// PathsFor resolves application paths for an operating system. It is exported
// so callers and tests can inspect paths without mutating process environment.
func PathsFor(goos, home string, lookup LookupEnv) (Paths, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	var configDir, dataDir, stateDir string
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		if home == "" {
			return Paths{}, errors.New("user home directory is empty")
		}
		configDir = filepath.Join(xdgBase(lookup, "XDG_CONFIG_HOME", filepath.Join(home, ".config")), appDirUnix)
		dataDir = filepath.Join(xdgBase(lookup, "XDG_DATA_HOME", filepath.Join(home, ".local", "share")), appDirUnix)
		stateDir = filepath.Join(xdgBase(lookup, "XDG_STATE_HOME", filepath.Join(home, ".local", "state")), appDirUnix)
	case "darwin":
		if home == "" {
			return Paths{}, errors.New("user home directory is empty")
		}
		configDir = filepath.Join(home, "Library", "Application Support", appDirGUI)
		dataDir = configDir
		stateDir = filepath.Join(home, "Library", "Logs", appDirGUI)
	case "windows":
		roaming := envPath(lookup, "APPDATA")
		local := envPath(lookup, "LOCALAPPDATA")
		if roaming == "" && home != "" {
			roaming = filepath.Join(home, "AppData", "Roaming")
		}
		if local == "" && home != "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		if roaming == "" || local == "" {
			return Paths{}, errors.New("APPDATA and LOCALAPPDATA are unavailable")
		}
		configDir = filepath.Join(roaming, appDirGUI)
		dataDir = filepath.Join(local, appDirGUI)
		stateDir = filepath.Join(local, appDirGUI, "Logs")
	default:
		if home == "" {
			return Paths{}, errors.New("user home directory is empty")
		}
		configDir = filepath.Join(home, ".config", appDirUnix)
		dataDir = filepath.Join(home, ".local", "share", appDirUnix)
		stateDir = filepath.Join(home, ".local", "state", appDirUnix)
	}

	return Paths{
		ConfigDir:    configDir,
		DataDir:      dataDir,
		StateDir:     stateDir,
		ConfigFile:   filepath.Join(configDir, "config.yaml"),
		DatabaseFile: filepath.Join(dataDir, "orynelo.db"),
		LogFile:      filepath.Join(stateDir, "orynelo.log"),
	}, nil
}

func xdgBase(lookup LookupEnv, name, fallback string) string {
	value := envPath(lookup, name)
	if value == "" || !filepath.IsAbs(value) {
		return fallback
	}
	return value
}

func envPath(lookup LookupEnv, name string) string {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return ""
	}
	return filepath.Clean(value)
}

// EnsurePrivateDir creates a directory hierarchy that is private to the
// current user. Chmod also corrects a directory created under a permissive
// umask on platforms that support POSIX permissions.
func EnsurePrivateDir(path string) error {
	if path == "" {
		return errors.New("directory path is empty")
	}
	clean := filepath.Clean(path)
	if clean == "." {
		info, err := os.Stat(clean)
		if err != nil {
			return fmt.Errorf("inspect current directory: %w", err)
		}
		if !info.IsDir() {
			return errors.New("current path is not a directory")
		}
		return nil
	}
	if clean == filepath.VolumeName(clean)+string(filepath.Separator) {
		return fmt.Errorf("refusing to modify filesystem root %q", clean)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("create private directory %q: %w", clean, err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect private directory %q: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory %q is a symbolic link", clean)
	}
	if !info.IsDir() {
		return fmt.Errorf("private directory %q is not a directory", clean)
	}
	if err := os.Chmod(clean, 0o700); err != nil {
		return fmt.Errorf("set private directory permissions for %q: %w", clean, err)
	}
	return nil
}

// Ensure creates the config, data, and state directories.
func (p Paths) Ensure() error {
	seen := make(map[string]struct{}, 3)
	for _, dir := range []string{p.ConfigDir, p.DataDir, p.StateDir} {
		if _, ok := seen[dir]; ok {
			continue
		}
		if err := EnsurePrivateDir(dir); err != nil {
			return err
		}
		seen[dir] = struct{}{}
	}
	return nil
}

// OpenLogFile opens a private append-only application log file.
func OpenLogFile(path string) (*os.File, error) {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("log file %q is a symbolic link", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("log file %q is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect log file %q: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set log file permissions for %q: %w", path, err)
	}
	return file, nil
}
