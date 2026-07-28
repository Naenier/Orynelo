package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathsFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		goos      string
		home      string
		env       map[string]string
		configDir string
		dataDir   string
		stateDir  string
		wantErr   bool
	}{
		{
			name:      "linux defaults",
			goos:      "linux",
			home:      filepath.Join(string(filepath.Separator), "home", "alice"),
			configDir: filepath.Join(string(filepath.Separator), "home", "alice", ".config", "opsdoctor"),
			dataDir:   filepath.Join(string(filepath.Separator), "home", "alice", ".local", "share", "opsdoctor"),
			stateDir:  filepath.Join(string(filepath.Separator), "home", "alice", ".local", "state", "opsdoctor"),
		},
		{
			name: "linux XDG",
			goos: "linux",
			home: filepath.Join(string(filepath.Separator), "home", "alice"),
			env: map[string]string{
				"XDG_CONFIG_HOME": filepath.Join(string(filepath.Separator), "xdg", "config"),
				"XDG_DATA_HOME":   filepath.Join(string(filepath.Separator), "xdg", "data"),
				"XDG_STATE_HOME":  filepath.Join(string(filepath.Separator), "xdg", "state"),
			},
			configDir: filepath.Join(string(filepath.Separator), "xdg", "config", "opsdoctor"),
			dataDir:   filepath.Join(string(filepath.Separator), "xdg", "data", "opsdoctor"),
			stateDir:  filepath.Join(string(filepath.Separator), "xdg", "state", "opsdoctor"),
		},
		{
			name:      "linux ignores relative XDG paths",
			goos:      "linux",
			home:      filepath.Join(string(filepath.Separator), "home", "alice"),
			env:       map[string]string{"XDG_CONFIG_HOME": "relative"},
			configDir: filepath.Join(string(filepath.Separator), "home", "alice", ".config", "opsdoctor"),
			dataDir:   filepath.Join(string(filepath.Separator), "home", "alice", ".local", "share", "opsdoctor"),
			stateDir:  filepath.Join(string(filepath.Separator), "home", "alice", ".local", "state", "opsdoctor"),
		},
		{
			name:      "macOS conventions",
			goos:      "darwin",
			home:      filepath.Join(string(filepath.Separator), "Users", "alice"),
			configDir: filepath.Join(string(filepath.Separator), "Users", "alice", "Library", "Application Support", "OpsDoctor"),
			dataDir:   filepath.Join(string(filepath.Separator), "Users", "alice", "Library", "Application Support", "OpsDoctor"),
			stateDir:  filepath.Join(string(filepath.Separator), "Users", "alice", "Library", "Logs", "OpsDoctor"),
		},
		{
			name: "Windows conventions",
			goos: "windows",
			home: `C:\Users\alice`,
			env:  map[string]string{"APPDATA": `C:\Users\alice\AppData\Roaming`, "LOCALAPPDATA": `C:\Users\alice\AppData\Local`},
			configDir: filepath.Join(
				`C:\Users\alice\AppData\Roaming`,
				"OpsDoctor",
			),
			dataDir: filepath.Join(
				`C:\Users\alice\AppData\Local`,
				"OpsDoctor",
			),
			stateDir: filepath.Join(
				`C:\Users\alice\AppData\Local`,
				"OpsDoctor",
				"Logs",
			),
		},
		{name: "missing home", goos: "linux", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(name string) (string, bool) {
				value, ok := tt.env[name]
				return value, ok
			}
			got, err := PathsFor(tt.goos, tt.home, lookup)
			if tt.wantErr {
				if err == nil {
					t.Fatal("PathsFor() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("PathsFor() error = %v", err)
			}
			if got.ConfigDir != tt.configDir || got.DataDir != tt.dataDir || got.StateDir != tt.stateDir {
				t.Fatalf("PathsFor() directories = (%q, %q, %q), want (%q, %q, %q)",
					got.ConfigDir, got.DataDir, got.StateDir, tt.configDir, tt.dataDir, tt.stateDir)
			}
			if got.ConfigFile != filepath.Join(tt.configDir, "config.yaml") {
				t.Errorf("ConfigFile = %q", got.ConfigFile)
			}
			if got.DatabaseFile != filepath.Join(tt.dataDir, "opsdoctor.db") {
				t.Errorf("DatabaseFile = %q", got.DatabaseFile)
			}
			if got.LogFile != filepath.Join(tt.stateDir, "opsdoctor.log") {
				t.Errorf("LogFile = %q", got.LogFile)
			}
		})
	}
}

func TestEnsureAndOpenLogFilePermissions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	paths := Paths{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		StateDir:  filepath.Join(root, "state"),
		LogFile:   filepath.Join(root, "state", "opsdoctor.log"),
	}
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	file, err := OpenLogFile(paths.LogFile)
	if err != nil {
		t.Fatalf("OpenLogFile() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	for _, path := range []string{paths.ConfigDir, paths.DataDir, paths.StateDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q) error = %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%q permissions = %o, want 700", path, got)
		}
	}
	info, err := os.Stat(paths.LogFile)
	if err != nil {
		t.Fatalf("Stat(log) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("log permissions = %o, want 600", got)
	}
}

func TestEnsurePrivateDirDoesNotChmodCurrentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not available")
	}

	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	originalMode := info.Mode().Perm()
	command := exec.Command(os.Args[0], "-test.run=^TestEnsurePrivateDirCurrentDirectoryHelper$")
	command.Dir = root
	command.Env = append(os.Environ(), "OPSDOCTOR_PATH_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper process error = %v\n%s", err, output)
	}
	info, err = os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != originalMode {
		t.Errorf("current directory permissions changed from %o to %o", originalMode, got)
	}
}

func TestEnsurePrivateDirCurrentDirectoryHelper(t *testing.T) {
	if os.Getenv("OPSDOCTOR_PATH_HELPER") != "1" {
		return
	}
	if err := EnsurePrivateDir("."); err != nil {
		t.Fatalf("EnsurePrivateDir(.) error = %v", err)
	}
}

func TestOpenLogFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on some Windows systems")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("do not append"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "opsdoctor.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLogFile(link); err == nil {
		t.Fatal("OpenLogFile(symlink) error = nil")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do not append" {
		t.Fatalf("target content changed to %q", content)
	}
}
