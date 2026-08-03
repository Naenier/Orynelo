package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/privacy"
)

type fakeApplication struct {
	diagnosis model.Diagnosis
	err       error
	options   model.DiagnoseOptions
	format    string
	mode      privacy.Mode
	content   []byte
}

type shortWriter struct{}

func (shortWriter) Write(content []byte) (int, error) {
	if len(content) == 0 {
		return 0, nil
	}
	return len(content) - 1, nil
}

func (f *fakeApplication) Diagnose(
	_ context.Context,
	options model.DiagnoseOptions,
	sink model.EventSink,
) (model.Diagnosis, error) {
	f.options = options
	if sink != nil {
		sink(model.CheckEvent{
			Type:      model.EventCheckCompleted,
			CheckName: "Target validation",
			Status:    model.StatusPassed,
		})
	}
	return f.diagnosis, f.err
}

func (f *fakeApplication) RenderReport(
	format string,
	_ model.Diagnosis,
	mode privacy.Mode,
) ([]byte, error) {
	f.format = format
	f.mode = mode
	return f.content, nil
}

func TestDiagnoseCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		status     model.Status
		appErr     error
		wantCode   int
		wantFormat string
		wantMode   privacy.Mode
	}{
		{
			name:       "successful JSON report",
			args:       []string{"diagnose", "https://example.test", "--format", "json", "--ip-version", "4"},
			status:     model.StatusPassed,
			wantCode:   ExitOK,
			wantFormat: "json",
			wantMode:   privacy.ModeStandard,
		},
		{
			name:       "markdown alias with strict anonymization",
			args:       []string{"diagnose", "https://example.test", "--format", "md", "--anonymize", "strict"},
			status:     model.StatusPassed,
			wantCode:   ExitOK,
			wantFormat: "markdown",
			wantMode:   privacy.ModeStrict,
		},
		{
			name:       "failed critical check",
			args:       []string{"diagnose", "host.test:443"},
			status:     model.StatusFailed,
			wantCode:   ExitFailure,
			wantFormat: "text",
			wantMode:   privacy.ModeStandard,
		},
		{
			name:     "invalid IP preference",
			args:     []string{"diagnose", "host.test", "--ip-version", "7"},
			status:   model.StatusPassed,
			wantCode: ExitInput,
		},
		{
			name:     "unsafe method",
			args:     []string{"diagnose", "host.test", "--method", "DELETE"},
			status:   model.StatusPassed,
			wantCode: ExitInput,
		},
		{
			name:     "per-check timeout exceeds global timeout",
			args:     []string{"diagnose", "host.test", "--timeout", "2s", "--check-timeout", "3s"},
			status:   model.StatusPassed,
			wantCode: ExitInput,
		},
		{
			name:     "global timeout exceeds application limit",
			args:     []string{"diagnose", "host.test", "--timeout", "25h"},
			status:   model.StatusPassed,
			wantCode: ExitInput,
		},
		{
			name:     "cancelled",
			args:     []string{"diagnose", "host.test"},
			status:   model.StatusPassed,
			appErr:   context.Canceled,
			wantCode: ExitCancel,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			app := &fakeApplication{
				diagnosis: model.Diagnosis{Summary: model.Summary{Status: tt.status}},
				err:       tt.appErr,
				content:   []byte("report\n"),
			}
			root := NewRoot(Options{
				Application: app,
				Build:       buildinfo.Info{Version: "test"},
				Stdout:      &stdout,
				Stderr:      &stderr,
			})
			root.SetArgs(tt.args)
			if got := Execute(context.Background(), root, &stderr); got != tt.wantCode {
				t.Fatalf("Execute() = %d, want %d; stderr=%q", got, tt.wantCode, stderr.String())
			}
			if tt.wantFormat != "" && app.format != tt.wantFormat {
				t.Errorf("render format = %q, want %q", app.format, tt.wantFormat)
			}
			if tt.wantMode != "" && app.mode != tt.wantMode {
				t.Errorf("anonymization mode = %q, want %q", app.mode, tt.wantMode)
			}
			if tt.wantCode == ExitOK && !strings.Contains(stdout.String(), "report") {
				t.Errorf("stdout = %q, want report", stdout.String())
			}
			if tt.name == "successful JSON report" && app.options.IPVersion != model.IPVersion4 {
				t.Errorf("IPVersion = %q, want 4", app.options.IPVersion)
			}
		})
	}
}

func TestDiagnoseWritesPrivateOutput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report.md")
	app := &fakeApplication{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		content:   []byte("# report\n"),
	}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{Application: app, Stdout: &stdout, Stderr: &stderr})
	root.SetArgs([]string{"diagnose", "host.test", "--format", "markdown", "--output", path})
	if code := Execute(context.Background(), root, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d; stderr=%q", code, stderr.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "# report\n" {
		t.Fatalf("report = %q", content)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), absolute) {
		t.Fatalf("success message does not contain exact output path %q: %q", absolute, stderr.String())
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("permissions = %o, want 600", got)
		}
	}
}

func TestWriteOutputRejectsSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	err := writeOutput(io.Discard, link, []byte("replacement"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("writeOutput() error = %v, want symbolic-link rejection", err)
	}
	content, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "keep me" {
		t.Fatalf("victim content = %q", content)
	}
}

func TestWriteOutputRejectsShortStdoutWrite(t *testing.T) {
	t.Parallel()

	err := writeOutput(shortWriter{}, "-", []byte("report"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeOutput() error = %v, want io.ErrShortWrite", err)
	}
}

func TestWriteOutputReplacesHardLinkWithoutChangingItsFormerTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o640); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "report")
	if err := os.Link(victim, output); err != nil {
		t.Skipf("hard-link creation is unavailable: %v", err)
	}

	if err := writeOutput(io.Discard, output, []byte("report")); err != nil {
		t.Fatalf("writeOutput() error = %v", err)
	}
	victimContent, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(victimContent) != "keep me" {
		t.Fatalf("former hard-link target content = %q", victimContent)
	}
	outputContent, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(outputContent) != "report" {
		t.Fatalf("report content = %q", outputContent)
	}
}

func TestDiagnoseUsesPersistedDefaultsUnlessFlagChanged(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Diagnostics.DefaultTimeout = 45 * time.Second
	cfg.Diagnostics.CheckTimeout = 9 * time.Second
	cfg.Diagnostics.PreferredIPVersion = "6"
	cfg.Diagnostics.MaxRedirects = 3
	cfg.Network.UseSystemProxy = false

	app := &fakeApplication{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		content:   []byte("report\n"),
	}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{
		Application: app,
		Stdout:      &stdout,
		Stderr:      &stderr,
		LoadConfig:  func() (config.Config, error) { return cfg, nil },
	})
	root.SetArgs([]string{"diagnose", "host.test", "--timeout", "12s"})
	if code := Execute(context.Background(), root, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d; stderr=%q", code, stderr.String())
	}
	if app.options.Timeout != 12*time.Second {
		t.Errorf("explicit timeout = %s, want 12s", app.options.Timeout)
	}
	if app.options.CheckTimeout != 9*time.Second ||
		app.options.IPVersion != model.IPVersion6 ||
		app.options.MaxRedirects != 3 ||
		!app.options.NoProxy {
		t.Errorf("persisted options not applied: %+v", app.options)
	}
}

func TestDiagnoseRedirectPolicyRequiresExplicitFlags(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		args      []string
		downgrade bool
		private   bool
	}{
		{name: "safe defaults", args: []string{"diagnose", "host.test"}},
		{
			name:      "explicit opt-ins",
			args:      []string{"diagnose", "host.test", "--allow-insecure-redirects", "--allow-private-redirects"},
			downgrade: true,
			private:   true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			app := &fakeApplication{
				diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
				content:   []byte("report\n"),
			}
			var stdout, stderr bytes.Buffer
			root := NewRoot(Options{Application: app, Stdout: &stdout, Stderr: &stderr})
			root.SetArgs(test.args)
			if code := Execute(context.Background(), root, &stderr); code != ExitOK {
				t.Fatalf("Execute() = %d; stderr=%q", code, stderr.String())
			}
			if app.options.AllowInsecureRedirects != test.downgrade ||
				app.options.AllowPrivateRedirects != test.private {
				t.Fatalf("options = %+v", app.options)
			}
		})
	}
}

func TestDiagnoseMapsInvalidPersistedConfigurationToInputError(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	root := NewRoot(Options{
		Application: &fakeApplication{},
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		LoadConfig: func() (config.Config, error) {
			return config.Config{}, &config.InvalidError{Err: errors.New("invalid configuration")}
		},
		IsConfigInvalid: config.IsInvalid,
	})
	root.SetArgs([]string{"diagnose", "host.test"})
	if got := Execute(context.Background(), root, &stderr); got != ExitInput {
		t.Fatalf("Execute() = %d, want %d; stderr=%q", got, ExitInput, stderr.String())
	}
}

func TestDiagnoseDistinguishesLogLevelInputFromRuntimeFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		level    string
		setLevel func(string) error
		want     int
	}{
		{
			name:     "invalid level",
			level:    "trace",
			setLevel: func(string) error { return nil },
			want:     ExitInput,
		},
		{
			name:     "logger startup failure",
			level:    "debug",
			setLevel: func(string) error { return errors.New("log file is unavailable") },
			want:     ExitInternal,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			root := NewRoot(Options{
				Application: &fakeApplication{},
				Stdout:      &bytes.Buffer{},
				Stderr:      &stderr,
				SetLogLevel: test.setLevel,
			})
			root.SetArgs([]string{"diagnose", "host.test", "--log-level", test.level})
			if got := Execute(context.Background(), root, &stderr); got != test.want {
				t.Fatalf("Execute() = %d, want %d; stderr=%q", got, test.want, stderr.String())
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	info := buildinfo.Info{
		Version:   "1.2.3",
		Commit:    "abc123",
		BuildDate: time.Unix(1, 0).UTC().Format(time.RFC3339),
	}
	root := NewRoot(Options{Build: info, Stdout: &stdout, Stderr: &stderr})
	root.SetArgs([]string{"version", "--json"})
	if code := Execute(context.Background(), root, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d; stderr=%q", code, stderr.String())
	}
	var got buildinfo.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Version != info.Version || got.Commit != info.Commit {
		t.Fatalf("version JSON = %+v", got)
	}
}

func TestExecuteMapsUnexpectedInput(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	root := NewRoot(Options{Stdout: &bytes.Buffer{}, Stderr: &stderr})
	root.SetArgs([]string{"unknown-command"})
	if got := Execute(context.Background(), root, &stderr); got != ExitInput {
		t.Fatalf("Execute() = %d, want %d", got, ExitInput)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestExitErrorUnwrap(t *testing.T) {
	t.Parallel()
	target := errors.New("target")
	if !errors.Is(&ExitError{Code: ExitInternal, Err: target}, target) {
		t.Fatal("ExitError does not unwrap")
	}
}
