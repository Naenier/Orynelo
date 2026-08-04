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

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

type fakeApplication struct {
	diagnosis model.Diagnosis
	err       error
	renderErr error
	config    application.Config
	request   application.DiagnoseRequest
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

func (f *fakeApplication) DiagnoseRequest(
	_ context.Context,
	request application.DiagnoseRequest,
	sink model.EventSink,
) (model.Diagnosis, error) {
	f.request = request
	config := f.config
	if config.SchemaVersion == "" {
		config = application.DefaultConfig()
	}
	options, err := application.ResolveDiagnoseOptions(config, request.Profile, request.Overrides)
	if err != nil {
		return model.Diagnosis{}, application.WrapError(
			err,
			application.ErrorCategoryValidation,
			"APP_DIAGNOSE_OPTIONS_INVALID",
			"error.diagnose_options_invalid",
			nil,
		)
	}
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
	return f.content, f.renderErr
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
		{
			name:     "timed out",
			args:     []string{"diagnose", "host.test"},
			status:   model.StatusPassed,
			appErr:   context.DeadlineExceeded,
			wantCode: ExitFailure,
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

func TestDiagnoseSendsOnlyExplicitOverridesToApplicationResolver(t *testing.T) {
	t.Parallel()

	cfg := application.DefaultConfig()
	cfg.Diagnostics.DefaultTimeout = 45 * time.Second
	cfg.Diagnostics.CheckTimeout = 9 * time.Second
	cfg.Diagnostics.PreferredIPVersion = "6"
	cfg.Diagnostics.MaxRedirects = 3
	cfg.Network.UseSystemProxy = false

	app := &fakeApplication{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		content:   []byte("report\n"),
		config:    cfg,
	}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{
		Application: app,
		Stdout:      &stdout,
		Stderr:      &stderr,
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
	overrides := app.request.Overrides
	if overrides.Target == nil || *overrides.Target != "host.test" ||
		overrides.Timeout == nil || *overrides.Timeout != 12*time.Second {
		t.Fatalf("explicit overrides not forwarded: %+v", overrides)
	}
	if overrides.CheckTimeout != nil || overrides.IPVersion != nil ||
		overrides.MaxRedirects != nil || overrides.NoProxy != nil ||
		overrides.Method != nil || overrides.Insecure != nil ||
		overrides.AllowInsecureRedirects != nil ||
		overrides.AllowPrivateRedirects != nil ||
		overrides.ReportVerbosity != nil {
		t.Fatalf("CLI populated omitted defaults: %+v", overrides)
	}
}

func TestDiagnosePreservesExplicitFalseOverrides(t *testing.T) {
	t.Parallel()

	config := application.DefaultConfig()
	config.Network.UseSystemProxy = false
	app := &fakeApplication{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		content:   []byte("report\n"),
		config:    config,
	}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{Application: app, Stdout: &stdout, Stderr: &stderr})
	root.SetArgs([]string{
		"diagnose", "host.test",
		"--no-proxy=false",
		"--insecure=false",
		"--allow-insecure-redirects=false",
		"--allow-private-redirects=false",
		"--verbose=false",
	})
	if code := Execute(context.Background(), root, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d; stderr=%q", code, stderr.String())
	}
	overrides := app.request.Overrides
	for name, value := range map[string]*bool{
		"no-proxy":                 overrides.NoProxy,
		"insecure":                 overrides.Insecure,
		"allow-insecure-redirects": overrides.AllowInsecureRedirects,
		"allow-private-redirects":  overrides.AllowPrivateRedirects,
	} {
		if value == nil || *value {
			t.Errorf("%s override = %v, want explicit false", name, value)
		}
	}
	if overrides.ReportVerbosity == nil ||
		*overrides.ReportVerbosity != model.ReportVerbosityNormal {
		t.Fatalf("verbose override = %v, want explicit normal", overrides.ReportVerbosity)
	}
	if app.options.NoProxy {
		t.Fatal("application resolver did not apply explicit no-proxy=false over configuration")
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

func TestDiagnoseMapsApplicationConfigurationErrorToInputError(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	root := NewRoot(Options{
		Application: &fakeApplication{err: application.NewError(
			application.ErrorCategoryConfiguration,
			"APP_CONFIGURATION_INVALID",
			"error.configuration_invalid",
			nil,
		)},
		Stdout: &bytes.Buffer{},
		Stderr: &stderr,
	})
	root.SetArgs([]string{"diagnose", "host.test"})
	if got := Execute(context.Background(), root, &stderr); got != ExitInput {
		t.Fatalf("Execute() = %d, want %d; stderr=%q", got, ExitInput, stderr.String())
	}
}

func TestDiagnoseJSONErrorEnvelopeIsTypedAndPrivacySafe(t *testing.T) {
	t.Parallel()

	const causeSecret = "database-password=raw-cause-secret"
	appErr := application.WrapError(
		errors.New(causeSecret),
		application.ErrorCategoryValidation,
		"APP_TARGET_REJECTED",
		"error.target_rejected",
		map[string]string{
			"field":        "target",
			"access_token": "raw-argument-secret",
		},
	)
	app := &fakeApplication{err: appErr}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{Application: app, Stdout: &stdout, Stderr: &stderr})
	root.SetArgs([]string{"diagnose", "host.test", "--format", "json"})

	if got := Execute(context.Background(), root, &stderr); got != ExitInput {
		t.Fatalf("Execute() = %d, want %d; stderr=%q", got, ExitInput, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout contains a partial report: %q", stdout.String())
	}
	var got errorEnvelope
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("JSON error envelope is invalid: %v; output=%q", err, stderr.String())
	}
	if got.Error.Category != application.ErrorCategoryValidation ||
		got.Error.Code != "APP_TARGET_REJECTED" ||
		got.Error.MessageID != "error.target_rejected" ||
		got.Error.Arguments["field"] != "target" ||
		got.Error.Arguments["access_token"] != "[REDACTED]" {
		t.Fatalf("unexpected JSON error envelope: %#v", got)
	}
	for _, secret := range []string{causeSecret, "raw-cause-secret", "raw-argument-secret"} {
		if strings.Contains(stderr.String(), secret) {
			t.Fatalf("JSON error envelope exposed %q: %s", secret, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "cause") || strings.Contains(stderr.String(), "Error:") {
		t.Fatalf("JSON error envelope contains text-only data: %s", stderr.String())
	}
}

func TestDiagnoseJSONFlagParseFailureUsesErrorEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "format before timeout",
			args: []string{"diagnose", "host.test", "--format", "json", "--timeout", "not-a-duration"},
		},
		{
			name: "format after timeout",
			args: []string{"diagnose", "host.test", "--timeout", "not-a-duration", "--format", "json"},
		},
		{
			name: "format before check timeout",
			args: []string{"diagnose", "host.test", "--format", "json", "--check-timeout", "not-a-duration"},
		},
		{
			name: "format after check timeout",
			args: []string{"diagnose", "host.test", "--check-timeout", "not-a-duration", "--format", "json"},
		},
		{
			name: "format before maximum redirects",
			args: []string{"diagnose", "host.test", "--format", "json", "--max-redirects", "not-an-integer"},
		},
		{
			name: "format after maximum redirects",
			args: []string{"diagnose", "host.test", "--max-redirects", "not-an-integer", "--format", "json"},
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
			})
			root.SetArgs(test.args)

			if got := Execute(context.Background(), root, &stderr); got != ExitInput {
				t.Fatalf("Execute() = %d, want %d; stderr=%q", got, ExitInput, stderr.String())
			}
			var got errorEnvelope
			if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
				t.Fatalf("JSON error envelope is invalid: %v; output=%q", err, stderr.String())
			}
			if got.Error.Category != application.ErrorCategoryValidation ||
				got.Error.Code != "APP_CLI_FLAGS_INVALID" {
				t.Fatalf("unexpected flag error: %#v", got.Error)
			}
		})
	}
}

func TestDiagnoseVerboseJSONErrorRemainsSingleDocument(t *testing.T) {
	t.Parallel()

	const causeSecret = "renderer-private-detail"
	app := &fakeApplication{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		renderErr: errors.New(causeSecret),
	}
	var stdout, stderr bytes.Buffer
	root := NewRoot(Options{Application: app, Stdout: &stdout, Stderr: &stderr})
	root.SetArgs([]string{"diagnose", "host.test", "--verbose", "--format", "json"})

	if got := Execute(context.Background(), root, &stderr); got != ExitInternal {
		t.Fatalf("Execute() = %d, want %d; stderr=%q", got, ExitInternal, stderr.String())
	}
	var got errorEnvelope
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("verbose JSON error is not one JSON document: %v; output=%q", err, stderr.String())
	}
	if got.Error.Code != "APP_REPORT_RENDER_FAILED" {
		t.Fatalf("unexpected error envelope: %#v", got.Error)
	}
	if strings.Contains(stderr.String(), "PASSED") || strings.Contains(stderr.String(), causeSecret) {
		t.Fatalf("JSON error contains progress or private cause: %q", stderr.String())
	}
}

func TestDiagnoseTypedErrorExitCodesAndTextGuidance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		category application.ErrorCategory
		code     application.ErrorCode
		wantExit int
		guidance string
	}{
		{
			name:     "validation",
			category: application.ErrorCategoryValidation,
			code:     "APP_TEST_VALIDATION",
			wantExit: ExitInput,
			guidance: "Correct the requested value",
		},
		{
			name:     "configuration",
			category: application.ErrorCategoryConfiguration,
			code:     "APP_TEST_CONFIGURATION",
			wantExit: ExitInput,
			guidance: "Correct the settings",
		},
		{
			name:     "network policy",
			category: application.ErrorCategoryNetworkPolicy,
			code:     "APP_TEST_NETWORK_POLICY",
			wantExit: ExitFailure,
			guidance: "Network policy blocked",
		},
		{
			name:     "cancelled",
			category: application.ErrorCategoryCancelled,
			code:     "APP_TEST_CANCELLED",
			wantExit: ExitCancel,
			guidance: "Operation cancelled",
		},
		{
			name:     "timed out",
			category: application.ErrorCategoryCancelled,
			code:     application.ErrorCodeOperationTimedOut,
			wantExit: ExitFailure,
			guidance: "Operation timed out",
		},
		{
			name:     "storage",
			category: application.ErrorCategoryStorage,
			code:     "APP_TEST_STORAGE",
			wantExit: ExitInternal,
			guidance: "continue without history",
		},
		{
			name:     "permission",
			category: application.ErrorCategoryPermission,
			code:     "APP_TEST_PERMISSION",
			wantExit: ExitInternal,
			guidance: "Check access",
		},
		{
			name:     "internal",
			category: application.ErrorCategoryInternal,
			code:     "APP_TEST_INTERNAL",
			wantExit: ExitInternal,
			guidance: "inspect the application logs",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			const causeSecret = "internal-cause-secret"
			app := &fakeApplication{err: application.WrapError(
				errors.New(causeSecret),
				test.category,
				test.code,
				"error.test",
				nil,
			)}
			var stderr bytes.Buffer
			root := NewRoot(Options{
				Application: app,
				Stdout:      &bytes.Buffer{},
				Stderr:      &stderr,
			})
			root.SetArgs([]string{"diagnose", "host.test"})
			if got := Execute(context.Background(), root, &stderr); got != test.wantExit {
				t.Fatalf("Execute() = %d, want %d; stderr=%q", got, test.wantExit, stderr.String())
			}
			if !strings.Contains(stderr.String(), string(test.code)) ||
				!strings.Contains(stderr.String(), test.guidance) {
				t.Fatalf("stderr lacks code or guidance: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), causeSecret) {
				t.Fatalf("stderr exposed wrapped cause: %q", stderr.String())
			}
		})
	}
}

func TestApplicationErrorGuidanceUsesReportErrorCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code application.ErrorCode
		want string
	}{
		{
			name: "report write",
			code: "APP_REPORT_WRITE_FAILED",
			want: "Check the destination path",
		},
		{
			name: "report destination",
			code: "APP_REPORT_DESTINATION_INVALID",
			want: "Choose a valid output path",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := application.NewError(
				application.ErrorCategoryStorage,
				test.code,
				"error.test",
				nil,
			)
			got := applicationErrorGuidance(err)
			if !strings.Contains(got, test.want) || strings.Contains(got, "history") {
				t.Fatalf("guidance = %q, want code-specific report recovery", got)
			}
		})
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
