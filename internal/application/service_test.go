package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
	"github.com/Naenier/orynelo/internal/redaction"
)

type fakeRunner struct {
	diagnosis model.Diagnosis
	err       error
	options   model.DiagnoseOptions
	events    []model.CheckEvent
}

func (f *fakeRunner) Diagnose(
	_ context.Context,
	options model.DiagnoseOptions,
	sink model.EventSink,
) (model.Diagnosis, error) {
	f.options = options
	for _, event := range f.events {
		if sink != nil {
			sink(event)
		}
	}
	return f.diagnosis, f.err
}

type fakePersistence struct {
	saved         model.Diagnosis
	saveLimit     int
	saveErr       error
	history       []model.HistoryEntry
	profiles      []model.Profile
	profileResult *model.Profile
	closed        bool
}

func (f *fakePersistence) SaveDiagnosis(_ context.Context, diagnosis model.Diagnosis, limit int) error {
	f.saved = diagnosis
	f.saveLimit = limit
	return f.saveErr
}
func (f *fakePersistence) GetDiagnosis(context.Context, string) (model.Diagnosis, error) {
	return f.saved, nil
}
func (f *fakePersistence) ListHistory(context.Context, model.HistoryQuery) ([]model.HistoryEntry, error) {
	return append([]model.HistoryEntry(nil), f.history...), nil
}
func (f *fakePersistence) DeleteDiagnosis(context.Context, string) error { return nil }
func (f *fakePersistence) ClearHistory(context.Context) error            { return nil }
func (f *fakePersistence) ListProfiles(context.Context) ([]model.Profile, error) {
	return append([]model.Profile(nil), f.profiles...), nil
}
func (f *fakePersistence) CreateProfile(_ context.Context, profile model.Profile) (model.Profile, error) {
	if f.profileResult != nil {
		return *f.profileResult, nil
	}
	profile.ID = 1
	f.profiles = append(f.profiles, profile)
	return profile, nil
}
func (f *fakePersistence) UpdateProfile(_ context.Context, profile model.Profile) (model.Profile, error) {
	if f.profileResult != nil {
		return *f.profileResult, nil
	}
	return profile, nil
}
func (f *fakePersistence) DeleteProfile(context.Context, int64) error { return nil }
func (f *fakePersistence) Close() error {
	f.closed = true
	return nil
}

type fakeConfigStore struct {
	saved Config
	err   error
}

func (f *fakeConfigStore) Save(value Config) error {
	f.saved = value
	return f.err
}

func TestServiceDiagnoseAddsBuildAndPersists(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.History.MaxEntries = 42
	cfg.Network.UserAgent = "Orynelo-Test/1"
	cfg.Diagnostics.CertificateWarningThreshold = 7 * 24 * time.Hour
	runner := &fakeRunner{diagnosis: model.Diagnosis{
		ID:      "diagnosis-1",
		Options: model.DiagnoseOptions{UserAgent: "Orynelo token=persisted-user-agent-secret"},
		Summary: model.Summary{Status: model.StatusPassed},
	}}
	persistence := &fakePersistence{}
	service, err := New(Dependencies{
		Runner:      runner,
		Persistence: persistence,
		ConfigStore: &fakeConfigStore{},
		Config:      cfg,
		Build:       model.BuildInfo{Version: "1.2.3", Commit: "abc"},
		RenderReport: func(string, model.Diagnosis, privacy.Mode) ([]byte, error) {
			return []byte("report"), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := service.Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("host.test"),
		nil,
	)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if got.Build.Version != "1.2.3" || persistence.saved.Build.Commit != "abc" {
		t.Fatalf("build info was not propagated: got=%+v saved=%+v", got.Build, persistence.saved.Build)
	}
	if persistence.saveLimit != 42 {
		t.Errorf("history limit = %d, want 42", persistence.saveLimit)
	}
	if runner.options.UserAgent != "Orynelo-Test/1" ||
		runner.options.CertificateWarningThreshold != 7*24*time.Hour {
		t.Errorf("config-backed diagnostic options = %+v", runner.options)
	}
	if strings.Contains(got.Options.UserAgent, "persisted-user-agent-secret") ||
		strings.Contains(persistence.saved.Options.UserAgent, "persisted-user-agent-secret") {
		t.Fatalf("user agent crossed the privacy boundary: got=%q saved=%q", got.Options.UserAgent, persistence.saved.Options.UserAgent)
	}
}

func TestServiceDiagnoseRequestResolvesEffectiveOptionsOnce(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.History.Enabled = false
	cfg.Diagnostics.DefaultTimeout = 40 * time.Second
	cfg.Diagnostics.CheckTimeout = 8 * time.Second
	cfg.Diagnostics.MaxRedirects = 9
	cfg.Network.UseSystemProxy = false
	cfg.Network.UserAgent = "Orynelo/service-config"
	profile := model.Profile{
		Name:         "saved",
		Target:       "profile.example:443",
		Mode:         model.DiagnosticModeTLS,
		IPVersion:    model.IPVersion4,
		Timeout:      20 * time.Second,
		CheckTimeout: 4 * time.Second,
		NoProxy:      true,
		MaxRedirects: 3,
		Method:       "HEAD",
	}
	runner := &fakeRunner{diagnosis: model.Diagnosis{
		Summary: model.Summary{Status: model.StatusPassed},
	}}
	service, err := New(Dependencies{Runner: runner, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}

	target := " https://override.example/status "
	timeout := 25 * time.Second
	noProxy := false
	diagnosis, err := service.DiagnoseRequest(context.Background(), DiagnoseRequest{
		Profile: &profile,
		Overrides: DiagnoseOverrides{
			Target:  &target,
			Timeout: &timeout,
			NoProxy: &noProxy,
		},
	}, nil)
	if err != nil {
		t.Fatalf("DiagnoseRequest() error = %v", err)
	}

	if runner.options.Target != "https://override.example/status" ||
		runner.options.Timeout != 25*time.Second ||
		runner.options.CheckTimeout != 4*time.Second ||
		runner.options.IPVersion != model.IPVersion4 ||
		runner.options.NoProxy ||
		!runner.options.EnableTLS ||
		runner.options.MaxRedirects != 3 ||
		runner.options.Method != "HEAD" ||
		runner.options.UserAgent != "Orynelo/service-config" {
		t.Fatalf("runner received non-effective options: %+v", runner.options)
	}
	if diagnosis.Build != (model.BuildInfo{}) {
		t.Fatalf("unexpected build metadata: %+v", diagnosis.Build)
	}
}

func TestServiceDiagnoseRequestReturnsTypedValidationError(t *testing.T) {
	t.Parallel()

	service, err := New(Dependencies{Runner: &fakeRunner{}, Config: DefaultConfig()})
	if err != nil {
		t.Fatal(err)
	}
	invalidTarget := "https://"
	_, err = service.DiagnoseRequest(context.Background(), DiagnoseRequest{
		Overrides: DiagnoseOverrides{Target: &invalidTarget},
	}, nil)
	if err == nil {
		t.Fatal("DiagnoseRequest() error = nil")
	}
	applicationError, ok := AsError(err)
	if !ok || applicationError.Category() != ErrorCategoryValidation ||
		applicationError.Code() != "APP_DIAGNOSE_OPTIONS_INVALID" {
		t.Fatalf("DiagnoseRequest() error = %#v", applicationError)
	}
	if !strings.Contains(fmt.Sprint(errors.Unwrap(applicationError)), "invalid target") {
		t.Fatalf("wrapped cause was not retained: %v", errors.Unwrap(applicationError))
	}
	if strings.Contains(applicationError.Error(), "https://") ||
		strings.Contains(applicationError.Error(), "invalid target") {
		t.Fatalf("user-facing error leaked its cause: %q", applicationError.Error())
	}
}

func TestServiceDiagnoseClassifiesRunnerLifecycleAndInputErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		runnerErr error
		category  ErrorCategory
		code      ErrorCode
	}{
		{
			name:      "cancelled",
			runnerErr: context.Canceled,
			category:  ErrorCategoryCancelled,
			code:      ErrorCodeOperationCancelled,
		},
		{
			name: "input",
			runnerErr: &diagnostics.InputError{
				Code:    "INVALID_TARGET",
				Message: "private parser detail",
			},
			category: ErrorCategoryValidation,
			code:     "APP_DIAGNOSE_OPTIONS_INVALID",
		},
		{
			name:      "internal",
			runnerErr: errors.New("private adapter failure"),
			category:  ErrorCategoryInternal,
			code:      "APP_DIAGNOSE_FAILED",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			cfg.History.Enabled = false
			service, err := New(Dependencies{
				Runner: &fakeRunner{err: test.runnerErr},
				Config: cfg,
			})
			if err != nil {
				t.Fatal(err)
			}
			target := "example.test"
			_, err = service.DiagnoseRequest(context.Background(), DiagnoseRequest{
				Overrides: DiagnoseOverrides{Target: &target},
			}, nil)
			applicationError, ok := AsError(err)
			if !ok || applicationError.Category() != test.category ||
				applicationError.Code() != test.code {
				t.Fatalf("DiagnoseRequest() error = %#v", applicationError)
			}
			if !errors.Is(applicationError, test.runnerErr) {
				t.Fatalf("typed error no longer wraps %v", test.runnerErr)
			}
		})
	}
}

func TestServiceProjectsEventsBeforeDeliveringThem(t *testing.T) {
	t.Parallel()

	offset := time.FixedZone("non-utc", 3*60*60)
	at := time.Date(2026, 8, 3, 12, 0, 0, 0, offset)
	result := model.CheckResult{
		StartedAt: at,
		Summary:   "request https://alice:password@example.test/?token=event-secret",
		Evidence: []model.Evidence{{Details: map[string]string{
			"responseHeader.Authorization": "Bearer namespaced-event-secret",
		}}},
	}
	runner := &fakeRunner{
		diagnosis: model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}},
		events:    []model.CheckEvent{{At: at, Result: &result}},
	}
	cfg := DefaultConfig()
	cfg.History.Enabled = false
	service, err := New(Dependencies{Runner: runner, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var delivered model.CheckEvent
	if _, err := service.Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("example.test"),
		func(event model.CheckEvent) { delivered = event },
	); err != nil {
		t.Fatal(err)
	}
	if delivered.Result == nil || strings.Contains(delivered.Result.Summary, "event-secret") ||
		strings.Contains(delivered.Result.Evidence[0].Details["responseHeader.Authorization"], "namespaced-event-secret") {
		t.Fatalf("event was not projected: %#v", delivered)
	}
	if delivered.At.Location() != time.UTC || delivered.Result.StartedAt.Location() != time.UTC {
		t.Fatalf("event timestamps are not UTC: %#v", delivered)
	}
	if !strings.Contains(result.Summary, "event-secret") {
		t.Fatal("event projection mutated the runner's result")
	}
}

func TestServiceProjectsProfileAdapterResult(t *testing.T) {
	t.Parallel()

	returned := model.Profile{
		ID:           1,
		Name:         "unsafe adapter result",
		Target:       "https://alice:password@example.test/?token=adapter-secret",
		Mode:         model.DiagnosticModeAuto,
		IPVersion:    model.IPVersionAuto,
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "GET",
	}
	persistence := &fakePersistence{profileResult: &returned}
	service, err := New(Dependencies{
		Runner:      &fakeRunner{},
		Persistence: persistence,
		Config:      DefaultConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := service.SaveProfile(context.Background(), returned)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice", "password", "adapter-secret"} {
		if strings.Contains(saved.Target, secret) {
			t.Fatalf("profile adapter result leaked %q: %#v", secret, saved)
		}
	}
}

func TestServiceHistoryFailureDoesNotHideDiagnosis(t *testing.T) {
	t.Parallel()

	var logBuffer bytes.Buffer
	logger := slog.New(redaction.NewHandler(slog.NewJSONHandler(&logBuffer, nil)))
	runner := &fakeRunner{diagnosis: model.Diagnosis{
		ID:      "diagnosis-1",
		Summary: model.Summary{Status: model.StatusPassed},
	}}
	service, err := New(Dependencies{
		Runner:      runner,
		Persistence: &fakePersistence{saveErr: errors.New("disk full")},
		Config:      DefaultConfig(),
		Logger:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("host.test"),
		nil,
	); err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !strings.Contains(logBuffer.String(), "history could not be saved") {
		t.Fatalf("log = %q", logBuffer.String())
	}
}

func TestServiceSaveConfigurationActivatesAfterPersistence(t *testing.T) {
	t.Parallel()

	store := &fakeConfigStore{}
	var activeLevel string
	service, err := New(Dependencies{
		Runner:      &fakeRunner{},
		ConfigStore: store,
		Config:      DefaultConfig(),
		SetLogLevel: func(level string) error {
			activeLevel = level
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated := DefaultConfig()
	updated.Diagnostics.DefaultTimeout = 30 * time.Second
	updated.Logging.Level = "debug"
	if err := service.SaveConfiguration(updated); err != nil {
		t.Fatalf("SaveConfiguration() error = %v", err)
	}
	if service.Configuration().Diagnostics.DefaultTimeout != 30*time.Second {
		t.Fatal("configuration was not activated")
	}
	if activeLevel != "debug" {
		t.Fatalf("active log level = %q, want debug", activeLevel)
	}

	store.err = errors.New("read only")
	rejected := updated
	rejected.Diagnostics.DefaultTimeout = 45 * time.Second
	if err := service.SaveConfiguration(rejected); err == nil {
		t.Fatal("SaveConfiguration() error = nil")
	}
	if service.Configuration().Diagnostics.DefaultTimeout != 30*time.Second {
		t.Fatal("failed configuration was activated")
	}
	if activeLevel != "debug" {
		t.Fatalf("failed save did not restore active log level: %q", activeLevel)
	}
}

func TestServiceClassifiesUserControlledAdapterValuesAsValidation(t *testing.T) {
	t.Parallel()

	service, err := New(Dependencies{
		Runner:      &fakeRunner{},
		Persistence: &fakePersistence{},
		Config:      DefaultConfig(),
		RenderReport: func(string, model.Diagnosis, privacy.Mode) ([]byte, error) {
			return []byte("report"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		run  func() error
		code ErrorCode
	}{
		{
			name: "history search",
			run: func() error {
				_, err := service.ListHistory(context.Background(), strings.Repeat("x", 4097), "")
				return err
			},
			code: "APP_HISTORY_SEARCH_INVALID",
		},
		{
			name: "history status",
			run: func() error {
				_, err := service.ListHistory(context.Background(), "", model.Status("unknown"))
				return err
			},
			code: "APP_HISTORY_STATUS_INVALID",
		},
		{
			name: "history ID",
			run: func() error {
				_, err := service.GetDiagnosis(context.Background(), "../private")
				return err
			},
			code: "APP_HISTORY_ID_INVALID",
		},
		{
			name: "profile values",
			run: func() error {
				_, err := service.SaveProfile(context.Background(), model.Profile{Name: "invalid"})
				return err
			},
			code: "APP_PROFILE_VALUES_INVALID",
		},
		{
			name: "profile ID",
			run: func() error {
				return service.DeleteProfile(context.Background(), 0)
			},
			code: "APP_PROFILE_ID_INVALID",
		},
		{
			name: "report format",
			run: func() error {
				_, err := service.RenderReport("xml", model.Diagnosis{}, privacy.ModeStandard)
				return err
			},
			code: "APP_REPORT_FORMAT_INVALID",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.run()
			applicationError, ok := AsError(err)
			if !ok || applicationError.Category() != ErrorCategoryValidation ||
				applicationError.Code() != test.code {
				t.Fatalf("error = %#v", applicationError)
			}
		})
	}
}

func TestServiceValidatesProfileBeforeCheckingStorageAvailability(t *testing.T) {
	t.Parallel()

	service, err := New(Dependencies{Runner: &fakeRunner{}, Config: DefaultConfig()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SaveProfile(context.Background(), model.Profile{})
	if !IsErrorCategory(err, ErrorCategoryValidation) ||
		!IsErrorCode(err, "APP_PROFILE_VALUES_INVALID") {
		t.Fatalf("invalid profile error = %v", err)
	}

	_, err = service.SaveProfile(context.Background(), model.Profile{
		Name:         "valid",
		Target:       "example.test",
		Mode:         model.DiagnosticModeAuto,
		IPVersion:    model.IPVersionAuto,
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "GET",
	})
	if !IsErrorCategory(err, ErrorCategoryStorage) ||
		!IsErrorCode(err, "APP_PROFILE_STORAGE_UNAVAILABLE") {
		t.Fatalf("valid profile without storage error = %v", err)
	}
}
