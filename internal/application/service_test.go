package application

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
)

type fakeRunner struct {
	diagnosis model.Diagnosis
	err       error
	options   model.DiagnoseOptions
}

func (f *fakeRunner) Diagnose(
	_ context.Context,
	options model.DiagnoseOptions,
	_ model.EventSink,
) (model.Diagnosis, error) {
	f.options = options
	return f.diagnosis, f.err
}

type fakePersistence struct {
	saved     model.Diagnosis
	saveLimit int
	saveErr   error
	history   []model.HistoryEntry
	profiles  []model.Profile
	closed    bool
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
	profile.ID = 1
	f.profiles = append(f.profiles, profile)
	return profile, nil
}
func (f *fakePersistence) UpdateProfile(_ context.Context, profile model.Profile) (model.Profile, error) {
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
	cfg.Network.UserAgent = "OpsDoctor-Test/1"
	cfg.Diagnostics.CertificateWarningThreshold = 7 * 24 * time.Hour
	runner := &fakeRunner{diagnosis: model.Diagnosis{
		ID:      "diagnosis-1",
		Summary: model.Summary{Status: model.StatusPassed},
	}}
	persistence := &fakePersistence{}
	service, err := New(Dependencies{
		Runner:      runner,
		Persistence: persistence,
		ConfigStore: &fakeConfigStore{},
		Config:      cfg,
		Build:       model.BuildInfo{Version: "1.2.3", Commit: "abc"},
		RenderReport: func(string, model.Diagnosis) ([]byte, error) {
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
	if runner.options.UserAgent != "OpsDoctor-Test/1" ||
		runner.options.CertificateWarningThreshold != 7*24*time.Hour {
		t.Errorf("config-backed diagnostic options = %+v", runner.options)
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
