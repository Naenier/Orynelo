//go:build wayland

package gui

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/gui/presenter"
	"github.com/Naenier/orynelo/internal/gui/taskrunner"
	"github.com/Naenier/orynelo/internal/privacy"
)

type coordinatorTestBackend struct {
	configuration application.Config
	diagnosis     model.Diagnosis
	history       []model.HistoryEntry
	profiles      []model.Profile

	listHistory func(context.Context, string, model.Status) ([]model.HistoryEntry, error)
}

func (backend *coordinatorTestBackend) DiagnoseRequest(
	context.Context,
	application.DiagnoseRequest,
	model.EventSink,
) (model.Diagnosis, error) {
	return backend.diagnosis, nil
}

func (backend *coordinatorTestBackend) Configuration() application.Config {
	return backend.configuration
}

func (backend *coordinatorTestBackend) SaveConfiguration(config application.Config) error {
	backend.configuration = config
	return nil
}

func (*coordinatorTestBackend) LogDirectory() string { return "" }

func (backend *coordinatorTestBackend) ListHistory(
	ctx context.Context,
	search string,
	status model.Status,
) ([]model.HistoryEntry, error) {
	if backend.listHistory != nil {
		return backend.listHistory(ctx, search, status)
	}
	return append([]model.HistoryEntry(nil), backend.history...), nil
}

func (backend *coordinatorTestBackend) GetDiagnosis(context.Context, string) (model.Diagnosis, error) {
	return backend.diagnosis, nil
}

func (*coordinatorTestBackend) DeleteDiagnosis(context.Context, string) error { return nil }
func (*coordinatorTestBackend) ClearHistory(context.Context) error            { return nil }

func (backend *coordinatorTestBackend) ListProfiles(context.Context) ([]model.Profile, error) {
	return append([]model.Profile(nil), backend.profiles...), nil
}

func (backend *coordinatorTestBackend) SaveProfile(
	_ context.Context,
	profile model.Profile,
) (model.Profile, error) {
	return profile, nil
}

func (*coordinatorTestBackend) DeleteProfile(context.Context, int64) error { return nil }

func (*coordinatorTestBackend) RenderReport(
	string,
	model.Diagnosis,
	privacy.Mode,
) ([]byte, error) {
	return nil, nil
}

func TestUseCaseCoordinatorsPublishTestableViewModels(t *testing.T) {
	t.Parallel()

	runner := newCoordinatorTestRunner(t)
	config := application.DefaultConfig()
	config.Diagnostics.DefaultTimeout = 23 * time.Second
	backend := &coordinatorTestBackend{
		configuration: config,
		diagnosis: model.Diagnosis{
			ID:      "diagnosis-1",
			Summary: model.Summary{Status: model.StatusPassed},
		},
		history:  []model.HistoryEntry{{ID: "history-1", Target: "example.test"}},
		profiles: []model.Profile{{ID: 7, Name: "Office", Target: "office.test"}},
	}

	diagnose, err := NewDiagnoseCoordinator(runner, backend, nil)
	if err != nil {
		t.Fatalf("NewDiagnoseCoordinator() error = %v", err)
	}
	history, err := NewHistoryCoordinator(runner, backend, nil)
	if err != nil {
		t.Fatalf("NewHistoryCoordinator() error = %v", err)
	}
	profiles, err := NewProfilesCoordinator(runner, backend, nil)
	if err != nil {
		t.Fatalf("NewProfilesCoordinator() error = %v", err)
	}
	settings, err := NewSettingsCoordinator(runner, backend, nil)
	if err != nil {
		t.Fatalf("NewSettingsCoordinator() error = %v", err)
	}

	diagnose.SetConfiguration(config)
	if _, err := diagnose.Start(presenter.DiagnoseInput{
		Target:       "https://example.test",
		Mode:         "auto",
		IPVersion:    "auto",
		Timeout:      config.Diagnostics.DefaultTimeout,
		CheckTimeout: config.Diagnostics.CheckTimeout,
		Method:       "GET",
		MaxRedirects: config.Diagnostics.MaxRedirects,
		Verbosity:    "normal",
	}, nil); err != nil {
		t.Fatalf("DiagnoseCoordinator.Start() error = %v", err)
	}
	if err := history.Load("", ""); err != nil {
		t.Fatalf("HistoryCoordinator.Load() error = %v", err)
	}
	if err := profiles.Load(); err != nil {
		t.Fatalf("ProfilesCoordinator.Load() error = %v", err)
	}
	if err := settings.Load(); err != nil {
		t.Fatalf("SettingsCoordinator.Load() error = %v", err)
	}
	runner.Wait()

	if state := diagnose.Snapshot(); state.State != taskrunner.StateSuccess ||
		state.Diagnosis.ID != "diagnosis-1" {
		t.Fatalf("diagnose state = %#v", state)
	}
	if state := history.Snapshot(); state.LoadState != taskrunner.StateSuccess ||
		len(state.Rows) != 1 || state.Rows[0].ID != "history-1" {
		t.Fatalf("history state = %#v", state)
	}
	if state := profiles.Snapshot(); state.LoadState != taskrunner.StateSuccess ||
		len(state.Profiles) != 1 || state.Profiles[0].ID != 7 {
		t.Fatalf("profiles state = %#v", state)
	}
	if state := settings.Snapshot(); state.LoadState != taskrunner.StateSuccess ||
		state.Config.Diagnostics.DefaultTimeout != 23*time.Second {
		t.Fatalf("settings state = %#v", state)
	}
}

func TestHistoryCoordinatorSuppressesStaleResponses(t *testing.T) {
	t.Parallel()

	runner := newCoordinatorTestRunner(t)
	oldStarted := make(chan struct{})
	releaseOld := make(chan struct{})
	newFinished := make(chan struct{})
	var newFinishedOnce sync.Once
	backend := &coordinatorTestBackend{
		configuration: application.DefaultConfig(),
		listHistory: func(
			_ context.Context,
			search string,
			_ model.Status,
		) ([]model.HistoryEntry, error) {
			if search == "old" {
				close(oldStarted)
				<-releaseOld
				return []model.HistoryEntry{{ID: "old"}}, nil
			}
			newFinishedOnce.Do(func() { close(newFinished) })
			return []model.HistoryEntry{{ID: "new"}}, nil
		},
	}
	coordinator, err := NewHistoryCoordinator(runner, backend, nil)
	if err != nil {
		t.Fatalf("NewHistoryCoordinator() error = %v", err)
	}
	if err := coordinator.Load("old", ""); err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old history request did not start")
	}
	if err := coordinator.Load("new", ""); err != nil {
		t.Fatalf("replacement Load() error = %v", err)
	}
	select {
	case <-newFinished:
	case <-time.After(time.Second):
		t.Fatal("new history request did not finish")
	}
	close(releaseOld)
	runner.Wait()

	state := coordinator.Snapshot()
	if state.LoadState != taskrunner.StateSuccess || len(state.Rows) != 1 || state.Rows[0].ID != "new" {
		t.Fatalf("stale response replaced current history state: %#v", state)
	}
}

func newCoordinatorTestRunner(t *testing.T) *taskrunner.Runner {
	t.Helper()
	runner, err := taskrunner.New(
		context.Background(),
		func(callback func()) { callback() },
		taskrunner.Options{MaxConcurrentReads: 4},
	)
	if err != nil {
		t.Fatalf("taskrunner.New() error = %v", err)
	}
	t.Cleanup(func() {
		runner.Close()
		runner.Wait()
	})
	return runner
}
