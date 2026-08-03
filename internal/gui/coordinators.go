package gui

import (
	"context"
	"errors"
	"sync"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
	"github.com/Naenier/opsdoctor/internal/gui/taskrunner"
	"github.com/Naenier/opsdoctor/internal/privacy"
)

var errCoordinatorBackendRequired = errors.New("gui coordinator: backend is nil")

// DiagnoseViewModel is the Fyne-free state of the active diagnostic use case.
type DiagnoseViewModel struct {
	OperationID taskrunner.OperationID
	State       taskrunner.State
	Diagnosis   model.Diagnosis
	Err         error
}

// DiagnoseCoordinator resolves GUI input and coordinates one replaceable
// diagnostic operation without depending on Fyne widgets.
type DiagnoseCoordinator struct {
	backend  Backend
	scope    *taskrunner.Scope[model.Diagnosis]
	observer func(DiagnoseViewModel)

	mu             sync.Mutex
	config         application.Config
	pendingProfile *model.Profile
	state          DiagnoseViewModel
}

// NewDiagnoseCoordinator creates a diagnostic use-case coordinator.
func NewDiagnoseCoordinator(
	runner *taskrunner.Runner,
	backend Backend,
	observer func(DiagnoseViewModel),
) (*DiagnoseCoordinator, error) {
	if backend == nil {
		return nil, errCoordinatorBackendRequired
	}
	coordinator := &DiagnoseCoordinator{
		backend:  backend,
		observer: observer,
		config:   application.DefaultConfig(),
		state:    DiagnoseViewModel{State: taskrunner.StateIdle},
	}
	scope, err := taskrunner.NewScope(runner, "diagnose", coordinator.observe)
	if err != nil {
		return nil, err
	}
	coordinator.scope = scope
	return coordinator, nil
}

// SetConfiguration replaces the settings snapshot used to identify explicit
// per-run overrides.
func (coordinator *DiagnoseCoordinator) SetConfiguration(config application.Config) {
	coordinator.mu.Lock()
	coordinator.config = config
	coordinator.mu.Unlock()
}

// SetPendingProfile selects a profile for the next run. The value is consumed
// exactly once when Start builds the request.
func (coordinator *DiagnoseCoordinator) SetPendingProfile(profile *model.Profile) {
	coordinator.mu.Lock()
	if profile == nil {
		coordinator.pendingProfile = nil
	} else {
		copy := *profile
		coordinator.pendingProfile = &copy
	}
	coordinator.mu.Unlock()
}

// Start replaces the current diagnosis and streams events with its operation
// identifier so the view can reject stale progress.
func (coordinator *DiagnoseCoordinator) Start(
	input presenter.DiagnoseInput,
	sink func(taskrunner.OperationID, model.CheckEvent),
) (taskrunner.OperationID, error) {
	request := coordinator.request(input)
	return coordinator.scope.StartReadOperation(func(
		ctx context.Context,
		operationID taskrunner.OperationID,
	) (model.Diagnosis, error) {
		var eventSink model.EventSink
		if sink != nil {
			eventSink = func(event model.CheckEvent) { sink(operationID, event) }
		}
		return coordinator.backend.DiagnoseRequest(ctx, request, eventSink)
	})
}

// Cancel publishes cancellation for the current diagnostic operation.
func (coordinator *DiagnoseCoordinator) Cancel() {
	coordinator.scope.Cancel()
}

// Invalidate cancels the current operation without presenting its terminal
// state and clears a profile that has not yet been consumed.
func (coordinator *DiagnoseCoordinator) Invalidate() {
	coordinator.scope.Invalidate()
	coordinator.SetPendingProfile(nil)
}

// Current reports whether operationID still belongs to a presentable run.
func (coordinator *DiagnoseCoordinator) Current(operationID taskrunner.OperationID) bool {
	snapshot := coordinator.scope.Snapshot()
	if snapshot.OperationID != operationID {
		return false
	}
	return snapshot.State == taskrunner.StateLoading || snapshot.State == taskrunner.StateSuccess
}

// Snapshot returns the current diagnostic view model.
func (coordinator *DiagnoseCoordinator) Snapshot() DiagnoseViewModel {
	if coordinator.scope != nil {
		snapshot := coordinator.scope.Snapshot()
		return DiagnoseViewModel{
			OperationID: snapshot.OperationID,
			State:       snapshot.State,
			Diagnosis:   privacy.Standard().Diagnosis(snapshot.Value),
			Err:         snapshot.Err,
		}
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	state := coordinator.state
	state.Diagnosis = privacy.Standard().Diagnosis(state.Diagnosis)
	return state
}

func (coordinator *DiagnoseCoordinator) request(input presenter.DiagnoseInput) application.DiagnoseRequest {
	coordinator.mu.Lock()
	profile := coordinator.pendingProfile
	coordinator.pendingProfile = nil
	config := coordinator.config
	coordinator.mu.Unlock()
	if config.Diagnostics.DefaultTimeout == 0 {
		config = application.DefaultConfig()
	}

	insecure := input.Insecure
	allowInsecureRedirects := input.AllowInsecureRedirects
	allowPrivateRedirects := input.AllowPrivateRedirects
	verbosity := model.ReportVerbosity(input.Verbosity)
	request := application.DiagnoseRequest{Profile: profile}
	if profile != nil {
		request.Overrides = application.DiagnoseOverrides{
			Insecure:               &insecure,
			AllowInsecureRedirects: &allowInsecureRedirects,
			AllowPrivateRedirects:  &allowPrivateRedirects,
			ReportVerbosity:        &verbosity,
		}
		return request
	}

	target := input.Target
	request.Overrides.Target = &target
	baseline, err := application.ResolveDiagnoseOptions(
		config,
		nil,
		application.DiagnoseOverrides{Target: &target},
	)
	if err != nil {
		return request
	}

	mode := model.DiagnosticMode(input.Mode)
	timeout := input.Timeout
	checkTimeout := input.CheckTimeout
	ipVersion := model.IPVersion(input.IPVersion)
	noProxy := input.NoProxy
	maxRedirects := input.MaxRedirects
	method := input.Method
	if mode != model.DiagnosticModeAuto {
		request.Overrides.Mode = &mode
	}
	if timeout != baseline.Timeout {
		request.Overrides.Timeout = &timeout
	}
	if checkTimeout != baseline.CheckTimeout {
		request.Overrides.CheckTimeout = &checkTimeout
	}
	if ipVersion != baseline.IPVersion {
		request.Overrides.IPVersion = &ipVersion
	}
	if noProxy != baseline.NoProxy {
		request.Overrides.NoProxy = &noProxy
	}
	if insecure != baseline.Insecure {
		request.Overrides.Insecure = &insecure
	}
	if allowInsecureRedirects != baseline.AllowInsecureRedirects {
		request.Overrides.AllowInsecureRedirects = &allowInsecureRedirects
	}
	if allowPrivateRedirects != baseline.AllowPrivateRedirects {
		request.Overrides.AllowPrivateRedirects = &allowPrivateRedirects
	}
	if maxRedirects != baseline.MaxRedirects {
		request.Overrides.MaxRedirects = &maxRedirects
	}
	if method != baseline.Method {
		request.Overrides.Method = &method
	}
	if verbosity != baseline.ReportVerbosity {
		request.Overrides.ReportVerbosity = &verbosity
	}
	return request
}

func (coordinator *DiagnoseCoordinator) observe(snapshot taskrunner.Snapshot[model.Diagnosis]) {
	state := DiagnoseViewModel{
		OperationID: snapshot.OperationID,
		State:       snapshot.State,
		Diagnosis:   privacy.Standard().Diagnosis(snapshot.Value),
		Err:         snapshot.Err,
	}
	coordinator.mu.Lock()
	coordinator.state = state
	observer := coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

// HistoryReadAction identifies how a loaded diagnosis will be consumed.
type HistoryReadAction uint8

const (
	HistoryReadOpen HistoryReadAction = iota + 1
	HistoryReadRerun
	HistoryReadExport
)

// HistoryMutationAction identifies a history mutation.
type HistoryMutationAction uint8

const (
	HistoryMutationDelete HistoryMutationAction = iota + 1
	HistoryMutationClear
)

type historyReadResult struct {
	Action    HistoryReadAction
	Diagnosis model.Diagnosis
}

type historyMutationResult struct {
	Action HistoryMutationAction
}

// HistoryViewChange identifies which portion of HistoryViewModel changed.
type HistoryViewChange uint8

const (
	HistoryViewLoadChanged HistoryViewChange = iota + 1
	HistoryViewReadChanged
	HistoryViewMutationChanged
)

// HistoryViewModel contains the complete Fyne-free state of history loading,
// reading, and mutation use cases.
type HistoryViewModel struct {
	Changed   HistoryViewChange
	LoadState taskrunner.State
	Rows      []presenter.HistoryView
	LoadErr   error

	ReadState     taskrunner.State
	ReadAction    HistoryReadAction
	Diagnosis     model.Diagnosis
	ReadErr       error
	MutationState taskrunner.State
	Mutation      HistoryMutationAction
	MutationErr   error
}

// HistoryCoordinator coordinates history reads and mutations independently of
// screen widgets and dialogs.
type HistoryCoordinator struct {
	backend  Backend
	observer func(HistoryViewModel)
	load     *taskrunner.Scope[[]presenter.HistoryView]
	read     *taskrunner.Scope[historyReadResult]
	mutation *taskrunner.Scope[historyMutationResult]

	mu    sync.Mutex
	state HistoryViewModel
}

// NewHistoryCoordinator creates a history use-case coordinator.
func NewHistoryCoordinator(
	runner *taskrunner.Runner,
	backend Backend,
	observer func(HistoryViewModel),
) (*HistoryCoordinator, error) {
	if backend == nil {
		return nil, errCoordinatorBackendRequired
	}
	coordinator := &HistoryCoordinator{
		backend:  backend,
		observer: observer,
		state: HistoryViewModel{
			LoadState:     taskrunner.StateIdle,
			ReadState:     taskrunner.StateIdle,
			MutationState: taskrunner.StateIdle,
		},
	}
	var err error
	coordinator.load, err = taskrunner.NewScope(runner, "history.load", coordinator.observeLoad)
	if err != nil {
		return nil, err
	}
	coordinator.read, err = taskrunner.NewScope(runner, "history.read", coordinator.observeRead)
	if err != nil {
		coordinator.load.Close()
		return nil, err
	}
	coordinator.mutation, err = taskrunner.NewScope(runner, "history.mutation", coordinator.observeMutation)
	if err != nil {
		coordinator.read.Close()
		coordinator.load.Close()
		return nil, err
	}
	return coordinator, nil
}

// Load replaces the current history query.
func (coordinator *HistoryCoordinator) Load(search string, status model.Status) error {
	_, err := coordinator.load.StartRead(func(ctx context.Context) ([]presenter.HistoryView, error) {
		entries, loadErr := coordinator.backend.ListHistory(ctx, search, status)
		if loadErr != nil {
			return nil, loadErr
		}
		rows := make([]presenter.HistoryView, 0, len(entries))
		for _, entry := range entries {
			rows = append(rows, presenter.History(entry))
		}
		return rows, nil
	})
	return err
}

// Read loads one diagnosis for the selected follow-up action.
func (coordinator *HistoryCoordinator) Read(action HistoryReadAction, id string) error {
	_, err := coordinator.read.StartRead(func(ctx context.Context) (historyReadResult, error) {
		diagnosis, readErr := coordinator.backend.GetDiagnosis(ctx, id)
		return historyReadResult{Action: action, Diagnosis: diagnosis}, readErr
	})
	return err
}

// Mutate serializes deletion of one diagnosis or clearing all history.
func (coordinator *HistoryCoordinator) Mutate(action HistoryMutationAction, id string) error {
	_, err := coordinator.mutation.StartMutation(func(ctx context.Context) (historyMutationResult, error) {
		result := historyMutationResult{Action: action}
		if action == HistoryMutationClear {
			return result, coordinator.backend.ClearHistory(ctx)
		}
		return result, coordinator.backend.DeleteDiagnosis(ctx, id)
	})
	return err
}

// Cancel invalidates all history work owned by the screen.
func (coordinator *HistoryCoordinator) Cancel() {
	coordinator.load.Cancel()
	coordinator.read.Cancel()
	coordinator.mutation.Cancel()
}

// Snapshot returns an independent copy of the current history view model.
func (coordinator *HistoryCoordinator) Snapshot() HistoryViewModel {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return cloneHistoryViewModel(coordinator.state)
}

func (coordinator *HistoryCoordinator) observeLoad(snapshot taskrunner.Snapshot[[]presenter.HistoryView]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = HistoryViewLoadChanged
	coordinator.state.LoadState = snapshot.State
	coordinator.state.LoadErr = snapshot.Err
	if snapshot.State == taskrunner.StateSuccess {
		coordinator.state.Rows = append([]presenter.HistoryView(nil), snapshot.Value...)
	}
	state, observer := cloneHistoryViewModel(coordinator.state), coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func (coordinator *HistoryCoordinator) observeRead(snapshot taskrunner.Snapshot[historyReadResult]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = HistoryViewReadChanged
	coordinator.state.ReadState = snapshot.State
	coordinator.state.ReadAction = snapshot.Value.Action
	coordinator.state.Diagnosis = privacy.Standard().Diagnosis(snapshot.Value.Diagnosis)
	coordinator.state.ReadErr = snapshot.Err
	state, observer := cloneHistoryViewModel(coordinator.state), coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func (coordinator *HistoryCoordinator) observeMutation(snapshot taskrunner.Snapshot[historyMutationResult]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = HistoryViewMutationChanged
	coordinator.state.MutationState = snapshot.State
	coordinator.state.Mutation = snapshot.Value.Action
	coordinator.state.MutationErr = snapshot.Err
	state, observer := cloneHistoryViewModel(coordinator.state), coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func cloneHistoryViewModel(state HistoryViewModel) HistoryViewModel {
	state.Rows = append([]presenter.HistoryView(nil), state.Rows...)
	return state
}

// ProfileMutationAction identifies a profile save, duplicate, or delete use case.
type ProfileMutationAction uint8

const (
	ProfileMutationSave ProfileMutationAction = iota + 1
	ProfileMutationDuplicate
	ProfileMutationDelete
)

type profileMutationResult struct {
	Action ProfileMutationAction
	Saved  model.Profile
}

// ProfilesViewChange identifies which portion of ProfilesViewModel changed.
type ProfilesViewChange uint8

const (
	ProfilesViewLoadChanged ProfilesViewChange = iota + 1
	ProfilesViewMutationChanged
)

// ProfilesViewModel contains the Fyne-free state of profile loading and mutation.
type ProfilesViewModel struct {
	Changed   ProfilesViewChange
	LoadState taskrunner.State
	Profiles  []presenter.ProfileView
	LoadErr   error

	MutationState taskrunner.State
	Mutation      ProfileMutationAction
	Saved         model.Profile
	MutationErr   error
}

// ProfilesCoordinator coordinates saved-profile use cases independently of widgets.
type ProfilesCoordinator struct {
	backend  Backend
	observer func(ProfilesViewModel)
	load     *taskrunner.Scope[[]presenter.ProfileView]
	mutation *taskrunner.Scope[profileMutationResult]

	mu    sync.Mutex
	state ProfilesViewModel
}

// NewProfilesCoordinator creates a profiles use-case coordinator.
func NewProfilesCoordinator(
	runner *taskrunner.Runner,
	backend Backend,
	observer func(ProfilesViewModel),
) (*ProfilesCoordinator, error) {
	if backend == nil {
		return nil, errCoordinatorBackendRequired
	}
	coordinator := &ProfilesCoordinator{
		backend:  backend,
		observer: observer,
		state: ProfilesViewModel{
			LoadState:     taskrunner.StateIdle,
			MutationState: taskrunner.StateIdle,
		},
	}
	var err error
	coordinator.load, err = taskrunner.NewScope(runner, "profiles.load", coordinator.observeLoad)
	if err != nil {
		return nil, err
	}
	coordinator.mutation, err = taskrunner.NewScope(runner, "profiles.mutation", coordinator.observeMutation)
	if err != nil {
		coordinator.load.Close()
		return nil, err
	}
	return coordinator, nil
}

// Load replaces the current saved-profile query.
func (coordinator *ProfilesCoordinator) Load() error {
	_, err := coordinator.load.StartRead(func(ctx context.Context) ([]presenter.ProfileView, error) {
		profiles, loadErr := coordinator.backend.ListProfiles(ctx)
		if loadErr != nil {
			return nil, loadErr
		}
		views := make([]presenter.ProfileView, 0, len(profiles))
		for _, profile := range profiles {
			views = append(views, presenter.Profile(profile))
		}
		return views, nil
	})
	return err
}

// Save serializes profile creation, update, or duplication.
func (coordinator *ProfilesCoordinator) Save(action ProfileMutationAction, profile model.Profile) error {
	_, err := coordinator.mutation.StartMutation(func(ctx context.Context) (profileMutationResult, error) {
		saved, saveErr := coordinator.backend.SaveProfile(ctx, profile)
		return profileMutationResult{Action: action, Saved: saved}, saveErr
	})
	return err
}

// Delete serializes removal of one profile.
func (coordinator *ProfilesCoordinator) Delete(id int64) error {
	_, err := coordinator.mutation.StartMutation(func(ctx context.Context) (profileMutationResult, error) {
		return profileMutationResult{Action: ProfileMutationDelete}, coordinator.backend.DeleteProfile(ctx, id)
	})
	return err
}

// Cancel invalidates all profile work owned by the screen.
func (coordinator *ProfilesCoordinator) Cancel() {
	coordinator.load.Cancel()
	coordinator.mutation.Cancel()
}

// Snapshot returns an independent copy of the current profiles view model.
func (coordinator *ProfilesCoordinator) Snapshot() ProfilesViewModel {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return cloneProfilesViewModel(coordinator.state)
}

func (coordinator *ProfilesCoordinator) observeLoad(snapshot taskrunner.Snapshot[[]presenter.ProfileView]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = ProfilesViewLoadChanged
	coordinator.state.LoadState = snapshot.State
	coordinator.state.LoadErr = snapshot.Err
	if snapshot.State == taskrunner.StateSuccess {
		coordinator.state.Profiles = append([]presenter.ProfileView(nil), snapshot.Value...)
	}
	state, observer := cloneProfilesViewModel(coordinator.state), coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func (coordinator *ProfilesCoordinator) observeMutation(snapshot taskrunner.Snapshot[profileMutationResult]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = ProfilesViewMutationChanged
	coordinator.state.MutationState = snapshot.State
	coordinator.state.Mutation = snapshot.Value.Action
	coordinator.state.Saved = snapshot.Value.Saved
	coordinator.state.MutationErr = snapshot.Err
	state, observer := cloneProfilesViewModel(coordinator.state), coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func cloneProfilesViewModel(state ProfilesViewModel) ProfilesViewModel {
	state.Profiles = append([]presenter.ProfileView(nil), state.Profiles...)
	return state
}

// SettingsViewChange identifies which portion of SettingsViewModel changed.
type SettingsViewChange uint8

const (
	SettingsViewLoadChanged SettingsViewChange = iota + 1
	SettingsViewSaveChanged
)

// SettingsViewModel contains Fyne-free configuration load and save state.
type SettingsViewModel struct {
	Changed   SettingsViewChange
	LoadState taskrunner.State
	SaveState taskrunner.State
	Config    application.Config
	LoadErr   error
	SaveErr   error
}

// SettingsCoordinator coordinates configuration persistence independently of widgets.
type SettingsCoordinator struct {
	backend  Backend
	observer func(SettingsViewModel)
	load     *taskrunner.Scope[application.Config]
	save     *taskrunner.Scope[application.Config]

	mu    sync.Mutex
	state SettingsViewModel
}

// NewSettingsCoordinator creates a settings use-case coordinator.
func NewSettingsCoordinator(
	runner *taskrunner.Runner,
	backend Backend,
	observer func(SettingsViewModel),
) (*SettingsCoordinator, error) {
	if backend == nil {
		return nil, errCoordinatorBackendRequired
	}
	coordinator := &SettingsCoordinator{
		backend:  backend,
		observer: observer,
		state: SettingsViewModel{
			LoadState: taskrunner.StateIdle,
			SaveState: taskrunner.StateIdle,
			Config:    application.DefaultConfig(),
		},
	}
	var err error
	coordinator.load, err = taskrunner.NewScope(runner, "configuration.load", coordinator.observeLoad)
	if err != nil {
		return nil, err
	}
	coordinator.save, err = taskrunner.NewScope(runner, "configuration.save", coordinator.observeSave)
	if err != nil {
		coordinator.load.Close()
		return nil, err
	}
	return coordinator, nil
}

// Load replaces the current configuration read.
func (coordinator *SettingsCoordinator) Load() error {
	_, err := coordinator.load.StartRead(func(context.Context) (application.Config, error) {
		return coordinator.backend.Configuration(), nil
	})
	return err
}

// Save serializes configuration persistence.
func (coordinator *SettingsCoordinator) Save(config application.Config) error {
	_, err := coordinator.save.StartMutation(func(context.Context) (application.Config, error) {
		return config, coordinator.backend.SaveConfiguration(config)
	})
	return err
}

// Cancel invalidates configuration work owned by the Settings screen.
func (coordinator *SettingsCoordinator) Cancel() {
	coordinator.load.Cancel()
	coordinator.save.Cancel()
}

// Snapshot returns the current settings view model.
func (coordinator *SettingsCoordinator) Snapshot() SettingsViewModel {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.state
}

func (coordinator *SettingsCoordinator) observeLoad(snapshot taskrunner.Snapshot[application.Config]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = SettingsViewLoadChanged
	coordinator.state.LoadState = snapshot.State
	coordinator.state.LoadErr = snapshot.Err
	if snapshot.State == taskrunner.StateSuccess {
		coordinator.state.Config = snapshot.Value
	}
	state, observer := coordinator.state, coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}

func (coordinator *SettingsCoordinator) observeSave(snapshot taskrunner.Snapshot[application.Config]) {
	coordinator.mu.Lock()
	coordinator.state.Changed = SettingsViewSaveChanged
	coordinator.state.SaveState = snapshot.State
	coordinator.state.SaveErr = snapshot.Err
	if snapshot.State == taskrunner.StateSuccess {
		coordinator.state.Config = snapshot.Value
	}
	state, observer := coordinator.state, coordinator.observer
	coordinator.mu.Unlock()
	if observer != nil {
		observer(state)
	}
}
