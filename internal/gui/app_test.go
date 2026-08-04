//go:build wayland

package gui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/gui/components"
	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/gui/presenter"
	"github.com/Naenier/orynelo/internal/gui/screens"
	"github.com/Naenier/orynelo/internal/gui/taskrunner"
)

func TestDiagnoseRequestCarriesExplicitOverridesToApplicationResolver(t *testing.T) {
	t.Parallel()

	coordinator := &DiagnoseCoordinator{config: application.DefaultConfig()}
	input := presenter.DiagnoseInput{
		Target:       "  https://example.test/path  ",
		Mode:         "tls",
		IPVersion:    "4",
		Timeout:      2 * time.Second,
		CheckTimeout: 3 * time.Second,
		Method:       "HEAD",
		NoProxy:      true,
		MaxRedirects: 5,
		Verbosity:    "verbose",
		Insecure:     true,
	}
	request := coordinator.request(input)
	if request.Profile != nil || request.Overrides.Target == nil ||
		*request.Overrides.Target != input.Target || request.Overrides.Mode == nil ||
		*request.Overrides.Mode != model.DiagnosticModeTLS {
		t.Fatalf("request = %#v", request)
	}
	if request.Overrides.EnableTLS != nil {
		t.Fatal("GUI duplicated mode-to-TLS normalization")
	}
	if _, err := application.ResolveDiagnoseOptions(
		application.DefaultConfig(),
		nil,
		request.Overrides,
	); err == nil || !application.IsErrorCode(err, "APP_DIAGNOSE_OPTIONS_INVALID") {
		t.Fatalf("application resolver error = %v, want typed options validation", err)
	}
}

func TestDiagnoseRequestUsesProfileWithoutReencodingItsDefaults(t *testing.T) {
	t.Parallel()

	profile := model.Profile{
		Name:         "Saved",
		Target:       "saved.example:443",
		Mode:         model.DiagnosticModeTCP,
		IPVersion:    model.IPVersion6,
		Timeout:      10 * time.Second,
		CheckTimeout: 4 * time.Second,
		MaxRedirects: 3,
		Method:       "HEAD",
	}
	coordinator := &DiagnoseCoordinator{
		config:         application.DefaultConfig(),
		pendingProfile: &profile,
	}
	request := coordinator.request(presenter.DiagnoseInput{
		Target:                 "must-not-override.example",
		Mode:                   "tls",
		Timeout:                time.Minute,
		Insecure:               true,
		AllowPrivateRedirects:  true,
		AllowInsecureRedirects: true,
		Verbosity:              "verbose",
	})
	if request.Profile != &profile {
		t.Fatalf("request profile = %p, want %p", request.Profile, &profile)
	}
	if request.Overrides.Target != nil || request.Overrides.Mode != nil ||
		request.Overrides.Timeout != nil || request.Overrides.CheckTimeout != nil {
		t.Fatalf("profile fields were redundantly encoded as overrides: %#v", request.Overrides)
	}
	if request.Overrides.Insecure == nil || !*request.Overrides.Insecure ||
		request.Overrides.ReportVerbosity == nil ||
		*request.Overrides.ReportVerbosity != model.ReportVerbosityVerbose {
		t.Fatalf("transient overrides = %#v", request.Overrides)
	}
	if coordinator.pendingProfile != nil {
		t.Fatal("pending profile was not consumed")
	}
}

func TestDiagnoseRequestDoesNotEncodeDisplayedConfigurationAsOverrides(t *testing.T) {
	t.Parallel()

	config := application.DefaultConfig()
	config.Diagnostics.DefaultTimeout = 21 * time.Second
	config.Diagnostics.CheckTimeout = 7 * time.Second
	config.Diagnostics.PreferredIPVersion = "6"
	config.Diagnostics.MaxRedirects = 4
	config.Network.UseSystemProxy = false
	coordinator := &DiagnoseCoordinator{config: config}
	request := coordinator.request(presenter.DiagnoseInput{
		Target:       "https://example.test",
		Mode:         "auto",
		IPVersion:    "6",
		Timeout:      21 * time.Second,
		CheckTimeout: 7 * time.Second,
		Method:       "GET",
		NoProxy:      true,
		MaxRedirects: 4,
		Verbosity:    "normal",
	})
	overrides := request.Overrides
	if overrides.Target == nil {
		t.Fatal("target was not explicitly submitted")
	}
	if overrides.Mode != nil || overrides.Timeout != nil ||
		overrides.CheckTimeout != nil || overrides.IPVersion != nil ||
		overrides.NoProxy != nil || overrides.MaxRedirects != nil ||
		overrides.Method != nil || overrides.Insecure != nil ||
		overrides.ReportVerbosity != nil {
		t.Fatalf("displayed configuration leaked into explicit overrides: %#v", overrides)
	}
}

func TestUserFacingApplicationErrorNeverShowsWrappedCause(t *testing.T) {
	t.Parallel()

	const secretCause = "database /private/path failed with password=hunter2"
	err := application.WrapError(
		errors.New(secretCause),
		application.ErrorCategoryStorage,
		"APP_HISTORY_LIST_FAILED",
		"error.history_list_failed",
		nil,
	)
	message := (&controller{texts: localization.English{}}).userFacingError(err)
	if strings.Contains(message, secretCause) || strings.Contains(message, "hunter2") ||
		strings.Contains(message, "/private/path") {
		t.Fatalf("user-facing message leaked wrapped cause: %q", message)
	}
	if !strings.Contains(message, "Retry") || !strings.Contains(message, "APP_HISTORY_LIST_FAILED") {
		t.Fatalf("user-facing message lacks recovery guidance/reference: %q", message)
	}
}

func TestUserFacingValidationErrorNamesSafeField(t *testing.T) {
	t.Parallel()

	err := application.NewError(
		application.ErrorCategoryValidation,
		"APP_DIAGNOSE_OPTIONS_INVALID",
		"error.diagnose_options_invalid",
		map[string]string{"field": "checkTimeout"},
	)
	message := (&controller{texts: localization.English{}}).userFacingError(err)
	if !strings.Contains(message, "Per-check timeout") {
		t.Fatalf("validation message does not identify the field: %q", message)
	}
}

func TestReportWriteBoundaryPreservesCauseButDisplaysTypedStorageError(t *testing.T) {
	t.Parallel()

	cause := errors.New("writer failed for /private/report with token=export-secret")
	err := guiBoundaryError(
		cause,
		application.ErrorCategoryStorage,
		"APP_REPORT_WRITE_FAILED",
		"error.report_write_failed",
		nil,
	)
	if !errors.Is(err, cause) {
		t.Fatal("typed report error did not preserve its logging cause")
	}
	view := application.ToErrorView(err)
	if view == nil || view.Category != application.ErrorCategoryStorage ||
		view.Code != "APP_REPORT_WRITE_FAILED" {
		t.Fatalf("typed report error view = %#v", view)
	}
	message := (&controller{texts: localization.English{}}).userFacingError(err)
	if strings.Contains(message, "private/report") || strings.Contains(message, "export-secret") {
		t.Fatalf("report write cause leaked to UI: %q", message)
	}
	if !strings.Contains(message, "APP_REPORT_WRITE_FAILED") {
		t.Fatalf("report write reference missing: %q", message)
	}
}

func TestHistoryRunOptionsAreRestoredToDiagnoseScreen(t *testing.T) {
	test.NewTempApp(t)
	diagnosis := model.Diagnosis{
		Target: model.Target{
			Original:    "https://example.test",
			DisplayHost: "example.test",
		},
		Options: model.DiagnoseOptions{
			Timeout:         15 * time.Second,
			CheckTimeout:    5 * time.Second,
			IPVersion:       model.IPVersionAuto,
			Insecure:        true,
			MaxRedirects:    10,
			Method:          "GET",
			ReportVerbosity: model.ReportVerbosityVerbose,
		},
	}
	screen := screens.NewDiagnose(localization.English{}, screens.DiagnoseActions{})
	screen.SetProfile(profileViewFromDiagnosis(diagnosis))

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if !input.Insecure {
		t.Fatal("history rerun did not restore insecure TLS")
	}
	if input.Verbosity != "verbose" {
		t.Fatalf("history rerun verbosity = %q, want verbose", input.Verbosity)
	}
}

func TestDiagnosticShortcutShowsDiagnoseBeforeRunning(t *testing.T) {
	test.NewTempApp(t)
	runs := 0
	diagnose := screens.NewDiagnose(localization.English{}, screens.DiagnoseActions{
		Run: func(presenter.DiagnoseInput) {
			runs++
		},
	})
	diagnose.SetTarget("example.test:443")
	controller := &controller{
		content:       container.NewStack(widget.NewLabel("Settings")),
		diagnose:      diagnose,
		currentScreen: "settings",
		texts:         localization.English{},
	}

	controller.triggerDiagnosticShortcut()

	if controller.currentScreen != "diagnose" {
		t.Fatalf("current screen = %q, want diagnose", controller.currentScreen)
	}
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

func TestHeaderStatusTracksRunOutcomes(t *testing.T) {
	test.NewTempApp(t)
	controller := &controller{
		header:       widget.NewLabel(""),
		headerStatus: components.NewStatusIcon(localization.English{}, "pending", ""),
		info:         buildinfo.Info{Version: "1.2.3"},
		texts:        localization.English{},
	}

	controller.setHeaderStatus(localization.HeaderRunning)
	if controller.header.Text != "Running · 1.2.3" {
		t.Fatalf("running header = %q", controller.header.Text)
	}
	controller.setHeaderForDiagnosis(model.Diagnosis{
		Summary: model.Summary{Status: model.StatusWarning},
	})
	if controller.header.Text != "Completed: WARNING · 1.2.3" {
		t.Fatalf("completed header = %q", controller.header.Text)
	}
	controller.setHeaderForDiagnosis(model.Diagnosis{
		Summary: model.Summary{Status: model.StatusCancelled},
	})
	if controller.header.Text != "Cancelled · 1.2.3" {
		t.Fatalf("cancelled header = %q", controller.header.Text)
	}
	controller.setHeaderStatus(localization.HeaderError)
	if !strings.HasPrefix(controller.header.Text, "Error · ") {
		t.Fatalf("error header = %q", controller.header.Text)
	}
	if label := controller.headerStatus.AccessibilityLabel(); !strings.Contains(label, "FAILED") {
		t.Fatalf("error status accessibility label = %q", label)
	}
}

func TestCompactHeaderVersionLeavesBuildDetailsForAboutScreen(t *testing.T) {
	t.Parallel()

	if got := compactHeaderVersion("1.2.3+local"); got != "1.2.3" {
		t.Fatalf("compactHeaderVersion() = %q, want 1.2.3", got)
	}
	if got := compactHeaderVersion("1.2.3"); got != "1.2.3" {
		t.Fatalf("plain version = %q, want 1.2.3", got)
	}
}

func TestShowScreenUpdatesPageTitleAndActiveNavigation(t *testing.T) {
	test.NewTempApp(t)
	diagnose := screens.NewDiagnose(
		localization.English{},
		screens.DiagnoseActions{},
	)
	active := widget.NewButton("Diagnose", nil)
	inactive := widget.NewButton("History", nil)
	controller := &controller{
		content:   container.NewStack(),
		diagnose:  diagnose,
		texts:     localization.English{},
		pageTitle: widget.NewLabel(""),
		navigationButtons: map[string]*widget.Button{
			"diagnose": active,
			"history":  inactive,
		},
	}

	controller.showScreen("diagnose")

	if controller.pageTitle.Text != "Diagnose" {
		t.Fatalf("page title = %q, want Diagnose", controller.pageTitle.Text)
	}
	if active.Importance != widget.HighImportance {
		t.Fatalf("active importance = %v, want high", active.Importance)
	}
	if inactive.Importance != widget.LowImportance {
		t.Fatalf("inactive importance = %v, want low", inactive.Importance)
	}
}

func TestNonDiagnoseScreenShowsContextualLastRunStatus(t *testing.T) {
	test.NewTempApp(t)
	diagnose := screens.NewDiagnose(
		localization.English{},
		screens.DiagnoseActions{},
	)
	controller := &controller{
		content:  container.NewStack(),
		diagnose: diagnose,
		settings: widget.NewLabel("Settings"),
		header:   widget.NewLabel(""),
		headerStatus: components.NewStatusIcon(
			localization.English{},
			"pending",
			"",
		),
		info:  buildinfo.Info{Version: "1.2.3"},
		texts: localization.English{},
	}

	controller.showScreen("settings")
	controller.setHeaderForDiagnosis(model.Diagnosis{
		Summary: model.Summary{Status: model.StatusFailed},
	})
	if controller.header.Text != "Last run: FAILED · 1.2.3" {
		t.Fatalf("settings header = %q, want contextual last-run status", controller.header.Text)
	}
	if !controller.headerStatus.Visible() {
		t.Fatal("settings last-run status icon is hidden")
	}

	controller.showScreen("diagnose")
	if controller.header.Text != "Completed: FAILED · 1.2.3" {
		t.Fatalf("diagnose header = %q, want restored run status", controller.header.Text)
	}

	controller.setHeaderForDiagnosis(model.Diagnosis{
		Summary: model.Summary{Status: model.StatusPassed},
	})
	controller.setDiagnoseHeaderStatus(localization.HeaderError)
	controller.showScreen("settings")
	if controller.header.Text != "Last run: PASSED · 1.2.3" {
		t.Fatalf(
			"settings header after input error = %q, want prior completed run",
			controller.header.Text,
		)
	}
}

func TestShowScreenUnfocusesDetachedControl(t *testing.T) {
	test.NewTempApp(t)
	diagnose := screens.NewDiagnose(
		localization.English{},
		screens.DiagnoseActions{},
	)
	content := container.NewStack(diagnose.Root)
	window := test.NewWindow(content)
	t.Cleanup(window.Close)
	controller := &controller{
		window:        window,
		content:       content,
		diagnose:      diagnose,
		settings:      widget.NewLabel("Settings"),
		currentScreen: "diagnose",
		texts:         localization.English{},
	}
	diagnose.FocusTarget(window.Canvas())
	if window.Canvas().Focused() == nil {
		t.Fatal("target entry was not focused before navigation")
	}

	controller.showScreen("settings")

	if focused := window.Canvas().Focused(); focused != nil {
		t.Fatalf("detached control retained focus: %T", focused)
	}
}

func TestStartProfileCancelsActiveRunBeforeReplacingInputs(t *testing.T) {
	test.NewTempApp(t)
	var started presenter.DiagnoseInput
	diagnose := screens.NewDiagnose(
		localization.English{},
		screens.DiagnoseActions{
			Run: func(input presenter.DiagnoseInput) {
				started = input
			},
		},
	)
	diagnose.SetTarget("active.example:443")
	diagnose.SetRunning(true)
	runner, coordinator, operationID, cancelled := activeDiagnosticTask(t)
	t.Cleanup(func() {
		runner.Close()
		runner.Wait()
	})
	controller := &controller{
		content:             container.NewStack(),
		diagnose:            diagnose,
		currentScreen:       "profiles",
		diagnoseCoordinator: coordinator,
		texts:               localization.English{},
	}

	controller.startProfile(presenter.ProfileView{
		Name:         "Profile",
		Target:       "profile.example:8443",
		Mode:         "tcp",
		IPVersion:    "4",
		Timeout:      10 * time.Second,
		CheckTimeout: 3 * time.Second,
		MaxRedirects: 5,
		Method:       "HEAD",
	})

	select {
	case <-cancelled:
	default:
		t.Fatal("active diagnostic was not cancelled")
	}
	if controller.shouldPresentDiagnostic(operationID) {
		t.Fatal("events from the replaced diagnostic are still presentable")
	}
	if started.Target != "profile.example:8443" ||
		started.Mode != "tcp" ||
		started.IPVersion != "4" {
		t.Fatalf("started profile input = %#v", started)
	}
	if controller.currentScreen != "diagnose" {
		t.Fatalf("current screen = %q, want diagnose", controller.currentScreen)
	}
}

func TestHistoricalDiagnosisInvalidatesRunAndRestoresRunAgainInput(t *testing.T) {
	test.NewTempApp(t)
	var rerun presenter.DiagnoseInput
	diagnose := screens.NewDiagnose(
		localization.English{},
		screens.DiagnoseActions{
			Run: func(input presenter.DiagnoseInput) {
				rerun = input
			},
		},
	)
	diagnose.SetTarget("active.example:443")
	diagnose.SetRunning(true)
	runner, coordinator, operationID, cancelled := activeDiagnosticTask(t)
	t.Cleanup(func() {
		runner.Close()
		runner.Wait()
	})
	controller := &controller{
		content:             container.NewStack(),
		diagnose:            diagnose,
		header:              widget.NewLabel(""),
		currentScreen:       "history",
		diagnoseCoordinator: coordinator,
		texts:               localization.English{},
		info:                buildinfo.Info{Version: "1.2.3"},
	}
	diagnosis := model.Diagnosis{
		Target: model.Target{
			Original:    "https://history.example/path",
			DisplayHost: "history.example",
		},
		Options: model.DiagnoseOptions{
			Timeout:         12 * time.Second,
			CheckTimeout:    4 * time.Second,
			IPVersion:       model.IPVersion6,
			MaxRedirects:    7,
			Method:          "OPTIONS",
			ReportVerbosity: model.ReportVerbosityVerbose,
		},
		Summary: model.Summary{
			Status:      model.StatusFailed,
			Title:       "DNS resolution failed",
			Description: "No address was returned.",
		},
	}

	controller.presentHistoricalDiagnosis(diagnosis)

	select {
	case <-cancelled:
	default:
		t.Fatal("active diagnostic was not cancelled before opening history")
	}
	if controller.shouldPresentDiagnostic(operationID) {
		t.Fatal("events from the replaced diagnostic are still presentable")
	}
	if !controller.haveDiagnosis ||
		controller.lastDiagnosis.Target.Original != diagnosis.Target.Original {
		t.Fatal("historical diagnosis was not made the current completed result")
	}

	diagnose.TriggerRun()
	if rerun.Target != diagnosis.Target.Original ||
		rerun.IPVersion != string(model.IPVersion6) ||
		rerun.Method != "OPTIONS" {
		t.Fatalf("Run again input = %#v", rerun)
	}
}

func TestHistoricalDiagnosisSuppressesQueuedCancellationPresentation(t *testing.T) {
	test.NewTempApp(t)
	dispatcher := &queuedTestDispatcher{}
	runner, err := taskrunner.New(context.Background(), dispatcher.dispatch, taskrunner.Options{})
	if err != nil {
		t.Fatalf("taskrunner.New() error = %v", err)
	}
	diagnose := screens.NewDiagnose(localization.English{}, screens.DiagnoseActions{})
	controller := &controller{
		content:       container.NewStack(),
		diagnose:      diagnose,
		currentScreen: "history",
		texts:         localization.English{},
	}
	coordinator := &DiagnoseCoordinator{
		observer: controller.observeDiagnosis,
		config:   application.DefaultConfig(),
		state:    DiagnoseViewModel{State: taskrunner.StateIdle},
	}
	scope, err := taskrunner.NewScope(runner, "diagnose", coordinator.observe)
	if err != nil {
		t.Fatalf("taskrunner.NewScope() error = %v", err)
	}
	coordinator.scope = scope
	controller.diagnoseCoordinator = coordinator
	started := make(chan struct{})
	if _, err := scope.StartRead(func(ctx context.Context) (model.Diagnosis, error) {
		close(started)
		<-ctx.Done()
		return model.Diagnosis{}, ctx.Err()
	}); err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("diagnostic test task did not start")
	}

	controller.presentHistoricalDiagnosis(model.Diagnosis{
		Target: model.Target{
			Original:    "https://history.example",
			DisplayHost: "history.example",
		},
		Options: model.DefaultDiagnoseOptions("https://history.example"),
		Summary: model.Summary{
			Status: model.StatusFailed,
			Title:  "Historical TLS failure",
		},
	})
	runner.Wait()
	dispatcher.drain()
	runner.Close()

	labels := make([]string, 0)
	for _, object := range test.LaidOutObjects(diagnose.Root) {
		if label, ok := object.(*widget.Label); ok {
			labels = append(labels, label.Text)
		}
	}
	joined := strings.Join(labels, "\n")
	if !strings.Contains(joined, "Historical TLS failure") {
		t.Fatalf("historical result was overwritten after queued delivery:\n%s", joined)
	}
	if strings.Contains(joined, "Diagnostics cancelled") {
		t.Fatalf("stale cancellation was presented over history:\n%s", joined)
	}
}

type queuedTestDispatcher struct {
	mu        sync.Mutex
	callbacks []func()
}

func (dispatcher *queuedTestDispatcher) dispatch(callback func()) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.callbacks = append(dispatcher.callbacks, callback)
}

func (dispatcher *queuedTestDispatcher) drain() {
	for {
		dispatcher.mu.Lock()
		if len(dispatcher.callbacks) == 0 {
			dispatcher.mu.Unlock()
			return
		}
		callbacks := dispatcher.callbacks
		dispatcher.callbacks = nil
		dispatcher.mu.Unlock()
		for _, callback := range callbacks {
			callback()
		}
	}
}

func activeDiagnosticTask(
	t *testing.T,
) (*taskrunner.Runner, *DiagnoseCoordinator, taskrunner.OperationID, <-chan struct{}) {
	t.Helper()
	runner, err := taskrunner.New(
		context.Background(),
		func(callback func()) { callback() },
		taskrunner.Options{},
	)
	if err != nil {
		t.Fatalf("taskrunner.New() error = %v", err)
	}
	scope, err := taskrunner.NewScope[model.Diagnosis](runner, "diagnose", nil)
	if err != nil {
		t.Fatalf("taskrunner.NewScope() error = %v", err)
	}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	operationID, err := scope.StartRead(func(ctx context.Context) (model.Diagnosis, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return model.Diagnosis{}, ctx.Err()
	})
	if err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("diagnostic test task did not start")
	}
	return runner, &DiagnoseCoordinator{
		scope:  scope,
		config: application.DefaultConfig(),
		state: DiagnoseViewModel{
			OperationID: operationID,
			State:       taskrunner.StateLoading,
		},
	}, operationID, cancelled
}

func TestProfileEditorMethodMappingIncludesOptions(t *testing.T) {
	t.Parallel()

	texts := localization.English{}
	label := profileMethodLabel(texts, "OPTIONS")
	if label != "OPTIONS" {
		t.Fatalf("profileMethodLabel(OPTIONS) = %q", label)
	}
	if got := profileMethodValue(texts, label); got != "OPTIONS" {
		t.Fatalf("profileMethodValue(%q) = %q", label, got)
	}
}
