//go:build wayland

package gui

import (
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/components"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
	"github.com/Naenier/opsdoctor/internal/gui/screens"
)

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
	cancelled := make(chan struct{})
	controller := &controller{
		content:       container.NewStack(),
		diagnose:      diagnose,
		currentScreen: "profiles",
		currentRun:    4,
		activeCancel:  func() { close(cancelled) },
		texts:         localization.English{},
	}

	controller.startProfile(presenter.ProfileView{
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
	if controller.shouldPresent(4) {
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
	cancelled := make(chan struct{})
	controller := &controller{
		content:       container.NewStack(),
		diagnose:      diagnose,
		header:        widget.NewLabel(""),
		currentScreen: "history",
		currentRun:    8,
		activeCancel:  func() { close(cancelled) },
		texts:         localization.English{},
		info:          buildinfo.Info{Version: "1.2.3"},
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
	if controller.shouldPresent(8) {
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
