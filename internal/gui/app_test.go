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
		header: widget.NewLabel(""),
		info:   buildinfo.Info{Version: "1.2.3"},
		texts:  localization.English{},
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
