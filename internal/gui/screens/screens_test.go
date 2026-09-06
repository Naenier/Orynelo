package screens

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/components"
	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/gui/presenter"
)

type overrideCatalog map[localization.Key]string

func (catalog overrideCatalog) Text(key localization.Key) string {
	if value, ok := catalog[key]; ok {
		return value
	}
	return localization.English{}.Text(key)
}

func TestDiagnoseUsesCatalogWithoutChangingDomainValues(t *testing.T) {
	test.NewTempApp(t)
	texts := overrideCatalog{
		localization.DiagnoseTargetPlaceholder: "destination",
		localization.DiagnoseRun:               "Execute checks",
		localization.OptionAuto:                "Automatic",
		localization.OptionTCP:                 "Transport",
		localization.OptionIPv6:                "Only v6",
		localization.OptionVerbose:             "Detailed",
		localization.OptionOPTIONS:             "Discover",
	}
	screen := NewDiagnose(texts, DiagnoseActions{})

	if screen.target.PlaceHolder != "destination" {
		t.Fatalf("target placeholder = %q", screen.target.PlaceHolder)
	}
	if screen.run.Text != "Execute checks" {
		t.Fatalf("run label = %q", screen.run.Text)
	}

	screen.target.SetText("example.test")
	screen.mode.SetSelected("Transport")
	screen.ipVersion.SetSelected("Only v6")
	screen.verbosity.SetSelected("Detailed")
	screen.method.SetSelected("Discover")
	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Mode != "tcp" || input.IPVersion != "6" ||
		input.Verbosity != "verbose" || input.Method != "" {
		t.Fatalf("localized selections produced %#v", input)
	}
}

func TestDiagnoseStageThreeControlsProduceRuntimeInput(t *testing.T) {
	test.NewTempApp(t)
	texts := localization.English{}
	screen := NewDiagnose(texts, DiagnoseActions{})
	screen.target.SetText("example.test:8443")
	screen.mode.SetSelected(texts.Text(localization.OptionTLS))
	screen.probeMode.SetSelected(texts.Text(localization.OptionAddressMatrix))
	screen.addressLimit.SetText("6")
	screen.matrixBudget.SetText("3s")
	screen.expectedStatus.SetText("201-204")
	screen.latencyThreshold.SetText("750ms")
	screen.connectIP.SetText("192.0.2.44")
	screen.serverName.SetText("node.example.test")
	screen.httpHost.SetText("service.example.test:8443")
	screen.caBundle.SetText("/runtime/private/ca.pem")
	screen.requestHeaders.SetText(
		"Authorization: Bearer gui-one-time-secret\nX-Incident: INC-42",
	)
	screen.collectDNSDetails.SetChecked(true)
	screen.inspectBody.SetChecked(true)

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Mode != "tls" || input.ProbeMode != "address_matrix" ||
		input.AddressLimit != 6 || input.AddressMatrixBudget != 3*time.Second ||
		input.ExpectedStatusSet || input.ExpectedStatusMin != 0 ||
		input.ExpectedStatusMax != 0 || input.LatencyThreshold != 750*time.Millisecond ||
		input.ConnectIP != "192.0.2.44" || input.ServerName != "node.example.test" ||
		input.HTTPHost != "" ||
		input.CustomCABundlePath != "/runtime/private/ca.pem" ||
		len(input.RequestHeaders) != 0 || !input.CollectDNSDetails || input.InspectBody {
		t.Fatalf("Input() = %#v", input)
	}
}

func TestDiagnoseTargetPreviewNeverShowsCredentialsOrSecretQueryValues(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.target.SetText(
		"https://preview-user:preview-password@example.test/private?token=preview-token&view=full",
	)

	preview := screen.targetPreview.Text
	for _, secret := range []string{"preview-user", "preview-password", "preview-token"} {
		if strings.Contains(preview, secret) {
			t.Fatalf("target preview exposed %q: %q", secret, preview)
		}
	}
	if !strings.Contains(preview, "https://example.test:443/private") ||
		!strings.Contains(preview, "token=[REDACTED]") ||
		!strings.Contains(preview, "view=full") {
		t.Fatalf("target preview lost safe effective context: %q", preview)
	}
}

func TestDiagnoseContextHidesIrrelevantProtocolControls(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.setAdvancedExpanded(true)

	screen.target.SetText("tcp://example.test:443")
	if screen.tlsFields.Visible() || screen.httpFields.Visible() || !screen.transportFields.Visible() {
		t.Fatal("TCP context exposes TLS/HTTP controls or hides transport controls")
	}

	screen.target.SetText("tls://example.test:443")
	if !screen.tlsFields.Visible() || screen.httpFields.Visible() {
		t.Fatal("TLS context does not expose exactly its protocol controls")
	}

	screen.target.SetText("https://example.test")
	if !screen.tlsFields.Visible() || !screen.httpFields.Visible() {
		t.Fatal("HTTPS context does not expose TLS and HTTP controls")
	}
}

func TestDiagnosePersistsOnlyNonSensitiveUIState(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.target.SetText("https://secret-user:secret-password@example.test/?token=secret")
	screen.ApplyUIState(DiagnoseUIState{
		AdvancedExpanded: true,
		ResultSplit:      0.37,
		ExplorerSplit:    0.61,
	})
	state := screen.UIState()
	if !state.AdvancedExpanded || state.ResultSplit != 0.37 || state.ExplorerSplit != 0.61 {
		t.Fatalf("UIState() = %#v", state)
	}
	serialized := fmt.Sprintf("%#v", state)
	for _, secret := range []string{"secret-user", "secret-password", "token"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("layout state exposed %q: %s", secret, serialized)
		}
	}
}

func TestDiagnoseStageThreeControlsRejectInvalidValuesWithoutEchoingSecrets(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*DiagnoseScreen)
		secret    string
	}{
		{name: "address limit", configure: func(screen *DiagnoseScreen) {
			screen.addressLimit.SetText("17")
		}},
		{name: "matrix budget", configure: func(screen *DiagnoseScreen) {
			screen.matrixBudget.SetText("0s")
		}},
		{name: "status range", configure: func(screen *DiagnoseScreen) {
			screen.expectedStatus.SetText("500-200")
		}},
		{name: "latency", configure: func(screen *DiagnoseScreen) {
			screen.latencyThreshold.SetText("0s")
		}},
		{name: "header injection", secret: "gui-header-secret", configure: func(screen *DiagnoseScreen) {
			screen.requestHeaders.SetText("gui-header-secret-without-colon")
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			test.NewTempApp(t)
			screen := NewDiagnose(localization.English{}, DiagnoseActions{})
			screen.target.SetText("https://example.test")
			testCase.configure(screen)
			_, err := screen.Input()
			if err == nil {
				t.Fatal("Input() error = nil")
			}
			if testCase.secret != "" && strings.Contains(err.Error(), testCase.secret) {
				t.Fatalf("Input() error exposed transient value: %v", err)
			}
		})
	}
}

func TestSetProfileResetsUnsafeRunOnlyControls(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.insecure.SetChecked(true)
	screen.allowInsecureRedirects.SetChecked(true)
	screen.allowPrivateRedirects.SetChecked(true)
	screen.verbosity.SetSelected("Verbose")
	screen.probeMode.SetSelected(localization.English{}.Text(localization.OptionAddressMatrix))
	screen.addressLimit.SetText("8")
	screen.matrixBudget.SetText("9s")
	screen.expectedStatus.SetText("204")
	screen.latencyThreshold.SetText("500ms")
	screen.connectIP.SetText("192.0.2.44")
	screen.serverName.SetText("node.example.test")
	screen.httpHost.SetText("service.example.test")
	screen.caBundle.SetText("/runtime/private/ca.pem")
	screen.requestHeaders.SetText("Authorization: Bearer profile-secret")
	screen.collectDNSDetails.SetChecked(true)
	screen.inspectBody.SetChecked(true)

	screen.SetProfile(presenter.ProfileView{
		Target:       "example.test:443",
		Mode:         "tcp",
		IPVersion:    "auto",
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "GET",
	})

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Insecure {
		t.Fatal("stored profile inherited insecure TLS")
	}
	if input.AllowInsecureRedirects || input.AllowPrivateRedirects {
		t.Fatal("stored profile inherited unsafe redirect opt-ins")
	}
	if input.Verbosity != "normal" {
		t.Fatalf("stored profile verbosity = %q, want normal", input.Verbosity)
	}
	if input.ProbeMode != "client_effective" || input.AddressLimit != 4 ||
		input.AddressMatrixBudget != 5*time.Second || input.ExpectedStatusSet ||
		input.LatencyThreshold != 0 || input.ConnectIP != "" || input.ServerName != "" ||
		input.HTTPHost != "" || input.CustomCABundlePath != "" ||
		len(input.RequestHeaders) != 0 || input.CollectDNSDetails || input.InspectBody {
		t.Fatalf("stored profile retained run-only Stage 3 values: %#v", input)
	}
}

func TestDiagnoseRedirectPolicyControlsAreExplicit(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.target.SetText("https://example.test")
	screen.allowInsecureRedirects.SetChecked(true)
	screen.allowPrivateRedirects.SetChecked(true)

	input, err := screen.Input()
	if err != nil {
		t.Fatal(err)
	}
	if !input.AllowInsecureRedirects || !input.AllowPrivateRedirects {
		t.Fatalf("input = %#v", input)
	}
	if !strings.Contains(screen.allowInsecureRedirects.Text, "HTTPS to HTTP") ||
		!strings.Contains(screen.allowPrivateRedirects.Text, "private-network") {
		t.Fatalf(
			"unsafe control labels are not explicit: %q / %q",
			screen.allowInsecureRedirects.Text,
			screen.allowPrivateRedirects.Text,
		)
	}
}

func TestDiagnoseValidatesTimeoutRelationshipInline(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.target.SetText("https://example.test")
	screen.timeout.SetText("2s")
	screen.checkTimeout.SetText("3s")

	_, err := screen.Input()
	var typed *FormError
	if !errors.As(err, &typed) || typed.Field != "checkTimeout" {
		t.Fatalf("Input() error = %#v, want checkTimeout FormError", err)
	}
}

func TestDiagnoseValidatesTimeoutLimitInline(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.target.SetText("https://example.test")
	screen.timeout.SetText("25h")

	_, err := screen.Input()
	var typed *FormError
	if !errors.As(err, &typed) || typed.Field != "timeout" {
		t.Fatalf("Input() error = %#v, want timeout FormError", err)
	}
}

func TestHistoryUsesReadableEnglishFilterLabels(t *testing.T) {
	test.NewTempApp(t)
	screen := NewHistory(localization.English{}, HistoryActions{})

	want := []string{"All", "Passed", "Warning", "Failed", "Cancelled"}
	if strings.Join(screen.status.Options, ",") != strings.Join(want, ",") {
		t.Fatalf("status options = %#v, want %#v", screen.status.Options, want)
	}
}

func TestSetProfileRestoresOptionsMethod(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.SetProfile(presenter.ProfileView{
		Target:       "example.test",
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		Method:       "OPTIONS",
	})

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Method != "OPTIONS" {
		t.Fatalf("Input().Method = %q, want OPTIONS", input.Method)
	}
}

func TestTimelineDisplaysShortResult(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.UpsertCheck(presenter.CheckView{
		ID:       "dns",
		Name:     "DNS resolution",
		Status:   "warning",
		Summary:  "No IPv6 addresses were returned.",
		Duration: time.Millisecond,
	})

	item := screen.timeline.CreateItem()
	screen.timeline.UpdateItem(0, item)
	row := item.(*fyne.Container)
	center := row.Objects[0].(*fyne.Container)
	shortResult := center.Objects[1].(*widget.Label)
	if shortResult.Text != "No IPv6 addresses were returned." {
		t.Fatalf("short result = %q", shortResult.Text)
	}
	if shortResult.Truncation != fyne.TextTruncateEllipsis {
		t.Fatalf("short result truncation = %v, want ellipsis", shortResult.Truncation)
	}
}

func TestDiagnoseCancelIsLaidOutAndDuplicateRunIsIgnored(t *testing.T) {
	test.NewTempApp(t)
	runs := 0
	screen := NewDiagnose(localization.English{}, DiagnoseActions{
		Run: func(presenter.DiagnoseInput) {
			runs++
		},
	})
	screen.SetTarget("example.test:443")

	foundCancel := false
	for _, object := range test.LaidOutObjects(screen.Root) {
		if object == screen.cancel {
			foundCancel = true
			break
		}
	}
	if !foundCancel {
		t.Fatal("Cancel button is not part of the Diagnose layout")
	}

	screen.TriggerRun()
	if runs != 1 {
		t.Fatalf("initial runs = %d, want 1", runs)
	}
	screen.SetRunning(true)
	screen.TriggerRun()
	if runs != 1 {
		t.Fatalf("runs while active = %d, want 1", runs)
	}
	if !screen.cancel.Visible() || screen.run.Visible() {
		t.Fatalf(
			"running actions: cancel visible=%v, run visible=%v",
			screen.cancel.Visible(),
			screen.run.Visible(),
		)
	}
	if !screen.activity.Visible() || !screen.activity.Running() {
		t.Fatal("running activity indicator is not active")
	}
	if !screen.target.Disabled() {
		t.Fatal("target remains editable during a run")
	}
}

func TestDiagnoseProgressiveDisclosureAndPrimaryFailureSelection(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})

	if !screen.idleState.Visible() || screen.resultView.Visible() {
		t.Fatal("idle Diagnose state is not the only visible state")
	}

	screen.SetTarget("https://example.test")
	screen.ResetResults()
	screen.SetRunning(true)
	if screen.idleState.Visible() || !screen.resultView.Visible() {
		t.Fatal("running state did not replace the idle state")
	}
	if screen.explorer.Visible() || screen.postActions.Visible() {
		t.Fatal("empty result explorer or post actions are visible while starting")
	}

	screen.UpsertCheck(presenter.CheckView{
		ID:      "target",
		Name:    "Target validation",
		Status:  "passed",
		Summary: "Target parsed.",
	})
	if !screen.explorer.Visible() || screen.selectedCheck != 0 {
		t.Fatal("first streamed check was not opened")
	}

	screen.ShowDiagnosis(presenter.DiagnosisView{
		Target:                 "https://example.test:443",
		SummaryTitle:           "DNS resolution failed",
		SummaryDetail:          "No usable address was returned.",
		SummaryRecommendations: []string{"Verify the hostname and resolver settings."},
		OverallStatus:          "failed",
		Checks: []presenter.CheckView{
			{
				ID:      "target",
				Name:    "Target validation",
				Status:  "passed",
				Summary: "Target parsed.",
			},
			{
				ID:              "dns",
				Name:            "DNS resolution",
				Status:          "failed",
				Summary:         "No usable address was returned.",
				Recommendations: []string{"Verify the hostname."},
			},
		},
		Timing: []presenter.TimingView{
			{Name: "DNS", Duration: time.Millisecond, Measured: true},
			{Name: "Total", Duration: 2 * time.Millisecond, Measured: true, IsTotal: true},
		},
	})

	if screen.selectedCheck != 1 || screen.detailTitle.Text != "DNS resolution" {
		t.Fatalf(
			"selected check = %d (%q), want failed DNS check",
			screen.selectedCheck,
			screen.detailTitle.Text,
		)
	}
	if !screen.summaryNextStep.Visible() ||
		screen.summaryNextText.Text != "Verify the hostname and resolver settings." {
		t.Fatal("summary recommendation is not visible")
	}
	if !screen.timingDisclosure.Visible() ||
		screen.timingDisclosure.Items[0].Open {
		t.Fatal("timing disclosure is not visible and collapsed")
	}
	if !screen.recommendSection.Visible() {
		t.Fatal("selected check recommendations are hidden")
	}
	if !screen.postActions.Visible() || screen.target.Disabled() {
		t.Fatal("completed state did not restore actions and inputs")
	}

	screen.ResetResults()
	if screen.explorer.Visible() || screen.selectedCheck != -1 {
		t.Fatal("reset left the previous result explorer visible")
	}
	if screen.timingDisclosure.Visible() {
		t.Fatal("reset left timing disclosure visible")
	}
	if screen.detailTitle.Text != "Select a diagnostic step" ||
		screen.detailRaw.Text != "" {
		t.Fatal("reset left stale selected-step details")
	}
}

func TestDiagnoseResultKeepsExplorerUsableAtMinimumContentSize(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	checks := make([]presenter.CheckView, 0, 7)
	for index, name := range []string{
		"Target validation",
		"Environment and proxy",
		"DNS resolution",
		"Route and source address",
		"TCP connection",
		"TLS handshake and certificate",
		"HTTP request",
	} {
		checks = append(checks, presenter.CheckView{
			ID:       strconv.Itoa(index),
			Name:     name,
			Status:   "passed",
			Summary:  "The check completed successfully.",
			Duration: time.Duration(index+1) * time.Millisecond,
		})
	}
	screen.ShowDiagnosis(presenter.DiagnosisView{
		Target:        "https://example.test:443",
		SummaryTitle:  "Target is reachable",
		SummaryDetail: "DNS, TCP, TLS, and HTTP completed successfully.",
		OverallStatus: "passed",
		Checks:        checks,
		SummaryRecommendations: []string{
			"Keep the successful result as a baseline.",
		},
		Timing: []presenter.TimingView{
			{Name: "DNS", Duration: time.Millisecond, Measured: true},
			{Name: "TCP", Duration: 2 * time.Millisecond, Measured: true},
			{Name: "TLS", Duration: 3 * time.Millisecond, Measured: true},
			{Name: "TTFB", Duration: 4 * time.Millisecond, Measured: true},
			{Name: "Total", Duration: 10 * time.Millisecond, Measured: true, IsTotal: true},
		},
	})

	screen.Root.Resize(fyne.NewSize(1200, 900))
	screen.setAdvancedExpanded(true)
	screen.timingDisclosure.Open(0)
	test.LaidOutObjects(screen.Root)
	screen.Root.Resize(fyne.NewSize(830, 620))
	test.LaidOutObjects(screen.Root)
	if screen.explorer.Horizontal {
		t.Fatal("narrow Diagnose layout did not switch to a vertical explorer")
	}
	if !screen.postActionsOverflow.Visible() || screen.postActionsWide.Visible() {
		t.Fatal("narrow Diagnose layout did not switch to the overflow action menu")
	}

	minimum := screen.Root.MinSize()
	if minimum.Width > 830 || minimum.Height > 620 {
		t.Fatalf(
			"expanded Diagnose minimum = %.0fx%.0f, want at most 830x620",
			minimum.Width,
			minimum.Height,
		)
	}
	if screen.explorer.Size().Height < 180 {
		t.Fatalf(
			"expanded explorer height = %.0f, want at least 180",
			screen.explorer.Size().Height,
		)
	}
	if screen.inputViewport.Size().Height > 300 {
		t.Fatalf(
			"input viewport height after shrinking = %.0f, want at most 300",
			screen.inputViewport.Size().Height,
		)
	}
	if screen.inputViewport.Offset.Y <= 0 {
		t.Fatal("expanded input did not preserve its advanced-fields scroll position")
	}
	if screen.timelineCard.Size().Width < 280 ||
		screen.detailsCard.Size().Width < 400 {
		t.Fatalf(
			"explorer widths = %.0f/%.0f, want readable panes",
			screen.timelineCard.Size().Width,
			screen.detailsCard.Size().Width,
		)
	}
	if screen.postActions.Position().X+screen.postActions.Size().Width >
		screen.Root.Size().Width+1 {
		t.Fatal("post-diagnosis actions overflow the Diagnose content width")
	}
	if screen.explorer.Size().Width > screen.Root.Size().Width+1 {
		t.Fatal("result explorer overflows the Diagnose content width")
	}
	if screen.detailsCard.Position().X+screen.detailsCard.Size().Width >
		screen.explorer.Size().Width+1 {
		t.Fatal("selected-step pane is clipped by the result explorer")
	}
}

func TestDiagnoseErrorDoesNotMixWithPreviousCompletedResult(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.ShowDiagnosis(presenter.DiagnosisView{
		Target:        "example.test:443",
		SummaryTitle:  "Target is reachable",
		SummaryDetail: "Connection succeeded.",
		OverallStatus: "passed",
		Checks: []presenter.CheckView{{
			ID:      "tcp",
			Name:    "TCP connection",
			Status:  "passed",
			Summary: "Connection succeeded.",
		}},
	})

	screen.ShowError("target could not be parsed", false)

	if len(screen.checks) != 0 || screen.explorer.Visible() {
		t.Fatal("input error retained checks from the previous diagnosis")
	}
	if screen.postActions.Visible() || screen.timingDisclosure.Visible() {
		t.Fatal("input error retained completed-result actions")
	}
	if screen.summaryTitle.Text != "Diagnostics could not be completed" {
		t.Fatalf("error title = %q", screen.summaryTitle.Text)
	}
}

func TestDiagnoseTimingDisclosureRequiresMeasuredStage(t *testing.T) {
	tests := []struct {
		name    string
		timing  []presenter.TimingView
		visible bool
	}{
		{name: "no timing"},
		{
			name: "total only",
			timing: []presenter.TimingView{{
				Name:     "Total",
				Duration: time.Millisecond,
				Measured: true,
				IsTotal:  true,
			}},
		},
		{
			name: "unmeasured stages",
			timing: []presenter.TimingView{
				{Name: "DNS"},
				{Name: "TCP"},
				{Name: "Total", Duration: time.Millisecond, Measured: true, IsTotal: true},
			},
		},
		{
			name: "measured stage",
			timing: []presenter.TimingView{
				{Name: "DNS", Duration: time.Millisecond, Measured: true},
				{Name: "Total", Duration: time.Millisecond, Measured: true, IsTotal: true},
			},
			visible: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test.NewTempApp(t)
			screen := NewDiagnose(localization.English{}, DiagnoseActions{})
			screen.ShowDiagnosis(presenter.DiagnosisView{
				Target:        "example.test:443",
				SummaryTitle:  "Diagnostics completed",
				SummaryDetail: "Result is available.",
				OverallStatus: "passed",
				Timing:        tt.timing,
			})

			if screen.timingDisclosure.Visible() != tt.visible {
				t.Fatalf(
					"timing disclosure visible = %v, want %v",
					screen.timingDisclosure.Visible(),
					tt.visible,
				)
			}
			if tt.visible && screen.timingDisclosure.Items[0].Open {
				t.Fatal("timing disclosure should initially be collapsed")
			}
		})
	}
}

func TestDiagnoseCancelledRunKeepsPartialChecks(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.SetTarget("example.test:443")
	screen.ResetResults()
	screen.SetRunning(true)
	screen.UpsertCheck(presenter.CheckView{
		ID:      "dns",
		Name:    "DNS resolution",
		Status:  "passed",
		Summary: "Address resolved.",
	})
	screen.UpsertCheck(presenter.CheckView{
		ID:      "tcp",
		Name:    "TCP connection",
		Status:  "cancelled",
		Summary: "Cancelled before completion.",
	})

	screen.ShowError("The diagnostic run was cancelled.", true)

	if len(screen.checks) != 2 || !screen.explorer.Visible() {
		t.Fatal("cancelled run did not retain its partial diagnostic timeline")
	}
	if screen.selectedCheck != 1 || screen.detailTitle.Text != "TCP connection" {
		t.Fatalf(
			"selected partial check = %d (%q), want cancelled TCP check",
			screen.selectedCheck,
			screen.detailTitle.Text,
		)
	}
	if screen.running || screen.activity.Visible() || screen.cancel.Visible() {
		t.Fatal("cancelled run still appears active")
	}
	if !screen.run.Visible() || screen.target.Disabled() {
		t.Fatal("cancelled run did not restore primary inputs")
	}
	if screen.postActions.Visible() || screen.timingDisclosure.Visible() {
		t.Fatal("cancelled run exposed completed-result actions")
	}
}

func TestDiagnoseEmptyResultClearsSelectionBeforeStreamingAgain(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.ShowDiagnosis(presenter.DiagnosisView{
		Target:        "example.test:443",
		SummaryTitle:  "Target is reachable",
		SummaryDetail: "Connection succeeded.",
		OverallStatus: "passed",
		Checks: []presenter.CheckView{{
			ID:      "tcp",
			Name:    "TCP connection",
			Status:  "passed",
			Summary: "Connection succeeded.",
		}},
	})
	screen.ShowDiagnosis(presenter.DiagnosisView{
		Target:        "example.test:443",
		SummaryTitle:  "No checks were run",
		SummaryDetail: "There are no diagnostic steps.",
		OverallStatus: "warning",
	})

	if screen.selectedCheck != -1 || screen.explorer.Visible() {
		t.Fatal("empty diagnosis retained the previous selection")
	}
	if screen.detailTitle.Text != "Select a diagnostic step" {
		t.Fatal("empty diagnosis retained stale selected-step details")
	}

	screen.UpsertCheck(presenter.CheckView{
		ID:      "dns",
		Name:    "DNS resolution",
		Status:  "failed",
		Summary: "No address was returned.",
	})
	if screen.selectedCheck != 0 || screen.detailTitle.Text != "DNS resolution" {
		t.Fatal("first check after an empty result was not selected")
	}
}

func TestHistoryStatusCellUsesAccessibleBadge(t *testing.T) {
	test.NewTempApp(t)
	screen := NewHistory(localization.English{}, HistoryActions{})
	screen.SetRows([]presenter.HistoryView{{
		ID:     "run-1",
		Status: "warning",
	}})

	row := screen.list.CreateItem()
	screen.list.UpdateItem(0, row)
	content := row.(*components.ActionRow).Content.(*fyne.Container)
	badge := content.Objects[2].(*components.StatusBadge)
	if accessible := badge.AccessibilityLabel(); !strings.Contains(accessible, "WARNING") {
		t.Fatalf("AccessibilityLabel() = %q", accessible)
	}
}

func TestSelectedStepSeparatesTechnicalDetailsAndRawData(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.showCheck(presenter.CheckView{
		Name:          "TCP connection",
		Status:        "failed",
		Summary:       "Connection timed out.",
		Technical:     "Error code: TCP_TIMEOUT",
		RawStructured: `{"errorCode":"TCP_TIMEOUT"}`,
	})
	if screen.detailTechnical.Text != "Error code: TCP_TIMEOUT" {
		t.Fatalf("technical details = %q", screen.detailTechnical.Text)
	}
	if screen.detailRaw.Text != `{"errorCode":"TCP_TIMEOUT"}` {
		t.Fatalf("raw data = %q", screen.detailRaw.Text)
	}
}
