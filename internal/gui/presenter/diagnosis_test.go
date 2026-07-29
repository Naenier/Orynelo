package presenter

import (
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

func TestProfilePreservesDiagnosticMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []model.DiagnosticMode{
		model.DiagnosticModeAuto,
		model.DiagnosticModeTCP,
		model.DiagnosticModeTLS,
	} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			got := Profile(model.Profile{Mode: mode})
			if got.Mode != string(mode) {
				t.Fatalf("Profile().Mode = %q, want %q", got.Mode, mode)
			}
		})
	}
}

func TestProfileResetsRunOnlyOptions(t *testing.T) {
	t.Parallel()

	got := Profile(model.Profile{})
	if got.Insecure {
		t.Fatal("stored profile preserved insecure TLS")
	}
	if got.Verbosity != string(model.ReportVerbosityNormal) {
		t.Fatalf("stored profile verbosity = %q, want normal", got.Verbosity)
	}
}

func TestDiagnosisUsesLongestCheckForStageTiming(t *testing.T) {
	t.Parallel()

	got := Diagnosis(localization.English{}, model.Diagnosis{
		Duration: 10 * time.Second,
		Checks: []model.CheckResult{
			{ID: "tcp.ipv4", Duration: 2 * time.Second},
			{ID: "tcp.ipv6", Duration: 3 * time.Second},
		},
	})
	if got.Timing[1].Name != "TCP" || got.Timing[1].Duration != 3*time.Second {
		t.Fatalf("TCP timing = %#v, want longest parallel check", got.Timing[1])
	}
	if got.Timing[4].Name != "Total" || got.Timing[4].Duration != 10*time.Second {
		t.Fatalf("Total timing = %#v", got.Timing[4])
	}
	if !got.Timing[1].Measured || !got.Timing[4].Measured {
		t.Fatalf("measured timing flags = %#v", got.Timing)
	}
}

func TestDiagnosisMarksSkippedTimingAndPresentsSummaryRecommendation(t *testing.T) {
	t.Parallel()

	got := Diagnosis(localization.English{}, model.Diagnosis{
		Duration: time.Second,
		Checks: []model.CheckResult{
			{
				ID:       "tls",
				Status:   model.StatusSkipped,
				Duration: time.Millisecond,
			},
		},
		Summary: model.Summary{
			Recommendations: []model.Recommendation{{
				Message: "Verify DNS first.",
			}},
		},
	})
	if got.Timing[2].Measured {
		t.Fatalf("skipped TLS timing marked measured: %#v", got.Timing[2])
	}
	if len(got.SummaryRecommendations) != 1 ||
		got.SummaryRecommendations[0] != "Verify DNS first." {
		t.Fatalf(
			"summary recommendations = %#v",
			got.SummaryRecommendations,
		)
	}
}

func TestCheckSeparatesTechnicalDetailsAndRawData(t *testing.T) {
	t.Parallel()

	got := Check(localization.English{}, model.CheckResult{
		ID:        "tcp",
		Name:      "TCP connection",
		Status:    model.StatusFailed,
		ErrorCode: "TCP_TIMEOUT",
	})
	if !strings.Contains(got.Technical, "Error code: TCP_TIMEOUT") {
		t.Fatalf("Technical = %q", got.Technical)
	}
	if !strings.Contains(got.RawStructured, `"errorCode": "TCP_TIMEOUT"`) {
		t.Fatalf("RawStructured = %q", got.RawStructured)
	}
	if strings.HasPrefix(strings.TrimSpace(got.Technical), "{") {
		t.Fatalf("Technical contains raw JSON: %q", got.Technical)
	}
}

func TestCheckDetailsTextIncludesEveryVisibleSection(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, time.July, 28, 12, 30, 0, 0, time.UTC)
	got := CheckDetailsText(localization.English{}, CheckView{
		Name:            "TCP connection",
		Status:          "failed",
		StartedAt:       started,
		FinishedAt:      started.Add(1500 * time.Millisecond),
		Duration:        1500 * time.Millisecond,
		Summary:         "The host refused the connection.",
		Evidence:        []string{"dial tcp: connection refused"},
		Recommendations: []string{"Verify that the service is listening."},
		Technical:       "Error code: TCP_REFUSED",
		RawStructured:   `{"status":"failed"}`,
	})

	for _, expected := range []string{
		"TCP connection",
		"Status: FAILED",
		"Started: " + started.Local().Format(time.RFC3339),
		"Duration: 1.5s",
		"Summary\nThe host refused the connection.",
		"Evidence\n• dial tcp: connection refused",
		"Recommendations\n• Verify that the service is listening.",
		"Technical details\nError code: TCP_REFUSED",
		"Raw structured data\n{\"status\":\"failed\"}",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("CheckDetailsText() missing %q:\n%s", expected, got)
		}
	}
}
