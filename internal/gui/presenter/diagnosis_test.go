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
