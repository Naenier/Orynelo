package presenter

import (
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/gui/localization"
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
		"Started: " + localization.FormatTime(localization.English{}, started),
		"Duration: " + localization.FormatDuration(localization.English{}, 1500*time.Millisecond),
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

func TestDiagnosisPreservesEveryRecommendationAndItsOwnEvidence(t *testing.T) {
	t.Parallel()
	value := model.Diagnosis{
		Summary: model.Summary{
			Status:       model.StatusFailed,
			EvidenceRefs: []string{"dns.fact"},
			Recommendations: []model.Recommendation{{
				ID: "summary.next_step", CheckID: "dns", Priority: "high", Message: "Fix DNS.",
			}},
		},
		Checks: []model.CheckResult{
			{
				ID: "dns", Evidence: []model.Evidence{{ID: "dns.fact"}, {ID: "dns.extra"}},
				Recommendations: []model.Recommendation{{ID: "dns.retry", Priority: "medium", Message: "Retry DNS."}},
			},
			{
				ID: "tls", Evidence: []model.Evidence{{ID: "tls.fact"}},
				Recommendations: []model.Recommendation{{ID: "tls.fix", Priority: "low", Message: "Fix TLS."}},
			},
		},
	}
	got := Diagnosis(localization.English{}, value)
	if len(got.Recommendations) != 3 {
		t.Fatalf("recommendations = %#v", got.Recommendations)
	}
	if strings.Join(got.Recommendations[0].EvidenceIDs, ",") != "dns.fact" {
		t.Fatalf("summary evidence = %#v, want only dns.fact", got.Recommendations[0].EvidenceIDs)
	}
	if strings.Join(got.Recommendations[1].EvidenceIDs, ",") != "dns.fact,dns.extra" {
		t.Fatalf("DNS evidence = %#v", got.Recommendations[1].EvidenceIDs)
	}
}

func TestDiagnosisBreakPointUsesPrimaryConclusionEvidence(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	value := model.Diagnosis{
		Summary: model.Summary{Status: model.StatusFailed, EvidenceRefs: []string{"tls.failure"}},
		Checks: []model.CheckResult{{
			ID: "tls", Evidence: []model.Evidence{{
				ID: "tls.failure", NetworkRef: &model.NetworkRef{PathID: "path-1", HopID: "origin", AttemptID: "tls-1"},
			}},
		}},
		NetworkPaths: []model.NetworkPath{{
			ID: "path-1", Role: model.NetworkPathRoleClientEffective, Kind: model.NetworkPathDirect,
			Hops: []model.NetworkHop{{
				ID: "origin", Host: "example.test",
				Attempts: []model.NetworkAttempt{
					{ID: "tcp-1", Kind: model.NetworkAttemptTCP, ErrorCode: "TCP_TIMEOUT"},
					{ID: "tls-1", Kind: model.NetworkAttemptTLS, ErrorCode: "TLS_EXPIRED"},
				},
				Timings: []model.PhaseTiming{{
					NetworkRef: model.NetworkRef{AttemptID: "tls-1"}, Phase: "tls",
					StartedAt: started, FinishedAt: started.Add(2 * time.Second), Duration: 99 * time.Second,
				}},
			}},
		}},
	}
	got := Diagnosis(localization.English{}, value)
	if got.BreakPoint != "example.test · TLS" {
		t.Fatalf("BreakPoint = %q", got.BreakPoint)
	}
	if len(got.Timing) != 1 || got.Timing[0].Duration != 2*time.Second {
		t.Fatalf("Timing = %#v, want timestamp-derived two seconds", got.Timing)
	}
}

func TestDiagnosisLocalizesStableDomainMessagesWithLegacyFallback(t *testing.T) {
	t.Parallel()
	translated := Diagnosis(localization.Russian{}, model.Diagnosis{
		Summary: model.Summary{
			Status:      model.StatusFailed,
			Title:       "TLS certificate expired",
			Description: "The TLS certificate has expired.",
		},
		Checks: []model.CheckResult{{
			ID: "tls", Name: "TLS handshake and certificate", Status: model.StatusFailed,
			Summary: "The TLS certificate has expired.",
		}},
	})
	if translated.SummaryTitle != "Срок действия сертификата TLS истёк" ||
		translated.Checks[0].Name != "Рукопожатие TLS и сертификат" {
		t.Fatalf("localized diagnosis = %#v", translated)
	}
	legacy := localizedDomainText(localization.Russian{}, "", "Legacy English snapshot text")
	if legacy != "Legacy English snapshot text" {
		t.Fatalf("legacy fallback = %q", legacy)
	}
	byID := localizedDomainText(
		localization.Russian{},
		"http.verify_request",
		"text intentionally differs from the current English copy",
	)
	if !strings.Contains(byID, "Проверьте URL") {
		t.Fatalf("message-ID translation = %q", byID)
	}
}
