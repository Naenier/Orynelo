package presenter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

// Diagnosis converts the domain result to a display-only view.
func Diagnosis(texts localization.Catalog, value model.Diagnosis) DiagnosisView {
	texts = localization.Normalize(texts)
	checks := make([]CheckView, 0, len(value.Checks))
	timings := map[string]time.Duration{
		"DNS":   0,
		"TCP":   0,
		"TLS":   0,
		"TTFB":  0,
		"Total": value.Duration,
	}
	measured := map[string]bool{
		"Total": value.Duration > 0,
	}
	for _, check := range value.Checks {
		checks = append(checks, Check(texts, check))
		lowerID := strings.ToLower(check.ID)
		checkMeasured := check.Status != model.StatusSkipped &&
			check.Status != model.StatusNotApplicable &&
			check.Status != model.StatusCancelled
		switch {
		case strings.Contains(lowerID, "dns"):
			if checkMeasured {
				timings["DNS"] = max(timings["DNS"], check.Duration)
				measured["DNS"] = true
			}
		case strings.Contains(lowerID, "tcp"):
			if checkMeasured {
				timings["TCP"] = max(timings["TCP"], check.Duration)
				measured["TCP"] = true
			}
		case strings.Contains(lowerID, "tls"):
			if checkMeasured {
				timings["TLS"] = max(timings["TLS"], check.Duration)
				measured["TLS"] = true
			}
		case strings.Contains(lowerID, "http"):
			for _, evidence := range check.Evidence {
				for key, raw := range evidence.Details {
					if strings.EqualFold(key, "ttfb") || strings.EqualFold(key, "firstByte") {
						if duration, err := time.ParseDuration(raw); err == nil {
							timings["TTFB"] = duration
							measured["TTFB"] = true
						}
					}
				}
			}
		}
	}
	orderedTiming := make([]TimingView, 0, 5)
	for _, item := range []struct {
		name string
		key  localization.Key
	}{
		{name: "DNS", key: localization.TimingDNS},
		{name: "TCP", key: localization.TimingTCP},
		{name: "TLS", key: localization.TimingTLS},
		{name: "TTFB", key: localization.TimingTTFB},
		{name: "Total", key: localization.TimingTotal},
	} {
		orderedTiming = append(
			orderedTiming,
			TimingView{
				Name:     texts.Text(item.key),
				Duration: timings[item.name],
				Measured: measured[item.name],
				IsTotal:  item.name == "Total",
			},
		)
	}
	summaryRecommendations := make(
		[]string,
		0,
		len(value.Summary.Recommendations),
	)
	for _, recommendation := range value.Summary.Recommendations {
		summaryRecommendations = append(
			summaryRecommendations,
			recommendation.Message,
		)
	}
	return DiagnosisView{
		ID:                     value.ID,
		Target:                 value.Target.Normalized,
		SummaryTitle:           value.Summary.Title,
		SummaryDetail:          value.Summary.Description,
		SummaryRecommendations: summaryRecommendations,
		OverallStatus:          string(value.Summary.Status),
		Checks:                 checks,
		Timing:                 orderedTiming,
	}
}

// Check converts one diagnostic check to a display-only view.
func Check(texts localization.Catalog, value model.CheckResult) CheckView {
	texts = localization.Normalize(texts)
	evidence := make([]string, 0, len(value.Evidence))
	for _, item := range value.Evidence {
		line := item.Message
		if len(item.Details) > 0 {
			keys := make([]string, 0, len(item.Details))
			for key := range item.Details {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			details := make([]string, 0, len(keys))
			for _, key := range keys {
				details = append(details, fmt.Sprintf("%s=%s", key, item.Details[key]))
			}
			line += " (" + strings.Join(details, ", ") + ")"
		}
		evidence = append(evidence, line)
	}
	recommendations := make([]string, 0, len(value.Recommendations))
	for _, recommendation := range value.Recommendations {
		recommendations = append(recommendations, recommendation.Message)
	}
	structured, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		structured, _ = json.Marshal(map[string]string{
			"error": texts.Text(localization.TechnicalJSONEncodingError),
		})
	}
	technical := []string{
		fmt.Sprintf(texts.Text(localization.TechnicalCheckIDFormat), value.ID),
		fmt.Sprintf(
			texts.Text(localization.TechnicalStatusFormat),
			texts.Text(localization.StatusKey(string(value.Status))),
		),
	}
	if value.ErrorCode != "" {
		technical = append(
			technical,
			fmt.Sprintf(texts.Text(localization.TechnicalErrorCodeFormat), value.ErrorCode),
		)
	}
	technical = append(
		technical,
		fmt.Sprintf(texts.Text(localization.TechnicalEvidenceCountFormat), len(value.Evidence)),
		fmt.Sprintf(
			texts.Text(localization.TechnicalRecommendationCountFormat),
			len(value.Recommendations),
		),
	)
	return CheckView{
		ID:              value.ID,
		Name:            value.Name,
		Status:          string(value.Status),
		Summary:         value.Summary,
		StartedAt:       value.StartedAt,
		FinishedAt:      value.FinishedAt,
		Duration:        value.Duration,
		Evidence:        evidence,
		Recommendations: recommendations,
		Technical:       strings.Join(technical, "\n"),
		RawStructured:   string(structured),
	}
}

// CheckDetailsText formats every user-visible detail of a diagnostic step for
// clipboard export.
func CheckDetailsText(texts localization.Catalog, value CheckView) string {
	texts = localization.Normalize(texts)
	name := strings.TrimSpace(value.Name)
	if name == "" {
		name = texts.Text(localization.DiagnoseCheck)
	}
	summary := strings.TrimSpace(value.Summary)
	if summary == "" {
		summary = texts.Text(localization.CommonUnavailable)
	}
	technical := strings.TrimSpace(value.Technical)
	if technical == "" {
		technical = texts.Text(localization.CommonUnavailable)
	}
	raw := strings.TrimSpace(value.RawStructured)
	if raw == "" {
		raw = texts.Text(localization.CommonUnavailable)
	}
	return strings.Join([]string{
		name,
		fmt.Sprintf(
			texts.Text(localization.TechnicalStatusFormat),
			texts.Text(localization.StatusKey(value.Status)),
		),
		fmt.Sprintf(
			texts.Text(localization.DiagnoseTimingFormat),
			formatDetailTime(texts, value.StartedAt),
			formatDetailTime(texts, value.FinishedAt),
			formatDetailDuration(texts, value.Duration),
		),
		texts.Text(localization.DiagnoseSummary) + "\n" + summary,
		texts.Text(localization.DiagnoseEvidence) + "\n" +
			formatDetailList(
				texts,
				value.Evidence,
				localization.DiagnoseNoEvidenceRecorded,
			),
		texts.Text(localization.DiagnoseRecommendations) + "\n" +
			formatDetailList(
				texts,
				value.Recommendations,
				localization.DiagnoseNoRecommendationsRecorded,
			),
		texts.Text(localization.DiagnoseTechnicalDetails) + "\n" + technical,
		texts.Text(localization.DiagnoseRawStructuredData) + "\n" + raw,
	}, "\n\n")
}

// formatDetailTime renders a timestamp for clipboard-oriented check details.
func formatDetailTime(texts localization.Catalog, value time.Time) string {
	if value.IsZero() {
		return texts.Text(localization.CommonUnavailable)
	}
	return value.Local().Format(time.RFC3339)
}

// formatDetailDuration renders a duration for clipboard-oriented check details.
func formatDetailDuration(texts localization.Catalog, value time.Duration) string {
	if value <= 0 {
		return texts.Text(localization.CommonUnavailable)
	}
	if value < time.Second {
		return value.Round(time.Microsecond).String()
	}
	return value.Round(time.Millisecond).String()
}

// formatDetailList appends a labeled list to a check-detail text buffer.
func formatDetailList(
	texts localization.Catalog,
	values []string,
	empty localization.Key,
) string {
	if len(values) == 0 {
		return texts.Text(empty)
	}
	lines := make([]string, 0, len(values))
	for _, value := range values {
		lines = append(
			lines,
			fmt.Sprintf(texts.Text(localization.CommonListItemFormat), value),
		)
	}
	return strings.Join(lines, "\n")
}

// History converts a compact domain history entry.
func History(value model.HistoryEntry) HistoryView {
	return HistoryView{
		ID:       value.ID,
		Date:     value.Date,
		Target:   value.Target,
		Status:   string(value.Status),
		Duration: value.Duration,
		Version:  value.Version,
	}
}

// Profile converts a stored profile to GUI form values.
func Profile(value model.Profile) ProfileView {
	mode := string(value.Mode)
	if mode == "" {
		mode = string(model.DiagnosticModeAuto)
	}
	return ProfileView{
		ID:           value.ID,
		Name:         value.Name,
		Target:       value.Target,
		Mode:         mode,
		IPVersion:    string(value.IPVersion),
		Timeout:      value.Timeout,
		CheckTimeout: value.CheckTimeout,
		NoProxy:      value.NoProxy,
		MaxRedirects: value.MaxRedirects,
		Method:       value.Method,
		Insecure:     false,
		Verbosity:    string(model.ReportVerbosityNormal),
	}
}
