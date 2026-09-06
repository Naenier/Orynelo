package presenter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/gui/localization"
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
	if actual := networkTiming(texts, value.NetworkPaths); len(actual) > 0 {
		orderedTiming = actual
	}
	recommendations := diagnosisRecommendations(texts, value)
	summaryRecommendations := make([]string, 0, len(recommendations))
	for _, recommendation := range recommendations {
		summaryRecommendations = append(summaryRecommendations, recommendation.Message)
	}
	paths, primaryPath, breakPoint := diagnosisPaths(texts, value)
	return DiagnosisView{
		ID:                     value.ID,
		Target:                 value.Target.Normalized,
		SummaryTitle:           localizedDomainText(texts, "summary.title", value.Summary.Title),
		SummaryDetail:          localizedDomainText(texts, "summary.description", value.Summary.Description),
		SummaryRecommendations: summaryRecommendations,
		Recommendations:        recommendations,
		Paths:                  paths,
		PrimaryPath:            primaryPath,
		BreakPoint:             breakPoint,
		StartedAt:              value.StartedAt,
		FinishedAt:             value.FinishedAt,
		Version:                value.Build.Version,
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
		line := localizedDomainText(texts, item.Code, item.Message)
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
	recommendationItems := make([]RecommendationView, 0, len(value.Recommendations))
	for _, recommendation := range value.Recommendations {
		message := localizedDomainText(texts, recommendation.ID, recommendation.Message)
		recommendations = append(recommendations, message)
		recommendationItems = append(recommendationItems, recommendationView(texts, recommendation, evidenceIDs(value.Evidence)))
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
		ID:                  value.ID,
		Name:                localizedCheckName(texts, value.ID, value.Name),
		Status:              string(value.Status),
		Summary:             localizedDomainText(texts, value.ErrorCode, value.Summary),
		StartedAt:           value.StartedAt,
		FinishedAt:          value.FinishedAt,
		Duration:            value.Duration,
		Evidence:            evidence,
		Recommendations:     recommendations,
		EvidenceGroups:      evidenceGroups(texts, value.Evidence),
		RecommendationItems: recommendationItems,
		Technical:           strings.Join(technical, "\n"),
		RawStructured:       string(structured),
	}
}

func evidenceGroups(texts localization.Catalog, values []model.Evidence) []EvidenceGroupView {
	groups := make([]EvidenceGroupView, 0)
	indexes := make(map[string]int)
	for _, evidence := range values {
		pathID, hopID, attemptID := "", "", ""
		if evidence.NetworkRef != nil {
			pathID, hopID, attemptID = evidence.NetworkRef.PathID, evidence.NetworkRef.HopID, evidence.NetworkRef.AttemptID
		}
		key := pathID + "\x00" + hopID + "\x00" + attemptID
		index, ok := indexes[key]
		if !ok {
			index = len(groups)
			indexes[key] = index
			groups = append(groups, EvidenceGroupView{PathID: pathID, HopID: hopID, AttemptID: attemptID})
		}
		keys := make([]string, 0, len(evidence.Details))
		for key := range evidence.Details {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		item := EvidenceItemView{ID: evidence.ID, Code: evidence.Code, Message: localizedDomainText(texts, evidence.Code, evidence.Message)}
		for _, key := range keys {
			full := evidence.Details[key]
			lower := strings.ToLower(key)
			kind := "text"
			switch {
			case strings.Contains(lower, "duration"), strings.Contains(lower, "latency"), strings.Contains(lower, "ttfb"):
				kind = "duration"
			case strings.Contains(lower, "time"), strings.Contains(lower, "date"), strings.HasSuffix(lower, "at"):
				kind = "time"
			case strings.Contains(lower, "ip"), strings.Contains(lower, "address"):
				kind = "address"
			case strings.Contains(lower, "certificate"), strings.Contains(lower, "issuer"), strings.Contains(lower, "subject"):
				kind = "certificate"
			case strings.Contains(lower, "header"):
				kind = "header"
			}
			display := formatEvidenceDisplay(texts, kind, full)
			collapsed := len([]rune(display)) > 160
			if collapsed {
				display = string([]rune(display)[:157]) + "…"
			}
			redacted := strings.Contains(full, "[REDACTED]") || strings.Contains(full, "<redacted>")
			item.Values = append(item.Values, EvidenceValueView{Key: key, Display: display, Full: full, Kind: kind, Redacted: redacted, Collapsed: collapsed})
		}
		groups[index].Items = append(groups[index].Items, item)
	}
	return groups
}

func formatEvidenceDisplay(texts localization.Catalog, kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "duration":
		if duration, err := time.ParseDuration(value); err == nil {
			return localization.FormatDuration(texts, duration)
		}
	case "time":
		if timestamp, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return localization.FormatTime(texts, timestamp)
		}
	}
	return value
}

func evidenceIDs(values []model.Evidence) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		if value.ID != "" {
			ids = append(ids, value.ID)
		}
	}
	return ids
}

func recommendationView(texts localization.Catalog, value model.Recommendation, refs []string) RecommendationView {
	return RecommendationView{ID: value.ID, Priority: value.Priority, Message: localizedDomainText(texts, value.ID, value.Message), CheckID: value.CheckID, EvidenceIDs: append([]string(nil), refs...)}
}

func diagnosisRecommendations(texts localization.Catalog, value model.Diagnosis) []RecommendationView {
	result := make([]RecommendationView, 0)
	seen := make(map[string]struct{})
	appendRecommendation := func(recommendation model.Recommendation, refs []string) {
		key := recommendation.ID + "\x00" + recommendation.CheckID + "\x00" + recommendation.Message
		if _, ok := seen[key]; ok || strings.TrimSpace(recommendation.Message) == "" {
			return
		}
		seen[key] = struct{}{}
		result = append(result, recommendationView(texts, recommendation, refs))
	}
	for _, recommendation := range value.Summary.Recommendations {
		refs := value.Summary.EvidenceRefs
		if recommendation.CheckID != "" {
			refs = referencedEvidenceForCheck(value, recommendation.CheckID, refs)
		}
		appendRecommendation(recommendation, refs)
	}
	for _, check := range value.Checks {
		refs := evidenceIDs(check.Evidence)
		for _, recommendation := range check.Recommendations {
			appendRecommendation(recommendation, refs)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return priorityRank(result[i].Priority) < priorityRank(result[j].Priority) })
	return result
}

func priorityRank(priority string) int {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "critical", "high":
		return 0
	case "medium", "normal":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func diagnosisPaths(texts localization.Catalog, value model.Diagnosis) ([]PathView, string, string) {
	paths := make([]PathView, 0, len(value.NetworkPaths))
	primary, broken := "", ""
	summaryRefs := make(map[string]struct{}, len(value.Summary.EvidenceRefs))
	for _, reference := range value.Summary.EvidenceRefs {
		summaryRefs[reference] = struct{}{}
	}
	summaryAttempts := make(map[string]struct{})
	for _, check := range value.Checks {
		for _, evidence := range check.Evidence {
			if _, ok := summaryRefs[evidence.ID]; ok && evidence.NetworkRef != nil && evidence.NetworkRef.AttemptID != "" {
				summaryAttempts[evidence.NetworkRef.AttemptID] = struct{}{}
			}
		}
	}
	for _, path := range value.NetworkPaths {
		view := PathView{ID: path.ID, Role: string(path.Role), Kind: string(path.Kind), Sequence: path.Sequence}
		view.Label = localizedPathRole(texts, path.Role) + " · " + localizedPathKind(texts, path.Kind)
		for _, hop := range path.Hops {
			label := strings.TrimSpace(hop.Host)
			if label == "" {
				label = strings.TrimSpace(hop.RemoteAddr)
			}
			if label == "" {
				label = localizedHopKind(texts, hop.Kind)
			}
			hopView := HopView{ID: hop.ID, Label: label, Reused: hop.Reused}
			for _, attempt := range hop.Attempts {
				hopView.Attempts = append(hopView.Attempts, AttemptView{ID: attempt.ID, Kind: string(attempt.Kind), State: string(attempt.State), StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt, Duration: attempt.Duration, Reused: attempt.Reused})
				_, supportsSummary := summaryAttempts[attempt.ID]
				if broken == "" && path.Role == model.NetworkPathRoleClientEffective &&
					attempt.ErrorCode != "" && (len(summaryAttempts) == 0 || supportsSummary) {
					broken = label + " · " + localizedAttemptKind(texts, attempt.Kind)
				}
			}
			view.Hops = append(view.Hops, hopView)
		}
		if primary == "" && path.Role == model.NetworkPathRoleClientEffective {
			primary = view.Label
		}
		paths = append(paths, view)
	}
	if broken == "" {
		broken = fallbackBreakPoint(value)
	}
	return paths, primary, broken
}

func networkTiming(texts localization.Catalog, paths []model.NetworkPath) []TimingView {
	result := make([]TimingView, 0)
	for _, path := range paths {
		for _, hop := range path.Hops {
			for _, timing := range hop.Timings {
				if timing.StartedAt.IsZero() || timing.FinishedAt.IsZero() {
					continue
				}
				duration := timing.FinishedAt.Sub(timing.StartedAt)
				result = append(result, TimingView{Name: localizedTimingPhase(texts, timing.Phase), Duration: duration, Measured: true, StartedAt: timing.StartedAt, FinishedAt: timing.FinishedAt, AttemptID: timing.AttemptID, Reused: hop.Reused})
			}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].AttemptID < result[j].AttemptID
		}
		return result[i].StartedAt.Before(result[j].StartedAt)
	})
	return result
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

// DiagnosisSummaryText creates a standalone clipboard summary containing the
// target, timestamps, status, observed path, main reason, every action, and
// producing application version.
func DiagnosisSummaryText(texts localization.Catalog, value DiagnosisView) string {
	texts = localization.Normalize(texts)
	version := strings.TrimSpace(value.Version)
	if version == "" {
		version = texts.Text(localization.CommonUnavailable)
	}
	lines := []string{
		texts.Text(localization.AppName) + " " + version,
		fmt.Sprintf(texts.Text(localization.DiagnoseTargetFormat), value.Target),
		fmt.Sprintf(texts.Text(localization.TechnicalStatusFormat), texts.Text(localization.StatusKey(value.OverallStatus))),
		fmt.Sprintf(texts.Text(localization.DiagnoseStartedFormat), formatDetailTime(texts, value.StartedAt)),
		fmt.Sprintf(texts.Text(localization.DiagnoseFinishedFormat), formatDetailTime(texts, value.FinishedAt)),
	}
	if value.PrimaryPath != "" {
		lines = append(lines, fmt.Sprintf(texts.Text(localization.DiagnoseActualPathFormat), value.PrimaryPath))
	}
	if value.BreakPoint != "" {
		lines = append(lines, fmt.Sprintf(texts.Text(localization.DiagnoseBreakPointFormat), value.BreakPoint))
	}
	lines = append(lines, "", value.SummaryTitle, value.SummaryDetail)
	if len(value.Recommendations) > 0 {
		lines = append(lines, "", texts.Text(localization.DiagnoseRecommendations))
		for _, recommendation := range value.Recommendations {
			prefix := localization.PriorityLabel(texts, recommendation.Priority)
			if prefix != "" {
				prefix += " · "
			}
			lines = append(lines, fmt.Sprintf(texts.Text(localization.CommonListItemFormat), prefix+recommendation.Message))
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// formatDetailTime renders a timestamp for clipboard-oriented check details.
func formatDetailTime(texts localization.Catalog, value time.Time) string {
	return localization.FormatTime(texts, value)
}

// formatDetailDuration renders a duration for clipboard-oriented check details.
func formatDetailDuration(texts localization.Catalog, value time.Duration) string {
	return localization.FormatDuration(texts, value)
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
