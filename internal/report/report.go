// Package report renders diagnoses without terminal assumptions or ANSI color.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

// Format is a supported report encoding.
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// ParseFormat validates a user-facing format name.
func ParseFormat(value string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(value))) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatMarkdown, "md":
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported report format %q", value)
	}
}

// JSONDocument is the versioned JSON envelope.
type JSONDocument struct {
	SchemaVersion string          `json:"schemaVersion"`
	Diagnosis     model.Diagnosis `json:"diagnosis"`
}

// Write streams a report in the requested format.
func Write(
	writer io.Writer,
	diagnosis model.Diagnosis,
	format Format,
	modes ...privacy.Mode,
) error {
	if writer == nil {
		return errors.New("report writer is nil")
	}
	projection, err := projectionFor(modes)
	if err != nil {
		return err
	}
	diagnosis = projection.Diagnosis(diagnosis)
	switch format {
	case FormatText:
		return writeText(writer, diagnosis)
	case FormatJSON:
		return writeJSON(writer, diagnosis)
	case FormatMarkdown:
		return writeMarkdown(writer, diagnosis)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func projectionFor(modes []privacy.Mode) (privacy.Projection, error) {
	if len(modes) == 0 {
		return privacy.Standard(), nil
	}
	if len(modes) != 1 {
		return privacy.Projection{}, errors.New("report accepts at most one anonymization mode")
	}
	return privacy.New(modes[0])
}

// Render returns a report as bytes.
func Render(
	diagnosis model.Diagnosis,
	format Format,
	modes ...privacy.Mode,
) ([]byte, error) {
	var buffer bytes.Buffer
	if err := Write(&buffer, diagnosis, format, modes...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeJSON(writer io.Writer, diagnosis model.Diagnosis) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(JSONDocument{SchemaVersion: "1", Diagnosis: diagnosis})
}

func writeText(writer io.Writer, diagnosis model.Diagnosis) error {
	if _, err := fmt.Fprintln(writer, "Orynelo diagnostic report"); err != nil {
		return err
	}
	lines := []string{
		"Target: " + safePlain(displayTarget(diagnosis.Target)),
		"Status: " + string(diagnosis.Summary.Status),
		"Started: " + formatTime(diagnosis.StartedAt),
		"Duration: " + formatDuration(diagnosis.Duration),
		"Redirect policy: " + redirectPolicyText(diagnosis.Options),
		fmt.Sprintf(
			"Redirect limits: %d hops, %d bytes per Location; actual HTTP reserve: %s",
			diagnosis.Options.MaxRedirects,
			diagnosis.Options.MaxRedirectLocationBytes,
			formatDuration(diagnosis.Options.ActualHTTPReserve),
		),
		fmt.Sprintf(
			"Probe mode: %s; address limit: %d; matrix budget: %s",
			diagnosis.Options.ProbeMode,
			diagnosis.Options.AddressLimit,
			formatDuration(diagnosis.Options.AddressMatrixBudget),
		),
		"Scenario: " + diagnosticScenarioText(diagnosis),
		"",
		"Summary: " + safePlain(diagnosis.Summary.Title),
		safePlain(diagnosis.Summary.Description),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
	}
	if err := writeTextNetworkPaths(writer, diagnosis.NetworkPaths); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "\nChecks:"); err != nil {
		return err
	}
	for index, result := range diagnosis.Checks {
		if _, err := fmt.Fprintf(
			writer,
			"%d. [%s] %s (%s)\n   %s\n",
			index+1,
			strings.ToUpper(string(result.Status)),
			safePlain(result.Name),
			formatDuration(result.Duration),
			safePlain(result.Summary),
		); err != nil {
			return err
		}
		if result.ErrorCode != "" {
			if _, err := fmt.Fprintf(writer, "   Error code: %s\n", result.ErrorCode); err != nil {
				return err
			}
		}
		if result.Role != "" {
			if _, err := fmt.Fprintf(writer, "   Role: %s\n", safePlain(string(result.Role))); err != nil {
				return err
			}
		}
		if diagnosis.Options.ReportVerbosity == model.ReportVerbosityVerbose {
			if _, err := fmt.Fprintf(
				writer,
				"   Check ID: %s\n   Started: %s\n   Finished: %s\n",
				safePlain(result.ID),
				formatTime(result.StartedAt),
				formatTime(result.FinishedAt),
			); err != nil {
				return err
			}
		}
		for _, evidence := range result.Evidence {
			if _, err := fmt.Fprintf(writer, "   Evidence: %s\n", safePlain(evidence.Message)); err != nil {
				return err
			}
			if diagnosis.Options.ReportVerbosity == model.ReportVerbosityVerbose {
				if _, err := fmt.Fprintf(
					writer,
					"     Evidence ID: %s\n     Evidence code: %s\n",
					safePlain(evidence.ID),
					safePlain(evidence.Code),
				); err != nil {
					return err
				}
			}
			if err := writeTextDetails(writer, evidence.Details, "     "); err != nil {
				return err
			}
		}
		for _, recommendation := range result.Recommendations {
			if _, err := fmt.Fprintf(writer, "   Next: %s\n", safePlain(recommendation.Message)); err != nil {
				return err
			}
		}
	}
	if len(diagnosis.Summary.Recommendations) > 0 {
		if _, err := fmt.Fprintln(writer, "\nRecommended next actions:"); err != nil {
			return err
		}
		for _, recommendation := range diagnosis.Summary.Recommendations {
			if _, err := fmt.Fprintf(writer, "- %s\n", safePlain(recommendation.Message)); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeMarkdown(writer io.Writer, diagnosis model.Diagnosis) error {
	if _, err := fmt.Fprintln(writer, "# Orynelo diagnostic report"); err != nil {
		return err
	}
	header := fmt.Sprintf(
		"\n- **Target:** `%s`\n- **Status:** %s\n- **Started:** %s\n- **Duration:** %s\n- **Probe mode:** `%s`\n- **Address limit:** %d\n- **Matrix budget:** %s\n- **Scenario:** %s\n- **Redirect policy:** %s\n- **Redirect limits:** %d hops, %d bytes per `Location`\n- **Actual HTTP reserve:** %s\n\n## %s\n\n%s\n",
		escapeCode(displayTarget(diagnosis.Target)),
		escapeMarkdown(string(diagnosis.Summary.Status)),
		formatTime(diagnosis.StartedAt),
		formatDuration(diagnosis.Duration),
		escapeCode(string(diagnosis.Options.ProbeMode)),
		diagnosis.Options.AddressLimit,
		formatDuration(diagnosis.Options.AddressMatrixBudget),
		escapeMarkdown(diagnosticScenarioText(diagnosis)),
		escapeMarkdown(redirectPolicyText(diagnosis.Options)),
		diagnosis.Options.MaxRedirects,
		diagnosis.Options.MaxRedirectLocationBytes,
		formatDuration(diagnosis.Options.ActualHTTPReserve),
		escapeMarkdown(diagnosis.Summary.Title),
		escapeMarkdown(diagnosis.Summary.Description),
	)
	if _, err := fmt.Fprint(writer, header); err != nil {
		return err
	}
	if err := writeMarkdownNetworkPaths(writer, diagnosis.NetworkPaths); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "\n## Checks"); err != nil {
		return err
	}
	for _, result := range diagnosis.Checks {
		if _, err := fmt.Fprintf(
			writer,
			"\n### %s — %s\n\n- **Status:** %s\n- **Duration:** %s\n",
			escapeMarkdown(result.Name),
			strings.ToUpper(string(result.Status)),
			escapeMarkdown(string(result.Status)),
			formatDuration(result.Duration),
		); err != nil {
			return err
		}
		if result.ErrorCode != "" {
			if _, err := fmt.Fprintf(writer, "- **Error code:** `%s`\n", escapeCode(result.ErrorCode)); err != nil {
				return err
			}
		}
		if result.Role != "" {
			if _, err := fmt.Fprintf(writer, "- **Role:** `%s`\n", escapeCode(string(result.Role))); err != nil {
				return err
			}
		}
		if diagnosis.Options.ReportVerbosity == model.ReportVerbosityVerbose {
			if _, err := fmt.Fprintf(
				writer,
				"- **Check ID:** `%s`\n- **Started:** %s\n- **Finished:** %s\n",
				escapeCode(result.ID),
				formatTime(result.StartedAt),
				formatTime(result.FinishedAt),
			); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(writer, "\n%s\n", escapeMarkdown(result.Summary)); err != nil {
			return err
		}
		if len(result.Evidence) > 0 {
			if _, err := fmt.Fprintln(writer, "\nEvidence:"); err != nil {
				return err
			}
			for _, evidence := range result.Evidence {
				if _, err := fmt.Fprintf(writer, "\n- %s", escapeMarkdown(evidence.Message)); err != nil {
					return err
				}
				if diagnosis.Options.ReportVerbosity == model.ReportVerbosityVerbose {
					if _, err := fmt.Fprintf(
						writer,
						" (`%s`, `%s`)",
						escapeCode(evidence.ID),
						escapeCode(evidence.Code),
					); err != nil {
						return err
					}
				}
				if len(evidence.Details) > 0 {
					if _, err := fmt.Fprintln(writer); err != nil {
						return err
					}
					for _, key := range sortedKeys(evidence.Details) {
						if _, err := fmt.Fprintf(
							writer,
							"  - `%s`: `%s`\n",
							escapeCode(key),
							escapeCode(evidence.Details[key]),
						); err != nil {
							return err
						}
					}
				} else if _, err := fmt.Fprintln(writer); err != nil {
					return err
				}
			}
		}
		if len(result.Recommendations) > 0 {
			if _, err := fmt.Fprintln(writer, "\nRecommended actions:"); err != nil {
				return err
			}
			for _, recommendation := range result.Recommendations {
				if _, err := fmt.Fprintf(writer, "\n- %s\n", escapeMarkdown(recommendation.Message)); err != nil {
					return err
				}
			}
		}
	}
	if len(diagnosis.Summary.Recommendations) > 0 {
		if _, err := fmt.Fprintln(writer, "\n## Recommended next actions"); err != nil {
			return err
		}
		for _, recommendation := range diagnosis.Summary.Recommendations {
			if _, err := fmt.Fprintf(writer, "\n- %s\n", escapeMarkdown(recommendation.Message)); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeTextNetworkPaths(writer io.Writer, paths []model.NetworkPath) error {
	if _, err := fmt.Fprintln(writer, "\nNetwork paths:"); err != nil {
		return err
	}
	if len(paths) == 0 {
		_, err := fmt.Fprintln(writer, "- No correlated network path was recorded.")
		return err
	}
	for _, path := range paths {
		if _, err := fmt.Fprintf(
			writer,
			"- %s: role=%s kind=%s\n",
			safePlain(path.ID),
			safePlain(string(path.Role)),
			safePlain(string(path.Kind)),
		); err != nil {
			return err
		}
		for _, hop := range path.Hops {
			selected := ""
			if hop.SelectedAttemptID != "" {
				selected = "; selected=" + safePlain(hop.SelectedAttemptID)
			}
			physical := ""
			if hop.RemoteAddr != "" {
				physical = "; remote=" + safePlain(hop.RemoteAddr) + "; local=" + safePlain(hop.LocalAddr) +
					"; reused=" + strconv.FormatBool(hop.Reused)
			}
			if _, err := fmt.Fprintf(
				writer,
				"  - %s: %s %s:%d%s%s\n",
				safePlain(hop.ID),
				safePlain(string(hop.Kind)),
				safePlain(hop.Host),
				hop.Port,
				selected,
				physical,
			); err != nil {
				return err
			}
			for _, attempt := range hop.Attempts {
				if _, err := fmt.Fprintf(
					writer,
					"    - %s: kind=%s state=%s remote=%s local=%s interface=%s mtu=%d duration=%s selected=%t reused=%t error=%s\n",
					safePlain(attempt.ID),
					safePlain(string(attempt.Kind)),
					safePlain(string(attempt.State)),
					safePlain(attemptEndpoint(attempt)),
					safePlain(attempt.LocalAddr),
					safePlain(attempt.InterfaceName),
					attempt.MTU,
					formatDuration(attempt.Duration),
					attempt.Selected,
					attempt.Reused,
					safePlain(attempt.ErrorCode),
				); err != nil {
					return err
				}
			}
			for _, timing := range hop.Timings {
				if _, err := fmt.Fprintf(
					writer,
					"    - timing %s (%s): %s\n",
					safePlain(timing.Phase),
					safePlain(timing.AttemptID),
					formatDuration(timing.Duration),
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeMarkdownNetworkPaths(writer io.Writer, paths []model.NetworkPath) error {
	if _, err := fmt.Fprintln(writer, "\n## Network paths"); err != nil {
		return err
	}
	if len(paths) == 0 {
		_, err := fmt.Fprintln(writer, "\nNo correlated network path was recorded.")
		return err
	}
	for _, path := range paths {
		if _, err := fmt.Fprintf(
			writer,
			"\n- `%s`: role `%s`, kind `%s`\n",
			escapeCode(path.ID),
			escapeCode(string(path.Role)),
			escapeCode(string(path.Kind)),
		); err != nil {
			return err
		}
		for _, hop := range path.Hops {
			endpoint := fmt.Sprintf("%s:%d", hop.Host, hop.Port)
			if _, err := fmt.Fprintf(
				writer,
				"  - `%s`: `%s` at `%s`",
				escapeCode(hop.ID),
				escapeCode(string(hop.Kind)),
				escapeCode(endpoint),
			); err != nil {
				return err
			}
			if hop.SelectedAttemptID != "" {
				if _, err := fmt.Fprintf(writer, "; selected `%s`", escapeCode(hop.SelectedAttemptID)); err != nil {
					return err
				}
			}
			if hop.RemoteAddr != "" {
				if _, err := fmt.Fprintf(
					writer,
					"; remote `%s`; local `%s`; reused `%t`",
					escapeCode(hop.RemoteAddr),
					escapeCode(hop.LocalAddr),
					hop.Reused,
				); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
			for _, attempt := range hop.Attempts {
				if _, err := fmt.Fprintf(
					writer,
					"    - `%s`: `%s`, state `%s`, remote `%s`, local `%s`, interface `%s`, MTU %d, duration %s, selected `%t`, reused `%t`, error `%s`\n",
					escapeCode(attempt.ID),
					escapeCode(string(attempt.Kind)),
					escapeCode(string(attempt.State)),
					escapeCode(attemptEndpoint(attempt)),
					escapeCode(attempt.LocalAddr),
					escapeCode(attempt.InterfaceName),
					attempt.MTU,
					formatDuration(attempt.Duration),
					attempt.Selected,
					attempt.Reused,
					escapeCode(attempt.ErrorCode),
				); err != nil {
					return err
				}
			}
			for _, timing := range hop.Timings {
				if _, err := fmt.Fprintf(
					writer,
					"    - timing `%s` (`%s`): %s\n",
					escapeCode(timing.Phase),
					escapeCode(timing.AttemptID),
					formatDuration(timing.Duration),
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func diagnosticScenarioText(diagnosis model.Diagnosis) string {
	parts := []string{"mode=" + string(diagnosis.Target.Mode)}
	if diagnosis.Options.ExpectedStatusConfigured {
		parts = append(parts, fmt.Sprintf(
			"expected-status=%d-%d",
			diagnosis.Options.ExpectedStatusMin,
			diagnosis.Options.ExpectedStatusMax,
		))
	}
	if diagnosis.Options.LatencyThreshold > 0 {
		parts = append(parts, "latency-threshold="+diagnosis.Options.LatencyThreshold.String())
	}
	if diagnosis.Options.ConnectIP != "" {
		parts = append(parts, "connect-ip="+diagnosis.Options.ConnectIP)
	}
	if diagnosis.Options.ServerName != "" {
		parts = append(parts, "sni="+diagnosis.Options.ServerName)
	}
	if diagnosis.Options.HTTPHost != "" {
		parts = append(parts, "http-host="+diagnosis.Options.HTTPHost)
	}
	if diagnosis.Options.CustomCAConfigured {
		parts = append(parts, "custom-ca=configured")
	}
	if len(diagnosis.Options.RequestHeaderNames) > 0 {
		parts = append(parts, "one-time-header-names="+strings.Join(diagnosis.Options.RequestHeaderNames, ","))
	}
	if diagnosis.Options.CollectDNSDetails {
		parts = append(parts, "dns-details=enabled")
	}
	if diagnosis.Options.InspectBody {
		parts = append(parts, "body-inspection=enabled")
	}
	return strings.Join(parts, "; ")
}

func attemptEndpoint(attempt model.NetworkAttempt) string {
	if attempt.RemoteAddr != "" {
		return attempt.RemoteAddr
	}
	if attempt.RemoteIP != nil {
		return attempt.RemoteIP.String()
	}
	return ""
}

func redirectPolicyText(options model.DiagnoseOptions) string {
	downgrade := "block HTTPS-to-HTTP downgrade"
	if options.AllowInsecureRedirects {
		downgrade = "allow HTTPS-to-HTTP downgrade (explicit opt-in)"
	}
	privateNetwork := "block public-to-private network transitions"
	if options.AllowPrivateRedirects {
		privateNetwork = "allow public-to-private network transitions (explicit opt-in)"
	}
	return downgrade + "; " + privateNetwork + "; strip sensitive headers cross-origin"
}

func writeTextDetails(writer io.Writer, details map[string]string, indent string) error {
	for _, key := range sortedKeys(details) {
		if _, err := fmt.Fprintf(writer, "%s%s: %s\n", indent, safePlain(key), safePlain(details[key])); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func displayTarget(target model.Target) string {
	if target.Normalized != "" {
		return target.Normalized
	}
	if target.Original != "" {
		return target.Original
	}
	return "[unknown target]"
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.UTC().Format(time.RFC3339)
}

func formatDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	return value.Round(time.Microsecond).String()
}

func escapeMarkdown(value string) string {
	value = safePlain(value)
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"<", "&lt;",
		">", "&gt;",
	)
	return replacer.Replace(value)
}

func escapeCode(value string) string {
	return strings.ReplaceAll(safePlain(value), "`", "'")
}

func safePlain(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n', r == '\r', r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, value)
}
