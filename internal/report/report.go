// Package report renders diagnoses without terminal assumptions or ANSI color.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
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
func Write(writer io.Writer, diagnosis model.Diagnosis, format Format) error {
	if writer == nil {
		return errors.New("report writer is nil")
	}
	diagnosis = sanitizeDiagnosis(diagnosis)
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

func sanitizeDiagnosis(input model.Diagnosis) model.Diagnosis {
	result := input
	result.Target.Original = redaction.RedactURL(input.Target.Original)
	result.Target.Normalized = redaction.RedactURL(input.Target.Normalized)
	result.Target.RequestURL = ""
	result.Options.Target = redaction.RedactURL(input.Options.Target)
	result.Options.UserAgent = redaction.RedactText(input.Options.UserAgent)
	result.Summary.Title = redaction.RedactText(input.Summary.Title)
	result.Summary.Description = redaction.RedactText(input.Summary.Description)
	result.Summary.Recommendations = sanitizeRecommendations(input.Summary.Recommendations)
	result.Checks = make([]model.CheckResult, len(input.Checks))
	for index, check := range input.Checks {
		result.Checks[index] = check
		result.Checks[index].Summary = redaction.RedactText(check.Summary)
		result.Checks[index].Evidence = make([]model.Evidence, len(check.Evidence))
		for evidenceIndex, evidence := range check.Evidence {
			result.Checks[index].Evidence[evidenceIndex] = evidence
			result.Checks[index].Evidence[evidenceIndex].Message = redaction.RedactText(evidence.Message)
			result.Checks[index].Evidence[evidenceIndex].Details = redaction.RedactMap(evidence.Details)
		}
		result.Checks[index].Recommendations = sanitizeRecommendations(check.Recommendations)
	}
	return result
}

func sanitizeRecommendations(values []model.Recommendation) []model.Recommendation {
	if values == nil {
		return nil
	}
	result := append([]model.Recommendation(nil), values...)
	for index := range result {
		result[index].Message = redaction.RedactText(result[index].Message)
	}
	return result
}

// Render returns a report as bytes.
func Render(diagnosis model.Diagnosis, format Format) ([]byte, error) {
	var buffer bytes.Buffer
	if err := Write(&buffer, diagnosis, format); err != nil {
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
	if _, err := fmt.Fprintln(writer, "OpsDoctor diagnostic report"); err != nil {
		return err
	}
	lines := []string{
		"Target: " + safePlain(displayTarget(diagnosis.Target)),
		"Status: " + string(diagnosis.Summary.Status),
		"Started: " + formatTime(diagnosis.StartedAt),
		"Duration: " + formatDuration(diagnosis.Duration),
		"",
		"Summary: " + safePlain(diagnosis.Summary.Title),
		safePlain(diagnosis.Summary.Description),
		"",
		"Checks:",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
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
	if _, err := fmt.Fprintln(writer, "# OpsDoctor diagnostic report"); err != nil {
		return err
	}
	header := fmt.Sprintf(
		"\n- **Target:** `%s`\n- **Status:** %s\n- **Started:** %s\n- **Duration:** %s\n\n## %s\n\n%s\n\n## Checks\n",
		escapeCode(displayTarget(diagnosis.Target)),
		escapeMarkdown(string(diagnosis.Summary.Status)),
		formatTime(diagnosis.StartedAt),
		formatDuration(diagnosis.Duration),
		escapeMarkdown(diagnosis.Summary.Title),
		escapeMarkdown(diagnosis.Summary.Description),
	)
	if _, err := fmt.Fprint(writer, header); err != nil {
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
