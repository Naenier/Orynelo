package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestRenderJSONSchemaAndPrivacy(t *testing.T) {
	t.Parallel()
	diagnosis := sampleDiagnosis()
	diagnosis.Target.RequestURL = "https://example.com/?token=top-secret"
	diagnosis.Options.Target = "https://alice:password@example.com/?token=top-secret"
	diagnosis.Checks[0].Evidence[0].Details["unsafe"] = "https://alice:password@example.com/?api_key=top-secret"
	output, err := Render(diagnosis, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"top-secret", "password", "alice"} {
		if strings.Contains(string(output), secret) {
			t.Fatalf("JSON leaked %q: %s", secret, output)
		}
	}
	var document JSONDocument
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != "1" || document.Diagnosis.ID != diagnosis.ID {
		t.Fatalf("document = %#v", document)
	}
}

func TestRenderTextIsDeterministicAndPlain(t *testing.T) {
	t.Parallel()
	output, err := Render(sampleDiagnosis(), FormatText)
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("text report contains ANSI: %q", text)
	}
	a := strings.Index(text, "     a: first")
	z := strings.Index(text, "     z: last")
	if a < 0 || z < 0 || a > z {
		t.Fatalf("evidence details are not deterministic:\n%s", text)
	}
	if !strings.Contains(text, "[WARNING] HTTP request") {
		t.Fatalf("missing status and check name:\n%s", text)
	}
}

func TestVerboseHumanReportsIncludeStableTechnicalIdentifiers(t *testing.T) {
	t.Parallel()

	diagnosis := sampleDiagnosis()
	diagnosis.Options.ReportVerbosity = model.ReportVerbosityVerbose
	for _, format := range []Format{FormatText, FormatMarkdown} {
		output, err := Render(diagnosis, format)
		if err != nil {
			t.Fatalf("Render(%s) error = %v", format, err)
		}
		for _, expected := range []string{"http", "http.response"} {
			if !strings.Contains(string(output), expected) {
				t.Fatalf("verbose %s report missing %q:\n%s", format, expected, output)
			}
		}
	}
}

func TestRenderMarkdownAndParseFormat(t *testing.T) {
	t.Parallel()
	output, err := Render(sampleDiagnosis(), FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	for _, expected := range []string{
		"# OpsDoctor diagnostic report",
		"## Target reachable with application-level error",
		"### HTTP request — WARNING",
		"## Recommended next actions",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("markdown missing %q:\n%s", expected, text)
		}
	}
	if format, err := ParseFormat("MD"); err != nil || format != FormatMarkdown {
		t.Fatalf("ParseFormat(MD) = %q, %v", format, err)
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("ParseFormat(xml) unexpectedly succeeded")
	}
}

func sampleDiagnosis() model.Diagnosis {
	started := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	return model.Diagnosis{
		ID: "diagnosis-1",
		Target: model.Target{
			Original:   "https://example.com",
			Normalized: "https://example.com:443",
			Host:       "example.com",
			Port:       443,
		},
		StartedAt:  started,
		FinishedAt: started.Add(time.Second),
		Duration:   time.Second,
		Summary: model.Summary{
			Status:      model.StatusWarning,
			Title:       "Target reachable with application-level error",
			Description: "Transport passed; the application returned HTTP 503.",
			Recommendations: []model.Recommendation{{
				Message: "Inspect service health.",
			}},
		},
		Checks: []model.CheckResult{{
			ID:        "http",
			Name:      "HTTP request",
			Status:    model.StatusWarning,
			Duration:  200 * time.Millisecond,
			Summary:   "HTTP 503 Service Unavailable.",
			ErrorCode: "HTTP_SERVER_ERROR",
			Evidence: []model.Evidence{{
				ID:      "http.response",
				Message: "The application response was recorded.",
				Details: map[string]string{"z": "last", "a": "first"},
			}},
		}},
	}
}
