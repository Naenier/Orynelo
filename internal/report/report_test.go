package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

func TestRenderJSONSchemaAndPrivacy(t *testing.T) {
	t.Parallel()
	diagnosis := sampleDiagnosis()
	diagnosis.Target.Original = "report-user:report-password@example.com/%zz#access_token=fragment-report-secret"
	diagnosis.Target.Normalized = diagnosis.Target.Original
	diagnosis.Target.RequestURL = "https://example.com/?token=top-secret"
	diagnosis.Options.Target = "https://alice:password@example.com/?token=top-secret"
	diagnosis.Options.UserAgent = "Orynelo token=user-agent-secret"
	diagnosis.Checks[0].Evidence[0].Details["unsafe"] = "https://alice:password@example.com/?api_key=top-secret"
	diagnosis.Checks[0].Evidence[0].Details["responseHeader.Authorization"] = "Bearer namespaced-report-secret"
	output, err := Render(diagnosis, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"top-secret", "password", "alice", "user-agent-secret", "namespaced-report-secret",
		"report-user", "report-password", "fragment-report-secret",
	} {
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

func TestRenderStrictAnonymizationIsOptIn(t *testing.T) {
	t.Parallel()

	diagnosis := sampleDiagnosis()
	diagnosis.Target.Original = "https://service.internal/private/customer/42?view=full"
	diagnosis.Target.Normalized = diagnosis.Target.Original
	diagnosis.Target.Host = "service.internal"
	diagnosis.Target.Path = "/private/customer/42"
	diagnosis.Checks[0].Evidence[0].Details["remoteIp"] = "10.2.3.4"
	diagnosis.Checks[0].Evidence[0].Details["logPath"] = "/home/alice/.local/share/orynelo/app.log"
	diagnosis.Checks[0].Evidence[0].Details["error"] = "lookup backend01: no such host"

	standard, err := Render(diagnosis, FormatJSON, privacy.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(standard), "service.internal") ||
		!strings.Contains(string(standard), "private/customer/42") {
		t.Fatalf("standard report unexpectedly removed non-secret context: %s", standard)
	}

	strict, err := Render(diagnosis, FormatJSON, privacy.ModeStrict)
	if err != nil {
		t.Fatal(err)
	}
	for _, identifying := range []string{
		"service.internal", "private/customer/42", "view=full", "10.2.3.4", "/home/alice", "backend01",
	} {
		if strings.Contains(string(strict), identifying) {
			t.Fatalf("strict report retained %q: %s", identifying, strict)
		}
	}
}

func TestRenderJSONNormalizesNonUTCTimestamps(t *testing.T) {
	t.Parallel()

	diagnosis := sampleDiagnosis()
	zone := time.FixedZone("non-utc", -7*60*60)
	diagnosis.StartedAt = time.Date(2026, 8, 3, 12, 0, 0, 0, zone)
	diagnosis.FinishedAt = diagnosis.StartedAt.Add(time.Second)
	diagnosis.Checks[0].StartedAt = diagnosis.StartedAt
	diagnosis.Checks[0].FinishedAt = diagnosis.FinishedAt
	output, err := Render(diagnosis, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "-07:00") || !strings.Contains(string(output), "Z") {
		t.Fatalf("JSON report timestamps are not UTC: %s", output)
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

func TestHumanReportsSurfaceRedirectAndAuxiliaryRoutePolicy(t *testing.T) {
	t.Parallel()
	diagnosis := sampleDiagnosis()
	diagnosis.Options.MaxRedirects = 7
	diagnosis.Options.MaxRedirectLocationBytes = 4096
	diagnosis.Options.ActualHTTPReserve = 3 * time.Second
	diagnosis.Options.AllowInsecureRedirects = true
	diagnosis.Checks[0].Role = model.CheckRoleAuxiliaryDirectComparison

	for _, format := range []Format{FormatText, FormatMarkdown} {
		output, err := Render(diagnosis, format)
		if err != nil {
			t.Fatalf("Render(%s) error = %v", format, err)
		}
		text := string(output)
		for _, expected := range []string{
			"allow HTTPS-to-HTTP downgrade (explicit opt-in)",
			"block public-to-private network transitions",
			"strip sensitive headers cross-origin",
			"4096",
			"auxiliary_direct_comparison",
		} {
			if !strings.Contains(text, expected) {
				t.Fatalf("%s report missing %q:\n%s", format, expected, text)
			}
		}
	}
}

func TestHumanReportsKeepMixedHTTPRouteTruthful(t *testing.T) {
	t.Parallel()
	diagnosis := sampleDiagnosis()
	diagnosis.Summary.Title = "Target reachable across mixed direct/proxy routes"
	diagnosis.Summary.Description = "The redirect chain used both direct and proxy routes."
	diagnosis.Checks[0].Evidence[0].Details = map[string]string{
		"route":             "mixed",
		"proxySource":       "HTTPS_PROXY",
		"proxyBypassReason": "no_proxy_match",
	}

	for _, format := range []Format{FormatText, FormatMarkdown} {
		output, err := Render(diagnosis, format)
		if err != nil {
			t.Fatalf("Render(%s) error = %v", format, err)
		}
		text := string(output)
		expectedDetails := []string{
			"route: mixed",
			"proxySource: HTTPS_PROXY",
			"proxyBypassReason: no_proxy_match",
		}
		if format == FormatMarkdown {
			expectedDetails = []string{
				"`route`: `mixed`",
				"`proxySource`: `HTTPS_PROXY`",
				"`proxyBypassReason`: `no_proxy_match`",
			}
		}
		for _, expected := range append([]string{"mixed direct/proxy routes"}, expectedDetails...) {
			if !strings.Contains(text, expected) {
				t.Fatalf("%s report missing %q:\n%s", format, expected, text)
			}
		}
		if strings.Contains(text, "Target reachable through selected proxy") {
			t.Fatalf("%s report made a proxy-only claim:\n%s", format, text)
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
		"# Orynelo diagnostic report",
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
