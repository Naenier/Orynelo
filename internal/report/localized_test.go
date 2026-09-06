package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestRenderLocalizedRussianHumanReportKeepsCanonicalIdentifiers(t *testing.T) {
	diagnosis := model.Diagnosis{
		Target:  model.Target{Normalized: "https://example.test"},
		Summary: model.Summary{Status: model.StatusFailed, Title: "Failure"},
		NetworkPaths: []model.NetworkPath{{
			ID: "path-client-1", Role: model.NetworkPathRoleClientEffective,
			Kind: model.NetworkPathDirect,
		}},
	}
	content, err := RenderLocalized(diagnosis, FormatMarkdown, "ru")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, expected := range []string{"# Диагностический отчёт Orynelo", "**Цель:**", "## Сетевые пути", "`path-client-1`"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("localized report is missing %q:\n%s", expected, text)
		}
	}
}

func TestRenderLocalizedNeverTranslatesCanonicalJSON(t *testing.T) {
	diagnosis := model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}}
	english, err := RenderLocalized(diagnosis, FormatJSON, "en")
	if err != nil {
		t.Fatal(err)
	}
	russian, err := RenderLocalized(diagnosis, FormatJSON, "ru")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(english, russian) {
		t.Fatal("JSON changed when report language changed")
	}
}

func TestRenderLocalizedDoesNotRewriteDiagnosticValues(t *testing.T) {
	diagnosis := model.Diagnosis{
		Target: model.Target{Normalized: "https://target.test/Target/Status/Network-paths"},
		Summary: model.Summary{
			Status:      model.StatusWarning,
			Title:       "Target Status Network paths",
			Description: "Evidence and Summary are diagnostic values here.",
		},
	}
	content, err := RenderLocalized(diagnosis, FormatMarkdown, "ru")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, value := range []string{
		"https://target.test/Target/Status/Network-paths",
		"## Target Status Network paths",
		"Evidence and Summary are diagnostic values here.",
	} {
		if !strings.Contains(text, value) {
			t.Fatalf("localized report rewrote diagnostic value %q:\n%s", value, text)
		}
	}
}
