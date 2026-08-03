package localization

import (
	"strings"
	"testing"
)

func TestEnglishCatalogEntriesAreNonEmpty(t *testing.T) {
	t.Parallel()

	for key, value := range english {
		if strings.TrimSpace(value) == "" {
			t.Errorf("English text for %q is empty", key)
		}
	}
}

func TestNormalizeUsesEnglishForNilCatalog(t *testing.T) {
	t.Parallel()

	if got := Normalize(nil).Text(DiagnoseRun); got != "Run diagnostics" {
		t.Fatalf("Normalize(nil).Text(DiagnoseRun) = %q", got)
	}
}

func TestStatusKeyMapsDomainValues(t *testing.T) {
	t.Parallel()

	tests := map[string]Key{
		"passed":         StatusPassed,
		" WARNING ":      StatusWarning,
		"failed":         StatusFailed,
		"running":        StatusRunning,
		"skipped":        StatusSkipped,
		"not_applicable": StatusNotApplicable,
		"cancelled":      StatusCancelled,
		"unknown":        StatusPending,
	}
	for value, want := range tests {
		if got := StatusKey(value); got != want {
			t.Errorf("StatusKey(%q) = %q, want %q", value, got, want)
		}
	}
}
