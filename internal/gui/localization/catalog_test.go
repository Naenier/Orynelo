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

func TestBuiltInCatalogsHaveExactKeyParity(t *testing.T) {
	t.Parallel()
	if err := ValidateBuiltins(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingTranslationDoesNotExposeInternalKey(t *testing.T) {
	t.Parallel()
	key := Key("internal.secret.key")
	for name, catalog := range map[string]Catalog{"en": English{}, "ru": Russian{}} {
		if got := catalog.Text(key); got == string(key) || strings.TrimSpace(got) == "" {
			t.Errorf("%s missing translation = %q", name, got)
		}
	}
}

func TestResolveLanguage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		preference Language
		locale     string
		want       Language
	}{
		{LanguageSystem, "ru_RU.UTF-8", LanguageRussian},
		{LanguageSystem, "en-US", LanguageEnglish},
		{LanguageSystem, "C", LanguageEnglish},
		{LanguageEnglish, "ru-RU", LanguageEnglish},
		{LanguageRussian, "en-US", LanguageRussian},
	}
	for _, test := range tests {
		if got := ResolveLanguage(test.preference, test.locale); got != test.want {
			t.Errorf("ResolveLanguage(%q, %q) = %q, want %q", test.preference, test.locale, got, test.want)
		}
	}
}

func TestNormalizeUsesEnglishForNilCatalog(t *testing.T) {
	t.Parallel()

	if got := Normalize(nil).Text(DiagnoseRun); got != "Run diagnostics" {
		t.Fatalf("Normalize(nil).Text(DiagnoseRun) = %q", got)
	}
}

func TestApplicationMessageResolutionIsLocalizedAndExplicitlyMissing(t *testing.T) {
	t.Parallel()

	if got, ok := Message(Russian{}, "error.history_list_failed"); !ok ||
		!strings.Contains(got, "историю") {
		t.Fatalf("Russian application message = %q, %v", got, ok)
	}
	if got, ok := Message(English{}, "error.future_unknown"); ok || got != "" {
		t.Fatalf("unknown application message = %q, %v", got, ok)
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
