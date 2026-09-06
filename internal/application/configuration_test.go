package application

import (
	"strings"
	"testing"
)

func TestDefaultConfigUsesSystemLanguagePreferences(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	if config.Appearance.Language != "system" {
		t.Fatalf("Appearance.Language = %q, want system", config.Appearance.Language)
	}
	if config.Appearance.ReportLanguage != "system" {
		t.Fatalf(
			"Appearance.ReportLanguage = %q, want system",
			config.Appearance.ReportLanguage,
		)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() error = %v", err)
	}
}

func TestConfigValidatesLanguagePreferencesIndependently(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "interface language",
			mutate: func(config *Config) {
				config.Appearance.Language = "de"
			},
			want: "appearance.language",
		},
		{
			name: "report language",
			mutate: func(config *Config) {
				config.Appearance.ReportLanguage = "fr"
			},
			want: "appearance.reportLanguage",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := DefaultConfig()
			test.mutate(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Config.Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestConfigAcceptsEverySupportedLanguagePreference(t *testing.T) {
	t.Parallel()

	for _, language := range []string{"system", "ru", "en"} {
		config := DefaultConfig()
		config.Appearance.Language = language
		config.Appearance.ReportLanguage = language
		if err := config.Validate(); err != nil {
			t.Errorf("Config.Validate() rejected language %q: %v", language, err)
		}
	}
}
