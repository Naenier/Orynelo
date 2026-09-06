package screens

import (
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	fynetheme "fyne.io/fyne/v2/theme"

	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/gui/presenter"
	apptheme "github.com/Naenier/orynelo/internal/gui/theme"
)

func TestDiagnoseLayoutGoldens(t *testing.T) {
	cases := []struct {
		name       string
		language   localization.Language
		appearance string
		viewport   string
		size       fyne.Size
		variant    fyne.ThemeVariant
	}{
		{"en_light_wide", localization.LanguageEnglish, apptheme.Light, "wide", fyne.NewSize(1200, 900), fynetheme.VariantLight},
		{"en_dark_wide", localization.LanguageEnglish, apptheme.Dark, "wide", fyne.NewSize(1200, 900), fynetheme.VariantDark},
		{"ru_light_wide", localization.LanguageRussian, apptheme.Light, "wide", fyne.NewSize(1200, 900), fynetheme.VariantLight},
		{"ru_dark_wide", localization.LanguageRussian, apptheme.Dark, "wide", fyne.NewSize(1200, 900), fynetheme.VariantDark},
		{"en_light_narrow", localization.LanguageEnglish, apptheme.Light, "narrow", fyne.NewSize(830, 620), fynetheme.VariantLight},
		{"en_dark_narrow", localization.LanguageEnglish, apptheme.Dark, "narrow", fyne.NewSize(830, 620), fynetheme.VariantDark},
		{"ru_light_narrow", localization.LanguageRussian, apptheme.Light, "narrow", fyne.NewSize(830, 620), fynetheme.VariantLight},
		{"ru_dark_narrow", localization.LanguageRussian, apptheme.Dark, "narrow", fyne.NewSize(830, 620), fynetheme.VariantDark},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			app := test.NewTempApp(t)
			texts := localization.ForLanguage(current.language)
			if err := apptheme.Apply(texts, app, current.appearance); err != nil {
				t.Fatal(err)
			}
			screen := NewDiagnose(texts, DiagnoseActions{})
			screen.ShowDiagnosis(representativeGoldenDiagnosis(texts))
			screen.Root.Resize(current.size)
			test.LaidOutObjects(screen.Root)

			minimum := screen.Root.MinSize()
			direction := "vertical"
			if screen.explorer.Horizontal {
				direction = "horizontal"
			}
			snapshot := fmt.Sprintf(
				"language=%s\nappearance=%s\nviewport=%s\nexplorer=%s\nwide_actions=%t\noverflow_actions=%t\nfits=%t\ntheme_fixed=%t\nrun=%s\ntimeline=%s\ndetails=%s\n",
				current.language,
				current.appearance,
				current.viewport,
				direction,
				screen.postActionsWide.Visible(),
				screen.postActionsOverflow.Visible(),
				minimum.Width <= current.size.Width && minimum.Height <= current.size.Height,
				sameColor(
					app.Settings().Theme().Color(fynetheme.ColorNameBackground, app.Settings().ThemeVariant()),
					fynetheme.DefaultTheme().Color(fynetheme.ColorNameBackground, current.variant),
				),
				screen.run.Text,
				screen.timelineCard.Title,
				screen.detailsCard.Title,
			)
			path := filepath.Join("testdata", "layout", current.name+".golden")
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot != string(expected) {
				t.Fatalf("layout snapshot differs from %s\n--- got ---\n%s--- want ---\n%s", path, snapshot, expected)
			}
		})
	}
}

func representativeGoldenDiagnosis(texts localization.Catalog) presenter.DiagnosisView {
	return presenter.DiagnosisView{
		Target:        "https://example.test",
		SummaryTitle:  texts.Text(localization.DiagnoseReadyTitle),
		SummaryDetail: texts.Text(localization.DiagnoseReadyDetail),
		OverallStatus: "passed",
		Checks: []presenter.CheckView{{
			ID:      "http",
			Name:    texts.Text(localization.CheckHTTP),
			Status:  "passed",
			Summary: texts.Text(localization.DiagnoseReadyDetail),
		}},
		Recommendations: []presenter.RecommendationView{{
			ID:       "golden.next",
			Priority: "medium",
			Message:  texts.Text(localization.DiagnoseRunAgain),
		}},
	}
}

func sameColor(left, right color.Color) bool {
	lr, lg, lb, la := left.RGBA()
	rr, rg, rb, ra := right.RGBA()
	return lr == rr && lg == rg && lb == rb && la == ra
}
