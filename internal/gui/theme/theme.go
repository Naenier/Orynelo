// Package theme applies the supported Orynelo appearance preferences.
package theme

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	fynetheme "fyne.io/fyne/v2/theme"

	"github.com/Naenier/orynelo/internal/gui/localization"
)

// Supported appearance preference values.
const (
	// System follows the desktop environment's current appearance.
	System = "system"
	// Light forces the light Fyne color variant.
	Light = "light"
	// Dark forces the dark Fyne color variant.
	Dark = "dark"
)

// Apply changes the Fyne application theme.
func Apply(texts localization.Catalog, app fyne.App, appearance string) error {
	texts = localization.Normalize(texts)
	switch strings.ToLower(strings.TrimSpace(appearance)) {
	case "", System:
		app.Settings().SetTheme(fynetheme.DefaultTheme())
	case Light:
		app.Settings().SetTheme(fixedVariantTheme{
			Theme:   fynetheme.DefaultTheme(),
			variant: fynetheme.VariantLight,
		})
	case Dark:
		app.Settings().SetTheme(fixedVariantTheme{
			Theme:   fynetheme.DefaultTheme(),
			variant: fynetheme.VariantDark,
		})
	default:
		return fmt.Errorf(
			texts.Text(localization.ThemeUnknownAppearanceFormat),
			appearance,
		)
	}
	return nil
}

// fixedVariantTheme keeps the current Fyne theme's fonts, icons, and metrics
// while deliberately overriding the color variant selected by the system.
type fixedVariantTheme struct {
	fyne.Theme
	variant fyne.ThemeVariant
}

// Color resolves colors using the explicitly selected light or dark variant.
func (t fixedVariantTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(name, t.variant)
}
