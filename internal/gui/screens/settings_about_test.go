package screens

import (
	"errors"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

func TestSettingsUsesFriendlyValuesAndPreservesDomainValues(t *testing.T) {
	test.NewTempApp(t)
	initial := application.DefaultConfig()
	var saved application.Config
	root := NewSettings(localization.English{}, initial, SettingsActions{
		Save: func(config application.Config, complete func(string)) {
			saved = config
			complete("")
		},
	})

	certificateWarning := settingsAboutFindEntry(t, root, "30d")
	ipVersion := settingsAboutFindSelect(t, root, []string{"Auto", "IPv4", "IPv6"})
	logLevel := settingsAboutFindSelect(
		t,
		root,
		[]string{"Debug", "Info", "Warning", "Error"},
	)
	appearance := settingsAboutFindRadio(
		t,
		root,
		[]string{"System", "Light", "Dark"},
	)
	save := settingsAboutFindButton(t, root, "Save settings")

	if !save.Disabled() {
		t.Fatal("unchanged settings can be saved")
	}
	certificateWarning.SetText("45d")
	ipVersion.SetSelected("IPv6")
	logLevel.SetSelected("Warning")
	appearance.SetSelected("Dark")
	if save.Disabled() {
		t.Fatal("save action remained disabled after editing settings")
	}

	test.Tap(save)
	if saved.Diagnostics.CertificateWarningThreshold != 45*24*time.Hour {
		t.Fatalf(
			"certificate warning = %s, want 45 days",
			saved.Diagnostics.CertificateWarningThreshold,
		)
	}
	if saved.Diagnostics.PreferredIPVersion != "6" {
		t.Fatalf("preferred IP = %q, want domain value 6", saved.Diagnostics.PreferredIPVersion)
	}
	if saved.Logging.Level != "warn" {
		t.Fatalf("log level = %q, want domain value warn", saved.Logging.Level)
	}
	if saved.Appearance.Theme != "dark" {
		t.Fatalf("theme = %q, want domain value dark", saved.Appearance.Theme)
	}
	if !save.Disabled() {
		t.Fatal("save action remained enabled after a successful save")
	}
}

func TestSettingsWaitsForAsynchronousSaveCompletion(t *testing.T) {
	test.NewTempApp(t)
	var complete func(string)
	root := NewSettings(
		localization.English{},
		application.DefaultConfig(),
		SettingsActions{
			Save: func(_ application.Config, done func(string)) {
				complete = done
			},
		},
	)
	settingsAboutFindEntry(t, root, "15s").SetText("20s")
	save := settingsAboutFindButton(t, root, "Save settings")
	test.Tap(save)
	if complete == nil {
		t.Fatal("save completion callback was not captured")
	}
	if !save.Disabled() {
		t.Fatal("save remained enabled while persistence was pending")
	}
	settingsAboutFindLabel(t, root, "Saving…")

	complete("safe failure")
	if save.Disabled() {
		t.Fatal("save remained disabled after asynchronous failure")
	}
	settingsAboutFindLabel(t, root, "Settings were not saved: safe failure")
}

func TestSettingsKeepsActionsVisibleAndSeparatesDestructiveHistoryAction(
	t *testing.T,
) {
	test.NewTempApp(t)
	initial := application.DefaultConfig()
	initial.History.Enabled = false
	clears := 0
	root := NewSettings(localization.English{}, initial, SettingsActions{
		ClearHistory: func() {
			clears++
		},
	})
	root.Resize(fyne.NewSize(1400, 700))
	test.LaidOutObjects(root)

	containerRoot, ok := root.(*fyne.Container)
	if !ok || len(containerRoot.Objects) != 2 {
		t.Fatalf("settings root = %T with unexpected children", root)
	}
	footer := containerRoot.Objects[1]
	if footer.Position().Y < root.Size().Height-footer.Size().Height-1 {
		t.Fatal("settings save bar is not pinned to the bottom edge")
	}

	save := settingsAboutFindButton(t, root, "Save settings")
	if save.Importance != widget.HighImportance || save.Icon == nil {
		t.Fatal("save action is not presented as the primary persistent action")
	}
	clearHistory := settingsAboutFindButton(t, root, "Clear history…")
	if clearHistory.Importance != widget.DangerImportance || clearHistory.Icon == nil {
		t.Fatal("clear-history action is not visually marked as destructive")
	}
	test.Tap(clearHistory)
	if clears != 1 {
		t.Fatalf("clear-history calls = %d, want 1", clears)
	}

	historyLimit := settingsAboutFindEntry(t, root, "200")
	if !historyLimit.Disabled() {
		t.Fatal("history limit remains editable while history saving is disabled")
	}

	for _, object := range test.LaidOutObjects(root) {
		entry, ok := object.(*widget.Entry)
		if !ok {
			continue
		}
		if entry.Size().Width > 520 {
			t.Fatalf(
				"settings field %q is stretched to %.0fpx",
				entry.Text,
				entry.Size().Width,
			)
		}
	}
}

func TestSettingsFitsMinimumContentSizeWithStickySaveBar(t *testing.T) {
	test.NewTempApp(t)
	root := NewSettings(
		localization.English{},
		application.DefaultConfig(),
		SettingsActions{Save: func(application.Config, func(string)) {}},
	)
	root.Resize(fyne.NewSize(830, 620))
	test.LaidOutObjects(root)

	minimum := root.MinSize()
	if minimum.Width > 830 || minimum.Height > 620 {
		t.Fatalf(
			"Settings minimum = %.0fx%.0f, want at most 830x620",
			minimum.Width,
			minimum.Height,
		)
	}
	containerRoot := root.(*fyne.Container)
	footer := containerRoot.Objects[1]
	if footer.Position().Y < 0 ||
		footer.Position().Y+footer.Size().Height > root.Size().Height+1 ||
		footer.Position().X < 0 ||
		footer.Position().X+footer.Size().Width > root.Size().Width+1 {
		t.Fatalf(
			"sticky footer bounds = (%.0f,%.0f) %.0fx%.0f inside %.0fx%.0f",
			footer.Position().X,
			footer.Position().Y,
			footer.Size().Width,
			footer.Size().Height,
			root.Size().Width,
			root.Size().Height,
		)
	}
	save := settingsAboutFindButton(t, root, "Save settings")
	if !save.Visible() {
		t.Fatal("sticky save action is hidden at minimum content size")
	}
}

func TestSettingsRejectsThemeThatCannotBeApplied(t *testing.T) {
	test.NewTempApp(t)
	root := NewSettings(
		localization.English{},
		application.DefaultConfig(),
		SettingsActions{
			Save: func(application.Config, func(string)) {},
			ApplyTheme: func(theme string) error {
				if theme == "dark" {
					return errors.New("theme unavailable")
				}
				return nil
			},
		},
	)
	appearance := settingsAboutFindRadio(
		t,
		root,
		[]string{"System", "Light", "Dark"},
	)
	save := settingsAboutFindButton(t, root, "Save settings")

	appearance.SetSelected("Dark")

	if appearance.Selected != "System" {
		t.Fatalf(
			"theme selection = %q after apply error, want System",
			appearance.Selected,
		)
	}
	if !save.Disabled() {
		t.Fatal("failed theme-only change enabled persistence")
	}
	settingsAboutFindLabel(
		t,
		root,
		"Theme could not be applied: theme unavailable",
	)
}

func TestSettingsDurationDayFormatRoundTripsAndRejectsOverflow(t *testing.T) {
	for _, duration := range []time.Duration{
		0,
		15 * time.Second,
		30 * 24 * time.Hour,
		-24 * time.Hour,
	} {
		formatted := formatSettingsDuration(duration)
		parsed, err := parseSettingsDuration(formatted)
		if err != nil {
			t.Fatalf("parseSettingsDuration(%q): %v", formatted, err)
		}
		if parsed != duration {
			t.Fatalf(
				"round trip %s -> %q -> %s",
				duration,
				formatted,
				parsed,
			)
		}
	}
	if _, err := parseSettingsDuration("999999999999999999d"); err == nil {
		t.Fatal("overflowing day duration was accepted")
	}
}

func TestSettingsDisablesUnavailableActions(t *testing.T) {
	test.NewTempApp(t)
	root := NewSettings(
		localization.English{},
		application.DefaultConfig(),
		SettingsActions{},
	)
	settingsAboutFindEntry(t, root, "15s").SetText("20s")

	for _, text := range []string{
		"Save settings",
		"Clear history…",
		"Open log directory",
	} {
		if button := settingsAboutFindButton(t, root, text); !button.Disabled() {
			t.Fatalf("unavailable action %q is enabled", text)
		}
	}
}

func TestAboutFormatsMetadataAndProvidesSupportActions(t *testing.T) {
	app := test.NewTempApp(t)
	info := buildinfo.Info{
		Version:   "dev",
		Commit:    "788c742cc093be834c9e34c48f053e683f9eda25",
		BuildDate: "2026-07-28T12:41:33Z",
		Dirty:     true,
		GoVersion: "go1.26.5",
		OS:        "linux",
		Arch:      "amd64",
	}
	root := NewAbout(localization.English{}, info)
	root.Resize(fyne.NewSize(1400, 800))
	test.LaidOutObjects(root)

	settingsAboutFindLabel(t, root, "28 Jul 2026, 12:41 UTC")
	settingsAboutFindLabel(t, root, "Linux/x86-64")
	settingsAboutFindLabel(t, root, "Local changes included")
	settingsAboutFindLabel(t, root, "MIT")

	copyBuild := settingsAboutFindButton(t, root, "Copy build information")
	test.Tap(copyBuild)
	copied := app.Clipboard().Content()
	for _, expected := range []string{
		info.Version,
		info.Commit,
		info.BuildDate,
		"Build state: Local changes included",
		"Platform: linux/amd64",
	} {
		if !strings.Contains(copied, expected) {
			t.Fatalf("copied build information does not contain %q:\n%s", expected, copied)
		}
	}
	feedback := settingsAboutFindLabel(t, root, "Build information copied.")
	if !feedback.Visible() {
		t.Fatal("copy action did not expose confirmation feedback")
	}

	wantLinks := map[string]string{
		"Source repository": repositoryURL,
		"Report an issue":   issueURL,
		"View MIT license":  licenseURL,
	}
	for _, object := range test.LaidOutObjects(root) {
		link, ok := object.(*widget.Hyperlink)
		if !ok {
			continue
		}
		if want, exists := wantLinks[link.Text]; exists {
			if link.URL.String() != want {
				t.Fatalf("%q URL = %q, want %q", link.Text, link.URL, want)
			}
			delete(wantLinks, link.Text)
		}
	}
	if len(wantLinks) != 0 {
		t.Fatalf("missing About links: %#v", wantLinks)
	}
}

func TestAboutPanelUsesReadableWidthAndBalancedVerticalSpace(t *testing.T) {
	test.NewTempApp(t)
	root := NewAbout(localization.English{}, buildinfo.Info{
		Version:   "1.0.0",
		Commit:    "0123456789abcdef0123456789abcdef01234567",
		BuildDate: "2026-07-28T12:41:33Z",
		GoVersion: "go1.26.5",
		OS:        "linux",
		Arch:      "amd64",
	})
	root.Resize(fyne.NewSize(1400, 900))
	test.LaidOutObjects(root)

	scroll, ok := root.(*container.Scroll)
	if !ok {
		t.Fatalf("About root = %T, want vertical scroll", root)
	}
	panel, ok := scroll.Content.(*fyne.Container)
	if !ok || len(panel.Objects) != 1 {
		t.Fatalf("About scroll content = %T with unexpected children", scroll.Content)
	}
	content := panel.Objects[0]
	if content.Size().Width > aboutMaxWidth+1 {
		t.Fatalf(
			"About content width = %.0f, want at most %.0f",
			content.Size().Width,
			float32(aboutMaxWidth),
		)
	}
	if content.Position().X < 100 {
		t.Fatalf("About content is not horizontally centered: x=%.0f", content.Position().X)
	}
	if content.Position().Y <= 0 {
		t.Fatal("About content is pinned to the top despite available vertical space")
	}
}

func settingsAboutFindButton(
	t *testing.T,
	root fyne.CanvasObject,
	text string,
) *widget.Button {
	t.Helper()
	for _, object := range test.LaidOutObjects(root) {
		if button, ok := object.(*widget.Button); ok && button.Text == text {
			return button
		}
	}
	t.Fatalf("button %q was not found", text)
	return nil
}

func settingsAboutFindEntry(
	t *testing.T,
	root fyne.CanvasObject,
	text string,
) *widget.Entry {
	t.Helper()
	for _, object := range test.LaidOutObjects(root) {
		if entry, ok := object.(*widget.Entry); ok && entry.Text == text {
			return entry
		}
	}
	t.Fatalf("entry with value %q was not found", text)
	return nil
}

func settingsAboutFindSelect(
	t *testing.T,
	root fyne.CanvasObject,
	options []string,
) *widget.Select {
	t.Helper()
	want := strings.Join(options, "\x00")
	for _, object := range test.LaidOutObjects(root) {
		if selectWidget, ok := object.(*widget.Select); ok &&
			strings.Join(selectWidget.Options, "\x00") == want {
			return selectWidget
		}
	}
	t.Fatalf("select with options %#v was not found", options)
	return nil
}

func settingsAboutFindRadio(
	t *testing.T,
	root fyne.CanvasObject,
	options []string,
) *widget.RadioGroup {
	t.Helper()
	want := strings.Join(options, "\x00")
	for _, object := range test.LaidOutObjects(root) {
		if radio, ok := object.(*widget.RadioGroup); ok &&
			strings.Join(radio.Options, "\x00") == want {
			return radio
		}
	}
	t.Fatalf("radio group with options %#v was not found", options)
	return nil
}

func settingsAboutFindLabel(
	t *testing.T,
	root fyne.CanvasObject,
	text string,
) *widget.Label {
	t.Helper()
	for _, object := range test.LaidOutObjects(root) {
		if label, ok := object.(*widget.Label); ok && label.Text == text {
			return label
		}
	}
	t.Fatalf("label %q was not found", text)
	return nil
}
