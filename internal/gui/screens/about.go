// Package screens builds the user-facing pages of the desktop application and
// exposes action callbacks without depending on backend implementations.
package screens

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/gui/localization"
)

const (
	repositoryURL = "https://github.com/Naenier/orynelo"
	issueURL      = repositoryURL + "/issues/new"
	licenseURL    = repositoryURL + "/blob/main/LICENSE"
	aboutMaxWidth = 920
)

// NewAbout builds the About screen from the same build metadata used by the
// CLI version command.
func NewAbout(texts localization.Catalog, info buildinfo.Info) fyne.CanvasObject {
	texts = localization.Normalize(texts)
	repository, _ := url.Parse(repositoryURL)
	issues, _ := url.Parse(issueURL)
	license, _ := url.Parse(licenseURL)

	buildState := texts.Text(localization.AboutBuildClean)
	if info.Dirty {
		buildState = texts.Text(localization.AboutBuildModified)
	}

	version := displayBuildValue(texts, info.Version)
	commit := displayBuildValue(texts, info.Commit)
	buildDate := friendlyBuildDate(texts, info.BuildDate)
	goVersion := displayBuildValue(texts, info.GoVersion)
	platform := fmt.Sprintf(
		texts.Text(localization.AboutPlatformFormat),
		friendlyOperatingSystem(info.OS),
		friendlyArchitecture(info.Arch),
	)
	build := container.NewGridWithColumns(
		2,
		newAboutFact(texts.Text(localization.AboutVersion), version),
		newAboutFact(texts.Text(localization.AboutPlatform), platform),
		newAboutFact(texts.Text(localization.AboutGitCommit), commit),
		newAboutFact(texts.Text(localization.AboutBuildDate), buildDate),
		newAboutFact(texts.Text(localization.AboutBuildState), buildState),
		newAboutFact(texts.Text(localization.AboutGoVersion), goVersion),
		newAboutFact(
			texts.Text(localization.AboutLicense),
			texts.Text(localization.AboutLicenseMIT),
		),
	)
	copyFeedback := widget.NewLabel("")
	copyFeedback.Importance = widget.SuccessImportance
	copyFeedback.Wrapping = fyne.TextWrapWord
	copyFeedback.Hide()
	copyBuild := widget.NewButtonWithIcon(
		texts.Text(localization.AboutCopyBuildInformation),
		theme.ContentCopyIcon(),
		func() {
			if app := fyne.CurrentApp(); app != nil {
				app.Clipboard().SetContent(buildInformationText(texts, info))
				copyFeedback.SetText(
					texts.Text(localization.AboutBuildInformationCopied),
				)
				copyFeedback.Show()
			}
		},
	)
	buildCard := widget.NewCard(
		texts.Text(localization.AboutBuildInformation),
		texts.Text(localization.AboutBuildSupportHint),
		container.NewVBox(
			build,
			widget.NewSeparator(),
			container.NewBorder(nil, nil, nil, copyBuild, copyFeedback),
		),
	)

	projectLinks := widget.NewCard(
		texts.Text(localization.AboutProjectLinks),
		texts.Text(localization.AboutProjectLinksSubtitle),
		container.NewVBox(
			widget.NewHyperlink(
				texts.Text(localization.AboutSourceRepository),
				repository,
			),
			widget.NewHyperlink(texts.Text(localization.AboutReportIssue), issues),
			widget.NewHyperlink(texts.Text(localization.AboutViewLicense), license),
		),
	)
	acknowledgements := widget.NewRichTextFromMarkdown(
		texts.Text(localization.AboutAcknowledgementsMarkdown),
	)
	acknowledgements.Wrapping = fyne.TextWrapWord
	acknowledgementsCard := widget.NewCard(
		texts.Text(localization.AboutAcknowledgements),
		"",
		acknowledgements,
	)

	name := widget.NewLabelWithStyle(
		texts.Text(localization.AppName),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	name.SizeName = theme.SizeNameHeadingText
	subtitle := widget.NewLabel(texts.Text(localization.AboutSubtitle))
	subtitle.Wrapping = fyne.TextWrapWord
	versionLabel := widget.NewLabel(fmt.Sprintf(
		"%s %s",
		texts.Text(localization.AboutVersion),
		version,
	))
	versionLabel.Importance = widget.LowImportance

	content := container.NewVBox(
		container.NewBorder(
			nil,
			nil,
			nil,
			versionLabel,
			container.NewVBox(name, subtitle),
		),
		buildCard,
		container.NewGridWithColumns(2, projectLinks, acknowledgementsCard),
	)

	return container.NewVScroll(container.New(
		aboutPanelLayout{maxWidth: aboutMaxWidth},
		content,
	))
}

// newAboutFact renders one labeled build or platform fact.
func newAboutFact(name, value string) fyne.CanvasObject {
	label := widget.NewLabelWithStyle(
		name,
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	label.Importance = widget.LowImportance
	label.SizeName = theme.SizeNameCaptionText

	detail := widget.NewLabel(value)
	detail.Selectable = true
	detail.Wrapping = fyne.TextWrapBreak
	return container.NewVBox(label, detail)
}

// buildInformationText produces the clipboard-ready version and platform summary.
func buildInformationText(
	texts localization.Catalog,
	info buildinfo.Info,
) string {
	buildState := texts.Text(localization.AboutBuildClean)
	if info.Dirty {
		buildState = texts.Text(localization.AboutBuildModified)
	}
	return strings.Join([]string{
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutVersion),
			displayBuildValue(texts, info.Version),
		),
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutGitCommit),
			displayBuildValue(texts, info.Commit),
		),
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutBuildDate),
			displayBuildValue(texts, info.BuildDate),
		),
		fmt.Sprintf("%s: %s", texts.Text(localization.AboutBuildState), buildState),
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutGoVersion),
			displayBuildValue(texts, info.GoVersion),
		),
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutPlatform),
			fmt.Sprintf(
				texts.Text(localization.AboutPlatformFormat),
				displayBuildValue(texts, info.OS),
				displayBuildValue(texts, info.Arch),
			),
		),
		fmt.Sprintf(
			"%s: %s",
			texts.Text(localization.AboutLicense),
			texts.Text(localization.AboutLicenseMIT),
		),
	}, "\n")
}

// displayBuildValue substitutes a localized placeholder for missing metadata.
func displayBuildValue(texts localization.Catalog, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") {
		return texts.Text(localization.CommonUnavailable)
	}
	return value
}

// friendlyBuildDate formats supported build timestamps for local display.
func friendlyBuildDate(texts localization.Catalog, value string) string {
	value = displayBuildValue(texts, value)
	if value == texts.Text(localization.CommonUnavailable) {
		return value
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return parsed.Format("2 Jan 2006, 15:04 MST")
}

// friendlyOperatingSystem maps Go operating-system identifiers to display names.
func friendlyOperatingSystem(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	default:
		return displayPlatformValue(value)
	}
}

// friendlyArchitecture maps Go architecture identifiers to display names.
func friendlyArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "ARM64"
	case "386":
		return "x86"
	default:
		return displayPlatformValue(value)
	}
}

// displayPlatformValue normalizes platform labels for the About screen.
func displayPlatformValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "—"
	}
	return value
}

// aboutPanelLayout constrains the About content to a readable centered width.
type aboutPanelLayout struct {
	maxWidth float32
}

// Layout centers and sizes the About panel within the available area.
func (layout aboutPanelLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, object := range objects {
		if !object.Visible() {
			continue
		}
		minimum := object.MinSize()
		width := fyne.Min(size.Width, layout.maxWidth)
		y := float32(0)
		if size.Height > minimum.Height {
			y = (size.Height - minimum.Height) / 2
		}
		object.Move(fyne.NewPos((size.Width-width)/2, y))
		object.Resize(fyne.NewSize(width, minimum.Height))
	}
}

// MinSize returns the minimum readable panel size.
func (layout aboutPanelLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	minimum := fyne.NewSize(0, 0)
	for _, object := range objects {
		if object.Visible() {
			minimum = minimum.Max(object.MinSize())
		}
	}
	minimum.Width = fyne.Min(minimum.Width, layout.maxWidth)
	return minimum
}
