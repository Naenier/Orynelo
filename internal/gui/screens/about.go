package screens

import (
	"fmt"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

const repositoryURL = "https://github.com/Naenier/opsdoctor"

// NewAbout builds the About screen from the same build metadata used by the
// CLI version command.
func NewAbout(texts localization.Catalog, info buildinfo.Info) fyne.CanvasObject {
	texts = localization.Normalize(texts)
	repository, _ := url.Parse(repositoryURL)
	dirty := texts.Text(localization.CommonNo)
	if info.Dirty {
		dirty = texts.Text(localization.CommonYes)
	}
	build := widget.NewForm(
		widget.NewFormItem(texts.Text(localization.AboutVersion), widget.NewLabel(info.Version)),
		widget.NewFormItem(texts.Text(localization.AboutGitCommit), widget.NewLabel(info.Commit)),
		widget.NewFormItem(texts.Text(localization.AboutBuildDate), widget.NewLabel(info.BuildDate)),
		widget.NewFormItem(texts.Text(localization.AboutDirtyTree), widget.NewLabel(dirty)),
		widget.NewFormItem(texts.Text(localization.AboutGoVersion), widget.NewLabel(info.GoVersion)),
		widget.NewFormItem(
			texts.Text(localization.AboutPlatform),
			widget.NewLabel(fmt.Sprintf(
				texts.Text(localization.AboutPlatformFormat),
				info.OS,
				info.Arch,
			)),
		),
		widget.NewFormItem(
			texts.Text(localization.AboutLicense),
			widget.NewLabel(texts.Text(localization.AboutLicenseMIT)),
		),
	)
	acknowledgements := widget.NewRichTextFromMarkdown(
		texts.Text(localization.AboutAcknowledgementsMarkdown),
	)
	return container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle(
			texts.Text(localization.AppName),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		widget.NewLabel(texts.Text(localization.AboutSubtitle)),
		widget.NewCard(texts.Text(localization.AboutBuildInformation), "", build),
		widget.NewHyperlink(texts.Text(localization.AboutSourceRepository), repository),
		widget.NewCard(texts.Text(localization.AboutAcknowledgements), "", acknowledgements),
	))
}
