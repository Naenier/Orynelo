package components

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/gui/presenter"
)

// EvidenceGroups renders bounded, typed key/value rows grouped by concrete
// path, hop, and attempt. Full values are available in accordions and through
// explicit copy actions without allowing one long value to expand the pane.
func EvidenceGroups(
	texts localization.Catalog,
	groups []presenter.EvidenceGroupView,
	copyText func(string),
) fyne.CanvasObject {
	texts = localization.Normalize(texts)
	if len(groups) == 0 {
		return widget.NewLabel(texts.Text(localization.DiagnoseNoEvidenceRecorded))
	}
	objects := make([]fyne.CanvasObject, 0, len(groups))
	for _, group := range groups {
		titleParts := make([]string, 0, 3)
		for _, part := range []string{group.PathID, group.HopID, group.AttemptID} {
			if part != "" {
				titleParts = append(titleParts, part)
			}
		}
		if len(titleParts) == 0 {
			titleParts = append(titleParts, texts.Text(localization.DiagnoseUnattributedEvidence))
		}
		items := make([]fyne.CanvasObject, 0, len(group.Items))
		for _, evidence := range group.Items {
			heading := strings.TrimSpace(evidence.Message)
			if evidence.Code != "" {
				heading = evidence.Code + " · " + heading
			}
			rows := make([]fyne.CanvasObject, 0, len(evidence.Values)+1)
			for _, value := range evidence.Values {
				value := value
				shown := value.Display
				if value.Redacted {
					shown = texts.Text(localization.DiagnoseRedactedFact)
				}
				label := widget.NewLabel(shown)
				label.Truncation = fyne.TextTruncateEllipsis
				kind := widget.NewLabel(evidenceKindLabel(texts, value.Kind))
				kind.Importance = widget.LowImportance
				copyButton := widget.NewButtonWithIcon(texts.Text(localization.CommonCopy), theme.ContentCopyIcon(), func() {
					if copyText != nil {
						copyText(value.Full)
					}
				})
				copyButton.Importance = widget.LowImportance
				row := container.NewBorder(nil, nil,
					container.NewVBox(widget.NewLabelWithStyle(value.Key, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), kind),
					copyButton,
					label,
				)
				if value.Collapsed && !value.Redacted {
					full := widget.NewMultiLineEntry()
					full.SetText(value.Full)
					full.Wrapping = fyne.TextWrapOff
					full.SetMinRowsVisible(3)
					full.Disable()
					rows = append(rows, widget.NewAccordion(widget.NewAccordionItem(texts.Text(localization.DiagnoseViewFullValue), container.NewVScroll(full))))
				}
				rows = append(rows, row)
			}
			if len(rows) == 0 {
				rows = append(rows, widget.NewLabel(texts.Text(localization.CommonUnavailable)))
			}
			items = append(items, widget.NewCard(heading, "", container.NewVBox(rows...)))
		}
		objects = append(objects, widget.NewCard(
			fmt.Sprintf(texts.Text(localization.DiagnoseEvidenceGroupFormat), strings.Join(titleParts, " → ")),
			"", container.NewVBox(items...),
		))
	}
	return container.NewVBox(objects...)
}

func evidenceKindLabel(texts localization.Catalog, kind string) string {
	key := localization.EvidenceKindText
	switch kind {
	case "duration":
		key = localization.EvidenceKindDuration
	case "time":
		key = localization.EvidenceKindTime
	case "address":
		key = localization.EvidenceKindAddress
	case "certificate":
		key = localization.EvidenceKindCertificate
	case "header":
		key = localization.EvidenceKindHeader
	}
	return strings.ToUpper(texts.Text(key))
}
