package components

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/localization"
)

// RawJSONViewer is a bounded monospace-style structured-data viewer with
// search, wrapping, and explicit copy controls.
type RawJSONViewer struct {
	*fyne.Container
	// Text mirrors the complete document for compatibility with existing
	// screen-level assertions and non-widget consumers.
	Text   string
	entry  *selectableReadOnlyEntry
	search *widget.Entry
	status *widget.Label
	value  string
	texts  localization.Catalog
}

// NewRawJSONViewer creates an empty viewer.
func NewRawJSONViewer(texts localization.Catalog, copyText func(string)) *RawJSONViewer {
	texts = localization.Normalize(texts)
	v := &RawJSONViewer{texts: texts}
	v.entry = newSelectableReadOnlyEntry()
	v.entry.TextStyle = fyne.TextStyle{Monospace: true}
	v.entry.Wrapping = fyne.TextWrapOff
	v.entry.SetMinRowsVisible(10)
	v.search = widget.NewEntry()
	v.search.SetPlaceHolder(texts.Text(localization.DiagnoseSearchJSON))
	v.status = widget.NewLabel("")
	v.status.Importance = widget.LowImportance
	v.search.OnChanged = func(query string) { v.updateSearch(query, texts) }
	wrap := widget.NewCheck(texts.Text(localization.DiagnoseWrapJSON), func(enabled bool) {
		if enabled {
			v.entry.Wrapping = fyne.TextWrapWord
		} else {
			v.entry.Wrapping = fyne.TextWrapOff
		}
		v.entry.Refresh()
	})
	copyButton := widget.NewButtonWithIcon(texts.Text(localization.CommonCopy), theme.ContentCopyIcon(), func() {
		if copyText != nil {
			copyText(v.value)
		}
	})
	toolbar := container.NewBorder(nil, nil, v.search, container.NewHBox(wrap, copyButton), v.status)
	v.Container = container.NewBorder(toolbar, nil, nil, nil, container.NewVScroll(v.entry))
	return v
}

// selectableReadOnlyEntry keeps the native Entry selection and navigation
// behavior without allowing typed text, paste, cut, or context-menu edits.
type selectableReadOnlyEntry struct {
	widget.Entry
}

func newSelectableReadOnlyEntry() *selectableReadOnlyEntry {
	entry := &selectableReadOnlyEntry{}
	entry.MultiLine = true
	entry.Wrapping = fyne.TextWrapOff
	entry.ExtendBaseWidget(entry)
	return entry
}

func (*selectableReadOnlyEntry) AcceptsTab() bool { return false }

func (*selectableReadOnlyEntry) TypedRune(rune) {}

func (entry *selectableReadOnlyEntry) TypedKey(event *fyne.KeyEvent) {
	switch event.Name {
	case fyne.KeyUp, fyne.KeyDown, fyne.KeyLeft, fyne.KeyRight,
		fyne.KeyHome, fyne.KeyEnd, fyne.KeyPageUp, fyne.KeyPageDown:
		entry.Entry.TypedKey(event)
	}
}

func (entry *selectableReadOnlyEntry) TypedShortcut(shortcut fyne.Shortcut) {
	switch shortcut.(type) {
	case *fyne.ShortcutCopy, *fyne.ShortcutSelectAll:
		entry.Entry.TypedShortcut(shortcut)
	}
}

func (*selectableReadOnlyEntry) TappedSecondary(*fyne.PointEvent) {}

// SetText replaces the complete selectable document.
func (v *RawJSONViewer) SetText(value string) {
	v.Text = value
	v.value = value
	v.entry.SetText(value)
	v.updateSearch(v.search.Text, v.texts)
}

func (v *RawJSONViewer) updateSearch(query string, texts localization.Catalog) {
	query = strings.TrimSpace(query)
	if query == "" {
		v.status.SetText("")
		return
	}
	count := strings.Count(strings.ToLower(v.value), strings.ToLower(query))
	v.status.SetText(fmt.Sprintf(texts.Text(localization.DiagnoseSearchMatchesFormat), count))
}
