package components

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/Naenier/orynelo/internal/gui/localization"
)

func TestRawJSONViewerDocumentIsSelectableButReadOnly(t *testing.T) {
	app := test.NewTempApp(t)
	viewer := NewRawJSONViewer(localization.English{}, nil)
	viewer.SetText("{\n  \"status\": \"passed\"\n}")
	want := viewer.Text

	viewer.entry.TypedRune('x')
	viewer.entry.TypedKey(&fyne.KeyEvent{Name: fyne.KeyBackspace})
	app.Clipboard().SetContent("replacement")
	viewer.entry.TypedShortcut(&fyne.ShortcutPaste{Clipboard: app.Clipboard()})

	if viewer.entry.Text != want || viewer.Text != want {
		t.Fatalf("read-only document changed: entry=%q mirror=%q", viewer.entry.Text, viewer.Text)
	}
	if viewer.entry.AcceptsTab() {
		t.Fatal("raw JSON viewer captured Tab instead of preserving focus traversal")
	}
}
