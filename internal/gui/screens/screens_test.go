package screens

import (
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/components"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
)

type overrideCatalog map[localization.Key]string

func (catalog overrideCatalog) Text(key localization.Key) string {
	if value, ok := catalog[key]; ok {
		return value
	}
	return localization.English{}.Text(key)
}

func TestDiagnoseUsesCatalogWithoutChangingDomainValues(t *testing.T) {
	test.NewTempApp(t)
	texts := overrideCatalog{
		localization.DiagnoseTargetPlaceholder: "destination",
		localization.DiagnoseRun:               "Execute checks",
		localization.OptionAuto:                "Automatic",
		localization.OptionTCP:                 "Transport",
		localization.OptionIPv6:                "Only v6",
		localization.OptionVerbose:             "Detailed",
		localization.OptionOPTIONS:             "Discover",
	}
	screen := NewDiagnose(texts, DiagnoseActions{})

	if screen.target.PlaceHolder != "destination" {
		t.Fatalf("target placeholder = %q", screen.target.PlaceHolder)
	}
	if screen.run.Text != "Execute checks" {
		t.Fatalf("run label = %q", screen.run.Text)
	}

	screen.target.SetText("example.test")
	screen.mode.SetSelected("Transport")
	screen.ipVersion.SetSelected("Only v6")
	screen.verbosity.SetSelected("Detailed")
	screen.method.SetSelected("Discover")
	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Mode != "tcp" || input.IPVersion != "6" ||
		input.Verbosity != "verbose" || input.Method != "OPTIONS" {
		t.Fatalf("localized selections produced %#v", input)
	}
}

func TestSetProfileResetsUnsafeRunOnlyControls(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.insecure.SetChecked(true)
	screen.verbosity.SetSelected("Verbose")

	screen.SetProfile(presenter.ProfileView{
		Target:       "example.test:443",
		Mode:         "tcp",
		IPVersion:    "auto",
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "GET",
	})

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Insecure {
		t.Fatal("stored profile inherited insecure TLS")
	}
	if input.Verbosity != "normal" {
		t.Fatalf("stored profile verbosity = %q, want normal", input.Verbosity)
	}
}

func TestHistoryKeepsLowercaseEnglishFilterLabels(t *testing.T) {
	test.NewTempApp(t)
	screen := NewHistory(localization.English{}, HistoryActions{})

	want := []string{"all", "passed", "warning", "failed", "cancelled"}
	if strings.Join(screen.status.Options, ",") != strings.Join(want, ",") {
		t.Fatalf("status options = %#v, want %#v", screen.status.Options, want)
	}
}

func TestSetProfileRestoresOptionsMethod(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.SetProfile(presenter.ProfileView{
		Target:       "example.test",
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		Method:       "OPTIONS",
	})

	input, err := screen.Input()
	if err != nil {
		t.Fatalf("Input() error = %v", err)
	}
	if input.Method != "OPTIONS" {
		t.Fatalf("Input().Method = %q, want OPTIONS", input.Method)
	}
}

func TestTimelineDisplaysShortResult(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.UpsertCheck(presenter.CheckView{
		ID:       "dns",
		Name:     "DNS resolution",
		Status:   "warning",
		Summary:  "No IPv6 addresses were returned.",
		Duration: time.Millisecond,
	})

	item := screen.timeline.CreateItem()
	screen.timeline.UpdateItem(0, item)
	row := item.(*fyne.Container)
	center := row.Objects[0].(*fyne.Container)
	shortResult := center.Objects[1].(*widget.Label)
	if shortResult.Text != "No IPv6 addresses were returned." {
		t.Fatalf("short result = %q", shortResult.Text)
	}
}

func TestHistoryStatusCellUsesAccessibleBadge(t *testing.T) {
	test.NewTempApp(t)
	screen := NewHistory(localization.English{}, HistoryActions{})
	screen.SetRows([]presenter.HistoryView{{
		ID:     "run-1",
		Status: "warning",
	}})

	cell := screen.table.CreateCell()
	screen.table.UpdateCell(widget.TableCellID{Row: 0, Col: 2}, cell)
	stack := cell.(*fyne.Container)
	label := stack.Objects[0].(*widget.Label)
	badge := stack.Objects[1].(*components.StatusBadge)
	if label.Visible() {
		t.Fatal("plain status label is visible")
	}
	if !badge.Visible() {
		t.Fatal("status badge is hidden")
	}
	if accessible := badge.AccessibilityLabel(); !strings.Contains(accessible, "WARNING") {
		t.Fatalf("AccessibilityLabel() = %q", accessible)
	}
}

func TestSelectedStepSeparatesTechnicalDetailsAndRawData(t *testing.T) {
	test.NewTempApp(t)
	screen := NewDiagnose(localization.English{}, DiagnoseActions{})
	screen.showCheck(presenter.CheckView{
		Name:          "TCP connection",
		Status:        "failed",
		Summary:       "Connection timed out.",
		Technical:     "Error code: TCP_TIMEOUT",
		RawStructured: `{"errorCode":"TCP_TIMEOUT"}`,
	})
	if screen.detailTechnical.Text != "Error code: TCP_TIMEOUT" {
		t.Fatalf("technical details = %q", screen.detailTechnical.Text)
	}
	if screen.detailRaw.Text != `{"errorCode":"TCP_TIMEOUT"}` {
		t.Fatalf("raw data = %q", screen.detailRaw.Text)
	}
}
