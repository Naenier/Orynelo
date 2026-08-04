package components

import (
	"math"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/localization"
)

func TestStatusBadgeExposesVisibleAndAccessibleStatus(t *testing.T) {
	test.NewTempApp(t)
	badge := NewStatusBadge(localization.English{}, "warning", "Certificate expires soon.")
	if label := badge.AccessibilityLabel(); !strings.Contains(label, "WARNING") ||
		!strings.Contains(label, "Certificate expires soon.") {
		t.Fatalf("AccessibilityLabel() = %q", label)
	}
	badge.Set("passed", "Connection succeeded.")
	if label := badge.AccessibilityLabel(); !strings.Contains(label, "PASSED") {
		t.Fatalf("updated AccessibilityLabel() = %q", label)
	}
}

func TestStatusIconKeepsAccessibleDescriptionWithoutDuplicateText(t *testing.T) {
	test.NewTempApp(t)
	icon := NewStatusIcon(localization.English{}, "failed", "The last run failed.")

	if icon.label.Visible() {
		t.Fatal("compact status icon unexpectedly renders duplicate status text")
	}
	if label := icon.AccessibilityLabel(); !strings.Contains(label, "FAILED") ||
		!strings.Contains(label, "The last run failed.") {
		t.Fatalf("AccessibilityLabel() = %q", label)
	}
}

func TestTimingWaterfallUsesElapsedTotalAsDenominator(t *testing.T) {
	test.NewTempApp(t)
	waterfall := NewTimingWaterfall(localization.English{})
	waterfall.SetSegments([]TimingSegment{
		{Name: "DNS", Duration: 2 * time.Second, Measured: true},
		{Name: "TCP", Duration: 3 * time.Second, Measured: true},
		{Name: "TLS", Duration: 12 * time.Second, Measured: true},
		{Name: "Total", Duration: 10 * time.Second, Measured: true, IsTotal: true},
	})

	want := []float64{0.2, 0.3, 1, 1}
	for index, object := range waterfall.Objects {
		row := object.(*fyne.Container)
		progress := row.Objects[0].(*widget.ProgressBar)
		if math.Abs(progress.Value-want[index]) > 0.0001 {
			t.Errorf("segment %d value = %f, want %f", index, progress.Value, want[index])
		}
	}
	totalRow := waterfall.Objects[3].(*fyne.Container)
	totalDuration := totalRow.Objects[2].(*widget.Label)
	if totalDuration.Text != "10s" {
		t.Fatalf("total duration = %q, want 10s", totalDuration.Text)
	}
}

func TestTimingWaterfallDistinguishesUnmeasuredStage(t *testing.T) {
	test.NewTempApp(t)
	waterfall := NewTimingWaterfall(localization.English{})
	waterfall.SetSegments([]TimingSegment{
		{Name: "DNS", Duration: 0, Measured: false},
		{Name: "Total", Duration: time.Second, Measured: true, IsTotal: true},
	})

	dnsRow := waterfall.Objects[0].(*fyne.Container)
	dnsDuration := dnsRow.Objects[2].(*widget.Label)
	if dnsDuration.Text != "Not measured" {
		t.Fatalf("DNS duration = %q, want Not measured", dnsDuration.Text)
	}
}
