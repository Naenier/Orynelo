package components

import (
	"math"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/localization"
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

func TestTimingWaterfallUsesElapsedTotalAsDenominator(t *testing.T) {
	test.NewTempApp(t)
	waterfall := NewTimingWaterfall(localization.English{})
	waterfall.SetSegments([]TimingSegment{
		{Name: "DNS", Duration: 2 * time.Second},
		{Name: "TCP", Duration: 3 * time.Second},
		{Name: "TLS", Duration: 12 * time.Second},
		{Name: "Total", Duration: 10 * time.Second, IsTotal: true},
	})

	want := []float64{0.2, 0.3, 1, 1}
	for index, object := range waterfall.Objects {
		progress := object.(*widget.ProgressBar)
		if math.Abs(progress.Value-want[index]) > 0.0001 {
			t.Errorf("segment %d value = %f, want %f", index, progress.Value, want[index])
		}
	}
	total := waterfall.Objects[3].(*widget.ProgressBar)
	if text := total.TextFormatter(); !strings.Contains(text, "100% of total") {
		t.Fatalf("total label = %q", text)
	}
}
