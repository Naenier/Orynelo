package components

import (
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"

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

func TestTimingWaterfallUsesActualOffsetsAndPreservesOverlap(t *testing.T) {
	test.NewTempApp(t)
	waterfall := NewTimingWaterfall(localization.English{})
	started := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	waterfall.SetSegments([]TimingSegment{
		{Name: "DNS", AttemptID: "dns-1", Duration: 2 * time.Second, Measured: true, StartedAt: started, FinishedAt: started.Add(2 * time.Second)},
		{Name: "TCP", AttemptID: "tcp-1", Duration: 3 * time.Second, Measured: true, StartedAt: started.Add(time.Second), FinishedAt: started.Add(4 * time.Second)},
		{Name: "TLS", AttemptID: "tls-1", Duration: 2 * time.Second, Measured: true, StartedAt: started.Add(time.Second), FinishedAt: started.Add(3 * time.Second), Reused: true},
	})

	if len(waterfall.Objects) != 4 { // one shared axis and three attempt lanes
		t.Fatalf("objects = %d, want 4", len(waterfall.Objects))
	}
	dns := waterfall.Objects[1].(*fyne.Container)
	tcp := waterfall.Objects[2].(*fyne.Container)
	tls := waterfall.Objects[3].(*fyne.Container)
	for _, row := range []*fyne.Container{dns, tcp, tls} {
		row.Resize(fyne.NewSize(1000, 32))
		row.Layout.Layout(row.Objects, row.Size())
	}
	dnsBar := dns.Objects[1].(*canvas.Rectangle)
	tcpBar := tcp.Objects[1].(*canvas.Rectangle)
	tlsBar := tls.Objects[1].(*canvas.Rectangle)
	if tcpBar.Position().X <= dnsBar.Position().X {
		t.Fatalf("TCP offset %f must follow DNS offset %f", tcpBar.Position().X, dnsBar.Position().X)
	}
	if tlsBar.Position().X != tcpBar.Position().X {
		t.Fatalf("parallel attempts have different offsets: %f and %f", tlsBar.Position().X, tcpBar.Position().X)
	}
}

func TestTimingWaterfallDistinguishesUnmeasuredStage(t *testing.T) {
	test.NewTempApp(t)
	waterfall := NewTimingWaterfall(localization.English{})
	waterfall.SetSegments([]TimingSegment{
		{Name: "DNS", Duration: 0, Measured: false},
		{Name: "Total", Duration: time.Second, Measured: true, IsTotal: true},
	})

	if len(waterfall.Objects) != 1 {
		t.Fatalf("unmeasured phase should not create a misleading lane: %d objects", len(waterfall.Objects))
	}
}
