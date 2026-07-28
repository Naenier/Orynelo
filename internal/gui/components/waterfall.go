package components

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

// TimingSegment is one measured stage in a diagnostic request.
type TimingSegment struct {
	Name     string
	Duration time.Duration
	IsTotal  bool
}

// TimingWaterfall is a lightweight timing visualization made from native Fyne
// widgets. Text is always present, so timing is not communicated by color alone.
type TimingWaterfall struct {
	*fyne.Container
	segments []TimingSegment
	texts    localization.Catalog
}

// NewTimingWaterfall creates an empty timing waterfall.
func NewTimingWaterfall(texts localization.Catalog) *TimingWaterfall {
	texts = localization.Normalize(texts)
	w := &TimingWaterfall{texts: texts}
	w.Container = container.NewVBox(widget.NewLabel(texts.Text(localization.TimingWaiting)))
	return w
}

// SetSegments replaces the displayed measurements.
func (w *TimingWaterfall) SetSegments(segments []TimingSegment) {
	w.segments = append(w.segments[:0], segments...)

	var total time.Duration
	for _, segment := range segments {
		if segment.IsTotal && segment.Duration > 0 {
			total = segment.Duration
			break
		}
	}
	if total <= 0 {
		for _, segment := range segments {
			if segment.Duration > total {
				total = segment.Duration
			}
		}
	}

	rows := make([]fyne.CanvasObject, 0, len(segments))
	for _, segment := range segments {
		duration := segment.Duration
		if duration < 0 {
			duration = 0
		}
		progress := widget.NewProgressBar()
		progress.Min = 0
		progress.Max = 1
		if total > 0 {
			progress.Value = float64(duration) / float64(total)
			if progress.Value > progress.Max {
				progress.Value = progress.Max
			}
		}
		name := segment.Name
		fraction := progress.Value
		progress.TextFormatter = func() string {
			return fmt.Sprintf(
				w.texts.Text(localization.TimingPercentFormat),
				name,
				formatDuration(duration),
				fraction*100,
			)
		}
		rows = append(rows, progress)
	}

	if len(rows) == 0 {
		rows = append(rows, widget.NewLabel(w.texts.Text(localization.TimingNoData)))
	}
	w.Objects = rows
	w.Refresh()
}

func formatDuration(duration time.Duration) string {
	if duration < time.Microsecond {
		return duration.String()
	}
	if duration < time.Second {
		return duration.Round(time.Microsecond).String()
	}
	return duration.Round(time.Millisecond).String()
}
