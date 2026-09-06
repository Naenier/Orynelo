package components

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/localization"
)

// TimingSegment is one attributable phase placed on a real elapsed-time axis.
// Timestamp-free legacy measurements remain visible as unplaced text and are
// never misrepresented as a percentage of total duration.
type TimingSegment struct {
	Name       string
	Duration   time.Duration
	Measured   bool
	IsTotal    bool
	StartedAt  time.Time
	FinishedAt time.Time
	AttemptID  string
	Reused     bool
}

// TimingWaterfall renders one lane per measured phase using actual offsets.
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

// SetSegments replaces the displayed measurements and derives one common
// origin/span from real timestamps, preserving overlaps and reused attempts.
func (w *TimingWaterfall) SetSegments(segments []TimingSegment) {
	w.segments = append(w.segments[:0], segments...)
	var origin, finish time.Time
	for _, segment := range segments {
		if !segment.Measured || segment.StartedAt.IsZero() || segment.FinishedAt.IsZero() {
			continue
		}
		if origin.IsZero() || segment.StartedAt.Before(origin) {
			origin = segment.StartedAt
		}
		if finish.IsZero() || segment.FinishedAt.After(finish) {
			finish = segment.FinishedAt
		}
	}
	span := finish.Sub(origin)
	rows := make([]fyne.CanvasObject, 0, len(segments)+1)
	if span > 0 {
		axis := widget.NewLabel(fmt.Sprintf(
			w.texts.Text(localization.TimingAxisFormat),
			localization.FormatDuration(w.texts, span),
		))
		axis.Alignment = fyne.TextAlignTrailing
		axis.Importance = widget.LowImportance
		rows = append(rows, axis)
	}
	for _, segment := range segments {
		if !segment.Measured {
			continue
		}
		duration := segment.Duration
		if !segment.StartedAt.IsZero() && !segment.FinishedAt.IsZero() {
			duration = segment.FinishedAt.Sub(segment.StartedAt)
		}
		nameText := segment.Name
		if segment.AttemptID != "" {
			nameText += " · " + segment.AttemptID
		}
		if segment.Reused {
			nameText += " · " + w.texts.Text(localization.TimingReused)
		}
		name := widget.NewLabel(nameText)
		name.Truncation = fyne.TextTruncateEllipsis
		measured := widget.NewLabel(localization.FormatDuration(w.texts, nonNegativeDuration(duration)))
		measured.Alignment = fyne.TextAlignTrailing
		if span <= 0 || segment.StartedAt.IsZero() || segment.FinishedAt.IsZero() {
			rows = append(rows, container.NewBorder(nil, nil, name, measured))
			continue
		}
		bar := canvas.NewRectangle(theme.PrimaryColor())
		bar.CornerRadius = theme.Padding()
		bar.SetMinSize(fyne.NewSize(2, theme.Padding()*2))
		rows = append(rows, container.New(waterfallRowLayout{
			offset:   segment.StartedAt.Sub(origin),
			duration: duration,
			span:     span,
		}, name, bar, measured))
	}
	if len(rows) == 0 {
		rows = append(rows, widget.NewLabel(w.texts.Text(localization.TimingNoData)))
	}
	w.Objects = rows
	w.Refresh()
}

type waterfallRowLayout struct {
	offset   time.Duration
	duration time.Duration
	span     time.Duration
}

func (l waterfallRowLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) != 3 {
		return
	}
	pad := theme.Padding()
	left := fyne.Min(float32(220), size.Width*.34)
	right := fyne.Min(float32(110), size.Width*.22)
	trackX := left + pad
	trackWidth := fyne.Max(1, size.Width-left-right-2*pad)
	objects[0].Move(fyne.NewPos(0, 0))
	objects[0].Resize(fyne.NewSize(left, size.Height))
	start, width := float32(0), float32(1)
	if l.span > 0 {
		start = float32(float64(l.offset)/float64(l.span)) * trackWidth
		width = fyne.Max(2, float32(float64(nonNegativeDuration(l.duration))/float64(l.span))*trackWidth)
	}
	objects[1].Move(fyne.NewPos(trackX+start, size.Height*.3))
	objects[1].Resize(fyne.NewSize(fyne.Min(width, trackWidth-start), size.Height*.4))
	objects[2].Move(fyne.NewPos(size.Width-right, 0))
	objects[2].Resize(fyne.NewSize(right, size.Height))
}

func (waterfallRowLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	height := float32(28)
	for _, object := range objects {
		height = fyne.Max(height, object.MinSize().Height)
	}
	return fyne.NewSize(360, height)
}

func nonNegativeDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}

// formatDuration renders compact, human-readable timing labels.
func formatDuration(duration time.Duration) string {
	if duration < time.Microsecond {
		return duration.String()
	}
	if duration < time.Second {
		return duration.Round(time.Microsecond).String()
	}
	return duration.Round(time.Millisecond).String()
}
