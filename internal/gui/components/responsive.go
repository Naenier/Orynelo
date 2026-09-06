package components

import (
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
)

// NewResponsiveGrid lays out as many columns as fit while preserving a
// readable minimum width; narrow windows naturally become a single column.
func NewResponsiveGrid(minColumnWidth float32, objects ...fyne.CanvasObject) *fyne.Container {
	return container.New(responsiveGridLayout{minColumnWidth: minColumnWidth}, objects...)
}

type responsiveGridLayout struct{ minColumnWidth float32 }

func (l responsiveGridLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	visible := make([]fyne.CanvasObject, 0, len(objects))
	for _, object := range objects {
		if object.Visible() {
			visible = append(visible, object)
		}
	}
	if len(visible) == 0 {
		return
	}
	pad := theme.Padding()
	columns := int((size.Width + pad) / (l.minColumnWidth + pad))
	if columns < 1 {
		columns = 1
	}
	if columns > len(visible) {
		columns = len(visible)
	}
	rows := int(math.Ceil(float64(len(visible)) / float64(columns)))
	cellWidth := (size.Width - float32(columns-1)*pad) / float32(columns)
	cellHeight := (size.Height - float32(rows-1)*pad) / float32(rows)
	for index, object := range visible {
		column, row := index%columns, index/columns
		object.Move(fyne.NewPos(float32(column)*(cellWidth+pad), float32(row)*(cellHeight+pad)))
		object.Resize(fyne.NewSize(cellWidth, cellHeight))
	}
}

func (l responsiveGridLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var height float32
	visible := 0
	for _, object := range objects {
		if object.Visible() {
			height += object.MinSize().Height
			visible++
		}
	}
	if visible > 1 {
		height += float32(visible-1) * theme.Padding()
	}
	return fyne.NewSize(l.minColumnWidth, height)
}
