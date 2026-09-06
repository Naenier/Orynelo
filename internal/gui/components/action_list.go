package components

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

var (
	_ fyne.Accessible     = (*ActionList)(nil)
	_ fyne.DoubleTappable = (*ActionRow)(nil)
	_ fyne.Accessible     = (*ActionRow)(nil)
)

// ActionList extends a Fyne list with a keyboard and pointer activation
// contract. Enter activates the selected row, or the keyboard-highlighted row
// when the user has not made a selection yet.
//
// Fyne 2.8 does not expose a list accessibility role. The list therefore
// presents itself as descriptive text and includes the active row's label in
// its accessible name.
type ActionList struct {
	widget.List

	// OnSelected and OnUnselected mirror widget.List callbacks while allowing
	// ActionList to keep its activation and accessibility state synchronized.
	OnSelected    func(widget.ListItemID)
	OnUnselected  func(widget.ListItemID)
	OnHighlighted func(widget.ListItemID)

	// OnActivated is called for a valid row after it has been selected.
	OnActivated func(widget.ListItemID)

	// ItemAccessibilityLabel returns a self-contained label for a row. It must
	// not include secret values that are hidden elsewhere in the interface.
	ItemAccessibilityLabel func(widget.ListItemID) string

	label       string
	selected    widget.ListItemID
	highlighted widget.ListItemID
}

// NewActionList creates a list whose rows can be activated with Enter or a
// double click. The create and update callbacks receive the caller-owned row
// content; ActionList adds its event wrapper transparently.
func NewActionList(
	label string,
	length func() int,
	createItem func() fyne.CanvasObject,
	updateItem func(widget.ListItemID, fyne.CanvasObject),
) *ActionList {
	list := &ActionList{
		label:       strings.TrimSpace(label),
		selected:    -1,
		highlighted: -1,
	}
	list.Length = length
	list.CreateItem = func() fyne.CanvasObject {
		return newActionRow(createItem(), list.activate)
	}
	list.UpdateItem = func(id widget.ListItemID, object fyne.CanvasObject) {
		row, ok := object.(*ActionRow)
		if !ok {
			return
		}
		row.id = id
		if updateItem != nil {
			updateItem(id, row.Content)
		}
		row.setAccessibilityLabel(list.itemLabel(id))
	}
	list.List.OnSelected = func(id widget.ListItemID) {
		list.selected = id
		list.highlighted = id
		list.Refresh()
		if list.OnSelected != nil {
			list.OnSelected(id)
		}
	}
	list.List.OnUnselected = func(id widget.ListItemID) {
		if list.selected == id {
			list.selected = -1
		}
		list.Refresh()
		if list.OnUnselected != nil {
			list.OnUnselected(id)
		}
	}
	list.List.OnHighlighted = func(id widget.ListItemID) {
		list.highlighted = id
		list.Refresh()
		if list.OnHighlighted != nil {
			list.OnHighlighted(id)
		}
	}
	list.ExtendBaseWidget(list)
	return list
}

// CreateRenderer preserves ActionList as the extended widget after the
// embedded Fyne list has initialized its renderer.
func (list *ActionList) CreateRenderer() fyne.WidgetRenderer {
	renderer := list.List.CreateRenderer()
	list.ExtendBaseWidget(list)
	return renderer
}

// MinSize returns the embedded list's minimum size while preserving the
// extended-widget event target.
func (list *ActionList) MinSize() fyne.Size {
	minimum := list.List.MinSize()
	list.ExtendBaseWidget(list)
	return minimum
}

// TypedKey delegates navigation keys to Fyne and handles row activation.
func (list *ActionList) TypedKey(event *fyne.KeyEvent) {
	if event != nil && (event.Name == fyne.KeyEnter || event.Name == fyne.KeyReturn) {
		id := list.selected
		if !list.valid(id) {
			id = list.highlighted
		}
		list.activate(id)
		return
	}
	list.List.TypedKey(event)
}

// AccessibilityLabel returns the list name plus the selected or highlighted
// row, giving assistive technology useful context despite Fyne's limited list
// accessibility API.
func (list *ActionList) AccessibilityLabel() string {
	id := list.selected
	if !list.valid(id) {
		id = list.highlighted
	}
	item := list.itemLabel(id)
	if item == "" {
		return list.label
	}
	if list.label == "" {
		return item
	}
	return list.label + ". " + item
}

// AccessibilityRole exposes the useful list context as descriptive text.
func (*ActionList) AccessibilityRole() fyne.AccessibleRole {
	return fyne.AccessibleRoleText
}

func (list *ActionList) activate(id widget.ListItemID) {
	if !list.valid(id) {
		return
	}
	list.List.Select(id)
	if list.OnActivated != nil {
		list.OnActivated(id)
	}
}

func (list *ActionList) valid(id widget.ListItemID) bool {
	return list != nil && list.Length != nil && id >= 0 && id < list.Length()
}

func (list *ActionList) itemLabel(id widget.ListItemID) string {
	if !list.valid(id) || list.ItemAccessibilityLabel == nil {
		return ""
	}
	return strings.TrimSpace(list.ItemAccessibilityLabel(id))
}

// ActionRow wraps list content with a double-click activation target and a
// self-contained accessible label.
type ActionRow struct {
	widget.BaseWidget

	Content fyne.CanvasObject

	id                 widget.ListItemID
	onActivated        func(widget.ListItemID)
	accessibilityLabel string
}

func newActionRow(
	content fyne.CanvasObject,
	onActivated func(widget.ListItemID),
) *ActionRow {
	row := &ActionRow{
		Content:     content,
		id:          -1,
		onActivated: onActivated,
	}
	row.ExtendBaseWidget(row)
	return row
}

// DoubleTapped activates the row represented by the current recycled list
// item. The ID is refreshed whenever Fyne reuses the row widget.
func (row *ActionRow) DoubleTapped(*fyne.PointEvent) {
	if row.onActivated != nil && row.id >= 0 {
		row.onActivated(row.id)
	}
}

// AccessibilityLabel returns the self-contained row summary.
func (row *ActionRow) AccessibilityLabel() string {
	return row.accessibilityLabel
}

// AccessibilityRole exposes a list row as descriptive text.
func (*ActionRow) AccessibilityRole() fyne.AccessibleRole {
	return fyne.AccessibleRoleText
}

// CreateRenderer lets the caller-owned content fill the complete row.
func (row *ActionRow) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(row.Content)
}

func (row *ActionRow) setAccessibilityLabel(label string) {
	row.accessibilityLabel = strings.TrimSpace(label)
	row.Refresh()
}
