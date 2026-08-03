// Package components contains reusable, accessible Fyne widgets used across
// OpsDoctor screens.
package components

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

var (
	_ fyne.Accessible   = (*StatusBadge)(nil)
	_ desktop.Hoverable = (*StatusBadge)(nil)
	_ fyne.Widget       = (*StatusBadge)(nil)
)

// StatusBadge displays an icon and explicit status text and exposes the full
// description both to accessibility services and as a desktop hover tooltip.
type StatusBadge struct {
	widget.BaseWidget

	icon        *widget.Icon
	label       *widget.Label
	status      string
	description string
	tooltip     *widget.PopUp
	texts       localization.Catalog
}

// NewStatusBadge creates a status display that does not rely on color alone.
func NewStatusBadge(texts localization.Catalog, status, description string) *StatusBadge {
	texts = localization.Normalize(texts)
	badge := &StatusBadge{
		icon:  widget.NewIcon(theme.QuestionIcon()),
		label: widget.NewLabel(texts.Text(localization.StatusPending)),
		texts: texts,
	}
	badge.ExtendBaseWidget(badge)
	badge.Set(status, description)
	return badge
}

// NewStatusIcon creates a compact status indicator for places where the
// adjacent control already renders the explicit status text.
func NewStatusIcon(texts localization.Catalog, status, description string) *StatusBadge {
	badge := NewStatusBadge(texts, status, description)
	badge.label.Hide()
	return badge
}

// StatusLabel retains the simple factory used by summary and detail panels.
func StatusLabel(texts localization.Catalog, status, description string) fyne.CanvasObject {
	return NewStatusBadge(texts, status, description)
}

// Set updates the visible status and accessible description.
func (b *StatusBadge) Set(status, description string) {
	b.MouseOut()
	b.status = strings.ToLower(strings.TrimSpace(status))
	b.description = strings.TrimSpace(description)
	b.icon.SetResource(statusIcon(b.status))
	b.label.SetText(b.texts.Text(localization.StatusKey(b.status)))
	b.Refresh()
}

// AccessibilityLabel provides the same information as the visible status and
// hover tooltip.
func (b *StatusBadge) AccessibilityLabel() string {
	if b.description == "" {
		return b.texts.Text(localization.StatusKey(b.status))
	}
	return fmt.Sprintf(
		b.texts.Text(localization.StatusAccessibleFormat),
		b.texts.Text(localization.StatusKey(b.status)),
		b.description,
	)
}

// AccessibilityRole identifies the badge as descriptive text.
func (*StatusBadge) AccessibilityRole() fyne.AccessibleRole {
	return fyne.AccessibleRoleText
}

// MouseIn displays the required status tooltip on desktop platforms.
func (b *StatusBadge) MouseIn(*desktop.MouseEvent) {
	if b.description == "" || b.tooltip != nil {
		return
	}
	app := fyne.CurrentApp()
	if app == nil {
		return
	}
	canvas := app.Driver().CanvasForObject(b)
	if canvas == nil {
		return
	}
	b.tooltip = widget.NewPopUp(widget.NewLabel(b.description), canvas)
	b.tooltip.ShowAtRelativePosition(fyne.NewPos(0, b.Size().Height), b)
}

// MouseMoved satisfies desktop.Hoverable; the tooltip remains anchored.
func (*StatusBadge) MouseMoved(*desktop.MouseEvent) {}

// MouseOut dismisses the desktop status tooltip.
func (b *StatusBadge) MouseOut() {
	if b.tooltip == nil {
		return
	}
	b.tooltip.Hide()
	b.tooltip = nil
}

// CreateRenderer renders the icon and explicit status text.
func (b *StatusBadge) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(container.NewHBox(b.icon, b.label))
}

// statusIcon selects the theme resource associated with a domain status.
func statusIcon(status string) fyne.Resource {
	switch status {
	case "passed":
		return theme.ConfirmIcon()
	case "warning":
		return theme.WarningIcon()
	case "failed":
		return theme.ErrorIcon()
	case "running":
		return theme.ViewRefreshIcon()
	case "cancelled":
		return theme.CancelIcon()
	case "skipped", "not_applicable":
		return theme.MediaSkipNextIcon()
	default:
		return theme.QuestionIcon()
	}
}
