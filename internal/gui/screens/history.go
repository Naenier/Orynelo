package screens

import (
	"fmt"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/orynelo/internal/gui/components"
	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/gui/presenter"
)

// HistoryActions connects history operations to the application layer.
type HistoryActions struct {
	Load   func(search, status string)
	Open   func(presenter.HistoryView)
	Rerun  func(presenter.HistoryView)
	Export func(presenter.HistoryView)
	Delete func(presenter.HistoryView)
	Clear  func()
}

const (
	historyDateColumnWidth     float32 = 150
	historyTargetColumnWidth   float32 = 285
	historyStatusColumnWidth   float32 = 125
	historyDurationColumnWidth float32 = 85
	historyVersionColumnWidth  float32 = 145
	historyColumnsWidth                = historyDateColumnWidth +
		historyTargetColumnWidth +
		historyStatusColumnWidth +
		historyDurationColumnWidth +
		historyVersionColumnWidth
)

// HistoryScreen displays searchable local diagnostic history.
type HistoryScreen struct {
	Root         fyne.CanvasObject
	rows         []presenter.HistoryView
	filtered     []presenter.HistoryView
	selected     int
	search       *widget.Entry
	status       *widget.Select
	order        *widget.Select
	list         *widget.List
	listPane     fyne.CanvasObject
	columnLayout *historyColumnsLayout
	message      *widget.Label
	open         *widget.Button
	rerun        *widget.Button
	export       *widget.Button
	delete       *widget.Button
	clear        *widget.Button
	refresh      *widget.Button
	empty        fyne.CanvasObject
	emptyCard    *widget.Card
	emptyRefresh *widget.Button
	emptyClear   *widget.Button
	actionBar    fyne.CanvasObject
	actions      HistoryActions
	texts        localization.Catalog
	loading      bool
}

// NewHistory creates the History screen.
func NewHistory(texts localization.Catalog, actions HistoryActions) *HistoryScreen {
	s := &HistoryScreen{
		actions:  actions,
		selected: -1,
		texts:    localization.Normalize(texts),
	}
	s.search = widget.NewEntry()
	s.search.SetPlaceHolder(s.texts.Text(localization.HistorySearchPlaceholder))
	s.status = widget.NewSelect([]string{
		s.texts.Text(localization.HistoryFilterAll),
		s.texts.Text(localization.HistoryFilterPassed),
		s.texts.Text(localization.HistoryFilterWarning),
		s.texts.Text(localization.HistoryFilterFailed),
		s.texts.Text(localization.HistoryFilterCancelled),
	}, nil)
	s.status.SetSelected(s.texts.Text(localization.HistoryFilterAll))
	s.order = widget.NewSelect([]string{
		s.texts.Text(localization.HistoryNewestFirst),
		s.texts.Text(localization.HistoryOldestFirst),
	}, nil)
	s.order.SetSelected(s.texts.Text(localization.HistoryNewestFirst))
	s.message = widget.NewLabel("")
	s.message.Wrapping = fyne.TextWrapWord
	s.message.Hide()

	s.list = widget.NewList(
		func() int { return len(s.filtered) },
		func() fyne.CanvasObject {
			status := components.NewStatusBadge(
				s.texts,
				"pending",
				s.texts.Text(localization.HistoryNoOverallStatus),
			)
			date := widget.NewLabel(s.texts.Text(localization.HistoryCell))
			target := widget.NewLabel(s.texts.Text(localization.HistoryCell))
			target.Truncation = fyne.TextTruncateEllipsis
			duration := widget.NewLabel(s.texts.Text(localization.HistoryCell))
			version := widget.NewLabel(s.texts.Text(localization.HistoryCell))
			version.Truncation = fyne.TextTruncateEllipsis
			return container.New(
				&historyColumnsLayout{},
				date,
				target,
				status,
				duration,
				version,
			)
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(s.filtered) {
				return
			}
			row := s.filtered[id]
			cell := object.(*fyne.Container)
			status := cell.Objects[2].(*components.StatusBadge)
			cell.Objects[0].(*widget.Label).SetText(
				row.Date.Local().Format("2006-01-02 15:04:05"),
			)
			cell.Objects[1].(*widget.Label).SetText(row.Target)
			status.Set(
				row.Status,
				fmt.Sprintf(
					s.texts.Text(localization.HistoryOverallStatusFormat),
					strings.ToUpper(row.Status),
				),
			)
			cell.Objects[3].(*widget.Label).SetText(
				formatViewDuration(s.texts, row.Duration),
			)
			cell.Objects[4].(*widget.Label).SetText(row.Version)
		},
	)
	headers := make([]fyne.CanvasObject, 0, 5)
	for _, text := range []string{
		s.texts.Text(localization.HistoryColumnDate),
		s.texts.Text(localization.HistoryColumnTarget),
		s.texts.Text(localization.HistoryColumnOverallStatus),
		s.texts.Text(localization.HistoryColumnDuration),
		s.texts.Text(localization.HistoryColumnVersion),
	} {
		label := widget.NewLabelWithStyle(
			text,
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		label.Truncation = fyne.TextTruncateEllipsis
		headers = append(headers, label)
	}
	s.columnLayout = &historyColumnsLayout{}
	header := container.New(s.columnLayout, headers...)
	s.listPane = container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil,
		nil,
		nil,
		s.list,
	)
	s.list.OnSelected = func(id widget.ListItemID) {
		s.selected = id
		s.SetMessage("")
		s.updateActionState()
	}
	s.list.OnUnselected = func(id widget.ListItemID) {
		if s.selected != id {
			return
		}
		s.selected = -1
		s.updateActionState()
	}

	s.refresh = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonRefresh),
		theme.ViewRefreshIcon(),
		s.Reload,
	)
	if actions.Load == nil {
		s.refresh.Disable()
	}
	s.search.OnSubmitted = func(string) { s.Reload() }
	s.status.OnChanged = func(string) { s.Reload() }
	s.order.OnChanged = func(string) { s.applyFilterAndSort() }

	s.open = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonOpen),
		theme.FolderOpenIcon(),
		func() {
			if row, ok := s.selectedRow(); ok && actions.Open != nil {
				actions.Open(row)
			}
		},
	)
	s.open.Importance = widget.HighImportance
	s.rerun = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonRerun),
		theme.MediaReplayIcon(),
		func() {
			if row, ok := s.selectedRow(); ok && actions.Rerun != nil {
				actions.Rerun(row)
			}
		},
	)
	s.export = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonExport),
		theme.DocumentSaveIcon(),
		func() {
			if row, ok := s.selectedRow(); ok && actions.Export != nil {
				actions.Export(row)
			}
		},
	)
	s.delete = widget.NewButtonWithIcon(
		s.texts.Text(localization.HistoryDeleteSelected),
		theme.DeleteIcon(),
		func() {
			row, ok := s.selectedRow()
			if !ok || actions.Delete == nil {
				return
			}
			actions.Delete(row)
		},
	)
	s.delete.Importance = widget.DangerImportance
	s.clear = widget.NewButtonWithIcon(
		s.texts.Text(localization.HistoryClear),
		theme.ContentClearIcon(),
		func() {
			if actions.Clear == nil {
				return
			}
			actions.Clear()
		},
	)
	s.clear.Importance = widget.DangerImportance

	searchField := container.NewVBox(
		widget.NewLabelWithStyle(
			s.texts.Text(localization.HistoryColumnTarget),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		s.search,
	)
	statusField := container.NewVBox(
		widget.NewLabelWithStyle(
			s.texts.Text(localization.HistoryColumnOverallStatus),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		s.status,
	)
	orderField := container.NewVBox(
		widget.NewLabelWithStyle(
			s.texts.Text(localization.HistoryColumnDate),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		s.order,
	)
	filters := container.NewHBox(
		historyToolbarField(300, searchField),
		historyToolbarField(170, statusField),
		historyToolbarField(190, orderField),
	)
	toolbar := container.NewBorder(
		nil,
		nil,
		filters,
		container.NewVBox(layout.NewSpacer(), s.refresh),
	)
	selectionActions := container.NewHBox(s.open, s.rerun, s.export, s.delete)
	s.actionBar = container.NewBorder(nil, nil, selectionActions, s.clear)
	s.emptyRefresh = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonRefresh),
		theme.ViewRefreshIcon(),
		s.Reload,
	)
	if actions.Load == nil {
		s.emptyRefresh.Disable()
	}
	s.emptyClear = widget.NewButtonWithIcon(
		s.texts.Text(localization.HistoryClearFilters),
		theme.ContentClearIcon(),
		func() {
			s.search.SetText("")
			all := s.texts.Text(localization.HistoryFilterAll)
			if s.status.Selected != all {
				s.status.SetSelected(all)
				return
			}
			s.Reload()
		},
	)
	s.emptyClear.Hide()
	emptyAction := container.NewStack(s.emptyRefresh, s.emptyClear)
	s.emptyCard = widget.NewCard(
		s.texts.Text(localization.HistoryEmptyTitle),
		s.texts.Text(localization.HistoryEmptyHint),
		emptyAction,
	)
	s.empty = container.NewCenter(s.emptyCard)
	content := container.NewStack(s.empty, s.listPane)
	s.Root = container.NewBorder(
		container.NewVBox(toolbar, s.message),
		s.actionBar,
		nil,
		nil,
		content,
	)
	s.updateContentState()
	s.updateActionState()
	return s
}

// SetMessage displays a non-modal history status or error.
func (s *HistoryScreen) SetMessage(message string) {
	s.message.SetText(message)
	if strings.TrimSpace(message) == "" {
		s.message.Hide()
		return
	}
	s.message.Show()
}

// Reload queries history with the current target and status filters.
func (s *HistoryScreen) Reload() {
	if s.actions.Load == nil {
		s.SetRows(nil)
		return
	}
	s.SetLoading(true)
	s.actions.Load(strings.TrimSpace(s.search.Text), s.statusValue())
}

// SetLoading reflects asynchronous history work without blocking the UI.
func (s *HistoryScreen) SetLoading(loading bool) {
	s.loading = loading
	if loading {
		s.SetMessage(s.texts.Text(localization.CommonLoading))
	} else if s.message.Text == s.texts.Text(localization.CommonLoading) {
		s.SetMessage("")
	}
	s.updateActionState()
}

// SetRows replaces the loaded history entries.
func (s *HistoryScreen) SetRows(rows []presenter.HistoryView) {
	s.loading = false
	s.SetMessage("")
	s.list.UnselectAll()
	s.rows = append(s.rows[:0], rows...)
	s.selected = -1
	s.applyFilterAndSort()
}

// applyFilterAndSort derives visible rows from the loaded history snapshot.
func (s *HistoryScreen) applyFilterAndSort() {
	s.filtered = append(s.filtered[:0], s.rows...)
	newest := s.order.Selected != s.texts.Text(localization.HistoryOldestFirst)
	sort.SliceStable(s.filtered, func(i, j int) bool {
		if newest {
			return s.filtered[i].Date.After(s.filtered[j].Date)
		}
		return s.filtered[i].Date.Before(s.filtered[j].Date)
	})
	s.list.UnselectAll()
	s.selected = -1
	s.list.Refresh()
	s.updateContentState()
	s.updateActionState()
}

// selectedRow returns the currently selected visible history entry.
func (s *HistoryScreen) selectedRow() (presenter.HistoryView, bool) {
	if s.selected < 0 || s.selected >= len(s.filtered) {
		s.SetMessage(s.texts.Text(localization.HistorySelectFirst))
		return presenter.HistoryView{}, false
	}
	return s.filtered[s.selected], true
}

// updateContentState switches between loading, empty, error, and table content.
func (s *HistoryScreen) updateContentState() {
	if len(s.filtered) == 0 {
		if s.hasActiveFilter() {
			s.emptyCard.Title = s.texts.Text(localization.HistoryNoMatchesTitle)
			s.emptyCard.Subtitle = s.texts.Text(localization.HistoryNoMatchesHint)
			s.emptyRefresh.Hide()
			s.emptyClear.Show()
		} else {
			s.emptyCard.Title = s.texts.Text(localization.HistoryEmptyTitle)
			s.emptyCard.Subtitle = s.texts.Text(localization.HistoryEmptyHint)
			s.emptyClear.Hide()
			s.emptyRefresh.Show()
		}
		s.emptyCard.Refresh()
		s.list.Hide()
		s.listPane.Hide()
		s.empty.Show()
		s.actionBar.Hide()
		return
	}
	s.empty.Hide()
	s.listPane.Show()
	s.list.Show()
	s.actionBar.Show()
}

// updateActionState enables row actions only when a valid selection exists.
func (s *HistoryScreen) updateActionState() {
	hasSelection := !s.loading && s.selected >= 0 && s.selected < len(s.filtered)
	setButtonEnabled(s.open, hasSelection && s.actions.Open != nil)
	setButtonEnabled(s.rerun, hasSelection && s.actions.Rerun != nil)
	setButtonEnabled(s.export, hasSelection && s.actions.Export != nil)
	setButtonEnabled(s.delete, hasSelection && s.actions.Delete != nil)
	setButtonEnabled(s.clear, !s.loading && len(s.filtered) > 0 && s.actions.Clear != nil)
}

// hasActiveFilter reports whether search or status filters constrain the list.
func (s *HistoryScreen) hasActiveFilter() bool {
	return strings.TrimSpace(s.search.Text) != "" || s.statusValue() != "all"
}

// historyToolbarField gives a toolbar control a stable desktop width.
func historyToolbarField(width float32, object fyne.CanvasObject) fyne.CanvasObject {
	return container.NewGridWrap(
		fyne.NewSize(width, object.MinSize().Height),
		object,
	)
}

// historyColumnsLayout assigns stable proportions to the history table columns.
type historyColumnsLayout struct {
	width        float32
	targetWidth  float32
	versionWidth float32
}

// Layout positions history cells using the configured column proportions.
func (l *historyColumnsLayout) Layout(
	objects []fyne.CanvasObject,
	size fyne.Size,
) {
	if len(objects) < 5 {
		return
	}
	if size.Width != l.width {
		l.width = size.Width
		padding := theme.Size(theme.SizeNamePadding)
		flexible := size.Width -
			4*padding -
			historyDateColumnWidth -
			historyStatusColumnWidth -
			historyDurationColumnWidth
		minimumFlexible := historyTargetColumnWidth + historyVersionColumnWidth
		if flexible < minimumFlexible {
			flexible = minimumFlexible
		}
		targetWidth := flexible * 0.60
		if targetWidth < historyTargetColumnWidth {
			targetWidth = historyTargetColumnWidth
		}
		versionWidth := flexible - targetWidth
		if versionWidth < historyVersionColumnWidth {
			versionWidth = historyVersionColumnWidth
			targetWidth = flexible - versionWidth
		}
		l.targetWidth = targetWidth
		l.versionWidth = versionWidth
	}
	padding := theme.Size(theme.SizeNamePadding)
	widths := []float32{
		historyDateColumnWidth,
		l.targetWidth,
		historyStatusColumnWidth,
		historyDurationColumnWidth,
		l.versionWidth,
	}
	x := float32(0)
	for index, object := range objects[:5] {
		object.Move(fyne.NewPos(x, 0))
		object.Resize(fyne.NewSize(widths[index], size.Height))
		x += widths[index] + padding
	}
}

// MinSize returns the minimum width required by a history row.
func (*historyColumnsLayout) MinSize(
	objects []fyne.CanvasObject,
) fyne.Size {
	height := float32(0)
	for _, object := range objects {
		height = fyne.Max(height, object.MinSize().Height)
	}
	return fyne.NewSize(
		historyColumnsWidth+4*theme.Size(theme.SizeNamePadding),
		height,
	)
}

// setButtonEnabled updates a button only when it is available.
func setButtonEnabled(button *widget.Button, enabled bool) {
	if enabled {
		button.Enable()
		return
	}
	button.Disable()
}

// statusValue maps the localized status selector to the domain vocabulary.
func (s *HistoryScreen) statusValue() string {
	switch s.status.Selected {
	case s.texts.Text(localization.HistoryFilterPassed):
		return "passed"
	case s.texts.Text(localization.HistoryFilterWarning):
		return "warning"
	case s.texts.Text(localization.HistoryFilterFailed):
		return "failed"
	case s.texts.Text(localization.HistoryFilterCancelled):
		return "cancelled"
	default:
		return "all"
	}
}
