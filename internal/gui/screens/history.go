package screens

import (
	"fmt"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/components"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
)

// HistoryActions connects history operations to the application layer.
type HistoryActions struct {
	Load   func(search, status string) ([]presenter.HistoryView, error)
	Open   func(presenter.HistoryView)
	Rerun  func(presenter.HistoryView)
	Export func(presenter.HistoryView)
	Delete func(presenter.HistoryView)
	Clear  func()
}

// HistoryScreen displays searchable local diagnostic history.
type HistoryScreen struct {
	Root     fyne.CanvasObject
	rows     []presenter.HistoryView
	filtered []presenter.HistoryView
	selected int
	search   *widget.Entry
	status   *widget.Select
	order    *widget.Select
	table    *widget.Table
	message  *widget.Label
	actions  HistoryActions
	texts    localization.Catalog
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

	s.table = widget.NewTable(
		func() (int, int) { return len(s.filtered), 5 },
		func() fyne.CanvasObject {
			status := components.NewStatusBadge(
				s.texts,
				"pending",
				s.texts.Text(localization.HistoryNoOverallStatus),
			)
			status.Hide()
			return container.NewStack(
				widget.NewLabel(s.texts.Text(localization.HistoryCell)),
				status,
			)
		},
		func(id widget.TableCellID, object fyne.CanvasObject) {
			if id.Row < 0 || id.Row >= len(s.filtered) {
				return
			}
			row := s.filtered[id.Row]
			cell := object.(*fyne.Container)
			label := cell.Objects[0].(*widget.Label)
			status := cell.Objects[1].(*components.StatusBadge)
			values := []string{
				row.Date.Local().Format("2006-01-02 15:04:05"),
				row.Target,
				strings.ToUpper(row.Status),
				formatViewDuration(s.texts, row.Duration),
				row.Version,
			}
			if id.Col == 2 {
				label.Hide()
				status.Set(
					row.Status,
					fmt.Sprintf(
						s.texts.Text(localization.HistoryOverallStatusFormat),
						values[id.Col],
					),
				)
				status.Show()
				return
			}
			status.Hide()
			label.SetText(values[id.Col])
			label.Show()
		},
	)
	s.table.ShowHeaderRow = true
	s.table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	}
	s.table.UpdateHeader = func(id widget.TableCellID, object fyne.CanvasObject) {
		if id.Row != -1 || id.Col < 0 {
			return
		}
		headers := []string{
			s.texts.Text(localization.HistoryColumnDate),
			s.texts.Text(localization.HistoryColumnTarget),
			s.texts.Text(localization.HistoryColumnOverallStatus),
			s.texts.Text(localization.HistoryColumnDuration),
			s.texts.Text(localization.HistoryColumnVersion),
		}
		if id.Col < len(headers) {
			object.(*widget.Label).SetText(headers[id.Col])
		}
	}
	s.table.SetColumnWidth(0, 175)
	s.table.SetColumnWidth(1, 360)
	s.table.SetColumnWidth(2, 135)
	s.table.SetColumnWidth(3, 100)
	s.table.SetColumnWidth(4, 140)
	s.table.OnSelected = func(id widget.TableCellID) {
		s.selected = id.Row
	}

	refresh := widget.NewButton(s.texts.Text(localization.CommonRefresh), s.Reload)
	s.search.OnSubmitted = func(string) { s.Reload() }
	s.status.OnChanged = func(string) { s.Reload() }
	s.order.OnChanged = func(string) { s.applyFilterAndSort() }

	open := widget.NewButton(s.texts.Text(localization.CommonOpen), func() {
		if row, ok := s.selectedRow(); ok && actions.Open != nil {
			actions.Open(row)
		}
	})
	rerun := widget.NewButton(s.texts.Text(localization.CommonRerun), func() {
		if row, ok := s.selectedRow(); ok && actions.Rerun != nil {
			actions.Rerun(row)
		}
	})
	export := widget.NewButton(s.texts.Text(localization.CommonExport), func() {
		if row, ok := s.selectedRow(); ok && actions.Export != nil {
			actions.Export(row)
		}
	})
	deleteSelected := widget.NewButton(s.texts.Text(localization.HistoryDeleteSelected), func() {
		row, ok := s.selectedRow()
		if !ok || actions.Delete == nil {
			return
		}
		actions.Delete(row)
	})
	clear := widget.NewButton(s.texts.Text(localization.HistoryClear), func() {
		if actions.Clear == nil {
			return
		}
		actions.Clear()
	})
	clear.Importance = widget.DangerImportance

	filters := container.NewGridWithColumns(4, s.search, s.status, s.order, refresh)
	actionsRow := container.NewHBox(open, rerun, export, deleteSelected, clear)
	s.Root = container.NewBorder(
		container.NewVBox(filters, s.message),
		actionsRow,
		nil,
		nil,
		s.table,
	)
	return s
}

// SetMessage displays a non-modal history status or error.
func (s *HistoryScreen) SetMessage(message string) {
	s.message.SetText(message)
}

// Reload queries history with the current target and status filters.
func (s *HistoryScreen) Reload() {
	if s.actions.Load == nil {
		s.SetRows(nil)
		return
	}
	rows, err := s.actions.Load(strings.TrimSpace(s.search.Text), s.statusValue())
	if err != nil {
		s.message.SetText(s.texts.Text(localization.HistoryLoadErrorPrefix) + err.Error())
		return
	}
	s.message.SetText("")
	s.SetRows(rows)
}

// SetRows replaces the loaded history entries.
func (s *HistoryScreen) SetRows(rows []presenter.HistoryView) {
	s.rows = append(s.rows[:0], rows...)
	s.selected = -1
	s.applyFilterAndSort()
}

func (s *HistoryScreen) applyFilterAndSort() {
	s.filtered = append(s.filtered[:0], s.rows...)
	newest := s.order.Selected != s.texts.Text(localization.HistoryOldestFirst)
	sort.SliceStable(s.filtered, func(i, j int) bool {
		if newest {
			return s.filtered[i].Date.After(s.filtered[j].Date)
		}
		return s.filtered[i].Date.Before(s.filtered[j].Date)
	})
	s.selected = -1
	s.table.Refresh()
}

func (s *HistoryScreen) selectedRow() (presenter.HistoryView, bool) {
	if s.selected < 0 || s.selected >= len(s.filtered) {
		s.message.SetText(s.texts.Text(localization.HistorySelectFirst))
		return presenter.HistoryView{}, false
	}
	return s.filtered[s.selected], true
}

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
