package screens

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
)

// ProfileActions connects profile operations to the application layer.
type ProfileActions struct {
	Load      func() ([]presenter.ProfileView, error)
	Create    func()
	Edit      func(presenter.ProfileView)
	Duplicate func(presenter.ProfileView) error
	Delete    func(presenter.ProfileView)
	Run       func(presenter.ProfileView)
}

// ProfilesScreen displays reusable, non-secret diagnostic profiles.
type ProfilesScreen struct {
	Root     fyne.CanvasObject
	profiles []presenter.ProfileView
	filtered []presenter.ProfileView
	selected int
	search   *widget.Entry
	list     *widget.List
	message  *widget.Label
	actions  ProfileActions
	texts    localization.Catalog
}

// NewProfiles creates the Profiles screen.
func NewProfiles(texts localization.Catalog, actions ProfileActions) *ProfilesScreen {
	s := &ProfilesScreen{
		actions:  actions,
		selected: -1,
		texts:    localization.Normalize(texts),
	}
	s.search = widget.NewEntry()
	s.search.SetPlaceHolder(s.texts.Text(localization.ProfilesSearchPlaceholder))
	s.message = widget.NewLabel("")
	s.message.Wrapping = fyne.TextWrapWord
	s.list = widget.NewList(
		func() int { return len(s.filtered) },
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabelWithStyle(
					s.texts.Text(localization.ProfilesProfile),
					fyne.TextAlignLeading,
					fyne.TextStyle{Bold: true},
				),
				widget.NewLabel(s.texts.Text(localization.ProfilesTarget)),
				widget.NewLabel(s.texts.Text(localization.ProfilesSettings)),
			)
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(s.filtered) {
				return
			}
			profile := s.filtered[id]
			box := object.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(profile.Name)
			box.Objects[1].(*widget.Label).SetText(profile.Target)
			box.Objects[2].(*widget.Label).SetText(fmt.Sprintf(
				s.texts.Text(localization.ProfilesSummaryFormat),
				profile.Mode,
				profile.IPVersion,
				profile.Method,
			))
		},
	)
	s.list.OnSelected = func(id widget.ListItemID) { s.selected = id }
	s.search.OnChanged = func(string) { s.applySearch() }

	create := widget.NewButton(s.texts.Text(localization.ProfilesCreate), func() {
		if actions.Create != nil {
			actions.Create()
		}
	})
	create.Importance = widget.HighImportance
	edit := widget.NewButton(s.texts.Text(localization.CommonEdit), func() {
		if profile, ok := s.selectedProfile(); ok && actions.Edit != nil {
			actions.Edit(profile)
		}
	})
	duplicate := widget.NewButton(s.texts.Text(localization.CommonDuplicate), func() {
		profile, ok := s.selectedProfile()
		if !ok || actions.Duplicate == nil {
			return
		}
		if err := actions.Duplicate(profile); err != nil {
			s.message.SetText(
				s.texts.Text(localization.ProfilesDuplicateErrorPrefix) + err.Error(),
			)
			return
		}
		s.Reload()
	})
	deleteSelected := widget.NewButton(s.texts.Text(localization.ProfilesDelete), func() {
		profile, ok := s.selectedProfile()
		if !ok || actions.Delete == nil {
			return
		}
		actions.Delete(profile)
	})
	run := widget.NewButton(s.texts.Text(localization.CommonRun), func() {
		if profile, ok := s.selectedProfile(); ok && actions.Run != nil {
			actions.Run(profile)
		}
	})
	run.Importance = widget.HighImportance
	refresh := widget.NewButton(s.texts.Text(localization.CommonRefresh), s.Reload)

	s.Root = container.NewBorder(
		container.NewBorder(nil, nil, s.search, refresh, s.message),
		container.NewHBox(create, edit, duplicate, deleteSelected, run),
		nil,
		nil,
		s.list,
	)
	return s
}

// SetMessage displays a non-modal profile status or error.
func (s *ProfilesScreen) SetMessage(message string) {
	s.message.SetText(message)
}

// Reload fetches profiles from the application layer.
func (s *ProfilesScreen) Reload() {
	if s.actions.Load == nil {
		s.SetProfiles(nil)
		return
	}
	profiles, err := s.actions.Load()
	if err != nil {
		s.message.SetText(s.texts.Text(localization.ProfilesLoadErrorPrefix) + err.Error())
		return
	}
	s.message.SetText("")
	s.SetProfiles(profiles)
}

// SetProfiles replaces the displayed profiles.
func (s *ProfilesScreen) SetProfiles(profiles []presenter.ProfileView) {
	s.profiles = append(s.profiles[:0], profiles...)
	s.applySearch()
}

func (s *ProfilesScreen) applySearch() {
	query := strings.ToLower(strings.TrimSpace(s.search.Text))
	s.filtered = s.filtered[:0]
	for _, profile := range s.profiles {
		if query == "" ||
			strings.Contains(strings.ToLower(profile.Name), query) ||
			strings.Contains(strings.ToLower(profile.Target), query) {
			s.filtered = append(s.filtered, profile)
		}
	}
	s.selected = -1
	s.list.Refresh()
}

func (s *ProfilesScreen) selectedProfile() (presenter.ProfileView, bool) {
	if s.selected < 0 || s.selected >= len(s.filtered) {
		s.message.SetText(s.texts.Text(localization.ProfilesSelectFirst))
		return presenter.ProfileView{}, false
	}
	return s.filtered[s.selected], true
}
