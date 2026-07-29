package screens

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
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
	Root        fyne.CanvasObject
	profiles    []presenter.ProfileView
	filtered    []presenter.ProfileView
	selected    int
	search      *widget.Entry
	list        *widget.List
	message     *widget.Label
	create      *widget.Button
	edit        *widget.Button
	duplicate   *widget.Button
	delete      *widget.Button
	run         *widget.Button
	refresh     *widget.Button
	empty       fyne.CanvasObject
	emptyCard   *widget.Card
	emptyCreate *widget.Button
	emptyClear  *widget.Button
	actionBar   fyne.CanvasObject
	actions     ProfileActions
	texts       localization.Catalog
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
	s.message.Hide()
	s.list = widget.NewList(
		func() int { return len(s.filtered) },
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle(
				s.texts.Text(localization.ProfilesProfile),
				fyne.TextAlignLeading,
				fyne.TextStyle{Bold: true},
			)
			name.Truncation = fyne.TextTruncateEllipsis
			target := widget.NewLabel(s.texts.Text(localization.ProfilesTarget))
			target.Truncation = fyne.TextTruncateEllipsis
			settings := widget.NewLabel(s.texts.Text(localization.ProfilesSettings))
			settings.Truncation = fyne.TextTruncateEllipsis
			return container.NewVBox(name, target, settings)
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(s.filtered) {
				return
			}
			profile := s.filtered[id]
			box := object.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(profile.Name)
			box.Objects[1].(*widget.Label).SetText(fmt.Sprintf(
				"%s: %s",
				s.texts.Text(localization.CommonTarget),
				profile.Target,
			))
			box.Objects[2].(*widget.Label).SetText(fmt.Sprintf(
				s.texts.Text(localization.ProfilesSummaryFormat),
				profileModeLabel(s.texts, profile.Mode),
				profileIPLabel(s.texts, profile.IPVersion),
				strings.ToUpper(profile.Method),
			))
		},
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
	s.search.OnChanged = func(string) { s.applySearch() }

	createProfile := func() {
		if actions.Create != nil {
			actions.Create()
		}
	}
	s.create = widget.NewButtonWithIcon(
		s.texts.Text(localization.ProfilesCreate),
		theme.ContentAddIcon(),
		createProfile,
	)
	s.create.Importance = widget.HighImportance
	if actions.Create == nil {
		s.create.Disable()
	}
	s.edit = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonEdit),
		theme.DocumentCreateIcon(),
		func() {
			if profile, ok := s.selectedProfile(); ok && actions.Edit != nil {
				actions.Edit(profile)
			}
		},
	)
	s.duplicate = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonDuplicate),
		theme.ContentCopyIcon(),
		func() {
			profile, ok := s.selectedProfile()
			if !ok || actions.Duplicate == nil {
				return
			}
			if err := actions.Duplicate(profile); err != nil {
				s.SetMessage(
					s.texts.Text(localization.ProfilesDuplicateErrorPrefix) + err.Error(),
				)
				return
			}
			s.Reload()
		},
	)
	s.delete = widget.NewButtonWithIcon(
		s.texts.Text(localization.ProfilesDelete),
		theme.DeleteIcon(),
		func() {
			profile, ok := s.selectedProfile()
			if !ok || actions.Delete == nil {
				return
			}
			actions.Delete(profile)
		},
	)
	s.delete.Importance = widget.DangerImportance
	s.run = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonRun),
		theme.MediaPlayIcon(),
		func() {
			if profile, ok := s.selectedProfile(); ok && actions.Run != nil {
				actions.Run(profile)
			}
		},
	)
	s.run.Importance = widget.HighImportance
	s.refresh = widget.NewButtonWithIcon(
		s.texts.Text(localization.CommonRefresh),
		theme.ViewRefreshIcon(),
		s.Reload,
	)
	if actions.Load == nil {
		s.refresh.Disable()
	}

	search := container.NewGridWrap(
		fyne.NewSize(420, s.search.MinSize().Height),
		s.search,
	)
	toolbar := container.NewBorder(
		nil,
		nil,
		search,
		container.NewVBox(layout.NewSpacer(), s.refresh),
	)
	selectionActions := container.NewHBox(s.run, s.edit, s.duplicate, s.delete)
	s.actionBar = container.NewBorder(nil, nil, s.create, selectionActions)
	s.emptyCreate = widget.NewButtonWithIcon(
		s.texts.Text(localization.ProfilesCreate),
		theme.ContentAddIcon(),
		createProfile,
	)
	s.emptyCreate.Importance = widget.HighImportance
	if actions.Create == nil {
		s.emptyCreate.Disable()
	}
	s.emptyClear = widget.NewButtonWithIcon(
		s.texts.Text(localization.ProfilesClearSearch),
		theme.ContentClearIcon(),
		func() { s.search.SetText("") },
	)
	s.emptyClear.Hide()
	emptyAction := container.NewStack(s.emptyCreate, s.emptyClear)
	s.emptyCard = widget.NewCard(
		s.texts.Text(localization.ProfilesEmptyTitle),
		s.texts.Text(localization.ProfilesEmptyHint),
		emptyAction,
	)
	s.empty = container.NewCenter(s.emptyCard)
	content := container.NewStack(s.empty, s.list)
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

// SetMessage displays a non-modal profile status or error.
func (s *ProfilesScreen) SetMessage(message string) {
	s.message.SetText(message)
	if strings.TrimSpace(message) == "" {
		s.message.Hide()
		return
	}
	s.message.Show()
}

// Reload fetches profiles from the application layer.
func (s *ProfilesScreen) Reload() {
	if s.actions.Load == nil {
		s.SetProfiles(nil)
		return
	}
	profiles, err := s.actions.Load()
	if err != nil {
		s.SetMessage(s.texts.Text(localization.ProfilesLoadErrorPrefix) + err.Error())
		return
	}
	s.SetMessage("")
	s.SetProfiles(profiles)
}

// SetProfiles replaces the displayed profiles.
func (s *ProfilesScreen) SetProfiles(profiles []presenter.ProfileView) {
	s.list.UnselectAll()
	s.profiles = append(s.profiles[:0], profiles...)
	s.applySearch()
}

func (s *ProfilesScreen) applySearch() {
	s.list.UnselectAll()
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
	s.updateContentState()
	s.updateActionState()
}

func (s *ProfilesScreen) selectedProfile() (presenter.ProfileView, bool) {
	if s.selected < 0 || s.selected >= len(s.filtered) {
		s.SetMessage(s.texts.Text(localization.ProfilesSelectFirst))
		return presenter.ProfileView{}, false
	}
	return s.filtered[s.selected], true
}

func (s *ProfilesScreen) updateContentState() {
	if len(s.filtered) == 0 {
		hasUnmatchedQuery := len(s.profiles) > 0 &&
			strings.TrimSpace(s.search.Text) != ""
		if hasUnmatchedQuery {
			s.emptyCard.Title = s.texts.Text(localization.ProfilesNoMatchesTitle)
			s.emptyCard.Subtitle = s.texts.Text(localization.ProfilesNoMatchesHint)
			s.emptyCreate.Hide()
			s.emptyClear.Show()
		} else {
			s.emptyCard.Title = s.texts.Text(localization.ProfilesEmptyTitle)
			s.emptyCard.Subtitle = s.texts.Text(localization.ProfilesEmptyHint)
			s.emptyClear.Hide()
			s.emptyCreate.Show()
		}
		s.emptyCard.Refresh()
		s.list.Hide()
		s.empty.Show()
		s.actionBar.Hide()
		return
	}
	s.empty.Hide()
	s.list.Show()
	s.actionBar.Show()
}

func (s *ProfilesScreen) updateActionState() {
	hasSelection := s.selected >= 0 && s.selected < len(s.filtered)
	setButtonEnabled(s.edit, hasSelection && s.actions.Edit != nil)
	setButtonEnabled(s.duplicate, hasSelection && s.actions.Duplicate != nil)
	setButtonEnabled(s.delete, hasSelection && s.actions.Delete != nil)
	setButtonEnabled(s.run, hasSelection && s.actions.Run != nil)
}

func profileModeLabel(texts localization.Catalog, value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "":
		return texts.Text(localization.OptionAuto)
	case "tcp":
		return texts.Text(localization.OptionTCP)
	case "tls":
		return texts.Text(localization.OptionTLS)
	default:
		return strings.ToUpper(value)
	}
}

func profileIPLabel(texts localization.Catalog, value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "":
		return texts.Text(localization.OptionAuto)
	case "4", "ipv4":
		return texts.Text(localization.OptionIPv4)
	case "6", "ipv6":
		return texts.Text(localization.OptionIPv6)
	default:
		return value
	}
}
