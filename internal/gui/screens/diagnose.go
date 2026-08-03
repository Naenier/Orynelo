package screens

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/components"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
)

// DiagnoseActions connects user interactions to the GUI controller.
type DiagnoseActions struct {
	Run            func(presenter.DiagnoseInput)
	InputError     func(error)
	Cancel         func()
	CopySummary    func()
	ExportJSON     func()
	ExportMarkdown func()
	SaveProfile    func()
	CopyStep       func(presenter.CheckView)
}

// DiagnoseScreen owns the mutable widgets of the main diagnostic screen.
type DiagnoseScreen struct {
	Root fyne.CanvasObject

	content                *fyne.Container
	target                 *widget.Entry
	mode                   *widget.Select
	ipVersion              *widget.Select
	timeout                *widget.Entry
	checkTimeout           *widget.Entry
	method                 *widget.Select
	noProxy                *widget.Check
	insecure               *widget.Check
	allowInsecureRedirects *widget.Check
	allowPrivateRedirects  *widget.Check
	maxRedirects           *widget.Entry
	verbosity              *widget.Select
	run                    *widget.Button
	cancel                 *widget.Button
	postActions            *fyne.Container
	inputError             *widget.Label
	inputErrorRow          *fyne.Container
	inputViewport          *container.Scroll
	inputCard              *widget.Card
	advancedToggle         *widget.Button
	advancedFields         *fyne.Container
	inputCollapsed         float32
	advancedExpanded       bool
	idleState              fyne.CanvasObject
	resultView             fyne.CanvasObject
	overview               *fyne.Container
	overviewViewport       *container.Scroll
	overviewFooter         *fyne.Container
	resultPanels           *container.Split
	explorer               *container.Split
	timelineCard           *widget.Card
	detailsCard            *widget.Card
	summaryTitle           *widget.Label
	summaryTarget          *widget.Label
	summaryDetail          *widget.Label
	summaryStatus          *fyne.Container
	summaryNextStep        *fyne.Container
	summaryNextText        *widget.Label
	activity               *widget.ProgressBarInfinite
	timingDisclosure       *widget.Accordion
	timeline               *widget.List
	checks                 []presenter.CheckView
	selectedCheck          int
	detailTitle            *widget.Label
	detailStatus           *fyne.Container
	detailTiming           *widget.Label
	detailSummary          *widget.Label
	detailEvidence         *widget.Label
	detailRecommend        *widget.Label
	detailTechnical        *widget.Label
	detailRaw              *widget.Entry
	detailsViewport        *container.Scroll
	recommendSection       *fyne.Container
	technicalSections      *widget.Accordion
	waterfall              *components.TimingWaterfall
	actions                DiagnoseActions
	texts                  localization.Catalog
	running                bool
}

// NewDiagnose creates the responsive Diagnose screen.
func NewDiagnose(texts localization.Catalog, actions DiagnoseActions) *DiagnoseScreen {
	screen := &DiagnoseScreen{
		actions:       actions,
		selectedCheck: -1,
		texts:         localization.Normalize(texts),
	}
	screen.buildInputs()
	screen.buildResults()
	return screen
}

func (s *DiagnoseScreen) buildInputs() {
	s.target = widget.NewEntry()
	s.target.SetPlaceHolder(s.texts.Text(localization.DiagnoseTargetPlaceholder))
	s.mode = widget.NewSelect([]string{
		s.texts.Text(localization.OptionAuto),
		s.texts.Text(localization.OptionTCP),
		s.texts.Text(localization.OptionTLS),
	}, nil)
	s.mode.SetSelected(s.texts.Text(localization.OptionAuto))
	s.ipVersion = widget.NewSelect([]string{
		s.texts.Text(localization.OptionAuto),
		s.texts.Text(localization.OptionIPv4),
		s.texts.Text(localization.OptionIPv6),
	}, nil)
	s.ipVersion.SetSelected(s.texts.Text(localization.OptionAuto))
	s.timeout = widget.NewEntry()
	s.timeout.SetText(s.texts.Text(localization.DiagnoseDefaultTimeout))
	s.checkTimeout = widget.NewEntry()
	s.checkTimeout.SetText(s.texts.Text(localization.DiagnoseDefaultCheckTimeout))
	s.method = widget.NewSelect([]string{
		s.texts.Text(localization.OptionGET),
		s.texts.Text(localization.OptionHEAD),
		s.texts.Text(localization.OptionOPTIONS),
	}, nil)
	s.method.SetSelected(s.texts.Text(localization.OptionGET))
	s.noProxy = widget.NewCheck(s.texts.Text(localization.CommonDisableProxy), nil)
	s.insecure = widget.NewCheck(s.texts.Text(localization.DiagnoseInsecureTLS), nil)
	s.allowInsecureRedirects = widget.NewCheck(
		s.texts.Text(localization.DiagnoseAllowInsecureRedirects),
		nil,
	)
	s.allowPrivateRedirects = widget.NewCheck(
		s.texts.Text(localization.DiagnoseAllowPrivateRedirects),
		nil,
	)
	s.maxRedirects = widget.NewEntry()
	s.maxRedirects.SetText(s.texts.Text(localization.DiagnoseDefaultMaxRedirects))
	s.verbosity = widget.NewSelect([]string{
		s.texts.Text(localization.OptionNormal),
		s.texts.Text(localization.OptionVerbose),
	}, nil)
	s.verbosity.SetSelected(s.texts.Text(localization.OptionNormal))
	s.inputError = widget.NewLabel("")
	s.inputError.Wrapping = fyne.TextWrapWord
	s.inputErrorRow = container.NewBorder(
		nil,
		nil,
		widget.NewIcon(theme.ErrorIcon()),
		nil,
		s.inputError,
	)
	s.inputErrorRow.Hide()

	s.run = widget.NewButton(s.texts.Text(localization.DiagnoseRun), s.triggerRun)
	s.run.Importance = widget.HighImportance
	s.cancel = widget.NewButton(s.texts.Text(localization.CommonCancel), func() {
		if s.actions.Cancel != nil {
			s.actions.Cancel()
		}
	})
	s.cancel.Importance = widget.DangerImportance
	s.cancel.Hide()

	actionSlot := container.NewStack(s.run, s.cancel)
	targetHeader := container.NewBorder(
		nil,
		nil,
		widget.NewLabelWithStyle(
			s.texts.Text(localization.CommonTarget),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		widget.NewLabel(s.texts.Text(localization.DiagnoseRunShortcutHint)),
	)
	targetLine := container.NewBorder(
		nil,
		nil,
		nil,
		actionSlot,
		s.target,
	)
	field := func(label string, control fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(
			widget.NewLabel(label),
			control,
		)
	}
	basicOptions := container.NewGridWithColumns(3,
		field(s.texts.Text(localization.CommonMode), s.mode),
		field(s.texts.Text(localization.CommonIP), s.ipVersion),
		field(s.texts.Text(localization.CommonTimeout), s.timeout),
	)
	s.advancedFields = container.NewVBox(
		container.NewGridWithColumns(2,
			field(s.texts.Text(localization.CommonHTTPMethod), s.method),
			field(s.texts.Text(localization.CommonPerCheckTimeout), s.checkTimeout),
			field(s.texts.Text(localization.CommonMaximumRedirects), s.maxRedirects),
			field(s.texts.Text(localization.DiagnoseReportVerbosity), s.verbosity),
		),
		container.NewVBox(
			container.NewHBox(s.noProxy, s.insecure),
			s.allowInsecureRedirects,
			s.allowPrivateRedirects,
		),
	)
	s.advancedFields.Hide()
	s.advancedToggle = widget.NewButtonWithIcon(
		s.texts.Text(localization.DiagnoseAdvancedOptions),
		theme.MenuDropDownIcon(),
		func() {
			s.setAdvancedExpanded(!s.advancedExpanded)
		},
	)
	s.advancedToggle.Alignment = widget.ButtonAlignLeading
	s.advancedToggle.IconPlacement = widget.ButtonIconLeadingText
	s.advancedToggle.Importance = widget.LowImportance

	s.content = container.NewStack()
	s.inputCard = widget.NewCard(
		"",
		"",
		container.NewVBox(
			targetHeader,
			targetLine,
			basicOptions,
			s.advancedToggle,
			s.advancedFields,
			s.inputErrorRow,
		),
	)
	s.inputCollapsed = s.inputCard.MinSize().Height
	s.inputViewport = container.NewVScroll(s.inputCard)
	s.Root = container.New(
		diagnoseRootLayout{screen: s},
		s.inputViewport,
		s.content,
	)
}

func (s *DiagnoseScreen) buildResults() {
	s.summaryTarget = widget.NewLabel("")
	s.summaryTarget.Truncation = fyne.TextTruncateEllipsis
	s.summaryTitle = widget.NewLabelWithStyle(
		s.texts.Text(localization.DiagnoseReadyTitle),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	s.summaryDetail = widget.NewLabel(s.texts.Text(localization.DiagnoseReadyDetail))
	s.summaryDetail.Wrapping = fyne.TextWrapWord
	s.summaryStatus = container.NewVBox()
	s.summaryNextText = widget.NewLabel("")
	s.summaryNextText.Wrapping = fyne.TextWrapWord
	s.summaryNextStep = container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle(
			s.texts.Text(localization.DiagnoseRecommendedNextStep),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		s.summaryNextText,
	)
	s.summaryNextStep.Hide()
	summaryHeading := container.NewBorder(
		nil,
		nil,
		s.summaryStatus,
		nil,
		s.summaryTitle,
	)
	summary := widget.NewCard(
		"",
		"",
		container.NewVBox(
			s.summaryTarget,
			summaryHeading,
			s.summaryDetail,
			s.summaryNextStep,
		),
	)

	s.timeline = widget.NewList(
		func() int { return len(s.checks) },
		func() fyne.CanvasObject {
			shortResult := widget.NewLabel(
				s.texts.Text(localization.DiagnoseShortResult),
			)
			shortResult.Truncation = fyne.TextTruncateEllipsis
			duration := widget.NewLabel(
				s.texts.Text(localization.DiagnoseZeroDuration),
			)
			duration.Alignment = fyne.TextAlignTrailing
			return container.NewBorder(
				nil,
				nil,
				components.NewStatusBadge(
					s.texts,
					"pending",
					s.texts.Text(localization.DiagnoseCheckNotStarted),
				),
				duration,
				container.NewVBox(
					widget.NewLabelWithStyle(
						s.texts.Text(localization.DiagnoseCheck),
						fyne.TextAlignLeading,
						fyne.TextStyle{Bold: true},
					),
					shortResult,
				),
			)
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(s.checks) {
				return
			}
			check := s.checks[id]
			row := object.(*fyne.Container)
			center := row.Objects[0].(*fyne.Container)
			left := row.Objects[1].(*components.StatusBadge)
			right := row.Objects[2].(*widget.Label)
			left.Set(check.Status, check.Summary)
			center.Objects[0].(*widget.Label).SetText(check.Name)
			center.Objects[1].(*widget.Label).SetText(check.Summary)
			right.SetText(formatViewDuration(s.texts, check.Duration))
		},
	)
	s.timeline.OnSelected = func(id widget.ListItemID) {
		if id >= 0 && id < len(s.checks) {
			s.selectedCheck = id
			s.showCheck(s.checks[id])
			s.detailsViewport.ScrollToTop()
		}
	}

	s.detailTitle = widget.NewLabelWithStyle(
		s.texts.Text(localization.DiagnoseSelectStep),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	s.detailStatus = container.NewVBox()
	s.detailTiming = widget.NewLabel("")
	s.detailSummary = widget.NewLabel("")
	s.detailSummary.Wrapping = fyne.TextWrapWord
	s.detailEvidence = widget.NewLabel(s.texts.Text(localization.DiagnoseNoEvidenceSelected))
	s.detailEvidence.Wrapping = fyne.TextWrapWord
	s.detailRecommend = widget.NewLabel(
		s.texts.Text(localization.DiagnoseNoRecommendationsSelected),
	)
	s.detailRecommend.Wrapping = fyne.TextWrapWord
	s.detailTechnical = widget.NewLabel("")
	s.detailTechnical.Wrapping = fyne.TextWrapWord
	s.detailRaw = widget.NewMultiLineEntry()
	s.detailRaw.Wrapping = fyne.TextWrapWord
	s.detailRaw.SetMinRowsVisible(6)
	s.detailRaw.Disable()
	copyStep := widget.NewButtonWithIcon(
		s.texts.Text(localization.DiagnoseCopyStep),
		theme.ContentCopyIcon(),
		func() {
			id := s.selectedCheck
			if id >= 0 && id < len(s.checks) && s.actions.CopyStep != nil {
				s.actions.CopyStep(s.checks[id])
			}
		},
	)
	detailHeader := container.NewBorder(
		nil,
		nil,
		nil,
		container.NewVBox(copyStep),
		container.NewVBox(
			s.detailTitle,
			s.detailStatus,
			s.detailTiming,
		),
	)
	s.recommendSection = container.NewVBox(
		widget.NewLabelWithStyle(
			s.texts.Text(localization.DiagnoseRecommendations),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		s.detailRecommend,
	)
	s.recommendSection.Hide()
	s.technicalSections = widget.NewAccordion(
		widget.NewAccordionItem(
			s.texts.Text(localization.DiagnoseTechnicalDetails),
			s.detailTechnical,
		),
		widget.NewAccordionItem(
			s.texts.Text(localization.DiagnoseRawStructuredData),
			s.detailRaw,
		),
	)
	s.technicalSections.MultiOpen = true
	s.technicalSections.CloseAll()
	s.detailsViewport = container.NewVScroll(container.NewVBox(
		detailHeader,
		widget.NewSeparator(),
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseSummary), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailSummary,
		s.recommendSection,
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseEvidence), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailEvidence,
		s.technicalSections,
	))

	s.waterfall = components.NewTimingWaterfall(s.texts)
	s.timingDisclosure = widget.NewAccordion(widget.NewAccordionItem(
		s.texts.Text(localization.DiagnoseTimingWaterfall),
		container.NewVBox(
			widget.NewLabel(s.texts.Text(localization.DiagnoseTimingSubtitle)),
			s.waterfall,
		),
	))
	s.timingDisclosure.CloseAll()
	s.timingDisclosure.Hide()
	s.overview = container.NewVBox(
		summary,
		s.timingDisclosure,
	)
	s.timelineCard = widget.NewCard(
		s.texts.Text(localization.DiagnoseDiagnosticSteps),
		"",
		s.timeline,
	)
	s.detailsCard = widget.NewCard(
		s.texts.Text(localization.DiagnoseSelectedStepDetails),
		"",
		s.detailsViewport,
	)
	s.explorer = container.NewHSplit(s.timelineCard, s.detailsCard)
	s.explorer.Offset = 0.40
	s.explorer.Hide()

	runAgain := widget.NewButtonWithIcon(
		s.texts.Text(localization.DiagnoseRunAgain),
		theme.ViewRefreshIcon(),
		s.triggerRun,
	)
	runAgain.Importance = widget.HighImportance
	s.postActions = container.NewGridWithColumns(
		5,
		runAgain,
		widget.NewButtonWithIcon(
			s.texts.Text(localization.DiagnoseCopySummary),
			theme.ContentCopyIcon(),
			func() {
				if s.actions.CopySummary != nil {
					s.actions.CopySummary()
				}
			},
		),
		widget.NewButton(s.texts.Text(localization.DiagnoseExportJSON), func() {
			if s.actions.ExportJSON != nil {
				s.actions.ExportJSON()
			}
		}),
		widget.NewButton(s.texts.Text(localization.DiagnoseExportMarkdown), func() {
			if s.actions.ExportMarkdown != nil {
				s.actions.ExportMarkdown()
			}
		}),
		widget.NewButtonWithIcon(
			s.texts.Text(localization.DiagnoseSaveAsProfile),
			theme.DocumentCreateIcon(),
			func() {
				if s.actions.SaveProfile != nil {
					s.actions.SaveProfile()
				}
			},
		),
	)
	s.postActions.Hide()
	s.activity = widget.NewProgressBarInfinite()
	s.activity.Hide()

	s.overviewViewport = container.NewVScroll(s.overview)
	s.overviewFooter = container.NewStack(s.activity, s.postActions)
	s.overviewFooter.Hide()
	overviewPane := container.NewBorder(
		nil,
		s.overviewFooter,
		nil,
		nil,
		s.overviewViewport,
	)
	s.resultPanels = container.NewVSplit(
		overviewPane,
		s.explorer,
	)
	s.resultPanels.Offset = 0.53
	s.resultView = s.resultPanels
	s.resultView.Hide()
	s.idleState = container.NewCenter(widget.NewCard(
		s.texts.Text(localization.DiagnoseReadyTitle),
		s.texts.Text(localization.DiagnoseReadyDetail),
		widget.NewLabel(s.texts.Text(localization.DiagnoseIdleHint)),
	))
	s.content.Add(s.resultView)
	s.content.Add(s.idleState)
}

func (s *DiagnoseScreen) triggerRun() {
	if s.running {
		return
	}
	input, err := s.Input()
	if err != nil {
		s.inputError.SetText(err.Error())
		s.inputErrorRow.Show()
		s.inputViewport.ScrollToBottom()
		if s.actions.InputError != nil {
			s.actions.InputError(err)
		}
		return
	}
	s.inputError.SetText("")
	s.inputErrorRow.Hide()
	s.inputViewport.ScrollToTop()
	if s.actions.Run != nil {
		s.actions.Run(input)
	}
}

// Input validates and returns the current Diagnose controls.
func (s *DiagnoseScreen) Input() (presenter.DiagnoseInput, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(s.timeout.Text))
	if err != nil {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidTimeout),
		)
	}
	checkTimeout, err := time.ParseDuration(strings.TrimSpace(s.checkTimeout.Text))
	if err != nil {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidCheckTimeout),
		)
	}
	redirects, err := strconv.Atoi(strings.TrimSpace(s.maxRedirects.Text))
	if err != nil {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidRedirects),
		)
	}
	target := strings.TrimSpace(s.target.Text)
	return presenter.DiagnoseInput{
		Target:                 target,
		Mode:                   s.modeValue(),
		IPVersion:              s.ipVersionValue(),
		Timeout:                timeout,
		CheckTimeout:           checkTimeout,
		Method:                 s.methodValue(),
		NoProxy:                s.noProxy.Checked,
		Insecure:               s.insecure.Checked,
		AllowInsecureRedirects: s.allowInsecureRedirects.Checked,
		AllowPrivateRedirects:  s.allowPrivateRedirects.Checked,
		MaxRedirects:           redirects,
		Verbosity:              s.verbosityValue(),
	}, nil
}

// FocusTarget implements Ctrl+L.
func (s *DiagnoseScreen) FocusTarget(canvas fyne.Canvas) {
	canvas.Focus(s.target)
}

// TriggerRun implements Ctrl+Enter and the Run again action.
func (s *DiagnoseScreen) TriggerRun() {
	s.triggerRun()
}

// SetTarget fills the target field, for example when running a profile.
func (s *DiagnoseScreen) SetTarget(target string) {
	s.target.SetText(target)
}

// SetProfile fills all reusable settings from a saved profile.
func (s *DiagnoseScreen) SetProfile(profile presenter.ProfileView) {
	s.target.SetText(profile.Target)
	switch strings.ToLower(profile.Mode) {
	case "tcp":
		s.mode.SetSelected(s.texts.Text(localization.OptionTCP))
	case "tls":
		s.mode.SetSelected(s.texts.Text(localization.OptionTLS))
	default:
		s.mode.SetSelected(s.texts.Text(localization.OptionAuto))
	}
	switch profile.IPVersion {
	case "4":
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionIPv4))
	case "6":
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionIPv6))
	default:
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionAuto))
	}
	if profile.Timeout > 0 {
		s.timeout.SetText(profile.Timeout.String())
	}
	if profile.CheckTimeout > 0 {
		s.checkTimeout.SetText(profile.CheckTimeout.String())
	}
	s.noProxy.SetChecked(profile.NoProxy)
	s.insecure.SetChecked(profile.Insecure)
	s.allowInsecureRedirects.SetChecked(profile.AllowInsecureRedirects)
	s.allowPrivateRedirects.SetChecked(profile.AllowPrivateRedirects)
	s.maxRedirects.SetText(strconv.Itoa(profile.MaxRedirects))
	if profile.Method != "" {
		switch strings.ToUpper(profile.Method) {
		case "HEAD":
			s.method.SetSelected(s.texts.Text(localization.OptionHEAD))
		case "OPTIONS":
			s.method.SetSelected(s.texts.Text(localization.OptionOPTIONS))
		default:
			s.method.SetSelected(s.texts.Text(localization.OptionGET))
		}
	}
	switch strings.ToLower(profile.Verbosity) {
	case "verbose":
		s.verbosity.SetSelected(s.texts.Text(localization.OptionVerbose))
	default:
		s.verbosity.SetSelected(s.texts.Text(localization.OptionNormal))
	}
}

// SetDefaults applies persisted diagnostic defaults on application startup.
func (s *DiagnoseScreen) SetDefaults(
	timeout time.Duration,
	checkTimeout time.Duration,
	ipVersion string,
	maxRedirects int,
	noProxy bool,
) {
	if timeout > 0 {
		s.timeout.SetText(timeout.String())
	}
	if checkTimeout > 0 {
		s.checkTimeout.SetText(checkTimeout.String())
	}
	switch ipVersion {
	case "4":
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionIPv4))
	case "6":
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionIPv6))
	default:
		s.ipVersion.SetSelected(s.texts.Text(localization.OptionAuto))
	}
	s.maxRedirects.SetText(strconv.Itoa(maxRedirects))
	s.noProxy.SetChecked(noProxy)
}

// SetRunning switches the available action controls for an active run.
func (s *DiagnoseScreen) SetRunning(running bool) {
	s.running = running
	s.setInputsEnabled(!running)
	if running {
		s.setAdvancedExpanded(false)
		s.inputViewport.ScrollToTop()
		s.overviewViewport.ScrollToTop()
		s.idleState.Hide()
		s.resultView.Show()
		s.run.Hide()
		s.cancel.Show()
		s.postActions.Hide()
		s.activity.Show()
		s.updateOverviewFooter()
		s.timingDisclosure.Hide()
		s.explorer.Hide()
		s.summaryTarget.SetText(fmt.Sprintf(
			s.texts.Text(localization.DiagnoseTargetFormat),
			strings.TrimSpace(s.target.Text),
		))
		s.summaryTitle.SetText(s.texts.Text(localization.DiagnoseRunningTitle))
		s.summaryDetail.SetText(s.texts.Text(localization.DiagnoseRunningDetail))
		s.summaryStatus.RemoveAll()
		s.summaryStatus.Add(components.StatusLabel(
			s.texts,
			"running",
			s.texts.Text(localization.DiagnoseRunningDetail),
		))
		s.summaryNextStep.Hide()
		s.resultPanels.Refresh()
		return
	}
	s.activity.Stop()
	s.activity.Hide()
	s.updateOverviewFooter()
	s.cancel.Hide()
	s.run.Show()
}

// SetRunEnabled keeps execution unavailable until application configuration
// has been loaded and applied.
func (s *DiagnoseScreen) SetRunEnabled(enabled bool) {
	if enabled {
		s.run.Enable()
		return
	}
	s.run.Disable()
}

// ResetResults clears a previous timeline before a new run.
func (s *DiagnoseScreen) ResetResults() {
	s.checks = nil
	s.selectedCheck = -1
	s.timeline.UnselectAll()
	s.timeline.Refresh()
	s.summaryStatus.RemoveAll()
	s.summaryNextStep.Hide()
	s.postActions.Hide()
	s.updateOverviewFooter()
	s.explorer.Hide()
	s.timingDisclosure.CloseAll()
	s.timingDisclosure.Hide()
	s.clearDetails()
	s.detailsViewport.ScrollToTop()
	s.overviewViewport.ScrollToTop()
	s.waterfall.SetSegments(nil)
}

// UpsertCheck streams one running or completed check into the timeline.
func (s *DiagnoseScreen) UpsertCheck(check presenter.CheckView) {
	s.explorer.Show()
	for i := range s.checks {
		if s.checks[i].ID == check.ID {
			s.checks[i] = check
			s.timeline.RefreshItem(i)
			if s.selectedCheck == i {
				s.showCheck(check)
			}
			return
		}
	}
	s.checks = append(s.checks, check)
	s.timeline.Refresh()
	if s.selectedCheck < 0 {
		index := len(s.checks) - 1
		s.timeline.Select(index)
		s.timeline.ScrollTo(index)
	}
	s.resultPanels.Refresh()
}

// ShowDiagnosis replaces streamed state with the deterministic final result.
func (s *DiagnoseScreen) ShowDiagnosis(diagnosis presenter.DiagnosisView) {
	s.idleState.Hide()
	s.resultView.Show()
	s.overviewViewport.ScrollToTop()
	s.selectedCheck = -1
	s.timeline.UnselectAll()
	s.checks = append(s.checks[:0], diagnosis.Checks...)
	s.timeline.Refresh()
	s.summaryTarget.SetText(fmt.Sprintf(
		s.texts.Text(localization.DiagnoseTargetFormat),
		diagnosis.Target,
	))
	s.summaryTitle.SetText(diagnosis.SummaryTitle)
	s.summaryDetail.SetText(diagnosis.SummaryDetail)
	s.summaryStatus.RemoveAll()
	s.summaryStatus.Add(
		components.StatusLabel(s.texts, diagnosis.OverallStatus, diagnosis.SummaryTitle),
	)
	if len(diagnosis.SummaryRecommendations) > 0 {
		s.summaryNextText.SetText(diagnosis.SummaryRecommendations[0])
		s.summaryNextStep.Show()
	} else {
		s.summaryNextText.SetText("")
		s.summaryNextStep.Hide()
	}
	if hasTimingBreakdown(diagnosis.Timing) {
		segments := make([]components.TimingSegment, 0, len(diagnosis.Timing))
		for _, timing := range diagnosis.Timing {
			segments = append(segments, components.TimingSegment{
				Name:     timing.Name,
				Duration: timing.Duration,
				Measured: timing.Measured,
				IsTotal:  timing.IsTotal,
			})
		}
		s.waterfall.SetSegments(segments)
		s.timingDisclosure.CloseAll()
		s.timingDisclosure.Show()
	} else {
		s.waterfall.SetSegments(nil)
		s.timingDisclosure.CloseAll()
		s.timingDisclosure.Hide()
	}
	s.SetRunning(false)
	s.postActions.Show()
	s.updateOverviewFooter()
	if len(s.checks) > 0 {
		s.explorer.Show()
		s.timeline.UnselectAll()
		index := preferredCheckIndex(s.checks)
		s.timeline.Select(index)
		s.timeline.ScrollTo(index)
	} else {
		s.explorer.Hide()
		s.clearDetails()
	}
	s.resultPanels.Refresh()
}

// ShowError ends a run with a user-readable error.
func (s *DiagnoseScreen) ShowError(message string, cancelled bool) {
	wasRunning := s.running
	if !wasRunning {
		s.ResetResults()
	}
	s.idleState.Hide()
	s.resultView.Show()
	s.overviewViewport.ScrollToTop()
	status := "failed"
	title := s.texts.Text(localization.DiagnoseCouldNotComplete)
	if cancelled {
		status = "cancelled"
		title = s.texts.Text(localization.DiagnoseCancelledTitle)
	}
	s.summaryTarget.SetText(fmt.Sprintf(
		s.texts.Text(localization.DiagnoseTargetFormat),
		strings.TrimSpace(s.target.Text),
	))
	s.summaryTitle.SetText(title)
	s.summaryDetail.SetText(message)
	s.summaryStatus.RemoveAll()
	s.summaryStatus.Add(components.StatusLabel(s.texts, status, title))
	s.summaryNextStep.Hide()
	s.waterfall.SetSegments(nil)
	s.timingDisclosure.CloseAll()
	s.timingDisclosure.Hide()
	if wasRunning && len(s.checks) > 0 {
		s.explorer.Show()
		s.timeline.UnselectAll()
		index := preferredCheckIndex(s.checks)
		s.timeline.Select(index)
		s.timeline.ScrollTo(index)
	} else {
		s.explorer.Hide()
		s.clearDetails()
	}
	s.SetRunning(false)
	s.postActions.Hide()
	s.updateOverviewFooter()
	s.resultPanels.Refresh()
}

// SetPageVisible pauses detached animations while keeping the current run state.
func (s *DiagnoseScreen) SetPageVisible(visible bool) {
	if visible && s.running {
		s.activity.Show()
		s.updateOverviewFooter()
		return
	}
	s.activity.Stop()
	s.activity.Hide()
	s.updateOverviewFooter()
}

func (s *DiagnoseScreen) showCheck(check presenter.CheckView) {
	s.detailTitle.SetText(check.Name)
	s.detailStatus.RemoveAll()
	s.detailStatus.Add(components.StatusLabel(s.texts, check.Status, check.Summary))
	s.detailTiming.SetText(fmt.Sprintf(
		s.texts.Text(localization.DiagnoseTimingFormat),
		formatViewTime(s.texts, check.StartedAt),
		formatViewTime(s.texts, check.FinishedAt),
		formatViewDuration(s.texts, check.Duration),
	))
	s.detailSummary.SetText(check.Summary)
	s.detailEvidence.SetText(joinDisplayLines(
		s.texts,
		check.Evidence,
		s.texts.Text(localization.DiagnoseNoEvidenceRecorded),
	))
	s.detailRecommend.SetText(joinDisplayLines(
		s.texts,
		check.Recommendations,
		s.texts.Text(localization.DiagnoseNoRecommendationsRecorded),
	))
	if len(check.Recommendations) > 0 {
		s.recommendSection.Show()
	} else {
		s.recommendSection.Hide()
	}
	s.detailTechnical.SetText(check.Technical)
	s.detailRaw.SetText(check.RawStructured)
	s.technicalSections.CloseAll()
}

func (s *DiagnoseScreen) setInputsEnabled(enabled bool) {
	if enabled {
		s.target.Enable()
		s.mode.Enable()
		s.ipVersion.Enable()
		s.timeout.Enable()
		s.checkTimeout.Enable()
		s.method.Enable()
		s.noProxy.Enable()
		s.insecure.Enable()
		s.allowInsecureRedirects.Enable()
		s.allowPrivateRedirects.Enable()
		s.maxRedirects.Enable()
		s.verbosity.Enable()
		return
	}
	s.target.Disable()
	s.mode.Disable()
	s.ipVersion.Disable()
	s.timeout.Disable()
	s.checkTimeout.Disable()
	s.method.Disable()
	s.noProxy.Disable()
	s.insecure.Disable()
	s.allowInsecureRedirects.Disable()
	s.allowPrivateRedirects.Disable()
	s.maxRedirects.Disable()
	s.verbosity.Disable()
}

func (s *DiagnoseScreen) clearDetails() {
	s.detailTitle.SetText(s.texts.Text(localization.DiagnoseSelectStep))
	s.detailStatus.RemoveAll()
	s.detailTiming.SetText("")
	s.detailSummary.SetText("")
	s.detailEvidence.SetText(s.texts.Text(localization.DiagnoseNoEvidenceSelected))
	s.detailRecommend.SetText(
		s.texts.Text(localization.DiagnoseNoRecommendationsSelected),
	)
	s.recommendSection.Hide()
	s.detailTechnical.SetText("")
	s.detailRaw.SetText("")
	s.technicalSections.CloseAll()
}

func (s *DiagnoseScreen) setAdvancedExpanded(expanded bool) {
	s.advancedExpanded = expanded
	if expanded {
		s.advancedFields.Show()
		s.advancedToggle.SetIcon(theme.MenuDropUpIcon())
		if s.resultPanels != nil {
			s.resultPanels.Offset = 0.50
		}
	} else {
		s.advancedFields.Hide()
		s.advancedToggle.SetIcon(theme.MenuDropDownIcon())
		s.inputViewport.ScrollToTop()
		if s.resultPanels != nil {
			s.resultPanels.Offset = 0.53
		}
	}
	s.Root.Refresh()
	if expanded {
		s.inputViewport.ScrollToBottom()
	}
}

type diagnoseRootLayout struct {
	screen *DiagnoseScreen
}

func (layout diagnoseRootLayout) Layout(
	objects []fyne.CanvasObject,
	size fyne.Size,
) {
	if len(objects) < 2 || layout.screen == nil {
		return
	}
	padding := theme.Padding()
	contentHeight := layout.screen.inputCard.MinSize().Height
	oldScrollableHeight := fyne.Max(
		0,
		contentHeight-layout.screen.inputViewport.Size().Height,
	)
	wasAtBottom := layout.screen.inputViewport.Offset.Y >= oldScrollableHeight-1
	inputHeight := layout.screen.inputCollapsed
	if layout.screen.advancedExpanded {
		inputHeight = contentHeight
		maxHeight := fyne.Min(float32(440), size.Height-370)
		maxHeight = fyne.Max(maxHeight, layout.screen.inputCollapsed)
		inputHeight = fyne.Min(inputHeight, maxHeight)
	}
	inputHeight = fyne.Min(inputHeight, fyne.Max(0, size.Height-padding))
	objects[0].Move(fyne.NewPos(0, 0))
	objects[0].Resize(fyne.NewSize(size.Width, inputHeight))
	if layout.screen.advancedExpanded && wasAtBottom {
		layout.screen.inputViewport.ScrollToBottom()
	}
	contentY := fyne.Min(size.Height, inputHeight+padding)
	objects[1].Move(fyne.NewPos(0, contentY))
	objects[1].Resize(fyne.NewSize(
		size.Width,
		fyne.Max(0, size.Height-contentY),
	))
}

func (layout diagnoseRootLayout) MinSize(
	objects []fyne.CanvasObject,
) fyne.Size {
	if len(objects) < 2 || layout.screen == nil {
		return fyne.NewSize(0, 0)
	}
	width := fyne.Max(objects[0].MinSize().Width, objects[1].MinSize().Width)
	return fyne.NewSize(
		width,
		layout.screen.inputCollapsed+theme.Padding()+objects[1].MinSize().Height,
	)
}

func (s *DiagnoseScreen) updateOverviewFooter() {
	if s.activity.Visible() || s.postActions.Visible() {
		s.overviewFooter.Show()
		return
	}
	s.overviewFooter.Hide()
}

func preferredCheckIndex(checks []presenter.CheckView) int {
	for _, status := range []string{"failed", "cancelled", "warning"} {
		for index, check := range checks {
			if strings.EqualFold(check.Status, status) {
				return index
			}
		}
	}
	for index := len(checks) - 1; index >= 0; index-- {
		if !strings.EqualFold(checks[index].Status, "skipped") &&
			!strings.EqualFold(checks[index].Status, "not_applicable") {
			return index
		}
	}
	return 0
}

func hasTimingBreakdown(timing []presenter.TimingView) bool {
	for _, item := range timing {
		if !item.IsTotal && item.Measured {
			return true
		}
	}
	return false
}

func formatViewDuration(texts localization.Catalog, duration time.Duration) string {
	if duration <= 0 {
		return texts.Text(localization.CommonUnavailable)
	}
	if duration < time.Second {
		return duration.Round(time.Microsecond).String()
	}
	return duration.Round(time.Millisecond).String()
}

func formatViewTime(texts localization.Catalog, value time.Time) string {
	if value.IsZero() {
		return texts.Text(localization.CommonUnavailable)
	}
	return value.Local().Format(time.RFC3339)
}

func joinDisplayLines(texts localization.Catalog, lines []string, empty string) string {
	if len(lines) == 0 {
		return empty
	}
	var builder strings.Builder
	for _, line := range lines {
		_, _ = fmt.Fprintf(&builder, texts.Text(localization.CommonListItemFormat), line)
		builder.WriteByte('\n')
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

func (s *DiagnoseScreen) modeValue() string {
	switch s.mode.Selected {
	case s.texts.Text(localization.OptionTCP):
		return "tcp"
	case s.texts.Text(localization.OptionTLS):
		return "tls"
	default:
		return "auto"
	}
}

func (s *DiagnoseScreen) ipVersionValue() string {
	switch s.ipVersion.Selected {
	case s.texts.Text(localization.OptionIPv4):
		return "4"
	case s.texts.Text(localization.OptionIPv6):
		return "6"
	default:
		return "auto"
	}
}

func (s *DiagnoseScreen) verbosityValue() string {
	if s.verbosity.Selected == s.texts.Text(localization.OptionVerbose) {
		return "verbose"
	}
	return "normal"
}

func (s *DiagnoseScreen) methodValue() string {
	switch s.method.Selected {
	case s.texts.Text(localization.OptionHEAD):
		return "HEAD"
	case s.texts.Text(localization.OptionOPTIONS):
		return "OPTIONS"
	default:
		return "GET"
	}
}
