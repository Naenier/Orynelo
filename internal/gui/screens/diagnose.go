package screens

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
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

	target          *widget.Entry
	mode            *widget.Select
	ipVersion       *widget.Select
	timeout         *widget.Entry
	checkTimeout    *widget.Entry
	method          *widget.Select
	noProxy         *widget.Check
	insecure        *widget.Check
	maxRedirects    *widget.Entry
	verbosity       *widget.Select
	run             *widget.Button
	cancel          *widget.Button
	postActions     *fyne.Container
	inputError      *widget.Label
	summaryTitle    *widget.Label
	summaryDetail   *widget.Label
	summaryStatus   *fyne.Container
	timeline        *widget.List
	checks          []presenter.CheckView
	selectedCheck   int
	detailTitle     *widget.Label
	detailStatus    *fyne.Container
	detailTiming    *widget.Label
	detailSummary   *widget.Label
	detailEvidence  *widget.Label
	detailRecommend *widget.Label
	detailTechnical *widget.Label
	detailRaw       *widget.Entry
	waterfall       *components.TimingWaterfall
	actions         DiagnoseActions
	texts           localization.Catalog
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
	s.maxRedirects = widget.NewEntry()
	s.maxRedirects.SetText(s.texts.Text(localization.DiagnoseDefaultMaxRedirects))
	s.verbosity = widget.NewSelect([]string{
		s.texts.Text(localization.OptionNormal),
		s.texts.Text(localization.OptionVerbose),
	}, nil)
	s.verbosity.SetSelected(s.texts.Text(localization.OptionNormal))
	s.inputError = widget.NewLabel("")
	s.inputError.Wrapping = fyne.TextWrapWord

	s.run = widget.NewButton(s.texts.Text(localization.DiagnoseRun), s.triggerRun)
	s.run.Importance = widget.HighImportance
	s.cancel = widget.NewButton(s.texts.Text(localization.CommonCancel), func() {
		if s.actions.Cancel != nil {
			s.actions.Cancel()
		}
	})
	s.cancel.Importance = widget.DangerImportance
	s.cancel.Hide()

	top := container.NewBorder(
		nil,
		nil,
		widget.NewLabel(s.texts.Text(localization.CommonTarget)),
		s.run,
		s.target,
	)
	basicOptions := container.NewGridWithColumns(6,
		widget.NewLabel(s.texts.Text(localization.CommonMode)), s.mode,
		widget.NewLabel(s.texts.Text(localization.CommonIP)), s.ipVersion,
		widget.NewLabel(s.texts.Text(localization.CommonTimeout)), s.timeout,
	)
	advanced := widget.NewAccordion(widget.NewAccordionItem(
		s.texts.Text(localization.DiagnoseAdvancedOptions),
		container.NewVBox(
			widget.NewForm(
				widget.NewFormItem(s.texts.Text(localization.CommonHTTPMethod), s.method),
				widget.NewFormItem(s.texts.Text(localization.CommonPerCheckTimeout), s.checkTimeout),
				widget.NewFormItem(s.texts.Text(localization.CommonMaximumRedirects), s.maxRedirects),
				widget.NewFormItem(s.texts.Text(localization.DiagnoseReportVerbosity), s.verbosity),
			),
			s.noProxy,
			s.insecure,
		),
	))

	s.Root = container.NewBorder(
		container.NewVBox(top, basicOptions, advanced, s.inputError),
		nil,
		nil,
		nil,
		widget.NewLabel(s.texts.Text(localization.DiagnosePreparing)),
	)
}

func (s *DiagnoseScreen) buildResults() {
	s.summaryTitle = widget.NewLabelWithStyle(
		s.texts.Text(localization.DiagnoseReadyTitle),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	s.summaryDetail = widget.NewLabel(s.texts.Text(localization.DiagnoseReadyDetail))
	s.summaryDetail.Wrapping = fyne.TextWrapWord
	s.summaryStatus = container.NewVBox()
	summary := widget.NewCard("", "", container.NewVBox(s.summaryTitle, s.summaryStatus, s.summaryDetail))

	s.timeline = widget.NewList(
		func() int { return len(s.checks) },
		func() fyne.CanvasObject {
			return container.NewBorder(
				nil,
				nil,
				components.NewStatusBadge(
					s.texts,
					"pending",
					s.texts.Text(localization.DiagnoseCheckNotStarted),
				),
				widget.NewLabel(s.texts.Text(localization.DiagnoseZeroDuration)),
				container.NewVBox(
					widget.NewLabelWithStyle(
						s.texts.Text(localization.DiagnoseCheck),
						fyne.TextAlignLeading,
						fyne.TextStyle{Bold: true},
					),
					widget.NewLabel(s.texts.Text(localization.DiagnoseShortResult)),
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
	s.detailRaw.Disable()
	copyStep := widget.NewButton(s.texts.Text(localization.DiagnoseCopyStep), func() {
		id := s.selectedCheck
		if id >= 0 && id < len(s.checks) && s.actions.CopyStep != nil {
			s.actions.CopyStep(s.checks[id])
		}
	})
	details := container.NewVScroll(container.NewVBox(
		s.detailTitle,
		s.detailStatus,
		s.detailTiming,
		widget.NewSeparator(),
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseSummary), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailSummary,
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseEvidence), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailEvidence,
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseRecommendations), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailRecommend,
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseTechnicalDetails), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailTechnical,
		widget.NewLabelWithStyle(s.texts.Text(localization.DiagnoseRawStructuredData), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		s.detailRaw,
		copyStep,
	))

	s.waterfall = components.NewTimingWaterfall(s.texts)
	split := container.NewHSplit(
		widget.NewCard(
			s.texts.Text(localization.DiagnoseDiagnosticSteps),
			s.texts.Text(localization.DiagnoseTimelineSubtitle),
			s.timeline,
		),
		widget.NewCard(s.texts.Text(localization.DiagnoseSelectedStepDetails), "", details),
	)
	split.Offset = 0.38

	s.postActions = container.NewHBox(
		widget.NewButton(s.texts.Text(localization.DiagnoseRunAgain), s.triggerRun),
		widget.NewButton(s.texts.Text(localization.DiagnoseCopySummary), func() {
			if s.actions.CopySummary != nil {
				s.actions.CopySummary()
			}
		}),
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
		widget.NewButton(s.texts.Text(localization.DiagnoseSaveAsProfile), func() {
			if s.actions.SaveProfile != nil {
				s.actions.SaveProfile()
			}
		}),
	)
	s.postActions.Hide()

	result := container.NewBorder(
		container.NewVBox(
			summary,
			widget.NewCard(
				s.texts.Text(localization.DiagnoseTimingWaterfall),
				s.texts.Text(localization.DiagnoseTimingSubtitle),
				s.waterfall,
			),
		),
		s.postActions,
		nil,
		nil,
		split,
	)
	root := s.Root.(*fyne.Container)
	root.Objects[0] = result
	root.Refresh()
}

func (s *DiagnoseScreen) triggerRun() {
	input, err := s.Input()
	if err != nil {
		s.inputError.SetText(err.Error())
		if s.actions.InputError != nil {
			s.actions.InputError(err)
		}
		return
	}
	s.inputError.SetText("")
	if s.actions.Run != nil {
		s.actions.Run(input)
	}
}

// Input validates and returns the current Diagnose controls.
func (s *DiagnoseScreen) Input() (presenter.DiagnoseInput, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(s.timeout.Text))
	if err != nil || timeout <= 0 {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidTimeout),
		)
	}
	checkTimeout, err := time.ParseDuration(strings.TrimSpace(s.checkTimeout.Text))
	if err != nil || checkTimeout <= 0 {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidCheckTimeout),
		)
	}
	redirects, err := strconv.Atoi(strings.TrimSpace(s.maxRedirects.Text))
	if err != nil || redirects < 0 || redirects > 50 {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseInvalidRedirects),
		)
	}
	target := strings.TrimSpace(s.target.Text)
	if target == "" {
		return presenter.DiagnoseInput{}, errors.New(
			s.texts.Text(localization.DiagnoseTargetRequired),
		)
	}
	return presenter.DiagnoseInput{
		Target:       target,
		Mode:         s.modeValue(),
		IPVersion:    s.ipVersionValue(),
		Timeout:      timeout,
		CheckTimeout: checkTimeout,
		Method:       s.methodValue(),
		NoProxy:      s.noProxy.Checked,
		Insecure:     s.insecure.Checked,
		MaxRedirects: redirects,
		Verbosity:    s.verbosityValue(),
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
	if running {
		s.run.Hide()
		s.cancel.Show()
		s.postActions.Hide()
		s.summaryTitle.SetText(s.texts.Text(localization.DiagnoseRunningTitle))
		s.summaryDetail.SetText(s.texts.Text(localization.DiagnoseRunningDetail))
		return
	}
	s.cancel.Hide()
	s.run.Show()
}

// ResetResults clears a previous timeline before a new run.
func (s *DiagnoseScreen) ResetResults() {
	s.checks = nil
	s.selectedCheck = -1
	s.timeline.Refresh()
	s.summaryStatus.RemoveAll()
	s.detailStatus.RemoveAll()
	s.waterfall.SetSegments(nil)
}

// UpsertCheck streams one running or completed check into the timeline.
func (s *DiagnoseScreen) UpsertCheck(check presenter.CheckView) {
	for i := range s.checks {
		if s.checks[i].ID == check.ID {
			s.checks[i] = check
			s.timeline.RefreshItem(i)
			return
		}
	}
	s.checks = append(s.checks, check)
	s.timeline.Refresh()
}

// ShowDiagnosis replaces streamed state with the deterministic final result.
func (s *DiagnoseScreen) ShowDiagnosis(diagnosis presenter.DiagnosisView) {
	s.checks = append(s.checks[:0], diagnosis.Checks...)
	s.timeline.Refresh()
	s.summaryTitle.SetText(diagnosis.SummaryTitle)
	s.summaryDetail.SetText(diagnosis.SummaryDetail)
	s.summaryStatus.RemoveAll()
	s.summaryStatus.Add(
		components.StatusLabel(s.texts, diagnosis.OverallStatus, diagnosis.SummaryTitle),
	)
	segments := make([]components.TimingSegment, 0, len(diagnosis.Timing))
	for _, timing := range diagnosis.Timing {
		segments = append(segments, components.TimingSegment{
			Name:     timing.Name,
			Duration: timing.Duration,
			IsTotal:  timing.IsTotal,
		})
	}
	s.waterfall.SetSegments(segments)
	s.SetRunning(false)
	s.postActions.Show()
	if len(s.checks) > 0 {
		s.timeline.Select(0)
	}
}

// ShowError ends a run with a user-readable error.
func (s *DiagnoseScreen) ShowError(message string, cancelled bool) {
	status := "failed"
	title := s.texts.Text(localization.DiagnoseCouldNotComplete)
	if cancelled {
		status = "cancelled"
		title = s.texts.Text(localization.DiagnoseCancelledTitle)
	}
	s.summaryTitle.SetText(title)
	s.summaryDetail.SetText(message)
	s.summaryStatus.RemoveAll()
	s.summaryStatus.Add(components.StatusLabel(s.texts, status, title))
	s.SetRunning(false)
	s.postActions.Hide()
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
	s.detailTechnical.SetText(check.Technical)
	s.detailRaw.SetText(check.RawStructured)
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
