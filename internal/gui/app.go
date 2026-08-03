package gui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	appassets "github.com/Naenier/opsdoctor/assets"
	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/components"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
	"github.com/Naenier/opsdoctor/internal/gui/screens"
	"github.com/Naenier/opsdoctor/internal/gui/taskrunner"
	apptheme "github.com/Naenier/opsdoctor/internal/gui/theme"
	"github.com/Naenier/opsdoctor/internal/privacy"
	"github.com/Naenier/opsdoctor/internal/redaction"
	"github.com/Naenier/opsdoctor/internal/secureio"
)

// Desktop window defaults and minimum responsive dimensions.
const (
	defaultWidth  = 1280
	defaultHeight = 820
	minimumWidth  = 1050
	minimumHeight = 680
)

// controller owns desktop navigation, screen state, asynchronous task scopes,
// and the boundary between Fyne widgets and the backend contract.
type controller struct {
	app     fyne.App
	window  fyne.Window
	backend Backend
	info    buildinfo.Info
	texts   localization.Catalog

	content            *fyne.Container
	diagnose           *screens.DiagnoseScreen
	history            *screens.HistoryScreen
	profiles           *screens.ProfilesScreen
	settings           fyne.CanvasObject
	about              fyne.CanvasObject
	header             *widget.Label
	headerStatus       *components.StatusBadge
	diagnoseHeader     string
	secondaryHeader    string
	diagnoseStatus     string
	secondaryStatus    string
	diagnoseStatusTip  string
	secondaryStatusTip string
	pageTitle          *widget.Label
	navigationButtons  map[string]*widget.Button

	mu             sync.Mutex
	closing        bool
	lastDiagnosis  model.Diagnosis
	haveDiagnosis  bool
	currentScreen  string
	pendingProfile *model.Profile
	reportSession  uint64
	settingsDone   func(message string)
	configuration  application.Config
	configLoaded   bool

	tasks               *taskrunner.Runner
	diagnoseTask        *taskrunner.Scope[model.Diagnosis]
	configurationTask   *taskrunner.Scope[application.Config]
	historyLoadTask     *taskrunner.Scope[[]presenter.HistoryView]
	historyReadTask     *taskrunner.Scope[historyReadResult]
	historyMutationTask *taskrunner.Scope[historyMutationResult]
	profilesLoadTask    *taskrunner.Scope[[]presenter.ProfileView]
	profileMutationTask *taskrunner.Scope[profileMutationResult]
	settingsTask        *taskrunner.Scope[settingsSaveResult]
	reportPrepareTask   *taskrunner.Scope[reportPrepareResult]
	reportInspectTask   *taskrunner.Scope[reportInspectResult]
	reportWriteTask     *taskrunner.Scope[reportWriteResult]
}

// Run starts the desktop application and blocks until the main window closes.
func Run(ctx context.Context, backend Backend, info buildinfo.Info) {
	if ctx == nil {
		ctx = context.Background()
	}
	fyneApp := app.NewWithID("io.github.naenier.opsdoctor")
	fyneApp.SetIcon(fyne.NewStaticResource("Icon.png", appassets.IconPNG()))
	texts := localization.English{}
	cfg := application.DefaultConfig()
	_ = apptheme.Apply(texts, fyneApp, cfg.Appearance.Theme)

	window := fyneApp.NewWindow(texts.Text(localization.AppName))
	window.Resize(fyne.NewSize(defaultWidth, defaultHeight))
	window.CenterOnScreen()
	window.SetMaster()

	c := &controller{
		app:           fyneApp,
		window:        window,
		backend:       backend,
		info:          info,
		texts:         texts,
		content:       container.NewStack(),
		configuration: cfg,
	}
	tasks, err := taskrunner.New(ctx, fyne.Do, taskrunner.Options{MaxConcurrentReads: 4})
	if err != nil {
		return
	}
	c.tasks = tasks
	c.buildScreens(cfg)
	if err := c.buildTaskScopes(); err != nil {
		tasks.Close()
		return
	}
	c.buildWindow()
	c.registerShortcuts()
	window.SetCloseIntercept(c.closeWindow)
	c.showScreen("diagnose")
	c.loadConfiguration()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if !c.isClosing() {
				fyne.Do(c.closeWindow)
			}
		case <-stopped:
		}
	}()
	window.ShowAndRun()
	close(stopped)
	c.tasks.Close()
	c.tasks.Wait()
}

// buildScreens constructs every top-level screen and wires user actions back
// to controller operations.
func (c *controller) buildScreens(cfg application.Config) {
	c.diagnose = screens.NewDiagnose(c.texts, screens.DiagnoseActions{
		Run: c.runDiagnostic,
		InputError: func(error) {
			c.setDiagnoseHeaderStatus(localization.HeaderError)
		},
		Cancel:         c.cancelDiagnostic,
		CopySummary:    c.copySummary,
		ExportJSON:     func() { c.exportLast("json") },
		ExportMarkdown: func() { c.exportLast("markdown") },
		SaveProfile:    c.saveLastAsProfile,
		CopyStep: func(check presenter.CheckView) {
			text := presenter.CheckDetailsText(c.texts, check)
			c.app.Clipboard().SetContent(privacy.Standard().Text(text))
		},
	})
	c.diagnose.SetDefaults(
		cfg.Diagnostics.DefaultTimeout,
		cfg.Diagnostics.CheckTimeout,
		cfg.Diagnostics.PreferredIPVersion,
		cfg.Diagnostics.MaxRedirects,
		!cfg.Network.UseSystemProxy,
	)
	c.diagnose.SetRunEnabled(false)
	c.history = screens.NewHistory(c.texts, screens.HistoryActions{
		Load:   c.loadHistory,
		Open:   c.openHistory,
		Rerun:  c.rerunHistory,
		Export: c.exportHistory,
		Delete: c.confirmDeleteHistory,
		Clear:  c.confirmClearHistory,
	})
	c.profiles = screens.NewProfiles(c.texts, screens.ProfileActions{
		Load:      c.loadProfiles,
		Create:    func() { c.showProfileEditor(nil, false) },
		Edit:      func(profile presenter.ProfileView) { c.showProfileEditor(&profile, false) },
		Duplicate: c.duplicateProfile,
		Delete:    c.confirmDeleteProfile,
		Run:       c.runProfile,
	})

	c.settings = c.newSettings(cfg)
	c.about = screens.NewAbout(c.texts, c.info)
}

// buildWindow assembles the responsive application shell, navigation, and
// shared status header.
func (c *controller) buildWindow() {
	version := compactHeaderVersion(c.info.Version)
	if version == "" {
		version = c.texts.Text(localization.HeaderDevelopment)
	}
	c.diagnoseHeader = fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		c.texts.Text(localization.HeaderReady),
		version,
	)
	c.secondaryHeader = c.versionOnlyHeader()
	c.diagnoseStatus = "pending"
	c.diagnoseStatusTip = c.texts.Text(localization.HeaderReady)
	c.header = widget.NewLabel(c.diagnoseHeader)
	c.headerStatus = components.NewStatusIcon(
		c.texts,
		c.diagnoseStatus,
		c.diagnoseStatusTip,
	)
	c.pageTitle = widget.NewLabelWithStyle(
		c.texts.Text(localization.NavigationDiagnose),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)
	sidebarHeader := container.NewGridWrap(
		fyne.NewSize(176+2*theme.Padding(), c.pageTitle.MinSize().Height),
		widget.NewLabelWithStyle(
			c.texts.Text(localization.AppName),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
	)
	header := container.NewBorder(
		nil,
		nil,
		sidebarHeader,
		container.NewHBox(c.headerStatus, c.header),
		c.pageTitle,
	)

	c.navigationButtons = make(map[string]*widget.Button, 5)
	navigationButton := func(
		name string,
		label localization.Key,
		icon fyne.Resource,
		tapped func(),
	) *widget.Button {
		button := widget.NewButtonWithIcon(c.texts.Text(label), icon, tapped)
		button.Alignment = widget.ButtonAlignLeading
		button.Importance = widget.LowImportance
		c.navigationButtons[name] = button
		return button
	}
	buttons := []fyne.CanvasObject{
		navigationButton("diagnose", localization.NavigationDiagnose, theme.SearchIcon(), func() {
			c.showScreen("diagnose")
		}),
		navigationButton("history", localization.NavigationHistory, theme.HistoryIcon(), func() {
			c.showScreen("history")
			c.history.Reload()
		}),
		navigationButton("profiles", localization.NavigationProfiles, theme.DocumentCreateIcon(), func() {
			c.showScreen("profiles")
			c.profiles.Reload()
		}),
		navigationButton("settings", localization.NavigationSettings, theme.SettingsIcon(), func() {
			c.showScreen("settings")
		}),
		navigationButton("about", localization.NavigationAbout, theme.InfoIcon(), func() {
			c.showScreen("about")
		}),
	}
	navigation := container.NewGridWrap(fyne.NewSize(176, 44), buttons...)
	body := container.NewBorder(
		nil,
		nil,
		container.NewPadded(navigation),
		nil,
		container.NewPadded(c.content),
	)
	layout := container.NewBorder(
		container.NewPadded(header),
		nil,
		nil,
		nil,
		body,
	)

	// The transparent floor enforces the documented minimum while the border
	// and split layouts remain responsive above it.
	floor := canvas.NewRectangle(color.Transparent)
	floor.SetMinSize(fyne.NewSize(minimumWidth, minimumHeight))
	c.window.SetContent(container.NewStack(floor, layout))
}

// compactHeaderVersion removes build metadata that is too verbose for the
// persistent window header.
func compactHeaderVersion(value string) string {
	value = strings.TrimSpace(value)
	if separator := strings.IndexByte(value, '+'); separator > 0 {
		return value[:separator]
	}
	return value
}

// registerShortcuts installs the desktop keyboard navigation and action map.
func (c *controller) registerShortcuts() {
	add := func(key fyne.KeyName, modifier fyne.KeyModifier, handler func()) {
		c.window.Canvas().AddShortcut(
			&desktop.CustomShortcut{KeyName: key, Modifier: modifier},
			func(fyne.Shortcut) { handler() },
		)
	}
	add(fyne.KeyL, fyne.KeyModifierControl, func() {
		c.showScreen("diagnose")
		c.diagnose.FocusTarget(c.window.Canvas())
	})
	add(fyne.KeyReturn, fyne.KeyModifierControl, c.triggerDiagnosticShortcut)
	add(fyne.KeyEnter, fyne.KeyModifierControl, c.triggerDiagnosticShortcut)
	add(fyne.KeyEscape, 0, c.cancelDiagnostic)
	add(fyne.KeyE, fyne.KeyModifierControl, func() { c.exportLast("markdown") })
	add(fyne.KeyComma, fyne.KeyModifierControl, func() { c.showScreen("settings") })
}

// showScreen activates one top-level page and cancels work owned by the page
// being left.
func (c *controller) showScreen(name string) {
	if c.currentScreen != "" && c.currentScreen != name {
		c.cancelScreenTasks(c.currentScreen)
	}
	var object fyne.CanvasObject
	title := localization.NavigationDiagnose
	switch name {
	case "history":
		object = c.history.Root
		title = localization.NavigationHistory
	case "profiles":
		object = c.profiles.Root
		title = localization.NavigationProfiles
	case "settings":
		object = c.settings
		title = localization.NavigationSettings
	case "about":
		object = c.about
		title = localization.NavigationAbout
	default:
		name = "diagnose"
		object = c.diagnose.Root
	}
	if c.window != nil {
		c.window.Canvas().Unfocus()
	}
	c.currentScreen = name
	if c.diagnose != nil {
		c.diagnose.SetPageVisible(name == "diagnose")
	}
	c.refreshHeader()
	if c.pageTitle != nil {
		c.pageTitle.SetText(c.texts.Text(title))
	}
	for buttonName, button := range c.navigationButtons {
		button.Importance = widget.LowImportance
		if buttonName == name {
			button.Importance = widget.HighImportance
		}
		button.Refresh()
	}
	c.content.RemoveAll()
	c.content.Add(object)
}

// runDiagnostic resolves form input into an asynchronous backend diagnosis.
func (c *controller) runDiagnostic(input presenter.DiagnoseInput) {
	c.mu.Lock()
	ready := c.configLoaded
	c.mu.Unlock()
	if !ready {
		c.diagnose.ShowError(
			c.texts.Text(localization.ErrorConfigurationGuidance),
			false,
		)
		return
	}
	request := c.diagnoseRequest(input)
	_, err := c.diagnoseTask.StartReadOperation(func(
		ctx context.Context,
		operationID taskrunner.OperationID,
	) (model.Diagnosis, error) {
		return c.backend.DiagnoseRequest(ctx, request, func(event model.CheckEvent) {
			c.handleEvent(operationID, event)
		})
	})
	if err != nil {
		c.diagnose.ShowError(c.userFacingError(guiTaskStartError(err, "diagnose")), false)
		c.setDiagnoseHeaderStatus(localization.HeaderError)
	}
}

// handleEvent projects a streaming diagnostic event into the current GUI
// operation while suppressing stale deliveries.
func (c *controller) handleEvent(
	operationID taskrunner.OperationID,
	event model.CheckEvent,
) {
	if !c.shouldPresentDiagnostic(operationID) {
		return
	}
	event = privacy.Standard().Event(event)
	var check presenter.CheckView
	switch event.Type {
	case model.EventCheckStarted:
		check = presenter.CheckView{
			ID:        event.CheckID,
			Name:      event.CheckName,
			Status:    string(model.StatusRunning),
			Summary:   c.texts.Text(localization.DiagnoseCheckRunning),
			StartedAt: event.At,
		}
	case model.EventCheckCompleted:
		if event.Result == nil {
			return
		}
		check = presenter.Check(c.texts, *event.Result)
	default:
		return
	}
	fyne.Do(func() {
		if c.shouldPresentDiagnostic(operationID) {
			c.diagnose.UpsertCheck(check)
		}
	})
}

// closeWindow marks shutdown, cancels background work, and closes the window.
func (c *controller) closeWindow() {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	if c.tasks != nil {
		c.tasks.Close()
	}
	c.window.Close()
}

// shouldPresentDiagnostic reports whether an event belongs to the active
// diagnostic generation.
func (c *controller) shouldPresentDiagnostic(operationID taskrunner.OperationID) bool {
	if c.diagnoseTask == nil {
		return false
	}
	snapshot := c.diagnoseTask.Snapshot()
	if snapshot.OperationID != operationID {
		return false
	}
	return snapshot.State == taskrunner.StateLoading || snapshot.State == taskrunner.StateSuccess
}

// isClosing returns the synchronized application shutdown state.
func (c *controller) isClosing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

// cancelActive invalidates diagnostic output and clears any pending profile.
func (c *controller) cancelActive() {
	if c.diagnoseTask != nil {
		c.diagnoseTask.Invalidate()
	}
	c.mu.Lock()
	c.pendingProfile = nil
	c.mu.Unlock()
}

// cancelDiagnostic requests cancellation for a currently running diagnosis.
func (c *controller) cancelDiagnostic() {
	if c.diagnoseTask != nil && c.diagnoseTask.Snapshot().State == taskrunner.StateLoading {
		c.setHeaderStatus(localization.HeaderCancelling)
		c.diagnoseTask.Cancel()
	}
}

// triggerDiagnosticShortcut navigates to Diagnose and invokes its primary action.
func (c *controller) triggerDiagnosticShortcut() {
	c.showScreen("diagnose")
	c.diagnose.TriggerRun()
}

// setHeaderStatus updates both Diagnose and secondary-page status summaries.
func (c *controller) setHeaderStatus(status localization.Key) {
	c.setDiagnoseHeaderStatus(status)
	label := c.texts.Text(status)
	rawStatus := headerStatusValue(status)
	switch status {
	case localization.HeaderRunning, localization.HeaderCancelling:
		c.secondaryHeader = c.diagnoseHeader
		c.secondaryStatus = rawStatus
		c.secondaryStatusTip = label
	case localization.HeaderReady:
		c.secondaryHeader = c.versionOnlyHeader()
		c.secondaryStatus = ""
		c.secondaryStatusTip = ""
	default:
		c.secondaryHeader = fmt.Sprintf(
			c.texts.Text(localization.HeaderStatusVersion),
			fmt.Sprintf(c.texts.Text(localization.HeaderLastRunFormat), label),
			c.version(),
		)
		c.secondaryStatus = rawStatus
		c.secondaryStatusTip = label
	}
	c.refreshHeader()
}

// setDiagnoseHeaderStatus updates the status shown on the Diagnose page.
func (c *controller) setDiagnoseHeaderStatus(status localization.Key) {
	label := c.texts.Text(status)
	c.diagnoseHeader = fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		label,
		c.version(),
	)
	c.diagnoseStatus = headerStatusValue(status)
	c.diagnoseStatusTip = label
	c.refreshHeader()
}

// setHeaderForDiagnosis derives persistent header state from a completed result.
func (c *controller) setHeaderForDiagnosis(diagnosis model.Diagnosis) {
	if diagnosis.Summary.Status == model.StatusCancelled {
		c.setHeaderStatus(localization.HeaderCancelled)
		return
	}
	completed := fmt.Sprintf(
		c.texts.Text(localization.HeaderCompletedFormat),
		c.texts.Text(localization.StatusKey(string(diagnosis.Summary.Status))),
	)
	c.diagnoseHeader = fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		completed,
		c.version(),
	)
	rawStatus := string(diagnosis.Summary.Status)
	description := strings.TrimSpace(diagnosis.Summary.Title)
	if description == "" {
		description = strings.TrimSpace(diagnosis.Summary.Description)
	}
	if description == "" {
		description = completed
	}
	c.diagnoseStatus = rawStatus
	c.diagnoseStatusTip = description
	c.secondaryHeader = fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		fmt.Sprintf(
			c.texts.Text(localization.HeaderLastRunFormat),
			c.texts.Text(localization.StatusKey(string(diagnosis.Summary.Status))),
		),
		c.version(),
	)
	c.secondaryStatus = rawStatus
	c.secondaryStatusTip = description
	c.refreshHeader()
}

// headerStatusValue maps localized header states to status badge vocabulary.
func headerStatusValue(status localization.Key) string {
	switch status {
	case localization.HeaderRunning:
		return "running"
	case localization.HeaderCancelling, localization.HeaderCancelled:
		return "cancelled"
	case localization.HeaderError:
		return "failed"
	default:
		return "pending"
	}
}

// version returns the compact display version or the development label.
func (c *controller) version() string {
	version := compactHeaderVersion(c.info.Version)
	if version == "" {
		return c.texts.Text(localization.HeaderDevelopment)
	}
	return version
}

// refreshHeader renders the header variant associated with the active page.
func (c *controller) refreshHeader() {
	if c.header == nil {
		return
	}
	if c.currentScreen == "" || c.currentScreen == "diagnose" {
		c.header.SetText(c.diagnoseHeader)
		c.refreshHeaderStatus(c.diagnoseStatus, c.diagnoseStatusTip)
		return
	}
	if c.secondaryHeader == "" {
		c.secondaryHeader = c.versionOnlyHeader()
	}
	c.header.SetText(c.secondaryHeader)
	c.refreshHeaderStatus(c.secondaryStatus, c.secondaryStatusTip)
}

// refreshHeaderStatus updates or hides the accessible status badge.
func (c *controller) refreshHeaderStatus(status, description string) {
	if c.headerStatus == nil {
		return
	}
	if status == "" {
		c.headerStatus.Hide()
		return
	}
	c.headerStatus.Set(status, description)
	c.headerStatus.Show()
}

// versionOnlyHeader returns the neutral header used outside Diagnose.
func (c *controller) versionOnlyHeader() string {
	return fmt.Sprintf(
		"%s %s",
		c.texts.Text(localization.AboutVersion),
		c.version(),
	)
}

// copySummary writes a privacy-projected diagnosis summary to the clipboard.
func (c *controller) copySummary() {
	if !c.haveDiagnosis {
		return
	}
	diagnosis := privacy.Standard().Diagnosis(c.lastDiagnosis)
	text := diagnosis.Summary.Title + "\n\n" + diagnosis.Summary.Description
	c.app.Clipboard().SetContent(privacy.Standard().Text(text))
}

// exportLast starts export for the most recent completed diagnosis.
func (c *controller) exportLast(format string) {
	if !c.haveDiagnosis {
		dialog.ShowInformation(
			c.texts.Text(localization.DialogNoCompletedDiagnosis),
			c.texts.Text(localization.DialogRunBeforeExporting),
			c.window,
		)
		return
	}
	c.exportDiagnosis(c.lastDiagnosis, format)
}

// exportDiagnosis asks the user for privacy mode and a safe destination name.
func (c *controller) exportDiagnosis(diagnosis model.Diagnosis, format string) {
	extension := exportExtension(format)
	standardLabel := c.texts.Text(localization.DialogExportStandard)
	strictLabel := c.texts.Text(localization.DialogExportStrict)
	choice := widget.NewRadioGroup([]string{standardLabel, strictLabel}, nil)
	choice.SetSelected(standardLabel)
	filename := widget.NewEntry()
	filename.SetText(c.texts.Text(localization.DialogReportFilenameBase) + extension)
	content := container.NewVBox(
		widget.NewLabel(c.texts.Text(localization.DialogExportPrivacyBody)),
		choice,
		widget.NewForm(widget.NewFormItem(c.texts.Text(localization.DialogExportFilename), filename)),
	)
	dialog.NewCustomConfirm(
		c.texts.Text(localization.DialogExportPrivacyTitle),
		c.texts.Text(localization.DialogExportContinue),
		c.texts.Text(localization.CommonCancel),
		content,
		func(confirmed bool) {
			if !confirmed {
				return
			}
			mode := privacy.ModeStandard
			if choice.Selected == strictLabel {
				mode = privacy.ModeStrict
			}
			name, err := normalizeExportFilename(filename.Text, extension)
			if err != nil {
				dialog.ShowError(err, c.window)
				return
			}
			c.exportDiagnosisWithPrivacy(diagnosis, format, mode, name)
		},
		c.window,
	).Show()
}

// exportDiagnosisWithPrivacy begins asynchronous rendering for the selected
// privacy policy.
func (c *controller) exportDiagnosisWithPrivacy(
	diagnosis model.Diagnosis,
	format string,
	mode privacy.Mode,
	filename string,
) {
	c.prepareReport(diagnosis, format, mode, filename)
}

// exportExtension returns the canonical file extension for a report format.
func exportExtension(format string) string {
	if format == "markdown" || format == "md" {
		return ".md"
	}
	return ".json"
}

// normalizeExportFilename validates a single path component and appends the
// expected extension when absent.
func normalizeExportFilename(input, extension string) (string, error) {
	name := strings.TrimSpace(input)
	if !validExportComponent(name) {
		return "", errors.New("export file name must be a single safe path component")
	}
	if !strings.HasSuffix(strings.ToLower(name), strings.ToLower(extension)) {
		name += extension
	}
	return name, nil
}

// exportDestination resolves a validated filename under a selected folder URI.
func exportDestination(folder fyne.URI, filename string) (fyne.URI, error) {
	if folder == nil {
		return nil, errors.New("export folder is unavailable")
	}
	if !validExportComponent(filename) {
		return nil, errors.New("export file name must be a single safe path component")
	}
	return storage.Child(folder, filename)
}

// validExportComponent reports whether value is a portable single filename.
func validExportComponent(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 255 ||
		strings.ContainsAny(value, `/\\`) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

// writeExportURI writes a complete report through secure local-file handling
// or the Fyne storage abstraction. The boolean reports use of a local file.
func writeExportURI(destination fyne.URI, content []byte, replaceExisting bool) (bool, error) {
	if destination == nil {
		return false, errors.New("export destination is unavailable")
	}
	if destination.Scheme() == "file" &&
		(destination.Authority() == "" || destination.Authority() == "localhost") {
		write := secureio.WriteFileIfAbsent
		if replaceExisting {
			write = secureio.WriteFile
		}
		if err := write(destination.Path(), content); err != nil {
			return true, err
		}
		return true, nil
	}
	writer, err := storage.Writer(destination)
	if err != nil {
		return false, fmt.Errorf("open export URI %q: %w", destination.String(), err)
	}
	if err := secureio.WriteAndClose(writer, content); err != nil {
		return false, fmt.Errorf("write export URI %q: %w", destination.String(), err)
	}
	return false, nil
}

// saveLastAsProfile opens the profile editor with the last diagnosis defaults.
func (c *controller) saveLastAsProfile() {
	if !c.haveDiagnosis {
		dialog.ShowInformation(
			c.texts.Text(localization.DialogNoCompletedDiagnosis),
			c.texts.Text(localization.DialogRunBeforeSavingProfile),
			c.window,
		)
		return
	}
	view := profileViewFromDiagnosis(c.lastDiagnosis)
	c.showProfileEditor(&view, c.lastDiagnosis.Target.PrivacyRedacted)
}

// loadHistory normalizes screen filters and starts a history query.
func (c *controller) loadHistory(search, status string) {
	filter := model.Status("")
	if status != "" && status != "all" {
		filter = model.Status(status)
	}
	c.startHistoryLoad(search, filter)
}

// openHistory loads a stored diagnosis for presentation.
func (c *controller) openHistory(row presenter.HistoryView) {
	c.startHistoryRead(historyReadOpen, row.ID)
}

// presentHistoricalDiagnosis projects and displays a stored diagnosis without
// rerunning network checks.
func (c *controller) presentHistoricalDiagnosis(diagnosis model.Diagnosis) {
	c.cancelActive()
	diagnosis = privacy.Standard().Diagnosis(diagnosis)
	c.lastDiagnosis = diagnosis
	c.haveDiagnosis = true
	c.diagnose.SetProfile(profileViewFromDiagnosis(diagnosis))
	c.diagnose.ShowDiagnosis(presenter.Diagnosis(c.texts, diagnosis))
	c.setHeaderForDiagnosis(diagnosis)
	c.showScreen("diagnose")
}

// rerunHistory loads a stored diagnosis and starts it as a new request.
func (c *controller) rerunHistory(row presenter.HistoryView) {
	c.startHistoryRead(historyReadRerun, row.ID)
}

// exportHistory loads a stored diagnosis and opens the export workflow.
func (c *controller) exportHistory(row presenter.HistoryView) {
	c.startHistoryRead(historyReadExport, row.ID)
}

// confirmDeleteHistory requires explicit confirmation before deleting one run.
func (c *controller) confirmDeleteHistory(row presenter.HistoryView) {
	dialog.ShowConfirm(
		c.texts.Text(localization.HistoryDeleteTitle),
		c.texts.Text(localization.HistoryDeleteBody),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			c.startHistoryMutation(historyMutationDelete, row.ID)
		},
		c.window,
	)
}

// confirmClearHistory requires explicit confirmation before clearing all runs.
func (c *controller) confirmClearHistory() {
	dialog.ShowConfirm(
		c.texts.Text(localization.HistoryClearTitle),
		c.texts.Text(localization.HistoryClearBody),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			c.startHistoryMutation(historyMutationClear, "")
		},
		c.window,
	)
}

// loadProfiles starts an asynchronous saved-profile query.
func (c *controller) loadProfiles() {
	c.startProfilesLoad()
}

// duplicateProfile validates a view model and saves an independent copy.
func (c *controller) duplicateProfile(profile presenter.ProfileView) {
	value, err := profileModel(c.texts, profile)
	if err != nil {
		c.profiles.SetMessage(c.texts.Text(localization.ProfilesDuplicateErrorPrefix) + err.Error())
		return
	}
	value.ID = 0
	value.Name += c.texts.Text(localization.ProfilesCopySuffix)
	value.CreatedAt = time.Time{}
	value.UpdatedAt = time.Time{}
	c.startProfileMutation(profileMutationDuplicate, value)
}

// confirmDeleteProfile requires explicit confirmation before profile deletion.
func (c *controller) confirmDeleteProfile(profile presenter.ProfileView) {
	dialog.ShowConfirm(
		c.texts.Text(localization.ProfilesDeleteTitle),
		fmt.Sprintf(
			c.texts.Text(localization.ProfilesDeleteBodyFormat),
			profile.Name,
		),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			c.startProfileDelete(profile.ID)
		},
		c.window,
	)
}

// runProfile forwards a selected saved profile into the Diagnose workflow.
func (c *controller) runProfile(profile presenter.ProfileView) {
	c.startProfile(profile)
}

// startProfile converts a display profile into a pending backend request.
func (c *controller) startProfile(profile presenter.ProfileView) {
	c.cancelActive()
	value, err := profileModel(c.texts, profile)
	if err != nil {
		c.diagnose.ShowError(err.Error(), false)
		return
	}
	c.mu.Lock()
	c.pendingProfile = &value
	c.mu.Unlock()
	c.diagnose.SetRunning(false)
	c.diagnose.SetProfile(profile)
	c.showScreen("diagnose")
	c.diagnose.TriggerRun()
}

// showProfileEditor presents validation, privacy projection, and persistence
// controls for creating or editing a profile.
func (c *controller) showProfileEditor(
	existing *presenter.ProfileView,
	targetWasRedacted bool,
) {
	autoOption := strings.ToLower(c.texts.Text(localization.OptionAuto))
	tcpOption := strings.ToLower(c.texts.Text(localization.OptionTCP))
	tlsOption := strings.ToLower(c.texts.Text(localization.OptionTLS))
	name := widget.NewEntry()
	target := widget.NewEntry()
	mode := widget.NewSelect([]string{autoOption, tcpOption, tlsOption}, nil)
	ipVersion := widget.NewSelect([]string{
		autoOption,
		c.texts.Text(localization.OptionIP4Value),
		c.texts.Text(localization.OptionIP6Value),
	}, nil)
	timeout := widget.NewEntry()
	checkTimeout := widget.NewEntry()
	noProxy := widget.NewCheck(c.texts.Text(localization.CommonDisableProxy), nil)
	redirects := widget.NewEntry()
	method := widget.NewSelect([]string{
		c.texts.Text(localization.OptionGET),
		c.texts.Text(localization.OptionHEAD),
		c.texts.Text(localization.OptionOPTIONS),
	}, nil)

	base := presenter.ProfileView{
		Mode:         "auto",
		IPVersion:    "auto",
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "GET",
	}
	title := c.texts.Text(localization.ProfilesCreateTitle)
	if existing != nil {
		base = *existing
		title = c.texts.Text(localization.ProfilesEditTitle)
	}
	name.SetText(base.Name)
	target.SetText(base.Target)
	switch base.Mode {
	case "tcp":
		mode.SetSelected(tcpOption)
	case "tls":
		mode.SetSelected(tlsOption)
	default:
		mode.SetSelected(autoOption)
	}
	switch base.IPVersion {
	case "4":
		ipVersion.SetSelected(c.texts.Text(localization.OptionIP4Value))
	case "6":
		ipVersion.SetSelected(c.texts.Text(localization.OptionIP6Value))
	default:
		ipVersion.SetSelected(autoOption)
	}
	timeout.SetText(base.Timeout.String())
	checkTimeout.SetText(base.CheckTimeout.String())
	noProxy.SetChecked(base.NoProxy)
	redirects.SetText(strconv.Itoa(base.MaxRedirects))
	method.SetSelected(profileMethodLabel(c.texts, base.Method))

	items := []*widget.FormItem{
		widget.NewFormItem(c.texts.Text(localization.ProfilesName), name),
		widget.NewFormItem(c.texts.Text(localization.CommonTarget), target),
		widget.NewFormItem(c.texts.Text(localization.CommonMode), mode),
		widget.NewFormItem(c.texts.Text(localization.ProfilesIPPreference), ipVersion),
		widget.NewFormItem(c.texts.Text(localization.CommonTimeout), timeout),
		widget.NewFormItem(c.texts.Text(localization.CommonPerCheckTimeout), checkTimeout),
		widget.NewFormItem(c.texts.Text(localization.ProfilesProxy), noProxy),
		widget.NewFormItem(c.texts.Text(localization.CommonMaximumRedirects), redirects),
		widget.NewFormItem(c.texts.Text(localization.CommonHTTPMethod), method),
	}
	dialog.NewForm(
		title,
		c.texts.Text(localization.CommonSave),
		c.texts.Text(localization.CommonCancel),
		items,
		func(save bool) {
			if !save {
				return
			}
			timeoutValue, err := time.ParseDuration(strings.TrimSpace(timeout.Text))
			if err != nil || timeoutValue <= 0 {
				dialog.ShowError(
					errors.New(c.texts.Text(localization.ProfilesInvalidTimeout)),
					c.window,
				)
				return
			}
			checkTimeoutValue, err := time.ParseDuration(strings.TrimSpace(checkTimeout.Text))
			if err != nil || checkTimeoutValue <= 0 || checkTimeoutValue > timeoutValue {
				dialog.ShowError(
					errors.New(c.texts.Text(localization.ProfilesInvalidCheckTimeout)),
					c.window,
				)
				return
			}
			redirectValue, err := strconv.Atoi(strings.TrimSpace(redirects.Text))
			if err != nil || redirectValue < 0 || redirectValue > 50 {
				dialog.ShowError(
					errors.New(c.texts.Text(localization.ProfilesInvalidRedirects)),
					c.window,
				)
				return
			}
			modeValue := "auto"
			switch mode.Selected {
			case tcpOption:
				modeValue = "tcp"
			case tlsOption:
				modeValue = "tls"
			}
			ipValue := "auto"
			switch ipVersion.Selected {
			case c.texts.Text(localization.OptionIP4Value):
				ipValue = "4"
			case c.texts.Text(localization.OptionIP6Value):
				ipValue = "6"
			}
			methodValue := profileMethodValue(c.texts, method.Selected)
			profile := model.Profile{
				ID:           base.ID,
				Name:         strings.TrimSpace(name.Text),
				Target:       strings.TrimSpace(target.Text),
				Mode:         model.DiagnosticMode(modeValue),
				IPVersion:    model.IPVersion(ipValue),
				Timeout:      timeoutValue,
				CheckTimeout: checkTimeoutValue,
				NoProxy:      noProxy.Checked,
				EnableTLS:    modeValue == "tls",
				MaxRedirects: redirectValue,
				Method:       methodValue,
			}
			if profile.Name == "" || profile.Target == "" || !profile.IPVersion.Valid() {
				dialog.ShowError(
					errors.New(c.texts.Text(localization.ProfilesRequiredFields)),
					c.window,
				)
				return
			}
			projected, changed := projectProfileForSave(profile, targetWasRedacted)
			saveProjected := func() {
				c.startProfileMutation(profileMutationSave, projected)
			}
			if changed {
				dialog.ShowConfirm(
					c.texts.Text(localization.DialogProfileRedactedTitle),
					fmt.Sprintf(
						c.texts.Text(localization.DialogProfileRedactedFormat),
						projected.Target,
					),
					func(confirmed bool) {
						if confirmed {
							saveProjected()
						}
					},
					c.window,
				)
				return
			}
			saveProjected()
		},
		c.window,
	).Show()
}

// projectProfileForSave applies the standard privacy policy and reports
// whether confirmation is required because target data was removed.
func projectProfileForSave(
	input model.Profile,
	privacyRedacted ...bool,
) (model.Profile, bool) {
	projected := privacy.Standard().Profile(input)
	changed := projected.Target != strings.TrimSpace(input.Target)
	alreadyRedacted := strings.Contains(input.Target, redaction.Replacement)
	redactionProvenance := len(privacyRedacted) > 0 && privacyRedacted[0]
	return projected, changed || alreadyRedacted || redactionProvenance
}

// profileMethodLabel maps a stored HTTP method to its localized selector label.
func profileMethodLabel(texts localization.Catalog, method string) string {
	switch strings.ToUpper(method) {
	case "HEAD":
		return texts.Text(localization.OptionHEAD)
	case "OPTIONS":
		return texts.Text(localization.OptionOPTIONS)
	default:
		return texts.Text(localization.OptionGET)
	}
}

// profileMethodValue maps a localized selector label to a canonical HTTP method.
func profileMethodValue(texts localization.Catalog, label string) string {
	switch label {
	case texts.Text(localization.OptionHEAD):
		return "HEAD"
	case texts.Text(localization.OptionOPTIONS):
		return "OPTIONS"
	default:
		return "GET"
	}
}

// newSettings constructs the settings screen with controller callbacks.
func (c *controller) newSettings(cfg application.Config) fyne.CanvasObject {
	return screens.NewSettings(c.texts, cfg, screens.SettingsActions{
		Save:             c.saveSettings,
		ClearHistory:     c.confirmClearHistory,
		OpenLogDirectory: c.openLogDirectory,
		ApplyTheme: func(value string) error {
			return apptheme.Apply(c.texts, c.app, value)
		},
	})
}

// saveSettings delegates validated settings to the serialized mutation scope.
func (c *controller) saveSettings(
	cfg application.Config,
	complete func(message string),
) {
	c.startSettingsSave(cfg, complete)
}

// openLogDirectory asks the desktop environment to reveal the backend log path.
func (c *controller) openLogDirectory() error {
	path := c.backend.LogDirectory()
	if path == "" {
		return errors.New(c.texts.Text(localization.DialogLogDirectoryUnavailable))
	}
	if err := c.app.OpenURL(&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}); err != nil {
		return errors.New(c.userFacingError(guiBoundaryError(
			err,
			application.ErrorCategoryInternal,
			"APP_LOG_DIRECTORY_OPEN_FAILED",
			"error.log_directory_open_failed",
			nil,
		)))
	}
	return nil
}

// profileViewFromDiagnosis extracts reusable settings from a completed run.
func profileViewFromDiagnosis(diagnosis model.Diagnosis) presenter.ProfileView {
	mode := "auto"
	if diagnosis.Target.Kind == model.TargetTCP {
		mode = "tcp"
	}
	if diagnosis.Options.EnableTLS {
		mode = "tls"
	}
	return presenter.ProfileView{
		Name:                   diagnosis.Target.DisplayHost,
		Target:                 diagnosis.Target.Original,
		Mode:                   mode,
		IPVersion:              string(diagnosis.Options.IPVersion),
		Timeout:                diagnosis.Options.Timeout,
		CheckTimeout:           diagnosis.Options.CheckTimeout,
		NoProxy:                diagnosis.Options.NoProxy,
		MaxRedirects:           diagnosis.Options.MaxRedirects,
		Method:                 diagnosis.Options.Method,
		Insecure:               diagnosis.Options.Insecure,
		AllowInsecureRedirects: diagnosis.Options.AllowInsecureRedirects,
		AllowPrivateRedirects:  diagnosis.Options.AllowPrivateRedirects,
		Verbosity:              string(diagnosis.Options.ReportVerbosity),
	}
}

// profileModel validates and converts editable GUI values into a domain profile.
func profileModel(
	texts localization.Catalog,
	profile presenter.ProfileView,
) (model.Profile, error) {
	texts = localization.Normalize(texts)
	if strings.TrimSpace(profile.Name) == "" || strings.TrimSpace(profile.Target) == "" {
		return model.Profile{}, errors.New(texts.Text(localization.ProfilesNameTargetRequired))
	}
	ipVersion := model.IPVersion(profile.IPVersion)
	if !ipVersion.Valid() {
		return model.Profile{}, fmt.Errorf(
			texts.Text(localization.ProfilesInvalidIPFormat),
			profile.IPVersion,
		)
	}
	return model.Profile{
		ID:           profile.ID,
		Name:         strings.TrimSpace(profile.Name),
		Target:       strings.TrimSpace(profile.Target),
		Mode:         model.DiagnosticMode(profile.Mode),
		IPVersion:    ipVersion,
		Timeout:      profile.Timeout,
		CheckTimeout: profile.CheckTimeout,
		NoProxy:      profile.NoProxy,
		EnableTLS:    profile.Mode == "tls",
		MaxRedirects: profile.MaxRedirects,
		Method:       profile.Method,
	}, nil
}
