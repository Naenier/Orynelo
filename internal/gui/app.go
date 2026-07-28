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

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	targetcheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/target"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
	"github.com/Naenier/opsdoctor/internal/gui/screens"
	apptheme "github.com/Naenier/opsdoctor/internal/gui/theme"
)

const (
	defaultWidth  = 1280
	defaultHeight = 820
	minimumWidth  = 1050
	minimumHeight = 680
)

type controller struct {
	app     fyne.App
	window  fyne.Window
	backend Backend
	info    buildinfo.Info
	texts   localization.Catalog

	content  *fyne.Container
	diagnose *screens.DiagnoseScreen
	history  *screens.HistoryScreen
	profiles *screens.ProfilesScreen
	settings fyne.CanvasObject
	about    fyne.CanvasObject
	header   *widget.Label

	mu            sync.Mutex
	activeCancel  context.CancelFunc
	currentRun    uint64
	closing       bool
	wg            sync.WaitGroup
	lastDiagnosis model.Diagnosis
	haveDiagnosis bool
	currentScreen string
}

// Run starts the desktop application and blocks until the main window closes.
func Run(ctx context.Context, backend Backend, info buildinfo.Info) {
	if ctx == nil {
		ctx = context.Background()
	}
	fyneApp := app.NewWithID("io.github.naenier.opsdoctor")
	texts := localization.English{}
	cfg := backend.Configuration()
	_ = apptheme.Apply(texts, fyneApp, cfg.Appearance.Theme)

	window := fyneApp.NewWindow(texts.Text(localization.AppName))
	window.Resize(fyne.NewSize(defaultWidth, defaultHeight))
	window.CenterOnScreen()
	window.SetMaster()

	c := &controller{
		app:     fyneApp,
		window:  window,
		backend: backend,
		info:    info,
		texts:   texts,
		content: container.NewStack(),
	}
	c.buildScreens()
	c.buildWindow()
	c.registerShortcuts()
	window.SetCloseIntercept(c.closeWindow)
	c.showScreen("diagnose")
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
	c.cancelActive()
	c.wg.Wait()
}

func (c *controller) buildScreens() {
	c.diagnose = screens.NewDiagnose(c.texts, screens.DiagnoseActions{
		Run:            c.runDiagnostic,
		InputError:     func(error) { c.setHeaderStatus(localization.HeaderError) },
		Cancel:         c.cancelDiagnostic,
		CopySummary:    c.copySummary,
		ExportJSON:     func() { c.exportLast("json") },
		ExportMarkdown: func() { c.exportLast("markdown") },
		SaveProfile:    c.saveLastAsProfile,
		CopyStep: func(check presenter.CheckView) {
			c.app.Clipboard().SetContent(
				check.Technical + "\n\n" +
					c.texts.Text(localization.DialogRawStructuredData) + "\n" +
					check.RawStructured,
			)
		},
	})
	cfg := c.backend.Configuration()
	c.diagnose.SetDefaults(
		cfg.Diagnostics.DefaultTimeout,
		cfg.Diagnostics.CheckTimeout,
		cfg.Diagnostics.PreferredIPVersion,
		cfg.Diagnostics.MaxRedirects,
		!cfg.Network.UseSystemProxy,
	)
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
		Create:    func() { c.showProfileEditor(nil) },
		Edit:      func(profile presenter.ProfileView) { c.showProfileEditor(&profile) },
		Duplicate: c.duplicateProfile,
		Delete:    c.confirmDeleteProfile,
		Run:       c.runProfile,
	})

	c.settings = screens.NewSettings(c.texts, cfg, screens.SettingsActions{
		Save:             c.saveSettings,
		ClearHistory:     c.confirmClearHistory,
		OpenLogDirectory: c.openLogDirectory,
		ApplyTheme: func(value string) error {
			return apptheme.Apply(c.texts, c.app, value)
		},
	})
	c.about = screens.NewAbout(c.texts, c.info)
}

func (c *controller) buildWindow() {
	version := c.info.Version
	if version == "" {
		version = c.texts.Text(localization.HeaderDevelopment)
	}
	c.header = widget.NewLabel(fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		c.texts.Text(localization.HeaderReady),
		version,
	))
	header := container.NewBorder(
		nil,
		nil,
		widget.NewLabelWithStyle(
			c.texts.Text(localization.AppName),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		c.header,
	)

	buttons := []fyne.CanvasObject{
		widget.NewButtonWithIcon(c.texts.Text(localization.NavigationDiagnose), theme.SearchIcon(), func() {
			c.showScreen("diagnose")
		}),
		widget.NewButtonWithIcon(c.texts.Text(localization.NavigationHistory), theme.HistoryIcon(), func() {
			c.history.Reload()
			c.showScreen("history")
		}),
		widget.NewButtonWithIcon(c.texts.Text(localization.NavigationProfiles), theme.DocumentCreateIcon(), func() {
			c.profiles.Reload()
			c.showScreen("profiles")
		}),
		widget.NewButtonWithIcon(c.texts.Text(localization.NavigationSettings), theme.SettingsIcon(), func() {
			c.showScreen("settings")
		}),
		widget.NewButtonWithIcon(c.texts.Text(localization.NavigationAbout), theme.InfoIcon(), func() {
			c.showScreen("about")
		}),
	}
	navigation := container.NewGridWrap(fyne.NewSize(190, 48), buttons...)
	body := container.NewBorder(nil, nil, navigation, nil, c.content)
	layout := container.NewBorder(header, nil, nil, nil, body)

	// The transparent floor enforces the documented minimum while the border
	// and split layouts remain responsive above it.
	floor := canvas.NewRectangle(color.Transparent)
	floor.SetMinSize(fyne.NewSize(minimumWidth, minimumHeight))
	c.window.SetContent(container.NewStack(floor, layout))
}

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

func (c *controller) showScreen(name string) {
	var object fyne.CanvasObject
	switch name {
	case "history":
		object = c.history.Root
	case "profiles":
		object = c.profiles.Root
	case "settings":
		object = c.settings
	case "about":
		object = c.about
	default:
		name = "diagnose"
		object = c.diagnose.Root
	}
	c.currentScreen = name
	c.content.RemoveAll()
	c.content.Add(object)
}

func (c *controller) runDiagnostic(input presenter.DiagnoseInput) {
	c.cancelActive()
	targetValue := input.Target
	if input.Mode == "tcp" {
		parsed, err := targetcheck.Parse(input.Target)
		if err != nil {
			c.diagnose.ShowError(err.Error(), false)
			c.setHeaderStatus(localization.HeaderError)
			return
		}
		targetValue = parsed.Address()
	}
	options := model.DefaultDiagnoseOptions(targetValue)
	options.Timeout = input.Timeout
	options.CheckTimeout = input.CheckTimeout
	options.IPVersion = model.IPVersion(input.IPVersion)
	options.NoProxy = input.NoProxy
	options.Insecure = input.Insecure
	options.EnableTLS = input.Mode == "tls"
	options.MaxRedirects = input.MaxRedirects
	options.Method = input.Method
	options.ReportVerbosity = model.ReportVerbosity(input.Verbosity)

	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.currentRun++
	runID := c.currentRun
	c.activeCancel = cancel
	c.mu.Unlock()
	c.diagnose.ResetResults()
	c.diagnose.SetRunning(true)
	c.setHeaderStatus(localization.HeaderRunning)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		diagnosis, err := c.backend.Diagnose(ctx, options, func(event model.CheckEvent) {
			c.handleEvent(runID, event)
		})
		wasCancelled := errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)
		if !c.shouldPresent(runID) {
			cancel()
			return
		}
		fyne.Do(func() {
			if !c.shouldPresent(runID) {
				cancel()
				return
			}
			c.clearCancel(runID, cancel)
			if err != nil {
				c.diagnose.ShowError(err.Error(), wasCancelled)
				if wasCancelled {
					c.setHeaderStatus(localization.HeaderCancelled)
				} else {
					c.setHeaderStatus(localization.HeaderError)
				}
				return
			}
			c.lastDiagnosis = diagnosis
			c.haveDiagnosis = true
			c.diagnose.ShowDiagnosis(presenter.Diagnosis(c.texts, diagnosis))
			c.setHeaderForDiagnosis(diagnosis)
		})
	}()
}

func (c *controller) handleEvent(runID uint64, event model.CheckEvent) {
	if !c.shouldPresent(runID) {
		return
	}
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
		if c.shouldPresent(runID) {
			c.diagnose.UpsertCheck(check)
		}
	})
}

func (c *controller) closeWindow() {
	c.mu.Lock()
	c.closing = true
	cancel := c.activeCancel
	c.activeCancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.window.Close()
}

func (c *controller) shouldPresent(runID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closing && c.currentRun == runID
}

func (c *controller) isClosing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

func (c *controller) cancelActive() {
	c.mu.Lock()
	cancel := c.activeCancel
	c.activeCancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *controller) cancelDiagnostic() {
	c.mu.Lock()
	cancel := c.activeCancel
	c.activeCancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		c.setHeaderStatus(localization.HeaderCancelling)
	}
}

func (c *controller) triggerDiagnosticShortcut() {
	c.showScreen("diagnose")
	c.diagnose.TriggerRun()
}

func (c *controller) setHeaderStatus(status localization.Key) {
	if c.header == nil {
		return
	}
	version := c.info.Version
	if version == "" {
		version = c.texts.Text(localization.HeaderDevelopment)
	}
	c.header.SetText(fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		c.texts.Text(status),
		version,
	))
}

func (c *controller) setHeaderForDiagnosis(diagnosis model.Diagnosis) {
	if diagnosis.Summary.Status == model.StatusCancelled {
		c.setHeaderStatus(localization.HeaderCancelled)
		return
	}
	completed := fmt.Sprintf(
		c.texts.Text(localization.HeaderCompletedFormat),
		c.texts.Text(localization.StatusKey(string(diagnosis.Summary.Status))),
	)
	c.header.SetText(fmt.Sprintf(
		c.texts.Text(localization.HeaderStatusVersion),
		completed,
		c.version(),
	))
}

func (c *controller) version() string {
	if c.info.Version == "" {
		return c.texts.Text(localization.HeaderDevelopment)
	}
	return c.info.Version
}

func (c *controller) clearCancel(runID uint64, completed context.CancelFunc) {
	c.mu.Lock()
	if c.currentRun == runID {
		c.activeCancel = nil
	}
	c.mu.Unlock()
	completed()
}

func (c *controller) copySummary() {
	if !c.haveDiagnosis {
		return
	}
	text := c.lastDiagnosis.Summary.Title + "\n\n" + c.lastDiagnosis.Summary.Description
	c.app.Clipboard().SetContent(text)
}

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

func (c *controller) exportDiagnosis(diagnosis model.Diagnosis, format string) {
	content, err := c.backend.RenderReport(format, diagnosis)
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	extension := ".json"
	if format == "markdown" {
		extension = ".md"
	}
	save := dialog.NewFileSave(func(writer fyne.URIWriteCloser, saveErr error) {
		if saveErr != nil {
			dialog.ShowError(saveErr, c.window)
			return
		}
		if writer == nil {
			return
		}
		_, writeErr := writer.Write(content)
		closeErr := writer.Close()
		if writeErr != nil {
			dialog.ShowError(writeErr, c.window)
		} else if closeErr != nil {
			dialog.ShowError(closeErr, c.window)
		}
	}, c.window)
	save.SetFilter(storage.NewExtensionFileFilter([]string{extension}))
	save.SetFileName(c.texts.Text(localization.DialogReportFilenameBase) + extension)
	save.Show()
}

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
	c.showProfileEditor(&view)
}

func (c *controller) loadHistory(search, status string) ([]presenter.HistoryView, error) {
	filter := model.Status("")
	if status != "" && status != "all" {
		filter = model.Status(status)
	}
	entries, err := c.backend.ListHistory(context.Background(), search, filter)
	if err != nil {
		return nil, err
	}
	result := make([]presenter.HistoryView, 0, len(entries))
	for _, entry := range entries {
		result = append(result, presenter.History(entry))
	}
	return result, nil
}

func (c *controller) openHistory(row presenter.HistoryView) {
	diagnosis, err := c.backend.GetDiagnosis(context.Background(), row.ID)
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	c.lastDiagnosis = diagnosis
	c.haveDiagnosis = true
	c.diagnose.ShowDiagnosis(presenter.Diagnosis(c.texts, diagnosis))
	c.setHeaderForDiagnosis(diagnosis)
	c.showScreen("diagnose")
}

func (c *controller) rerunHistory(row presenter.HistoryView) {
	diagnosis, err := c.backend.GetDiagnosis(context.Background(), row.ID)
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	c.diagnose.SetProfile(profileViewFromDiagnosis(diagnosis))
	c.showScreen("diagnose")
	c.diagnose.TriggerRun()
}

func (c *controller) exportHistory(row presenter.HistoryView) {
	diagnosis, err := c.backend.GetDiagnosis(context.Background(), row.ID)
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	c.exportDiagnosis(diagnosis, "markdown")
}

func (c *controller) confirmDeleteHistory(row presenter.HistoryView) {
	dialog.ShowConfirm(
		c.texts.Text(localization.HistoryDeleteTitle),
		c.texts.Text(localization.HistoryDeleteBody),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			if err := c.backend.DeleteDiagnosis(context.Background(), row.ID); err != nil {
				c.history.SetMessage(
					c.texts.Text(localization.HistoryDeleteErrorPrefix) + err.Error(),
				)
				return
			}
			c.history.Reload()
		},
		c.window,
	)
}

func (c *controller) confirmClearHistory() {
	dialog.ShowConfirm(
		c.texts.Text(localization.HistoryClearTitle),
		c.texts.Text(localization.HistoryClearBody),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			if err := c.backend.ClearHistory(context.Background()); err != nil {
				dialog.ShowError(err, c.window)
				return
			}
			c.history.Reload()
		},
		c.window,
	)
}

func (c *controller) loadProfiles() ([]presenter.ProfileView, error) {
	profiles, err := c.backend.ListProfiles(context.Background())
	if err != nil {
		return nil, err
	}
	result := make([]presenter.ProfileView, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, presenter.Profile(profile))
	}
	return result, nil
}

func (c *controller) duplicateProfile(profile presenter.ProfileView) error {
	value, err := profileModel(c.texts, profile)
	if err != nil {
		return err
	}
	value.ID = 0
	value.Name += c.texts.Text(localization.ProfilesCopySuffix)
	value.CreatedAt = time.Time{}
	value.UpdatedAt = time.Time{}
	_, err = c.backend.SaveProfile(context.Background(), value)
	return err
}

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
			if err := c.backend.DeleteProfile(context.Background(), profile.ID); err != nil {
				c.profiles.SetMessage(
					c.texts.Text(localization.ProfilesDeleteErrorPrefix) + err.Error(),
				)
				return
			}
			c.profiles.Reload()
		},
		c.window,
	)
}

func (c *controller) runProfile(profile presenter.ProfileView) {
	c.diagnose.SetProfile(profile)
	c.showScreen("diagnose")
	c.diagnose.TriggerRun()
}

func (c *controller) showProfileEditor(existing *presenter.ProfileView) {
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
			if err != nil || checkTimeoutValue <= 0 {
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
			if _, err := c.backend.SaveProfile(context.Background(), profile); err != nil {
				dialog.ShowError(err, c.window)
				return
			}
			c.profiles.Reload()
		},
		c.window,
	).Show()
}

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

func (c *controller) saveSettings(cfg application.Config) error {
	if err := c.backend.SaveConfiguration(cfg); err != nil {
		return err
	}
	if err := apptheme.Apply(c.texts, c.app, cfg.Appearance.Theme); err != nil {
		return err
	}
	c.diagnose.SetDefaults(
		cfg.Diagnostics.DefaultTimeout,
		cfg.Diagnostics.CheckTimeout,
		cfg.Diagnostics.PreferredIPVersion,
		cfg.Diagnostics.MaxRedirects,
		!cfg.Network.UseSystemProxy,
	)
	return nil
}

func (c *controller) openLogDirectory() error {
	path := c.backend.LogDirectory()
	if path == "" {
		return errors.New(c.texts.Text(localization.DialogLogDirectoryUnavailable))
	}
	return c.app.OpenURL(&url.URL{Scheme: "file", Path: filepath.ToSlash(path)})
}

func profileViewFromDiagnosis(diagnosis model.Diagnosis) presenter.ProfileView {
	mode := "auto"
	if diagnosis.Target.Kind == model.TargetTCP {
		mode = "tcp"
	}
	if diagnosis.Options.EnableTLS {
		mode = "tls"
	}
	return presenter.ProfileView{
		Name:         diagnosis.Target.DisplayHost,
		Target:       diagnosis.Target.Original,
		Mode:         mode,
		IPVersion:    string(diagnosis.Options.IPVersion),
		Timeout:      diagnosis.Options.Timeout,
		CheckTimeout: diagnosis.Options.CheckTimeout,
		NoProxy:      diagnosis.Options.NoProxy,
		MaxRedirects: diagnosis.Options.MaxRedirects,
		Method:       diagnosis.Options.Method,
		Insecure:     diagnosis.Options.Insecure,
		Verbosity:    string(diagnosis.Options.ReportVerbosity),
	}
}

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
