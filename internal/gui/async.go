package gui

import (
	"context"
	"errors"
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
	"github.com/Naenier/opsdoctor/internal/gui/taskrunner"
	apptheme "github.com/Naenier/opsdoctor/internal/gui/theme"
	"github.com/Naenier/opsdoctor/internal/privacy"
)

type historyReadAction uint8

const (
	historyReadOpen historyReadAction = iota + 1
	historyReadRerun
	historyReadExport
)

type historyReadResult struct {
	Action    historyReadAction
	Diagnosis model.Diagnosis
}

type historyMutationAction uint8

const (
	historyMutationDelete historyMutationAction = iota + 1
	historyMutationClear
)

type historyMutationResult struct {
	Action historyMutationAction
}

type profileMutationAction uint8

const (
	profileMutationSave profileMutationAction = iota + 1
	profileMutationDuplicate
	profileMutationDelete
)

type profileMutationResult struct {
	Action profileMutationAction
	Saved  model.Profile
}

type settingsSaveResult struct {
	Config   application.Config
	Complete func(message string)
}

type reportPrepareResult struct {
	Session  uint64
	Filename string
	Content  []byte
}

type reportInspectResult struct {
	Session     uint64
	Destination fyne.URI
	Content     []byte
	Exists      bool
}

type reportWriteResult struct {
	Session     uint64
	Destination fyne.URI
	Atomic      bool
}

func (c *controller) buildTaskScopes() error {
	var err error
	c.diagnoseTask, err = taskrunner.NewScope(c.tasks, "diagnose", c.observeDiagnosis)
	if err != nil {
		return err
	}
	c.configurationTask, err = taskrunner.NewScope(c.tasks, "configuration", c.observeConfiguration)
	if err != nil {
		return err
	}
	c.historyLoadTask, err = taskrunner.NewScope(c.tasks, "history.load", c.observeHistoryLoad)
	if err != nil {
		return err
	}
	c.historyReadTask, err = taskrunner.NewScope(c.tasks, "history.read", c.observeHistoryRead)
	if err != nil {
		return err
	}
	c.historyMutationTask, err = taskrunner.NewScope(c.tasks, "history.mutation", c.observeHistoryMutation)
	if err != nil {
		return err
	}
	c.profilesLoadTask, err = taskrunner.NewScope(c.tasks, "profiles.load", c.observeProfilesLoad)
	if err != nil {
		return err
	}
	c.profileMutationTask, err = taskrunner.NewScope(c.tasks, "profiles.mutation", c.observeProfileMutation)
	if err != nil {
		return err
	}
	c.settingsTask, err = taskrunner.NewScope(c.tasks, "settings.save", c.observeSettingsSave)
	if err != nil {
		return err
	}
	c.reportPrepareTask, err = taskrunner.NewScope(c.tasks, "report.prepare", c.observeReportPrepare)
	if err != nil {
		return err
	}
	c.reportInspectTask, err = taskrunner.NewScope(c.tasks, "report.inspect", c.observeReportInspect)
	if err != nil {
		return err
	}
	c.reportWriteTask, err = taskrunner.NewScope(c.tasks, "report.write", c.observeReportWrite)
	return err
}

func (c *controller) diagnoseRequest(input presenter.DiagnoseInput) application.DiagnoseRequest {
	c.mu.Lock()
	profile := c.pendingProfile
	c.pendingProfile = nil
	config := c.configuration
	c.mu.Unlock()
	if config.Diagnostics.DefaultTimeout == 0 {
		config = application.DefaultConfig()
	}

	insecure := input.Insecure
	allowInsecureRedirects := input.AllowInsecureRedirects
	allowPrivateRedirects := input.AllowPrivateRedirects
	verbosity := model.ReportVerbosity(input.Verbosity)
	request := application.DiagnoseRequest{Profile: profile}
	if profile != nil {
		request.Overrides = application.DiagnoseOverrides{
			Insecure:               &insecure,
			AllowInsecureRedirects: &allowInsecureRedirects,
			AllowPrivateRedirects:  &allowPrivateRedirects,
			ReportVerbosity:        &verbosity,
		}
		return request
	}

	target := input.Target
	request.Overrides.Target = &target
	baseline, err := application.ResolveDiagnoseOptions(
		config,
		nil,
		application.DiagnoseOverrides{Target: &target},
	)
	if err != nil {
		// The application boundary will return the typed validation failure.
		// Do not manufacture defaults in the GUI when a baseline cannot be
		// resolved from the submitted target.
		return request
	}

	mode := model.DiagnosticMode(input.Mode)
	timeout := input.Timeout
	checkTimeout := input.CheckTimeout
	ipVersion := model.IPVersion(input.IPVersion)
	noProxy := input.NoProxy
	maxRedirects := input.MaxRedirects
	method := input.Method
	if mode != model.DiagnosticModeAuto {
		request.Overrides.Mode = &mode
	}
	if timeout != baseline.Timeout {
		request.Overrides.Timeout = &timeout
	}
	if checkTimeout != baseline.CheckTimeout {
		request.Overrides.CheckTimeout = &checkTimeout
	}
	if ipVersion != baseline.IPVersion {
		request.Overrides.IPVersion = &ipVersion
	}
	if noProxy != baseline.NoProxy {
		request.Overrides.NoProxy = &noProxy
	}
	if insecure != baseline.Insecure {
		request.Overrides.Insecure = &insecure
	}
	if allowInsecureRedirects != baseline.AllowInsecureRedirects {
		request.Overrides.AllowInsecureRedirects = &allowInsecureRedirects
	}
	if allowPrivateRedirects != baseline.AllowPrivateRedirects {
		request.Overrides.AllowPrivateRedirects = &allowPrivateRedirects
	}
	if maxRedirects != baseline.MaxRedirects {
		request.Overrides.MaxRedirects = &maxRedirects
	}
	if method != baseline.Method {
		request.Overrides.Method = &method
	}
	if verbosity != baseline.ReportVerbosity {
		request.Overrides.ReportVerbosity = &verbosity
	}
	return request
}

func (c *controller) observeDiagnosis(snapshot taskrunner.Snapshot[model.Diagnosis]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.diagnose.ResetResults()
		c.diagnose.SetRunning(true)
		c.setHeaderStatus(localization.HeaderRunning)
	case taskrunner.StateSuccess:
		diagnosis := privacy.Standard().Diagnosis(snapshot.Value)
		c.lastDiagnosis = diagnosis
		c.haveDiagnosis = true
		c.diagnose.ShowDiagnosis(presenter.Diagnosis(c.texts, diagnosis))
		c.setHeaderForDiagnosis(diagnosis)
	case taskrunner.StateError:
		c.diagnose.ShowError(c.userFacingError(snapshot.Err), false)
		c.setHeaderStatus(localization.HeaderError)
	case taskrunner.StateCancelled:
		c.diagnose.ShowError(c.userFacingError(snapshot.Err), true)
		c.setHeaderStatus(localization.HeaderCancelled)
	}
}

func (c *controller) loadConfiguration() {
	_, err := c.configurationTask.StartRead(func(context.Context) (application.Config, error) {
		return c.backend.Configuration(), nil
	})
	if err != nil {
		c.showUserError(guiTaskStartError(err, "configuration.load"))
	}
}

func (c *controller) observeConfiguration(snapshot taskrunner.Snapshot[application.Config]) {
	if snapshot.State != taskrunner.StateSuccess {
		return
	}
	c.applyConfiguration(snapshot.Value, true)
}

func (c *controller) applyConfiguration(cfg application.Config, rebuildSettings bool) {
	c.mu.Lock()
	c.configuration = cfg
	c.configLoaded = true
	c.mu.Unlock()
	if err := apptheme.Apply(c.texts, c.app, cfg.Appearance.Theme); err != nil {
		c.showUserError(guiBoundaryError(
			err,
			application.ErrorCategoryConfiguration,
			"APP_GUI_THEME_APPLY_FAILED",
			"error.gui_theme_apply_failed",
			map[string]string{"field": "appearance"},
		))
	}
	c.diagnose.SetDefaults(
		cfg.Diagnostics.DefaultTimeout,
		cfg.Diagnostics.CheckTimeout,
		cfg.Diagnostics.PreferredIPVersion,
		cfg.Diagnostics.MaxRedirects,
		!cfg.Network.UseSystemProxy,
	)
	c.diagnose.SetRunEnabled(true)
	if !rebuildSettings {
		return
	}
	c.settings = c.newSettings(cfg)
	if c.currentScreen == "settings" {
		c.content.RemoveAll()
		c.content.Add(c.settings)
	}
}

func (c *controller) startHistoryLoad(search string, status model.Status) {
	_, err := c.historyLoadTask.StartRead(func(ctx context.Context) ([]presenter.HistoryView, error) {
		entries, loadErr := c.backend.ListHistory(ctx, search, status)
		if loadErr != nil {
			return nil, loadErr
		}
		result := make([]presenter.HistoryView, 0, len(entries))
		for _, entry := range entries {
			result = append(result, presenter.History(entry))
		}
		return result, nil
	})
	if err != nil {
		c.history.SetLoading(false)
		c.history.SetMessage(c.texts.Text(localization.HistoryLoadErrorPrefix) + c.userFacingError(guiTaskStartError(err, "history.load")))
	}
}

func (c *controller) observeHistoryLoad(snapshot taskrunner.Snapshot[[]presenter.HistoryView]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.history.SetLoading(true)
	case taskrunner.StateSuccess:
		c.history.SetRows(snapshot.Value)
	case taskrunner.StateError:
		c.history.SetLoading(false)
		c.history.SetMessage(c.texts.Text(localization.HistoryLoadErrorPrefix) + c.userFacingError(snapshot.Err))
	case taskrunner.StateCancelled:
		c.history.SetLoading(false)
		c.history.SetMessage("")
	}
}

func (c *controller) startHistoryRead(action historyReadAction, id string) {
	_, err := c.historyReadTask.StartRead(func(ctx context.Context) (historyReadResult, error) {
		diagnosis, readErr := c.backend.GetDiagnosis(ctx, id)
		return historyReadResult{Action: action, Diagnosis: diagnosis}, readErr
	})
	if err != nil {
		c.history.SetMessage(c.userFacingError(guiTaskStartError(err, "history.read")))
	}
}

func (c *controller) observeHistoryRead(snapshot taskrunner.Snapshot[historyReadResult]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.history.SetMessage(c.texts.Text(localization.CommonLoading))
	case taskrunner.StateError:
		c.history.SetMessage(c.userFacingError(snapshot.Err))
	case taskrunner.StateCancelled:
		c.history.SetMessage("")
	case taskrunner.StateSuccess:
		c.history.SetMessage("")
		switch snapshot.Value.Action {
		case historyReadOpen:
			c.presentHistoricalDiagnosis(snapshot.Value.Diagnosis)
		case historyReadRerun:
			c.startProfile(profileViewFromDiagnosis(snapshot.Value.Diagnosis))
		case historyReadExport:
			c.exportDiagnosis(snapshot.Value.Diagnosis, "markdown")
		}
	}
}

func (c *controller) startHistoryMutation(action historyMutationAction, id string) {
	_, err := c.historyMutationTask.StartMutation(func(ctx context.Context) (historyMutationResult, error) {
		result := historyMutationResult{Action: action}
		if action == historyMutationClear {
			return result, c.backend.ClearHistory(ctx)
		}
		return result, c.backend.DeleteDiagnosis(ctx, id)
	})
	if err != nil {
		c.history.SetMessage(c.userFacingError(guiTaskStartError(err, "history.mutation")))
	}
}

func (c *controller) observeHistoryMutation(snapshot taskrunner.Snapshot[historyMutationResult]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.history.SetMessage(c.texts.Text(localization.CommonSaving))
	case taskrunner.StateSuccess:
		c.history.SetMessage("")
		if c.currentScreen == "history" {
			c.history.Reload()
		}
	case taskrunner.StateError:
		prefix := ""
		if snapshot.Value.Action == historyMutationDelete {
			prefix = c.texts.Text(localization.HistoryDeleteErrorPrefix)
		}
		message := prefix + c.userFacingError(snapshot.Err)
		c.history.SetMessage(message)
		if c.currentScreen != "history" {
			c.showUserError(snapshot.Err)
		}
	case taskrunner.StateCancelled:
		c.history.SetMessage("")
	}
}

func (c *controller) startProfilesLoad() {
	_, err := c.profilesLoadTask.StartRead(func(ctx context.Context) ([]presenter.ProfileView, error) {
		profiles, loadErr := c.backend.ListProfiles(ctx)
		if loadErr != nil {
			return nil, loadErr
		}
		result := make([]presenter.ProfileView, 0, len(profiles))
		for _, profile := range profiles {
			result = append(result, presenter.Profile(profile))
		}
		return result, nil
	})
	if err != nil {
		c.profiles.SetLoading(false)
		c.profiles.SetMessage(c.texts.Text(localization.ProfilesLoadErrorPrefix) + c.userFacingError(guiTaskStartError(err, "profiles.load")))
	}
}

func (c *controller) observeProfilesLoad(snapshot taskrunner.Snapshot[[]presenter.ProfileView]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.profiles.SetLoading(true)
	case taskrunner.StateSuccess:
		c.profiles.SetProfiles(snapshot.Value)
	case taskrunner.StateError:
		c.profiles.SetLoading(false)
		c.profiles.SetMessage(c.texts.Text(localization.ProfilesLoadErrorPrefix) + c.userFacingError(snapshot.Err))
	case taskrunner.StateCancelled:
		c.profiles.SetLoading(false)
		c.profiles.SetMessage("")
	}
}

func (c *controller) startProfileMutation(action profileMutationAction, profile model.Profile) {
	_, err := c.profileMutationTask.StartMutation(func(ctx context.Context) (profileMutationResult, error) {
		saved, saveErr := c.backend.SaveProfile(ctx, profile)
		return profileMutationResult{Action: action, Saved: saved}, saveErr
	})
	if err != nil {
		c.profiles.SetMessage(c.userFacingError(guiTaskStartError(err, "profiles.save")))
	}
}

func (c *controller) startProfileDelete(id int64) {
	_, err := c.profileMutationTask.StartMutation(func(ctx context.Context) (profileMutationResult, error) {
		return profileMutationResult{Action: profileMutationDelete}, c.backend.DeleteProfile(ctx, id)
	})
	if err != nil {
		c.profiles.SetMessage(c.userFacingError(guiTaskStartError(err, "profiles.delete")))
	}
}

func (c *controller) observeProfileMutation(snapshot taskrunner.Snapshot[profileMutationResult]) {
	switch snapshot.State {
	case taskrunner.StateLoading:
		c.profiles.SetMessage(c.texts.Text(localization.CommonSaving))
	case taskrunner.StateSuccess:
		c.profiles.SetMessage("")
		if c.currentScreen == "profiles" {
			c.profiles.Reload()
		}
	case taskrunner.StateError:
		prefix := ""
		switch snapshot.Value.Action {
		case profileMutationDuplicate:
			prefix = c.texts.Text(localization.ProfilesDuplicateErrorPrefix)
		case profileMutationDelete:
			prefix = c.texts.Text(localization.ProfilesDeleteErrorPrefix)
		}
		c.profiles.SetMessage(prefix + c.userFacingError(snapshot.Err))
		if c.currentScreen != "profiles" {
			c.showUserError(snapshot.Err)
		}
	case taskrunner.StateCancelled:
		c.profiles.SetMessage("")
	}
}

func (c *controller) startSettingsSave(
	cfg application.Config,
	complete func(message string),
) {
	c.mu.Lock()
	c.settingsDone = complete
	c.mu.Unlock()
	_, err := c.settingsTask.StartMutation(func(context.Context) (settingsSaveResult, error) {
		result := settingsSaveResult{Config: cfg, Complete: complete}
		return result, c.backend.SaveConfiguration(cfg)
	})
	if err != nil && complete != nil {
		complete(c.userFacingError(guiTaskStartError(err, "settings.save")))
		c.mu.Lock()
		c.settingsDone = nil
		c.mu.Unlock()
	}
}

func (c *controller) observeSettingsSave(snapshot taskrunner.Snapshot[settingsSaveResult]) {
	complete := snapshot.Value.Complete
	if complete == nil {
		c.mu.Lock()
		complete = c.settingsDone
		c.mu.Unlock()
	}
	switch snapshot.State {
	case taskrunner.StateSuccess:
		c.applyConfiguration(snapshot.Value.Config, false)
		if complete != nil {
			complete("")
		}
	case taskrunner.StateError, taskrunner.StateCancelled:
		if complete != nil {
			complete(c.userFacingError(snapshot.Err))
		}
	}
	if snapshot.State == taskrunner.StateSuccess ||
		snapshot.State == taskrunner.StateError ||
		snapshot.State == taskrunner.StateCancelled {
		c.mu.Lock()
		c.settingsDone = nil
		c.mu.Unlock()
	}
}

func (c *controller) prepareReport(
	diagnosis model.Diagnosis,
	format string,
	mode privacy.Mode,
	filename string,
) {
	session := c.beginReportSession()
	_, err := c.reportPrepareTask.StartRead(func(context.Context) (reportPrepareResult, error) {
		content, renderErr := c.backend.RenderReport(format, diagnosis, mode)
		return reportPrepareResult{Session: session, Filename: filename, Content: content}, renderErr
	})
	if err != nil {
		c.showUserError(guiTaskStartError(err, "report.prepare"))
	}
}

func (c *controller) observeReportPrepare(snapshot taskrunner.Snapshot[reportPrepareResult]) {
	if snapshot.State == taskrunner.StateError {
		c.showUserError(snapshot.Err)
		return
	}
	if snapshot.State != taskrunner.StateSuccess || !c.reportSessionCurrent(snapshot.Value.Session) {
		return
	}
	result := snapshot.Value
	picker := dialog.NewFolderOpen(func(folder fyne.ListableURI, pickErr error) {
		if !c.reportSessionCurrent(result.Session) {
			return
		}
		if pickErr != nil {
			c.showUserError(guiBoundaryError(
				pickErr,
				application.ErrorCategoryStorage,
				"APP_REPORT_PICK_FAILED",
				"error.report_pick_failed",
				nil,
			))
			return
		}
		if folder == nil {
			return
		}
		destination, err := exportDestination(folder, result.Filename)
		if err != nil {
			c.showUserError(guiBoundaryError(
				err,
				application.ErrorCategoryValidation,
				"APP_REPORT_DESTINATION_INVALID",
				"error.report_destination_invalid",
				map[string]string{"field": "destination"},
			))
			return
		}
		c.inspectReportDestination(result.Session, destination, result.Content)
	}, c.window)
	picker.Show()
}

func (c *controller) inspectReportDestination(
	session uint64,
	destination fyne.URI,
	content []byte,
) {
	_, err := c.reportInspectTask.StartRead(func(context.Context) (reportInspectResult, error) {
		exists, inspectErr := storage.Exists(destination)
		inspectErr = guiBoundaryError(
			inspectErr,
			application.ErrorCategoryStorage,
			"APP_REPORT_DESTINATION_INSPECT_FAILED",
			"error.report_destination_inspect_failed",
			nil,
		)
		return reportInspectResult{
			Session:     session,
			Destination: destination,
			Content:     content,
			Exists:      exists,
		}, inspectErr
	})
	if err != nil {
		c.showUserError(guiTaskStartError(err, "report.inspect"))
	}
}

func (c *controller) observeReportInspect(snapshot taskrunner.Snapshot[reportInspectResult]) {
	if snapshot.State == taskrunner.StateError {
		c.showUserError(snapshot.Err)
		return
	}
	if snapshot.State != taskrunner.StateSuccess || !c.reportSessionCurrent(snapshot.Value.Session) {
		return
	}
	result := snapshot.Value
	if result.Exists {
		dialog.ShowConfirm(
			c.texts.Text(localization.DialogExportOverwriteTitle),
			fmt.Sprintf(c.texts.Text(localization.DialogExportOverwriteFormat), result.Destination.String()),
			func(confirmed bool) {
				if confirmed && c.reportSessionCurrent(result.Session) {
					c.writeReport(result.Session, result.Destination, result.Content, true)
				}
			},
			c.window,
		)
		return
	}
	c.writeReport(result.Session, result.Destination, result.Content, false)
}

func (c *controller) writeReport(
	session uint64,
	destination fyne.URI,
	content []byte,
	replaceExisting bool,
) {
	_, err := c.reportWriteTask.StartMutation(func(context.Context) (reportWriteResult, error) {
		atomic, writeErr := writeExportURI(destination, content, replaceExisting)
		writeErr = guiBoundaryError(
			writeErr,
			application.ErrorCategoryStorage,
			"APP_REPORT_WRITE_FAILED",
			"error.report_write_failed",
			nil,
		)
		return reportWriteResult{Session: session, Destination: destination, Atomic: atomic}, writeErr
	})
	if err != nil {
		c.showUserError(guiTaskStartError(err, "report.write"))
	}
}

func (c *controller) observeReportWrite(snapshot taskrunner.Snapshot[reportWriteResult]) {
	if snapshot.State == taskrunner.StateError {
		c.showUserError(snapshot.Err)
		return
	}
	if snapshot.State != taskrunner.StateSuccess || !c.reportSessionCurrent(snapshot.Value.Session) {
		return
	}
	messageKey := localization.DialogExportSavedURIFormat
	if snapshot.Value.Atomic {
		messageKey = localization.DialogExportSavedAtomicFormat
	}
	dialog.ShowInformation(
		c.texts.Text(localization.DialogExportSavedTitle),
		fmt.Sprintf(c.texts.Text(messageKey), snapshot.Value.Destination.String()),
		c.window,
	)
}

func (c *controller) beginReportSession() uint64 {
	c.cancelReportTasks()
	c.mu.Lock()
	session := c.reportSession
	c.mu.Unlock()
	return session
}

func (c *controller) cancelReportTasks() {
	for _, cancel := range []func(){
		func() {
			if c.reportPrepareTask != nil {
				c.reportPrepareTask.Cancel()
			}
		},
		func() {
			if c.reportInspectTask != nil {
				c.reportInspectTask.Cancel()
			}
		},
		func() {
			if c.reportWriteTask != nil {
				c.reportWriteTask.Cancel()
			}
		},
	} {
		cancel()
	}
	c.mu.Lock()
	c.reportSession++
	c.mu.Unlock()
}

func (c *controller) reportSessionCurrent(session uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closing && c.reportSession == session
}

func (c *controller) cancelScreenTasks(screen string) {
	switch screen {
	case "diagnose":
		if c.diagnoseTask != nil {
			c.diagnoseTask.Cancel()
		}
		if c.profileMutationTask != nil {
			c.profileMutationTask.Cancel()
		}
	case "history":
		if c.historyLoadTask != nil {
			c.historyLoadTask.Cancel()
		}
		if c.historyReadTask != nil {
			c.historyReadTask.Cancel()
		}
		if c.historyMutationTask != nil {
			c.historyMutationTask.Cancel()
		}
	case "profiles":
		if c.profilesLoadTask != nil {
			c.profilesLoadTask.Cancel()
		}
		if c.profileMutationTask != nil {
			c.profileMutationTask.Cancel()
		}
	case "settings":
		if c.settingsTask != nil {
			c.settingsTask.Cancel()
		}
		if c.historyMutationTask != nil {
			c.historyMutationTask.Cancel()
		}
	}
	c.cancelReportTasks()
}

func (c *controller) userFacingError(err error) string {
	view := application.ToErrorView(err)
	if view == nil {
		return ""
	}
	key := localization.ErrorInternalGuidance
	switch view.Category {
	case application.ErrorCategoryValidation:
		key = localization.ErrorValidationGuidance
	case application.ErrorCategoryConfiguration:
		key = localization.ErrorConfigurationGuidance
	case application.ErrorCategoryStorage:
		key = localization.ErrorStorageGuidance
	case application.ErrorCategoryPermission:
		key = localization.ErrorPermissionGuidance
	case application.ErrorCategoryCancelled:
		key = localization.ErrorCancelledGuidance
	case application.ErrorCategoryNetworkPolicy:
		key = localization.ErrorNetworkPolicyGuidance
	}
	texts := localization.Normalize(c.texts)
	guidance := texts.Text(key)
	if field := view.Arguments["field"]; field != "" {
		guidance += "\n" + fmt.Sprintf(
			texts.Text(localization.ErrorFieldFormat),
			applicationErrorFieldLabel(texts, field),
		)
	}
	return fmt.Sprintf(
		"%s\n\n%s",
		guidance,
		fmt.Sprintf(texts.Text(localization.ErrorReferenceFormat), view.Code),
	)
}

func applicationErrorFieldLabel(texts localization.Catalog, field string) string {
	switch field {
	case "target":
		return texts.Text(localization.CommonTarget)
	case "mode":
		return texts.Text(localization.CommonMode)
	case "timeout":
		return texts.Text(localization.CommonTimeout)
	case "checkTimeout":
		return texts.Text(localization.CommonPerCheckTimeout)
	case "ipVersion":
		return texts.Text(localization.CommonIP)
	case "maxRedirects":
		return texts.Text(localization.CommonMaximumRedirects)
	case "method":
		return texts.Text(localization.CommonHTTPMethod)
	case "reportVerbosity":
		return texts.Text(localization.DiagnoseReportVerbosity)
	default:
		return field
	}
}

func (c *controller) showUserError(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	dialog.ShowError(errors.New(c.userFacingError(err)), c.window)
}

func guiBoundaryError(
	err error,
	category application.ErrorCategory,
	code application.ErrorCode,
	messageID application.MessageID,
	arguments map[string]string,
) error {
	if err == nil {
		return nil
	}
	if _, ok := application.AsError(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrPermission) {
		return application.ClassifyError(err)
	}
	return application.WrapError(err, category, code, messageID, arguments)
}

func guiTaskStartError(err error, operation string) error {
	return guiBoundaryError(
		err,
		application.ErrorCategoryInternal,
		"APP_GUI_TASK_START_FAILED",
		"error.gui_task_start_failed",
		map[string]string{"operation": operation},
	)
}
