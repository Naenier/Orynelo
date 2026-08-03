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

// reportPrepareResult contains rendered bytes and destination metadata.
type reportPrepareResult struct {
	Session  uint64
	Filename string
	Content  []byte
}

// reportInspectResult records whether the selected destination already exists.
type reportInspectResult struct {
	Session     uint64
	Destination fyne.URI
	Content     []byte
	Exists      bool
}

// reportWriteResult describes a completed report write.
type reportWriteResult struct {
	Session     uint64
	Destination fyne.URI
	Atomic      bool
}

// buildTaskScopes creates independently replaceable asynchronous operation
// streams for every controller workflow.
func (c *controller) buildTaskScopes() error {
	var err error
	c.diagnoseCoordinator, err = NewDiagnoseCoordinator(c.tasks, c.backend, c.observeDiagnosis)
	if err != nil {
		return err
	}
	c.historyCoordinator, err = NewHistoryCoordinator(c.tasks, c.backend, c.observeHistory)
	if err != nil {
		return err
	}
	c.profilesCoordinator, err = NewProfilesCoordinator(c.tasks, c.backend, c.observeProfiles)
	if err != nil {
		return err
	}
	c.settingsCoordinator, err = NewSettingsCoordinator(c.tasks, c.backend, c.observeSettings)
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

// observeDiagnosis applies current diagnosis lifecycle transitions on the GUI thread.
func (c *controller) observeDiagnosis(state DiagnoseViewModel) {
	switch state.State {
	case taskrunner.StateLoading:
		c.diagnose.ResetResults()
		c.diagnose.SetRunning(true)
		c.setHeaderStatus(localization.HeaderRunning)
	case taskrunner.StateSuccess:
		diagnosis := state.Diagnosis
		c.lastDiagnosis = diagnosis
		c.haveDiagnosis = true
		c.diagnose.ShowDiagnosis(presenter.Diagnosis(c.texts, diagnosis))
		c.setHeaderForDiagnosis(diagnosis)
	case taskrunner.StateError:
		c.diagnose.ShowError(c.userFacingError(state.Err), false)
		c.setHeaderStatus(localization.HeaderError)
	case taskrunner.StateCancelled:
		c.diagnose.ShowError(c.userFacingError(state.Err), true)
		c.setHeaderStatus(localization.HeaderCancelled)
	}
}

// loadConfiguration starts the initial backend settings read.
func (c *controller) loadConfiguration() {
	err := c.settingsCoordinator.Load()
	if err != nil {
		c.showUserError(guiTaskStartError(err, "configuration.load"))
	}
}

// applyConfiguration updates controller defaults, theme, and optionally the
// settings screen from one configuration snapshot.
func (c *controller) applyConfiguration(cfg application.Config, rebuildSettings bool) {
	c.mu.Lock()
	c.configuration = cfg
	c.configLoaded = true
	c.mu.Unlock()
	if c.diagnoseCoordinator != nil {
		c.diagnoseCoordinator.SetConfiguration(cfg)
	}
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

// startHistoryLoad submits a bounded read for filtered history rows.
func (c *controller) startHistoryLoad(search string, status model.Status) {
	err := c.historyCoordinator.Load(search, status)
	if err != nil {
		c.history.SetLoading(false)
		c.history.SetMessage(c.texts.Text(localization.HistoryLoadErrorPrefix) + c.userFacingError(guiTaskStartError(err, "history.load")))
	}
}

// observeHistory applies the coordinator's testable state to History widgets
// and routes successful reads to root-level navigation or dialogs.
func (c *controller) observeHistory(state HistoryViewModel) {
	switch state.Changed {
	case HistoryViewLoadChanged:
		switch state.LoadState {
		case taskrunner.StateLoading:
			c.history.SetLoading(true)
		case taskrunner.StateSuccess:
			c.history.SetRows(state.Rows)
		case taskrunner.StateError:
			c.history.SetLoading(false)
			c.history.SetMessage(c.texts.Text(localization.HistoryLoadErrorPrefix) + c.userFacingError(state.LoadErr))
		case taskrunner.StateCancelled:
			c.history.SetLoading(false)
		}
	case HistoryViewReadChanged:
		switch state.ReadState {
		case taskrunner.StateLoading:
			c.history.SetMessage(c.texts.Text(localization.CommonLoading))
		case taskrunner.StateError:
			c.history.SetMessage(c.userFacingError(state.ReadErr))
		case taskrunner.StateCancelled:
			c.history.SetMessage("")
		case taskrunner.StateSuccess:
			c.history.SetMessage("")
			switch state.ReadAction {
			case HistoryReadOpen:
				c.presentHistoricalDiagnosis(state.Diagnosis)
			case HistoryReadRerun:
				c.startProfile(profileViewFromDiagnosis(state.Diagnosis))
			case HistoryReadExport:
				c.exportDiagnosis(state.Diagnosis, "markdown")
			}
		}
	case HistoryViewMutationChanged:
		switch state.MutationState {
		case taskrunner.StateLoading:
			c.history.SetMessage(c.texts.Text(localization.CommonSaving))
		case taskrunner.StateSuccess:
			c.history.SetMessage("")
			if c.currentScreen == "history" {
				c.history.Reload()
			}
		case taskrunner.StateError:
			prefix := ""
			if state.Mutation == HistoryMutationDelete {
				prefix = c.texts.Text(localization.HistoryDeleteErrorPrefix)
			}
			c.history.SetMessage(prefix + c.userFacingError(state.MutationErr))
			if c.currentScreen != "history" {
				c.showUserError(state.MutationErr)
			}
		case taskrunner.StateCancelled:
			c.history.SetMessage("")
		}
	}
}

// startHistoryRead loads one diagnosis for opening, rerunning, or exporting.
func (c *controller) startHistoryRead(action HistoryReadAction, id string) {
	err := c.historyCoordinator.Read(action, id)
	if err != nil {
		c.history.SetMessage(c.userFacingError(guiTaskStartError(err, "history.read")))
	}
}

// startHistoryMutation serializes deletion or clearing through the mutation queue.
func (c *controller) startHistoryMutation(action HistoryMutationAction, id string) {
	err := c.historyCoordinator.Mutate(action, id)
	if err != nil {
		c.history.SetMessage(c.userFacingError(guiTaskStartError(err, "history.mutation")))
	}
}

// startProfilesLoad submits a bounded read for all saved profiles.
func (c *controller) startProfilesLoad() {
	err := c.profilesCoordinator.Load()
	if err != nil {
		c.profiles.SetLoading(false)
		c.profiles.SetMessage(c.texts.Text(localization.ProfilesLoadErrorPrefix) + c.userFacingError(guiTaskStartError(err, "profiles.load")))
	}
}

// observeProfiles applies the coordinator's testable state to profile widgets.
func (c *controller) observeProfiles(state ProfilesViewModel) {
	switch state.Changed {
	case ProfilesViewLoadChanged:
		switch state.LoadState {
		case taskrunner.StateLoading:
			c.profiles.SetLoading(true)
		case taskrunner.StateSuccess:
			c.profiles.SetProfiles(state.Profiles)
		case taskrunner.StateError:
			c.profiles.SetLoading(false)
			c.profiles.SetMessage(c.texts.Text(localization.ProfilesLoadErrorPrefix) + c.userFacingError(state.LoadErr))
		case taskrunner.StateCancelled:
			c.profiles.SetLoading(false)
		}
	case ProfilesViewMutationChanged:
		switch state.MutationState {
		case taskrunner.StateLoading:
			c.profiles.SetMessage(c.texts.Text(localization.CommonSaving))
		case taskrunner.StateSuccess:
			c.profiles.SetMessage("")
			if c.currentScreen == "profiles" {
				c.profiles.Reload()
			}
		case taskrunner.StateError:
			prefix := ""
			switch state.Mutation {
			case ProfileMutationDuplicate:
				prefix = c.texts.Text(localization.ProfilesDuplicateErrorPrefix)
			case ProfileMutationDelete:
				prefix = c.texts.Text(localization.ProfilesDeleteErrorPrefix)
			}
			c.profiles.SetMessage(prefix + c.userFacingError(state.MutationErr))
			if c.currentScreen != "profiles" {
				c.showUserError(state.MutationErr)
			}
		case taskrunner.StateCancelled:
			c.profiles.SetMessage("")
		}
	}
}

// startProfileMutation serializes profile creation, update, or duplication.
func (c *controller) startProfileMutation(action ProfileMutationAction, profile model.Profile) {
	err := c.profilesCoordinator.Save(action, profile)
	if err != nil {
		c.profiles.SetMessage(c.userFacingError(guiTaskStartError(err, "profiles.save")))
	}
}

// startProfileDelete serializes removal of one profile by identifier.
func (c *controller) startProfileDelete(id int64) {
	err := c.profilesCoordinator.Delete(id)
	if err != nil {
		c.profiles.SetMessage(c.userFacingError(guiTaskStartError(err, "profiles.delete")))
	}
}

// startSettingsSave persists configuration through the shared mutation queue.
func (c *controller) startSettingsSave(
	cfg application.Config,
	complete func(message string),
) {
	c.mu.Lock()
	c.settingsDone = complete
	c.mu.Unlock()
	err := c.settingsCoordinator.Save(cfg)
	if err != nil && complete != nil {
		complete(c.userFacingError(guiTaskStartError(err, "settings.save")))
		c.mu.Lock()
		c.settingsDone = nil
		c.mu.Unlock()
	}
}

// observeSettings applies coordinator state while keeping widget completion
// callbacks and theme changes at the root presentation boundary.
func (c *controller) observeSettings(state SettingsViewModel) {
	if state.Changed == SettingsViewLoadChanged {
		if state.LoadState == taskrunner.StateSuccess {
			c.applyConfiguration(state.Config, true)
		}
		return
	}
	if state.Changed != SettingsViewSaveChanged {
		return
	}

	c.mu.Lock()
	complete := c.settingsDone
	c.mu.Unlock()
	switch state.SaveState {
	case taskrunner.StateSuccess:
		c.applyConfiguration(state.Config, false)
		if complete != nil {
			complete("")
		}
	case taskrunner.StateError, taskrunner.StateCancelled:
		if complete != nil {
			complete(c.userFacingError(state.SaveErr))
		}
	}
	if state.SaveState == taskrunner.StateSuccess ||
		state.SaveState == taskrunner.StateError ||
		state.SaveState == taskrunner.StateCancelled {
		c.mu.Lock()
		c.settingsDone = nil
		c.mu.Unlock()
	}
}

// prepareReport starts privacy projection and report rendering off the GUI thread.
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

// observeReportPrepare opens destination selection for the current report session.
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

// inspectReportDestination checks for an existing file before any write occurs.
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

// observeReportInspect requests overwrite consent or proceeds with a safe write.
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

// writeReport commits rendered content to the selected destination asynchronously.
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

// observeReportWrite reports completion for the current export session.
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

// beginReportSession invalidates older export callbacks and returns a new generation.
func (c *controller) beginReportSession() uint64 {
	c.cancelReportTasks()
	c.mu.Lock()
	session := c.reportSession
	c.mu.Unlock()
	return session
}

// cancelReportTasks invalidates all work associated with the previous export session.
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

// reportSessionCurrent reports whether an export callback belongs to the active session.
func (c *controller) reportSessionCurrent(session uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closing && c.reportSession == session
}

// cancelScreenTasks invalidates asynchronous work owned by a page being left.
func (c *controller) cancelScreenTasks(screen string) {
	switch screen {
	case "diagnose":
		if c.diagnoseCoordinator != nil {
			c.diagnoseCoordinator.Cancel()
		}
		if c.profilesCoordinator != nil {
			c.profilesCoordinator.Cancel()
		}
	case "history":
		if c.historyCoordinator != nil {
			c.historyCoordinator.Cancel()
		}
	case "profiles":
		if c.profilesCoordinator != nil {
			c.profilesCoordinator.Cancel()
		}
	case "settings":
		if c.settingsCoordinator != nil {
			c.settingsCoordinator.Cancel()
		}
		if c.historyCoordinator != nil {
			c.historyCoordinator.Cancel()
		}
	}
	c.cancelReportTasks()
}

// userFacingError renders a typed application error as localized, privacy-safe text.
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

// applicationErrorFieldLabel maps stable validation field names to localized labels.
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

// showUserError presents a boundary-safe error dialog.
func (c *controller) showUserError(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	dialog.ShowError(errors.New(c.userFacingError(err)), c.window)
}

// guiBoundaryError wraps an adapter failure in the application's stable error contract.
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

// guiTaskStartError classifies a failure to enqueue GUI background work.
func guiTaskStartError(err error, operation string) error {
	return guiBoundaryError(
		err,
		application.ErrorCategoryInternal,
		"APP_GUI_TASK_START_FAILED",
		"error.gui_task_start_failed",
		map[string]string{"operation": operation},
	)
}
