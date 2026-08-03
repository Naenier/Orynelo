package screens

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

// SettingsActions connects the settings screen to the application layer.
type SettingsActions struct {
	// Save starts asynchronous persistence. The completion callback must be
	// delivered on the GUI thread with an empty message on success or a
	// cause-free, user-facing message on failure.
	Save             func(application.Config, func(message string))
	ClearHistory     func()
	OpenLogDirectory func() error
	ApplyTheme       func(string) error
}

// NewSettings builds a functional settings editor for implemented settings.
func NewSettings(
	texts localization.Catalog,
	initial application.Config,
	actions SettingsActions,
) fyne.CanvasObject {
	texts = localization.Normalize(texts)
	ipValues := map[string]string{
		texts.Text(localization.OptionAuto): "auto",
		texts.Text(localization.OptionIPv4): "4",
		texts.Text(localization.OptionIPv6): "6",
	}
	ipLabels := reverseLabels(ipValues)
	themeValues := map[string]string{
		texts.Text(localization.OptionSystem): "system",
		texts.Text(localization.OptionLight):  "light",
		texts.Text(localization.OptionDark):   "dark",
	}
	themeLabels := reverseLabels(themeValues)
	logValues := map[string]string{
		texts.Text(localization.OptionDebug): "debug",
		texts.Text(localization.OptionInfo):  "info",
		texts.Text(localization.OptionWarn):  "warn",
		texts.Text(localization.OptionError): "error",
	}
	logLabels := reverseLabels(logValues)

	timeout := widget.NewEntry()
	timeout.SetText(formatSettingsDuration(initial.Diagnostics.DefaultTimeout))
	checkTimeout := widget.NewEntry()
	checkTimeout.SetText(formatSettingsDuration(initial.Diagnostics.CheckTimeout))
	redirects := widget.NewEntry()
	redirects.SetText(strconv.Itoa(initial.Diagnostics.MaxRedirects))
	ipVersion := widget.NewSelect([]string{
		ipLabels["auto"],
		ipLabels["4"],
		ipLabels["6"],
	}, nil)
	ipVersion.SetSelected(ipLabels[initial.Diagnostics.PreferredIPVersion])
	certificateWarning := widget.NewEntry()
	certificateWarning.SetText(formatSettingsDuration(
		initial.Diagnostics.CertificateWarningThreshold,
	))

	useProxy := widget.NewCheck(texts.Text(localization.SettingsUseSystemProxy), nil)
	useProxy.SetChecked(initial.Network.UseSystemProxy)
	userAgent := widget.NewEntry()
	userAgent.SetText(initial.Network.UserAgent)

	historyEnabled := widget.NewCheck(texts.Text(localization.SettingsSaveHistory), nil)
	historyEnabled.SetChecked(initial.History.Enabled)
	historyLimit := widget.NewEntry()
	historyLimit.SetText(strconv.Itoa(initial.History.MaxEntries))

	appearance := widget.NewRadioGroup([]string{
		themeLabels["system"],
		themeLabels["light"],
		themeLabels["dark"],
	}, nil)
	appearance.Horizontal = true
	appearance.SetSelected(themeLabels[initial.Appearance.Theme])

	logLevel := widget.NewSelect([]string{
		logLabels["debug"],
		logLabels["info"],
		logLabels["warn"],
		logLabels["error"],
	}, nil)
	logLevel.SetSelected(logLabels[initial.Logging.Level])
	status := widget.NewLabel(texts.Text(localization.SettingsStoredLocally))
	status.Wrapping = fyne.TextWrapWord
	status.Importance = widget.LowImportance

	readConfig := func() (application.Config, error) {
		cfg := initial
		var err error
		cfg.Diagnostics.DefaultTimeout, err = parseSettingsDuration(timeout.Text)
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidDefaultTimeout),
				err,
			)
		}
		cfg.Diagnostics.CheckTimeout, err = parseSettingsDuration(checkTimeout.Text)
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidCheckTimeout),
				err,
			)
		}
		cfg.Diagnostics.MaxRedirects, err = strconv.Atoi(strings.TrimSpace(redirects.Text))
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidRedirects),
				err,
			)
		}
		cfg.Diagnostics.CertificateWarningThreshold, err = parseSettingsDuration(
			certificateWarning.Text,
		)
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidCertificate),
				err,
			)
		}
		cfg.Diagnostics.PreferredIPVersion = ipValues[ipVersion.Selected]
		cfg.Network.UseSystemProxy = useProxy.Checked
		cfg.Network.UserAgent = strings.TrimSpace(userAgent.Text)
		cfg.History.Enabled = historyEnabled.Checked
		cfg.History.MaxEntries, err = strconv.Atoi(strings.TrimSpace(historyLimit.Text))
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidHistoryLimit),
				err,
			)
		}
		cfg.Appearance.Theme = themeValues[appearance.Selected]
		cfg.Logging.Level = logValues[logLevel.Selected]
		if err := cfg.Validate(); err != nil {
			return application.Config{}, err
		}
		return cfg, nil
	}

	var save *widget.Button
	save = widget.NewButtonWithIcon(
		texts.Text(localization.SettingsSave),
		theme.DocumentSaveIcon(),
		func() {
			if actions.Save == nil {
				return
			}
			cfg, err := readConfig()
			if err != nil {
				status.SetText(texts.Text(localization.SettingsSaveErrorPrefix) + err.Error())
				status.Importance = widget.DangerImportance
				status.Refresh()
				return
			}
			save.Disable()
			status.SetText(texts.Text(localization.CommonSaving))
			status.Importance = widget.LowImportance
			status.Refresh()
			actions.Save(cfg, func(message string) {
				if message != "" {
					status.SetText(texts.Text(localization.SettingsSaveErrorPrefix) + message)
					status.Importance = widget.DangerImportance
					status.Refresh()
					save.Enable()
					return
				}
				initial = cfg
				status.SetText(texts.Text(localization.SettingsSaved))
				status.Importance = widget.SuccessImportance
				status.Refresh()
				save.Disable()
			})
		})
	save.Importance = widget.HighImportance
	save.Disable()

	clearHistory := widget.NewButtonWithIcon(
		texts.Text(localization.HistoryClear),
		theme.DeleteIcon(),
		func() {
			if actions.ClearHistory == nil {
				return
			}
			actions.ClearHistory()
		},
	)
	clearHistory.Importance = widget.DangerImportance
	if actions.ClearHistory == nil {
		clearHistory.Disable()
	}
	openLogs := widget.NewButtonWithIcon(
		texts.Text(localization.SettingsOpenLogDirectory),
		theme.FolderOpenIcon(),
		func() {
			if actions.OpenLogDirectory == nil {
				return
			}
			if err := actions.OpenLogDirectory(); err != nil {
				status.SetText(
					texts.Text(localization.SettingsOpenLogErrorPrefix) + err.Error(),
				)
				status.Importance = widget.DangerImportance
				status.Refresh()
			}
		},
	)
	if actions.OpenLogDirectory == nil {
		openLogs.Disable()
	}

	markDirty := func() {
		if actions.Save != nil {
			save.Enable()
		}
		status.SetText(texts.Text(localization.SettingsUnsaved))
		status.Importance = widget.WarningImportance
		status.Refresh()
	}
	for _, entry := range []*widget.Entry{
		timeout,
		checkTimeout,
		redirects,
		certificateWarning,
		userAgent,
		historyLimit,
	} {
		entry.OnChanged = func(string) {
			markDirty()
		}
	}
	ipVersion.OnChanged = func(string) {
		markDirty()
	}
	useProxy.OnChanged = func(bool) {
		markDirty()
	}
	historyEnabled.OnChanged = func(enabled bool) {
		if enabled {
			historyLimit.Enable()
		} else {
			historyLimit.Disable()
		}
		markDirty()
	}
	if !historyEnabled.Checked {
		historyLimit.Disable()
	}
	lastAppliedTheme := appearance.Selected
	revertingTheme := false
	appearance.OnChanged = func(selected string) {
		if revertingTheme {
			return
		}
		wasDirty := !save.Disabled()
		if actions.ApplyTheme != nil {
			if err := actions.ApplyTheme(themeValues[selected]); err != nil {
				revertingTheme = true
				appearance.SetSelected(lastAppliedTheme)
				revertingTheme = false
				if !wasDirty {
					save.Disable()
				}
				status.SetText(
					texts.Text(localization.SettingsThemeErrorPrefix) + err.Error(),
				)
				status.Importance = widget.DangerImportance
				status.Refresh()
				return
			}
		}
		lastAppliedTheme = selected
		markDirty()
	}
	logLevel.OnChanged = func(string) {
		markDirty()
	}

	durationHint := widget.NewLabel(texts.Text(localization.SettingsDurationHint))
	durationHint.Wrapping = fyne.TextWrapWord
	durationHint.Importance = widget.LowImportance
	durationHint.SizeName = theme.SizeNameCaptionText
	diagnostics := widget.NewCard(
		texts.Text(localization.SettingsDiagnostics),
		texts.Text(localization.SettingsDiagnosticsSubtitle),
		container.NewVBox(
			widget.NewForm(
				widget.NewFormItem(texts.Text(localization.SettingsDefaultTimeout), timeout),
				widget.NewFormItem(texts.Text(localization.CommonPerCheckTimeout), checkTimeout),
				widget.NewFormItem(texts.Text(localization.CommonMaximumRedirects), redirects),
				widget.NewFormItem(texts.Text(localization.SettingsPreferredIPVersion), ipVersion),
				widget.NewFormItem(
					texts.Text(localization.SettingsCertificateWarning),
					certificateWarning,
				),
			),
			durationHint,
		),
	)
	network := widget.NewCard(
		texts.Text(localization.SettingsNetwork),
		texts.Text(localization.SettingsNetworkSubtitle),
		container.NewVBox(
			useProxy,
			widget.NewForm(
				widget.NewFormItem(texts.Text(localization.SettingsUserAgent), userAgent),
			),
		),
	)
	clearHint := widget.NewLabel(texts.Text(localization.SettingsClearHistoryHint))
	clearHint.Wrapping = fyne.TextWrapWord
	clearHint.Importance = widget.LowImportance
	history := widget.NewCard(
		texts.Text(localization.NavigationHistory),
		texts.Text(localization.SettingsHistorySubtitle),
		container.NewVBox(
			historyEnabled,
			widget.NewForm(
				widget.NewFormItem(
					texts.Text(localization.SettingsMaximumEntries),
					historyLimit,
				),
			),
			widget.NewSeparator(),
			container.NewBorder(nil, nil, nil, clearHistory, clearHint),
		),
	)
	appearanceCard := widget.NewCard(
		texts.Text(localization.SettingsAppearance),
		texts.Text(localization.SettingsAppearanceSubtitle),
		appearance,
	)
	logging := widget.NewCard(
		texts.Text(localization.SettingsLogging),
		texts.Text(localization.SettingsLoggingSubtitle),
		container.NewVBox(
			widget.NewForm(
				widget.NewFormItem(texts.Text(localization.SettingsLogLevel), logLevel),
			),
			container.NewBorder(nil, nil, nil, openLogs),
		),
	)
	privacyText := widget.NewLabel(
		texts.Text(localization.PrivacyNoTelemetry) + " " +
			texts.Text(localization.PrivacyDataRemainsOnDevice),
	)
	privacyText.Wrapping = fyne.TextWrapWord
	privacy := widget.NewCard(
		texts.Text(localization.SettingsPrivacy),
		texts.Text(localization.SettingsPrivacySubtitle),
		privacyText,
	)

	content := container.NewVBox(
		container.NewGridWithColumns(
			2,
			container.NewVBox(diagnostics, appearanceCard),
			container.NewVBox(network, history),
		),
		container.NewGridWithColumns(2, logging, privacy),
	)
	scroll := container.NewVScroll(newReadableWidth(content, settingsReadableWidth))
	footer := widget.NewCard(
		"",
		"",
		container.NewBorder(nil, nil, nil, save, status),
	)

	return container.NewBorder(
		nil,
		newReadableWidth(footer, settingsReadableWidth),
		nil,
		nil,
		scroll,
	)
}

const settingsReadableWidth float32 = 980

// parseSettingsDuration accepts the duration syntax exposed by the settings form.
func parseSettingsDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(value, "d")), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration %q", value)
		}
		const day = 24 * time.Hour
		if days > int64((1<<63-1)/day) || days < int64((-1<<63)/day) {
			return 0, fmt.Errorf("day duration %q is out of range", value)
		}
		return time.Duration(days) * day, nil
	}
	return time.ParseDuration(value)
}

// formatSettingsDuration renders a stable editable duration value.
func formatSettingsDuration(value time.Duration) string {
	const day = 24 * time.Hour
	if value != 0 && value%day == 0 {
		return fmt.Sprintf("%dd", value/day)
	}
	return value.String()
}

// readableWidthLayout centers one object and caps its maximum content width.
type readableWidthLayout struct {
	maxWidth float32
}

// Layout centers the child while respecting its minimum and configured maximum.
func (layout readableWidthLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	width := fyne.Min(size.Width, layout.maxWidth)
	for _, object := range objects {
		if !object.Visible() {
			continue
		}
		object.Move(fyne.NewPos((size.Width-width)/2, 0))
		object.Resize(fyne.NewSize(width, size.Height))
	}
}

// MinSize returns the child's intrinsic minimum size.
func (layout readableWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	minimum := fyne.NewSize(0, 0)
	for _, object := range objects {
		if object.Visible() {
			minimum = minimum.Max(object.MinSize())
		}
	}
	minimum.Width = fyne.Min(minimum.Width, layout.maxWidth)
	return minimum
}

// newReadableWidth wraps content in the centered readable-width layout.
func newReadableWidth(object fyne.CanvasObject, maxWidth float32) *fyne.Container {
	return container.New(readableWidthLayout{maxWidth: maxWidth}, object)
}

// reverseLabels builds a localized-label-to-domain-value lookup map.
func reverseLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for label, value := range values {
		result[value] = label
	}
	return result
}
