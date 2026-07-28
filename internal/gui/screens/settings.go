package screens

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/gui/localization"
)

// SettingsActions connects the settings screen to the application layer.
type SettingsActions struct {
	Save             func(application.Config) error
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
		strings.ToLower(texts.Text(localization.OptionAuto)): "auto",
		texts.Text(localization.OptionIP4Value):              "4",
		texts.Text(localization.OptionIP6Value):              "6",
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
	timeout.SetText(initial.Diagnostics.DefaultTimeout.String())
	checkTimeout := widget.NewEntry()
	checkTimeout.SetText(initial.Diagnostics.CheckTimeout.String())
	redirects := widget.NewEntry()
	redirects.SetText(strconv.Itoa(initial.Diagnostics.MaxRedirects))
	ipVersion := widget.NewSelect([]string{
		ipLabels["auto"],
		ipLabels["4"],
		ipLabels["6"],
	}, nil)
	ipVersion.SetSelected(ipLabels[initial.Diagnostics.PreferredIPVersion])
	certificateWarning := widget.NewEntry()
	certificateWarning.SetText(initial.Diagnostics.CertificateWarningThreshold.String())

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
	}, func(selected string) {
		if actions.ApplyTheme != nil {
			_ = actions.ApplyTheme(themeValues[selected])
		}
	})
	appearance.Horizontal = true
	appearance.SetSelected(themeLabels[initial.Appearance.Theme])

	logLevel := widget.NewSelect([]string{
		logLabels["debug"],
		logLabels["info"],
		logLabels["warn"],
		logLabels["error"],
	}, nil)
	logLevel.SetSelected(logLabels[initial.Logging.Level])
	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	readConfig := func() (application.Config, error) {
		cfg := initial
		var err error
		cfg.Diagnostics.DefaultTimeout, err = time.ParseDuration(strings.TrimSpace(timeout.Text))
		if err != nil {
			return application.Config{}, fmt.Errorf(
				texts.Text(localization.SettingsInvalidDefaultTimeout),
				err,
			)
		}
		cfg.Diagnostics.CheckTimeout, err = time.ParseDuration(strings.TrimSpace(checkTimeout.Text))
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
		cfg.Diagnostics.CertificateWarningThreshold, err = time.ParseDuration(strings.TrimSpace(certificateWarning.Text))
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

	save := widget.NewButton(texts.Text(localization.SettingsSave), func() {
		cfg, err := readConfig()
		if err == nil && actions.Save != nil {
			err = actions.Save(cfg)
		}
		if err != nil {
			status.SetText(texts.Text(localization.SettingsSaveErrorPrefix) + err.Error())
			return
		}
		initial = cfg
		status.SetText(texts.Text(localization.SettingsSaved))
	})

	clearHistory := widget.NewButton(texts.Text(localization.HistoryClear), func() {
		if actions.ClearHistory == nil {
			return
		}
		actions.ClearHistory()
	})
	openLogs := widget.NewButton(texts.Text(localization.SettingsOpenLogDirectory), func() {
		if actions.OpenLogDirectory == nil {
			return
		}
		if err := actions.OpenLogDirectory(); err != nil {
			status.SetText(texts.Text(localization.SettingsOpenLogErrorPrefix) + err.Error())
		}
	})

	diagnostics := widget.NewCard(texts.Text(localization.SettingsDiagnostics), "", widget.NewForm(
		widget.NewFormItem(texts.Text(localization.SettingsDefaultTimeout), timeout),
		widget.NewFormItem(texts.Text(localization.CommonPerCheckTimeout), checkTimeout),
		widget.NewFormItem(texts.Text(localization.CommonMaximumRedirects), redirects),
		widget.NewFormItem(texts.Text(localization.SettingsPreferredIPVersion), ipVersion),
		widget.NewFormItem(texts.Text(localization.SettingsCertificateWarning), certificateWarning),
	))
	network := widget.NewCard(texts.Text(localization.SettingsNetwork), "", container.NewVBox(
		useProxy,
		widget.NewForm(widget.NewFormItem(texts.Text(localization.SettingsUserAgent), userAgent)),
	))
	history := widget.NewCard(texts.Text(localization.NavigationHistory), "", container.NewVBox(
		historyEnabled,
		widget.NewForm(widget.NewFormItem(texts.Text(localization.SettingsMaximumEntries), historyLimit)),
		clearHistory,
	))
	appearanceCard := widget.NewCard(texts.Text(localization.SettingsAppearance), "", appearance)
	logging := widget.NewCard(texts.Text(localization.SettingsLogging), "", container.NewVBox(
		widget.NewForm(widget.NewFormItem(texts.Text(localization.SettingsLogLevel), logLevel)),
		openLogs,
	))
	privacy := widget.NewCard(texts.Text(localization.SettingsPrivacy), "", container.NewVBox(
		widget.NewLabel(texts.Text(localization.PrivacyNoTelemetry)),
		widget.NewLabel(texts.Text(localization.PrivacyDataRemainsOnDevice)),
	))

	return container.NewVScroll(container.NewVBox(
		diagnostics,
		network,
		history,
		appearanceCard,
		logging,
		privacy,
		save,
		status,
	))
}

func reverseLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for label, value := range values {
		result[value] = label
	}
	return result
}
