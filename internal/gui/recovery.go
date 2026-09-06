package gui

import (
	"context"
	"fmt"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	fynelang "fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	appassets "github.com/Naenier/orynelo/assets"
	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/gui/localization"
	"github.com/Naenier/orynelo/internal/platform"
)

// StartupRecoveryChoice is the action selected in the minimal startup window.
type StartupRecoveryChoice uint8

const (
	StartupRecoveryExit StartupRecoveryChoice = iota
	StartupRecoveryRetry
	StartupRecoveryEphemeral
)

// RunStartupRecovery shows only privacy-safe identifiers and lets the user
// retry initialization or continue without touching local storage.
func RunStartupRecovery(
	ctx context.Context,
	info buildinfo.Info,
	err error,
) StartupRecoveryChoice {
	if ctx == nil {
		ctx = context.Background()
	}
	fyneApp := app.NewWithID("io.github.naenier.orynelo.recovery")
	fyneApp.SetIcon(fyne.NewStaticResource("Icon.png", appassets.IconPNG()))
	texts := localization.ForLanguage(localization.ResolveLanguage(
		localization.LanguageSystem, string(fynelang.SystemLocale()),
	))
	window := fyneApp.NewWindow(texts.Text(localization.RecoveryTitle))
	window.Resize(fyne.NewSize(760, 340))
	window.CenterOnScreen()
	window.SetMaster()

	code := application.ErrorCodeInternal
	if typed, ok := application.AsError(err); ok {
		code = typed.Code()
	}
	choice := StartupRecoveryExit
	closeWith := func(selected StartupRecoveryChoice) {
		choice = selected
		window.SetCloseIntercept(nil)
		window.Close()
	}
	openLocation := func(path string) {
		if path == "" {
			dialog.ShowInformation(
				texts.Text(localization.RecoveryTitle),
				texts.Text(localization.RecoveryPathUnavailable), window,
			)
			return
		}
		location := &url.URL{Scheme: "file", Path: path}
		if openErr := fyneApp.OpenURL(location); openErr != nil {
			dialog.ShowError(fmt.Errorf("%s", texts.Text(localization.RecoveryOpenPathError)), window)
		}
	}
	configPath, logPath := "", ""
	if paths, pathErr := platform.DefaultPaths(); pathErr == nil {
		configPath, logPath = paths.ConfigDir, paths.StateDir
	}
	intro := widget.NewLabel(texts.Text(localization.RecoveryIntro))
	intro.Wrapping = fyne.TextWrapWord
	explanation := widget.NewLabel(texts.Text(localization.RecoveryExplanation))
	explanation.Wrapping = fyne.TextWrapWord
	window.SetContent(container.NewBorder(
		nil,
		widget.NewLabel(fmt.Sprintf(texts.Text(localization.RecoveryVersionFormat), info.Version)),
		nil,
		nil,
		container.NewVScroll(container.NewVBox(
			intro,
			widget.NewLabel(fmt.Sprintf(texts.Text(localization.RecoveryReferenceFormat), code)),
			explanation,
			container.NewGridWithColumns(2,
				widget.NewButton(texts.Text(localization.RecoveryRetry), func() { closeWith(StartupRecoveryRetry) }),
				widget.NewButton(texts.Text(localization.RecoveryContinue), func() { closeWith(StartupRecoveryEphemeral) }),
				widget.NewButton(texts.Text(localization.RecoveryOpenConfig), func() { openLocation(configPath) }),
				widget.NewButton(texts.Text(localization.RecoveryOpenLogs), func() { openLocation(logPath) }),
			),
			widget.NewButton(texts.Text(localization.RecoveryExit), func() { closeWith(StartupRecoveryExit) }),
		)),
	))
	window.SetCloseIntercept(func() { closeWith(StartupRecoveryExit) })
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			fyne.Do(func() { closeWith(StartupRecoveryExit) })
		case <-stopped:
		}
	}()
	window.ShowAndRun()
	close(stopped)
	return choice
}
