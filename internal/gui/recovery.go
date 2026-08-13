package gui

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	appassets "github.com/Naenier/orynelo/assets"
	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
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
	window := fyneApp.NewWindow("Orynelo startup recovery")
	window.Resize(fyne.NewSize(560, 240))
	window.CenterOnScreen()
	window.SetMaster()

	code := application.ErrorCodeInternal
	message := application.MessageIDInternal
	if typed, ok := application.AsError(err); ok {
		code = typed.Code()
		message = typed.MessageID()
	}
	choice := StartupRecoveryExit
	closeWith := func(selected StartupRecoveryChoice) {
		choice = selected
		window.SetCloseIntercept(nil)
		window.Close()
	}
	window.SetContent(container.NewVBox(
		widget.NewLabel("Orynelo could not initialize its mandatory runtime."),
		widget.NewLabel(fmt.Sprintf("%s (%s)", code, message)),
		widget.NewLabel("Retry, or continue in memory without configuration, logs, history, or profiles."),
		container.NewHBox(
			widget.NewButton("Retry", func() { closeWith(StartupRecoveryRetry) }),
			widget.NewButton("Continue in memory", func() { closeWith(StartupRecoveryEphemeral) }),
			widget.NewButton("Exit", func() { closeWith(StartupRecoveryExit) }),
		),
		widget.NewLabel("Version "+info.Version),
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
