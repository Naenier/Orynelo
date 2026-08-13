// Binary orynelo provides the command-line interface to the shared
// diagnostic application service.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/bootstrap"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/cli"
	"github.com/Naenier/orynelo/internal/config"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/platform"
	"github.com/Naenier/orynelo/internal/privacy"
)

// main translates the process context and command result into an exit status.
func main() {
	os.Exit(run())
}

// run assembles the CLI command tree and owns process-level cancellation.
func run() int {
	info := buildinfo.Current()
	lazy := &lazyApplication{info: info}
	lazy.warningWriter = os.Stderr
	defer func() {
		if err := lazy.Close(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Error closing Orynelo:", err)
		}
	}()

	ctx, stop := platform.NotifyShutdownContext(
		context.Background(),
		func() { os.Exit(cli.ExitCancel) },
		terminationSignals()...,
	)
	defer stop()
	root := cli.NewRoot(cli.Options{
		Application:          lazy,
		Build:                info,
		Stdout:               os.Stdout,
		Stderr:               os.Stderr,
		SetLogLevel:          lazy.SetLogLevel,
		SetPersistencePolicy: lazy.SetPersistencePolicy,
	})
	return cli.Execute(ctx, root, os.Stderr)
}

// lazyApplication delays runtime initialization until a command needs backend
// services, allowing lightweight commands such as help and version to run
// without opening configuration, logs, or storage.
type lazyApplication struct {
	info                   buildinfo.Info
	openRuntime            func(buildinfo.Info) (*bootstrap.Runtime, error)
	openRuntimeWithOptions func(buildinfo.Info, bootstrap.RuntimeOptions) (*bootstrap.Runtime, error)
	policy                 bootstrap.PersistencePolicy
	warningWriter          io.Writer
	once                   sync.Once
	run                    *bootstrap.Runtime
	err                    error
}

var _ cli.Application = (*lazyApplication)(nil)

// runtime returns the shared initialized runtime, creating it exactly once.
func (l *lazyApplication) runtime() (*bootstrap.Runtime, error) {
	l.once.Do(func() {
		openRuntime := l.openRuntime
		if openRuntime != nil {
			l.run, l.err = openRuntime(l.info)
		} else {
			openRuntimeWithOptions := l.openRuntimeWithOptions
			if openRuntimeWithOptions == nil {
				openRuntimeWithOptions = bootstrap.OpenRuntimeWithOptions
			}
			l.run, l.err = openRuntimeWithOptions(l.info, bootstrap.RuntimeOptions{
				Persistence: l.policy,
			})
		}
		l.err = runtimeApplicationError(l.err)
		if l.err == nil {
			l.writeStartupWarnings()
		}
	})
	return l.run, l.err
}

// SetPersistencePolicy validates a safe local-state mode before lazy startup.
func (l *lazyApplication) SetPersistencePolicy(value string) error {
	policy, err := bootstrap.ParsePersistencePolicy(value)
	if err != nil {
		return err
	}
	if l.run != nil {
		return errors.New("persistence policy cannot change after runtime startup")
	}
	l.policy = policy
	return nil
}

func (l *lazyApplication) writeStartupWarnings() {
	if l.run == nil || l.run.Service == nil || l.warningWriter == nil {
		return
	}
	for _, warning := range l.run.Service.StartupWarnings() {
		_, _ = fmt.Fprintf(
			l.warningWriter,
			"Warning: %s (%s); diagnostics continue with limited local state.\n",
			warning.Code,
			warning.Message,
		)
	}
}

// runtimeApplicationError maps bootstrap failures to the stable application
// error boundary consumed by the CLI.
func runtimeApplicationError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := application.AsError(err); ok {
		return err
	}
	if config.IsInvalid(err) {
		return application.WrapError(
			err,
			application.ErrorCategoryConfiguration,
			"APP_CONFIGURATION_INVALID",
			"error.configuration_invalid",
			nil,
		)
	}
	classified := application.ClassifyError(err)
	if classified.Category() != application.ErrorCategoryInternal {
		return classified
	}
	return application.WrapError(
		err,
		application.ErrorCategoryInternal,
		"APP_RUNTIME_INITIALIZATION_FAILED",
		"error.runtime_initialization_failed",
		nil,
	)
}

// DiagnoseRequest initializes the runtime and delegates a diagnostic request.
func (l *lazyApplication) DiagnoseRequest(
	ctx context.Context,
	request application.DiagnoseRequest,
	sink model.EventSink,
) (model.Diagnosis, error) {
	runtime, err := l.runtime()
	if err != nil {
		return model.Diagnosis{}, err
	}
	return runtime.Service.DiagnoseRequest(ctx, request, sink)
}

// RenderReport initializes the runtime and renders a privacy-projected report.
func (l *lazyApplication) RenderReport(
	ctx context.Context,
	format string,
	diagnosis model.Diagnosis,
	mode privacy.Mode,
) ([]byte, error) {
	runtime, err := l.runtime()
	if err != nil {
		return nil, err
	}
	return runtime.Service.RenderReportContext(ctx, format, diagnosis, mode)
}

// SetLogLevel updates the runtime logger after lazy initialization.
func (l *lazyApplication) SetLogLevel(level string) error {
	runtime, err := l.runtime()
	if err != nil {
		return err
	}
	return runtime.Logging.SetLevel(level)
}

// Close releases the runtime if it was initialized.
func (l *lazyApplication) Close() error {
	if l.run == nil {
		return nil
	}
	err := l.run.Close()
	if err == nil {
		return nil
	}
	if _, ok := application.AsError(err); ok {
		return err
	}
	classified := application.ClassifyError(err)
	if classified.Category() != application.ErrorCategoryInternal {
		return classified
	}
	return application.WrapError(
		err,
		application.ErrorCategoryStorage,
		"APP_RUNTIME_CLOSE_FAILED",
		"error.runtime_close_failed",
		nil,
	)
}
