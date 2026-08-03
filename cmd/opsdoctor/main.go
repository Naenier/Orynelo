// Binary opsdoctor provides the command-line interface to the shared
// diagnostic application service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/bootstrap"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/cli"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/privacy"
)

// main translates the process context and command result into an exit status.
func main() {
	os.Exit(run())
}

// run assembles the CLI command tree and owns process-level cancellation.
func run() int {
	info := buildinfo.Current()
	lazy := &lazyApplication{info: info}
	defer func() {
		if err := lazy.Close(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Error closing OpsDoctor:", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	root := cli.NewRoot(cli.Options{
		Application: lazy,
		Build:       info,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		SetLogLevel: lazy.SetLogLevel,
	})
	return cli.Execute(ctx, root, os.Stderr)
}

// lazyApplication delays runtime initialization until a command needs backend
// services, allowing lightweight commands such as help and version to run
// without opening configuration, logs, or storage.
type lazyApplication struct {
	info        buildinfo.Info
	openRuntime func(buildinfo.Info) (*bootstrap.Runtime, error)
	once        sync.Once
	run         *bootstrap.Runtime
	err         error
}

var _ cli.Application = (*lazyApplication)(nil)

// runtime returns the shared initialized runtime, creating it exactly once.
func (l *lazyApplication) runtime() (*bootstrap.Runtime, error) {
	l.once.Do(func() {
		openRuntime := l.openRuntime
		if openRuntime == nil {
			openRuntime = bootstrap.OpenRuntime
		}
		l.run, l.err = openRuntime(l.info)
		l.err = runtimeApplicationError(l.err)
	})
	return l.run, l.err
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
	format string,
	diagnosis model.Diagnosis,
	mode privacy.Mode,
) ([]byte, error) {
	runtime, err := l.runtime()
	if err != nil {
		return nil, err
	}
	return runtime.Service.RenderReport(format, diagnosis, mode)
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
