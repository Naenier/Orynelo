package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/Naenier/opsdoctor/internal/bootstrap"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/cli"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func main() {
	os.Exit(run())
}

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
		Application:     lazy,
		Build:           info,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		SetLogLevel:     lazy.SetLogLevel,
		LoadConfig:      lazy.Configuration,
		IsConfigInvalid: config.IsInvalid,
	})
	return cli.Execute(ctx, root, os.Stderr)
}

func (l *lazyApplication) Configuration() (config.Config, error) {
	runtime, err := l.runtime()
	if err != nil {
		return config.Config{}, err
	}
	return runtime.Service.Configuration(), nil
}

type lazyApplication struct {
	info buildinfo.Info
	once sync.Once
	run  *bootstrap.Runtime
	err  error
}

func (l *lazyApplication) runtime() (*bootstrap.Runtime, error) {
	l.once.Do(func() {
		l.run, l.err = bootstrap.OpenRuntime(l.info)
	})
	return l.run, l.err
}

func (l *lazyApplication) Diagnose(
	ctx context.Context,
	options model.DiagnoseOptions,
	sink model.EventSink,
) (model.Diagnosis, error) {
	runtime, err := l.runtime()
	if err != nil {
		return model.Diagnosis{}, err
	}
	return runtime.Service.Diagnose(ctx, options, sink)
}

func (l *lazyApplication) RenderReport(
	format string,
	diagnosis model.Diagnosis,
) ([]byte, error) {
	runtime, err := l.runtime()
	if err != nil {
		return nil, err
	}
	return runtime.Service.RenderReport(format, diagnosis)
}

func (l *lazyApplication) SetLogLevel(level string) error {
	runtime, err := l.runtime()
	if err != nil {
		return err
	}
	return runtime.Logging.SetLevel(level)
}

func (l *lazyApplication) Close() error {
	if l.run == nil {
		return nil
	}
	return l.run.Close()
}
