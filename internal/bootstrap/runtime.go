// Package bootstrap assembles infrastructure adapters around the inward-facing
// application service. Command entry points own this composition root.
package bootstrap

import (
	"errors"
	"fmt"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/diagnostics"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/platform"
	"github.com/Naenier/opsdoctor/internal/report"
	"github.com/Naenier/opsdoctor/internal/storage"
)

// Runtime owns the common application service and local resources.
type Runtime struct {
	Service *application.Service
	Logging *Logging
	Paths   platform.Paths
}

// OpenRuntime initializes platform directories, configuration, logging,
// SQLite migrations, and the shared diagnostic core.
func OpenRuntime(info buildinfo.Info) (*Runtime, error) {
	paths, err := platform.DefaultPaths()
	if err != nil {
		return nil, err
	}
	if err := paths.Ensure(); err != nil {
		return nil, err
	}
	configStore := config.NewStore(paths.ConfigFile)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, err
	}
	logging, err := NewLogging(paths.LogFile, cfg.Logging.Level)
	if err != nil {
		return nil, err
	}
	database, err := storage.Open(paths.DatabaseFile)
	if err != nil {
		_ = logging.Close()
		return nil, err
	}
	domainBuild := model.BuildInfo{
		Version:   info.Version,
		Commit:    info.Commit,
		BuildDate: info.BuildDate,
		Dirty:     info.Dirty,
		GoVersion: info.GoVersion,
		OS:        info.OS,
		Arch:      info.Arch,
	}
	runner := diagnostics.NewRunner(diagnostics.WithBuildInfo(domainBuild))
	service, err := application.New(application.Dependencies{
		Runner:      runner,
		Persistence: database,
		ConfigStore: configStore,
		Config:      cfg,
		Build:       domainBuild,
		LogFile:     paths.LogFile,
		Logger:      logging.Logger,
		SetLogLevel: logging.SetLevel,
		RenderReport: func(format string, diagnosis model.Diagnosis) ([]byte, error) {
			parsed, err := report.ParseFormat(format)
			if err != nil {
				return nil, err
			}
			return report.Render(diagnosis, parsed)
		},
	})
	if err != nil {
		_ = database.Close()
		_ = logging.Close()
		return nil, fmt.Errorf("initialize application service: %w", err)
	}
	return &Runtime{Service: service, Logging: logging, Paths: paths}, nil
}

// Close releases SQLite and the log file.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var serviceErr, logErr error
	if r.Service != nil {
		serviceErr = r.Service.Close()
	}
	if r.Logging != nil {
		logErr = r.Logging.Close()
	}
	return errors.Join(serviceErr, logErr)
}
