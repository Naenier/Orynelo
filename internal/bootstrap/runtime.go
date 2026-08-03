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
	"github.com/Naenier/opsdoctor/internal/privacy"
	"github.com/Naenier/opsdoctor/internal/report"
	"github.com/Naenier/opsdoctor/internal/storage"
)

// Runtime owns the common application service and local resources.
type Runtime struct {
	Service *application.Service
	Logging *Logging
	Paths   platform.Paths
}

type runtimeConfigStore interface {
	application.ConfigurationStore
	Load() (application.Config, error)
}

type runtimeOpeners struct {
	resolvePaths   func() (platform.Paths, error)
	ensurePaths    func(platform.Paths) error
	newConfigStore func(string) runtimeConfigStore
	openLogging    func(string, string) (*Logging, error)
	openStorage    func(string) (application.Persistence, error)
	newService     func(application.Dependencies) (*application.Service, error)
}

// OpenRuntime initializes platform directories, configuration, logging,
// SQLite migrations, and the shared diagnostic core.
func OpenRuntime(info buildinfo.Info) (*Runtime, error) {
	return openRuntime(info, defaultRuntimeOpeners())
}

func defaultRuntimeOpeners() runtimeOpeners {
	return runtimeOpeners{
		resolvePaths: platform.DefaultPaths,
		ensurePaths: func(paths platform.Paths) error {
			return paths.Ensure()
		},
		newConfigStore: func(path string) runtimeConfigStore {
			return config.NewStore(path)
		},
		openLogging: NewLogging,
		openStorage: func(path string) (application.Persistence, error) {
			return storage.Open(path)
		},
		newService: application.New,
	}
}

func openRuntime(info buildinfo.Info, openers runtimeOpeners) (*Runtime, error) {
	paths, err := openers.resolvePaths()
	if err != nil {
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryConfiguration,
			"APP_PATHS_RESOLVE_FAILED",
			"error.paths_resolve_failed",
		)
	}
	if err := openers.ensurePaths(paths); err != nil {
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryStorage,
			"APP_PATHS_PREPARE_FAILED",
			"error.paths_prepare_failed",
		)
	}
	configStore := openers.newConfigStore(paths.ConfigFile)
	cfg, err := configStore.Load()
	if err != nil {
		if config.IsInvalid(err) {
			return nil, bootstrapBoundaryError(
				err,
				application.ErrorCategoryConfiguration,
				"APP_CONFIGURATION_INVALID",
				"error.configuration_invalid",
			)
		}
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryStorage,
			"APP_CONFIGURATION_LOAD_FAILED",
			"error.configuration_load_failed",
		)
	}
	logging, err := openers.openLogging(paths.LogFile, cfg.Logging.Level)
	if err != nil {
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryStorage,
			"APP_LOGGING_INITIALIZATION_FAILED",
			"error.logging_initialization_failed",
		)
	}
	database, err := openers.openStorage(paths.DatabaseFile)
	if err != nil {
		_ = logging.Close()
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryStorage,
			"APP_STORAGE_INITIALIZATION_FAILED",
			"error.storage_initialization_failed",
		)
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
	service, err := openers.newService(application.Dependencies{
		Runner:      runner,
		Persistence: database,
		ConfigStore: configStore,
		Config:      cfg,
		Build:       domainBuild,
		LogFile:     paths.LogFile,
		Logger:      logging.Logger,
		SetLogLevel: logging.SetLevel,
		RenderReport: func(
			format string,
			diagnosis model.Diagnosis,
			mode privacy.Mode,
		) ([]byte, error) {
			parsed, err := report.ParseFormat(format)
			if err != nil {
				return nil, err
			}
			return report.Render(diagnosis, parsed, mode)
		},
	})
	if err != nil {
		if database != nil {
			_ = database.Close()
		}
		_ = logging.Close()
		return nil, bootstrapBoundaryError(
			fmt.Errorf("initialize application service: %w", err),
			application.ErrorCategoryInternal,
			"APP_SERVICE_INITIALIZATION_FAILED",
			"error.service_initialization_failed",
		)
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
	return runtimeCloseError(serviceErr, logErr)
}

// runtimeCloseError always places a privacy-safe application error at the
// display boundary while preserving every close failure for errors.Is/As and
// internal logging.
func runtimeCloseError(serviceErr, logErr error) error {
	return application.WrapError(
		errors.Join(serviceErr, logErr),
		application.ErrorCategoryStorage,
		"APP_RUNTIME_CLOSE_FAILED",
		"error.runtime_close_failed",
		nil,
	)
}
