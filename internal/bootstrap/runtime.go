// Package bootstrap assembles infrastructure adapters around the inward-facing
// application service. Command entry points own this composition root.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/config"
	"github.com/Naenier/orynelo/internal/diagnostics"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/platform"
	"github.com/Naenier/orynelo/internal/privacy"
	"github.com/Naenier/orynelo/internal/report"
	"github.com/Naenier/orynelo/internal/storage"
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
	return OpenRuntimeWithOptions(info, RuntimeOptions{})
}

// OpenRuntimeWithOptions initializes the diagnostic core and the optional
// adapters selected by options. Optional adapter failures are reported as
// startup warnings and do not prevent diagnostics.
func OpenRuntimeWithOptions(info buildinfo.Info, options RuntimeOptions) (*Runtime, error) {
	return openRuntimeWithOptions(info, options, defaultRuntimeOpeners())
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
	return openRuntimeWithOptions(info, RuntimeOptions{}, openers)
}

func openRuntimeWithOptions(
	info buildinfo.Info,
	options RuntimeOptions,
	openers runtimeOpeners,
) (*Runtime, error) {
	policy, err := ParsePersistencePolicy(string(options.Persistence))
	if err != nil {
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryConfiguration,
			"APP_PERSISTENCE_POLICY_INVALID",
			"error.persistence_policy_invalid",
		)
	}

	var paths platform.Paths
	var configStore runtimeConfigStore
	var database application.Persistence
	warnings := make([]application.StartupWarning, 0, 3)
	cfg := application.DefaultConfig()
	logFile := ""
	logging, err := newLogging(io.Discard, cfg.Logging.Level)
	if err != nil {
		return nil, bootstrapBoundaryError(
			err,
			application.ErrorCategoryInternal,
			"APP_FALLBACK_LOGGING_FAILED",
			"error.logging_initialization_failed",
		)
	}

	if policy != PersistenceEphemeral {
		resolved, resolveErr := openers.resolvePaths()
		if resolveErr != nil {
			warnings = append(warnings, startupWarningForError(
				resolveErr,
				application.ErrorCategoryConfiguration,
				"APP_PATHS_RESOLVE_FAILED",
				"error.paths_resolve_failed",
				application.RecoveryRetry,
				application.RecoveryRunEphemeral,
			))
		} else {
			paths = resolved
			if ensureErr := openers.ensurePaths(paths); ensureErr != nil {
				warnings = append(warnings, startupWarningForError(
					ensureErr,
					application.ErrorCategoryStorage,
					"APP_PATHS_PREPARE_FAILED",
					"error.paths_prepare_failed",
					application.RecoveryRetry,
					application.RecoveryRunEphemeral,
				))
			}

			candidateStore := openers.newConfigStore(paths.ConfigFile)
			loaded, loadErr := candidateStore.Load()
			if loadErr != nil {
				category := application.ErrorCategoryStorage
				code := application.ErrorCode("APP_CONFIGURATION_LOAD_FAILED")
				message := application.MessageID("error.configuration_load_failed")
				if config.IsInvalid(loadErr) {
					category = application.ErrorCategoryConfiguration
					code = "APP_CONFIGURATION_INVALID"
					message = "error.configuration_invalid"
				}
				warnings = append(warnings, startupWarningForError(
					loadErr,
					category,
					code,
					message,
					application.RecoveryRetry,
					application.RecoveryRunEphemeral,
				))
			} else {
				cfg = loaded
				configStore = candidateStore
			}

			persistentLogging, loggingErr := openers.openLogging(paths.LogFile, cfg.Logging.Level)
			if loggingErr != nil {
				warnings = append(warnings, startupWarningForError(
					loggingErr,
					application.ErrorCategoryStorage,
					"APP_LOGGING_INITIALIZATION_FAILED",
					"error.logging_initialization_failed",
					application.RecoveryRetry,
					application.RecoveryRunEphemeral,
				))
			} else {
				logging = persistentLogging
				logFile = paths.LogFile
				if loadErr != nil && logging.Logger != nil {
					logging.Logger.Warn(
						"configuration unavailable; using in-memory defaults",
						"error",
						loadErr,
					)
				}
			}

			if policy == PersistenceDefault {
				opened, storageErr := openers.openStorage(paths.DatabaseFile)
				if storageErr != nil {
					if logging.Logger != nil {
						logging.Logger.Warn(
							"history storage unavailable; diagnostics remain enabled",
							"error",
							storageErr,
						)
					}
					warnings = append(warnings, startupWarningForError(
						storageErr,
						application.ErrorCategoryStorage,
						"APP_STORAGE_INITIALIZATION_FAILED",
						"error.storage_initialization_failed",
						application.RecoveryRetry,
						application.RecoveryOpenReadOnly,
						application.RecoveryUseQuarantine,
						application.RecoveryRunNoHistory,
					))
				} else {
					database = opened
				}
			}
		}
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
		LogFile:     logFile,
		Logger:      logging.Logger,
		SetLogLevel: logging.SetLevel,
		Warnings:    warnings,
		RenderReport: func(
			ctx context.Context,
			format string,
			diagnosis model.Diagnosis,
			mode privacy.Mode,
		) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			parsed, err := report.ParseFormat(format)
			if err != nil {
				return nil, err
			}
			return report.Render(diagnosis, parsed, mode)
		},
		RenderLocalizedReport: func(
			ctx context.Context,
			format string,
			diagnosis model.Diagnosis,
			mode privacy.Mode,
			language string,
		) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			parsed, err := report.ParseFormat(format)
			if err != nil {
				return nil, err
			}
			return report.RenderLocalized(diagnosis, parsed, language, mode)
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

func startupWarning(
	category application.ErrorCategory,
	code application.ErrorCode,
	message application.MessageID,
	actions ...application.RecoveryAction,
) application.StartupWarning {
	return application.StartupWarning{
		Category: category,
		Code:     code,
		Message:  message,
		Actions:  actions,
	}
}

func startupWarningForError(
	err error,
	category application.ErrorCategory,
	code application.ErrorCode,
	message application.MessageID,
	actions ...application.RecoveryAction,
) application.StartupWarning {
	classified := application.ClassifyError(err)
	if classified.Category() != application.ErrorCategoryInternal {
		return startupWarning(
			classified.Category(),
			classified.Code(),
			classified.MessageID(),
			actions...,
		)
	}
	return startupWarning(category, code, message, actions...)
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
