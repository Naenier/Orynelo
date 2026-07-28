// Package application coordinates diagnostics, configuration, reports, and
// persistence without depending on CLI or GUI frameworks.
package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

// DiagnosticRunner is implemented by the shared diagnostic core.
type DiagnosticRunner interface {
	Diagnose(context.Context, model.DiagnoseOptions, model.EventSink) (model.Diagnosis, error)
}

// Persistence is the normalized local history/profile contract.
type Persistence interface {
	SaveDiagnosis(context.Context, model.Diagnosis, int) error
	GetDiagnosis(context.Context, string) (model.Diagnosis, error)
	ListHistory(context.Context, model.HistoryQuery) ([]model.HistoryEntry, error)
	DeleteDiagnosis(context.Context, string) error
	ClearHistory(context.Context) error

	ListProfiles(context.Context) ([]model.Profile, error)
	CreateProfile(context.Context, model.Profile) (model.Profile, error)
	UpdateProfile(context.Context, model.Profile) (model.Profile, error)
	DeleteProfile(context.Context, int64) error

	Close() error
}

// ConfigurationStore persists user settings.
type ConfigurationStore interface {
	Save(Config) error
}

// ReportRenderer produces one of the stable report formats.
type ReportRenderer func(format string, diagnosis model.Diagnosis) ([]byte, error)

// Dependencies contains application infrastructure adapters.
type Dependencies struct {
	Runner       DiagnosticRunner
	Persistence  Persistence
	ConfigStore  ConfigurationStore
	Config       Config
	Build        model.BuildInfo
	LogFile      string
	Logger       *slog.Logger
	RenderReport ReportRenderer
	SetLogLevel  func(string) error
}

// Service is the common application layer used by both interfaces.
type Service struct {
	runner       DiagnosticRunner
	persistence  Persistence
	configStore  ConfigurationStore
	build        model.BuildInfo
	logFile      string
	logger       *slog.Logger
	renderReport ReportRenderer
	setLogLevel  func(string) error

	mu       sync.RWMutex
	config   Config
	configMu sync.Mutex
}

// New constructs an application service from explicit dependencies.
func New(dependencies Dependencies) (*Service, error) {
	if dependencies.Runner == nil {
		return nil, errors.New("application diagnostic runner is required")
	}
	if err := dependencies.Config.Validate(); err != nil {
		return nil, fmt.Errorf("application configuration: %w", err)
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		runner:       dependencies.Runner,
		persistence:  dependencies.Persistence,
		configStore:  dependencies.ConfigStore,
		config:       dependencies.Config,
		build:        dependencies.Build,
		logFile:      dependencies.LogFile,
		logger:       logger,
		renderReport: dependencies.RenderReport,
		setLogLevel:  dependencies.SetLogLevel,
	}, nil
}

// Diagnose runs the shared core and stores a privacy-sanitized history entry
// when history is enabled. A storage failure does not hide a valid diagnostic
// result; it is logged after mandatory redaction by the configured logger.
func (s *Service) Diagnose(
	ctx context.Context,
	options model.DiagnoseOptions,
	sink model.EventSink,
) (model.Diagnosis, error) {
	cfg := s.Configuration()
	if !cfg.Network.UseSystemProxy {
		options.NoProxy = true
	}
	options.UserAgent = cfg.Network.UserAgent
	options.CertificateWarningThreshold = cfg.Diagnostics.CertificateWarningThreshold
	diagnosis, err := s.runner.Diagnose(ctx, options, sink)
	if err != nil {
		return diagnosis, err
	}
	diagnosis.Build = s.build

	if cfg.History.Enabled && s.persistence != nil {
		if err := s.persistence.SaveDiagnosis(ctx, diagnosis, cfg.History.MaxEntries); err != nil {
			s.logger.WarnContext(ctx, "diagnosis completed but history could not be saved", "error", err)
		}
	}
	return diagnosis, nil
}

// Configuration returns a copy of the active configuration.
func (s *Service) Configuration() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SaveConfiguration validates and persists settings before activating them.
func (s *Service) SaveConfiguration(value Config) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if s.configStore == nil {
		return errors.New("configuration store is unavailable")
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	previous := s.Configuration()
	levelChanged := previous.Logging.Level != value.Logging.Level && s.setLogLevel != nil
	if levelChanged {
		if err := s.setLogLevel(value.Logging.Level); err != nil {
			return fmt.Errorf("apply log level: %w", err)
		}
	}
	if err := s.configStore.Save(value); err != nil {
		if levelChanged {
			if rollbackErr := s.setLogLevel(previous.Logging.Level); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous log level: %w", rollbackErr))
			}
		}
		return err
	}
	s.mu.Lock()
	s.config = value
	s.mu.Unlock()
	return nil
}

// LogDirectory returns the platform-specific log directory.
func (s *Service) LogDirectory() string {
	if s.logFile == "" {
		return ""
	}
	return filepath.Dir(s.logFile)
}

// ListHistory returns date-sorted compact history.
func (s *Service) ListHistory(
	ctx context.Context,
	search string,
	status model.Status,
) ([]model.HistoryEntry, error) {
	if s.persistence == nil {
		return []model.HistoryEntry{}, nil
	}
	const pageSize = 1000
	entries := make([]model.HistoryEntry, 0)
	for offset := 0; ; offset += pageSize {
		page, err := s.persistence.ListHistory(ctx, model.HistoryQuery{
			Search: search,
			Status: status,
			Sort:   model.HistorySortDate,
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		entries = append(entries, page...)
		if len(page) < pageSize {
			return entries, nil
		}
	}
}

// GetDiagnosis loads one complete diagnosis.
func (s *Service) GetDiagnosis(ctx context.Context, id string) (model.Diagnosis, error) {
	if s.persistence == nil {
		return model.Diagnosis{}, errors.New("diagnostic history is unavailable")
	}
	return s.persistence.GetDiagnosis(ctx, id)
}

// DeleteDiagnosis removes one history entry.
func (s *Service) DeleteDiagnosis(ctx context.Context, id string) error {
	if s.persistence == nil {
		return errors.New("diagnostic history is unavailable")
	}
	return s.persistence.DeleteDiagnosis(ctx, id)
}

// ClearHistory removes all history entries, preserving profiles.
func (s *Service) ClearHistory(ctx context.Context) error {
	if s.persistence == nil {
		return errors.New("diagnostic history is unavailable")
	}
	return s.persistence.ClearHistory(ctx)
}

// ListProfiles returns reusable profiles.
func (s *Service) ListProfiles(ctx context.Context) ([]model.Profile, error) {
	if s.persistence == nil {
		return []model.Profile{}, nil
	}
	return s.persistence.ListProfiles(ctx)
}

// SaveProfile creates or updates a reusable profile.
func (s *Service) SaveProfile(ctx context.Context, profile model.Profile) (model.Profile, error) {
	if s.persistence == nil {
		return model.Profile{}, errors.New("profile storage is unavailable")
	}
	if profile.ID == 0 {
		return s.persistence.CreateProfile(ctx, profile)
	}
	return s.persistence.UpdateProfile(ctx, profile)
}

// DeleteProfile removes one profile.
func (s *Service) DeleteProfile(ctx context.Context, id int64) error {
	if s.persistence == nil {
		return errors.New("profile storage is unavailable")
	}
	return s.persistence.DeleteProfile(ctx, id)
}

// RenderReport renders a completed diagnosis in a stable format.
func (s *Service) RenderReport(format string, diagnosis model.Diagnosis) ([]byte, error) {
	if s.renderReport == nil {
		return nil, errors.New("report renderer is unavailable")
	}
	return s.renderReport(format, diagnosis)
}

// Close releases application-owned infrastructure.
func (s *Service) Close() error {
	if s.persistence == nil {
		return nil
	}
	return s.persistence.Close()
}
