// Package application coordinates diagnostics, configuration, reports, and
// persistence without depending on CLI or GUI frameworks.
package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Naenier/opsdoctor/internal/diagnostics"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/privacy"
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
type ReportRenderer func(
	format string,
	diagnosis model.Diagnosis,
	mode privacy.Mode,
) ([]byte, error)

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
		return nil, NewError(
			ErrorCategoryInternal,
			"APP_RUNNER_UNAVAILABLE",
			"error.runner_unavailable",
			nil,
		)
	}
	if err := dependencies.Config.Validate(); err != nil {
		return nil, operationError(
			fmt.Errorf("application configuration: %w", err),
			ErrorCategoryConfiguration,
			"APP_CONFIGURATION_INVALID",
			"error.configuration_invalid",
			nil,
		)
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

// ResolveDiagnoseOptions returns the canonical effective options for preview,
// execution, reports, and reruns. Configuration is read once so every field in
// the result belongs to the same application snapshot.
func (s *Service) ResolveDiagnoseOptions(
	profile *model.Profile,
	overrides DiagnoseOverrides,
) (model.DiagnoseOptions, error) {
	return ResolveDiagnoseOptions(s.Configuration(), profile, overrides)
}

// PreviewDiagnoseOptions returns privacy-projected effective options for UI
// previews. The execution value remains available only through the resolver
// and DiagnoseRequest paths.
func (s *Service) PreviewDiagnoseOptions(
	profile *model.Profile,
	overrides DiagnoseOverrides,
	mode privacy.Mode,
) (model.DiagnoseOptions, error) {
	return PreviewDiagnoseOptions(s.Configuration(), profile, overrides, mode)
}

// DiagnoseRequest resolves interface/profile input and executes the resulting
// effective options. Interfaces should prefer this method over Diagnose.
func (s *Service) DiagnoseRequest(
	ctx context.Context,
	request DiagnoseRequest,
	sink model.EventSink,
) (model.Diagnosis, error) {
	options, err := s.ResolveDiagnoseOptions(request.Profile, request.Overrides)
	if err != nil {
		return model.Diagnosis{}, err
	}
	return s.diagnoseEffective(ctx, options, sink)
}

// Diagnose runs the shared core and stores a privacy-sanitized history entry
// when history is enabled. A storage failure does not hide a valid diagnostic
// result; it is logged after mandatory redaction by the configured logger.
// Deprecated: interface adapters should pass optional overrides through
// DiagnoseRequest so configuration/profile precedence remains centralized.
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
	return s.diagnoseEffective(ctx, options, sink)
}

func (s *Service) diagnoseEffective(
	ctx context.Context,
	options model.DiagnoseOptions,
	sink model.EventSink,
) (model.Diagnosis, error) {
	cfg := s.Configuration()
	projectedSink := sink
	if sink != nil {
		projectedSink = func(event model.CheckEvent) {
			sink(privacy.Standard().Event(event))
		}
	}
	diagnosis, err := s.runner.Diagnose(ctx, options, projectedSink)
	if err != nil {
		category := ErrorCategoryInternal
		code := ErrorCode("APP_DIAGNOSE_FAILED")
		messageID := MessageID("error.diagnose_failed")
		if diagnostics.IsInputError(err) {
			category = ErrorCategoryValidation
			code = "APP_DIAGNOSE_OPTIONS_INVALID"
			messageID = "error.diagnose_options_invalid"
		}
		return privacy.Standard().Diagnosis(diagnosis), operationError(
			err,
			category,
			code,
			messageID,
			nil,
		)
	}
	diagnosis.Build = s.build
	diagnosis = privacy.Standard().Diagnosis(diagnosis)

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
		return operationError(
			err,
			ErrorCategoryValidation,
			"APP_CONFIGURATION_VALUES_INVALID",
			"error.configuration_values_invalid",
			nil,
		)
	}
	if s.configStore == nil {
		return NewError(
			ErrorCategoryConfiguration,
			"APP_CONFIGURATION_STORE_UNAVAILABLE",
			"error.configuration_store_unavailable",
			nil,
		)
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	previous := s.Configuration()
	levelChanged := previous.Logging.Level != value.Logging.Level && s.setLogLevel != nil
	if levelChanged {
		if err := s.setLogLevel(value.Logging.Level); err != nil {
			return operationError(
				fmt.Errorf("apply log level: %w", err),
				ErrorCategoryConfiguration,
				"APP_LOG_LEVEL_APPLY_FAILED",
				"error.log_level_apply_failed",
				nil,
			)
		}
	}
	if err := s.configStore.Save(value); err != nil {
		if levelChanged {
			if rollbackErr := s.setLogLevel(previous.Logging.Level); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("restore previous log level: %w", rollbackErr))
			}
		}
		return operationError(
			err,
			ErrorCategoryConfiguration,
			"APP_CONFIGURATION_SAVE_FAILED",
			"error.configuration_save_failed",
			nil,
		)
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
	if len(search) > 4096 {
		return nil, NewError(
			ErrorCategoryValidation,
			"APP_HISTORY_SEARCH_INVALID",
			"error.history_search_invalid",
			map[string]string{"field": "search"},
		)
	}
	if status != "" && !status.Valid() {
		return nil, NewError(
			ErrorCategoryValidation,
			"APP_HISTORY_STATUS_INVALID",
			"error.history_status_invalid",
			map[string]string{"field": "status"},
		)
	}
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
			return nil, operationError(
				err,
				ErrorCategoryStorage,
				"APP_HISTORY_LIST_FAILED",
				"error.history_list_failed",
				nil,
			)
		}
		for _, entry := range page {
			entries = append(entries, privacy.Standard().HistoryEntry(entry))
		}
		if len(page) < pageSize {
			return entries, nil
		}
	}
}

// GetDiagnosis loads one complete diagnosis.
func (s *Service) GetDiagnosis(ctx context.Context, id string) (model.Diagnosis, error) {
	if !validApplicationIdentifier(id) {
		return model.Diagnosis{}, NewError(
			ErrorCategoryValidation,
			"APP_HISTORY_ID_INVALID",
			"error.history_id_invalid",
			map[string]string{"field": "id"},
		)
	}
	if s.persistence == nil {
		return model.Diagnosis{}, NewError(
			ErrorCategoryStorage,
			"APP_HISTORY_UNAVAILABLE",
			"error.history_unavailable",
			nil,
		)
	}
	diagnosis, err := s.persistence.GetDiagnosis(ctx, id)
	if err != nil {
		return model.Diagnosis{}, operationError(
			err,
			ErrorCategoryStorage,
			"APP_HISTORY_GET_FAILED",
			"error.history_get_failed",
			nil,
		)
	}
	return privacy.Standard().Diagnosis(diagnosis), nil
}

// DeleteDiagnosis removes one history entry.
func (s *Service) DeleteDiagnosis(ctx context.Context, id string) error {
	if !validApplicationIdentifier(id) {
		return NewError(
			ErrorCategoryValidation,
			"APP_HISTORY_ID_INVALID",
			"error.history_id_invalid",
			map[string]string{"field": "id"},
		)
	}
	if s.persistence == nil {
		return NewError(
			ErrorCategoryStorage,
			"APP_HISTORY_UNAVAILABLE",
			"error.history_unavailable",
			nil,
		)
	}
	return operationError(
		s.persistence.DeleteDiagnosis(ctx, id),
		ErrorCategoryStorage,
		"APP_HISTORY_DELETE_FAILED",
		"error.history_delete_failed",
		nil,
	)
}

// ClearHistory removes all history entries, preserving profiles.
func (s *Service) ClearHistory(ctx context.Context) error {
	if s.persistence == nil {
		return NewError(
			ErrorCategoryStorage,
			"APP_HISTORY_UNAVAILABLE",
			"error.history_unavailable",
			nil,
		)
	}
	return operationError(
		s.persistence.ClearHistory(ctx),
		ErrorCategoryStorage,
		"APP_HISTORY_CLEAR_FAILED",
		"error.history_clear_failed",
		nil,
	)
}

// ListProfiles returns reusable profiles.
func (s *Service) ListProfiles(ctx context.Context) ([]model.Profile, error) {
	if s.persistence == nil {
		return []model.Profile{}, nil
	}
	profiles, err := s.persistence.ListProfiles(ctx)
	if err != nil {
		return nil, operationError(
			err,
			ErrorCategoryStorage,
			"APP_PROFILE_LIST_FAILED",
			"error.profile_list_failed",
			nil,
		)
	}
	for index := range profiles {
		profiles[index] = privacy.Standard().Profile(profiles[index])
	}
	return profiles, nil
}

// SaveProfile creates or updates a reusable profile.
func (s *Service) SaveProfile(ctx context.Context, profile model.Profile) (model.Profile, error) {
	if profile.ID < 0 || len(profile.Name) > 128 || containsControl(profile.Name) ||
		len(profile.Target) > 4096 || containsControl(profile.Target) {
		return model.Profile{}, NewError(
			ErrorCategoryValidation,
			"APP_PROFILE_VALUES_INVALID",
			"error.profile_values_invalid",
			nil,
		)
	}
	profile = privacy.Standard().Profile(profile)
	if strings.TrimSpace(profile.Name) == "" {
		return model.Profile{}, NewError(
			ErrorCategoryValidation,
			"APP_PROFILE_VALUES_INVALID",
			"error.profile_values_invalid",
			map[string]string{"field": "name"},
		)
	}
	if _, err := s.ResolveDiagnoseOptions(&profile, DiagnoseOverrides{}); err != nil {
		if IsErrorCategory(err, ErrorCategoryConfiguration) {
			return model.Profile{}, err
		}
		arguments := map[string]string(nil)
		if applicationError, ok := AsError(err); ok {
			arguments = applicationError.Arguments()
		}
		return model.Profile{}, WrapError(
			err,
			ErrorCategoryValidation,
			"APP_PROFILE_VALUES_INVALID",
			"error.profile_values_invalid",
			arguments,
		)
	}
	if s.persistence == nil {
		return model.Profile{}, NewError(
			ErrorCategoryStorage,
			"APP_PROFILE_STORAGE_UNAVAILABLE",
			"error.profile_storage_unavailable",
			nil,
		)
	}
	var saved model.Profile
	var err error
	if profile.ID == 0 {
		saved, err = s.persistence.CreateProfile(ctx, profile)
	} else {
		saved, err = s.persistence.UpdateProfile(ctx, profile)
	}
	if err != nil {
		return model.Profile{}, operationError(
			err,
			ErrorCategoryStorage,
			"APP_PROFILE_SAVE_FAILED",
			"error.profile_save_failed",
			nil,
		)
	}
	return privacy.Standard().Profile(saved), nil
}

// DeleteProfile removes one profile.
func (s *Service) DeleteProfile(ctx context.Context, id int64) error {
	if id <= 0 {
		return NewError(
			ErrorCategoryValidation,
			"APP_PROFILE_ID_INVALID",
			"error.profile_id_invalid",
			map[string]string{"field": "id"},
		)
	}
	if s.persistence == nil {
		return NewError(
			ErrorCategoryStorage,
			"APP_PROFILE_STORAGE_UNAVAILABLE",
			"error.profile_storage_unavailable",
			nil,
		)
	}
	return operationError(
		s.persistence.DeleteProfile(ctx, id),
		ErrorCategoryStorage,
		"APP_PROFILE_DELETE_FAILED",
		"error.profile_delete_failed",
		nil,
	)
}

// RenderReport renders a completed diagnosis in a stable format.
func (s *Service) RenderReport(
	format string,
	diagnosis model.Diagnosis,
	mode privacy.Mode,
) ([]byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "text", "json", "markdown", "md":
	default:
		return nil, NewError(
			ErrorCategoryValidation,
			"APP_REPORT_FORMAT_INVALID",
			"error.report_format_invalid",
			map[string]string{"field": "format"},
		)
	}
	if s.renderReport == nil {
		return nil, NewError(
			ErrorCategoryInternal,
			"APP_REPORT_RENDERER_UNAVAILABLE",
			"error.report_renderer_unavailable",
			nil,
		)
	}
	if _, err := privacy.New(mode); err != nil {
		return nil, operationError(
			err,
			ErrorCategoryValidation,
			"APP_REPORT_PRIVACY_MODE_INVALID",
			"error.report_privacy_mode_invalid",
			nil,
		)
	}
	content, err := s.renderReport(format, diagnosis, mode)
	if err != nil {
		return nil, operationError(
			err,
			ErrorCategoryInternal,
			"APP_REPORT_RENDER_FAILED",
			"error.report_render_failed",
			nil,
		)
	}
	return content, nil
}

func validApplicationIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-', char == '_', char == '.', char == ':':
		default:
			return false
		}
	}
	return true
}

// Close releases application-owned infrastructure.
func (s *Service) Close() error {
	if s.persistence == nil {
		return nil
	}
	return operationError(
		s.persistence.Close(),
		ErrorCategoryStorage,
		"APP_STORAGE_CLOSE_FAILED",
		"error.storage_close_failed",
		nil,
	)
}
