package application

import (
	"errors"
	"fmt"
	"strings"
	"time"

	targetcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/target"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

const (
	maximumDiagnoseTimeout      = 24 * time.Hour
	maximumCertificateThreshold = 365 * 24 * time.Hour
	maximumDiagnoseTargetBytes  = 4096
)

type diagnoseOptionProblem struct {
	field string
	err   error
}

// Error returns the validation message associated with the invalid field.
func (problem *diagnoseOptionProblem) Error() string { return problem.err.Error() }

// Unwrap returns the underlying validation error.
func (problem *diagnoseOptionProblem) Unwrap() error { return problem.err }

func invalidDiagnoseOption(field, message string) error {
	return &diagnoseOptionProblem{field: field, err: errors.New(message)}
}

func wrapInvalidDiagnoseOption(field, message string, cause error) error {
	return &diagnoseOptionProblem{field: field, err: fmt.Errorf("%s: %w", message, cause)}
}

// DiagnoseOverrides contains only values explicitly supplied for one run.
// Pointer fields distinguish an omitted value from an intentional false or
// zero value. Interfaces should not populate this structure with their own
// defaults; defaults and persisted settings are resolved by
// ResolveDiagnoseOptions.
type DiagnoseOverrides struct {
	Target                      *string
	Mode                        *model.DiagnosticMode
	Timeout                     *time.Duration
	CheckTimeout                *time.Duration
	IPVersion                   *model.IPVersion
	NoProxy                     *bool
	Insecure                    *bool
	EnableTLS                   *bool
	MaxRedirects                *int
	MaxRedirectLocationBytes    *int
	AllowInsecureRedirects      *bool
	AllowPrivateRedirects       *bool
	ActualHTTPReserve           *time.Duration
	Method                      *string
	ReportVerbosity             *model.ReportVerbosity
	UserAgent                   *string
	CertificateWarningThreshold *time.Duration
	MaxConcurrency              *int
	BodyLimit                   *int64
}

// DiagnoseRequest carries only an optional saved profile and explicit
// interface overrides. The application service resolves it into one canonical
// effective option set before invoking the diagnostic core.
type DiagnoseRequest struct {
	Profile   *model.Profile
	Overrides DiagnoseOverrides
}

// ResolveDiagnoseOptions merges and validates all settings that affect one
// diagnostic run. Precedence is model defaults, application configuration,
// optional profile, then explicit run overrides. The returned value is the
// canonical effective execution value. Because Target and UserAgent may be
// request-capable, callers must use PreviewDiagnoseOptions before displaying
// it. Completed diagnoses are projected by Service before reports or reruns.
func ResolveDiagnoseOptions(
	config Config,
	profile *model.Profile,
	overrides DiagnoseOverrides,
) (model.DiagnoseOptions, error) {
	if err := config.Validate(); err != nil {
		return model.DiagnoseOptions{}, operationError(
			fmt.Errorf("resolve diagnosis options: %w", err),
			ErrorCategoryConfiguration,
			"APP_CONFIGURATION_INVALID",
			"error.configuration_invalid",
			nil,
		)
	}

	options := model.DefaultDiagnoseOptions("")
	mode := model.DiagnosticModeAuto

	options.Timeout = config.Diagnostics.DefaultTimeout
	options.CheckTimeout = config.Diagnostics.CheckTimeout
	options.IPVersion = model.IPVersion(config.Diagnostics.PreferredIPVersion)
	options.NoProxy = !config.Network.UseSystemProxy
	options.MaxRedirects = config.Diagnostics.MaxRedirects
	if config.Network.UserAgent != "" {
		options.UserAgent = config.Network.UserAgent
	}
	options.CertificateWarningThreshold = config.Diagnostics.CertificateWarningThreshold

	if profile != nil {
		options.Target = profile.Target
		mode = profile.Mode
		options.Timeout = profile.Timeout
		options.CheckTimeout = profile.CheckTimeout
		options.IPVersion = profile.IPVersion
		options.NoProxy = profile.NoProxy
		options.MaxRedirects = profile.MaxRedirects
		options.Method = profile.Method
	}

	applyDiagnoseOverrides(&options, &mode, overrides)
	mode = model.DiagnosticMode(strings.ToLower(strings.TrimSpace(string(mode))))

	// Mode is an interface/profile concept rather than a serialized runner
	// option. Normalize its execution semantics before the explicit EnableTLS
	// override is applied. The redundant Profile.EnableTLS value is
	// deliberately not trusted when it disagrees with Profile.Mode.
	if !mode.Valid() {
		return model.DiagnoseOptions{}, operationError(
			fmt.Errorf(
				`resolve diagnosis options: mode must be "auto", "tcp", or "tls", got %q`,
				mode,
			),
			ErrorCategoryValidation,
			"APP_DIAGNOSE_OPTIONS_INVALID",
			"error.diagnose_options_invalid",
			map[string]string{"field": "mode"},
		)
	}
	options.EnableTLS = mode == model.DiagnosticModeTLS
	if overrides.EnableTLS != nil {
		options.EnableTLS = *overrides.EnableTLS
	}

	if err := normalizeAndValidateDiagnoseOptions(&options, mode); err != nil {
		arguments := map[string]string(nil)
		var problem *diagnoseOptionProblem
		if errors.As(err, &problem) {
			arguments = map[string]string{"field": problem.field}
		}
		return model.DiagnoseOptions{}, operationError(
			fmt.Errorf("resolve diagnosis options: %w", err),
			ErrorCategoryValidation,
			"APP_DIAGNOSE_OPTIONS_INVALID",
			"error.diagnose_options_invalid",
			arguments,
		)
	}
	return options, nil
}

// PreviewDiagnoseOptions returns the same resolved option set after applying
// the requested privacy projection. It is safe to display or serialize and
// cannot be used for execution because request credentials/query values may
// have been removed.
func PreviewDiagnoseOptions(
	config Config,
	profile *model.Profile,
	overrides DiagnoseOverrides,
	mode privacy.Mode,
) (model.DiagnoseOptions, error) {
	options, err := ResolveDiagnoseOptions(config, profile, overrides)
	if err != nil {
		return model.DiagnoseOptions{}, err
	}
	projection, err := privacy.New(mode)
	if err != nil {
		return model.DiagnoseOptions{}, operationError(
			err,
			ErrorCategoryValidation,
			"APP_PREVIEW_PRIVACY_MODE_INVALID",
			"error.preview_privacy_mode_invalid",
			map[string]string{"field": "privacyMode"},
		)
	}
	return projection.Options(options), nil
}

func applyDiagnoseOverrides(
	options *model.DiagnoseOptions,
	mode *model.DiagnosticMode,
	overrides DiagnoseOverrides,
) {
	if overrides.Target != nil {
		options.Target = *overrides.Target
	}
	if overrides.Mode != nil {
		*mode = *overrides.Mode
	}
	if overrides.Timeout != nil {
		options.Timeout = *overrides.Timeout
	}
	if overrides.CheckTimeout != nil {
		options.CheckTimeout = *overrides.CheckTimeout
	}
	if overrides.IPVersion != nil {
		options.IPVersion = *overrides.IPVersion
	}
	if overrides.NoProxy != nil {
		options.NoProxy = *overrides.NoProxy
	}
	if overrides.Insecure != nil {
		options.Insecure = *overrides.Insecure
	}
	if overrides.MaxRedirects != nil {
		options.MaxRedirects = *overrides.MaxRedirects
	}
	if overrides.MaxRedirectLocationBytes != nil {
		options.MaxRedirectLocationBytes = *overrides.MaxRedirectLocationBytes
	}
	if overrides.AllowInsecureRedirects != nil {
		options.AllowInsecureRedirects = *overrides.AllowInsecureRedirects
	}
	if overrides.AllowPrivateRedirects != nil {
		options.AllowPrivateRedirects = *overrides.AllowPrivateRedirects
	}
	if overrides.ActualHTTPReserve != nil {
		options.ActualHTTPReserve = *overrides.ActualHTTPReserve
	}
	if overrides.Method != nil {
		options.Method = *overrides.Method
	}
	if overrides.ReportVerbosity != nil {
		options.ReportVerbosity = *overrides.ReportVerbosity
	}
	if overrides.UserAgent != nil {
		options.UserAgent = *overrides.UserAgent
	}
	if overrides.CertificateWarningThreshold != nil {
		options.CertificateWarningThreshold = *overrides.CertificateWarningThreshold
	}
	if overrides.MaxConcurrency != nil {
		options.MaxConcurrency = *overrides.MaxConcurrency
	}
	if overrides.BodyLimit != nil {
		options.BodyLimit = *overrides.BodyLimit
	}
}

func normalizeAndValidateDiagnoseOptions(
	options *model.DiagnoseOptions,
	mode model.DiagnosticMode,
) error {
	options.Target = strings.TrimSpace(options.Target)
	if options.Target == "" {
		return invalidDiagnoseOption("target", "target is required")
	}
	if len(options.Target) > maximumDiagnoseTargetBytes {
		return invalidDiagnoseOption("target", "target must not exceed 4096 bytes")
	}
	parsed, err := targetcheck.Parse(options.Target)
	if err != nil {
		return wrapInvalidDiagnoseOption("target", "invalid target", err)
	}
	if mode == model.DiagnosticModeTCP {
		options.Target = parsed.Address()
	}

	if options.Timeout <= 0 || options.Timeout > maximumDiagnoseTimeout {
		return invalidDiagnoseOption("timeout", "timeout must be greater than zero and at most 24h")
	}
	if options.CheckTimeout <= 0 || options.CheckTimeout > maximumDiagnoseTimeout {
		return invalidDiagnoseOption("checkTimeout", "check timeout must be greater than zero and at most 24h")
	}
	if options.CheckTimeout > options.Timeout {
		return invalidDiagnoseOption("checkTimeout", "check timeout must not exceed global timeout")
	}
	switch strings.ToLower(strings.TrimSpace(string(options.IPVersion))) {
	case "auto":
		options.IPVersion = model.IPVersionAuto
	case "4", "ipv4":
		options.IPVersion = model.IPVersion4
	case "6", "ipv6":
		options.IPVersion = model.IPVersion6
	default:
		options.IPVersion = model.IPVersion(strings.ToLower(strings.TrimSpace(string(options.IPVersion))))
	}
	if !options.IPVersion.Valid() {
		return invalidDiagnoseOption("ipVersion", `IP version must be "auto", "4", or "6"`)
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > 50 {
		return invalidDiagnoseOption("maxRedirects", "maximum redirects must be between 0 and 50")
	}
	if options.MaxRedirectLocationBytes < 1 || options.MaxRedirectLocationBytes > 64<<10 {
		return invalidDiagnoseOption("maxRedirectLocationBytes", "redirect Location limit must be between 1 byte and 64 KiB")
	}
	if options.ActualHTTPReserve < 0 || options.ActualHTTPReserve >= options.Timeout {
		return invalidDiagnoseOption("actualHTTPReserve", "actual HTTP reserve must be non-negative and shorter than the global timeout")
	}
	if options.ActualHTTPReserve == 0 {
		options.ActualHTTPReserve = options.CheckTimeout
		if maximum := options.Timeout / 3; options.ActualHTTPReserve > maximum {
			options.ActualHTTPReserve = maximum
		}
	}

	options.Method = strings.ToUpper(strings.TrimSpace(options.Method))
	if strings.ContainsAny(options.Method, " \t\r\n") {
		return invalidDiagnoseOption("method", "HTTP method contains whitespace")
	}
	switch options.Method {
	case "GET", "HEAD", "OPTIONS":
	default:
		return invalidDiagnoseOption("method", "HTTP method must be GET, HEAD, or OPTIONS")
	}
	options.ReportVerbosity = model.ReportVerbosity(
		strings.ToLower(strings.TrimSpace(string(options.ReportVerbosity))),
	)
	if !options.ReportVerbosity.Valid() {
		return invalidDiagnoseOption("reportVerbosity", "report verbosity must be normal or verbose")
	}
	if options.UserAgent == "" || len(options.UserAgent) > 256 || containsControl(options.UserAgent) {
		return invalidDiagnoseOption("userAgent", "user agent must contain 1 to 256 characters without control characters")
	}
	if options.CertificateWarningThreshold < 0 ||
		options.CertificateWarningThreshold > maximumCertificateThreshold {
		return invalidDiagnoseOption("certificateWarningThreshold", "certificate warning threshold must be between 0 and 365 days")
	}
	if options.MaxConcurrency < 1 || options.MaxConcurrency > 32 {
		return invalidDiagnoseOption("maxConcurrency", "maximum concurrency must be between 1 and 32")
	}
	if options.BodyLimit < 1 || options.BodyLimit > 4<<20 {
		return invalidDiagnoseOption("bodyLimit", "body limit must be between 1 byte and 4 MiB")
	}
	return nil
}
