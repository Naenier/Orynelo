// Package diagnostics exposes the application-facing diagnostic core.
package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/checks"
	"github.com/Naenier/opsdoctor/internal/diagnostics/checks/target"
	"github.com/Naenier/opsdoctor/internal/diagnostics/engine"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/diagnostics/summary"
)

// InputError reports invalid user-controlled options.
type InputError struct {
	Code    string
	Message string
	Err     error
}

func (e *InputError) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *InputError) Unwrap() error { return e.Err }

// IsInputError distinguishes invalid input from runtime diagnostic failures.
func IsInputError(err error) bool {
	var input *InputError
	return errors.As(err, &input)
}

// Outcome is delivered once by Stream.
type Outcome struct {
	Diagnosis model.Diagnosis
	Err       error
}

// Option customizes a Runner.
type Option func(*Runner)

// Runner coordinates parsing, execution, summary generation, and events.
type Runner struct {
	build       model.BuildInfo
	planFactory func() engine.Plan
	now         func() time.Time
}

// NewRunner constructs the production diagnostic core.
func NewRunner(options ...Option) *Runner {
	runner := &Runner{
		planFactory: checks.Default,
		now:         time.Now,
	}
	for _, option := range options {
		option(runner)
	}
	return runner
}

// WithBuildInfo attaches executable metadata to every diagnosis.
func WithBuildInfo(info model.BuildInfo) Option {
	return func(runner *Runner) { runner.build = info }
}

// WithPlan replaces the production plan, primarily for deterministic tests.
func WithPlan(plan engine.Plan) Option {
	return func(runner *Runner) {
		runner.planFactory = func() engine.Plan { return plan }
	}
}

// Diagnose runs synchronously. Network and application failures are represented
// in Diagnosis.Checks; error is reserved for invalid input/configuration.
func (r *Runner) Diagnose(ctx context.Context, options model.DiagnoseOptions, sink model.EventSink) (model.Diagnosis, error) {
	options, err := normalizeOptions(options)
	if err != nil {
		return model.Diagnosis{}, err
	}
	started := r.now()
	diagnosis := model.Diagnosis{
		ID:        newDiagnosisID(started),
		Options:   options,
		StartedAt: started,
		Build:     r.build,
	}
	emit(sink, model.CheckEvent{
		Type:   model.EventRunStarted,
		Status: model.StatusRunning,
		At:     started,
	})

	parsed, parseErr := target.Parse(options.Target)
	if parseErr != nil {
		result := model.CheckResult{
			ID:         "target",
			Name:       "Target validation",
			Status:     model.StatusFailed,
			StartedAt:  started,
			FinishedAt: r.now(),
			Summary:    "The target could not be parsed.",
			ErrorCode:  target.ErrorCode(parseErr),
			Evidence: []model.Evidence{{
				ID:      "target.invalid",
				CheckID: "target",
				Code:    target.ErrorCode(parseErr),
				Message: "Target validation rejected the supplied value.",
			}},
		}.Complete(started, r.now())
		diagnosis.Target = model.Target{Original: "[invalid target]"}
		diagnosis.Options.Target = "[invalid target]"
		diagnosis.Checks = []model.CheckResult{result}
		diagnosis.Summary = summary.Build(diagnosis.Checks)
		diagnosis.FinishedAt = r.now()
		diagnosis.Duration = diagnosis.FinishedAt.Sub(started)
		emit(sink, model.CheckEvent{
			Type:      model.EventCheckStarted,
			CheckID:   result.ID,
			CheckName: result.Name,
			Status:    model.StatusRunning,
			At:        started,
		})
		emit(sink, model.CheckEvent{
			Type:      model.EventCheckCompleted,
			CheckID:   result.ID,
			CheckName: result.Name,
			Status:    result.Status,
			At:        result.FinishedAt,
			Result:    resultPointer(result),
		})
		emit(sink, model.CheckEvent{
			Type:   model.EventRunCompleted,
			Status: diagnosis.Summary.Status,
			At:     diagnosis.FinishedAt,
		})
		return diagnosis, &InputError{
			Code:    target.ErrorCode(parseErr),
			Message: "invalid target",
			Err:     parseErr,
		}
	}

	diagnosis.Target = parsed
	// Never retain the raw target in a diagnosis because it can contain
	// credentials or secret query values.
	options.Target = parsed.Normalized
	diagnosis.Options = options
	state := model.NewState(parsed, options)

	runContext := ctx
	cancel := func() {}
	if options.Timeout > 0 {
		runContext, cancel = context.WithTimeout(ctx, options.Timeout)
	}
	defer cancel()
	executor := engine.New(engine.Config{
		CheckTimeout:   options.CheckTimeout,
		MaxConcurrency: options.MaxConcurrency,
		Now:            r.now,
	})
	plan := r.planFactory()
	diagnosis.Checks = executor.Run(runContext, state, plan, sink)
	diagnosis.Summary = summary.Build(diagnosis.Checks)
	diagnosis.FinishedAt = r.now()
	diagnosis.Duration = diagnosis.FinishedAt.Sub(started)
	emit(sink, model.CheckEvent{
		Type:   model.EventRunCompleted,
		Status: diagnosis.Summary.Status,
		At:     diagnosis.FinishedAt,
	})
	return diagnosis, nil
}

// Stream runs asynchronously and closes both returned channels on completion.
func (r *Runner) Stream(ctx context.Context, options model.DiagnoseOptions) (<-chan model.CheckEvent, <-chan Outcome) {
	events := make(chan model.CheckEvent, 256)
	outcomes := make(chan Outcome, 1)
	go func() {
		defer close(events)
		defer close(outcomes)
		diagnosis, err := r.Diagnose(ctx, options, model.NonBlockingEventSink(events))
		outcomes <- Outcome{Diagnosis: diagnosis, Err: err}
	}()
	return events, outcomes
}

func normalizeOptions(options model.DiagnoseOptions) (model.DiagnoseOptions, error) {
	defaults := model.DefaultDiagnoseOptions(options.Target)
	if strings.TrimSpace(options.Target) == "" {
		return options, &InputError{Code: target.ErrorEmptyTarget, Message: "target is required"}
	}
	if options.Timeout < 0 {
		return options, &InputError{Code: "INVALID_TIMEOUT", Message: "timeout cannot be negative"}
	}
	if options.Timeout == 0 {
		options.Timeout = defaults.Timeout
	}
	if options.CheckTimeout < 0 {
		return options, &InputError{Code: "INVALID_CHECK_TIMEOUT", Message: "check timeout cannot be negative"}
	}
	if options.CheckTimeout == 0 {
		options.CheckTimeout = defaults.CheckTimeout
	}
	if options.IPVersion == "" {
		options.IPVersion = defaults.IPVersion
	}
	if !options.IPVersion.Valid() {
		return options, &InputError{
			Code:    "INVALID_IP_VERSION",
			Message: fmt.Sprintf("invalid IP version %q", options.IPVersion),
		}
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > 100 {
		return options, &InputError{Code: "INVALID_MAX_REDIRECTS", Message: "maximum redirects must be between 0 and 100"}
	}
	if strings.TrimSpace(options.Method) == "" {
		options.Method = defaults.Method
	}
	options.Method = strings.ToUpper(strings.TrimSpace(options.Method))
	if strings.ContainsAny(options.Method, " \t\r\n") {
		return options, &InputError{Code: "INVALID_HTTP_METHOD", Message: "HTTP method contains whitespace"}
	}
	switch options.Method {
	case "GET", "HEAD", "OPTIONS":
	default:
		return options, &InputError{
			Code:    "INVALID_HTTP_METHOD",
			Message: "HTTP method must be GET, HEAD, or OPTIONS",
		}
	}
	if options.ReportVerbosity == "" {
		options.ReportVerbosity = defaults.ReportVerbosity
	}
	if !options.ReportVerbosity.Valid() {
		return options, &InputError{
			Code:    "INVALID_REPORT_VERBOSITY",
			Message: "report verbosity must be normal or verbose",
		}
	}
	if options.UserAgent == "" {
		options.UserAgent = defaults.UserAgent
	}
	if len(options.UserAgent) > 256 || containsControl(options.UserAgent) {
		return options, &InputError{Code: "INVALID_USER_AGENT", Message: "user agent is invalid"}
	}
	if options.CertificateWarningThreshold < 0 ||
		options.CertificateWarningThreshold > 365*24*time.Hour {
		return options, &InputError{
			Code:    "INVALID_CERTIFICATE_WARNING_THRESHOLD",
			Message: "certificate warning threshold must be between 0 and 365 days",
		}
	}
	if options.MaxConcurrency < 0 || options.MaxConcurrency > 32 {
		return options, &InputError{Code: "INVALID_CONCURRENCY", Message: "maximum concurrency must be between 1 and 32"}
	}
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = defaults.MaxConcurrency
	}
	if options.BodyLimit < 0 || options.BodyLimit > 4<<20 {
		return options, &InputError{Code: "INVALID_BODY_LIMIT", Message: "body limit must be between 1 byte and 4 MiB"}
	}
	if options.BodyLimit == 0 {
		options.BodyLimit = defaults.BodyLimit
	}
	return options, nil
}

func containsControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func newDiagnosisID(now time.Time) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return fmt.Sprintf("%d-%s", now.UTC().UnixNano(), hex.EncodeToString(random))
	}
	return fmt.Sprintf("%d", now.UTC().UnixNano())
}

func resultPointer(result model.CheckResult) *model.CheckResult {
	copy := result
	return &copy
}

func emit(sink model.EventSink, event model.CheckEvent) {
	if sink != nil {
		sink(event)
	}
}
