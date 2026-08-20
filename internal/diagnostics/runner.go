// Package diagnostics exposes the application-facing diagnostic core.
package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/checks"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/environment"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/target"
	"github.com/Naenier/orynelo/internal/diagnostics/engine"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/diagnostics/summary"
	"github.com/Naenier/orynelo/internal/privacy"
	"github.com/Naenier/orynelo/internal/trust"
	"golang.org/x/net/http/httpguts"
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

// Unwrap returns the parser or validator error that caused the input failure.
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

const (
	maximumDiagnosticTimeout       = 24 * time.Hour
	errorProxySelectionUnavailable = "PROXY_SELECTION_UNAVAILABLE"
)

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
	options, err = prepareRuntimeOptions(options)
	if err != nil {
		return model.Diagnosis{}, err
	}
	delivery := newEventDispatcher(privacyEventSink(sink), r.now)
	sink = delivery.Sink()
	started := r.now()
	diagnosis := model.Diagnosis{
		ID:        newDiagnosisID(started),
		Options:   reportableOptions(options),
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
		return finishEventDelivery(delivery, diagnosis, &InputError{
			Code:    target.ErrorCode(parseErr),
			Message: "invalid target",
			Err:     parseErr,
		})
	}

	diagnosis.Target = parsed
	// Never retain the raw target in a diagnosis because it can contain
	// credentials or secret query values.
	options.Target = parsed.Normalized
	diagnosis.Options = reportableOptions(options)
	state := model.NewState(parsed, options)
	state.SetNetworkPaths([]model.NetworkPath{initialDirectPath(parsed, options)})
	sink = correlatedEventSink(sink, state)

	runContext := ctx
	cancel := func() {}
	if options.Timeout > 0 {
		runContext, cancel = context.WithTimeout(ctx, options.Timeout)
	}
	defer cancel()
	plan := r.planFactory()
	preflight, actual := splitPlanAtCheck(plan, "http")
	if len(actual) == 0 {
		executor := engine.New(engine.Config{
			CheckTimeout:   options.CheckTimeout,
			MaxConcurrency: options.MaxConcurrency,
			Now:            r.now,
			SkipCheck:      skipInvalidProxyDirectCheck,
		})
		diagnosis.Checks = executor.Run(runContext, state, plan, sink)
	} else {
		mandatory, auxiliary := splitMandatoryPreflight(preflight)
		mandatoryExecutor := engine.New(engine.Config{
			CheckTimeout:     options.CheckTimeout,
			MaxConcurrency:   options.MaxConcurrency,
			Now:              r.now,
			SkipCheck:        skipInvalidProxyDirectCheck,
			EventIndexOffset: 0,
		})
		mandatoryResults := mandatoryExecutor.Run(
			runContext,
			state,
			mandatory,
			sink,
		)

		preflightContext, cancelPreflight := reservedPreflightContext(
			runContext,
			options.ActualHTTPReserve,
		)
		preflightExecutor := engine.New(engine.Config{
			CheckTimeout:     options.CheckTimeout,
			MaxConcurrency:   options.MaxConcurrency,
			Now:              r.now,
			SkipCheck:        skipInvalidProxyDirectCheck,
			EventIndexOffset: planSize(mandatory),
		})
		proxySelected := state.Proxy().Selected
		auxiliaryHTTPPreflight := parsed.Kind == model.TargetHTTP &&
			(options.ProbeMode != model.ProbeModeAddressMatrix || proxySelected)
		preflightSink := sink
		if auxiliaryHTTPPreflight {
			preflightSink = auxiliaryPreflightEventSink(sink, proxySelected)
		}
		preflightResults := preflightExecutor.Run(
			preflightContext,
			state,
			auxiliary,
			preflightSink,
		)
		cancelPreflight()
		if parsed.Kind == model.TargetHTTP && options.ProbeMode != model.ProbeModeAddressMatrix {
			markHTTPPreflightAuxiliary(preflightResults, proxySelected)
		} else if options.ProbeMode == model.ProbeModeAddressMatrix {
			markProxyPreflightAuxiliary(preflightResults, state.Proxy())
		}

		actualExecutor := engine.New(engine.Config{
			CheckTimeout:     options.CheckTimeout,
			MaxConcurrency:   options.MaxConcurrency,
			Now:              r.now,
			EventIndexOffset: planSize(preflight),
		})
		actualResults := actualExecutor.Run(runContext, state, actual, sink)
		diagnosis.Checks = append(mandatoryResults, preflightResults...)
		diagnosis.Checks = append(diagnosis.Checks, actualResults...)
	}
	diagnosis.NetworkPaths, diagnosis.Checks = correlatedNetworkResult(state, diagnosis.Checks)
	diagnosis.Summary = summary.Build(diagnosis.Checks)
	diagnosis.FinishedAt = r.now()
	diagnosis.Duration = diagnosis.FinishedAt.Sub(started)
	emit(sink, model.CheckEvent{
		Type:   model.EventRunCompleted,
		Status: diagnosis.Summary.Status,
		At:     diagnosis.FinishedAt,
	})
	return finishEventDelivery(delivery, diagnosis, nil)
}

func correlatedEventSink(sink model.EventSink, state *model.State) model.EventSink {
	if sink == nil || state == nil {
		return sink
	}
	return func(event model.CheckEvent) {
		if event.Result != nil {
			_, results := correlatedNetworkResult(state, []model.CheckResult{*event.Result})
			if len(results) == 1 {
				event.Result = &results[0]
			}
		}
		emit(sink, event)
	}
}

// Stream runs asynchronously and closes both returned channels on completion.
func (r *Runner) Stream(ctx context.Context, options model.DiagnoseOptions) (<-chan model.CheckEvent, <-chan Outcome) {
	events := make(chan model.CheckEvent, 256)
	outcomes := make(chan Outcome, 1)
	go func() {
		defer close(events)
		defer close(outcomes)
		diagnosis, err := r.Diagnose(ctx, options, func(event model.CheckEvent) {
			events <- event
		})
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
	if options.Timeout > maximumDiagnosticTimeout {
		return options, &InputError{Code: "INVALID_TIMEOUT", Message: "timeout must be at most 24h"}
	}
	if options.Timeout == 0 {
		options.Timeout = defaults.Timeout
	}
	if options.CheckTimeout < 0 {
		return options, &InputError{Code: "INVALID_CHECK_TIMEOUT", Message: "check timeout cannot be negative"}
	}
	if options.CheckTimeout > maximumDiagnosticTimeout {
		return options, &InputError{Code: "INVALID_CHECK_TIMEOUT", Message: "check timeout must be at most 24h"}
	}
	if options.CheckTimeout == 0 {
		options.CheckTimeout = defaults.CheckTimeout
	}
	if options.CheckTimeout > options.Timeout {
		return options, &InputError{
			Code:    "INVALID_CHECK_TIMEOUT",
			Message: "check timeout must not exceed global timeout",
		}
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
	if options.ProbeMode == "" {
		options.ProbeMode = defaults.ProbeMode
	}
	options.ProbeMode = model.ProbeMode(
		strings.ReplaceAll(strings.ToLower(strings.TrimSpace(string(options.ProbeMode))), "-", "_"),
	)
	if options.ProbeMode == "matrix" {
		options.ProbeMode = model.ProbeModeAddressMatrix
	}
	if !options.ProbeMode.Valid() {
		return options, &InputError{Code: "INVALID_PROBE_MODE", Message: "probe mode must be client_effective or address_matrix"}
	}
	if options.AddressLimit == 0 {
		options.AddressLimit = defaults.AddressLimit
	}
	if options.AddressLimit < 1 || options.AddressLimit > 16 {
		return options, &InputError{Code: "INVALID_ADDRESS_LIMIT", Message: "address limit must be between 1 and 16"}
	}
	if options.AddressMatrixBudget == 0 {
		options.AddressMatrixBudget = defaults.AddressMatrixBudget
	}
	if options.AddressMatrixBudget < 0 || options.AddressMatrixBudget > maximumDiagnosticTimeout {
		return options, &InputError{Code: "INVALID_ADDRESS_MATRIX_BUDGET", Message: "address matrix budget must be positive and at most 24h"}
	}
	if options.AddressMatrixBudget > options.Timeout {
		options.AddressMatrixBudget = options.Timeout
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > 50 {
		return options, &InputError{Code: "INVALID_MAX_REDIRECTS", Message: "maximum redirects must be between 0 and 50"}
	}
	if options.MaxRedirectLocationBytes < 0 || options.MaxRedirectLocationBytes > 64<<10 {
		return options, &InputError{
			Code:    "INVALID_REDIRECT_LOCATION_LIMIT",
			Message: "redirect Location limit must be between 1 byte and 64 KiB",
		}
	}
	if options.MaxRedirectLocationBytes == 0 {
		options.MaxRedirectLocationBytes = defaults.MaxRedirectLocationBytes
	}
	if options.ActualHTTPReserve < 0 || options.ActualHTTPReserve >= options.Timeout {
		return options, &InputError{
			Code:    "INVALID_ACTUAL_HTTP_RESERVE",
			Message: "actual HTTP reserve must be non-negative and shorter than the global timeout",
		}
	}
	if options.ActualHTTPReserve == 0 {
		options.ActualHTTPReserve = options.CheckTimeout
		if maximum := options.Timeout / 3; options.ActualHTTPReserve > maximum {
			options.ActualHTTPReserve = maximum
		}
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
	if options.ExpectedStatusMin == 0 {
		options.ExpectedStatusMin = defaults.ExpectedStatusMin
	}
	if options.ExpectedStatusMax == 0 {
		options.ExpectedStatusMax = defaults.ExpectedStatusMax
	}
	if options.ExpectedStatusMin < 100 || options.ExpectedStatusMin > 599 ||
		options.ExpectedStatusMax < 100 || options.ExpectedStatusMax > 599 ||
		options.ExpectedStatusMin > options.ExpectedStatusMax {
		return options, &InputError{Code: "INVALID_EXPECTED_STATUS", Message: "expected HTTP status must be between 100 and 599"}
	}
	if options.LatencyThreshold < 0 || options.LatencyThreshold > maximumDiagnosticTimeout {
		return options, &InputError{Code: "INVALID_LATENCY_THRESHOLD", Message: "latency threshold must be between zero and 24h"}
	}
	options.ConnectIP = strings.TrimSpace(options.ConnectIP)
	if options.ConnectIP != "" {
		address, parseErr := netip.ParseAddr(options.ConnectIP)
		if parseErr != nil {
			return options, &InputError{Code: "INVALID_CONNECT_IP", Message: "connect IP must be an IP literal"}
		}
		if address.Zone() != "" && (!address.Is6() || !address.IsLinkLocalUnicast()) {
			return options, &InputError{Code: "INVALID_CONNECT_IP", Message: "an IPv6 zone is allowed only for a link-local address"}
		}
		if options.IPVersion == model.IPVersion4 && !address.Is4() ||
			options.IPVersion == model.IPVersion6 && !address.Is6() {
			return options, &InputError{Code: "INVALID_CONNECT_IP", Message: "connect IP does not match the selected IP version"}
		}
		options.ConnectIP = address.String()
	}
	options.ServerName = strings.TrimSuffix(strings.TrimSpace(options.ServerName), ".")
	options.HTTPHost = strings.TrimSpace(options.HTTPHost)
	if invalidEndpointIdentity(options.ServerName, false) || invalidEndpointIdentity(options.HTTPHost, true) {
		return options, &InputError{Code: "INVALID_ENDPOINT_IDENTITY", Message: "SNI or HTTP Host override is invalid"}
	}
	headers, names, headerErr := normalizeRuntimeHeaders(options.RequestHeaders)
	if headerErr != nil {
		return options, headerErr
	}
	options.RequestHeaders = headers
	options.RequestHeaderNames = names
	return options, nil
}

var runnerManagedHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "proxy-connection": {},
	"te": {}, "trailer": {}, "transfer-encoding": {}, "upgrade": {},
}

func normalizeRuntimeHeaders(input map[string]string) (map[string]string, []string, error) {
	if len(input) == 0 {
		return nil, nil, nil
	}
	if len(input) > 16 {
		return nil, nil, &InputError{Code: "INVALID_REQUEST_HEADERS", Message: "at most 16 one-time request headers are allowed"}
	}
	result := make(map[string]string, len(input))
	total := 0
	for name, value := range input {
		name = strings.TrimSpace(name)
		canonical := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, nil, &InputError{Code: "INVALID_REQUEST_HEADERS", Message: "one-time request headers are invalid"}
		}
		if _, forbidden := runnerManagedHeaders[canonical]; forbidden {
			return nil, nil, &InputError{Code: "INVALID_REQUEST_HEADERS", Message: "one-time request header is managed by Orynelo"}
		}
		if _, duplicate := result[canonical]; duplicate {
			return nil, nil, &InputError{Code: "INVALID_REQUEST_HEADERS", Message: "one-time request header is duplicated"}
		}
		total += len(name) + len(value)
		if total > 8<<10 {
			return nil, nil, &InputError{Code: "INVALID_REQUEST_HEADERS", Message: "one-time request headers exceed the 8 KiB limit"}
		}
		result[canonical] = value
	}
	names := make([]string, 0, len(result))
	for name := range result {
		names = append(names, name)
	}
	sort.Strings(names)
	return result, names, nil
}

func invalidEndpointIdentity(value string, allowPort bool) bool {
	if value == "" {
		return false
	}
	if len(value) > 512 || containsControl(value) || strings.ContainsAny(value, " /\\?#@") {
		return true
	}
	return !allowPort && strings.Contains(value, ":")
}

func prepareRuntimeOptions(options model.DiagnoseOptions) (model.DiagnoseOptions, error) {
	if options.Insecure && (options.CustomCABundlePath != "" || len(options.CustomCAPEM) > 0) {
		return options, &InputError{Code: "INVALID_CA_BUNDLE", Message: "custom CA and insecure TLS mode are mutually exclusive"}
	}
	if options.CustomCABundlePath != "" {
		content, err := trust.ReadBundle(options.CustomCABundlePath)
		if err != nil {
			return options, &InputError{Code: "INVALID_CA_BUNDLE", Message: "custom CA bundle could not be loaded"}
		}
		options.CustomCAPEM = content
	}
	if len(options.CustomCAPEM) > 0 {
		if err := trust.ValidateBundle(options.CustomCAPEM); err != nil {
			return options, &InputError{Code: "INVALID_CA_BUNDLE", Message: "custom CA bundle is invalid"}
		}
		options.CustomCAConfigured = true
	}
	return options, nil
}

func reportableOptions(options model.DiagnoseOptions) model.DiagnoseOptions {
	result := options
	result.CustomCABundlePath = ""
	result.CustomCAPEM = nil
	result.RequestHeaders = nil
	result.RequestHeaderNames = append([]string(nil), options.RequestHeaderNames...)
	return result
}

func splitPlanAtCheck(plan engine.Plan, checkID string) (engine.Plan, engine.Plan) {
	for stageIndex, stage := range plan {
		for _, check := range stage {
			if check.ID() != checkID {
				continue
			}
			return plan[:stageIndex], plan[stageIndex:]
		}
	}
	return plan, nil
}

// splitMandatoryPreflight keeps target parsing and proxy-policy selection on
// the global diagnosis budget. Only the remaining direct-origin comparison
// checks may consume the shorter auxiliary budget.
func splitMandatoryPreflight(plan engine.Plan) (engine.Plan, engine.Plan) {
	if mandatory, auxiliary, found := splitPlanAfterCheck(plan, "environment"); found {
		return mandatory, auxiliary
	}
	if mandatory, auxiliary, found := splitPlanAfterCheck(plan, "target"); found {
		return mandatory, auxiliary
	}
	return nil, plan
}

func splitPlanAfterCheck(plan engine.Plan, checkID string) (engine.Plan, engine.Plan, bool) {
	for stageIndex, stage := range plan {
		for checkIndex, check := range stage {
			if check.ID() != checkID {
				continue
			}

			mandatory := append(engine.Plan(nil), plan[:stageIndex]...)
			mandatory = append(mandatory, stage[:checkIndex+1])

			auxiliary := make(engine.Plan, 0, len(plan)-stageIndex)
			if checkIndex+1 < len(stage) {
				auxiliary = append(auxiliary, stage[checkIndex+1:])
			}
			auxiliary = append(auxiliary, plan[stageIndex+1:]...)
			return mandatory, auxiliary, true
		}
	}
	return nil, plan, false
}

func reservedPreflightContext(
	parent context.Context,
	configuredReserve time.Duration,
) (context.Context, context.CancelFunc) {
	deadline, ok := parent.Deadline()
	if !ok || configuredReserve <= 0 {
		return context.WithCancel(parent)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(parent)
	}
	preflightDeadline := deadline.Add(-configuredReserve)
	return context.WithDeadlineCause(
		parent,
		preflightDeadline,
		engine.ErrAuxiliaryBudgetExhausted,
	)
}

func markProxyPreflightAuxiliary(results []model.CheckResult, proxy model.ProxyInfo) {
	if !proxy.Selected {
		return
	}
	markHTTPPreflightAuxiliary(results, true)
}

func markHTTPPreflightAuxiliary(results []model.CheckResult, proxySelected bool) {
	for index := range results {
		switch results[index].ID {
		case "dns", "route", "tcp", "tls":
			results[index].Role = model.CheckRoleAuxiliaryDirectComparison
			message := "This short-lived direct preflight is separate from the connection selected by the actual HTTP transport."
			route := "direct_origin_preflight"
			if proxySelected {
				message = "This direct-origin probe is an auxiliary comparison, not the selected proxy route."
				route = "direct_origin_comparison"
			}
			results[index].Evidence = append(results[index].Evidence, model.Evidence{
				ID:      results[index].ID + ".auxiliary_role",
				CheckID: results[index].ID,
				Code:    "AUXILIARY_DIRECT_COMPARISON",
				Message: message,
				Details: map[string]string{
					"role":  string(model.CheckRoleAuxiliaryDirectComparison),
					"route": route,
				},
			})
		}
	}
}

func auxiliaryPreflightEventSink(sink model.EventSink, proxySelected bool) model.EventSink {
	if sink == nil {
		return nil
	}
	return func(event model.CheckEvent) {
		if event.Result != nil {
			result := *event.Result
			values := []model.CheckResult{result}
			markHTTPPreflightAuxiliary(values, proxySelected)
			event.Result = &values[0]
		}
		emit(sink, event)
	}
}

func skipInvalidProxyDirectCheck(
	state *model.State,
	check model.Check,
) (model.CheckResult, bool) {
	if state.Proxy().Selected && state.Options.ProbeMode != model.ProbeModeAddressMatrix {
		switch check.ID() {
		case "dns", "route", "tcp", "tls":
			return model.CheckResult{
				ID:          check.ID(),
				Name:        check.Name(),
				Status:      model.StatusSkipped,
				Summary:     "The direct-origin comparison was not selected in client-effective proxy mode.",
				NetworkRefs: []model.NetworkRef{{PathID: directPathID, HopID: originHopID}},
				Evidence: []model.Evidence{{
					ID:         check.ID() + ".client_effective_proxy",
					Code:       "DIRECT_PROBE_NOT_SELECTED",
					Message:    "Only the actual proxy route was exercised; enable address-matrix mode for a direct-origin comparison.",
					NetworkRef: &model.NetworkRef{PathID: directPathID, HopID: originHopID},
				}},
			}, true
		}
	}
	validity := state.Proxy().Selection.Validity
	if validity != model.ProxyValidityInvalid && validity != "" {
		return model.CheckResult{}, false
	}
	switch check.ID() {
	case "dns", "route", "tcp", "tls":
		if validity == "" {
			return model.CheckResult{
				ID:        check.ID(),
				Name:      check.Name(),
				Status:    model.StatusSkipped,
				Summary:   "The direct-origin check was skipped because proxy selection did not complete.",
				ErrorCode: errorProxySelectionUnavailable,
				Evidence: []model.Evidence{{
					ID:      check.ID() + ".proxy_policy",
					CheckID: check.ID(),
					Code:    errorProxySelectionUnavailable,
					Message: "No direct-origin network operation was started while proxy policy was unresolved.",
				}},
			}, true
		}
		return model.CheckResult{
			ID:        check.ID(),
			Name:      check.Name(),
			Status:    model.StatusSkipped,
			Summary:   "The direct-origin check was skipped because proxy configuration is invalid.",
			ErrorCode: environment.ErrorProxyConfigInvalid,
			Evidence: []model.Evidence{{
				ID:      check.ID() + ".proxy_policy",
				CheckID: check.ID(),
				Code:    environment.ErrorProxyConfigInvalid,
				Message: "No direct-origin network operation was started while the configured proxy was invalid.",
			}},
		}, true
	default:
		return model.CheckResult{}, false
	}
}

func planSize(plan engine.Plan) int {
	total := 0
	for _, stage := range plan {
		total += len(stage)
	}
	return total
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

func privacyEventSink(sink model.EventSink) model.EventSink {
	if sink == nil {
		return nil
	}
	projection := privacy.Standard()
	return func(event model.CheckEvent) {
		sink(projection.Event(event))
	}
}
