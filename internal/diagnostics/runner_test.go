package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	httpcheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/http"
	"github.com/Naenier/opsdoctor/internal/diagnostics/engine"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type passingCheck struct{}

func (passingCheck) ID() string   { return "offline" }
func (passingCheck) Name() string { return "Offline check" }
func (passingCheck) Run(context.Context, *model.State) model.CheckResult {
	return model.CheckResult{
		Status:  model.StatusPassed,
		Summary: "Offline check passed.",
	}
}

type secretEventCheck struct{}

func (secretEventCheck) ID() string   { return "secret-event" }
func (secretEventCheck) Name() string { return "Secret event" }
func (secretEventCheck) Run(context.Context, *model.State) model.CheckResult {
	return model.CheckResult{
		Status:  model.StatusPassed,
		Summary: "request https://alice:password@example.test/?token=event-secret passed",
	}
}

type identifiedPassingCheck string

func (c identifiedPassingCheck) ID() string   { return string(c) }
func (c identifiedPassingCheck) Name() string { return string(c) }
func (c identifiedPassingCheck) Run(context.Context, *model.State) model.CheckResult {
	return model.CheckResult{Status: model.StatusPassed, Summary: "passed"}
}

type waitsForContextCheck string

func (c waitsForContextCheck) ID() string   { return string(c) }
func (c waitsForContextCheck) Name() string { return string(c) }
func (c waitsForContextCheck) Run(ctx context.Context, _ *model.State) model.CheckResult {
	<-ctx.Done()
	return model.CheckResult{Status: model.StatusCancelled, Summary: "stopped"}
}

type invalidProxyCheck struct{}

func (invalidProxyCheck) ID() string   { return "environment" }
func (invalidProxyCheck) Name() string { return "environment" }
func (invalidProxyCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	state.SetProxy(model.ProxyInfo{Selection: model.ProxySelection{
		SourceVariable: "HTTPS_PROXY",
		Validity:       model.ProxyValidityInvalid,
		ErrorCode:      "PROXY_CONFIG_INVALID",
	}})
	return model.CheckResult{
		Status:    model.StatusFailed,
		Summary:   "invalid proxy",
		ErrorCode: "PROXY_CONFIG_INVALID",
	}
}

type callCountingCheck struct {
	id    string
	calls *int
}

func (c callCountingCheck) ID() string   { return c.id }
func (c callCountingCheck) Name() string { return c.id }
func (c callCountingCheck) Run(context.Context, *model.State) model.CheckResult {
	*c.calls++
	return model.CheckResult{Status: model.StatusPassed, Summary: "unexpected call"}
}

type perCheckTimeoutCheck string

func (c perCheckTimeoutCheck) ID() string   { return string(c) }
func (c perCheckTimeoutCheck) Name() string { return "Diagnostic stage " + string(c) }
func (c perCheckTimeoutCheck) Run(ctx context.Context, _ *model.State) model.CheckResult {
	<-ctx.Done()
	return model.CheckResult{Status: model.StatusCancelled, Summary: "cancelled"}
}

type delayedPassingCheck struct {
	id    string
	delay time.Duration
}

func (c delayedPassingCheck) ID() string   { return c.id }
func (c delayedPassingCheck) Name() string { return c.id }
func (c delayedPassingCheck) Run(ctx context.Context, _ *model.State) model.CheckResult {
	timer := time.NewTimer(c.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return model.CheckResult{Status: model.StatusCancelled, Summary: "cancelled"}
	case <-timer.C:
		return model.CheckResult{Status: model.StatusPassed, Summary: "passed"}
	}
}

type unavailableEnvironmentCheck struct {
	deadline *time.Time
}

func (unavailableEnvironmentCheck) ID() string   { return "environment" }
func (unavailableEnvironmentCheck) Name() string { return "environment" }
func (c unavailableEnvironmentCheck) Run(ctx context.Context, _ *model.State) model.CheckResult {
	if deadline, ok := ctx.Deadline(); ok {
		*c.deadline = deadline
	}
	return model.CheckResult{
		Status:    model.StatusFailed,
		Summary:   "proxy selection unavailable",
		ErrorCode: errorProxySelectionUnavailable,
	}
}

type directEnvironmentCheck struct{}

func (directEnvironmentCheck) ID() string   { return "environment" }
func (directEnvironmentCheck) Name() string { return "environment" }
func (directEnvironmentCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	state.SetProxy(model.ProxyInfo{Selection: model.ProxySelection{
		Validity: model.ProxyValidityNotConfigured,
	}})
	return model.CheckResult{Status: model.StatusPassed, Summary: "direct route selected"}
}

type exhaustedAuxiliaryTLSCheck struct{}

func (exhaustedAuxiliaryTLSCheck) ID() string   { return "tls" }
func (exhaustedAuxiliaryTLSCheck) Name() string { return "tls" }
func (exhaustedAuxiliaryTLSCheck) Run(ctx context.Context, state *model.State) model.CheckResult {
	<-ctx.Done()
	state.SetTLS(model.TLSResult{
		ErrorCode: engine.ErrorAuxiliaryBudget,
		Error:     "auxiliary TLS comparison stopped",
	})
	return model.CheckResult{Status: model.StatusCancelled, Summary: "stopped"}
}

type roundTripFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripFunc) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	return f(request)
}

func timeoutTestPlan(stage string) engine.Plan {
	check := perCheckTimeoutCheck(stage)
	switch stage {
	case "dns", "route", "tcp", "tls":
		return engine.Plan{{directEnvironmentCheck{}}, {check}}
	default:
		return engine.Plan{{check}}
	}
}

func TestRunnerDiagnoseAndEvents(t *testing.T) {
	t.Parallel()
	runner := NewRunner(WithPlan(engine.Plan{{passingCheck{}}}))
	options := model.DefaultDiagnoseOptions(
		"https://alice:password@пример.рф/path?token=top-secret",
	)
	var events []model.CheckEvent
	diagnosis, err := runner.Diagnose(context.Background(), options, func(event model.CheckEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if diagnosis.ID == "" || diagnosis.Summary.Status != model.StatusPassed {
		t.Fatalf("diagnosis = %#v", diagnosis)
	}
	serialized, err := json.Marshal(diagnosis)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice", "password", "top-secret"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("diagnosis leaked %q: %s", secret, serialized)
		}
	}
	types := []model.CheckEventType{
		model.EventRunStarted,
		model.EventCheckStarted,
		model.EventCheckCompleted,
		model.EventRunCompleted,
	}
	if len(events) != len(types) {
		t.Fatalf("events = %#v", events)
	}
	for index, eventType := range types {
		if events[index].Type != eventType {
			t.Fatalf("event %d = %#v", index, events[index])
		}
	}
}

func TestRunnerProjectsEventsThroughPrivacyBoundary(t *testing.T) {
	t.Parallel()

	runner := NewRunner(WithPlan(engine.Plan{{secretEventCheck{}}}))
	var completed model.CheckEvent
	_, err := runner.Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("example.test:443"),
		func(event model.CheckEvent) {
			if event.Type == model.EventCheckCompleted {
				completed = event
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Result == nil {
		t.Fatal("completed event was not delivered")
	}
	for _, secret := range []string{"alice", "password", "event-secret"} {
		if strings.Contains(completed.Result.Summary, secret) {
			t.Fatalf("event leaked %q: %#v", secret, completed)
		}
	}
}

func TestRunnerInvalidTargetIsSafeInputError(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions(
		"https://alice:password@example.com/%zz?token=top-secret",
	)
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if !IsInputError(err) {
		t.Fatalf("error = %T %v", err, err)
	}
	serialized, marshalErr := json.Marshal(diagnosis)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, secret := range []string{"alice", "password", "top-secret"} {
		if strings.Contains(string(serialized), secret) || strings.Contains(err.Error(), secret) {
			t.Fatalf("invalid target leaked %q: diagnosis=%s error=%v", secret, serialized, err)
		}
	}
}

func TestRunnerStream(t *testing.T) {
	t.Parallel()
	runner := NewRunner(WithPlan(engine.Plan{{passingCheck{}}}))
	events, outcomes := runner.Stream(
		context.Background(),
		model.DefaultDiagnoseOptions("example.com:443"),
	)
	var eventCount int
	for range events {
		eventCount++
	}
	outcome := <-outcomes
	if outcome.Err != nil || outcome.Diagnosis.ID == "" {
		t.Fatalf("outcome = %#v", outcome)
	}
	if eventCount != 4 {
		t.Fatalf("event count = %d", eventCount)
	}
}

func TestRunnerReservesGlobalBudgetForActualHTTPRoute(t *testing.T) {
	t.Parallel()
	plan := engine.Plan{
		{waitsForContextCheck("slow_auxiliary")},
		{identifiedPassingCheck("http")},
	}
	runner := NewRunner(WithPlan(plan))
	options := model.DefaultDiagnoseOptions("https://example.com")
	options.Timeout = 120 * time.Millisecond
	options.CheckTimeout = 100 * time.Millisecond
	options.ActualHTTPReserve = 40 * time.Millisecond
	var events []model.CheckEvent

	diagnosis, err := runner.Diagnose(context.Background(), options, func(event model.CheckEvent) {
		events = append(events, event)
	})

	if err != nil {
		t.Fatal(err)
	}
	if len(diagnosis.Checks) != 2 ||
		diagnosis.Checks[0].Status != model.StatusSkipped ||
		diagnosis.Checks[0].ErrorCode != engine.ErrorAuxiliaryBudget ||
		diagnosis.Checks[1].Status != model.StatusPassed {
		t.Fatalf("checks = %#v", diagnosis.Checks)
	}
	var started []model.CheckEvent
	for _, event := range events {
		if event.Type == model.EventCheckStarted {
			started = append(started, event)
		}
	}
	if len(started) != 2 || started[0].Index != 0 || started[1].Index != 1 {
		t.Fatalf("started events = %#v", started)
	}
}

func TestReservedPreflightContextUsesExactConfiguredReserve(t *testing.T) {
	t.Parallel()

	t.Run("reserve is not clamped to one third", func(t *testing.T) {
		t.Parallel()
		parentDeadline := time.Now().Add(time.Hour)
		parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
		defer cancelParent()

		preflight, cancelPreflight := reservedPreflightContext(parent, 40*time.Minute)
		defer cancelPreflight()
		deadline, ok := preflight.Deadline()
		if !ok {
			t.Fatal("preflight context has no deadline")
		}
		want := parentDeadline.Add(-40 * time.Minute)
		if !deadline.Equal(want) {
			t.Fatalf("preflight deadline = %v, want %v", deadline, want)
		}
	})

	t.Run("reserve larger than remaining time expires auxiliary work immediately", func(t *testing.T) {
		t.Parallel()
		parentDeadline := time.Now().Add(time.Second)
		parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
		defer cancelParent()

		preflight, cancelPreflight := reservedPreflightContext(parent, 2*time.Second)
		defer cancelPreflight()
		deadline, ok := preflight.Deadline()
		if !ok {
			t.Fatal("preflight context has no deadline")
		}
		want := parentDeadline.Add(-2 * time.Second)
		if !deadline.Equal(want) {
			t.Fatalf("preflight deadline = %v, want %v", deadline, want)
		}
		select {
		case <-preflight.Done():
		case <-time.After(100 * time.Millisecond):
			t.Fatal("auxiliary context did not expire immediately")
		}
		if !errors.Is(context.Cause(preflight), engine.ErrAuxiliaryBudgetExhausted) {
			t.Fatalf("context cause = %v", context.Cause(preflight))
		}
	})
}

func TestRunnerKeepsEnvironmentMandatoryAndFailsClosedWhenSelectionUnavailable(t *testing.T) {
	t.Parallel()
	var environmentDeadline time.Time
	directCalls := 0
	transportFactoryCalls := 0
	transportCalls := 0
	httpRequest := httpcheck.New()
	httpRequest.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		transportFactoryCalls++
		return roundTripFunc(func(*stdhttp.Request) (*stdhttp.Response, error) {
			transportCalls++
			return nil, errors.New("unexpected HTTP transport")
		})
	}
	plan := engine.Plan{
		{delayedPassingCheck{id: "target", delay: 10 * time.Millisecond}},
		{unavailableEnvironmentCheck{deadline: &environmentDeadline}},
		{callCountingCheck{id: "dns", calls: &directCalls}},
		{httpRequest},
	}
	options := model.DefaultDiagnoseOptions("https://example.com")
	options.Timeout = 2 * time.Second
	options.CheckTimeout = 2 * time.Second
	options.ActualHTTPReserve = 1500 * time.Millisecond

	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(
		context.Background(),
		options,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if environmentDeadline.IsZero() ||
		environmentDeadline.Sub(diagnosis.StartedAt) < 1800*time.Millisecond {
		t.Fatalf(
			"environment deadline = %v; diagnosis started at %v",
			environmentDeadline,
			diagnosis.StartedAt,
		)
	}
	if directCalls != 0 {
		t.Fatalf("direct-origin checks called %d time(s)", directCalls)
	}
	if transportFactoryCalls != 0 || transportCalls != 0 {
		t.Fatalf(
			"HTTP transport initialized/called = %d/%d",
			transportFactoryCalls,
			transportCalls,
		)
	}
	if len(diagnosis.Checks) != 4 ||
		diagnosis.Checks[2].Status != model.StatusSkipped ||
		diagnosis.Checks[2].ErrorCode != errorProxySelectionUnavailable ||
		diagnosis.Checks[3].Status != model.StatusFailed ||
		diagnosis.Checks[3].ErrorCode != errorProxySelectionUnavailable {
		t.Fatalf("checks = %#v", diagnosis.Checks)
	}
}

func TestRunnerAttemptsActualHTTPAfterAuxiliaryTLSBudgetExhaustion(t *testing.T) {
	t.Parallel()
	transportCalls := 0
	httpRequest := httpcheck.New()
	httpRequest.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			transportCalls++
			return &stdhttp.Response{
				StatusCode: stdhttp.StatusOK,
				Status:     "200 OK",
				Header:     make(stdhttp.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    request,
				Proto:      "HTTP/1.1",
			}, nil
		})
	}
	plan := engine.Plan{
		{directEnvironmentCheck{}},
		{exhaustedAuxiliaryTLSCheck{}},
		{httpRequest},
	}
	options := model.DefaultDiagnoseOptions("https://example.com")
	options.Timeout = 160 * time.Millisecond
	options.CheckTimeout = 140 * time.Millisecond
	options.ActualHTTPReserve = 120 * time.Millisecond

	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(
		context.Background(),
		options,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transportCalls != 1 {
		t.Fatalf("actual HTTP transport calls = %d, want 1", transportCalls)
	}
	if len(diagnosis.Checks) != 3 ||
		diagnosis.Checks[1].ErrorCode != engine.ErrorAuxiliaryBudget ||
		diagnosis.Checks[2].Status != model.StatusPassed {
		t.Fatalf("checks = %#v", diagnosis.Checks)
	}
}

func TestMarkProxyPreflightAuxiliary(t *testing.T) {
	t.Parallel()
	results := []model.CheckResult{
		{ID: "environment"},
		{ID: "dns"},
		{ID: "route"},
		{ID: "tcp"},
		{ID: "tls"},
	}
	markProxyPreflightAuxiliary(results, model.ProxyInfo{Selected: true})
	if results[0].Role != "" {
		t.Fatalf("environment role = %q", results[0].Role)
	}
	for _, result := range results[1:] {
		if result.Role != model.CheckRoleAuxiliaryDirectComparison {
			t.Fatalf("%s role = %q", result.ID, result.Role)
		}
		if len(result.Evidence) != 1 || result.Evidence[0].Code != "AUXILIARY_DIRECT_COMPARISON" {
			t.Fatalf("%s evidence = %#v", result.ID, result.Evidence)
		}
	}
}

func TestRunnerInvalidProxySkipsEveryDirectOriginNetworkCheck(t *testing.T) {
	t.Parallel()
	calls := 0
	plan := engine.Plan{
		{invalidProxyCheck{}},
		{callCountingCheck{id: "dns", calls: &calls}},
		{callCountingCheck{id: "route", calls: &calls}},
		{callCountingCheck{id: "tcp", calls: &calls}},
		{callCountingCheck{id: "tls", calls: &calls}},
		{identifiedPassingCheck("http")},
	}
	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("https://example.com"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("direct-origin checks called %d time(s)", calls)
	}
	for _, result := range diagnosis.Checks[1:5] {
		if result.Status != model.StatusSkipped || result.ErrorCode != "PROXY_CONFIG_INVALID" {
			t.Fatalf("result = %#v", result)
		}
		if len(result.Evidence) != 1 || result.Evidence[0].Code != "PROXY_CONFIG_INVALID" {
			t.Fatalf("evidence = %#v", result.Evidence)
		}
	}
}

func TestRunnerSummaryExplainsPerCheckTimeoutBudget(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{
		"target",
		"environment",
		"dns",
		"route",
		"tcp",
		"tls",
		"http",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			options := model.DefaultDiagnoseOptions("example.com:443")
			options.CheckTimeout = 5 * time.Millisecond
			options.Timeout = time.Second
			diagnosis, err := NewRunner(
				WithPlan(timeoutTestPlan(stage)),
			).Diagnose(context.Background(), options, nil)
			if err != nil {
				t.Fatal(err)
			}
			result := diagnosis.Checks[len(diagnosis.Checks)-1]
			if result.ErrorCode != engine.ErrorCheckTimeout {
				t.Fatalf("checks = %#v", diagnosis.Checks)
			}
			var timeoutEvidence *model.Evidence
			for index := range result.Evidence {
				if result.Evidence[index].Code == engine.ErrorCheckTimeout {
					timeoutEvidence = &result.Evidence[index]
					break
				}
			}
			if timeoutEvidence == nil ||
				timeoutEvidence.ID != stage+".timeout" ||
				timeoutEvidence.CheckID != stage ||
				timeoutEvidence.Details["stage"] != stage ||
				timeoutEvidence.Details["configuredBudget"] != "5ms" ||
				timeoutEvidence.Details["elapsed"] == "" {
				t.Fatalf("timeout evidence = %#v", timeoutEvidence)
			}
			if diagnosis.Summary.Title != "Diagnostic check timed out" ||
				diagnosis.Summary.Status != model.StatusFailed ||
				!strings.Contains(diagnosis.Summary.Description, "Diagnostic stage "+stage) ||
				!strings.Contains(diagnosis.Summary.Description, "5ms") {
				t.Fatalf("summary = %#v", diagnosis.Summary)
			}
			found := false
			for _, reference := range diagnosis.Summary.EvidenceRefs {
				if reference == stage+".timeout" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("summary refs = %#v", diagnosis.Summary.EvidenceRefs)
			}
		})
	}
}

func TestRunnerGlobalDeadlineRemainsOperationTimeout(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.CheckTimeout = 500 * time.Millisecond
	options.Timeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	diagnosis, err := NewRunner(
		WithPlan(timeoutTestPlan("dns")),
	).Diagnose(ctx, options, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := diagnosis.Checks[len(diagnosis.Checks)-1]
	if result.ErrorCode != "OPERATION_TIMEOUT" ||
		result.Status != model.StatusFailed {
		t.Fatalf("checks = %#v", diagnosis.Checks)
	}
	for _, evidence := range result.Evidence {
		if evidence.Code == engine.ErrorCheckTimeout {
			t.Fatalf("global deadline was reported as per-check timeout: %#v", evidence)
		}
	}
	if diagnosis.Summary.Title != "Diagnosis timed out" ||
		diagnosis.Summary.Status != model.StatusFailed {
		t.Fatalf("summary = %#v", diagnosis.Summary)
	}
}

func TestNonBlockingEventSink(t *testing.T) {
	t.Parallel()
	channel := make(chan model.CheckEvent, 1)
	sink := model.NonBlockingEventSink(channel)
	sink(model.CheckEvent{CheckID: "first"})
	sink(model.CheckEvent{CheckID: "dropped"})
	if len(channel) != 1 || (<-channel).CheckID != "first" {
		t.Fatal("nonblocking sink did not preserve bounded behavior")
	}
}

func TestRunnerRejectsUnsafeUserAgentAndThreshold(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*model.DiagnoseOptions)
		code   string
	}{
		{
			name: "check timeout exceeds global timeout",
			mutate: func(options *model.DiagnoseOptions) {
				options.Timeout = 2 * time.Second
				options.CheckTimeout = 3 * time.Second
			},
			code: "INVALID_CHECK_TIMEOUT",
		},
		{
			name: "global timeout exceeds 24 hours",
			mutate: func(options *model.DiagnoseOptions) {
				options.Timeout = 25 * time.Hour
				options.CheckTimeout = time.Hour
			},
			code: "INVALID_TIMEOUT",
		},
		{
			name: "check timeout exceeds 24 hours",
			mutate: func(options *model.DiagnoseOptions) {
				options.Timeout = 24 * time.Hour
				options.CheckTimeout = 25 * time.Hour
			},
			code: "INVALID_CHECK_TIMEOUT",
		},
		{
			name: "redirect limit is consistent with configuration",
			mutate: func(options *model.DiagnoseOptions) {
				options.MaxRedirects = 51
			},
			code: "INVALID_MAX_REDIRECTS",
		},
		{
			name: "header injection",
			mutate: func(options *model.DiagnoseOptions) {
				options.UserAgent = "OpsDoctor\r\nX-Evil: true"
			},
			code: "INVALID_USER_AGENT",
		},
		{
			name: "oversized certificate threshold",
			mutate: func(options *model.DiagnoseOptions) {
				options.CertificateWarningThreshold = 366 * 24 * time.Hour
			},
			code: "INVALID_CERTIFICATE_WARNING_THRESHOLD",
		},
		{
			name: "invalid report verbosity",
			mutate: func(options *model.DiagnoseOptions) {
				options.ReportVerbosity = "debug"
			},
			code: "INVALID_REPORT_VERBOSITY",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := model.DefaultDiagnoseOptions("example.com")
			test.mutate(&options)
			_, err := NewRunner(WithPlan(engine.Plan{{passingCheck{}}})).Diagnose(
				context.Background(), options, nil,
			)
			var input *InputError
			if !errors.As(err, &input) || input.Code != test.code {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}
