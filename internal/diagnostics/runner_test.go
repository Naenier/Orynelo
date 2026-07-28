package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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
