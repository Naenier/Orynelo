package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type testCheck struct {
	id      string
	delay   time.Duration
	status  model.Status
	active  *atomic.Int32
	maximum *atomic.Int32
	panic   bool
}

func (c testCheck) ID() string   { return c.id }
func (c testCheck) Name() string { return "Check " + c.id }

func (c testCheck) Run(ctx context.Context, _ *model.State) model.CheckResult {
	if c.panic {
		panic("test panic")
	}
	if c.active != nil {
		current := c.active.Add(1)
		defer c.active.Add(-1)
		for {
			seen := c.maximum.Load()
			if current <= seen || c.maximum.CompareAndSwap(seen, current) {
				break
			}
		}
	}
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return model.CheckResult{Status: model.StatusCancelled, Summary: "cancelled"}
	}
	status := c.status
	if status == "" {
		status = model.StatusPassed
	}
	return model.CheckResult{Status: status, Summary: "finished " + c.id}
}

func TestRunIsBoundedAndDeterministic(t *testing.T) {
	t.Parallel()
	var active atomic.Int32
	var maximum atomic.Int32
	plan := Plan{{
		testCheck{id: "a", delay: 30 * time.Millisecond, active: &active, maximum: &maximum},
		testCheck{id: "b", delay: time.Millisecond, active: &active, maximum: &maximum},
		testCheck{id: "c", delay: 10 * time.Millisecond, active: &active, maximum: &maximum},
	}}
	var events []model.CheckEvent
	results := New(Config{
		CheckTimeout:   time.Second,
		MaxConcurrency: 2,
	}).Run(context.Background(), &model.State{}, plan, func(event model.CheckEvent) {
		events = append(events, event)
	})
	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", maximum.Load())
	}
	for index, id := range []string{"a", "b", "c"} {
		if results[index].ID != id {
			t.Fatalf("result order = %#v", results)
		}
		if events[index].Type != model.EventCheckStarted || events[index].CheckID != id {
			t.Fatalf("start event %d = %#v", index, events[index])
		}
		if events[index+3].Type != model.EventCheckCompleted || events[index+3].CheckID != id {
			t.Fatalf("completion event %d = %#v", index, events[index+3])
		}
	}
}

func TestRunPerCheckTimeout(t *testing.T) {
	t.Parallel()
	results := New(Config{
		CheckTimeout:   5 * time.Millisecond,
		MaxConcurrency: 1,
	}).Run(context.Background(), &model.State{}, Plan{{
		testCheck{id: "slow", delay: time.Hour},
	}}, nil)
	if results[0].Status != model.StatusFailed || results[0].ErrorCode != ErrorCheckTimeout {
		t.Fatalf("result = %#v", results[0])
	}
}

func TestRunCancellationAndDeadlineAreDistinct(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		status  model.Status
		code    string
	}{
		{
			name: "explicit cancellation",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			status: model.StatusCancelled,
			code:   "OPERATION_CANCELLED",
		},
		{
			name: "global deadline",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				return ctx, cancel
			},
			status: model.StatusFailed,
			code:   "OPERATION_TIMEOUT",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := test.context()
			defer cancel()
			results := New(Config{MaxConcurrency: 1}).Run(ctx, &model.State{}, Plan{
				{testCheck{id: "one"}},
				{testCheck{id: "two"}},
			}, nil)
			for _, result := range results {
				if result.Status != test.status || result.ErrorCode != test.code {
					t.Fatalf("result = %#v", result)
				}
			}
		})
	}
}

func TestRunRecoversCheckPanic(t *testing.T) {
	t.Parallel()
	results := New(Config{MaxConcurrency: 1}).Run(
		context.Background(),
		&model.State{},
		Plan{{testCheck{id: "panic", panic: true}}},
		nil,
	)
	if results[0].Status != model.StatusFailed || results[0].ErrorCode != ErrorInternalPanic {
		t.Fatalf("result = %#v", results[0])
	}
}
