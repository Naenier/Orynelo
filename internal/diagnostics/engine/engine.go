// Package engine executes staged diagnostic plans with bounded concurrency,
// per-check timeouts, deterministic results/events, and cancellation.
package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

const ErrorCheckTimeout = "CHECK_TIMEOUT"
const ErrorInternalPanic = "CHECK_INTERNAL_PANIC"

// Plan is an ordered list of stages. Checks within a stage may execute in
// parallel; stages execute sequentially.
type Plan [][]model.Check

// Config controls plan execution.
type Config struct {
	CheckTimeout   time.Duration
	MaxConcurrency int
	Now            func() time.Time
}

// Engine executes a reusable diagnostic plan without global mutable state.
type Engine struct {
	config Config
}

// New constructs an engine.
func New(config Config) *Engine {
	if config.MaxConcurrency < 1 {
		config.MaxConcurrency = 4
	}
	if config.MaxConcurrency > 32 {
		config.MaxConcurrency = 32
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Engine{config: config}
}

// Run executes plan and returns results in exact plan order. Check-started and
// check-completed events are also emitted in plan order, regardless of actual
// goroutine completion order.
func (e *Engine) Run(ctx context.Context, state *model.State, plan Plan, sink model.EventSink) []model.CheckResult {
	total := planSize(plan)
	results := make([]model.CheckResult, total)
	offset := 0
	for _, stage := range plan {
		if len(stage) == 0 {
			continue
		}
		if ctx.Err() != nil {
			for _, check := range stage {
				results[offset] = stoppedResult(check, e.now(), ctx.Err())
				emit(sink, model.CheckEvent{
					Type:      model.EventCheckCompleted,
					CheckID:   check.ID(),
					CheckName: check.Name(),
					Status:    results[offset].Status,
					At:        e.now(),
					Index:     offset,
					Result:    resultPointer(results[offset]),
				})
				offset++
			}
			continue
		}

		for index, check := range stage {
			emit(sink, model.CheckEvent{
				Type:      model.EventCheckStarted,
				CheckID:   check.ID(),
				CheckName: check.Name(),
				Status:    model.StatusRunning,
				At:        e.now(),
				Index:     offset + index,
			})
		}
		stageResults := e.runStage(ctx, state, stage)
		for index, result := range stageResults {
			results[offset+index] = result
			emit(sink, model.CheckEvent{
				Type:      model.EventCheckCompleted,
				CheckID:   result.ID,
				CheckName: result.Name,
				Status:    result.Status,
				At:        result.FinishedAt,
				Index:     offset + index,
				Result:    resultPointer(result),
			})
		}
		offset += len(stage)
	}
	return results
}

func (e *Engine) runStage(ctx context.Context, state *model.State, checks []model.Check) []model.CheckResult {
	results := make([]model.CheckResult, len(checks))
	jobs := make(chan int)
	workers := e.config.MaxConcurrency
	if workers > len(checks) {
		workers = len(checks)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				results[index] = e.runCheck(ctx, state, checks[index])
			}
		}()
	}
	for index := range checks {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	return results
}

func (e *Engine) runCheck(ctx context.Context, state *model.State, check model.Check) (result model.CheckResult) {
	started := e.now()
	if ctx.Err() != nil {
		return stoppedResult(check, started, ctx.Err())
	}
	checkCtx := ctx
	cancel := func() {}
	if e.config.CheckTimeout > 0 {
		checkCtx, cancel = context.WithTimeout(ctx, e.config.CheckTimeout)
	}
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			finished := e.now()
			result = model.CheckResult{
				ID:        check.ID(),
				Name:      check.Name(),
				Status:    model.StatusFailed,
				Summary:   "The check stopped because of an internal error.",
				ErrorCode: ErrorInternalPanic,
				Evidence: []model.Evidence{{
					ID:      check.ID() + ".panic",
					CheckID: check.ID(),
					Code:    ErrorInternalPanic,
					Message: "The diagnostic check encountered an internal error.",
				}},
			}.Complete(started, finished)
		}
	}()

	result = check.Run(checkCtx, state)
	finished := e.now()
	if result.ID == "" {
		result.ID = check.ID()
	}
	if result.Name == "" {
		result.Name = check.Name()
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.Status = model.StatusFailed
			result.ErrorCode = "OPERATION_TIMEOUT"
			result.Summary = "The diagnosis timeout elapsed."
		} else {
			result.Status = model.StatusCancelled
			result.ErrorCode = "OPERATION_CANCELLED"
			result.Summary = "The check was cancelled."
		}
	} else if checkCtx.Err() == context.DeadlineExceeded &&
		(result.Status == model.StatusCancelled || result.Status == model.StatusRunning || result.Status == model.StatusPending) {
		result.Status = model.StatusFailed
		result.ErrorCode = ErrorCheckTimeout
		result.Summary = "The check exceeded its configured timeout."
	}
	if !result.Status.Valid() || result.Status == model.StatusPending || result.Status == model.StatusRunning {
		result.Status = model.StatusFailed
		if result.ErrorCode == "" {
			result.ErrorCode = "CHECK_INVALID_RESULT"
		}
	}
	return result.Complete(started, finished)
}

func stoppedResult(check model.Check, now time.Time, err error) model.CheckResult {
	result := model.CheckResult{
		ID:         check.ID(),
		Name:       check.Name(),
		Status:     model.StatusCancelled,
		StartedAt:  now,
		FinishedAt: now,
		Summary:    "The check was cancelled before it started.",
		ErrorCode:  "OPERATION_CANCELLED",
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.Status = model.StatusFailed
		result.Summary = "The diagnosis timeout elapsed before the check started."
		result.ErrorCode = "OPERATION_TIMEOUT"
	}
	return result
}

func planSize(plan Plan) int {
	total := 0
	for _, stage := range plan {
		total += len(stage)
	}
	return total
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

func (e *Engine) now() time.Time { return e.config.Now() }
