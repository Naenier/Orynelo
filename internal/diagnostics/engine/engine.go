// Package engine executes staged diagnostic plans with bounded concurrency,
// per-check timeouts, deterministic results/events, and cancellation.
package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const ErrorCheckTimeout = "CHECK_TIMEOUT"
const ErrorInternalPanic = "CHECK_INTERNAL_PANIC"
const ErrorAuxiliaryBudget = "AUXILIARY_BUDGET_RESERVED"

// ErrAuxiliaryBudgetExhausted is used by the Runner's short-term budget split.
// It stops comparison probes while leaving the parent deadline available to
// the actual HTTP/proxy route.
var ErrAuxiliaryBudgetExhausted = errors.New("auxiliary diagnostic budget exhausted")

// Plan is an ordered list of stages. Checks within a stage may execute in
// parallel; stages execute sequentially.
type Plan [][]model.Check

// Config controls plan execution.
type Config struct {
	CheckTimeout     time.Duration
	MaxConcurrency   int
	Now              func() time.Time
	EventIndexOffset int
	SkipCheck        func(*model.State, model.Check) (model.CheckResult, bool)
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
				results[offset] = stoppedResult(check, e.now(), context.Cause(ctx))
				emit(sink, model.CheckEvent{
					Type:      model.EventCheckCompleted,
					CheckID:   check.ID(),
					CheckName: check.Name(),
					Status:    results[offset].Status,
					At:        e.now(),
					Index:     e.config.EventIndexOffset + offset,
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
				Index:     e.config.EventIndexOffset + offset + index,
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
				Index:     e.config.EventIndexOffset + offset + index,
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
		return stoppedResult(check, started, context.Cause(ctx))
	}
	if e.config.SkipCheck != nil {
		if skipped, ok := e.config.SkipCheck(state, check); ok {
			if skipped.ID == "" {
				skipped.ID = check.ID()
			}
			if skipped.Name == "" {
				skipped.Name = check.Name()
			}
			return skipped.Complete(started, e.now())
		}
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
		cause := context.Cause(ctx)
		if errors.Is(cause, ErrAuxiliaryBudgetExhausted) {
			result.Status = model.StatusSkipped
			result.ErrorCode = ErrorAuxiliaryBudget
			result.Summary = "The auxiliary comparison stopped to preserve time for the actual HTTP route."
			result.Evidence = append(result.Evidence, model.Evidence{
				ID:      check.ID() + ".auxiliary_budget",
				Code:    ErrorAuxiliaryBudget,
				Message: "The reserved actual-route budget was preserved.",
			})
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.Status = model.StatusFailed
			result.ErrorCode = "OPERATION_TIMEOUT"
			result.Summary = "The diagnosis timeout elapsed."
		} else {
			result.Status = model.StatusCancelled
			result.ErrorCode = "OPERATION_CANCELLED"
			result.Summary = "The check was cancelled."
		}
	} else if checkCtx.Err() == context.DeadlineExceeded {
		result.Status = model.StatusFailed
		result.ErrorCode = ErrorCheckTimeout
		result.Summary = "The check exceeded its configured timeout."
		result.Evidence = ensureCheckTimeoutEvidence(
			result.Evidence,
			result.ID,
			result.Name,
			e.config.CheckTimeout,
			finished.Sub(started),
		)
	}
	if !result.Status.Valid() || result.Status == model.StatusPending || result.Status == model.StatusRunning {
		result.Status = model.StatusFailed
		if result.ErrorCode == "" {
			result.ErrorCode = "CHECK_INVALID_RESULT"
		}
	}
	return result.Complete(started, finished)
}

func ensureCheckTimeoutEvidence(
	evidence []model.Evidence,
	checkID string,
	checkName string,
	budget time.Duration,
	elapsed time.Duration,
) []model.Evidence {
	if elapsed < 0 {
		elapsed = 0
	}
	details := map[string]string{
		"stage":            checkID,
		"checkName":        checkName,
		"configuredBudget": budget.String(),
		"elapsed":          elapsed.String(),
	}
	for index := range evidence {
		if evidence[index].Code != ErrorCheckTimeout {
			continue
		}
		if evidence[index].ID == "" {
			evidence[index].ID = checkID + ".timeout"
		}
		if evidence[index].CheckID == "" {
			evidence[index].CheckID = checkID
		}
		if evidence[index].Message == "" {
			evidence[index].Message = "The diagnostic check exceeded its configured timeout."
		}
		if evidence[index].Details == nil {
			evidence[index].Details = make(map[string]string, len(details))
		}
		for key, value := range details {
			evidence[index].Details[key] = value
		}
		return evidence
	}
	return append(evidence, model.Evidence{
		ID:      checkID + ".timeout",
		CheckID: checkID,
		Code:    ErrorCheckTimeout,
		Message: "The diagnostic check exceeded its configured timeout.",
		Details: details,
	})
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
	if errors.Is(err, ErrAuxiliaryBudgetExhausted) {
		result.Status = model.StatusSkipped
		result.Summary = "The auxiliary comparison was not started so the actual HTTP route retained its reserved budget."
		result.ErrorCode = ErrorAuxiliaryBudget
		result.Evidence = []model.Evidence{{
			ID:      check.ID() + ".auxiliary_budget",
			CheckID: check.ID(),
			Code:    ErrorAuxiliaryBudget,
			Message: "The reserved actual-route budget was preserved.",
		}}
		return result
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
