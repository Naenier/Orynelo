// Package taskrunner coordinates asynchronous GUI work without depending on a
// particular UI toolkit. Callers provide a dispatcher such as fyne.Do; every
// observer invocation is routed through that dispatcher.
package taskrunner

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const DefaultMaxConcurrentReads = 4

var (
	ErrNilDispatcher         = errors.New("taskrunner: dispatcher is nil")
	ErrInvalidReadLimit      = errors.New("taskrunner: maximum concurrent reads must not be negative")
	ErrNilRunner             = errors.New("taskrunner: runner is nil")
	ErrRunnerClosed          = errors.New("taskrunner: runner is closed")
	ErrScopeClosed           = errors.New("taskrunner: scope is closed")
	ErrNilTask               = errors.New("taskrunner: task is nil")
	ErrInvalidOperationClass = errors.New("taskrunner: invalid operation class")
)

// Dispatcher schedules a callback on the GUI thread. In production Fyne code,
// pass fyne.Do directly.
type Dispatcher func(func())

// Options controls the amount of background work allowed by a Runner.
type Options struct {
	// MaxConcurrentReads limits read-only tasks that may execute at once. Zero
	// selects DefaultMaxConcurrentReads. Mutations are always executed one at a
	// time, in the order in which the runner accepts them.
	MaxConcurrentReads int
}

// State is the lifecycle state of the latest operation in a scope.
type State string

const (
	StateIdle      State = "idle"
	StateLoading   State = "loading"
	StateSuccess   State = "success"
	StateError     State = "error"
	StateCancelled State = "cancelled"
)

// Valid reports whether state is part of the task-runner state contract.
func (state State) Valid() bool {
	switch state {
	case StateIdle, StateLoading, StateSuccess, StateError, StateCancelled:
		return true
	default:
		return false
	}
}

// OperationClass identifies whether a task is read-only or mutating.
type OperationClass uint8

const (
	ReadOperation OperationClass = iota + 1
	MutationOperation
)

func (class OperationClass) valid() bool {
	return class == ReadOperation || class == MutationOperation
}

// OperationID is monotonically increasing within one Scope. An ID is never
// reused for that scope, which lets consumers correlate state transitions.
type OperationID uint64

// Snapshot is an immutable view of the latest operation state. Values returned
// by tasks should not be mutated after the task returns.
type Snapshot[T any] struct {
	Scope       string
	OperationID OperationID
	Class       OperationClass
	State       State
	Value       T
	Err         error
}

// Task performs background work. The supplied context is cancelled when the
// scope starts a replacement operation, Scope.Cancel is called, or the Runner
// is closed.
type Task[T any] func(context.Context) (T, error)

// OperationTask is a Task that also receives its operation ID. It is useful
// for streaming callbacks that must be correlated with the current scope
// operation before they are dispatched to the GUI.
type OperationTask[T any] func(context.Context, OperationID) (T, error)

// Observer receives state transitions on the injected Dispatcher.
type Observer[T any] func(Snapshot[T])

type scopeLifecycle interface {
	runnerClosed()
}

// Runner owns the application-lifetime context and shared execution limits.
// Close cancels all registered scopes and prevents new work. Close does not
// wait for tasks that ignore cancellation; use Wait when shutdown must wait.
type Runner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	dispatch Dispatcher

	readSlots chan struct{}

	mu            sync.Mutex
	closed        bool
	scopes        map[scopeLifecycle]struct{}
	mutationQueue []scheduledTask
	mutationReady chan struct{}

	tasks sync.WaitGroup
}

type scheduledTask struct {
	ctx      context.Context
	run      func()
	panicked func(any)
}

// New creates a task runner rooted in parent. A nil parent is treated as
// context.Background. A nil dispatcher is rejected so UI delivery cannot
// accidentally bypass the GUI thread.
func New(parent context.Context, dispatcher Dispatcher, options Options) (*Runner, error) {
	if dispatcher == nil {
		return nil, ErrNilDispatcher
	}
	if options.MaxConcurrentReads < 0 {
		return nil, ErrInvalidReadLimit
	}
	if options.MaxConcurrentReads == 0 {
		options.MaxConcurrentReads = DefaultMaxConcurrentReads
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{
		ctx:           ctx,
		cancel:        cancel,
		dispatch:      dispatcher,
		readSlots:     make(chan struct{}, options.MaxConcurrentReads),
		scopes:        make(map[scopeLifecycle]struct{}),
		mutationReady: make(chan struct{}, 1),
	}
	go runner.runMutations()
	go func() {
		<-ctx.Done()
		runner.Close()
	}()
	if ctx.Err() != nil {
		runner.Close()
	}
	return runner, nil
}

// Context returns the application-lifetime context owned by the runner.
func (runner *Runner) Context() context.Context {
	if runner == nil {
		return context.Background()
	}
	return runner.ctx
}

// Close cancels all active and queued operations. It is safe to call multiple
// times and from multiple goroutines.
func (runner *Runner) Close() {
	if runner == nil {
		return
	}

	runner.mu.Lock()
	if runner.closed {
		runner.mu.Unlock()
		return
	}
	runner.closed = true
	runner.cancel()
	scopes := make([]scopeLifecycle, 0, len(runner.scopes))
	for scope := range runner.scopes {
		scopes = append(scopes, scope)
	}
	runner.scopes = nil
	runner.mu.Unlock()

	for _, scope := range scopes {
		scope.runnerClosed()
	}
	runner.signalMutationWorker()
}

// Wait waits for all operations accepted before the call to finish. Callers
// should stop starting operations (normally by calling Close) before using
// Wait as a shutdown barrier.
func (runner *Runner) Wait() {
	if runner == nil {
		return
	}
	runner.tasks.Wait()
}

func (runner *Runner) register(scope scopeLifecycle) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.closed {
		return ErrRunnerClosed
	}
	runner.scopes[scope] = struct{}{}
	return nil
}

func (runner *Runner) unregister(scope scopeLifecycle) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	delete(runner.scopes, scope)
}

func (runner *Runner) schedule(class OperationClass, task scheduledTask) error {
	if !class.valid() {
		return ErrInvalidOperationClass
	}

	runner.mu.Lock()
	if runner.closed {
		runner.mu.Unlock()
		return ErrRunnerClosed
	}
	runner.tasks.Add(1)
	if class == MutationOperation {
		runner.mutationQueue = append(runner.mutationQueue, task)
		runner.mu.Unlock()
		runner.signalMutationWorker()
		return nil
	}
	runner.mu.Unlock()

	go func() {
		defer runner.tasks.Done()
		select {
		case runner.readSlots <- struct{}{}:
			defer func() { <-runner.readSlots }()
			runScheduled(task)
		case <-task.ctx.Done():
			runScheduled(task)
		}
	}()
	return nil
}

func (runner *Runner) signalMutationWorker() {
	select {
	case runner.mutationReady <- struct{}{}:
	default:
	}
}

func (runner *Runner) runMutations() {
	for range runner.mutationReady {
		for {
			runner.mu.Lock()
			if len(runner.mutationQueue) == 0 {
				closed := runner.closed
				runner.mu.Unlock()
				if closed {
					return
				}
				break
			}
			task := runner.mutationQueue[0]
			runner.mutationQueue[0] = scheduledTask{}
			runner.mutationQueue = runner.mutationQueue[1:]
			runner.mu.Unlock()

			func() {
				defer runner.tasks.Done()
				runScheduled(task)
			}()
		}
	}
}

func runScheduled(task scheduledTask) {
	defer func() {
		if recovered := recover(); recovered != nil && task.panicked != nil {
			task.panicked(recovered)
		}
	}()
	task.run()
}

// Scope represents one independently replaceable GUI operation stream, such as
// a history or profiles screen. Starting new work cancels the previous current
// operation and suppresses every late transition from that operation.
type Scope[T any] struct {
	runner   *Runner
	name     string
	observer Observer[T]

	mu       sync.Mutex
	closed   bool
	nextID   OperationID
	revision uint64
	snapshot Snapshot[T]
	cancel   context.CancelFunc
}

// NewScope registers an independently replaceable operation scope. When an
// observer is supplied, its initial idle snapshot is also dispatched.
func NewScope[T any](runner *Runner, name string, observer Observer[T]) (*Scope[T], error) {
	if runner == nil {
		return nil, ErrNilRunner
	}
	scope := &Scope[T]{
		runner:   runner,
		name:     name,
		observer: observer,
		revision: 1,
		snapshot: Snapshot[T]{
			Scope: name,
			State: StateIdle,
		},
	}
	if err := runner.register(scope); err != nil {
		return nil, err
	}
	scope.deliver(scope.snapshot, scope.revision)
	return scope, nil
}

// Snapshot returns the latest state without invoking the dispatcher.
func (scope *Scope[T]) Snapshot() Snapshot[T] {
	if scope == nil {
		return Snapshot[T]{State: StateIdle}
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	return scope.snapshot
}

// StartRead replaces the current operation with a bounded-concurrency read.
func (scope *Scope[T]) StartRead(task Task[T]) (OperationID, error) {
	if task == nil {
		return 0, ErrNilTask
	}
	return scope.start(ReadOperation, func(ctx context.Context, _ OperationID) (T, error) {
		return task(ctx)
	})
}

// StartReadOperation is StartRead with access to the accepted operation ID.
func (scope *Scope[T]) StartReadOperation(task OperationTask[T]) (OperationID, error) {
	return scope.start(ReadOperation, task)
}

// StartMutation replaces the current operation with a mutation. All mutations
// handled by the same Runner are executed serially in acceptance order.
func (scope *Scope[T]) StartMutation(task Task[T]) (OperationID, error) {
	if task == nil {
		return 0, ErrNilTask
	}
	return scope.start(MutationOperation, func(ctx context.Context, _ OperationID) (T, error) {
		return task(ctx)
	})
}

// StartMutationOperation is StartMutation with access to the accepted
// operation ID.
func (scope *Scope[T]) StartMutationOperation(task OperationTask[T]) (OperationID, error) {
	return scope.start(MutationOperation, task)
}

func (scope *Scope[T]) start(class OperationClass, task OperationTask[T]) (OperationID, error) {
	if task == nil {
		return 0, ErrNilTask
	}
	if !class.valid() {
		return 0, ErrInvalidOperationClass
	}

	scope.mu.Lock()
	if scope.closed {
		scope.mu.Unlock()
		return 0, ErrScopeClosed
	}
	if scope.cancel != nil {
		scope.cancel()
	}
	scope.nextID++
	if scope.nextID == 0 {
		scope.nextID++
	}
	id := scope.nextID
	ctx, cancel := context.WithCancel(scope.runner.ctx)
	scope.cancel = cancel
	scope.revision++
	revision := scope.revision
	var zero T
	snapshot := Snapshot[T]{
		Scope:       scope.name,
		OperationID: id,
		Class:       class,
		State:       StateLoading,
		Value:       zero,
	}
	scope.snapshot = snapshot
	startGate := make(chan struct{})

	scheduled := scheduledTask{
		ctx: ctx,
		run: func() {
			<-startGate
			if err := ctx.Err(); err != nil {
				scope.finish(id, ctx, zero, err)
				return
			}
			value, err := invoke(ctx, id, task)
			scope.finish(id, ctx, value, err)
		},
		panicked: func(recovered any) {
			scope.finish(
				id,
				ctx,
				zero,
				fmt.Errorf("taskrunner: scheduled operation panicked: %v", recovered),
			)
		},
	}
	if err := scope.runner.schedule(class, scheduled); err != nil {
		cancel()
		scope.cancel = nil
		scope.closed = errors.Is(err, ErrRunnerClosed)
		scope.revision++
		scope.snapshot.State = StateCancelled
		scope.snapshot.Err = context.Canceled
		scope.mu.Unlock()
		return 0, err
	}
	scope.mu.Unlock()

	func() {
		defer close(startGate)
		scope.deliver(snapshot, revision)
	}()
	return id, nil
}

func invoke[T any](
	ctx context.Context,
	id OperationID,
	task OperationTask[T],
) (value T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("taskrunner: task panicked: %v", recovered)
		}
	}()
	return task(ctx, id)
}

func (scope *Scope[T]) finish(id OperationID, ctx context.Context, value T, err error) {
	scope.mu.Lock()
	if scope.closed || scope.snapshot.OperationID != id || scope.snapshot.State != StateLoading {
		scope.mu.Unlock()
		return
	}

	state := StateSuccess
	finalErr := err
	if ctxErr := ctx.Err(); ctxErr != nil {
		state = StateCancelled
		if finalErr == nil {
			finalErr = ctxErr
		}
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		state = StateCancelled
	} else if err != nil {
		state = StateError
	}

	cancel := scope.cancel
	scope.cancel = nil
	scope.revision++
	revision := scope.revision
	scope.snapshot.State = state
	scope.snapshot.Value = value
	scope.snapshot.Err = finalErr
	snapshot := scope.snapshot
	scope.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	scope.deliver(snapshot, revision)
}

// Cancel cancels the current operation and immediately publishes a cancelled
// state. A later task return for that operation is ignored.
func (scope *Scope[T]) Cancel() {
	if scope == nil {
		return
	}
	scope.mu.Lock()
	if scope.closed || scope.snapshot.State != StateLoading {
		scope.mu.Unlock()
		return
	}
	if scope.cancel != nil {
		scope.cancel()
		scope.cancel = nil
	}
	scope.revision++
	revision := scope.revision
	scope.snapshot.State = StateCancelled
	scope.snapshot.Err = context.Canceled
	snapshot := scope.snapshot
	scope.mu.Unlock()

	scope.deliver(snapshot, revision)
}

// Invalidate cancels the current operation and advances the scope to a fresh
// idle generation without observer delivery. Use it when another UI state is
// about to replace the task result (for example, opening an already-loaded
// history item). Pending callbacks from the previous generation become stale.
func (scope *Scope[T]) Invalidate() OperationID {
	if scope == nil {
		return 0
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.closed {
		return 0
	}
	if scope.cancel != nil {
		scope.cancel()
		scope.cancel = nil
	}
	scope.nextID++
	if scope.nextID == 0 {
		scope.nextID++
	}
	scope.revision++
	var zero T
	scope.snapshot = Snapshot[T]{
		Scope:       scope.name,
		OperationID: scope.nextID,
		State:       StateIdle,
		Value:       zero,
	}
	return scope.nextID
}

// Close permanently closes the scope, cancels its active operation, and
// suppresses all future observer delivery for it.
func (scope *Scope[T]) Close() {
	if scope == nil {
		return
	}
	scope.close()
	scope.runner.unregister(scope)
}

func (scope *Scope[T]) runnerClosed() {
	scope.close()
}

func (scope *Scope[T]) close() {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.closed {
		return
	}
	scope.closed = true
	if scope.cancel != nil {
		scope.cancel()
		scope.cancel = nil
	}
	if scope.snapshot.State == StateLoading {
		scope.revision++
		scope.snapshot.State = StateCancelled
		scope.snapshot.Err = context.Canceled
	}
}

func (scope *Scope[T]) deliver(snapshot Snapshot[T], revision uint64) {
	if scope.observer == nil {
		return
	}
	scope.runner.dispatch(func() {
		scope.runner.mu.Lock()
		runnerClosed := scope.runner.closed
		scope.runner.mu.Unlock()
		if runnerClosed {
			return
		}

		scope.mu.Lock()
		current := !scope.closed && scope.revision == revision
		observer := scope.observer
		scope.mu.Unlock()
		if current {
			observer(snapshot)
		}
	})
}
