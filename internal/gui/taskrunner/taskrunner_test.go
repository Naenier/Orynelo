package taskrunner

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testTimeout = 3 * time.Second

type manualDispatcher struct {
	mu     sync.Mutex
	queue  []func()
	queued chan struct{}
}

func newManualDispatcher() *manualDispatcher {
	return &manualDispatcher{queued: make(chan struct{}, 1)}
}

func (dispatcher *manualDispatcher) dispatch(callback func()) {
	dispatcher.mu.Lock()
	dispatcher.queue = append(dispatcher.queue, callback)
	dispatcher.mu.Unlock()
	select {
	case dispatcher.queued <- struct{}{}:
	default:
	}
}

func (dispatcher *manualDispatcher) drain() int {
	count := 0
	for {
		dispatcher.mu.Lock()
		if len(dispatcher.queue) == 0 {
			dispatcher.mu.Unlock()
			return count
		}
		callbacks := dispatcher.queue
		dispatcher.queue = nil
		dispatcher.mu.Unlock()
		for _, callback := range callbacks {
			callback()
			count++
		}
	}
}

func (dispatcher *manualDispatcher) pending() int {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return len(dispatcher.queue)
}

type recorder[T any] struct {
	mu        sync.Mutex
	snapshots []Snapshot[T]
}

func (recorder *recorder[T]) observe(snapshot Snapshot[T]) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.snapshots = append(recorder.snapshots, snapshot)
}

func (recorder *recorder[T]) all() []Snapshot[T] {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Snapshot[T](nil), recorder.snapshots...)
}

func receive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for channel value")
		var zero T
		return zero
	}
}

func waitForDispatch(t *testing.T, dispatcher *manualDispatcher) {
	t.Helper()
	deadline := time.NewTimer(testTimeout)
	defer deadline.Stop()
	for dispatcher.pending() == 0 {
		select {
		case <-dispatcher.queued:
		case <-deadline.C:
			t.Fatal("timed out waiting for dispatched callback")
		}
	}
}

func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		runtime.Gosched()
	}
}

func TestNewRequiresSafeDispatcherAndValidReadLimit(t *testing.T) {
	t.Parallel()

	if _, err := New(context.Background(), nil, Options{}); !errors.Is(err, ErrNilDispatcher) {
		t.Fatalf("New(nil dispatcher) error = %v, want %v", err, ErrNilDispatcher)
	}
	if _, err := New(context.Background(), func(callback func()) { callback() }, Options{MaxConcurrentReads: -1}); !errors.Is(err, ErrInvalidReadLimit) {
		t.Fatalf("New(negative read limit) error = %v, want %v", err, ErrInvalidReadLimit)
	}
}

func TestAlreadyCancelledParentCreatesClosedRunner(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	runner, err := New(parent, func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := NewScope[int](runner, "closed", nil); !errors.Is(err, ErrRunnerClosed) {
		t.Fatalf("NewScope() error = %v, want %v", err, ErrRunnerClosed)
	}
	runner.Wait()
}

func TestScopeLifecycleIsDeliveredOnlyThroughDispatcher(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		runner.Close()
		runner.Wait()
	})
	recorded := &recorder[string]{}
	scope, err := NewScope(runner, "history", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}

	if got := recorded.all(); len(got) != 0 {
		t.Fatalf("observer ran outside dispatcher: %#v", got)
	}
	if snapshot := scope.Snapshot(); snapshot.State != StateIdle || snapshot.Scope != "history" {
		t.Fatalf("initial snapshot = %#v, want history/idle", snapshot)
	}
	dispatcher.drain()
	if got := recorded.all(); len(got) != 1 || got[0].State != StateIdle {
		t.Fatalf("dispatched initial snapshots = %#v, want idle", got)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	id, err := scope.StartRead(func(context.Context) (string, error) {
		close(started)
		<-release
		return "loaded", nil
	})
	if err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	if id != 1 {
		t.Fatalf("operation ID = %d, want 1", id)
	}
	receive(t, started)
	if got := recorded.all(); len(got) != 1 {
		t.Fatalf("loading bypassed dispatcher: %#v", got)
	}
	dispatcher.drain()
	if got := recorded.all(); len(got) != 2 || got[1].State != StateLoading || got[1].Class != ReadOperation {
		t.Fatalf("loading snapshots = %#v", got)
	}

	close(release)
	runner.Wait()
	waitForDispatch(t, dispatcher)
	if snapshot := scope.Snapshot(); snapshot.State != StateSuccess || snapshot.Value != "loaded" {
		t.Fatalf("completed snapshot = %#v", snapshot)
	}
	if got := recorded.all(); len(got) != 2 {
		t.Fatalf("success bypassed dispatcher: %#v", got)
	}
	dispatcher.drain()
	got := recorded.all()
	if len(got) != 3 || got[2].State != StateSuccess || got[2].Value != "loaded" || got[2].OperationID != id {
		t.Fatalf("completed snapshots = %#v", got)
	}
}

func TestOperationTaskReceivesAcceptedID(t *testing.T) {
	t.Parallel()

	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope, err := NewScope[int](runner, "stream", nil)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	received := make(chan OperationID, 1)
	contexts := make(chan context.Context, 1)
	accepted, err := scope.StartReadOperation(func(ctx context.Context, id OperationID) (int, error) {
		contexts <- ctx
		received <- id
		return 1, nil
	})
	if err != nil {
		t.Fatalf("StartReadOperation() error = %v", err)
	}
	if got := receive(t, received); got != accepted || got == 0 {
		t.Fatalf("task operation ID = %d, accepted ID = %d", got, accepted)
	}
	operationContext := receive(t, contexts)
	runner.Wait()
	select {
	case <-operationContext.Done():
	case <-time.After(testTimeout):
		t.Fatal("completed operation context was not released")
	}
	runner.Close()
}

func TestLoadingDeliveryIsQueuedBeforeOperationCanEmit(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var orderMu sync.Mutex
	order := make([]string, 0, 2)
	scope, err := NewScope(runner, "stream-order", func(snapshot Snapshot[int]) {
		if snapshot.State == StateLoading {
			orderMu.Lock()
			order = append(order, "loading")
			orderMu.Unlock()
		}
	})
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	dispatcher.drain()
	eventQueued := make(chan struct{})
	release := make(chan struct{})
	if _, err := scope.StartReadOperation(func(context.Context, OperationID) (int, error) {
		dispatcher.dispatch(func() {
			orderMu.Lock()
			order = append(order, "event")
			orderMu.Unlock()
		})
		close(eventQueued)
		<-release
		return 1, nil
	}); err != nil {
		t.Fatalf("StartReadOperation() error = %v", err)
	}
	receive(t, eventQueued)
	dispatcher.drain()
	orderMu.Lock()
	got := append([]string(nil), order...)
	orderMu.Unlock()
	if len(got) != 2 || got[0] != "loading" || got[1] != "event" {
		t.Fatalf("delivery order = %#v, want [loading event]", got)
	}
	close(release)
	runner.Wait()
	runner.Close()
}

func TestReplacementCancelsOldContextAndSuppressesStaleResponse(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{MaxConcurrentReads: 2})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recorded := &recorder[string]{}
	scope, err := NewScope(runner, "search", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	dispatcher.drain()

	firstStarted := make(chan context.Context, 1)
	firstRelease := make(chan struct{})
	firstID, err := scope.StartRead(func(ctx context.Context) (string, error) {
		firstStarted <- ctx
		<-firstRelease // Deliberately emulate a slow dependency that ignores cancellation.
		return "stale", nil
	})
	if err != nil {
		t.Fatalf("first StartRead() error = %v", err)
	}
	firstContext := receive(t, firstStarted)

	secondStarted := make(chan struct{})
	secondRelease := make(chan struct{})
	secondID, err := scope.StartRead(func(context.Context) (string, error) {
		close(secondStarted)
		<-secondRelease
		return "current", nil
	})
	if err != nil {
		t.Fatalf("second StartRead() error = %v", err)
	}
	receive(t, secondStarted)
	if firstID != 1 || secondID != 2 {
		t.Fatalf("operation IDs = %d, %d; want 1, 2", firstID, secondID)
	}
	select {
	case <-firstContext.Done():
	case <-time.After(testTimeout):
		t.Fatal("replacement did not cancel the old operation context")
	}

	// Complete the current request first, then let the stale request return.
	close(secondRelease)
	waitFor(t, func() bool { return scope.Snapshot().State != StateLoading }, "current operation did not finish")
	dispatcher.drain()
	close(firstRelease)
	runner.Wait()
	dispatcher.drain()

	snapshot := scope.Snapshot()
	if snapshot.OperationID != secondID || snapshot.State != StateSuccess || snapshot.Value != "current" {
		t.Fatalf("latest snapshot = %#v", snapshot)
	}
	for _, delivered := range recorded.all() {
		if delivered.OperationID == firstID && delivered.State != StateLoading {
			t.Fatalf("stale operation was delivered: %#v", delivered)
		}
		if delivered.Value == "stale" {
			t.Fatalf("stale value was delivered: %#v", delivered)
		}
	}
	runner.Close()
}

func TestCancelPublishesCancelledAndIgnoresLateReturn(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recorded := &recorder[int]{}
	scope, err := NewScope(runner, "report", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	dispatcher.drain()
	started := make(chan struct{})
	finished := make(chan struct{})
	_, err = scope.StartRead(func(ctx context.Context) (int, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return 42, nil // A dependency may return a value even after cancellation.
	})
	if err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	receive(t, started)
	dispatcher.drain()

	scope.Cancel()
	if snapshot := scope.Snapshot(); snapshot.State != StateCancelled || !errors.Is(snapshot.Err, context.Canceled) {
		t.Fatalf("cancelled snapshot = %#v", snapshot)
	}
	dispatcher.drain()
	receive(t, finished)
	runner.Wait()
	dispatcher.drain()

	got := recorded.all()
	if len(got) != 3 {
		t.Fatalf("snapshots = %#v, want idle/loading/cancelled", got)
	}
	if got[2].State != StateCancelled || got[2].Value != 0 {
		t.Fatalf("final delivered snapshot = %#v, want cancelled without late value", got[2])
	}
	runner.Close()
}

func TestInvalidateSuppressesQueuedCancellationDelivery(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recorded := &recorder[int]{}
	scope, err := NewScope(runner, "replace-ui", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	dispatcher.drain()
	started := make(chan struct{})
	if _, err := scope.StartRead(func(ctx context.Context) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	}); err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	receive(t, started)
	dispatcher.drain()
	scope.Cancel()
	if dispatcher.pending() == 0 {
		t.Fatal("cancelled delivery was not queued")
	}
	scope.Invalidate()
	dispatcher.drain()
	runner.Wait()
	runner.Close()

	for _, snapshot := range recorded.all() {
		if snapshot.State == StateCancelled {
			t.Fatalf("invalidated cancellation was delivered: %#v", snapshot)
		}
	}
	if snapshot := scope.Snapshot(); snapshot.State != StateIdle {
		t.Fatalf("invalidated scope state = %s, want idle", snapshot.State)
	}
}

func TestCloseCancelsAllScopesAndSuppressesPostCloseDelivery(t *testing.T) {
	t.Parallel()

	dispatcher := newManualDispatcher()
	runner, err := New(context.Background(), dispatcher.dispatch, Options{MaxConcurrentReads: 2})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recorded := &recorder[string]{}
	first, err := NewScope(runner, "history", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope(history) error = %v", err)
	}
	second, err := NewScope(runner, "profiles", recorded.observe)
	if err != nil {
		t.Fatalf("NewScope(profiles) error = %v", err)
	}
	dispatcher.drain()
	started := make(chan struct{}, 2)
	finished := make(chan struct{}, 2)
	task := func(ctx context.Context) (string, error) {
		started <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return "late", nil
	}
	if _, err := first.StartRead(task); err != nil {
		t.Fatalf("history StartRead() error = %v", err)
	}
	if _, err := second.StartRead(task); err != nil {
		t.Fatalf("profiles StartRead() error = %v", err)
	}
	receive(t, started)
	receive(t, started)
	dispatcher.drain()
	deliveredBeforeClose := len(recorded.all())

	runner.Close()
	receive(t, finished)
	receive(t, finished)
	runner.Wait()
	dispatcher.drain()

	if first.Snapshot().State != StateCancelled || second.Snapshot().State != StateCancelled {
		t.Fatalf("states after Close = %s, %s; want cancelled", first.Snapshot().State, second.Snapshot().State)
	}
	if got := len(recorded.all()); got != deliveredBeforeClose {
		t.Fatalf("callbacks delivered after Close: before=%d after=%d", deliveredBeforeClose, got)
	}
	if _, err := first.StartRead(task); !errors.Is(err, ErrScopeClosed) {
		t.Fatalf("StartRead() after Close error = %v, want %v", err, ErrScopeClosed)
	}
}

func TestParentContextEndsRunnerLifetime(t *testing.T) {
	t.Parallel()

	parent, cancelParent := context.WithCancel(context.Background())
	runner, err := New(parent, func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope, err := NewScope[int](runner, "lifetime", nil)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	started := make(chan struct{})
	finished := make(chan struct{})
	if _, err := scope.StartRead(func(ctx context.Context) (int, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return 0, ctx.Err()
	}); err != nil {
		t.Fatalf("StartRead() error = %v", err)
	}
	receive(t, started)
	cancelParent()
	receive(t, finished)
	runner.Wait()
	waitFor(t, func() bool {
		runner.mu.Lock()
		defer runner.mu.Unlock()
		return runner.closed
	}, "parent cancellation did not close the runner scope")
	if _, startErr := scope.StartRead(func(context.Context) (int, error) { return 0, nil }); !errors.Is(startErr, ErrScopeClosed) {
		t.Fatalf("StartRead() after parent cancellation error = %v, want %v", startErr, ErrScopeClosed)
	}
	if snapshot := scope.Snapshot(); snapshot.State != StateCancelled {
		t.Fatalf("state after parent cancellation = %s, want cancelled", snapshot.State)
	}
}

func TestCloseDrainsQueuedMutationsWithoutStartingThem(t *testing.T) {
	t.Parallel()

	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := make(chan int, 3)
	scopes := make([]*Scope[int], 0, 3)
	for index := 1; index <= 3; index++ {
		scope, scopeErr := NewScope[int](runner, "shutdown-mutation", nil)
		if scopeErr != nil {
			t.Fatalf("NewScope() error = %v", scopeErr)
		}
		scopes = append(scopes, scope)
		value := index
		if _, startErr := scope.StartMutation(func(ctx context.Context) (int, error) {
			started <- value
			<-ctx.Done()
			return 0, ctx.Err()
		}); startErr != nil {
			t.Fatalf("StartMutation(%d) error = %v", index, startErr)
		}
	}
	if got := receive(t, started); got != 1 {
		t.Fatalf("first mutation = %d, want 1", got)
	}
	runner.Close()
	runner.Wait()
	select {
	case got := <-started:
		t.Fatalf("queued mutation %d started after Close", got)
	default:
	}
	for index, scope := range scopes {
		if state := scope.Snapshot().State; state != StateCancelled {
			t.Errorf("scope %d state = %s, want cancelled", index+1, state)
		}
	}
}

func TestMutationsExecuteSeriallyInAcceptanceOrder(t *testing.T) {
	t.Parallel()

	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := make(chan int, 3)
	release := make(chan struct{})
	for index := 1; index <= 3; index++ {
		scope, scopeErr := NewScope[int](runner, "mutation", nil)
		if scopeErr != nil {
			t.Fatalf("NewScope() error = %v", scopeErr)
		}
		value := index
		if _, startErr := scope.StartMutation(func(context.Context) (int, error) {
			started <- value
			<-release
			return value, nil
		}); startErr != nil {
			t.Fatalf("StartMutation(%d) error = %v", index, startErr)
		}
	}

	for want := 1; want <= 3; want++ {
		if got := receive(t, started); got != want {
			t.Fatalf("mutation start order: got %d, want %d", got, want)
		}
		select {
		case unexpected := <-started:
			t.Fatalf("mutation %d overlapped mutation %d", unexpected, want)
		default:
		}
		release <- struct{}{}
	}
	runner.Wait()
	runner.Close()
}

func TestMutationWorkerSurvivesObserverPanic(t *testing.T) {
	t.Parallel()

	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer runner.Close()

	first, err := NewScope[int](runner, "panicking-observer", func(snapshot Snapshot[int]) {
		if snapshot.State == StateSuccess {
			panic("broken GUI observer")
		}
	})
	if err != nil {
		t.Fatalf("NewScope(first) error = %v", err)
	}
	second, err := NewScope[int](runner, "following-mutation", nil)
	if err != nil {
		t.Fatalf("NewScope(second) error = %v", err)
	}

	if _, err := first.StartMutation(func(context.Context) (int, error) {
		return 1, nil
	}); err != nil {
		t.Fatalf("first StartMutation() error = %v", err)
	}
	if _, err := second.StartMutation(func(context.Context) (int, error) {
		return 2, nil
	}); err != nil {
		t.Fatalf("second StartMutation() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		runner.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mutation worker stopped after an observer panic")
	}

	if snapshot := first.Snapshot(); snapshot.State != StateSuccess {
		t.Fatalf("first state = %s, want success", snapshot.State)
	}
	if snapshot := second.Snapshot(); snapshot.State != StateSuccess || snapshot.Value != 2 {
		t.Fatalf("second snapshot = %+v, want successful value 2", snapshot)
	}
}

func TestReadsUseBoundedConcurrency(t *testing.T) {
	t.Parallel()

	const (
		readLimit = 2
		readCount = 5
	)
	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{MaxConcurrentReads: readLimit})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := make(chan int, readCount)
	releases := make([]chan struct{}, readCount)
	var active atomic.Int32
	var maximum atomic.Int32
	for index := range readCount {
		releases[index] = make(chan struct{})
		scope, scopeErr := NewScope[int](runner, "read", nil)
		if scopeErr != nil {
			t.Fatalf("NewScope() error = %v", scopeErr)
		}
		value := index
		if _, startErr := scope.StartRead(func(context.Context) (int, error) {
			current := active.Add(1)
			for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
			}
			started <- value
			<-releases[value]
			active.Add(-1)
			return value, nil
		}); startErr != nil {
			t.Fatalf("StartRead(%d) error = %v", index, startErr)
		}
	}

	first := receive(t, started)
	second := receive(t, started)
	select {
	case third := <-started:
		t.Fatalf("read %d exceeded concurrency limit while %d and %d were blocked", third, first, second)
	case <-time.After(50 * time.Millisecond):
	}

	close(releases[first])
	third := receive(t, started)
	close(releases[second])
	fourth := receive(t, started)
	close(releases[third])
	fifth := receive(t, started)
	close(releases[fourth])
	close(releases[fifth])
	runner.Wait()
	runner.Close()

	if got := maximum.Load(); got != readLimit {
		t.Fatalf("maximum concurrent reads = %d, want %d", got, readLimit)
	}
}

func TestTaskErrorsPanicsAndCancellationHaveStableStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		task      Task[int]
		wantState State
		wantError string
	}{
		{
			name: "error",
			task: func(context.Context) (int, error) {
				return 0, errors.New("read failed")
			},
			wantState: StateError,
			wantError: "read failed",
		},
		{
			name: "panic",
			task: func(context.Context) (int, error) {
				panic("broken dependency")
			},
			wantState: StateError,
			wantError: "taskrunner: task panicked: broken dependency",
		},
		{
			name: "cancelled error",
			task: func(context.Context) (int, error) {
				return 0, context.Canceled
			},
			wantState: StateCancelled,
			wantError: context.Canceled.Error(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			scope, err := NewScope[int](runner, "errors", nil)
			if err != nil {
				t.Fatalf("NewScope() error = %v", err)
			}
			if _, err := scope.StartRead(test.task); err != nil {
				t.Fatalf("StartRead() error = %v", err)
			}
			runner.Wait()
			runner.Close()
			snapshot := scope.Snapshot()
			if snapshot.State != test.wantState {
				t.Fatalf("state = %s, want %s", snapshot.State, test.wantState)
			}
			if snapshot.Err == nil || snapshot.Err.Error() != test.wantError {
				t.Fatalf("error = %v, want %q", snapshot.Err, test.wantError)
			}
		})
	}
}

func TestStateValidationAndInputErrors(t *testing.T) {
	t.Parallel()

	for _, state := range []State{StateIdle, StateLoading, StateSuccess, StateError, StateCancelled} {
		if !state.Valid() {
			t.Errorf("State(%q).Valid() = false", state)
		}
	}
	if State("unknown").Valid() {
		t.Fatal("unknown State.Valid() = true")
	}
	if _, err := NewScope[int](nil, "nil", nil); !errors.Is(err, ErrNilRunner) {
		t.Fatalf("NewScope(nil) error = %v, want %v", err, ErrNilRunner)
	}

	runner, err := New(context.Background(), func(callback func()) { callback() }, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope, err := NewScope[int](runner, "input", nil)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	if _, err := scope.StartRead(nil); !errors.Is(err, ErrNilTask) {
		t.Fatalf("StartRead(nil) error = %v, want %v", err, ErrNilTask)
	}
	scope.Close()
	if _, err := scope.StartMutation(func(context.Context) (int, error) { return 0, nil }); !errors.Is(err, ErrScopeClosed) {
		t.Fatalf("StartMutation() after scope Close error = %v, want %v", err, ErrScopeClosed)
	}
	runner.Close()
	runner.Wait()
}
