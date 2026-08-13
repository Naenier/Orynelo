package application

import (
	"context"
	"fmt"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

// AdapterOperationTimeout is the maximum cooperative duration granted to a
// local application adapter when its caller has no earlier deadline.
const AdapterOperationTimeout = 5 * time.Second

// AdapterPanicError identifies a recovered infrastructure panic without
// exposing the panic value across the application boundary.
type AdapterPanicError struct {
	Adapter   string
	Operation string
}

func (e *AdapterPanicError) Error() string {
	return fmt.Sprintf("%s adapter panicked during %s", e.Adapter, e.Operation)
}

func callAdapter[T any](
	ctx context.Context,
	adapter string,
	operation string,
	call func(context.Context) (T, error),
) (result T, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, AdapterOperationTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = &AdapterPanicError{Adapter: adapter, Operation: operation}
		}
	}()
	result, err = call(bounded)
	if err == nil && bounded.Err() != nil {
		err = bounded.Err()
	}
	return result, err
}

func callAdapterError(
	ctx context.Context,
	adapter string,
	operation string,
	call func(context.Context) error,
) error {
	_, err := callAdapter(ctx, adapter, operation, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, call(ctx)
	})
	return err
}

type guardedPersistence struct {
	next Persistence
}

func guardPersistence(next Persistence) Persistence {
	if next == nil {
		return nil
	}
	return &guardedPersistence{next: next}
}

func (p *guardedPersistence) SaveDiagnosis(ctx context.Context, value model.Diagnosis, limit int) error {
	return callAdapterError(ctx, "persistence", "save-diagnosis", func(ctx context.Context) error {
		return p.next.SaveDiagnosis(ctx, value, limit)
	})
}

func (p *guardedPersistence) GetDiagnosis(ctx context.Context, id string) (model.Diagnosis, error) {
	return callAdapter(ctx, "persistence", "get-diagnosis", func(ctx context.Context) (model.Diagnosis, error) {
		return p.next.GetDiagnosis(ctx, id)
	})
}

func (p *guardedPersistence) ListHistory(ctx context.Context, query model.HistoryQuery) ([]model.HistoryEntry, error) {
	return callAdapter(ctx, "persistence", "list-history", func(ctx context.Context) ([]model.HistoryEntry, error) {
		return p.next.ListHistory(ctx, query)
	})
}

func (p *guardedPersistence) DeleteDiagnosis(ctx context.Context, id string) error {
	return callAdapterError(ctx, "persistence", "delete-diagnosis", func(ctx context.Context) error {
		return p.next.DeleteDiagnosis(ctx, id)
	})
}

func (p *guardedPersistence) ClearHistory(ctx context.Context) error {
	return callAdapterError(ctx, "persistence", "clear-history", p.next.ClearHistory)
}

func (p *guardedPersistence) ListProfiles(ctx context.Context) ([]model.Profile, error) {
	return callAdapter(ctx, "persistence", "list-profiles", p.next.ListProfiles)
}

func (p *guardedPersistence) CreateProfile(ctx context.Context, profile model.Profile) (model.Profile, error) {
	return callAdapter(ctx, "persistence", "create-profile", func(ctx context.Context) (model.Profile, error) {
		return p.next.CreateProfile(ctx, profile)
	})
}

func (p *guardedPersistence) UpdateProfile(ctx context.Context, profile model.Profile) (model.Profile, error) {
	return callAdapter(ctx, "persistence", "update-profile", func(ctx context.Context) (model.Profile, error) {
		return p.next.UpdateProfile(ctx, profile)
	})
}

func (p *guardedPersistence) DeleteProfile(ctx context.Context, id int64) error {
	return callAdapterError(ctx, "persistence", "delete-profile", func(ctx context.Context) error {
		return p.next.DeleteProfile(ctx, id)
	})
}

func (p *guardedPersistence) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = &AdapterPanicError{Adapter: "persistence", Operation: "close"}
		}
	}()
	return p.next.Close()
}
