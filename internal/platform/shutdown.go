package platform

import (
	"context"
	"os"
	"os/signal"
	"sync"
)

// NotifyShutdownContext cancels on the first termination signal and invokes
// force on the second. Adapters should use the first cancellation to release
// resources cooperatively; force is the documented escape hatch for a blocked
// platform syscall.
func NotifyShutdownContext(
	parent context.Context,
	force func(),
	signals ...os.Signal,
) (context.Context, func()) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	events := make(chan os.Signal, 2)
	stopped := make(chan struct{})
	signal.Notify(events, signals...)
	go func() {
		select {
		case <-events:
			cancel()
		case <-ctx.Done():
			return
		case <-stopped:
			return
		}
		select {
		case <-events:
			if force != nil {
				force()
			}
		case <-stopped:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(events)
			close(stopped)
			cancel()
		})
	}
}
