package diagnostics

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	defaultEventQueueCapacity = 128
	defaultEventDrainTimeout  = 100 * time.Millisecond
)

// EventDeliveryError is returned when an event consumer panics. The diagnostic
// result remains available, while the adapter failure crosses the application
// boundary as a typed internal cause.
type EventDeliveryError struct {
	Panics uint64
}

func (e *EventDeliveryError) Error() string {
	return fmt.Sprintf("diagnostic event consumer panicked %d time(s)", e.Panics)
}

type eventDispatcher struct {
	sink model.EventSink
	now  func() time.Time

	queue chan model.CheckEvent
	done  chan struct{}

	mu        sync.Mutex
	dropped   uint64
	panics    uint64
	announced uint64
	closed    bool
	once      sync.Once
}

func newEventDispatcher(sink model.EventSink, now func() time.Time) *eventDispatcher {
	if sink == nil {
		return nil
	}
	dispatcher := &eventDispatcher{
		sink:  sink,
		now:   now,
		queue: make(chan model.CheckEvent, defaultEventQueueCapacity),
		done:  make(chan struct{}),
	}
	go dispatcher.run()
	return dispatcher
}

func (d *eventDispatcher) Sink() model.EventSink {
	if d == nil {
		return nil
	}
	return d.emit
}

func (d *eventDispatcher) emit(event model.CheckEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		d.dropped++
		return
	}
	select {
	case d.queue <- event:
	default:
		d.dropped++
	}
}

func (d *eventDispatcher) run() {
	defer close(d.done)
	for event := range d.queue {
		d.deliver(event)
		d.deliverOverflowNotice()
	}
	d.deliverOverflowNotice()
}

func (d *eventDispatcher) deliver(event model.CheckEvent) {
	defer func() {
		if recover() != nil {
			d.mu.Lock()
			d.panics++
			d.mu.Unlock()
		}
	}()
	d.sink(event)
}

func (d *eventDispatcher) deliverOverflowNotice() {
	d.mu.Lock()
	dropped := d.dropped
	if dropped == d.announced {
		d.mu.Unlock()
		return
	}
	d.announced = dropped
	d.mu.Unlock()
	d.deliver(model.CheckEvent{
		Type:          model.EventDeliveryOverflow,
		Status:        model.StatusWarning,
		At:            d.now(),
		DroppedEvents: dropped,
	})
}

func (d *eventDispatcher) close() (model.EventDeliveryStats, error) {
	if d == nil {
		return model.EventDeliveryStats{}, nil
	}
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.queue)
		d.mu.Unlock()
	})
	timedOut := false
	select {
	case <-d.done:
	case <-time.After(defaultEventDrainTimeout):
		timedOut = true
		d.mu.Lock()
		d.dropped += uint64(len(d.queue)) + 1
		d.mu.Unlock()
	}
	d.mu.Lock()
	stats := model.EventDeliveryStats{
		Dropped:        d.dropped,
		ConsumerPanics: d.panics,
		DrainTimedOut:  timedOut,
	}
	d.mu.Unlock()
	if stats.ConsumerPanics != 0 {
		return stats, &EventDeliveryError{Panics: stats.ConsumerPanics}
	}
	return stats, nil
}

func finishEventDelivery(
	dispatcher *eventDispatcher,
	diagnosis model.Diagnosis,
	diagnosisErr error,
) (model.Diagnosis, error) {
	stats, deliveryErr := dispatcher.close()
	if !stats.Empty() {
		diagnosis.EventDelivery = &stats
	}
	if diagnosisErr != nil && deliveryErr != nil {
		return diagnosis, errors.Join(diagnosisErr, deliveryErr)
	}
	if deliveryErr != nil {
		return diagnosis, deliveryErr
	}
	return diagnosis, diagnosisErr
}
