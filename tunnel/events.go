package tunnel

import (
	"sync"
	"sync/atomic"
)

// eventBus decouples event production (hot receive/send paths) from
// embedder-supplied handlers. Producers never block and never panic on slow
// consumers: when the queue is full the event is DROPPED and counted —
// handlers must therefore treat events as notifications, not as a reliable
// stream (the Stats counters remain the authoritative record).
type eventBus[T any] struct {
	ch   chan T
	stop chan struct{}
	// dropped MUST be atomic.Uint64, not bare uint64: the compiler 8-byte
	// aligns that type even on 32-bit platforms, where an unaligned uint64
	// makes every sync/atomic op panic. See alignment.go.
	dropped atomic.Uint64 // events discarded because the queue was full
	stopped atomic.Bool
	wg      sync.WaitGroup
	// started guarantees exactly one consumer goroutine for the bus's lifetime.
	started sync.Once
	// handler is hot-swapped on every SetEventHandler; the consumer reads it
	// atomically so swapping never starts a second goroutine or strands the
	// previous one. A nil handler stops delivery (events still drain).
	handler atomic.Pointer[func(T)]
}

func newEventBus[T any](capacity int) *eventBus[T] {
	return &eventBus[T]{ch: make(chan T, capacity), stop: make(chan struct{})}
}

// setHandler installs h as the current handler and starts (once) the single
// consumer goroutine that hands events to it. Calling it again just swaps the
// handler; passing nil stops delivery without tearing the bus down.
func (b *eventBus[T]) setHandler(h func(T)) {
	stored := new(func(T))
	*stored = h
	b.handler.Store(stored)
	b.started.Do(func() {
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			for {
				select {
				case ev := <-b.ch:
					hp := b.handler.Load()
					if hp == nil || *hp == nil {
						continue
					}
					safeEventCall(*hp, ev)
				case <-b.stop:
					return
				}
			}
		}()
	})
}

func (b *eventBus[T]) emit(ev T) {
	if b.stopped.Load() {
		return
	}
	select {
	case b.ch <- ev:
	default:
		b.dropped.Add(1)
	}
}

func (b *eventBus[T]) droppedCount() uint64 { return b.dropped.Load() }

func (b *eventBus[T]) close() {
	b.stopped.Store(true)
	close(b.stop)
}

// safeEventCall isolates embedder-handler panics: a panicking callback must
// never take down the tunnel.
func safeEventCall[T any](h func(T), ev T) {
	defer func() {
		_ = recover() // an embedder bug must not kill the tunnel
	}()
	h(ev)
}
