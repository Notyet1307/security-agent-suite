package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitorReadinessRefreshesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	observed := make(chan bool, 2)
	var ready atomic.Bool
	var calls atomic.Int32
	check := func(context.Context) bool {
		switch calls.Add(1) {
		case 1:
			return true
		case 2:
			observed <- ready.Load()
			return false
		default:
			observed <- !ready.Load()
			cancel()
			return false
		}
	}
	done := make(chan struct{})
	go func() {
		monitorReadiness(ctx, ticks, check, &ready)
		close(done)
	}()

	// An unbuffered tick is received only after the preceding refresh stored its result.
	ticks <- time.Now()
	if previousReady := <-observed; !previousReady {
		t.Fatal("initial ready result was not stored before refresh")
	}
	ticks <- time.Now()
	if previousNotReady := <-observed; !previousNotReady {
		t.Fatal("not-ready result was not stored before refresh")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness monitor did not stop")
	}
}

func TestMonitorReadinessCancelsBlockedCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var ready atomic.Bool
		monitorReadiness(ctx, nil, func(ctx context.Context) bool {
			close(started)
			<-ctx.Done()
			return false
		}, &ready)
		close(done)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness check did not stop after cancellation")
	}
}
