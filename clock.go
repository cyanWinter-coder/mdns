// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import "time"

// Clock abstracts the passage of time so that cache TTL expiry and the
// resolver's cleanup timer can be driven deterministically from tests.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// NewTimer creates a Timer that fires after d.
	NewTimer(d time.Duration) Timer
}

// Timer is the subset of time.Timer used by the resolver.
type Timer interface {
	// C returns the channel on which the firing time is delivered.
	C() <-chan time.Time

	// Stop prevents the timer from firing. It reports whether the call
	// stopped the timer before it fired.
	Stop() bool

	// Reset schedules the timer to fire after d instead of its previous
	// schedule.
	Reset(d time.Duration) bool
}

// systemClock implements Clock using the wall clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer {
	return &systemTimer{timer: time.NewTimer(d)}
}

// systemTimer adapts *time.Timer to the Timer interface.
type systemTimer struct {
	timer *time.Timer
}

func (t *systemTimer) C() <-chan time.Time        { return t.timer.C }
func (t *systemTimer) Stop() bool                 { return t.timer.Stop() }
func (t *systemTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }
