// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"testing"
	"time"
)

// inject sends a packet into the resolver as a network listener would.
func (r *Resolver) inject(msg *msgAddr) {
	select {
	case r.msgCh <- msg:
	case <-r.closedCh:
	}
}

func drainEvents(ch <-chan Event) []Event {
	out := []Event{}
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func waitForEvent(t *testing.T, ch <-chan Event, want EventType) Event {
	t.Helper()
	select {
	case ev := <-ch:
		if ev.Type != want {
			t.Fatalf("expected event %s, got %s", want, ev.Type)
		}
		return ev
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for event %s", want)
	}
	return Event{}
}

func TestResolver_CacheHitAndUpdates(t *testing.T) {
	clock := newMockClock()
	events := make(chan Event, 64)
	r := newResolverForTest(clock, events)
	defer r.Close()

	// An announcement arrives before any query exists.
	r.inject(&msgAddr{msg: announceMsg(120)})
	ev := waitForEvent(t, events, EventNew)
	if ev.Entry == nil || ev.Entry.Name != testInstance {
		t.Fatalf("bad new event: %+v", ev)
	}

	// First query must be served from the cache as a hit without waiting.
	entries1 := make(chan *ServiceEntry, 4)
	queryDone := make(chan error, 1)
	go func() {
		queryDone <- r.QueryContext(context.Background(), &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: entries1,
		})
	}()
	hit := waitForEvent(t, events, EventCacheHit)
	if hit.Service != testService {
		t.Fatalf("hit has wrong service: %q", hit.Service)
	}
	select {
	case e := <-entries1:
		if e.Name != testInstance {
			t.Fatalf("wrong cached entry: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("cache hit was not delivered to the entries channel")
	}

	// A second, concurrent query shares the same cache and also gets a hit.
	entries2 := make(chan *ServiceEntry, 4)
	go func() {
		_ = r.QueryContext(context.Background(), &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: entries2,
		})
	}()
	waitForEvent(t, events, EventCacheHit)
	select {
	case <-entries2:
	case <-time.After(time.Second):
		t.Fatal("second subscription did not receive the cached entry")
	}

	// A repeated announcement is an update fanned out to both subscriptions.
	r.inject(&msgAddr{msg: announceMsg(120)})
	waitForEvent(t, events, EventUpdate)
	for i, ch := range []chan *ServiceEntry{entries1, entries2} {
		select {
		case e := <-ch:
			if e.Name != testInstance {
				t.Fatalf("subscription %d got wrong entry: %+v", i, e)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscription %d did not receive the update", i)
		}
	}
}

func TestResolver_ContextCancelOnlyUnsubscribes(t *testing.T) {
	clock := newMockClock()
	events := make(chan Event, 64)
	r := newResolverForTest(clock, events)
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	entries := make(chan *ServiceEntry, 4)
	done := make(chan error, 1)
	go func() {
		done <- r.QueryContext(ctx, &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: entries,
		})
	}()

	// Drain the cache-hit event only if one is produced (cache is empty,
	// so typically none is).
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("query did not return after cancellation")
	}

	// The resolver and its listener are still alive and accept new queries.
	r.mu.Lock()
	n := len(r.subs)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("cancelled subscription was not removed: %d remain", n)
	}

	entries2 := make(chan *ServiceEntry, 4)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		_ = r.QueryContext(ctx2, &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: entries2,
		})
	}()
	// Give the second query time to register, then announce.
	time.Sleep(20 * time.Millisecond)
	r.inject(&msgAddr{msg: announceMsg(120)})
	waitForEvent(t, events, EventNew)
	select {
	case <-entries2:
	case <-time.After(time.Second):
		t.Fatal("new query after cancellation received nothing")
	}
}

func TestResolver_TTLExpiryThroughInjectedClock(t *testing.T) {
	clock := newMockClock()
	events := make(chan Event, 64)
	r := newResolverForTest(clock, events)
	defer r.Close()

	entries := make(chan *ServiceEntry, 4)
	go func() {
		_ = r.QueryContext(context.Background(), &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: entries,
		})
	}()
	time.Sleep(20 * time.Millisecond)

	r.inject(&msgAddr{msg: announceMsg(10)})
	waitForEvent(t, events, EventNew)
	select {
	case <-entries:
	case <-time.After(time.Second):
		t.Fatal("new entry not delivered")
	}

	// Within the TTL nothing expires.
	clock.Advance(9 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := drainEvents(events); len(got) != 0 {
		t.Fatalf("unexpected events before TTL: %v", got)
	}

	// Crossing the TTL fires the cleanup timer and produces an expiry.
	clock.Advance(2 * time.Second)
	expiry := waitForEvent(t, events, EventExpired)
	if expiry.Service != testService || expiry.Entry != nil {
		t.Fatalf("bad expiry event: %+v", expiry)
	}

	// The subscription forgot the instance, so a re-registration is new again.
	r.inject(&msgAddr{msg: announceMsg(10)})
	waitForEvent(t, events, EventNew)
}

func TestResolver_GoodbyeObservedThenExpiry(t *testing.T) {
	clock := newMockClock()
	events := make(chan Event, 64)
	r := newResolverForTest(clock, events)
	defer r.Close()

	r.inject(&msgAddr{msg: announceMsg(10)})
	waitForEvent(t, events, EventNew)

	r.inject(&msgAddr{msg: announceMsg(0)})
	goodbye := waitForEvent(t, events, EventGoodbye)
	if goodbye.Entry == nil || goodbye.Entry.Name != testInstance {
		t.Fatalf("bad goodbye event: %+v", goodbye)
	}
	// Still cached as pending.
	if len(r.cache.Snapshot()) != 1 {
		t.Fatal("goodbye must keep the instance pending in the cache")
	}

	clock.Advance(11 * time.Second)
	waitForEvent(t, events, EventExpired)
	if len(r.cache.Snapshot()) != 0 {
		t.Fatal("pending instance should expire once its records time out")
	}
}

func TestResolver_ConcurrentQueriesShareListener(t *testing.T) {
	serv, err := NewServer(&Config{Zone: makeServiceWithServiceName(t, "_foobar._tcp")})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer serv.Shutdown()

	events := make(chan Event, 64)
	resolver, err := NewResolver(&ResolverConfig{
		DisableIPv6: true,
		Events:      events,
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	defer resolver.Close()

	// Warm the shared cache with a first query.
	warm := make(chan *ServiceEntry, 4)
	if err := resolver.QueryContext(context.Background(), &QueryParam{
		Service: "_foobar._tcp",
		Domain:  "local",
		Timeout: 200 * time.Millisecond,
		Entries: warm,
	}); err != nil {
		t.Fatalf("warmup query: %v", err)
	}
	select {
	case e := <-warm:
		if e.Name != "hostname._foobar._tcp.local." {
			t.Fatalf("wrong warmup entry: %+v", e)
		}
	default:
		t.Fatal("warmup query discovered nothing")
	}
	waitForEvent(t, events, EventNew)

	// Concurrent queries must all be served from the same cache without
	// opening additional listeners.
	const n = 3
	entryChs := make([]chan *ServiceEntry, n)
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		entryChs[i] = make(chan *ServiceEntry, 4)
		go func(ch chan *ServiceEntry) {
			done <- resolver.QueryContext(context.Background(), &QueryParam{
				Service: "_foobar._tcp",
				Domain:  "local",
				Timeout: 200 * time.Millisecond,
				Entries: ch,
			})
		}(entryChs[i])
	}

	hits := 0
	gotEntry := make([]bool, n)
	completed := 0
	deadline := time.After(2 * time.Second)
	for completed < n {
		select {
		case ev := <-events:
			if ev.Type == EventCacheHit {
				hits++
			}
		case err := <-done:
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			completed++
		case <-deadline:
			t.Fatalf("timed out; hits=%d entries=%v completed=%d", hits, gotEntry, completed)
		}
		for i, ch := range entryChs {
			select {
			case e := <-ch:
				if e.Name != "hostname._foobar._tcp.local." {
					t.Fatalf("wrong entry: %+v", e)
				}
				gotEntry[i] = true
			default:
			}
		}
	}
	// Any hits emitted as the final queries register are still buffered.
drain:
	for {
		select {
		case ev := <-events:
			if ev.Type == EventCacheHit {
				hits++
			}
		default:
			break drain
		}
	}
	if hits != n {
		t.Fatalf("each concurrent query should observe a cache hit, got %d", hits)
	}
	for i, ok := range gotEntry {
		if !ok {
			t.Fatalf("query %d never received an entry", i)
		}
	}
}

func TestResolver_QueryWrapperAndSnapshot(t *testing.T) {
	// This test relies on the wall-clock timeout rather than advancing a
	// mock clock.
	r := newResolverForTest(systemClock{}, nil)
	defer r.Close()

	r.inject(&msgAddr{msg: announceMsg(120)})
	time.Sleep(20 * time.Millisecond)

	entries := make(chan *ServiceEntry, 4)
	if err := r.Query(&QueryParam{
		Service: "_http._tcp",
		Domain:  "local",
		Timeout: 20 * time.Millisecond,
		Entries: entries,
	}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	select {
	case e := <-entries:
		if e.Name != testInstance {
			t.Fatalf("wrong entry: %+v", e)
		}
	default:
		t.Fatal("Query delivered nothing")
	}

	if snap := r.Cache().Snapshot(); len(snap) != 1 || snap[0].Name != testInstance {
		t.Fatalf("bad snapshot: %+v", snap)
	}
}

func TestEventType_String(t *testing.T) {
	cases := map[EventType]string{
		EventNew:      "new",
		EventUpdate:   "update",
		EventCacheHit: "cache-hit",
		EventGoodbye:  "goodbye",
		EventExpired:  "expired",
		EventType(99): "unknown",
	}
	for event, want := range cases {
		if got := event.String(); got != want {
			t.Errorf("%d: got %q, want %q", event, got, want)
		}
	}
}

func TestResolver_CloseWakesQueriesAndStopsTimer(t *testing.T) {
	clock := newMockClock()
	events := make(chan Event, 64)
	r := newResolverForTest(clock, events)

	done := make(chan error, 1)
	go func() {
		done <- r.QueryContext(context.Background(), &QueryParam{
			Service: "_http._tcp",
			Domain:  "local",
			Timeout: time.Minute,
			Entries: make(chan *ServiceEntry, 1),
		})
	}()
	time.Sleep(20 * time.Millisecond)

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("closed query should return nil, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake the in-flight query")
	}

	// Idempotent.
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// A late packet cannot repopulate the closed cache.
	r.inject(&msgAddr{msg: announceMsg(120)})
	time.Sleep(20 * time.Millisecond)
	if got := drainEvents(events); len(got) != 0 {
		t.Fatalf("closed resolver emitted events: %v", got)
	}
	if _, err := r.cache.Apply(announceMsg(120), nil); !errors.Is(err, ErrCacheClosed) {
		t.Fatalf("late packet not rejected: %v", err)
	}
	if err := r.QueryContext(context.Background(), &QueryParam{Service: "_http._tcp"}); !errors.Is(err, ErrResolverClosed) {
		t.Fatalf("query after close: %v", err)
	}
}
