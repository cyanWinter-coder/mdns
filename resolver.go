// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// defaultCleanupInterval is how often the resolver sweeps expired records
// when ResolverConfig.CleanupInterval is left zero.
const defaultCleanupInterval = time.Second

// ErrResolverClosed is returned by queries issued after Resolver.Close.
var ErrResolverClosed = errors.New("mdns: resolver is closed")

// ResolverConfig configures a long-lived Resolver.
type ResolverConfig struct {
	// Interface binds the multicast listeners to one interface. The
	// system default multicast interface is used when nil.
	Interface *net.Interface

	// DisableIPv4 / DisableIPv6 turn off the respective protocol. At
	// least one must remain enabled.
	DisableIPv4 bool
	DisableIPv6 bool

	// WantUnicastResponse requests unicast responses as per RFC 6762 5.4.
	WantUnicastResponse bool

	// Clock drives TTL expiry and the cleanup timer. It defaults to the
	// wall clock; inject a controllable clock in tests.
	Clock Clock

	// CleanupInterval is the period of the cache expiry sweep. Defaults
	// to one second.
	CleanupInterval time.Duration

	// Events, when non-nil, receives every cache transition: new
	// instances, updates, cache hits, goodbyes and expiries. Goodbye and
	// expiry events are not delivered on query entry channels. Sends are
	// non-blocking, so the channel should be buffered; events are dropped
	// when it is full.
	Events chan<- Event

	// Logger receives protocol errors. Defaults to log.Default().
	Logger *log.Logger
}

// Resolver is a reusable mDNS discovery session. All concurrent queries
// share one set of multicast/unicast listeners and one ResolverCache;
// cancelling a single query only unsubscribes that query and never tears
// down the shared listener.
type Resolver struct {
	client *client
	cache  *ResolverCache
	events chan<- Event
	clock  Clock
	log    *log.Logger

	cleanupInterval time.Duration

	msgCh chan *msgAddr

	mu       sync.Mutex
	subs     map[*subscription]struct{}
	closed   bool
	closedCh chan struct{}
	shutdown sync.Once
}

// subscription is one in-flight QueryContext's view onto the shared cache.
type subscription struct {
	service string
	entries chan<- *ServiceEntry

	// seen records the cache version last delivered for each instance so
	// repeated announcements that change nothing are not re-delivered.
	seen map[string]uint64
}

// subscriptionEntry pairs an instance snapshot with its cache version.
type subscriptionEntry struct {
	entry   *ServiceEntry
	version uint64
	name    string
}

// NewResolver creates a Resolver, opening the shared UDP listeners and
// starting the packet dispatcher and the cache cleanup loop.
func NewResolver(config *ResolverConfig) (*Resolver, error) {
	if config == nil {
		config = &ResolverConfig{}
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	cleanupInterval := config.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = defaultCleanupInterval
	}

	client, err := newClient(!config.DisableIPv4, !config.DisableIPv6, logger)
	if err != nil {
		return nil, err
	}
	if config.Interface != nil {
		if err := client.setInterface(config.Interface); err != nil {
			client.Close()
			return nil, err
		}
	}

	r := &Resolver{
		client:          client,
		cache:           NewResolverCache(clock),
		events:          config.Events,
		clock:           clock,
		log:             logger,
		cleanupInterval: cleanupInterval,
		msgCh:           make(chan *msgAddr, 32),
		subs:            make(map[*subscription]struct{}),
		closedCh:        make(chan struct{}),
	}

	if client.use_ipv4 {
		go client.recv(client.ipv4UnicastConn, r.msgCh)
		go client.recv(client.ipv4MulticastConn, r.msgCh)
	}
	if client.use_ipv6 {
		go client.recv(client.ipv6UnicastConn, r.msgCh)
		go client.recv(client.ipv6MulticastConn, r.msgCh)
	}
	go r.dispatch()
	go r.cleanup()

	return r, nil
}

// newResolverForTest builds a Resolver without opening UDP sockets. Tests
// drive packets through msgCh and time through the provided clock directly.
func newResolverForTest(clock Clock, events chan<- Event) *Resolver {
	if clock == nil {
		clock = systemClock{}
	}
	r := &Resolver{
		cache:           NewResolverCache(clock),
		events:          events,
		clock:           clock,
		log:             log.Default(),
		cleanupInterval: time.Second,
		msgCh:           make(chan *msgAddr, 32),
		subs:            make(map[*subscription]struct{}),
		closedCh:        make(chan struct{}),
	}
	go r.dispatch()
	go r.cleanup()
	return r
}

// Cache exposes the backing cache, e.g. for snapshots.
func (r *Resolver) Cache() *ResolverCache {
	return r.cache
}

// Query runs a lookup against the shared cache and listener, streaming
// instances to params.Entries until the timeout, ctx cancellation, or
// Resolver.Close. Cached instances are delivered immediately as cache hits;
// later announcements arrive as new/update events.
func (r *Resolver) Query(params *QueryParam) error {
	return r.QueryContext(context.Background(), params)
}

// QueryContext is Query with cancellation. Cancelling ctx removes only this
// query's subscription; other queries, the listener and the cache keep
// running.
func (r *Resolver) QueryContext(ctx context.Context, params *QueryParam) error {
	if params.Domain == "" {
		params.Domain = "local"
	}
	if params.Timeout == 0 {
		params.Timeout = time.Second
	}
	serviceAddr := fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrResolverClosed
	}
	sub := &subscription{
		service: serviceAddr,
		entries: params.Entries,
		seen:    make(map[string]uint64),
	}
	r.subs[sub] = struct{}{}
	r.mu.Unlock()
	defer r.removeSubscription(sub)

	// Serve everything the cache already knows instead of waiting for a
	// fresh announcement.
	for _, hit := range r.cache.snapshotForService(serviceAddr) {
		sub.seen[hit.name] = hit.version
		r.emit(Event{Type: EventCacheHit, Service: serviceAddr, Entry: hit.entry})
		if hit.entry.complete() {
			r.deliver(sub, hit.entry)
		}
	}

	// Multicast the question so responders announce on the wire.
	m := new(dns.Msg)
	m.SetQuestion(serviceAddr, dns.TypePTR)
	// RFC 6762, section 18.12: the top bit of qclass requests unicast.
	if params.WantUnicastResponse {
		m.Question[0].Qclass |= 1 << 15
	}
	m.RecursionDesired = false
	if r.client != nil {
		if err := r.client.sendQuery(m); err != nil {
			return err
		}
	}

	finish := r.clock.NewTimer(params.Timeout)
	defer finish.Stop()
	select {
	case <-finish.C():
		return nil
	case <-ctx.Done():
		// Only this subscription is removed; the shared listener stays
		// open for every other query.
		return ctx.Err()
	case <-r.closedCh:
		// Close wakes every in-flight query.
		return nil
	}
}

// dispatch is the single goroutine that applies incoming packets to the
// cache, serializing all cache mutations.
func (r *Resolver) dispatch() {
	for {
		select {
		case resp := <-r.msgCh:
			changes, err := r.cache.Apply(resp.msg, resp.src)
			if err != nil {
				// ErrCacheClosed: a late packet cannot resurrect us.
				return
			}
			r.handleChanges(changes)
		case <-r.closedCh:
			return
		}
	}
}

// cleanup periodically sweeps records whose TTL has elapsed. The timer is
// created from the injected clock so tests can drive expiry deterministically.
func (r *Resolver) cleanup() {
	timer := r.clock.NewTimer(r.cleanupInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C():
			r.handleChanges(r.cache.purge())
			timer.Reset(r.cleanupInterval)
		case <-r.closedCh:
			return
		}
	}
}

// handleChanges publishes cache transitions to the global event observer and
// to the matching subscriptions.
func (r *Resolver) handleChanges(changes []cacheChange) {
	for _, change := range changes {
		var entry *ServiceEntry
		if change.event != EventExpired {
			entry = r.cache.entryFor(change.name)
		}
		r.emit(Event{Type: change.event, Service: change.service, Entry: entry})
		r.fanout(change, entry)
	}
}

// emit delivers an event to the observer without ever blocking the
// dispatcher; a full channel drops the event.
func (r *Resolver) emit(event Event) {
	if r.events == nil {
		return
	}
	select {
	case r.events <- event:
	default:
	}
}

// fanout routes one transition to every subscription for its service. A
// subscription that has already observed this version is skipped.
func (r *Resolver) fanout(change cacheChange, entry *ServiceEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for sub := range r.subs {
		if sub.service != change.service {
			continue
		}
		if change.event == EventExpired {
			// The instance is gone; forget it so a later re-registration
			// can be delivered as a fresh new event.
			delete(sub.seen, change.name)
			continue
		}
		if change.event == EventGoodbye {
			// Goodbyes are observable through the Events channel only:
			// the instance stays cached as pending and is not re-delivered
			// to an entries channel unless it is re-confirmed or updated.
			continue
		}
		if entry == nil || !entry.complete() {
			continue
		}
		if sub.seen[change.name] == change.version {
			continue
		}
		sub.seen[change.name] = change.version
		r.deliverLocked(sub, entry)
	}
}

// deliver sends an entry to a subscription without blocking, used outside
// the resolver lock.
func (r *Resolver) deliver(sub *subscription, entry *ServiceEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliverLocked(sub, entry)
}

// deliverLocked performs a non-blocking send on a subscription channel. The
// caller must hold r.mu, which also guarantees the subscription cannot be
// removed concurrently.
func (r *Resolver) deliverLocked(sub *subscription, entry *ServiceEntry) {
	select {
	case sub.entries <- entry:
	default:
	}
}

// removeSubscription detaches one query. It never closes the shared client,
// so other queries keep receiving packets.
func (r *Resolver) removeSubscription(sub *subscription) {
	r.mu.Lock()
	delete(r.subs, sub)
	r.mu.Unlock()
}

// Close wakes every in-flight query, stops the cleanup timer and packet
// dispatcher, closes the shared listeners, and marks the cache closed so a
// late packet can never repopulate it.
func (r *Resolver) Close() error {
	r.shutdown.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.subs = make(map[*subscription]struct{})
		close(r.closedCh)
		r.mu.Unlock()

		r.cache.Close()
		if r.client != nil {
			r.client.Close()
		}
	})
	return nil
}
