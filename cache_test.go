// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testService  = "_http._tcp.local."
	testInstance = "web._http._tcp.local."
	testHost     = "testhost.local."
	testOther    = "other._http._tcp.local."
)

// mockTimer is a controllable Timer backed by mockClock.
type mockTimer struct {
	clock    *mockClock
	deadline time.Time
	ch       chan time.Time
	fired    bool
	stopped  bool
}

func (t *mockTimer) C() <-chan time.Time { return t.ch }

func (t *mockTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.fired && !t.stopped
	t.stopped = true
	return active
}

func (t *mockTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.fired && !t.stopped
	t.fired = false
	t.stopped = false
	t.deadline = t.clock.now.Add(d)
	t.clock.timers = append(t.clock.timers, t)
	return active
}

// mockClock is a manually advanced Clock for deterministic TTL tests.
type mockClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*mockTimer
}

func newMockClock() *mockClock {
	return &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *mockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mockClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &mockTimer{
		clock:    c,
		deadline: c.now.Add(d),
		ch:       make(chan time.Time, 1),
	}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock forward by d and fires every timer whose deadline
// has passed. Firing is non-blocking because mockTimer channels are buffered.
func (c *mockClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	fire := []*mockTimer{}
	for _, t := range c.timers {
		if !t.fired && !t.stopped && !t.deadline.After(c.now) {
			t.fired = true
			fire = append(fire, t)
		}
	}
	c.mu.Unlock()
	for _, t := range fire {
		select {
		case t.ch <- c.now:
		default:
		}
	}
}

// hdr builds a RR_Header with the given name/type and TTL in seconds.
func hdr(name string, typ uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET, Ttl: ttl}
}

// announceMsg builds a typical mDNS response announcing testInstance.
func announceMsg(ttl uint32) *dns.Msg {
	return &dns.Msg{
		Answer: []dns.RR{
			&dns.PTR{Hdr: hdr(testService, dns.TypePTR, ttl), Ptr: testInstance},
		},
		Extra: []dns.RR{
			&dns.SRV{Hdr: hdr(testInstance, dns.TypeSRV, ttl), Priority: 10, Weight: 1, Port: 80, Target: testHost},
			&dns.TXT{Hdr: hdr(testInstance, dns.TypeTXT, ttl), Txt: []string{"hello"}},
			&dns.A{Hdr: hdr(testHost, dns.TypeA, ttl), A: net.IPv4(192, 168, 0, 42)},
			&dns.AAAA{Hdr: hdr(testHost, dns.TypeAAAA, ttl), AAAA: net.ParseIP("fe80::1")},
		},
	}
}

func changeTypes(changes []cacheChange) []EventType {
	out := make([]EventType, 0, len(changes))
	for _, ch := range changes {
		out = append(out, ch.event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestCache_NewAndAggregate(t *testing.T) {
	cache := NewResolverCache(newMockClock())

	changes, err := cache.Apply(announceMsg(120), nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventNew {
		t.Fatalf("expected one new event, got %v", got)
	}

	entries := cache.Snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(entries))
	}
	e := entries[0]
	if e.Name != testInstance || e.Host != testHost || e.Port != 80 {
		t.Fatalf("bad entry: %+v", e)
	}
	if e.AddrV4 == nil || !e.AddrV4.Equal(net.IPv4(192, 168, 0, 42)) {
		t.Fatalf("bad IPv4: %v", e.AddrV4)
	}
	if e.AddrV6IPAddr == nil || e.AddrV6IPAddr.IP.String() != "fe80::1" {
		t.Fatalf("bad IPv6: %+v", e.AddrV6IPAddr)
	}
	if e.Info != "hello" || !e.hasTXT || !e.complete() {
		t.Fatalf("entry not complete: %+v", e)
	}

	// The host and its addresses live in a shared, independent map.
	cache.mu.Lock()
	host := cache.hosts[testHost]
	cache.mu.Unlock()
	if host == nil || len(host.addrs) != 2 {
		t.Fatalf("expected shared host with 2 addrs, got %+v", host)
	}
}

func TestCache_RepeatedAnnouncementRefreshesTTL(t *testing.T) {
	clock := newMockClock()
	cache := NewResolverCache(clock)

	if _, err := cache.Apply(announceMsg(10), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	clock.Advance(9 * time.Second)

	// Re-announce with a fresh TTL before expiry.
	changes, err := cache.Apply(announceMsg(10), nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventUpdate {
		t.Fatalf("expected update event, got %v", got)
	}

	clock.Advance(9 * time.Second)
	if changes := cache.purge(); len(changes) != 0 {
		t.Fatalf("refreshed entry expired early: %v", changes)
	}

	// Now let the refreshed TTL run out.
	clock.Advance(2 * time.Second)
	changes = cache.purge()
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventExpired {
		t.Fatalf("expected one expiry, got %v", got)
	}
	if len(cache.Snapshot()) != 0 || len(cache.hosts) != 0 {
		t.Fatalf("cache should be empty after expiry: %+v", cache.Snapshot())
	}
}

func TestCache_PerRecordTTL(t *testing.T) {
	clock := newMockClock()
	cache := NewResolverCache(clock)

	msg := announceMsg(10)
	// The A record outlives the SRV/TXT records.
	msg.Extra[2].(*dns.A).Hdr.Ttl = 30
	if _, err := cache.Apply(msg, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	clock.Advance(11 * time.Second)
	changes := cache.purge()
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventExpired {
		t.Fatalf("expected instance expiry, got %v", got)
	}
	// The shared host with its longer-lived address survives the instance.
	cache.mu.Lock()
	host := cache.hosts[testHost]
	cache.mu.Unlock()
	if host == nil || len(host.addrs) != 1 {
		t.Fatalf("expected host address to survive, got %+v", host)
	}
}

func TestCache_GoodbyePendingAndReconfirm(t *testing.T) {
	cache := NewResolverCache(newMockClock())

	if _, err := cache.Apply(announceMsg(120), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A goodbye carries TTL zero on the PTR/SRV/TXT records.
	goodbye := announceMsg(0)
	changes, err := cache.Apply(goodbye, nil)
	if err != nil {
		t.Fatalf("Apply goodbye: %v", err)
	}
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventGoodbye {
		t.Fatalf("expected goodbye event, got %v", got)
	}
	if changes[0].service != testService {
		t.Fatalf("goodbye event lost its service label: %q", changes[0].service)
	}

	cache.mu.Lock()
	inst := cache.instances[testInstance]
	pending := inst.pending
	_, member := inst.services[testService]
	host := cache.hosts[testHost]
	cache.mu.Unlock()
	if !pending {
		t.Fatal("instance should be marked pending")
	}
	if member {
		t.Fatal("instance should be removed from the service enumeration")
	}
	if host == nil {
		t.Fatal("shared host record must survive a goodbye")
	}
	if len(cache.Snapshot()) != 1 {
		t.Fatal("pending instance must remain queryable until expiry")
	}

	// A fresh announcement clears the pending state.
	changes, err = cache.Apply(announceMsg(120), nil)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventUpdate {
		t.Fatalf("expected update after re-announcement, got %v", got)
	}
	cache.mu.Lock()
	pending = cache.instances[testInstance].pending
	cache.mu.Unlock()
	if pending {
		t.Fatal("re-announcement should clear the pending flag")
	}
}

func TestCache_GoodbyeDoesNotTouchOtherServiceOrHost(t *testing.T) {
	cache := NewResolverCache(newMockClock())

	// Two instances sharing one host.
	first := announceMsg(120)
	second := &dns.Msg{
		Answer: []dns.RR{
			&dns.PTR{Hdr: hdr(testService, dns.TypePTR, 120), Ptr: testOther},
		},
		Extra: []dns.RR{
			&dns.SRV{Hdr: hdr(testOther, dns.TypeSRV, 120), Port: 81, Target: testHost},
			&dns.TXT{Hdr: hdr(testOther, dns.TypeTXT, 120), Txt: []string{"two"}},
			&dns.A{Hdr: hdr(testHost, dns.TypeA, 120), A: net.IPv4(192, 168, 0, 42)},
		},
	}
	if _, err := cache.Apply(first, nil); err != nil {
		t.Fatalf("Apply first: %v", err)
	}
	if _, err := cache.Apply(second, nil); err != nil {
		t.Fatalf("Apply second: %v", err)
	}

	if _, err := cache.Apply(announceMsg(0), nil); err != nil {
		t.Fatalf("goodbye: %v", err)
	}

	cache.mu.Lock()
	_, otherExists := cache.instances[testOther]
	_, firstExists := cache.instances[testInstance]
	cache.mu.Unlock()
	if !otherExists {
		t.Fatal("goodbye for one instance removed the other instance")
	}
	if !firstExists {
		t.Fatal("goodbye instance should stay pending, not be deleted")
	}

	// Rebuild the shared addresses that the goodbye packet's TTL-zero
	// A/AAAA records removed; the other live service then keeps the host.
	refresh := &dns.Msg{
		Extra: []dns.RR{
			&dns.A{Hdr: hdr(testHost, dns.TypeA, 120), A: net.IPv4(192, 168, 0, 42)},
			&dns.AAAA{Hdr: hdr(testHost, dns.TypeAAAA, 120), AAAA: net.ParseIP("fe80::1")},
		},
	}
	if _, err := cache.Apply(refresh, nil); err != nil {
		t.Fatalf("refresh addresses: %v", err)
	}
	cache.mu.Lock()
	host := cache.hosts[testHost]
	otherStillClean := !cache.instances[testOther].pending
	cache.mu.Unlock()
	if host == nil || len(host.addrs) != 2 {
		t.Fatalf("shared host must survive for the other service, got %+v", host)
	}
	if !otherStillClean {
		t.Fatal("the other service must never be marked pending")
	}
}

func TestCache_GoodbyeAddressOnlyRemovesAddress(t *testing.T) {
	cache := NewResolverCache(newMockClock())
	if _, err := cache.Apply(announceMsg(120), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	addrGoodbye := &dns.Msg{
		Extra: []dns.RR{
			&dns.A{Hdr: hdr(testHost, dns.TypeA, 0), A: net.IPv4(192, 168, 0, 42)},
		},
	}
	changes, err := cache.Apply(addrGoodbye, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := changeTypes(changes); len(got) != 1 || got[0] != EventUpdate {
		t.Fatalf("expected address update, got %v", got)
	}
	e := cache.entryFor(testInstance)
	if e == nil || e.AddrV4 != nil {
		t.Fatalf("IPv4 should be gone: %+v", e)
	}
	if e.AddrV6IPAddr == nil {
		t.Fatal("unrelated IPv6 address must remain")
	}
}

func TestCache_CloseRejectsLatePackets(t *testing.T) {
	cache := NewResolverCache(newMockClock())
	if _, err := cache.Apply(announceMsg(120), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cache.Close()

	if _, err := cache.Apply(announceMsg(120), nil); !errors.Is(err, ErrCacheClosed) {
		t.Fatalf("expected ErrCacheClosed, got %v", err)
	}
	if changes := cache.purge(); changes != nil {
		t.Fatalf("closed cache must not purge, got %v", changes)
	}
}

func TestCache_LinkLocalZoneFromSource(t *testing.T) {
	cache := NewResolverCache(newMockClock())
	msg := announceMsg(120)
	src := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}
	if _, err := cache.Apply(msg, src); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	e := cache.entryFor(testInstance)
	if e == nil || e.AddrV6IPAddr == nil || e.AddrV6IPAddr.Zone != "eth0" {
		t.Fatalf("expected link-local zone eth0, got %+v", e)
	}
}
