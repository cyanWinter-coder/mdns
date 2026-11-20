// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// EventType identifies the kind of change observed on a ResolverCache.
type EventType int

const (
	// EventNew is emitted the first time a service instance is observed.
	EventNew EventType = iota

	// EventUpdate is emitted when an existing instance's records are
	// refreshed (a repeated announcement renewed a TTL) or its host,
	// addresses or TXT records change.
	EventUpdate

	// EventCacheHit is emitted when a query is served an instance that was
	// already present in the cache instead of waiting for a fresh packet.
	EventCacheHit

	// EventGoodbye is emitted when a goodbye record (TTL zero) marks an
	// instance as pending confirmation. The instance is not removed yet:
	// a repeated announcement can confirm it again.
	EventGoodbye

	// EventExpired is emitted when an instance has not been re-announced
	// before every one of its records reached its TTL.
	EventExpired
)

// String returns a human-readable name for the event type.
func (e EventType) String() string {
	switch e {
	case EventNew:
		return "new"
	case EventUpdate:
		return "update"
	case EventCacheHit:
		return "cache-hit"
	case EventGoodbye:
		return "goodbye"
	case EventExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Event describes a cache transition. Entry is nil for EventExpired, where
// only the instance name and service remain available.
type Event struct {
	Type    EventType
	Service string
	Entry   *ServiceEntry
}

// ErrCacheClosed is returned when a packet reaches a cache that has already
// been closed. A late announcement can never resurrect a closed cache.
var ErrCacheClosed = errors.New("mdns: resolver cache is closed")

// cachedAddress is one A/AAAA record together with its absolute expiry.
type cachedAddress struct {
	ip       net.IP
	expireAt time.Time
	zone     string
}

// cachedHost aggregates the A/AAAA records published under a hostname. Hosts
// are shared between instances, so a goodbye for one instance never removes
// addresses still in use by another service on the same host.
type cachedHost struct {
	name     string
	addrs    map[string]*cachedAddress // keyed by IP string
	expireAt time.Time                 // latest TTL among the host's records
}

// cachedInstance aggregates the SRV/TXT/PTR records describing one service
// instance and points at the shared host carrying its addresses.
type cachedInstance struct {
	name string

	// services is the set of service enumeration PTR names (e.g.
	// "_http._tcp.local.") under which this instance has been announced.
	services map[string]struct{}

	host        string
	port        int
	info        string
	infoFields  []string
	hasTXT      bool
	srvExpireAt time.Time
	txtExpireAt time.Time

	// lastService remembers the most recently observed service
	// enumeration name so goodbye/expiry events stay labeled even after a
	// goodbye PTR removes the instance from its service set.
	lastService string

	// pending is set by a goodbye and cleared by a subsequent
	// announcement. A pending instance stays in the cache until it is
	// re-confirmed or its records expire.
	pending bool

	// version is bumped on every cache transition affecting the instance
	// so subscribers can tell updates from mere re-delivery.
	version uint64
}

// ResolverCache is a concurrency-safe, reusable aggregation of the mDNS
// records seen on the wire. SRV, TXT, A and AAAA records are aggregated per
// instance, host and address respectively, and each repeated announcement
// refreshes the TTL of the records it carries.
type ResolverCache struct {
	clock Clock

	mu        sync.Mutex
	instances map[string]*cachedInstance
	hosts     map[string]*cachedHost
	closed    bool

	version uint64
}

// NewResolverCache creates an empty cache driven by the given clock. A nil
// clock is replaced by the wall clock.
func NewResolverCache(clock Clock) *ResolverCache {
	if clock == nil {
		clock = systemClock{}
	}
	return &ResolverCache{
		clock:     clock,
		instances: make(map[string]*cachedInstance),
		hosts:     make(map[string]*cachedHost),
	}
}

// Apply ingests one mDNS message. Goodbye records (TTL zero) mark the
// affected instance as pending confirmation and remove only that instance's
// membership; shared hosts and other services are left untouched. Repeated
// announcements refresh per-record TTLs. Apply returns ErrCacheClosed once
// Close has been called, so late packets cannot resurrect a closed cache.
// The returned changes describe every transition the message caused.
func (c *ResolverCache) Apply(msg *dns.Msg, src *net.UDPAddr) ([]cacheChange, error) {
	if msg == nil {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrCacheClosed
	}

	now := c.clock.Now()
	touched := make(map[string]struct{})
	goodbyed := make(map[string]struct{})
	isNew := make(map[string]struct{})

	// Records within a single packet describe the same state snapshot;
	// process them in a fixed order so that PTR membership exists before
	// the SRV/TXT/A/AAAA records that flesh the instance out.
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Extra...) {
		hdr := rr.Header()
		ttl := time.Duration(hdr.Ttl) * time.Second
		expireAt := now.Add(ttl)

		switch rec := rr.(type) {
		case *dns.PTR:
			c.applyPTR(rec, expireAt, hdr.Ttl == 0, touched, goodbyed, isNew)
		case *dns.SRV:
			c.applySRV(rec, expireAt, hdr.Ttl == 0, touched, goodbyed, isNew)
		case *dns.TXT:
			c.applyTXT(rec, expireAt, hdr.Ttl == 0, touched, goodbyed, isNew)
		case *dns.A:
			c.applyAddress(rec.Hdr.Name, rec.A, "", expireAt, hdr.Ttl == 0, touched, goodbyed, isNew)
		case *dns.AAAA:
			zone := ""
			if (rec.AAAA.IsLinkLocalUnicast() || rec.AAAA.IsLinkLocalMulticast()) && src != nil {
				// Link-local IPv6 addresses are only meaningful with a
				// zone, which the wire format cannot carry; borrow it
				// from the packet's source interface.
				zone = src.Zone
			}
			c.applyAddress(rec.Hdr.Name, rec.AAAA, zone, expireAt, hdr.Ttl == 0, touched, goodbyed, isNew)
		}
	}

	for name := range goodbyed {
		delete(touched, name)
	}
	return c.changesLocked(touched, goodbyed, isNew)
}

// applyPTR maintains service -> instance membership. A goodbye PTR removes
// only this instance from the service enumeration; the instance itself is
// marked pending and kept until its other records expire.
func (c *ResolverCache) applyPTR(rec *dns.PTR, expireAt time.Time, goodbye bool, touched, goodbyed, isNew map[string]struct{}) {
	inst := c.ensureInstance(rec.Ptr, isNew)
	if goodbye {
		inst.pending = true
		delete(inst.services, rec.Hdr.Name)
		goodbyed[inst.name] = struct{}{}
		return
	}
	inst.pending = false
	inst.services[rec.Hdr.Name] = struct{}{}
	inst.lastService = rec.Hdr.Name
	touched[inst.name] = struct{}{}
}

// applySRV stores the instance host and port and links the shared host into
// the instance. A goodbye SRV only marks the instance pending.
func (c *ResolverCache) applySRV(rec *dns.SRV, expireAt time.Time, goodbye bool, touched, goodbyed, isNew map[string]struct{}) {
	inst := c.ensureInstance(rec.Hdr.Name, isNew)
	if goodbye {
		inst.pending = true
		goodbyed[inst.name] = struct{}{}
		return
	}
	inst.pending = false
	inst.host = rec.Target
	inst.port = int(rec.Port)
	inst.srvExpireAt = expireAt
	c.ensureHost(rec.Target, expireAt)
	touched[inst.name] = struct{}{}
}

// applyTXT stores the TXT payload and refreshes the TXT TTL.
func (c *ResolverCache) applyTXT(rec *dns.TXT, expireAt time.Time, goodbye bool, touched, goodbyed, isNew map[string]struct{}) {
	inst := c.ensureInstance(rec.Hdr.Name, isNew)
	if goodbye {
		inst.pending = true
		goodbyed[inst.name] = struct{}{}
		return
	}
	inst.pending = false
	inst.info = strings.Join(rec.Txt, "|")
	inst.infoFields = append([]string(nil), rec.Txt...)
	inst.hasTXT = true
	inst.txtExpireAt = expireAt
	touched[inst.name] = struct{}{}
}

// applyAddress stores one A/AAAA record under the shared host and refreshes
// the address TTL. Instances referring to the host are touched so their
// subscribers observe the new reachability information. A goodbye address
// removes only that address.
func (c *ResolverCache) applyAddress(hostName string, ip net.IP, zone string, expireAt time.Time, goodbye bool, touched, goodbyed, isNew map[string]struct{}) {
	host := c.ensureHost(hostName, expireAt)
	key := ip.String()
	if goodbye {
		delete(host.addrs, key)
		for _, inst := range c.instances {
			if inst.host == hostName {
				touched[inst.name] = struct{}{}
			}
		}
		return
	}

	host.addrs[key] = &cachedAddress{ip: append(net.IP(nil), ip...), expireAt: expireAt, zone: zone}
	if expireAt.After(host.expireAt) {
		host.expireAt = expireAt
	}
	for _, inst := range c.instances {
		if inst.host == hostName {
			inst.pending = false
			touched[inst.name] = struct{}{}
		}
	}
}

// ensureInstance returns the named instance, creating it on first sight.
func (c *ResolverCache) ensureInstance(name string, isNew map[string]struct{}) *cachedInstance {
	inst, ok := c.instances[name]
	if !ok {
		inst = &cachedInstance{
			name:     name,
			services: make(map[string]struct{}),
		}
		c.instances[name] = inst
		isNew[name] = struct{}{}
	}
	return inst
}

// ensureHost returns the named shared host, creating it on first sight.
func (c *ResolverCache) ensureHost(name string, expireAt time.Time) *cachedHost {
	host, ok := c.hosts[name]
	if !ok {
		host = &cachedHost{
			name:  name,
			addrs: make(map[string]*cachedAddress),
		}
		c.hosts[name] = host
	}
	if expireAt.After(host.expireAt) {
		host.expireAt = expireAt
	}
	return host
}

// cacheChange is an internal description of one transition.
type cacheChange struct {
	event   EventType
	name    string
	service string
	version uint64
}

// changesLocked bumps versions and builds the change list for one Apply call.
// The caller must hold c.mu.
func (c *ResolverCache) changesLocked(touched, goodbyed, isNew map[string]struct{}) ([]cacheChange, error) {
	changes := make([]cacheChange, 0, len(touched)+len(goodbyed))
	for name := range touched {
		inst, ok := c.instances[name]
		if !ok {
			continue
		}
		c.version++
		inst.version = c.version
		event := EventUpdate
		if _, fresh := isNew[name]; fresh {
			event = EventNew
		}
		changes = append(changes, cacheChange{
			event:   event,
			name:    name,
			service: c.primaryServiceLocked(inst),
			version: inst.version,
		})
	}
	for name := range goodbyed {
		inst, ok := c.instances[name]
		if !ok {
			continue
		}
		c.version++
		inst.version = c.version
		changes = append(changes, cacheChange{
			event:   EventGoodbye,
			name:    name,
			service: c.primaryServiceLocked(inst),
			version: inst.version,
		})
	}
	return changes, nil
}

// purge removes every record whose TTL has elapsed and returns the changes
// the sweep caused. Shared hosts are only removed once no instance and no
// live address references them, so expiring one service never disturbs
// another service on the same host. The caller must not hold c.mu.
func (c *ResolverCache) purge() []cacheChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	now := c.clock.Now()
	changes := []cacheChange{}

	// Drop expired addresses from their shared hosts.
	for hostName, host := range c.hosts {
		for key, addr := range host.addrs {
			if !addr.expireAt.After(now) {
				delete(host.addrs, key)
			}
		}
		referenced := false
		for _, inst := range c.instances {
			if inst.host == hostName && inst.srvExpireAt.After(now) {
				referenced = true
				break
			}
		}
		if !referenced && len(host.addrs) == 0 {
			delete(c.hosts, hostName)
		}
	}

	// Remove instances whose SRV and TXT records have both expired; an
	// instance missing one record class survives as long as the other is
	// still live.
	for name, inst := range c.instances {
		srvLive := !inst.srvExpireAt.IsZero() && inst.srvExpireAt.After(now)
		txtLive := !inst.txtExpireAt.IsZero() && inst.txtExpireAt.After(now)
		if srvLive || txtLive {
			// Address loss may still have changed the rendered entry.
			if inst.host != "" {
				if host, ok := c.hosts[inst.host]; ok && len(host.addrs) == 0 {
					c.version++
					inst.version = c.version
					changes = append(changes, cacheChange{
						event:   EventUpdate,
						name:    name,
						service: c.primaryServiceLocked(inst),
						version: inst.version,
					})
				}
			}
			continue
		}

		c.version++
		changes = append(changes, cacheChange{
			event:   EventExpired,
			name:    name,
			service: c.primaryServiceLocked(inst),
			version: c.version,
		})
		delete(c.instances, name)
	}
	return changes
}

// primaryServiceLocked returns a deterministic service name for an instance,
// preferring the lexicographically smallest membership. The caller must hold
// c.mu.
func (c *ResolverCache) primaryServiceLocked(inst *cachedInstance) string {
	if len(inst.services) > 0 {
		names := make([]string, 0, len(inst.services))
		for svc := range inst.services {
			names = append(names, svc)
		}
		sort.Strings(names)
		return names[0]
	}
	return inst.lastService
}

// entryLocked renders an immutable ServiceEntry snapshot for an instance. The
// caller must hold c.mu.
func (c *ResolverCache) entryLocked(inst *cachedInstance, now time.Time) *ServiceEntry {
	entry := &ServiceEntry{
		Name:       inst.name,
		Host:       inst.host,
		Port:       inst.port,
		Info:       inst.info,
		InfoFields: append([]string(nil), inst.infoFields...),
		hasTXT:     inst.hasTXT,
	}

	if host, ok := c.hosts[inst.host]; ok {
		keys := make([]string, 0, len(host.addrs))
		for key := range host.addrs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			addr := host.addrs[key]
			if !addr.expireAt.After(now) {
				continue
			}
			if v4 := addr.ip.To4(); v4 != nil {
				if entry.AddrV4 == nil {
					entry.AddrV4 = append(net.IP(nil), v4...)
					if entry.Addr == nil {
						entry.Addr = append(net.IP(nil), v4...)
					}
				}
			} else if entry.AddrV6 == nil {
				entry.AddrV6 = append(net.IP(nil), addr.ip...)
				entry.AddrV6IPAddr = &net.IPAddr{IP: append(net.IP(nil), addr.ip...), Zone: addr.zone}
				if entry.Addr == nil {
					entry.Addr = append(net.IP(nil), addr.ip...)
				}
			}
		}
	}
	return entry
}

// Snapshot returns ServiceEntry copies of all currently cached instances.
func (c *ResolverCache) Snapshot() []*ServiceEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	entries := make([]*ServiceEntry, 0, len(c.instances))
	names := make([]string, 0, len(c.instances))
	for name := range c.instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entries = append(entries, c.entryLocked(c.instances[name], now))
	}
	return entries
}

// snapshotForService returns the cached instances belonging to service, each
// paired with its current version.
func (c *ResolverCache) snapshotForService(service string) []subscriptionEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	out := make([]subscriptionEntry, 0, len(c.instances))
	for name, inst := range c.instances {
		if _, ok := inst.services[service]; !ok {
			continue
		}
		out = append(out, subscriptionEntry{
			entry:   c.entryLocked(inst, now),
			version: inst.version,
			name:    name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// entryFor returns a current snapshot of one instance, or nil if it is gone.
func (c *ResolverCache) entryFor(name string) *ServiceEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	inst, ok := c.instances[name]
	if !ok {
		return nil
	}
	return c.entryLocked(inst, c.clock.Now())
}

// Close marks the cache closed. After Close, Apply always fails with
// ErrCacheClosed and purge and snapshots return nothing.
func (c *ResolverCache) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}
