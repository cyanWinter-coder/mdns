# mdns
[![Build Status](https://github.com/hashicorp/mdns/workflows/ci/badge.svg)](https://github.com/hashicorp/mdns/actions)

Simple mDNS client/server library in Golang. mDNS or Multicast DNS can be
used to discover services on the local network without the use of an authoritative
DNS server. This enables peer-to-peer discovery. It is important to note that many
networks restrict the use of multicasting, which prevents mDNS from functioning.
Notably, multicast cannot be used in any sort of cloud, or shared infrastructure
environment. However it works well in most office, home, or private infrastructure
environments.

Using the library is very simple, here is an example of publishing a service entry:
```go
// Setup our service export
host, _ := os.Hostname()
info := []string{"My awesome service"}
service, _ := mdns.NewMDNSService(host, "_foobar._tcp", "", "", 8000, nil, info)

// Create the mDNS server, defer shutdown
server, _ := mdns.NewServer(&mdns.Config{Zone: service})
defer server.Shutdown()
```

Doing a lookup for service providers is also very simple:
```go
// Make a channel for results and start listening
entriesCh := make(chan *mdns.ServiceEntry, 4)
go func() {
    for entry := range entriesCh {
        fmt.Printf("Got new entry: %v\n", entry)
    }
}()

// Start the lookup
mdns.Lookup("_foobar._tcp", entriesCh)
close(entriesCh)
```

### Reusable resolver with a persistent cache

One-shot `Lookup`/`Query` calls open fresh listeners per call. For repeated
or concurrent discovery, create a `Resolver` instead: all queries share one
set of UDP listeners and one cache that aggregates SRV/A/AAAA/TXT records
with per-record TTLs, distinguishes goodbyes from TTL expiries, and exposes
every transition as an event.

```go
events := make(chan mdns.Event, 16)
go func() {
    for ev := range events {
        fmt.Printf("service %s: %s\n", ev.Type, ev.Service)
    }
}()

resolver, err := mdns.NewResolver(&mdns.ResolverConfig{
    DisableIPv6: true,
    Events:      events,
})
if err != nil {
    log.Fatal(err)
}
defer resolver.Close()

entries := make(chan *mdns.ServiceEntry, 16)
go func() {
    for entry := range entries {
        fmt.Printf("Got entry: %v\n", entry)
    }
}()

// Several concurrent queries share the same listener; a cached instance is
// delivered as a cache-hit instead of waiting for a new announcement.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := resolver.QueryContext(ctx, &mdns.QueryParam{
    Service: "_foobar._tcp",
    Entries: entries,
    Timeout: time.Second,
}); err != nil {
    log.Fatal(err)
}

// The cache can also be inspected directly at any time.
for _, entry := range resolver.Cache().Snapshot() {
    fmt.Printf("Cached entry: %v\n", entry)
}
```

