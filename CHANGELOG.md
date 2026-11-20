## Unreleased

### Improvements

- Added a reusable `Resolver` and `ResolverCache` for service discovery.
  SRV, A/AAAA and TXT records are aggregated per instance and shared host,
  with per-record TTLs refreshed by repeated announcements, replacing the
  per-query in-memory map.
- Goodbye records (TTL zero) now mark an instance as pending confirmation
  instead of deleting it; only the announcing instance is affected, so a
  shared host or another service on the same host is never removed.
- Cache transitions are observable through `ResolverConfig.Events` /
  `QueryParam.Events` as new, update, cache-hit, goodbye and expiry events.
  TTL expiry is swept on an injectable `Clock` so timing is testable.
- Concurrent queries on one `Resolver` share the same UDP listeners and
  cache; cancelling a single query's context only removes that
  subscription. `Resolver.Close` wakes all queries, stops the cleanup
  timer, and rejects late packets so a closed cache cannot be revived.

### Changes

- `Query`, `QueryContext` and `Lookup` keep their existing signatures and
  callback channel; they now run on a short-lived `Resolver` internally.
  Prefer a long-lived `NewResolver` for repeated or concurrent queries.

### Fixed

### Security
