# Changelog

The crates, `http-acl`, `http-acl-reqwest` and `http-acl-wasmtime`, share one version.

## Unreleased

### Added

- `http-acl-wasmtime`: the ACL for wasmtime-wasi-http 36's outgoing requests, through its
  overridable `WasiHttpView::send_request`. `check_request` checks the method, scheme, port
  and decoded URL path; `send_request_handler` checks the host, resolves it and checks every
  address the resolver returns before connecting, and applies the request and response
  rewrite hooks. It replaces the http-acl patch carried in the hisn-io/wasmtime fork
  (hisn-io/hisn#3638), so the fork is no longer needed.

## 0.14.0 (2026-10-16)

### Changed (behaviour)

- `http-acl`: the IPv6 ranges that embed an IPv4 address are now non-global, so they are
  denied unless `non_global_ip_ranges(true)` is set, and an allowed IP range that starts or
  ends in one is refused at build time. The new ranges are IPv4-compatible `::/96`,
  IPv4-translated `::ffff:0:0:0/96`, NAT64 `64:ff9b::/96` and 6to4 `2002::/16`; IPv4-mapped
  `::ffff:0:0/96` and `64:ff9b:1::/48` already were. Before, `::7f00:1` or
  `64:ff9b::7f00:1` could reach loopback. The whole range is denied whatever the embedded
  address, so a NAT64 network that reaches public IPv4 hosts through `64:ff9b::/96` now
  needs `non_global_ip_ranges(true)` (hisn-io/hisn#2821).

### Fixed

- `http-acl-reqwest`: `HttpAclDnsResolver` no longer checks the port of a resolved address
  that carries port 0, which every `getaddrinfo` answer does. With an ACL that does not
  allow port 0 (the default allows only 80 and 443) every resolved address was dropped, so
  no request by hostname could connect. The connector replaces port 0 with the URL's port,
  which the middleware already checks; a non-zero resolved port is still checked
  (hisn-io/hisn#2794, hisn-io/hisn#2821).
