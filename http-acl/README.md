# http-acl

An ACL for HTTP requests.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

## What it checks

An `HttpAcl` can check a request's scheme, method, host, port, IP, headers, and URL path, plus any custom logic you supply as a `ValidateFn`, and optionally mutate the request/response themselves via a `ModifyRequestFn`/`ModifyResponseFn` (see [Modifying requests and responses](#modifying-requests-and-responses) below). Each of these (other than scheme, which is a simple allow/deny flag per protocol) is evaluated the same way: the allow list is checked first, then the deny list, and if neither matches, a per-category default decides the outcome. Methods, hosts, ports, and IPs deny by default; headers and URL paths allow by default. Every check returns an `AclClassification` rather than a plain boolean, so you can see why a request was allowed or denied, not just whether it was; call `.is_allowed()`/`.is_denied()` on it once only the outcome matters.

Non-global IP addresses (private, loopback, link-local, and other special-use ranges) are denied outright regardless of the IP allow/deny lists, unless you opt in with `.non_global_ip_ranges(true)` on the builder.

## Usage

```rust
use http_acl::{HttpAcl, IpNet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an HTTP ACL
    let acl = HttpAcl::builder()
        .add_allowed_host("example.com".to_string())
        .unwrap()
        .add_allowed_host("*.example.org".to_string())
        .unwrap()
        .add_denied_host("example.net".to_string())
        .unwrap()
        .add_allowed_port_range(8080..=8080)
        .unwrap()
        .add_denied_port_range(8443..=8443)
        .unwrap()
        .add_allowed_ip_range("1.0.0.0/8".parse::<IpNet>().unwrap())
        .unwrap()
        .add_denied_ip_range("9.0.0.0/8".parse::<IpNet>().unwrap())
        .unwrap()
        .build();

    // Check if a request is allowed
    assert!(acl.is_host_allowed("example.com").is_allowed());
    assert!(acl.is_host_allowed("foo.example.org").is_allowed());
    assert!(!acl.is_host_allowed("example.net").is_allowed());
    assert!(acl.is_port_allowed(8080).is_allowed());
    assert!(!acl.is_port_allowed(8443).is_allowed());
    assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
    assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
    assert!(acl
        .is_ip_allowed(&"192.168.1.1".parse().unwrap())
        .is_denied());

    Ok(())
}
```

## Wildcard hosts

Allowed/denied hosts may be exact hostnames or wildcard patterns, matched label-by-label:

- `?` matches exactly one label (`?.example.com` matches `foo.example.com`, not `foo.bar.example.com` or bare `example.com`).
- `*` matches one or more labels (`*.example.com` matches `foo.example.com` and `foo.bar.example.com`, but not bare `example.com`).

A wildcard must occupy an entire label - `foo*.example.com` is rejected as an invalid pattern.

Allow-list entries (including wildcard ones) are always checked before deny-list entries, so a broad wildcard allow can shadow a more specific deny - e.g. allowing `*.example.com` while denying `secret.example.com` still allows `secret.example.com`, since the wildcard allow matches first.

## Static DNS mappings

A host can be pinned to a fixed address with `add_static_dns_mapping`, or `add_trusted_static_dns_mapping` if that address should bypass the IP/port ACL entirely. This is enforced by whichever DNS resolver a consuming crate wires up (e.g. `http-acl-reqwest`'s); `http-acl` itself only holds the mappings and exposes `resolve_static_dns_mapping`/`resolve_trusted_static_dns_mapping` for a consumer to look them up.

## Modifying requests and responses

Beyond checking a request, an `HttpAcl` can also carry a `ModifyRequestFn` and a `ModifyResponseFn`. Neither is about allow/deny - they run after the ACL has already decided a request is allowed, and let you rewrite it (or its response) instead. Typical uses:

- **Injecting secrets.** Attach an API key, bearer token, or signature header to every outgoing request without the caller having to know about it or being able to see, override, or leak it themselves - handy when the request is built from untrusted input (e.g. a user-supplied webhook URL) but the credential belongs to your service, not the caller.
- **Adding operational headers.** Stamp a request ID, tracing header, or `User-Agent` onto every outgoing request centrally, rather than at every call site.
- **Sanitising requests before they leave.** Strip a header a caller set that shouldn't reach the destination (distinct from denying the header outright via `add_denied_header`, which rejects the whole request - a `ModifyRequestFn` lets the request through with the header quietly removed instead).
- **Redacting responses.** Strip `Set-Cookie` or other sensitive response headers before they reach application code, or scrub a field out of a JSON response body, so a caller several layers away from the network call never sees it.
- **Normalising responses.** Rewrite an upstream's non-standard status code or error body into something the rest of your application expects, in one place rather than at every call site.

Both hooks are attached the same way as `ValidateFn` - via `HttpAclBuilder::build_full`/`try_build_full`'s `HttpAclHooks` argument, not a dedicated setter - since they're typically closures capturing state from outside the builder (a secret, a request-scoped ID generator, and so on):

```rust
use http_acl::{HttpAcl, HttpAclHooks};
use std::sync::Arc;

let api_key = "super-secret-api-key".to_string();

let acl = HttpAcl::builder().build_full(HttpAclHooks {
    // Inject a secret the caller never sees or controls.
    modify_request_fn: Some(Arc::new(move |_scheme, _authority, mutation| {
        mutation
            .headers
            .push(("x-api-key".to_string(), api_key.clone()));
    })),
    // Strip a header before the caller ever sees the response.
    modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
        mutation.headers.retain(|(name, _)| name != "set-cookie");
    })),
    ..Default::default()
});
```

Check `HttpAcl::has_modify_request`/`has_modify_response` before doing any work to make a request/response available for mutation (e.g. buffering a body): a consuming crate should skip that work entirely when the corresponding hook isn't configured, so the feature costs nothing unless you use it. [`http-acl-reqwest`](https://docs.rs/http-acl-reqwest) does exactly this - see its README for the concrete performance trade-off of enabling `ModifyResponseFn`, and for more end-to-end examples.

## Integrating with a different HTTP client

`http-acl` is client-agnostic: it only classifies requests, it never makes them or touches the network itself. [`http-acl-reqwest`](https://docs.rs/http-acl-reqwest) is one integration, for [reqwest](https://docs.rs/reqwest); wiring up another client (`hyper`, `ureq`, `isahc`, or your own) means covering the same three places yourself.

**1. Before the request is sent**, check whatever you can read off the request as built:

```rust
use http_acl::{
    HttpAcl,
    utils::authority::{Authority, Host},
};

fn check_request(
    acl: &HttpAcl,
    scheme: &str,
    method: &str,
    authority: &str,
    headers: &[(&str, &str)],
    url_path: &str,
    body: Option<&[u8]>,
) -> Result<(), String> {
    if acl.is_scheme_allowed(scheme).is_denied() {
        return Err(format!("scheme {scheme} is denied"));
    }
    if acl.is_method_allowed(method).is_denied() {
        return Err(format!("method {method} is denied"));
    }

    let authority = Authority::parse(authority).map_err(|_| "invalid host".to_string())?;
    match &authority.host {
        Host::Ip(ip) if acl.is_ip_allowed(ip).is_denied() => {
            return Err(format!("ip {ip} is denied"));
        }
        Host::Domain(domain) if acl.is_host_allowed(domain).is_denied() => {
            return Err(format!("host {domain} is denied"));
        }
        _ => {}
    }
    if acl.is_port_allowed(authority.port).is_denied() {
        return Err(format!("port {} is denied", authority.port));
    }
    for (name, value) in headers.iter().copied() {
        if acl.is_header_allowed(name, value).is_denied() {
            return Err(format!("header {name} is denied"));
        }
    }
    if acl.is_url_path_allowed(url_path).is_denied() {
        return Err(format!("path {url_path} is denied"));
    }
    if acl
        .is_valid(scheme, &authority, headers.iter().copied(), body)
        .is_denied()
    {
        return Err("request failed custom validation".to_string());
    }

    Ok(())
}

fn main() {
    let acl = HttpAcl::builder()
        .add_denied_host("example.com".to_string())
        .unwrap()
        .build();

    let result = check_request(
        &acl,
        "https",
        "GET",
        "example.com:443",
        &[("accept", "*/*")],
        "/",
        None,
    );
    assert!(result.is_err());
}
```

`is_url_path_allowed` expects a percent-decoded path; most URL types (including `url::Url`, which both `http-acl` and `reqwest` use) return the path percent-encoded, so decode it first if it might contain encoded characters.

**2. At DNS resolution**, if your client lets you plug in a resolver, filter what it returns rather than trusting the host check in step 1 alone: a domain that passes `is_host_allowed` can still resolve to a denied or private IP, which is the classic SSRF vector this crate exists for. Check `resolve_trusted_static_dns_mapping` first and return it as-is if present, then `resolve_static_dns_mapping` and check it against `is_ip_allowed`/`is_port_allowed`, then fall back to real resolution and filter those results the same way. `http-acl-reqwest`'s `HttpAclDnsResolver` does exactly this and is a reasonable template to copy.

**3. On redirects**, a request to an allowed host can still be redirected to a denied one. If your client follows redirects internally, look for a hook to intercept each hop (like reqwest's `redirect::Policy::custom`, which `http-acl-reqwest`'s `HttpAclMiddleware::redirect_policy` uses) and re-run the checks from step 1 against the new URL; otherwise disable automatic redirects and follow them yourself, checking each hop before you do.

A client that doesn't give you a hook for one of these three only leaves you able to protect against what's within reach of the other two.

## Documentation

See [docs.rs](https://docs.rs/http-acl).
