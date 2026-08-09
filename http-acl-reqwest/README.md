# http-acl-reqwest

An ACL middleware for reqwest.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

Not using reqwest? See the [`http-acl`](https://docs.rs/http-acl) documentation for how to integrate the underlying ACL with a different HTTP client.

## What it checks

`HttpAclMiddleware` checks a request's scheme, method, host or IP, port, headers, and URL path, in that order, plus any custom `ValidateFn` you've attached to the ACL, denying on the first check that fails. See the [`http-acl`](https://docs.rs/http-acl) documentation for how the allow list, deny list, and per-category default combine for each of these. Beyond checking, the ACL can also carry a `ModifyRequestFn`/`ModifyResponseFn` to rewrite an allowed request or its response instead of denying it - see [Modifying requests and responses](#modifying-requests-and-responses) below.

That covers the request as originally built, which on its own is not enough: a request to an allowed host can still reach a denied address if the hostname resolves to one, or if the server redirects there. Wire up the DNS resolver and redirect policy below to close both gaps.

<div class="warning">
  <blockquote style="background:rgba(255,229,100,0.2);padding:0.75em;margin:0.2em;">
    <strong>Warning:</strong>
    <br>
    The DNS resolver needs to be set on the reqwest Client to ensure that the ACL is enforced. If the DNS resolver is not set, the ACL will not be enforced on IP addresses resolved by the DNS resolver.
    <br><br>
    The redirect policy also needs to be set on the reqwest Client. By default reqwest follows HTTP redirects internally before the middleware ever sees them, so a redirect to a denied host or IP (e.g. an internal address) would otherwise bypass the ACL entirely.
  </blockquote>
</div>

## Usage

```rust
use http_acl_reqwest::{HttpAcl, HttpAclMiddleware};
use reqwest::Client;
use reqwest_middleware::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an HTTP ACL
    let acl = HttpAcl::builder()
        .add_denied_host("example.com".to_string())
        .unwrap()
        .build();

    // Create the HTTP ACL middleware
    let middleware = HttpAclMiddleware::new(acl.clone());

    // Create a reqwest client with the DNS resolver and redirect policy
    let client = Client::builder()
        .dns_resolver(middleware.dns_resolver())
        .redirect(middleware.redirect_policy())
        .build()
        .unwrap();

    // Create a reqwest client with the middleware
    let client_with_middleware = ClientBuilder::new(client)
        .with(middleware)
        .build();

    // Make a request to a denied host
    assert!(client_with_middleware.get("http://example.com/").send().await.is_err());

    Ok(())
}
```

## Static DNS mappings

A hostname can be pinned to a fixed address via `add_static_dns_mapping` and `add_trusted_static_dns_mapping` on the `HttpAcl` builder. The former's resolved address is still checked against the IP/port ACL, like any other resolved address; the latter bypasses that check entirely, so only use it for a mapping you trust regardless of what the ACL would otherwise say (e.g. deliberately pinning a hostname to an internal address). Both need the DNS resolver above to be set to take effect.

## Modifying requests and responses

Attach a `ModifyRequestFn`/`ModifyResponseFn` to the `HttpAcl` (via `HttpAclBuilder::build_full`'s `HttpAclHooks`, see the [`http-acl`](https://docs.rs/http-acl) documentation for the full range of use cases - injecting secrets, adding tracing headers, sanitising requests before they leave, redacting or normalising responses) and `HttpAclMiddleware` applies them automatically: request mutation runs after all ACL checks pass and right before the request is sent, so an injected header is never itself checked against the ACL; response mutation runs on the way back, before the caller ever sees the `Response`.

```rust
use http_acl_reqwest::{HttpAcl, HttpAclHooks, HttpAclMiddleware};
use std::sync::Arc;

let api_key = "super-secret-api-key".to_string();

let acl = HttpAcl::builder().build_full(HttpAclHooks {
    // Inject a secret the caller building the request never sees or controls.
    modify_request_fn: Some(Arc::new(move |_scheme, _authority, mutation| {
        mutation
            .headers
            .push(("x-api-key".to_string(), api_key.clone()));
    })),
    // Strip `Set-Cookie` before the caller ever sees the response.
    modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
        mutation.headers.retain(|(name, _)| name != "set-cookie");
    })),
    ..Default::default()
});
let middleware = HttpAclMiddleware::new(acl);
```

<div class="warning">
  <blockquote style="background:rgba(255,229,100,0.2);padding:0.75em;margin:0.2em;">
    <strong>Performance:</strong>
    <br>
    A configured <code>ModifyResponseFn</code> forces the <em>entire</em> response body to be buffered into memory and the response rebuilt from scratch - for every request the ACL is used with, not just the ones the closure changes. There is no per-request opt-out. If this matters for some traffic but not others, use a separate <code>HttpAcl</code>/<code>HttpAclMiddleware</code> (without a <code>ModifyResponseFn</code>) for the traffic that doesn't need it. With no <code>ModifyRequestFn</code>/<code>ModifyResponseFn</code> attached, behaviour and performance are unchanged from before this feature existed.
    <br><br>
    <strong>Responsibility for header consistency:</strong> if a <code>ModifyResponseFn</code> changes the body's length, it must update or remove <code>Content-Length</code> (and strip <code>Transfer-Encoding</code> if present) itself - the rebuilt response otherwise carries whatever <code>Content-Length</code> was already in the header list, even if it no longer matches. Non-UTF8 response header values are also lossily re-encoded on rebuild, even ones the closure doesn't touch.
    <br><br>
    Neither hook applies to a redirect hop the way you might expect: <code>ModifyRequestFn</code> only ever runs once, against the original outgoing request, and <code>ModifyResponseFn</code> only ever sees the final response of a redirect chain - see the redirect policy limitations above. A header a <code>ModifyRequestFn</code> injects does still reach every hop, though, since reqwest's own redirect handling carries headers set before <code>send()</code> forward regardless of who set them.
  </blockquote>
</div>

## Documentation

See [docs.rs](https://docs.rs/http-acl-reqwest).
