# http-acl-wasmtime

An ACL for the outgoing HTTP requests of a WebAssembly guest run by wasmtime-wasi-http.

## Why?

A guest that can make HTTP requests can be pointed at internal services (SSRF), either directly or through a domain that resolves to a private address. wasmtime-wasi-http has no ACL of its own, but it sends every outgoing request through `WasiHttpView::send_request`, which the embedder can override. This crate is what that override calls.

## What it checks

- `check_request` checks the request's method, scheme, port and URL path, in that order. The path is checked percent-decoded and with dot segments resolved, so `/%61dmin` and `/x/../admin` do not pass a denied `/admin`. It returns a `Refusal` that names the reason (`method`, `scheme`, `port` or `path`) and the host, for the embedder's log.
- `send_request_handler` sends the request as wasmtime-wasi-http's default handler does, except that it checks the host, uses the ACL's static and trusted static DNS mappings, resolves the host itself and checks **every** address the resolver returns before it connects, and applies the ACL's `ModifyRequestFn` and `ModifyResponseFn`. A host or address denial comes back as `ErrorCode::InternalError` with a message that starts `Host ` or `IP `.

Headers are not checked here: check them in your `send_request` with the ACL's `is_header_allowed` if you need to.

## Usage

Depend on wasmtime-wasi-http with `default-features = false`, so that `send_request` has no default and a view that forgets to override it does not compile.

```rust,ignore
impl WasiHttpView for MyState {
    // ctx() and table() as usual.

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let config = match http_acl_wasmtime::check_request(&request, config, self.acl.clone()) {
            Ok(config) => config,
            Err(refusal) => {
                if let Some((reason, host)) = refusal.denial() {
                    tracing::warn!(reason, host, "outbound request denied");
                }
                return Err(refusal.into_error().into());
            }
        };
        Ok(HostFutureIncomingResponse::pending(wasmtime_wasi::runtime::spawn(async move {
            Ok(http_acl_wasmtime::send_request_handler(request, config).await)
        })))
    }
}
```

## Versions

This release line is for wasmtime-wasi-http 36.

## Licence

Apache-2.0. `send_request_handler` is derived from wasmtime-wasi-http 36.0.19's `default_send_request_handler` (the Bytecode Alliance contributors, Apache-2.0 WITH LLVM-exception); the changes are listed in the crate documentation.
