#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::borrow::Cow;
use std::future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use bytes::Bytes;
use http::Extensions;
use http::header::{HeaderName, HeaderValue};
use http_acl::utils::authority::{Authority, Host};
use reqwest::{
    Body, Request, Response, ResponseBuilderExt,
    dns::{Name, Resolve, Resolving},
    redirect,
};
use reqwest_middleware::{Error, Middleware, Next};
use thiserror::Error;

pub use http_acl::{
    self, HttpAcl, HttpAclBuilder, HttpAclHooks, ModifyRequestFn, ModifyResponseFn,
    RequestMutation, ResponseMutation, ValidateFn,
};

#[derive(Debug, Clone)]
/// A reqwest middleware that enforces an [`HttpAcl`].
///
/// On each request, checks (in order) the scheme, method, host or IP, port, headers,
/// URL path, and finally any custom `ValidateFn`, returning
/// [`reqwest_middleware::Error::Middleware`] on the first denial. This alone only
/// covers the request as originally built: attach [`Self::dns_resolver`] to the
/// `Client` as well, so domains are checked against the ACL as they resolve, and
/// [`Self::redirect_policy`], so redirect targets are checked too. See the crate-level
/// documentation for a full example wiring all three together.
///
/// If the `HttpAcl` has a `ModifyRequestFn` and/or `ModifyResponseFn` attached (see
/// `HttpAclHooks`), those run too - a `ModifyRequestFn` once all the checks above
/// pass and just before the request is sent, and a `ModifyResponseFn` on the way
/// back, before the caller ever sees the `Response`. Neither is applied when not
/// configured - see `HttpAcl::has_modify_request`/`has_modify_response`. A
/// configured `ModifyResponseFn` forces the whole response body to be buffered and
/// the response rebuilt from scratch; see the crate README for the performance
/// trade-off.
///
/// Header values that are not valid UTF-8 (`obs-text` bytes 0x80-0xFF) are not
/// refused. The header ACL compares them as raw bytes
/// (`HttpAcl::is_header_allowed_bytes`); a `ValidateFn` and the mutation hooks see
/// them lossily decoded (U+FFFD), and a value a hook leaves unchanged is sent or
/// returned with its original bytes.
pub struct HttpAclMiddleware {
    acl: Arc<HttpAcl>,
}

impl HttpAclMiddleware {
    /// Create a new HTTP ACL middleware from an already-built [`HttpAcl`].
    pub fn new(acl: HttpAcl) -> Self {
        Self { acl: Arc::new(acl) }
    }

    /// Get the [`HttpAcl`] this middleware enforces.
    pub fn acl(&self) -> Arc<HttpAcl> {
        self.acl.clone()
    }

    /// Create a DNS resolver that enforces the ACL, using `getaddrinfo` to actually
    /// resolve hostnames.
    ///
    /// Set via `Client::builder().dns_resolver(...)`. Without this, a domain that
    /// resolves to a denied or non-global IP (the classic SSRF vector) is never
    /// checked, since [`HttpAclMiddleware`] only ever sees the request as built, not
    /// the address it eventually connects to.
    pub fn dns_resolver(&self) -> Arc<HttpAclDnsResolver> {
        Arc::new(HttpAclDnsResolver::new(self))
    }

    /// Same as [`Self::dns_resolver`], but delegating actual resolution to a custom
    /// [`Resolve`] implementation instead of `getaddrinfo`.
    pub fn with_dns_resolver(&self, dns_resolver: Arc<dyn Resolve>) -> Arc<HttpAclDnsResolver> {
        Arc::new(HttpAclDnsResolver::with_dns_resolver(self, dns_resolver))
    }

    /// Create a [`redirect::Policy`] that enforces the ACL on every redirect hop.
    ///
    /// # Why this is necessary
    ///
    /// `HttpAclMiddleware` only validates the request it is given. By default `reqwest`
    /// follows HTTP redirects internally (up to 10 hops) before control ever returns to
    /// the middleware chain, so a server an allowed host redirects to - e.g. a `302` to
    /// `http://169.254.169.254/` - is never re-checked against the ACL. Set this policy
    /// on the `Client` (in addition to [`Self::dns_resolver`]) to close that gap:
    ///
    /// ```no_run
    /// # use http_acl_reqwest::HttpAclMiddleware;
    /// # use http_acl::HttpAcl;
    /// # let middleware = HttpAclMiddleware::new(HttpAcl::builder().build());
    /// let client = reqwest::Client::builder()
    ///     .dns_resolver(middleware.dns_resolver())
    ///     .redirect(middleware.redirect_policy())
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// Uses a maximum of 10 redirects, matching `reqwest`'s own default. Use
    /// [`Self::redirect_policy_with_max`] to customise this.
    ///
    /// # Limitations
    ///
    /// Only the scheme, host/IP, port, and URL path of each redirect target can be
    /// checked this way - `reqwest`'s redirect policy does not expose the headers or
    /// body of the redirected request, so denied headers, denied bodies, and any custom
    /// `validate_fn` are not re-evaluated per hop. `ModifyResponseFn` only ever sees
    /// the final response of a redirect chain, never an intermediate `3xx`, for the
    /// same reason.
    ///
    /// `ModifyRequestFn` is different: it's called once, against the original
    /// outgoing request, before `Middleware::handle` hands it to `reqwest`, but a
    /// header it injects is - like any header set before `send()` - carried forward
    /// by `reqwest`'s own redirect handling to every subsequent hop (`reqwest` may
    /// still strip specific headers, e.g. `Authorization`, when a redirect crosses
    /// origins). So an injected header reaches the whole chain even though the
    /// closure itself does not run again.
    pub fn redirect_policy(&self) -> redirect::Policy {
        self.redirect_policy_with_max(10)
    }

    /// Same as [`Self::redirect_policy`], but with a custom maximum number of redirects.
    pub fn redirect_policy_with_max(&self, max_redirects: usize) -> redirect::Policy {
        let acl = self.acl.clone();
        redirect::Policy::custom(move |attempt| {
            // `Attempt::error`/`follow`/`stop` consume `attempt` by value, so the denial
            // reason (if any) is computed into an owned `String` first, in its own scope,
            // to release the borrow of `attempt` held by `attempt.url()`/`attempt.previous()`.
            let deny_reason = 'reason: {
                if attempt.previous().len() > max_redirects {
                    break 'reason Some("too many redirects".to_string());
                }

                let url = attempt.url();

                let scheme = url.scheme();
                if acl.is_scheme_allowed(scheme).is_denied() {
                    break 'reason Some(format!("scheme {scheme} is denied"));
                }

                let Some(host) = url.host() else {
                    break 'reason Some("missing host".to_string());
                };

                match host {
                    url::Host::Domain(domain) => {
                        if acl.is_host_allowed(domain).is_denied() {
                            break 'reason Some(format!("host {domain} is denied"));
                        }
                    }
                    url::Host::Ipv4(ip) => {
                        let ip = std::net::IpAddr::V4(ip);
                        if acl.is_ip_allowed(&ip).is_denied() {
                            break 'reason Some(format!("ip {ip} is denied"));
                        }
                    }
                    url::Host::Ipv6(ip) => {
                        let ip = std::net::IpAddr::V6(ip);
                        if acl.is_ip_allowed(&ip).is_denied() {
                            break 'reason Some(format!("ip {ip} is denied"));
                        }
                    }
                }

                if let Some(port) = url.port_or_known_default()
                    && acl.is_port_allowed(port).is_denied()
                {
                    break 'reason Some(format!("port {port} is denied"));
                }

                // `Url::path()` is percent-encoded; `is_url_path_allowed` expects a
                // decoded path.
                match percent_encoding::percent_decode_str(url.path()).decode_utf8() {
                    Ok(path) => {
                        if acl.is_url_path_allowed(&path).is_denied() {
                            break 'reason Some(format!("path {path} is denied"));
                        }
                    }
                    Err(_) => break 'reason Some("invalid URL path encoding".to_string()),
                }

                None
            };

            match deny_reason {
                Some(reason) => attempt.error(std::io::Error::other(reason)),
                None => attempt.follow(),
            }
        })
    }
}

#[async_trait::async_trait]
impl Middleware for HttpAclMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> std::result::Result<Response, Error> {
        // Owned, rather than borrowed from `req.url()`, since it's still needed
        // after `req` is moved into `next.run(...)` below (to check the response
        // against `ModifyResponseFn`).
        let scheme = req.url().scheme().to_string();
        let acl_scheme_match = self.acl.is_scheme_allowed(&scheme);
        if acl_scheme_match.is_denied() {
            return Err(Error::Middleware(anyhow!(
                "scheme {} is denied - {}",
                scheme,
                acl_scheme_match
            )));
        }

        let method = req.method().as_str();
        let acl_method_match = self.acl.is_method_allowed(method);
        if acl_method_match.is_denied() {
            return Err(Error::Middleware(anyhow!(
                "method {} is denied - {}",
                method,
                acl_method_match
            )));
        }

        if let Some(host) = req.url().host_str() {
            let authority = Authority::parse(host)
                .map_err(|_| Error::Middleware(anyhow!("invalid host: {}", host)))?;

            match &authority.host {
                Host::Ip(ip) => {
                    let acl_ip_match = self.acl.is_ip_allowed(ip);
                    if acl_ip_match.is_denied() {
                        return Err(Error::Middleware(anyhow!(
                            "ip {} is denied - {}",
                            ip,
                            acl_ip_match
                        )));
                    }
                }
                Host::Domain(domain) => {
                    let acl_host_match = self.acl.is_host_allowed(domain);
                    if acl_host_match.is_denied() {
                        return Err(Error::Middleware(anyhow!(
                            "host {} is denied - {}",
                            domain,
                            acl_host_match
                        )));
                    }
                }
            }

            if let Some(port) = req.url().port_or_known_default() {
                let acl_port_match = self.acl.is_port_allowed(port);
                if acl_port_match.is_denied() {
                    return Err(Error::Middleware(anyhow!(
                        "port {} is denied - {}",
                        port,
                        acl_port_match
                    )));
                }
            }

            // Header values may carry obs-text bytes (0x80-0xFF) that are not valid
            // UTF-8, so they are checked as raw bytes rather than refused.
            for (key, value) in req.headers() {
                let header_name = key.as_str();
                let acl_header_match = self
                    .acl
                    .is_header_allowed_bytes(header_name, value.as_bytes());
                if acl_header_match.is_denied() {
                    return Err(Error::Middleware(anyhow!(
                        "header {}: {} is denied - {}",
                        header_name,
                        header_value_lossy(value),
                        acl_header_match
                    )));
                }
            }

            // `Url::path()` is percent-encoded; `is_url_path_allowed` expects a
            // decoded path.
            let url_path = percent_encoding::percent_decode_str(req.url().path())
                .decode_utf8()
                .map_err(|_| Error::Middleware(anyhow!("invalid URL path encoding")))?;
            let acl_url_path_match = self.acl.is_url_path_allowed(&url_path);
            if acl_url_path_match.is_denied() {
                return Err(Error::Middleware(anyhow!(
                    "path {} is denied - {}",
                    url_path,
                    acl_url_path_match
                )));
            }

            // Every header reaches the `ValidateFn`, a non-UTF-8 value lossily
            // decoded, so a custom check keyed on a header cannot be bypassed by
            // putting obs-text bytes in it.
            let lossy_headers: Vec<(&str, Cow<'_, str>)> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str(), header_value_lossy(v)))
                .collect();
            let valid_match = self.acl.is_valid(
                &scheme,
                &authority,
                lossy_headers.iter().map(|(k, v)| (*k, v.as_ref())),
                req.body().and_then(|b| b.as_bytes()),
            );
            if valid_match.is_denied() {
                return Err(Error::Middleware(anyhow!(
                    "request is denied - {}",
                    valid_match
                )));
            }

            if self.acl.has_modify_request() {
                let (headers, mut raw_headers) = mutation_headers(req.headers());
                let mut mutation = RequestMutation {
                    headers,
                    body: req
                        .body()
                        .and_then(|b| b.as_bytes())
                        .map(Bytes::copy_from_slice),
                };
                self.acl.modify_request(&scheme, &authority, &mut mutation);

                req.headers_mut().clear();
                for (name, value) in &mutation.headers {
                    let header_name = HeaderName::from_str(name).map_err(|e| {
                        Error::Middleware(anyhow!("invalid header name `{name}`: {e}"))
                    })?;
                    let header_value = match take_raw_header(&mut raw_headers, name, value) {
                        Some(raw) => raw,
                        None => HeaderValue::from_str(value).map_err(|e| {
                            Error::Middleware(anyhow!("invalid header value for `{name}`: {e}"))
                        })?,
                    };
                    req.headers_mut().append(header_name, header_value);
                }
                if let Some(body) = mutation.body {
                    *req.body_mut() = Some(Body::from(body));
                }
            }

            let mut res = next.run(req, extensions).await?;

            if self.acl.has_modify_response() {
                let status = res.status();
                let version = res.version();
                let url = res.url().clone();
                let extensions_snapshot = res.extensions().clone();
                let (headers, mut raw_headers) = mutation_headers(res.headers());
                // The point where the whole response body is buffered into memory -
                // only reached when a `ModifyResponseFn` is actually configured.
                let body = res.bytes().await?;

                let mut mutation = ResponseMutation {
                    status: status.as_u16(),
                    headers,
                    body,
                };
                self.acl.modify_response(&scheme, &authority, &mut mutation);

                let mut builder = http::Response::builder()
                    .status(mutation.status)
                    .version(version);
                for (name, value) in &mutation.headers {
                    builder = match take_raw_header(&mut raw_headers, name, value) {
                        Some(raw) => builder.header(name.as_str(), raw),
                        None => builder.header(name.as_str(), value.as_str()),
                    };
                }
                // `Response`'s own `Extensions` (distinct from the `extensions`
                // parameter of this function) carries things like `HttpInfo`
                // (backing `Response::remote_addr()`) - restore it here, before
                // `.url(...)`, not after: `.url()` inserts its own extension entry,
                // and a wholesale `*extensions_mut() = ...` afterwards would
                // clobber that again.
                if let Some(ext) = builder.extensions_mut() {
                    *ext = extensions_snapshot;
                }
                let http_response = builder
                    .url(url)
                    .body(mutation.body)
                    .map_err(|e| Error::Middleware(anyhow!("failed to rebuild response: {e}")))?;
                res = Response::from(http_response);
            }

            Ok(res)
        } else {
            return Err(Error::Middleware(anyhow!("missing host")));
        }
    }
}

/// Decodes a header value for the `&str`-based ACL hooks: exact for UTF-8, lossy
/// (U+FFFD) for obs-text bytes that are not valid UTF-8.
fn header_value_lossy(value: &HeaderValue) -> Cow<'_, str> {
    String::from_utf8_lossy(value.as_bytes())
}

/// A header whose value is not valid UTF-8: its name, its lossy decode as handed
/// to a mutation hook, and its original bytes.
type RawHeader = (String, String, HeaderValue);

/// Builds the `(name, value)` list handed to a mutation hook, plus the original
/// bytes of every value that could only be decoded lossily, so a header the hook
/// leaves untouched goes back out with its bytes unchanged rather than dropped or
/// rewritten as U+FFFD.
fn mutation_headers(headers: &http::HeaderMap) -> (Vec<(String, String)>, Vec<RawHeader>) {
    let mut raw = Vec::new();
    let list = headers
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().to_string();
            let value = header_value_lossy(v).into_owned();
            if std::str::from_utf8(v.as_bytes()).is_err() {
                raw.push((name.clone(), value.clone(), v.clone()));
            }
            (name, value)
        })
        .collect();
    (list, raw)
}

/// Returns (and consumes) the original bytes of a header the hook left as it was
/// given, matched on name and lossy value.
fn take_raw_header(raw: &mut Vec<RawHeader>, name: &str, value: &str) -> Option<HeaderValue> {
    let index = raw
        .iter()
        .position(|(n, v, _)| n.eq_ignore_ascii_case(name) && v == value)?;
    Some(raw.remove(index).2)
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

struct GaiResolver;

impl Resolve for GaiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            // `Name` is a bare hostname with no port, so `ToSocketAddrs` must be given one
            // explicitly (e.g. via a tuple) - calling it on the string directly always fails.
            let addresses = (name.as_str(), 0)
                .to_socket_addrs()
                .map_err(|e| Box::new(e) as BoxError)?;
            Ok(Box::new(addresses.into_iter()) as Box<dyn Iterator<Item = SocketAddr> + Send>)
        })
    }
}

/// A [`Resolve`]r that checks each resolved address against an [`HttpAcl`] before
/// handing it back to `reqwest`.
///
/// Denies the hostname itself first via [`HttpAcl::is_host_allowed`]. For the
/// addresses it resolves to, a trusted static DNS mapping (see
/// [`HttpAclBuilder::add_trusted_static_dns_mapping`]) is returned as-is; a regular
/// static mapping or a genuinely resolved address is
/// filtered through [`HttpAcl::is_ip_allowed`] and [`HttpAcl::is_port_allowed`], so
/// only addresses the ACL permits are ever handed to `reqwest`. Constructed via
/// [`HttpAclMiddleware::dns_resolver`] or [`HttpAclMiddleware::with_dns_resolver`],
/// not directly.
pub struct HttpAclDnsResolver {
    dns_resolver: Arc<dyn Resolve>,
    acl: Arc<HttpAcl>,
}

impl HttpAclDnsResolver {
    /// Create a new ACL resolver that resolves hostnames via `getaddrinfo`.
    pub fn new(middleware: &HttpAclMiddleware) -> Self {
        Self {
            dns_resolver: Arc::new(GaiResolver),
            acl: middleware.acl(),
        }
    }

    /// Create a new ACL resolver that delegates actual resolution to a custom
    /// [`Resolve`] implementation.
    pub fn with_dns_resolver(
        middleware: &HttpAclMiddleware,
        dns_resolver: Arc<dyn Resolve>,
    ) -> Self {
        Self {
            dns_resolver,
            acl: middleware.acl(),
        }
    }
}

impl Resolve for HttpAclDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        if self.acl.is_host_allowed(name.as_str()).is_denied() {
            let err: BoxError = Box::new(HttpAclError::HostDenied {
                host: name.as_str().to_string(),
            });
            return Box::pin(future::ready(Err(err)));
        }

        let acl = self.acl.clone();
        let resolver = self.dns_resolver.clone();

        Box::pin(async move {
            if let Some(tcp_address) = acl.resolve_trusted_static_dns_mapping(name.as_str()) {
                // Trusted mappings intentionally bypass the IP/port ACL - the caller
                // vouches for this destination (e.g. pinning a hostname to an internal
                // address on purpose).
                Ok(Box::new(std::iter::once(tcp_address))
                    as Box<dyn Iterator<Item = SocketAddr> + Send>)
            } else if let Some(tcp_address) = acl.resolve_static_dns_mapping(name.as_str()) {
                // Regular static mappings must still pass the IP/port ACL, just like
                // resolved addresses do below - otherwise they'd be a way to bypass it
                // entirely (e.g. mapping a host to a private IP while non-global IPs
                // are denied).
                if acl.is_ip_allowed(&tcp_address.ip()).is_allowed()
                    && acl.is_port_allowed(tcp_address.port()).is_allowed()
                {
                    Ok(Box::new(std::iter::once(tcp_address))
                        as Box<dyn Iterator<Item = SocketAddr> + Send>)
                } else {
                    let err: BoxError =
                        Box::new(std::io::Error::other("Static DNS mapping denied by ACL"));
                    Err(err)
                }
            } else {
                let resolved = resolver.resolve(name).await;
                match resolved {
                    Ok(addresses) => {
                        let filtered = addresses
                            .into_iter()
                            .filter(|addr| {
                                acl.is_ip_allowed(&addr.ip()).is_allowed()
                                    && acl.is_port_allowed(addr.port()).is_allowed()
                            })
                            .collect::<Vec<_>>();
                        Ok(Box::new(filtered.into_iter())
                            as Box<dyn Iterator<Item = SocketAddr> + Send>)
                    }
                    Err(e) => Err(e),
                }
            }
        })
    }
}

#[derive(Error, Debug)]
/// An error that can occur when resolving a host.
///
/// Returned by [`HttpAclDnsResolver`] when a hostname itself is denied by the ACL.
/// Downcast the boxed error from a failed resolution to check for this specifically,
/// as opposed to a lower-level resolution failure.
pub enum HttpAclError {
    /// Host resolution denied by ACL.
    #[error("Host resolution denied by ACL: {host}")]
    HostDenied {
        /// The host that was denied.
        host: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_acl::acl::AclClassification;
    use reqwest_middleware::ClientWithMiddleware;

    #[tokio::test]
    async fn test_http_acl_middleware() {
        let acl = HttpAcl::builder()
            .add_denied_host("example.com".to_string())
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let request = client.get("http://example.com/").send().await;

        assert!(request.is_err());
        assert_eq!(
            request.unwrap_err().to_string(),
            "host example.com is denied - The entity is denied according to the denied ACL."
        );
    }

    #[tokio::test]
    async fn test_middleware_decodes_percent_encoded_path() {
        let acl = HttpAcl::builder()
            .add_allowed_host("example.com".to_string())
            .unwrap()
            .add_denied_url_path("/secret file".to_string())
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client =
            reqwest_middleware::ClientBuilder::new(reqwest::Client::builder().build().unwrap())
                .with(middleware)
                .build();

        // Regression test: `Url::path()` is percent-encoded ("%20" for the space
        // here), but `is_url_path_allowed` matches against the decoded path, so the
        // middleware must decode before checking - otherwise this denied path would
        // never match and the request would go through.
        let request = client.get("http://example.com/secret%20file").send().await;

        assert!(request.is_err());
        assert!(
            request
                .unwrap_err()
                .to_string()
                .contains("path /secret file is denied")
        );
    }

    #[tokio::test]
    async fn test_dns_resolver_returns_typed_error_for_denied_host() {
        let acl = HttpAcl::builder()
            .add_denied_host("denied.example.com".to_string())
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);
        let resolver = middleware.dns_resolver();

        let name: reqwest::dns::Name = "denied.example.com".parse().unwrap();
        let err = match resolver.resolve(name).await {
            Ok(_) => panic!("expected resolution to be denied"),
            Err(e) => e,
        };

        let acl_err = err
            .downcast_ref::<HttpAclError>()
            .expect("expected a HttpAclError");
        assert!(matches!(
            acl_err,
            HttpAclError::HostDenied { host } if host == "denied.example.com"
        ));
    }

    #[tokio::test]
    async fn test_dns_resolver_resolves_hostnames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        // Regression test: the default `GaiResolver` used to call `to_socket_addrs()` on a
        // bare hostname (no port), which always errors, so *no* hostname could ever resolve.
        let request = client
            .get(format!("http://localhost:{}/", addr.port()))
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
    }

    #[tokio::test]
    async fn test_trusted_static_dns_mapping_bypasses_ip_port_acl() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Deny everything at the IP/port level (the default), but pin "trusted.internal"
        // to our mock server via a *trusted* static mapping, which should bypass that.
        let acl = HttpAcl::builder()
            .host_acl_default(true)
            .add_trusted_static_dns_mapping("trusted.internal".to_string(), addr)
            .unwrap()
            .build();

        assert!(acl.is_ip_allowed(&addr.ip()).is_denied());
        assert!(acl.is_port_allowed(addr.port()).is_denied());

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        // No explicit port in the URL - the connector must pick up the trusted
        // mapping's port, proving both the IP and port ACL were bypassed for it.
        let request = client.get("http://trusted.internal/").send().await;

        assert!(request.is_ok(), "{:?}", request.err());
    }

    #[tokio::test]
    async fn test_redirect_policy_blocks_disallowed_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 302 Found\r\nLocation: http://192.168.1.1/\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Allow everything except one specific (non-global) IP, so the initial request to
        // our local mock server succeeds but the redirect target is denied.
        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .add_denied_ip_range((
                "192.168.1.1".parse::<std::net::IpAddr>().unwrap(),
                "192.168.1.1".parse::<std::net::IpAddr>().unwrap(),
            ))
            .unwrap()
            .build();

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .redirect(middleware.redirect_policy())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let request = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .send()
            .await;

        assert!(request.is_err());
    }

    #[test]
    fn test_no_hooks_configured_leaves_acl_unaffected() {
        let acl = HttpAcl::builder().build();

        assert!(!acl.has_modify_request());
        assert!(!acl.has_modify_response());
    }

    #[tokio::test]
    async fn test_modify_request_injects_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = captured_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_request_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation
                        .headers
                        .push(("x-injected-secret".to_string(), "sssh".to_string()));
                })),
                ..Default::default()
            });

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let request = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
        let captured = captured_rx.await.unwrap();
        assert!(
            captured.to_lowercase().contains("x-injected-secret: sssh"),
            "captured request did not contain the injected header:\n{captured}"
        );
    }

    #[tokio::test]
    async fn test_modify_request_replaces_body_and_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = captured_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let new_body = "a much longer replacement body than the original";
        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_request_fn: Some(Arc::new(move |_scheme, _authority, mutation| {
                    mutation.body = Some(Bytes::from(new_body));
                })),
                ..Default::default()
            });

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let request = client
            .post(format!("http://127.0.0.1:{}/", addr.port()))
            .body("short")
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
        let captured = captured_rx.await.unwrap();
        assert!(
            captured.contains(&format!("content-length: {}", new_body.len()))
                || captured.contains(&format!("Content-Length: {}", new_body.len())),
            "captured request did not have a Content-Length matching the replaced body:\n{captured}"
        );
        assert!(
            captured.ends_with(new_body),
            "captured request did not end with the replaced body:\n{captured}"
        );
    }

    #[tokio::test]
    async fn test_modify_response_rewrites_status_headers_and_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = "original body";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nx-remove-me: yes\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation.status = 201;
                    mutation.headers.retain(|(k, _)| k != "x-remove-me");
                    mutation
                        .headers
                        .push(("x-added".to_string(), "yes".to_string()));
                    mutation.body = Bytes::from_static(b"redacted body");
                })),
                ..Default::default()
            });

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let response = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 201);
        assert!(!response.headers().contains_key("x-remove-me"));
        assert_eq!(response.headers().get("x-added").unwrap(), "yes");
        let body = response.text().await.unwrap();
        assert_eq!(body, "redacted body");
    }

    #[tokio::test]
    async fn test_modify_response_preserves_url_and_remote_addr() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation.body = Bytes::from_static(b"changed");
                })),
                ..Default::default()
            });

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let url = format!("http://127.0.0.1:{}/", addr.port());
        let response = client.get(&url).send().await.unwrap();

        assert_eq!(response.url().as_str(), url);
        assert!(
            response.remote_addr().is_some(),
            "remote_addr() was lost when the response was rebuilt"
        );
    }

    #[tokio::test]
    async fn test_modify_request_header_carries_through_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_addr = second_listener.local_addr().unwrap();

        let (second_captured_tx, second_captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = second_listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = second_captured_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = first_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/\r\nContent-Length: 0\r\n\r\n",
                    second_addr.port()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_request_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation
                        .headers
                        .push(("x-marker".to_string(), "hop-one-only".to_string()));
                })),
                ..Default::default()
            });

        let middleware = HttpAclMiddleware::new(acl);

        let client = reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .redirect(middleware.redirect_policy())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build();

        let request = client
            .get(format!("http://127.0.0.1:{}/", first_addr.port()))
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
        let second_captured = second_captured_rx.await.unwrap();
        // `ModifyRequestFn` only ever runs once, against the original request, but
        // `reqwest`'s own redirect handling carries a header set before `send()`
        // (which is indistinguishable from one injected by the closure) forward to
        // every hop - the header shows up here even though the closure itself
        // never ran again. See the `redirect_policy` doc comment.
        assert!(
            second_captured.to_lowercase().contains("x-marker"),
            "expected the header injected for the original request to carry through \
             reqwest's redirect handling to the second hop, but it did not:\n{second_captured}"
        );
    }

    /// Accepts one connection, captures the raw request bytes, and answers with
    /// `response`.
    async fn capture_server(
        response: &'static [u8],
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = captured_tx.send(buf[..n].to_ascii_lowercase());
                let _ = socket.write_all(response).await;
            }
        });
        (addr, captured_rx)
    }

    fn local_client(hooks: HttpAclHooks, builder: HttpAclBuilder) -> ClientWithMiddleware {
        let acl = builder
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(hooks);
        let middleware = HttpAclMiddleware::new(acl);
        reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .dns_resolver(middleware.dns_resolver())
                .build()
                .unwrap(),
        )
        .with(middleware)
        .build()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    const OK_EMPTY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    #[tokio::test]
    async fn test_obs_text_header_values_are_sent_unchanged() {
        let (addr, captured_rx) = capture_server(OK_EMPTY).await;
        let client = local_client(HttpAclHooks::default(), HttpAcl::builder());

        let request = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .header("cookie", HeaderValue::from_bytes(b"a=caf\xE9").unwrap())
            .header("user-agent", HeaderValue::from_bytes(b"caf\xE9").unwrap())
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
        let captured = captured_rx.await.unwrap();
        assert!(
            contains(&captured, b"cookie: a=caf\xE9\r\n"),
            "{captured:?}"
        );
        assert!(
            contains(&captured, b"user-agent: caf\xE9\r\n"),
            "{captured:?}"
        );
    }

    #[tokio::test]
    async fn test_denied_header_with_obs_text_value_is_still_denied() {
        let client = local_client(
            HttpAclHooks::default(),
            HttpAcl::builder()
                .add_denied_header("cookie".to_string(), None)
                .unwrap(),
        );

        let request = client
            .get("http://127.0.0.1:9/")
            .header("cookie", HeaderValue::from_bytes(b"a=caf\xE9").unwrap())
            .send()
            .await;

        let error = request.unwrap_err().to_string();
        assert!(error.starts_with("header cookie: "), "{error}");
        assert!(error.contains("is denied"), "{error}");
    }

    #[tokio::test]
    async fn test_allowed_header_value_is_compared_as_raw_bytes() {
        // A lossy decode turns 0xE9 into U+FFFD, so comparing lossily would let
        // `caf\xE9` match an allow-listed `caf\u{FFFD}`.
        let builder = || {
            HttpAcl::builder()
                .add_allowed_header("x-token".to_string(), Some("caf\u{FFFD}".to_string()))
                .unwrap()
        };

        let client = local_client(HttpAclHooks::default(), builder());
        let request = client
            .get("http://127.0.0.1:9/")
            .header("x-token", HeaderValue::from_bytes(b"caf\xE9").unwrap())
            .send()
            .await;
        let error = request.unwrap_err().to_string();
        assert!(error.starts_with("header x-token: "), "{error}");

        let (addr, captured_rx) = capture_server(OK_EMPTY).await;
        let client = local_client(HttpAclHooks::default(), builder());
        let request = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .header(
                "x-token",
                HeaderValue::from_bytes("caf\u{FFFD}".as_bytes()).unwrap(),
            )
            .send()
            .await;
        assert!(request.is_ok(), "{:?}", request.err());
        let captured = captured_rx.await.unwrap();
        assert!(
            contains(&captured, "x-token: caf\u{FFFD}\r\n".as_bytes()),
            "{captured:?}"
        );
    }

    #[tokio::test]
    async fn test_validate_fn_sees_obs_text_headers() {
        // A `ValidateFn` must not have an obs-text header hidden from it, or a
        // custom denial keyed on that header could be bypassed.
        let client = local_client(
            HttpAclHooks {
                validate_fn: Some(Arc::new(|_scheme, _authority, mut headers, _body| {
                    if headers.any(|(k, v)| k == "cookie" && v == "a=caf\u{FFFD}") {
                        AclClassification::Denied("cookie seen".to_string())
                    } else {
                        AclClassification::AllowedDefault
                    }
                })),
                ..Default::default()
            },
            HttpAcl::builder(),
        );

        let request = client
            .get("http://127.0.0.1:9/")
            .header("cookie", HeaderValue::from_bytes(b"a=caf\xE9").unwrap())
            .send()
            .await;

        let error = request.unwrap_err().to_string();
        assert!(error.contains("cookie seen"), "{error}");
    }

    #[tokio::test]
    async fn test_modify_request_keeps_obs_text_header_bytes() {
        let (addr, captured_rx) = capture_server(OK_EMPTY).await;
        let client = local_client(
            HttpAclHooks {
                modify_request_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation.headers.retain(|(k, _)| k != "x-drop-me");
                    mutation
                        .headers
                        .push(("x-injected".to_string(), "yes".to_string()));
                })),
                ..Default::default()
            },
            HttpAcl::builder(),
        );

        let request = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .header("cookie", HeaderValue::from_bytes(b"a=caf\xE9").unwrap())
            .header("x-drop-me", HeaderValue::from_bytes(b"caf\xE9").unwrap())
            .send()
            .await;

        assert!(request.is_ok(), "{:?}", request.err());
        let captured = captured_rx.await.unwrap();
        assert!(
            contains(&captured, b"cookie: a=caf\xE9\r\n"),
            "{captured:?}"
        );
        assert!(contains(&captured, b"x-injected: yes\r\n"), "{captured:?}");
        assert!(!contains(&captured, b"x-drop-me"), "{captured:?}");
    }

    #[tokio::test]
    async fn test_modify_response_keeps_obs_text_header_bytes() {
        let (addr, _captured_rx) =
            capture_server(b"HTTP/1.1 200 OK\r\nx-raw: caf\xE9\r\nContent-Length: 2\r\n\r\nok")
                .await;
        let client = local_client(
            HttpAclHooks {
                modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation.body = Bytes::from_static(b"changed");
                })),
                ..Default::default()
            },
            HttpAcl::builder(),
        );

        let response = client
            .get(format!("http://127.0.0.1:{}/", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("x-raw").unwrap().as_bytes(),
            b"caf\xE9"
        );
        assert_eq!(response.text().await.unwrap(), "changed");
    }
}
