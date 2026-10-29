//! An [`http_acl`] ACL for the outgoing requests of a wasmtime-wasi-http 36 guest.
//!
//! wasmtime-wasi-http hands every outgoing request to [`WasiHttpView::send_request`], after
//! `outgoing-handler.handle` has built it from the guest's method, scheme, authority and path.
//! An embedder that overrides `send_request` calls [`check_request`] first, which checks the
//! request's method, scheme, port and decoded URL path, and then [`send_request_handler`],
//! which checks the host, resolves it itself, checks **every** address the resolver returns
//! before it connects (SSRF and DNS rebinding), and applies the ACL's request and response
//! rewrite hooks.
//!
//! ```ignore
//! fn send_request(
//!     &mut self,
//!     request: hyper::Request<HyperOutgoingBody>,
//!     config: OutgoingRequestConfig,
//! ) -> HttpResult<HostFutureIncomingResponse> {
//!     let config = match http_acl_wasmtime::check_request(&request, config, self.acl.clone()) {
//!         Ok(config) => config,
//!         Err(refusal) => {
//!             if let Some((reason, host)) = refusal.denial() {
//!                 tracing::warn!(reason, host, "outbound request denied");
//!             }
//!             return Err(refusal.into_error().into());
//!         }
//!     };
//!     Ok(HostFutureIncomingResponse::pending(wasmtime_wasi::runtime::spawn(async move {
//!         Ok(http_acl_wasmtime::send_request_handler(request, config).await)
//!     })))
//! }
//! ```
//!
//! Build wasmtime-wasi-http with `default-features = false`: without its
//! `default-send-request` feature `send_request` has no default, so the compiler refuses a
//! view that forgets to override it.
//!
//! Host and address denials come back from [`send_request_handler`] as
//! `ErrorCode::InternalError` with a message starting `Host ` or `IP ` and containing
//! ` is not allowed - `.
//!
//! # Licence and provenance
//!
//! [`send_request_handler`] is wasmtime-wasi-http 36.0.19's `default_send_request_handler`
//! (Copyright the Bytecode Alliance contributors, Apache-2.0 WITH LLVM-exception), as
//! changed in the hisn-io/wasmtime fork, `release-36.0.0` at 05202e1b37. Changed by Hisn.io:
//! the ACL host check, static and trusted static DNS mappings, the resolver run here with
//! every address it returns checked against the ACL, the rewrite hooks, and rustls 0.23 with
//! the aws-lc-rs provider named. [`check_request`] is the fork's checks in
//! `outgoing_handler::Host::handle`, moved here.

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_acl::HttpAcl;
use http_acl::mutation::{RequestMutation, ResponseMutation};
use http_acl::utils::authority::{Authority, Host};
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wasmtime_wasi_http::bindings::http::types::{DnsErrorPayload, ErrorCode};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::hyper_request_error;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{IncomingResponse, OutgoingRequestConfig};

pub use http_acl;

/// An outgoing request's configuration once [`check_request`] has passed it: wasmtime's
/// [`OutgoingRequestConfig`] plus the ACL and the request's parsed authority.
#[derive(Clone, Debug)]
pub struct AclRequestConfig {
    /// Whether to use TLS for the request.
    pub use_tls: bool,
    /// The timeout for connecting.
    pub connect_timeout: Duration,
    /// The timeout until the first byte.
    pub first_byte_timeout: Duration,
    /// The timeout between chunks of a streaming body.
    pub between_bytes_timeout: Duration,
    /// The ACL the request is sent under.
    pub acl: Arc<HttpAcl>,
    /// The request's authority, parsed.
    pub authority: Authority,
}

/// Why [`check_request`] refused a request.
#[derive(Debug)]
pub enum Refusal {
    /// The ACL denied the request's method, scheme, port or URL path.
    Denied {
        /// `"method"`, `"scheme"`, `"port"` or `"path"`.
        reason: &'static str,
        /// The request's host without its port; empty when the authority does not parse.
        host: String,
        /// What goes back to the guest.
        error: ErrorCode,
    },
    /// The request's authority does not parse, so it cannot be checked.
    Invalid(ErrorCode),
}

impl Refusal {
    /// The denial's reason and host, for the embedder's log; `None` for an invalid request.
    pub fn denial(&self) -> Option<(&'static str, &str)> {
        match self {
            Refusal::Denied { reason, host, .. } => Some((reason, host)),
            Refusal::Invalid(_) => None,
        }
    }

    /// The error to return to the guest.
    pub fn into_error(self) -> ErrorCode {
        match self {
            Refusal::Denied { error, .. } | Refusal::Invalid(error) => error,
        }
    }
}

fn internal_error(msg: String) -> ErrorCode {
    ErrorCode::InternalError(Some(msg))
}

fn dns_error(rcode: String, info_code: u16) -> ErrorCode {
    ErrorCode::DnsError(DnsErrorPayload {
        rcode: Some(rcode),
        info_code: Some(info_code),
    })
}

/// The host part of an authority, for a method or scheme denial, found before the authority
/// is parsed; empty when it does not parse.
fn acl_host(authority: &str) -> String {
    Authority::parse(authority)
        .map(|a| a.host.to_string())
        .unwrap_or_default()
}

/// Checks a request's method, scheme, port and URL path against `acl`, in that order, and on
/// success returns the configuration [`send_request_handler`] sends it with.
///
/// The URL path is checked the way the server will read it: percent-decoded, with dot
/// segments resolved, as http-acl's reqwest middleware does, so `/%61dmin` or `/x/../admin`
/// cannot pass a denied `/admin`. A request without a path is sent to `/`, so `/` is what is
/// checked. An authority without a port is checked against its scheme's default port.
pub fn check_request<B>(
    request: &hyper::Request<B>,
    config: OutgoingRequestConfig,
    acl: Arc<HttpAcl>,
) -> Result<AclRequestConfig, Refusal> {
    let uri = request.uri();
    let raw_authority = uri.authority().map(|a| a.as_str()).unwrap_or("");

    let method = request.method().as_str();
    let acl_method_match = acl.is_method_allowed(method);
    if acl_method_match.is_denied() {
        return Err(Refusal::Denied {
            reason: "method",
            host: acl_host(raw_authority),
            error: internal_error(format!(
                "Method {method} is not allowed - {acl_method_match}"
            )),
        });
    }

    let scheme = uri
        .scheme_str()
        .unwrap_or(if config.use_tls { "https" } else { "http" });
    let acl_scheme_match = acl.is_scheme_allowed(scheme);
    if acl_scheme_match.is_denied() {
        return Err(Refusal::Denied {
            reason: "scheme",
            host: acl_host(raw_authority),
            error: internal_error(format!(
                "Scheme {scheme} is not allowed - {acl_scheme_match}"
            )),
        });
    }

    let authority = Authority::parse(raw_authority)
        .map_err(|e| Refusal::Invalid(internal_error(format!("invalid authority: {e}"))))?;
    let port = if authority.port == 0 {
        match scheme {
            "http" => 80,
            "https" => 443,
            _ if config.use_tls => 443,
            _ => 80,
        }
    } else {
        authority.port
    };
    let acl_port_match = acl.is_port_allowed(port);
    if acl_port_match.is_denied() {
        return Err(Refusal::Denied {
            reason: "port",
            host: authority.host.to_string(),
            error: internal_error(format!("Port {port} is not allowed - {acl_port_match}")),
        });
    }

    let raw_path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let raw_path = raw_path.split(['?', '#']).next().unwrap_or("");
    let separator = if raw_path.starts_with('/') { "" } else { "/" };
    let Some(url_path) =
        http_acl::utils::url::get_url_path(&format!("http://acl.invalid{separator}{raw_path}"))
    else {
        return Err(Refusal::Denied {
            reason: "path",
            host: authority.host.to_string(),
            error: internal_error(format!("URL Path {raw_path} is not allowed - invalid path")),
        });
    };
    let acl_url_path_match = acl.is_url_path_allowed(&url_path);
    if acl_url_path_match.is_denied() {
        return Err(Refusal::Denied {
            reason: "path",
            host: authority.host.to_string(),
            error: internal_error(format!(
                "URL Path {url_path} is not allowed - {acl_url_path_match}"
            )),
        });
    }

    let OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    } = config;
    Ok(AclRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
        acl,
        authority,
    })
}

/// Sends a request [`check_request`] passed, as wasmtime-wasi-http's
/// `default_send_request_handler` does, under the ACL: the host is checked, static and
/// trusted static DNS mappings are used, the host is resolved here and every address the
/// resolver returns is checked before the connection is made (a trusted static mapping's is
/// not), and the ACL's `ModifyRequestFn` and `ModifyResponseFn` are applied. Spawn it in a
/// task.
pub async fn send_request_handler(
    mut request: hyper::Request<HyperOutgoingBody>,
    AclRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
        acl,
        authority: authority_parsed,
    }: AclRequestConfig,
) -> Result<IncomingResponse, ErrorCode> {
    let port;
    let authority = if let Some(authority) = request.uri().authority() {
        if let Some(port_value) = authority.port() {
            port = port_value.as_u16();
            authority.to_string()
        } else {
            port = if use_tls { 443 } else { 80 };
            format!("{authority}:{port}")
        }
    } else {
        return Err(ErrorCode::HttpRequestUriInvalid);
    };

    // Only ever `true` for a *trusted* static mapping: a regular static
    // mapping still needs its one address checked below, same as any
    // genuinely resolved address.
    let mut trusted_static_mapping = false;

    let tcp_addresses = match &authority_parsed.host {
        Host::Domain(domain) => {
            if let Some(tcp_address) = acl.resolve_trusted_static_dns_mapping(domain) {
                trusted_static_mapping = true;

                vec![tcp_address]
            } else if let Some(tcp_address) = acl.resolve_static_dns_mapping(domain) {
                vec![tcp_address]
            } else {
                let acl_host_match = acl.is_host_allowed(domain);
                if acl_host_match.is_denied() {
                    return Err(internal_error(format!(
                        "Host {domain} is not allowed - {acl_host_match}",
                    )));
                }

                timeout(
                    connect_timeout,
                    tokio::net::lookup_host((domain.as_str(), port)),
                )
                .await
                .map_err(|_| ErrorCode::DnsTimeout)?
                .map_err(|e| {
                    tracing::warn!("dns lookup error: {e:?}");
                    dns_error("dns lookup error".to_string(), 0)
                })?
                .collect::<Vec<_>>()
            }
        }
        Host::Ip(ip) => {
            let acl_ip_match = acl.is_ip_allowed(ip);
            if acl_ip_match.is_denied() {
                return Err(internal_error(format!(
                    "IP {ip} is not allowed - {acl_ip_match}",
                )));
            }

            vec![SocketAddr::new(*ip, port)]
        }
    };

    if tcp_addresses.is_empty() {
        return Err(dns_error("dns lookup error".to_string(), 0));
    }

    if !trusted_static_mapping {
        for tcp_address in &tcp_addresses {
            let acl_ip_match = acl.is_ip_allowed(&tcp_address.ip());
            if acl_ip_match.is_denied() {
                return Err(internal_error(format!(
                    "IP {} is not allowed - {}",
                    tcp_address.ip(),
                    acl_ip_match,
                )));
            }
        }
    }

    let tcp_stream = timeout(
        connect_timeout,
        TcpStream::connect(tcp_addresses.as_slice()),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrNotAvailable => dns_error("address not available".to_string(), 0),
        _ => {
            if e.to_string()
                .starts_with("failed to lookup address information")
            {
                dns_error("address not available".to_string(), 0)
            } else {
                ErrorCode::ConnectionRefused
            }
        }
    })?;

    let (mut sender, worker) = if use_tls {
        use rustls::pki_types::ServerName;

        // derived from https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleclient.rs
        let root_cert_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        // Name the provider rather than rely on the process default, which rustls 0.23
        // cannot pick when a dependent enables both the ring and aws-lc-rs features.
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            tracing::warn!("tls config error: {e:?}");
            ErrorCode::TlsProtocolError
        })?
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut parts = authority.split(":");
        let host = parts.next().unwrap_or(&authority);
        let domain = ServerName::try_from(host)
            .map_err(|e| {
                tracing::warn!("dns lookup error: {e:?}");
                dns_error("invalid dns name".to_string(), 0)
            })?
            .to_owned();
        let stream = connector.connect(domain, tcp_stream).await.map_err(|e| {
            tracing::warn!("tls protocol error: {e:?}");
            ErrorCode::TlsProtocolError
        })?;
        let stream = TokioIo::new(stream);

        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(stream),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;

        let worker = wasmtime_wasi::runtime::spawn(async move {
            match conn.await {
                Ok(()) => {}
                // TODO: shouldn't throw away this error and ideally should
                // surface somewhere.
                Err(e) => tracing::warn!("dropping error {e}"),
            }
        });

        (sender, worker)
    } else {
        let tcp_stream = TokioIo::new(tcp_stream);
        let (sender, conn) = timeout(
            connect_timeout,
            // TODO: we should plumb the builder through the http context, and use it here
            hyper::client::conn::http1::handshake(tcp_stream),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;

        let worker = wasmtime_wasi::runtime::spawn(async move {
            match conn.await {
                Ok(()) => {}
                // TODO: same as above, shouldn't throw this error away.
                Err(e) => tracing::warn!("dropping error {e}"),
            }
        });

        (sender, worker)
    };

    // at this point, the request contains the scheme and the authority, but
    // the http packet should only include those if addressing a proxy, so
    // remove them here, since SendRequest::send_request does not do it for us
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        )
        .build()
        .expect("comes from valid request");

    let scheme_str = if use_tls { "https" } else { "http" };

    // The request body is only read into memory when a `ModifyRequestFn` is
    // attached; otherwise the request goes out untouched.
    let request = if acl.has_modify_request() {
        let (mut parts, body) = request.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        let mut mutation = RequestMutation {
            headers: header_pairs(&parts.headers),
            body: Some(body_bytes),
        };
        acl.modify_request(scheme_str, &authority_parsed, &mut mutation);
        parts.headers = header_map(&mutation.headers)?;
        hyper::Request::from_parts(
            parts,
            Full::new(mutation.body.unwrap_or_default())
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
    } else {
        request
    };

    let resp = timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(hyper_request_error)?
        .map(|body| body.map_err(hyper_request_error).boxed());

    // The response body is only read into memory when a `ModifyResponseFn`
    // is attached. The connection is driven by `worker`, already spawned, so
    // collecting here cannot stall it.
    let resp = if acl.has_modify_response() {
        let (mut parts, body) = resp.into_parts();
        let body_bytes: Bytes = body.collect().await?.to_bytes();
        let mut mutation = ResponseMutation {
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
            body: body_bytes,
        };
        acl.modify_response(scheme_str, &authority_parsed, &mut mutation);
        parts.status = http::StatusCode::from_u16(mutation.status)
            .map_err(|_| internal_error(format!("invalid status code {}", mutation.status)))?;
        parts.headers = header_map(&mutation.headers)?;
        hyper::Response::from_parts(
            parts,
            Full::new(mutation.body)
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
    } else {
        resp
    };

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout,
    })
}

/// The headers as the name/value pairs http-acl's mutation hooks work on.
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Rebuilds a header map from the pairs a mutation hook left behind.
fn header_map(pairs: &[(String, String)]) -> Result<HeaderMap, ErrorCode> {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| internal_error(format!("invalid header name `{name}`")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| internal_error(format!("invalid header value for `{name}`")))?;
        headers.append(name, value);
    }
    Ok(headers)
}

/// The http-acl hooks and trusted static mappings: the fork's `acl_parity_tests`
/// (4ede536b9d), against [`send_request_handler`].
#[cfg(test)]
mod acl_parity_tests {
    use super::{AclRequestConfig, send_request_handler};
    use bytes::Bytes;
    use http_acl::{HttpAcl, HttpAclHooks, utils::authority::Authority};
    use http_body_util::{BodyExt, Full};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wasmtime_wasi_http::bindings::http::types::ErrorCode;

    async fn serve(response: &'static str) -> (u16, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (port, rx)
    }

    fn config(acl: HttpAcl, port: u16) -> AclRequestConfig {
        AclRequestConfig {
            use_tls: false,
            connect_timeout: Duration::from_secs(5),
            first_byte_timeout: Duration::from_secs(5),
            between_bytes_timeout: Duration::from_secs(5),
            acl: Arc::new(acl),
            authority: Authority::parse(&format!("127.0.0.1:{port}")).unwrap(),
        }
    }

    fn request(uri: String) -> hyper::Request<wasmtime_wasi_http::body::HyperOutgoingBody> {
        http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(
                Full::new(Bytes::new())
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed(),
            )
            .unwrap()
    }

    fn base() -> http_acl::HttpAclBuilder {
        HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
    }

    #[tokio::test]
    async fn modify_request_and_response_hooks_are_applied() {
        let (port, captured) =
            serve("HTTP/1.1 200 OK\r\nx-remove-me: yes\r\nContent-Length: 13\r\n\r\noriginal body")
                .await;
        let acl = base().build_full(HttpAclHooks {
            modify_request_fn: Some(Arc::new(|_s, _a, m| {
                m.headers.push(("x-injected-secret".into(), "sssh".into()));
            })),
            modify_response_fn: Some(Arc::new(|_s, _a, m| {
                m.status = 201;
                m.headers.retain(|(k, _)| k != "x-remove-me");
                m.body = Bytes::from_static(b"redacted body");
            })),
            ..Default::default()
        });
        let res = send_request_handler(
            request(format!("http://127.0.0.1:{port}/")),
            config(acl, port),
        )
        .await
        .unwrap();
        assert_eq!(res.resp.status(), 201);
        assert!(!res.resp.headers().contains_key("x-remove-me"));
        let body = res.resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"redacted body");
        let captured = captured.await.unwrap().to_lowercase();
        assert!(captured.contains("x-injected-secret: sssh"), "{captured}");
    }

    #[tokio::test]
    async fn no_hooks_configured_is_unaffected() {
        let (port, _captured) = serve("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let acl = base().build();
        assert!(!acl.has_modify_request() && !acl.has_modify_response());
        let res = send_request_handler(
            request(format!("http://127.0.0.1:{port}/")),
            config(acl, port),
        )
        .await
        .unwrap();
        assert_eq!(res.resp.status(), 200);
        let body = res.resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn a_regular_static_mapping_is_still_ip_checked_and_a_trusted_one_is_not() {
        let (port, _c) = serve("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let cfg = |acl: HttpAcl| AclRequestConfig {
            authority: Authority::parse(&format!("svc.internal:{port}")).unwrap(),
            ..config(acl, port)
        };
        let deny_local = || {
            HttpAcl::builder()
                .non_global_ip_ranges(false)
                .ip_acl_default(true)
                .port_acl_default(true)
                .host_acl_default(true)
        };
        let regular = deny_local()
            .add_static_dns_mapping("svc.internal".into(), addr)
            .unwrap()
            .build();
        let Err(err) = send_request_handler(
            request(format!("http://svc.internal:{port}/")),
            cfg(regular),
        )
        .await
        else {
            panic!("a regular mapping to loopback must be refused");
        };
        assert!(matches!(err, ErrorCode::InternalError(_)), "{err:?}");

        let trusted = deny_local()
            .add_trusted_static_dns_mapping("svc.internal".into(), addr)
            .unwrap()
            .build();
        let res = send_request_handler(
            request(format!("http://svc.internal:{port}/")),
            cfg(trusted),
        )
        .await
        .unwrap();
        assert_eq!(res.resp.status(), 200);
    }
}
