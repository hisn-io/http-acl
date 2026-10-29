//! The ACL through wasmtime-wasi-http's own `outgoing-handler.handle`, which builds the request
//! and hands it to an overridden `send_request` that calls [`check_request`].
//!
//! The first five tests are the fork's `http_impl` tests (590e80726d, 199a703d78): the fork
//! reported these denials through `WasiHttpView::acl_denied` from inside `handle`; here the
//! view reports them from `send_request`, and the guest sees the same error.

use http_acl::HttpAcl;
use http_acl_wasmtime::{check_request, send_request_handler};
use std::sync::Arc;
use wasmtime::component::ResourceTable;
use wasmtime_wasi_http::bindings::http::outgoing_handler::Host as _;
use wasmtime_wasi_http::bindings::http::types::{ErrorCode, Method, Scheme};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{
    FieldMap, HostFutureIncomingResponse, HostOutgoingRequest, OutgoingRequestConfig,
};
use wasmtime_wasi_http::{HttpResult, WasiHttpCtx, WasiHttpImpl, WasiHttpView};

/// A view that records each ACL denial, and each request that got past [`check_request`].
struct Recorder {
    ctx: WasiHttpCtx,
    table: ResourceTable,
    acl: Arc<HttpAcl>,
    denials: Vec<(&'static str, String)>,
    sent: usize,
}

impl WasiHttpView for Recorder {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.ctx
    }

    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        match check_request(&request, config, self.acl.clone()) {
            Ok(_) => {
                self.sent += 1;
                Err(ErrorCode::InternalError(Some("not sent in this test".to_string())).into())
            }
            Err(refusal) => {
                if let Some((reason, host)) = refusal.denial() {
                    self.denials.push((reason, host.to_string()));
                }
                Err(refusal.into_error().into())
            }
        }
    }
}

/// Runs `handle` on the request and returns the denials, how many requests were sent, and
/// the error the guest got.
fn handle(
    acl: HttpAcl,
    method: Method,
    scheme: Scheme,
    authority: &str,
    path: &str,
) -> (Vec<(&'static str, String)>, usize, ErrorCode) {
    let mut view = Recorder {
        ctx: WasiHttpCtx::new(),
        table: ResourceTable::new(),
        acl: Arc::new(acl),
        denials: Vec::new(),
        sent: 0,
    };
    let request = view
        .table
        .push(HostOutgoingRequest {
            method,
            scheme: Some(scheme),
            authority: Some(authority.to_string()),
            path_with_query: Some(path.to_string()),
            headers: FieldMap::empty(usize::MAX),
            body: None,
        })
        .unwrap();
    let error = WasiHttpImpl(&mut view)
        .handle(request, None)
        .expect_err("never sent in these tests")
        .downcast()
        .unwrap();
    (view.denials, view.sent, error)
}

fn acl() -> http_acl::HttpAclBuilder {
    HttpAcl::builder()
        .ip_acl_default(true)
        .host_acl_default(true)
        .port_acl_default(true)
        .method_acl_default(true)
        .header_acl_default(true)
        .url_path_acl_default(true)
}

fn denial(reason: &'static str) -> Vec<(&'static str, String)> {
    vec![(reason, "example.com".to_string())]
}

fn message(error: &ErrorCode) -> &str {
    match error {
        ErrorCode::InternalError(Some(message)) => message,
        other => panic!("not an internal error: {other:?}"),
    }
}

#[test]
fn denied_method_is_reported() {
    let acl = acl()
        .clear_allowed_methods()
        .add_denied_method("DELETE")
        .unwrap()
        .build();
    let (denials, sent, error) = handle(acl, Method::Delete, Scheme::Https, "example.com", "/");
    assert_eq!((denials, sent), (denial("method"), 0));
    assert!(message(&error).starts_with("Method DELETE is not allowed - "));
}

#[test]
fn denied_scheme_is_reported() {
    let acl = acl().http(false).build();
    let (denials, sent, error) = handle(acl, Method::Get, Scheme::Http, "example.com", "/");
    assert_eq!((denials, sent), (denial("scheme"), 0));
    assert!(message(&error).starts_with("Scheme http is not allowed - "));
}

#[test]
fn denied_port_is_reported() {
    let acl = acl().add_denied_port_range(8080..=8080).unwrap().build();
    let (denials, sent, error) = handle(acl, Method::Get, Scheme::Https, "example.com:8080", "/");
    assert_eq!((denials, sent), (denial("port"), 0));
    assert!(message(&error).starts_with("Port 8080 is not allowed - "));
}

#[test]
fn denied_path_is_reported() {
    let acl = acl()
        .add_denied_url_path("/admin".to_string())
        .unwrap()
        .build();
    let (denials, sent, error) = handle(acl, Method::Get, Scheme::Https, "example.com", "/%61dmin");
    assert_eq!((denials, sent), (denial("path"), 0));
    assert!(message(&error).starts_with("URL Path /admin is not allowed - "));
}

#[test]
fn allowed_request_reports_nothing() {
    let (denials, sent, _) = handle(
        acl().build(),
        Method::Get,
        Scheme::Https,
        "example.com",
        "/",
    );
    assert_eq!((denials, sent), (Vec::new(), 1));
}

/// 199a703d78: dot segments are resolved, and the query and fragment are not part of the
/// path.
#[test]
fn dot_segments_and_queries_do_not_hide_a_denied_path() {
    let acl = || {
        acl()
            .add_denied_url_path("/admin".to_string())
            .unwrap()
            .build()
    };
    for path in ["/x/../admin", "/admin?x=1", "/./admin", "/%2e%2e/admin"] {
        let (denials, sent, _) = handle(acl(), Method::Get, Scheme::Https, "example.com", path);
        assert_eq!((denials, sent), (denial("path"), 0), "{path}");
    }
}

/// An authority without a port is checked against its scheme's default port.
#[test]
fn a_missing_port_is_checked_as_the_default() {
    let acl = || {
        acl()
            .clear_allowed_port_ranges()
            .add_denied_port_range(443..=443)
            .unwrap()
            .build()
    };
    let (denials, _, _) = handle(acl(), Method::Get, Scheme::Https, "example.com", "/");
    assert_eq!(denials, denial("port"));
    let (denials, sent, _) = handle(acl(), Method::Get, Scheme::Http, "example.com", "/");
    assert_eq!((denials, sent), (Vec::new(), 1));
}

/// A method the ACL does not name, sent as `Method::Other`, is checked by its name.
#[test]
fn other_methods_are_checked_by_name() {
    let acl = acl()
        .clear_allowed_methods()
        .add_denied_method("PURGE")
        .unwrap()
        .build();
    let (denials, sent, _) = handle(
        acl,
        Method::Other("PURGE".to_string()),
        Scheme::Https,
        "example.com",
        "/",
    );
    assert_eq!((denials, sent), (denial("method"), 0));
}

fn config() -> OutgoingRequestConfig {
    OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: std::time::Duration::from_secs(5),
        first_byte_timeout: std::time::Duration::from_secs(5),
        between_bytes_timeout: std::time::Duration::from_secs(5),
    }
}

fn get(uri: &str) -> hyper::Request<HyperOutgoingBody> {
    use http_body_util::{BodyExt, Empty};
    hyper::Request::builder()
        .uri(uri)
        .body(
            Empty::<bytes::Bytes>::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .unwrap()
}

/// What the guest gets back when the request is sent under `acl`.
async fn send(acl: HttpAcl, uri: &str) -> Result<u16, ErrorCode> {
    let request = get(uri);
    let config = check_request(&request, config(), Arc::new(acl)).expect("passes the checks");
    send_request_handler(request, config)
        .await
        .map(|incoming| incoming.resp.status().as_u16())
}

fn global_only() -> http_acl::HttpAclBuilder {
    HttpAcl::builder()
        .non_global_ip_ranges(false)
        .ip_acl_default(true)
        .host_acl_default(true)
        .port_acl_default(true)
}

/// A host the ACL denies is refused before it is resolved.
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_host_is_refused() {
    let acl = global_only()
        .add_denied_host("denied.hisn.io".to_string())
        .unwrap()
        .build();
    let error = send(acl, "http://denied.hisn.io/").await.unwrap_err();
    assert!(
        message(&error).starts_with("Host denied.hisn.io is not allowed - "),
        "{error:?}"
    );
}

/// A literal address the ACL denies is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_literal_address_is_refused() {
    let error = send(global_only().build(), "http://127.0.0.1:9/")
        .await
        .unwrap_err();
    assert!(
        message(&error).starts_with("IP 127.0.0.1 is not allowed - "),
        "{error:?}"
    );
    let error = send(global_only().build(), "http://[::ffff:127.0.0.1]:9/")
        .await
        .unwrap_err();
    assert!(message(&error).starts_with("IP "), "{error:?}");
}

/// A name that resolves to a denied address is refused after resolution and before any
/// connection (SSRF through DNS, and DNS rebinding).
#[tokio::test(flavor = "multi_thread")]
async fn every_resolved_address_is_checked() {
    let error = send(global_only().build(), "http://localhost:9/")
        .await
        .unwrap_err();
    assert!(message(&error).starts_with("IP "), "{error:?}");

    // A regular static mapping is a resolver answer like any other.
    let acl = global_only()
        .add_static_dns_mapping("svc.hisn.io".into(), "10.0.0.1:80".parse().unwrap())
        .unwrap()
        .build();
    let error = send(acl, "http://svc.hisn.io/").await.unwrap_err();
    assert!(
        message(&error).starts_with("IP 10.0.0.1 is not allowed - "),
        "{error:?}"
    );
}

/// A request without a path never reaches `send_request`: wasmtime-wasi-http 36 cannot build
/// its URI and refuses it first. The fork checked it as `/` before that point, so it logged a
/// path denial where this logs none; neither sends it.
#[test]
fn a_request_without_a_path_is_never_sent() {
    let mut view = Recorder {
        ctx: WasiHttpCtx::new(),
        table: ResourceTable::new(),
        acl: Arc::new(acl().build()),
        denials: Vec::new(),
        sent: 0,
    };
    let request = view
        .table
        .push(HostOutgoingRequest {
            method: Method::Get,
            scheme: Some(Scheme::Https),
            authority: Some("example.com".to_string()),
            path_with_query: None,
            headers: FieldMap::empty(usize::MAX),
            body: None,
        })
        .unwrap();
    let error = WasiHttpImpl(&mut view)
        .handle(request, None)
        .expect_err("refused")
        .downcast()
        .unwrap();
    assert_eq!((view.denials, view.sent), (Vec::new(), 0));
    assert!(matches!(error, ErrorCode::HttpProtocolError), "{error:?}");
}
