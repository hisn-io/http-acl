#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub use ipnet::IpNet;

pub mod acl;
pub mod error;
pub mod mutation;
pub mod utils;

pub use acl::{
    AclClassification, HttpAcl, HttpAclBuilder, HttpAclHooks, HttpRequestMethod, ValidateFn,
};
pub use mutation::{ModifyRequestFn, ModifyResponseFn, RequestMutation, ResponseMutation};
pub use utils::IntoIpRange;

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use ipnet::IpNet;

    use super::{AclClassification, HttpAclBuilder, HttpAclHooks};

    #[test]
    fn acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_host("example.com".to_string())
            .unwrap()
            .add_allowed_host("example.org".to_string())
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
            .try_build()
            .unwrap();

        assert!(acl.is_host_allowed("example.com").is_allowed());
        assert!(acl.is_host_allowed("example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.net").is_allowed());
        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
    }

    #[test]
    fn host_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_host("example.com".to_string())
            .unwrap()
            .add_allowed_host("example.org".to_string())
            .unwrap()
            .add_denied_host("example.net".to_string())
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_host_allowed("example.com").is_allowed());
        assert!(acl.is_host_allowed("example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.net").is_allowed());
    }

    #[test]
    fn wildcard_host_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_host("*.example.com".to_string())
            .unwrap()
            .add_allowed_host("?.example.org".to_string())
            .unwrap()
            .add_denied_host("secret.example.com".to_string())
            .unwrap()
            .try_build()
            .unwrap();

        // `*` matches one or more labels.
        assert!(acl.is_host_allowed("foo.example.com").is_allowed());
        assert!(acl.is_host_allowed("foo.bar.example.com").is_allowed());
        assert!(!acl.is_host_allowed("example.com").is_allowed());

        // `?` matches exactly one label.
        assert!(acl.is_host_allowed("foo.example.org").is_allowed());
        assert!(!acl.is_host_allowed("foo.bar.example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.org").is_allowed());

        // Allow-list entries (including wildcard ones) are checked before deny-list
        // entries, same as for exact hosts - a broad wildcard allow can shadow a more
        // specific deny, so `secret.example.com` here is allowed, not denied.
        assert!(acl.is_host_allowed("secret.example.com").is_allowed());

        // Unrelated hosts fall through to the default (deny).
        assert!(acl.is_host_allowed("example.net").is_denied());
    }

    #[test]
    fn invalid_wildcard_host_pattern_rejected() {
        assert!(
            HttpAclBuilder::new()
                .add_allowed_host("foo*.example.com".to_string())
                .is_err()
        );
    }

    #[test]
    fn port_acl() {
        let acl = HttpAclBuilder::new()
            .clear_allowed_port_ranges()
            .add_allowed_port_range(8080..=8080)
            .unwrap()
            .add_denied_port_range(8441..=8443)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_port_allowed(80).is_denied());
        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(acl.is_port_allowed(8440).is_denied());
        assert!(!acl.is_port_allowed(8441).is_allowed());
        assert!(!acl.is_port_allowed(8442).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
        assert!(acl.is_port_allowed(8444).is_denied());
    }

    #[test]
    fn denied_port_ranges_setter_rejects_overlaps() {
        // Overlaps (but doesn't exactly equal) the default allowed range `80..=80`.
        assert!(
            HttpAclBuilder::new()
                .denied_port_ranges(vec![70..=85])
                .is_err()
        );

        // Overlaps within the new list itself.
        assert!(
            HttpAclBuilder::new()
                .denied_port_ranges(vec![1000..=2000, 1500..=2500])
                .is_err()
        );
    }

    #[test]
    fn mixed_family_ip_range_rejected() {
        let start: IpAddr = "1.0.0.0".parse().unwrap();
        let end: IpAddr = "::1".parse().unwrap();
        assert!(
            HttpAclBuilder::new()
                .add_allowed_ip_range((start, end))
                .is_err()
        );
    }

    #[test]
    fn ip_acl() {
        let acl = HttpAclBuilder::new()
            .clear_allowed_ip_ranges()
            .add_allowed_ip_range("1.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .add_denied_ip_range("9.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
    }

    #[test]
    fn non_global_ip_acl() {
        let acl = HttpAclBuilder::new()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .try_build()
            .unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_allowed()
        );
        assert!(
            acl.is_ip_allowed(&"203.0.113.12".parse().unwrap())
                .is_allowed()
        );

        let acl = HttpAclBuilder::new()
            .ip_acl_default(true)
            .try_build()
            .unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
        assert!(
            acl.is_ip_allowed(&"203.0.113.12".parse().unwrap())
                .is_denied()
        );
    }

    #[test]
    fn default_ip_acl() {
        let acl = HttpAclBuilder::new().try_build().unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_denied());
        assert!(!acl.is_port_allowed(8080).is_allowed());
    }

    #[test]
    fn url_path_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_url_path("/allowed".to_string())
            .unwrap()
            .add_allowed_url_path("/allowed/:id".to_string())
            .unwrap()
            .add_denied_url_path("/denied".to_string())
            .unwrap()
            .add_denied_url_path("/denied/{*path}".to_string())
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_url_path_allowed("/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/allowed/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied/denied").is_denied());
    }

    #[test]
    fn header_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_header("X-Allowed".to_string(), Some("true".to_string()))
            .unwrap()
            .add_allowed_header("X-Allowed2".to_string(), None)
            .unwrap()
            .add_denied_header("X-Denied".to_string(), Some("true".to_string()))
            .unwrap()
            .add_denied_header("X-Denied2".to_string(), None)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_header_allowed("X-Allowed", "true").is_allowed());
        assert!(acl.is_header_allowed("X-Allowed2", "false").is_allowed());
        assert!(acl.is_header_allowed("X-Denied", "true").is_denied());
        assert!(acl.is_header_allowed("X-Denied2", "false").is_denied());
    }

    #[test]
    fn static_dns_mapping() {
        let regular_addr = "10.0.0.1:80".parse().unwrap();
        let trusted_addr = "10.0.0.2:80".parse().unwrap();

        let acl = HttpAclBuilder::new()
            .add_static_dns_mapping("regular.example.com".to_string(), regular_addr)
            .unwrap()
            .add_trusted_static_dns_mapping("trusted.example.com".to_string(), trusted_addr)
            .unwrap()
            .try_build()
            .unwrap();

        assert_eq!(
            acl.resolve_static_dns_mapping("regular.example.com"),
            Some(regular_addr)
        );
        assert_eq!(
            acl.resolve_trusted_static_dns_mapping("trusted.example.com"),
            Some(trusted_addr)
        );
        // The two maps are looked up independently - a host in one isn't found in the other.
        assert_eq!(
            acl.resolve_trusted_static_dns_mapping("regular.example.com"),
            None
        );
        assert_eq!(acl.resolve_static_dns_mapping("trusted.example.com"), None);

        // A regular mapping's resolved address is still subject to the IP/port ACL
        // (denied here because no IP ranges are allowed by default).
        assert!(acl.is_ip_allowed(&regular_addr.ip()).is_denied());

        // A host can't be present in both maps.
        assert!(
            HttpAclBuilder::new()
                .add_static_dns_mapping("both.example.com".to_string(), regular_addr)
                .unwrap()
                .add_trusted_static_dns_mapping("both.example.com".to_string(), trusted_addr)
                .is_err()
        );
        assert!(
            HttpAclBuilder::new()
                .add_trusted_static_dns_mapping("both.example.com".to_string(), trusted_addr)
                .unwrap()
                .add_static_dns_mapping("both.example.com".to_string(), regular_addr)
                .is_err()
        );
    }

    #[test]
    fn valid_acl() {
        let acl = HttpAclBuilder::new()
            .try_build_full(HttpAclHooks {
                validate_fn: Some(Arc::new(|scheme, authority, headers, body| {
                    if scheme == "http" {
                        return AclClassification::DeniedUserAcl;
                    }

                    if authority.host.is_ip() {
                        return AclClassification::DeniedUserAcl;
                    }

                    for (header_name, header_value) in headers {
                        if header_name == "<dangerous-header>"
                            && header_value == "<dangerous-value>"
                        {
                            return AclClassification::DeniedUserAcl;
                        }
                    }

                    if let Some(body) = body
                        && body == b"<dangerous-body>"
                    {
                        return AclClassification::DeniedUserAcl;
                    }

                    AclClassification::AllowedDefault
                })),
                ..Default::default()
            })
            .unwrap();

        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_allowed()
        );
        assert!(
            acl.is_valid(
                "http",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"1.1.1.1".parse::<IpAddr>().unwrap().into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<dangerous-header>", "<dangerous-value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"<dangerous-body>"),
            )
            .is_denied()
        );
    }

    #[test]
    fn modify_hooks_unset_by_default() {
        let acl = HttpAclBuilder::new().build();

        assert!(!acl.has_modify_request());
        assert!(!acl.has_modify_response());

        let mut request_mutation = super::RequestMutation::default();
        acl.modify_request("https", &"example.com".into(), &mut request_mutation);
        assert_eq!(request_mutation, super::RequestMutation::default());

        let mut response_mutation = super::ResponseMutation {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: bytes::Bytes::from_static(b"body"),
        };
        let unchanged = response_mutation.clone();
        acl.modify_response("https", &"example.com".into(), &mut response_mutation);
        assert_eq!(response_mutation, unchanged);
    }

    #[test]
    fn modify_hooks_invoked_with_expected_context() {
        let acl = HttpAclBuilder::new().build_full(HttpAclHooks {
            modify_request_fn: Some(std::sync::Arc::new(|scheme, authority, mutation| {
                mutation
                    .headers
                    .push(("x-injected".to_string(), format!("{scheme}://{authority}")));
                mutation.body = Some(bytes::Bytes::from_static(b"replaced"));
            })),
            modify_response_fn: Some(std::sync::Arc::new(|scheme, authority, mutation| {
                mutation.status = 201;
                mutation.headers.retain(|(k, _)| k != "x-remove-me");
                mutation.body = bytes::Bytes::from(format!("{scheme}://{authority}"));
            })),
            ..Default::default()
        });

        assert!(acl.has_modify_request());
        assert!(acl.has_modify_response());

        let mut request_mutation = super::RequestMutation::default();
        acl.modify_request("https", &"example.com".into(), &mut request_mutation);
        assert_eq!(
            request_mutation.headers,
            vec![("x-injected".to_string(), "https://example.com".to_string())]
        );
        assert_eq!(
            request_mutation.body,
            Some(bytes::Bytes::from_static(b"replaced"))
        );

        let mut response_mutation = super::ResponseMutation {
            status: 200,
            headers: vec![
                ("x-remove-me".to_string(), "yes".to_string()),
                ("x-keep-me".to_string(), "yes".to_string()),
            ],
            body: bytes::Bytes::new(),
        };
        acl.modify_response("https", &"example.com".into(), &mut response_mutation);
        assert_eq!(response_mutation.status, 201);
        assert_eq!(
            response_mutation.headers,
            vec![("x-keep-me".to_string(), "yes".to_string())]
        );
        assert_eq!(response_mutation.body, "https://example.com");
    }
}
