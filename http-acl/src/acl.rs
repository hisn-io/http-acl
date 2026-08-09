//! Contains the [`HttpAcl`], [`HttpAclBuilder`],
//! and related types.
//!
//! Each category an [`HttpAcl`] checks (scheme, method, host, port, IP, header, URL
//! path) is evaluated the same way: the allow-list is checked first, then the
//! deny-list, and if neither matches, the category's configured default (set via
//! e.g. [`HttpAclBuilder::host_acl_default`]) decides the outcome. The allow-list
//! always wins over the deny-list, so a broad allow entry can shadow a narrower deny
//! entry in the same category. Every check returns an [`AclClassification`] rather
//! than a plain `bool`, so callers can tell *why* something was allowed or denied;
//! use [`AclClassification::is_allowed`]/[`AclClassification::is_denied`] where only
//! the outcome matters.

#[cfg(feature = "hashbrown")]
use hashbrown::{HashMap, HashSet, hash_map::Entry};
#[cfg(not(feature = "hashbrown"))]
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;

use matchit::Router;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::AddError,
    mutation::{ModifyRequestFn, ModifyResponseFn, RequestMutation, ResponseMutation},
    utils::{
        self, IntoIpRange,
        authority::Authority,
        host_pattern::{HostPattern, is_wildcard_host},
    },
};

/// A function that validates an HTTP request against an ACL.
///
/// Called by [`HttpAcl::is_valid`] with the request's scheme, authority (host and
/// port), headers, and optional body, in that order. It is the only hook for checks
/// that don't fit the built-in categories (e.g. inspecting the body, or applying
/// custom cross-field logic). Return [`AclClassification::DeniedUserAcl`] or
/// [`AclClassification::Denied`] to reject the request, or
/// [`AclClassification::AllowedDefault`] to let it through.
///
/// A `ValidateFn` is attached via [`HttpAclBuilder::build_full`] or
/// [`HttpAclBuilder::try_build_full`] rather than a dedicated builder setter, since
/// it is typically a closure that captures state from outside the builder.
pub type ValidateFn = Arc<
    dyn for<'h> Fn(
            &str,
            &Authority,
            Box<dyn Iterator<Item = (&'h str, &'h str)> + Send + Sync + 'h>,
            Option<&[u8]>,
        ) -> AclClassification
        + Send
        + Sync,
>;

#[derive(Clone)]
/// Represents an HTTP ACL.
///
/// Built via [`HttpAcl::builder`] (an [`HttpAclBuilder`]) rather than constructed
/// directly. Once built, an `HttpAcl` is immutable; the various `is_*_allowed`
/// methods check a single aspect of a request (scheme, method, host, port, IP,
/// header, or URL path) and return an [`AclClassification`]. See the module-level
/// documentation for how allow-lists, deny-lists, and per-category defaults combine.
pub struct HttpAcl {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: HashSet<HttpRequestMethod>,
    denied_methods: HashSet<HttpRequestMethod>,
    allowed_hosts: HashSet<Box<str>>,
    denied_hosts: HashSet<Box<str>>,
    allowed_host_patterns: Box<[HostPattern]>,
    denied_host_patterns: Box<[HostPattern]>,
    allowed_port_ranges: Box<[RangeInclusive<u16>]>,
    denied_port_ranges: Box<[RangeInclusive<u16>]>,
    allowed_ip_ranges: Box<[RangeInclusive<IpAddr>]>,
    denied_ip_ranges: Box<[RangeInclusive<IpAddr>]>,
    static_dns_mapping: HashMap<Box<str>, SocketAddr>,
    trusted_static_dns_mapping: HashMap<Box<str>, SocketAddr>,
    allowed_headers: HashMap<Box<str>, Option<Box<str>>>,
    denied_headers: HashMap<Box<str>, Option<Box<str>>>,
    allowed_url_paths_router: Router<()>,
    denied_url_paths_router: Router<()>,
    validate_fn: Option<ValidateFn>,
    modify_request_fn: Option<ModifyRequestFn>,
    modify_response_fn: Option<ModifyResponseFn>,
    allow_non_global_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
    header_acl_default: bool,
    url_path_acl_default: bool,
}

impl std::fmt::Debug for HttpAcl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAcl")
            .field("allow_http", &self.allow_http)
            .field("allow_https", &self.allow_https)
            .field("allowed_methods", &self.allowed_methods)
            .field("denied_methods", &self.denied_methods)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("denied_hosts", &self.denied_hosts)
            .field("allowed_port_ranges", &self.allowed_port_ranges)
            .field("denied_port_ranges", &self.denied_port_ranges)
            .field("allowed_ip_ranges", &self.allowed_ip_ranges)
            .field("denied_ip_ranges", &self.denied_ip_ranges)
            .field("static_dns_mapping", &self.static_dns_mapping)
            .field(
                "trusted_static_dns_mapping",
                &self.trusted_static_dns_mapping,
            )
            .field("allowed_headers", &self.allowed_headers)
            .field("denied_headers", &self.denied_headers)
            .field(
                "allow_non_global_ip_ranges",
                &self.allow_non_global_ip_ranges,
            )
            .field("method_acl_default", &self.method_acl_default)
            .field("host_acl_default", &self.host_acl_default)
            .field("port_acl_default", &self.port_acl_default)
            .field("ip_acl_default", &self.ip_acl_default)
            .field("header_acl_default", &self.header_acl_default)
            .field("url_path_acl_default", &self.url_path_acl_default)
            .finish()
    }
}

impl PartialEq for HttpAcl {
    fn eq(&self, other: &Self) -> bool {
        self.allow_http == other.allow_http
            && self.allow_https == other.allow_https
            && self.allowed_methods == other.allowed_methods
            && self.denied_methods == other.denied_methods
            && self.allowed_hosts == other.allowed_hosts
            && self.denied_hosts == other.denied_hosts
            && self.allowed_port_ranges == other.allowed_port_ranges
            && self.denied_port_ranges == other.denied_port_ranges
            && self.allowed_ip_ranges == other.allowed_ip_ranges
            && self.denied_ip_ranges == other.denied_ip_ranges
            && self.static_dns_mapping == other.static_dns_mapping
            && self.trusted_static_dns_mapping == other.trusted_static_dns_mapping
            && self.allowed_headers == other.allowed_headers
            && self.denied_headers == other.denied_headers
            && self.allow_non_global_ip_ranges == other.allow_non_global_ip_ranges
            && self.method_acl_default == other.method_acl_default
            && self.host_acl_default == other.host_acl_default
            && self.port_acl_default == other.port_acl_default
            && self.ip_acl_default == other.ip_acl_default
            && self.header_acl_default == other.header_acl_default
            && self.url_path_acl_default == other.url_path_acl_default
    }
}

impl std::default::Default for HttpAcl {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: [
                HttpRequestMethod::CONNECT,
                HttpRequestMethod::DELETE,
                HttpRequestMethod::GET,
                HttpRequestMethod::HEAD,
                HttpRequestMethod::OPTIONS,
                HttpRequestMethod::PATCH,
                HttpRequestMethod::POST,
                HttpRequestMethod::PUT,
                HttpRequestMethod::TRACE,
            ]
            .into_iter()
            .collect(),
            denied_methods: HashSet::new(),
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            allowed_host_patterns: Box::new([]),
            denied_host_patterns: Box::new([]),
            allowed_port_ranges: vec![80..=80, 443..=443].into_boxed_slice(),
            denied_port_ranges: Vec::new().into_boxed_slice(),
            allowed_ip_ranges: Vec::new().into_boxed_slice(),
            denied_ip_ranges: Vec::new().into_boxed_slice(),
            static_dns_mapping: HashMap::new(),
            trusted_static_dns_mapping: HashMap::new(),
            allowed_headers: HashMap::new(),
            denied_headers: HashMap::new(),
            allowed_url_paths_router: Router::new(),
            denied_url_paths_router: Router::new(),
            validate_fn: None,
            modify_request_fn: None,
            modify_response_fn: None,
            allow_non_global_ip_ranges: false,
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
            header_acl_default: true,
            url_path_acl_default: true,
        }
    }
}

impl HttpAcl {
    /// Returns a new [`HttpAclBuilder`].
    pub fn builder() -> HttpAclBuilder {
        HttpAclBuilder::new()
    }

    /// Returns whether the scheme is allowed.
    ///
    /// Unlike the other `is_*_allowed` methods, this is a plain per-scheme flag (set
    /// via [`HttpAclBuilder::http`]/[`HttpAclBuilder::https`]) rather than an
    /// allow/deny/default check, so it only ever returns
    /// [`AclClassification::AllowedUserAcl`] or [`AclClassification::DeniedUserAcl`].
    /// Any scheme other than `"http"`/`"https"` is denied.
    pub fn is_scheme_allowed(&self, scheme: &str) -> AclClassification {
        if scheme == "http" && self.allow_http || scheme == "https" && self.allow_https {
            AclClassification::AllowedUserAcl
        } else {
            AclClassification::DeniedUserAcl
        }
    }

    /// Returns whether the method is allowed.
    ///
    /// Note: If you pass a string ensure it is uppercased first.
    pub fn is_method_allowed(&self, method: impl Into<HttpRequestMethod>) -> AclClassification {
        let method = method.into();
        if self.allowed_methods.contains(&method) {
            AclClassification::AllowedUserAcl
        } else if self.denied_methods.contains(&method) {
            AclClassification::DeniedUserAcl
        } else if self.method_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether the host is allowed.
    ///
    /// Hosts may be exact hostnames or wildcard patterns (see
    /// [`HttpAclBuilder::add_allowed_host`] for the wildcard syntax).
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn is_host_allowed(&self, host: &str) -> AclClassification {
        if self.allowed_hosts.contains(host)
            || self.allowed_host_patterns.iter().any(|p| p.matches(host))
        {
            AclClassification::AllowedUserAcl
        } else if self.denied_hosts.contains(host)
            || self.denied_host_patterns.iter().any(|p| p.matches(host))
        {
            AclClassification::DeniedUserAcl
        } else if self.host_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether the port is allowed.
    pub fn is_port_allowed(&self, port: u16) -> AclClassification {
        if Self::is_port_in_ranges(port, &self.allowed_port_ranges) {
            AclClassification::AllowedUserAcl
        } else if Self::is_port_in_ranges(port, &self.denied_port_ranges) {
            AclClassification::DeniedUserAcl
        } else if self.port_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether an IP is allowed.
    ///
    /// A non-global IP (private, loopback, link-local, and other special-use
    /// addresses) is denied with [`AclClassification::DeniedNotGlobal`] before the
    /// allow/deny lists are even checked, unless
    /// [`HttpAclBuilder::non_global_ip_ranges`] was set to `true`.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> AclClassification {
        if !utils::ip::is_global_ip(ip) && !self.allow_non_global_ip_ranges {
            AclClassification::DeniedNotGlobal
        } else if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
            AclClassification::AllowedUserAcl
        } else if Self::is_ip_in_ranges(ip, &self.denied_ip_ranges) {
            AclClassification::DeniedUserAcl
        } else if self.ip_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Resolve a static DNS mapping.
    ///
    /// The returned address is still subject to the IP and port ACL - callers must
    /// check it with [`Self::is_ip_allowed`] and [`Self::is_port_allowed`] themselves.
    /// Use [`Self::resolve_trusted_static_dns_mapping`] for mappings that should
    /// bypass those checks entirely.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn resolve_static_dns_mapping(&self, host: &str) -> Option<SocketAddr> {
        self.static_dns_mapping.get(host).copied()
    }

    /// Resolve a trusted static DNS mapping.
    ///
    /// Unlike [`Self::resolve_static_dns_mapping`], the returned address is meant to
    /// bypass the IP and port ACL entirely - only use this for mappings you trust
    /// regardless of what the ACL would otherwise say (e.g. pinning a hostname to an
    /// internal address on purpose).
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn resolve_trusted_static_dns_mapping(&self, host: &str) -> Option<SocketAddr> {
        self.trusted_static_dns_mapping.get(host).copied()
    }

    /// Returns whether a header is allowed.
    ///
    /// Note: Header names are case-insensitive, but this function assumes the caller provides them in a consistent case.
    pub fn is_header_allowed(&self, header_name: &str, header_value: &str) -> AclClassification {
        if let Some(allowed_value) = self.allowed_headers.get(header_name) {
            if allowed_value.as_deref() == Some(header_value) || allowed_value.is_none() {
                AclClassification::AllowedUserAcl
            } else {
                AclClassification::DeniedUserAcl
            }
        } else if let Some(denied_value) = self.denied_headers.get(header_name) {
            if denied_value.as_deref() == Some(header_value) || denied_value.is_none() {
                AclClassification::DeniedUserAcl
            } else {
                AclClassification::AllowedUserAcl
            }
        } else if self.header_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether a URL path is allowed.
    ///
    /// Note: The URL path should be percent-decoded before passing it to this function.
    pub fn is_url_path_allowed(&self, url_path: &str) -> AclClassification {
        if self.allowed_url_paths_router.at(url_path).is_ok() {
            AclClassification::AllowedUserAcl
        } else if self.denied_url_paths_router.at(url_path).is_ok() {
            AclClassification::DeniedUserAcl
        } else if self.url_path_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Runs the [`ValidateFn`] attached to this ACL, if any, against a request.
    ///
    /// Returns [`AclClassification::AllowedDefault`] when no `ValidateFn` was
    /// attached (the default for an `HttpAcl` built without one), so calling this is
    /// always safe even if you never configured custom validation.
    pub fn is_valid<'h>(
        &self,
        scheme: &str,
        authority: &Authority,
        headers: impl Iterator<Item = (&'h str, &'h str)> + Send + Sync + 'h,
        body: Option<&[u8]>,
    ) -> AclClassification {
        if let Some(validate_fn) = &self.validate_fn {
            validate_fn(scheme, authority, Box::new(headers), body)
        } else {
            AclClassification::AllowedDefault
        }
    }

    /// Returns whether a [`ModifyRequestFn`] is attached to this ACL.
    ///
    /// Cheap (a single field read). Check this before doing any work to make a
    /// request's body/headers available for mutation (e.g. buffering a streaming
    /// body), so that omitting a `ModifyRequestFn` costs nothing at request time.
    pub fn has_modify_request(&self) -> bool {
        self.modify_request_fn.is_some()
    }

    /// Returns whether a [`ModifyResponseFn`] is attached to this ACL.
    ///
    /// See [`Self::has_modify_request`] - same rationale, for the response side.
    pub fn has_modify_response(&self) -> bool {
        self.modify_response_fn.is_some()
    }

    /// Runs the [`ModifyRequestFn`] attached to this ACL, if any, against
    /// `mutation`, mutating it in place.
    ///
    /// Does nothing when no `ModifyRequestFn` was attached, so calling this is
    /// always safe even if you never configured one - though see
    /// [`Self::has_modify_request`] if you want to skip preparing `mutation` at all
    /// in that case.
    pub fn modify_request(
        &self,
        scheme: &str,
        authority: &Authority,
        mutation: &mut RequestMutation,
    ) {
        if let Some(modify_request_fn) = &self.modify_request_fn {
            modify_request_fn(scheme, authority, mutation);
        }
    }

    /// Runs the [`ModifyResponseFn`] attached to this ACL, if any, against
    /// `mutation`, mutating it in place. See [`Self::modify_request`].
    pub fn modify_response(
        &self,
        scheme: &str,
        authority: &Authority,
        mutation: &mut ResponseMutation,
    ) {
        if let Some(modify_response_fn) = &self.modify_response_fn {
            modify_response_fn(scheme, authority, mutation);
        }
    }

    /// Checks if an ip is in a list of ip ranges.
    fn is_ip_in_ranges(ip: &IpAddr, ranges: &[RangeInclusive<IpAddr>]) -> bool {
        ranges.iter().any(|range| range.contains(ip))
    }

    /// Checks if a port is in a list of port ranges.
    fn is_port_in_ranges(port: u16, ranges: &[RangeInclusive<u16>]) -> bool {
        ranges.iter().any(|range| range.contains(&port))
    }
}

/// Represents the outcome of an ACL check, and why it was reached.
///
/// Every `is_*_allowed` method on [`HttpAcl`] returns one of these instead of a plain
/// `bool`, so the reason for an outcome is preserved for logging or error messages.
/// Use [`Self::is_allowed`] or [`Self::is_denied`] to collapse it to a `bool` once you
/// only care about the outcome.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AclClassification {
    /// The entity is allowed according to the allowed ACL.
    AllowedUserAcl,
    /// The entity is allowed because the default is to allow if no ACL match is found.
    AllowedDefault,
    /// The entity is denied according to the denied ACL.
    DeniedUserAcl,
    /// The entity is denied because the default is to deny if no ACL match is found.
    DeniedDefault,
    /// The entity is denied for a custom reason.
    ///
    /// Not produced by any built-in check; this exists for a [`ValidateFn`] to return
    /// a denial with a human-readable explanation of its own.
    Denied(String),
    /// The IP is denied because it is not global.
    DeniedNotGlobal,
}

impl std::fmt::Display for AclClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclClassification::AllowedUserAcl => {
                write!(f, "The entity is allowed according to the allowed ACL.")
            }
            AclClassification::AllowedDefault => write!(
                f,
                "The entity is allowed because the default is to allow if no ACL match is found."
            ),
            AclClassification::DeniedUserAcl => {
                write!(f, "The entity is denied according to the denied ACL.")
            }
            AclClassification::DeniedNotGlobal => {
                write!(f, "The ip is denied because it is not global.")
            }
            AclClassification::DeniedDefault => write!(
                f,
                "The entity is denied because the default is to deny if no ACL match is found."
            ),
            AclClassification::Denied(reason) => {
                write!(f, "The entity is denied because {reason}.")
            }
        }
    }
}

impl AclClassification {
    /// Returns whether the classification is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AclClassification::AllowedUserAcl | AclClassification::AllowedDefault
        )
    }

    /// Returns whether the classification is denied.
    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            AclClassification::DeniedUserAcl
                | AclClassification::Denied(_)
                | AclClassification::DeniedDefault
                | AclClassification::DeniedNotGlobal
        )
    }
}

/// Represents an HTTP request method.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HttpRequestMethod {
    /// The CONNECT method.
    CONNECT,
    /// The DELETE method.
    DELETE,
    /// The GET method.
    GET,
    /// The HEAD method.
    HEAD,
    /// The OPTIONS method.
    OPTIONS,
    /// The PATCH method.
    PATCH,
    /// The POST method.
    POST,
    /// The PUT method.
    PUT,
    /// The TRACE method.
    TRACE,
    /// Any other method.
    OTHER(Box<str>),
}

impl From<&str> for HttpRequestMethod {
    fn from(method: &str) -> Self {
        match method {
            "CONNECT" => HttpRequestMethod::CONNECT,
            "DELETE" => HttpRequestMethod::DELETE,
            "GET" => HttpRequestMethod::GET,
            "HEAD" => HttpRequestMethod::HEAD,
            "OPTIONS" => HttpRequestMethod::OPTIONS,
            "PATCH" => HttpRequestMethod::PATCH,
            "POST" => HttpRequestMethod::POST,
            "PUT" => HttpRequestMethod::PUT,
            "TRACE" => HttpRequestMethod::TRACE,
            _ => HttpRequestMethod::OTHER(method.into()),
        }
    }
}

impl HttpRequestMethod {
    /// Return the method as a `&str`.
    pub fn as_str(&self) -> &str {
        match self {
            HttpRequestMethod::CONNECT => "CONNECT",
            HttpRequestMethod::DELETE => "DELETE",
            HttpRequestMethod::GET => "GET",
            HttpRequestMethod::HEAD => "HEAD",
            HttpRequestMethod::OPTIONS => "OPTIONS",
            HttpRequestMethod::PATCH => "PATCH",
            HttpRequestMethod::POST => "POST",
            HttpRequestMethod::PUT => "PUT",
            HttpRequestMethod::TRACE => "TRACE",
            HttpRequestMethod::OTHER(other) => other,
        }
    }
}

/// The runtime hooks attached to an [`HttpAcl`] at build time, via
/// [`HttpAclBuilder::build_full`]/[`HttpAclBuilder::try_build_full`].
///
/// Each field is typically a closure that captures state from outside the builder
/// (a database handle, a secret, and so on), which is why these aren't set through
/// dedicated builder setter methods the way most of [`HttpAclBuilder`]'s other
/// configuration is.
#[derive(Clone, Default)]
pub struct HttpAclHooks {
    /// See [`ValidateFn`].
    pub validate_fn: Option<ValidateFn>,
    /// See [`ModifyRequestFn`].
    pub modify_request_fn: Option<ModifyRequestFn>,
    /// See [`ModifyResponseFn`].
    pub modify_response_fn: Option<ModifyResponseFn>,
}

/// A builder for [`HttpAcl`].
///
/// Most categories (methods, hosts, port ranges, IP ranges, headers, URL paths,
/// static DNS mappings) follow the same set of methods: `add_allowed_*`/
/// `add_denied_*` to add a single entry, `remove_allowed_*`/`remove_denied_*` to
/// remove one, `allowed_*`/`denied_*` to replace the whole list at once, and
/// `clear_allowed_*`/`clear_denied_*` to empty it. The fallible variants return
/// [`AddError`] rather than panicking, e.g. when an entry is already present on the
/// opposite list, so a host (or header, port range, and so on) can never end up
/// allowed and denied at the same time.
///
/// Call [`Self::build`] or [`Self::try_build`] to finish. Only the latter validates
/// the finished configuration (uniqueness, overlaps, non-global IP ranges); see
/// their docs for when each applies.
#[derive(Default, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HttpAclBuilder {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: Vec<HttpRequestMethod>,
    denied_methods: Vec<HttpRequestMethod>,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    #[cfg_attr(feature = "serde", serde(skip))]
    allowed_host_patterns: Vec<HostPattern>,
    #[cfg_attr(feature = "serde", serde(skip))]
    denied_host_patterns: Vec<HostPattern>,
    allowed_port_ranges: Vec<RangeInclusive<u16>>,
    denied_port_ranges: Vec<RangeInclusive<u16>>,
    allowed_ip_ranges: Vec<RangeInclusive<IpAddr>>,
    denied_ip_ranges: Vec<RangeInclusive<IpAddr>>,
    static_dns_mapping: HashMap<String, SocketAddr>,
    trusted_static_dns_mapping: HashMap<String, SocketAddr>,
    allowed_headers: HashMap<String, Option<String>>,
    denied_headers: HashMap<String, Option<String>>,
    allowed_url_paths: Vec<String>,
    #[cfg_attr(feature = "serde", serde(skip))]
    allowed_url_paths_router: Router<()>,
    denied_url_paths: Vec<String>,
    #[cfg_attr(feature = "serde", serde(skip))]
    denied_url_paths_router: Router<()>,
    allow_non_global_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
    header_acl_default: bool,
    url_path_acl_default: bool,
}

impl std::fmt::Debug for HttpAclBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAclBuilder")
            .field("allow_http", &self.allow_http)
            .field("allow_https", &self.allow_https)
            .field("allowed_methods", &self.allowed_methods)
            .field("denied_methods", &self.denied_methods)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("denied_hosts", &self.denied_hosts)
            .field("allowed_port_ranges", &self.allowed_port_ranges)
            .field("denied_port_ranges", &self.denied_port_ranges)
            .field("allowed_ip_ranges", &self.allowed_ip_ranges)
            .field("denied_ip_ranges", &self.denied_ip_ranges)
            .field("static_dns_mapping", &self.static_dns_mapping)
            .field(
                "trusted_static_dns_mapping",
                &self.trusted_static_dns_mapping,
            )
            .field("allowed_headers", &self.allowed_headers)
            .field("denied_headers", &self.denied_headers)
            .field("allowed_url_paths", &self.allowed_url_paths)
            .field("denied_url_paths", &self.denied_url_paths)
            .field(
                "allow_non_global_ip_ranges",
                &self.allow_non_global_ip_ranges,
            )
            .field("method_acl_default", &self.method_acl_default)
            .field("host_acl_default", &self.host_acl_default)
            .field("port_acl_default", &self.port_acl_default)
            .field("ip_acl_default", &self.ip_acl_default)
            .field("header_acl_default", &self.header_acl_default)
            .field("url_path_acl_default", &self.url_path_acl_default)
            .finish()
    }
}

impl PartialEq for HttpAclBuilder {
    fn eq(&self, other: &Self) -> bool {
        self.allow_http == other.allow_http
            && self.allow_https == other.allow_https
            && self.allowed_methods == other.allowed_methods
            && self.denied_methods == other.denied_methods
            && self.allowed_hosts == other.allowed_hosts
            && self.denied_hosts == other.denied_hosts
            && self.allowed_port_ranges == other.allowed_port_ranges
            && self.denied_port_ranges == other.denied_port_ranges
            && self.allowed_ip_ranges == other.allowed_ip_ranges
            && self.denied_ip_ranges == other.denied_ip_ranges
            && self.static_dns_mapping == other.static_dns_mapping
            && self.trusted_static_dns_mapping == other.trusted_static_dns_mapping
            && self.allowed_headers == other.allowed_headers
            && self.denied_headers == other.denied_headers
            && self.allowed_url_paths == other.allowed_url_paths
            && self.denied_url_paths == other.denied_url_paths
            && self.allow_non_global_ip_ranges == other.allow_non_global_ip_ranges
            && self.method_acl_default == other.method_acl_default
            && self.host_acl_default == other.host_acl_default
            && self.port_acl_default == other.port_acl_default
            && self.ip_acl_default == other.ip_acl_default
            && self.header_acl_default == other.header_acl_default
            && self.url_path_acl_default == other.url_path_acl_default
    }
}

impl HttpAclBuilder {
    /// Create a new [`HttpAclBuilder`].
    pub fn new() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: vec![
                HttpRequestMethod::CONNECT,
                HttpRequestMethod::DELETE,
                HttpRequestMethod::GET,
                HttpRequestMethod::HEAD,
                HttpRequestMethod::OPTIONS,
                HttpRequestMethod::PATCH,
                HttpRequestMethod::POST,
                HttpRequestMethod::PUT,
                HttpRequestMethod::TRACE,
            ],
            denied_methods: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_host_patterns: Vec::new(),
            denied_host_patterns: Vec::new(),
            allowed_port_ranges: vec![80..=80, 443..=443],
            denied_port_ranges: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allowed_headers: HashMap::new(),
            denied_headers: HashMap::new(),
            allowed_url_paths: Vec::new(),
            allowed_url_paths_router: Router::new(),
            denied_url_paths: Vec::new(),
            denied_url_paths_router: Router::new(),
            allow_non_global_ip_ranges: false,
            static_dns_mapping: HashMap::new(),
            trusted_static_dns_mapping: HashMap::new(),
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
            header_acl_default: true,
            url_path_acl_default: true,
        }
    }

    /// Sets whether HTTP is allowed.
    pub fn http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Sets whether HTTPS is allowed.
    pub fn https(mut self, allow: bool) -> Self {
        self.allow_https = allow;
        self
    }

    /// Sets whether non-global IP ranges are allowed.
    ///
    /// Non-global IP ranges include private, loopback, link-local, and other special-use addresses.
    pub fn non_global_ip_ranges(mut self, allow: bool) -> Self {
        self.allow_non_global_ip_ranges = allow;
        self
    }

    /// Set default action for HTTP methods if no ACL match is found.
    pub fn method_acl_default(mut self, allow: bool) -> Self {
        self.method_acl_default = allow;
        self
    }

    /// Set default action for hosts if no ACL match is found.
    pub fn host_acl_default(mut self, allow: bool) -> Self {
        self.host_acl_default = allow;
        self
    }

    /// Set default action for ports if no ACL match is found.
    pub fn port_acl_default(mut self, allow: bool) -> Self {
        self.port_acl_default = allow;
        self
    }

    /// Set default action for IPs if no ACL match is found.
    pub fn ip_acl_default(mut self, allow: bool) -> Self {
        self.ip_acl_default = allow;
        self
    }

    /// Set default action for headers if no ACL match is found.
    pub fn header_acl_default(mut self, allow: bool) -> Self {
        self.header_acl_default = allow;
        self
    }

    /// Set default action for URL paths if no ACL match is found.
    pub fn url_path_acl_default(mut self, allow: bool) -> Self {
        self.url_path_acl_default = allow;
        self
    }

    /// Adds a method to the allowed methods.
    ///
    /// Note: If you pass a string ensure it is uppercased first.
    pub fn add_allowed_method(
        mut self,
        method: impl Into<HttpRequestMethod>,
    ) -> Result<Self, AddError> {
        let method = method.into();
        if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDeniedMethod(method))
        } else if self.allowed_methods.contains(&method) {
            Err(AddError::AlreadyAllowedMethod(method))
        } else {
            self.allowed_methods.push(method);
            Ok(self)
        }
    }

    /// Removes a method from the allowed methods.
    ///
    /// Note: If you pass a string ensure it is uppercased first.
    pub fn remove_allowed_method(mut self, method: impl Into<HttpRequestMethod>) -> Self {
        let method = method.into();
        self.allowed_methods.retain(|m| m != &method);
        self
    }

    /// Sets the allowed methods.
    ///
    /// Note: If you pass strings ensure they are uppercased first.
    pub fn allowed_methods(
        mut self,
        methods: Vec<impl Into<HttpRequestMethod>>,
    ) -> Result<Self, AddError> {
        let methods = methods.into_iter().map(|m| m.into()).collect::<Vec<_>>();

        for method in &methods {
            if self.denied_methods.contains(method) {
                return Err(AddError::AlreadyDeniedMethod(method.clone()));
            }
        }
        self.allowed_methods = methods;
        Ok(self)
    }

    /// Clears the allowed methods.
    pub fn clear_allowed_methods(mut self) -> Self {
        self.allowed_methods.clear();
        self
    }

    /// Adds a method to the denied methods.
    ///
    /// Note: If you pass a string ensure it is uppercased first.
    pub fn add_denied_method(
        mut self,
        method: impl Into<HttpRequestMethod>,
    ) -> Result<Self, AddError> {
        let method = method.into();
        if self.allowed_methods.contains(&method) {
            Err(AddError::AlreadyAllowedMethod(method))
        } else if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDeniedMethod(method))
        } else {
            self.denied_methods.push(method);
            Ok(self)
        }
    }

    /// Removes a method from the denied methods.
    ///
    /// Note: If you pass a string ensure it is uppercased first.
    pub fn remove_denied_method(mut self, method: impl Into<HttpRequestMethod>) -> Self {
        let method = method.into();
        self.denied_methods.retain(|m| m != &method);
        self
    }

    /// Sets the denied methods.
    ///
    /// Note: If you pass strings ensure they are uppercased first.
    pub fn denied_methods(
        mut self,
        methods: Vec<impl Into<HttpRequestMethod>>,
    ) -> Result<Self, AddError> {
        let methods = methods.into_iter().map(|m| m.into()).collect::<Vec<_>>();

        for method in &methods {
            if self.allowed_methods.contains(method) {
                return Err(AddError::AlreadyAllowedMethod(method.clone()));
            }
        }
        self.denied_methods = methods;
        Ok(self)
    }

    /// Clears the denied methods.
    pub fn clear_denied_methods(mut self) -> Self {
        self.denied_methods.clear();
        self
    }

    /// Adds a host to the allowed hosts.
    ///
    /// `host` may be an exact hostname, or a wildcard pattern where each label
    /// (dot-separated segment) is either literal or one of:
    ///
    /// - `?` - matches exactly one label (e.g. `?.example.com` matches `foo.example.com`
    ///   but not `foo.bar.example.com` or bare `example.com`).
    /// - `*` - matches one or more labels (e.g. `*.example.com` matches `foo.example.com`
    ///   and `foo.bar.example.com`, but not bare `example.com`).
    ///
    /// A wildcard must occupy an entire label; `foo*.example.com` is not a valid pattern.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn add_allowed_host(mut self, host: String) -> Result<Self, AddError> {
        let pattern = Self::validate_host_or_pattern(&host)?;

        if self.denied_hosts.contains(&host) {
            return Err(AddError::AlreadyDeniedHost(host));
        }
        if self.allowed_hosts.contains(&host) {
            return Err(AddError::AlreadyAllowedHost(host));
        }

        if let Some(pattern) = pattern {
            self.allowed_host_patterns.push(pattern);
        }
        self.allowed_hosts.push(host);
        Ok(self)
    }

    /// Removes a host from the allowed hosts.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn remove_allowed_host(mut self, host: String) -> Self {
        self.allowed_hosts.retain(|h| h != &host);
        self.allowed_host_patterns = Self::compile_host_patterns(&self.allowed_hosts);
        self
    }

    /// Sets the allowed hosts.
    ///
    /// See [`Self::add_allowed_host`] for the wildcard pattern syntax.
    ///
    /// Note: The hosts should be in their canonical form (lowercase, punycode for IDN).
    pub fn allowed_hosts(mut self, hosts: Vec<String>) -> Result<Self, AddError> {
        let mut patterns = Vec::new();
        for host in &hosts {
            if let Some(pattern) = Self::validate_host_or_pattern(host)? {
                patterns.push(pattern);
            }
            if self.denied_hosts.contains(host) {
                return Err(AddError::AlreadyDeniedHost(host.clone()));
            }
        }
        self.allowed_host_patterns = patterns;
        self.allowed_hosts = hosts;
        Ok(self)
    }

    /// Clears the allowed hosts.
    pub fn clear_allowed_hosts(mut self) -> Self {
        self.allowed_hosts.clear();
        self.allowed_host_patterns.clear();
        self
    }

    /// Adds a host to the denied hosts.
    ///
    /// See [`Self::add_allowed_host`] for the wildcard pattern syntax.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn add_denied_host(mut self, host: String) -> Result<Self, AddError> {
        let pattern = Self::validate_host_or_pattern(&host)?;

        if self.allowed_hosts.contains(&host) {
            return Err(AddError::AlreadyAllowedHost(host));
        }
        if self.denied_hosts.contains(&host) {
            return Err(AddError::AlreadyDeniedHost(host));
        }

        if let Some(pattern) = pattern {
            self.denied_host_patterns.push(pattern);
        }
        self.denied_hosts.push(host);
        Ok(self)
    }

    /// Removes a host from the denied hosts.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn remove_denied_host(mut self, host: String) -> Self {
        self.denied_hosts.retain(|h| h != &host);
        self.denied_host_patterns = Self::compile_host_patterns(&self.denied_hosts);
        self
    }

    /// Sets the denied hosts.
    ///
    /// See [`Self::add_allowed_host`] for the wildcard pattern syntax.
    ///
    /// Note: The hosts should be in their canonical form (lowercase, punycode for IDN).
    pub fn denied_hosts(mut self, hosts: Vec<String>) -> Result<Self, AddError> {
        let mut patterns = Vec::new();
        for host in &hosts {
            if let Some(pattern) = Self::validate_host_or_pattern(host)? {
                patterns.push(pattern);
            }
            if self.allowed_hosts.contains(host) {
                return Err(AddError::AlreadyAllowedHost(host.clone()));
            }
        }
        self.denied_host_patterns = patterns;
        self.denied_hosts = hosts;
        Ok(self)
    }

    /// Clears the denied hosts.
    pub fn clear_denied_hosts(mut self) -> Self {
        self.denied_hosts.clear();
        self.denied_host_patterns.clear();
        self
    }

    /// Validates a host string, returning its compiled [`HostPattern`] if it is a
    /// wildcard pattern, or `None` if it's a literal host.
    fn validate_host_or_pattern(host: &str) -> Result<Option<HostPattern>, AddError> {
        if is_wildcard_host(host) {
            match HostPattern::parse(host) {
                Some(pattern) => Ok(Some(pattern)),
                None => Err(AddError::InvalidEntity(host.to_string())),
            }
        } else if utils::authority::is_valid_host(host) {
            Ok(None)
        } else {
            Err(AddError::InvalidEntity(host.to_string()))
        }
    }

    /// Compiles the wildcard patterns out of a list of (already-validated) host strings.
    fn compile_host_patterns(hosts: &[String]) -> Vec<HostPattern> {
        hosts
            .iter()
            .filter(|h| is_wildcard_host(h))
            .filter_map(|h| HostPattern::parse(h))
            .collect()
    }

    /// Adds a port range to the allowed port ranges.
    pub fn add_allowed_port_range(
        mut self,
        port_range: RangeInclusive<u16>,
    ) -> Result<Self, AddError> {
        if self.denied_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyDeniedPortRange(port_range))
        } else if self.allowed_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyAllowedPortRange(port_range))
        } else if utils::range_overlaps(&self.allowed_port_ranges, &port_range, None)
            || utils::range_overlaps(&self.denied_port_ranges, &port_range, None)
        {
            Err(AddError::Overlaps(format!("{port_range:?}")))
        } else {
            self.allowed_port_ranges.push(port_range);
            Ok(self)
        }
    }

    /// Removes a port range from the allowed port ranges.
    pub fn remove_allowed_port_range(mut self, port_range: RangeInclusive<u16>) -> Self {
        self.allowed_port_ranges.retain(|p| p != &port_range);
        self
    }

    /// Sets the allowed port ranges.
    pub fn allowed_port_ranges(
        mut self,
        port_ranges: Vec<RangeInclusive<u16>>,
    ) -> Result<Self, AddError> {
        for (i, port_range) in port_ranges.iter().enumerate() {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyDeniedPortRange(port_range.clone()));
            } else if utils::range_overlaps(&port_ranges, port_range, Some(i))
                || utils::range_overlaps(&self.denied_port_ranges, port_range, None)
            {
                return Err(AddError::Overlaps(format!("{port_range:?}")));
            }
        }
        self.allowed_port_ranges = port_ranges;
        Ok(self)
    }

    /// Clears the allowed port ranges.
    pub fn clear_allowed_port_ranges(mut self) -> Self {
        self.allowed_port_ranges.clear();
        self
    }

    /// Adds a port range to the denied port ranges.
    pub fn add_denied_port_range(
        mut self,
        port_range: RangeInclusive<u16>,
    ) -> Result<Self, AddError> {
        if self.allowed_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyAllowedPortRange(port_range))
        } else if self.denied_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyDeniedPortRange(port_range))
        } else if utils::range_overlaps(&self.allowed_port_ranges, &port_range, None)
            || utils::range_overlaps(&self.denied_port_ranges, &port_range, None)
        {
            Err(AddError::Overlaps(format!("{port_range:?}")))
        } else {
            self.denied_port_ranges.push(port_range);
            Ok(self)
        }
    }

    /// Removes a port range from the denied port ranges.
    pub fn remove_denied_port_range(mut self, port_range: RangeInclusive<u16>) -> Self {
        self.denied_port_ranges.retain(|p| p != &port_range);
        self
    }

    /// Sets the denied port ranges.
    pub fn denied_port_ranges(
        mut self,
        port_ranges: Vec<RangeInclusive<u16>>,
    ) -> Result<Self, AddError> {
        for (i, port_range) in port_ranges.iter().enumerate() {
            if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyAllowedPortRange(port_range.clone()));
            } else if utils::range_overlaps(&port_ranges, port_range, Some(i))
                || utils::range_overlaps(&self.allowed_port_ranges, port_range, None)
            {
                return Err(AddError::Overlaps(format!("{port_range:?}")));
            }
        }
        self.denied_port_ranges = port_ranges;
        Ok(self)
    }

    /// Clears the denied port ranges.
    pub fn clear_denied_port_ranges(mut self) -> Self {
        self.denied_port_ranges.clear();
        self
    }

    /// Adds an IP range to the allowed IP ranges.
    pub fn add_allowed_ip_range<Ip: IntoIpRange>(mut self, ip_range: Ip) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDeniedIpRange(ip_range));
        } else if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowedIpRange(ip_range));
        } else if utils::range_overlaps(&self.allowed_ip_ranges, &ip_range, None)
            || utils::range_overlaps(&self.denied_ip_ranges, &ip_range, None)
        {
            return Err(AddError::Overlaps(format!("{ip_range:?}")));
        }
        self.allowed_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the allowed IP ranges.
    pub fn remove_allowed_ip_range<Ip: IntoIpRange>(
        mut self,
        ip_range: Ip,
    ) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        self.allowed_ip_ranges.retain(|ip| ip != &ip_range);
        Ok(self)
    }

    /// Sets the allowed IP ranges.
    pub fn allowed_ip_ranges<Ip: IntoIpRange>(
        mut self,
        ip_ranges: Vec<Ip>,
    ) -> Result<Self, AddError> {
        let ip_ranges = ip_ranges
            .into_iter()
            .map(|ip| ip.into_range())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        for (i, ip_range) in ip_ranges.iter().enumerate() {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyDeniedIpRange(ip_range.clone()));
            } else if utils::range_overlaps(&ip_ranges, ip_range, Some(i))
                || utils::range_overlaps(&self.denied_ip_ranges, ip_range, None)
            {
                return Err(AddError::Overlaps(format!("{ip_range:?}")));
            }
        }
        self.allowed_ip_ranges = ip_ranges;
        Ok(self)
    }

    /// Clears the allowed IP ranges.
    pub fn clear_allowed_ip_ranges(mut self) -> Self {
        self.allowed_ip_ranges.clear();
        self
    }

    /// Adds an IP range to the denied IP ranges.
    pub fn add_denied_ip_range<Ip: IntoIpRange>(mut self, ip_range: Ip) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowedIpRange(ip_range));
        } else if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDeniedIpRange(ip_range));
        } else if utils::range_overlaps(&self.allowed_ip_ranges, &ip_range, None)
            || utils::range_overlaps(&self.denied_ip_ranges, &ip_range, None)
        {
            return Err(AddError::Overlaps(format!("{ip_range:?}")));
        }
        self.denied_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the denied IP ranges.
    pub fn remove_denied_ip_range<Ip: IntoIpRange>(
        mut self,
        ip_range: Ip,
    ) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        self.denied_ip_ranges.retain(|ip| ip != &ip_range);
        Ok(self)
    }

    /// Sets the denied IP ranges.
    pub fn denied_ip_ranges<Ip: IntoIpRange>(
        mut self,
        ip_ranges: Vec<Ip>,
    ) -> Result<Self, AddError> {
        let ip_ranges = ip_ranges
            .into_iter()
            .map(|ip| ip.into_range())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        for (i, ip_range) in ip_ranges.iter().enumerate() {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyAllowedIpRange(ip_range.clone()));
            } else if utils::range_overlaps(&ip_ranges, ip_range, Some(i))
                || utils::range_overlaps(&self.allowed_ip_ranges, ip_range, None)
            {
                return Err(AddError::Overlaps(format!("{ip_range:?}")));
            }
        }
        self.denied_ip_ranges = ip_ranges;
        Ok(self)
    }

    /// Clears the denied IP ranges.
    pub fn clear_denied_ip_ranges(mut self) -> Self {
        self.denied_ip_ranges.clear();
        self
    }

    /// Add a static DNS mapping.
    ///
    /// The resolved address is still subject to the IP and port ACL. Use
    /// [`Self::add_trusted_static_dns_mapping`] for a mapping that should bypass
    /// those checks entirely.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn add_static_dns_mapping(
        mut self,
        host: String,
        sock_addr: SocketAddr,
    ) -> Result<Self, AddError> {
        if !utils::authority::is_valid_host(&host) {
            return Err(AddError::InvalidEntity(host));
        }
        if self.trusted_static_dns_mapping.contains_key(&host) {
            return Err(AddError::AlreadyPresentTrustedStaticDnsMapping(
                host, sock_addr,
            ));
        }
        if let Entry::Vacant(e) = self.static_dns_mapping.entry(host.clone()) {
            e.insert(sock_addr);
            Ok(self)
        } else {
            Err(AddError::AlreadyPresentStaticDnsMapping(host, sock_addr))
        }
    }

    /// Removes a static DNS mapping.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn remove_static_dns_mapping(mut self, host: &str) -> Self {
        self.static_dns_mapping.remove(host);
        self
    }

    /// Sets the static DNS mappings.
    ///
    /// Note: The hosts should be in their canonical form (lowercase, punycode for IDN).
    pub fn static_dns_mappings(
        mut self,
        mappings: HashMap<String, SocketAddr>,
    ) -> Result<Self, AddError> {
        for (host, ip) in &mappings {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.clone()));
            }
            if self.trusted_static_dns_mapping.contains_key(host) {
                return Err(AddError::AlreadyPresentTrustedStaticDnsMapping(
                    host.clone(),
                    *ip,
                ));
            }
            if self.static_dns_mapping.contains_key(host) {
                return Err(AddError::AlreadyPresentStaticDnsMapping(host.clone(), *ip));
            }
            self.static_dns_mapping.insert(host.to_string(), *ip);
        }
        Ok(self)
    }

    /// Clears the static DNS mappings.
    pub fn clear_static_dns_mappings(mut self) -> Self {
        self.static_dns_mapping.clear();
        self
    }

    /// Add a trusted static DNS mapping.
    ///
    /// Unlike [`Self::add_static_dns_mapping`], the resolved address is meant to
    /// bypass the IP and port ACL entirely - only use this for mappings you trust
    /// regardless of what the ACL would otherwise say (e.g. pinning a hostname to an
    /// internal address on purpose).
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn add_trusted_static_dns_mapping(
        mut self,
        host: String,
        sock_addr: SocketAddr,
    ) -> Result<Self, AddError> {
        if !utils::authority::is_valid_host(&host) {
            return Err(AddError::InvalidEntity(host));
        }
        if self.static_dns_mapping.contains_key(&host) {
            return Err(AddError::AlreadyPresentStaticDnsMapping(host, sock_addr));
        }
        if let Entry::Vacant(e) = self.trusted_static_dns_mapping.entry(host.clone()) {
            e.insert(sock_addr);
            Ok(self)
        } else {
            Err(AddError::AlreadyPresentTrustedStaticDnsMapping(
                host, sock_addr,
            ))
        }
    }

    /// Removes a trusted static DNS mapping.
    ///
    /// Note: The host should be in its canonical form (lowercase, punycode for IDN).
    pub fn remove_trusted_static_dns_mapping(mut self, host: &str) -> Self {
        self.trusted_static_dns_mapping.remove(host);
        self
    }

    /// Sets the trusted static DNS mappings.
    ///
    /// Note: The hosts should be in their canonical form (lowercase, punycode for IDN).
    pub fn trusted_static_dns_mappings(
        mut self,
        mappings: HashMap<String, SocketAddr>,
    ) -> Result<Self, AddError> {
        for (host, ip) in &mappings {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.clone()));
            }
            if self.static_dns_mapping.contains_key(host) {
                return Err(AddError::AlreadyPresentStaticDnsMapping(host.clone(), *ip));
            }
            if self.trusted_static_dns_mapping.contains_key(host) {
                return Err(AddError::AlreadyPresentTrustedStaticDnsMapping(
                    host.clone(),
                    *ip,
                ));
            }
            self.trusted_static_dns_mapping
                .insert(host.to_string(), *ip);
        }
        Ok(self)
    }

    /// Clears the trusted static DNS mappings.
    pub fn clear_trusted_static_dns_mappings(mut self) -> Self {
        self.trusted_static_dns_mapping.clear();
        self
    }

    /// Adds a header to the allowed headers.
    ///
    /// If `value` is `None`, any value for the header is allowed.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn add_allowed_header(
        mut self,
        header: String,
        value: Option<String>,
    ) -> Result<Self, AddError> {
        if self.denied_headers.contains_key(&header) {
            Err(AddError::AlreadyDeniedHeader(header, value.clone()))
        } else if let Entry::Vacant(e) = self.allowed_headers.entry(header.clone()) {
            e.insert(value);
            Ok(self)
        } else {
            Err(AddError::AlreadyAllowedHeader(header, value))
        }
    }

    /// Removes a header from the allowed headers.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn remove_allowed_header(mut self, header: &str) -> Self {
        self.allowed_headers.remove(header);
        self
    }

    /// Sets the allowed headers.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn allowed_headers(
        mut self,
        headers: HashMap<String, Option<String>>,
    ) -> Result<Self, AddError> {
        for (header, value) in &headers {
            if self.denied_headers.contains_key(header) {
                return Err(AddError::AlreadyDeniedHeader(header.clone(), value.clone()));
            }
        }
        self.allowed_headers = headers;
        Ok(self)
    }

    /// Clears the allowed headers.
    pub fn clear_allowed_headers(mut self) -> Self {
        self.allowed_headers.clear();
        self
    }

    /// Adds a header to the denied headers.
    ///
    /// If `value` is `None`, any value for the header is denied.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn add_denied_header(
        mut self,
        header: String,
        value: Option<String>,
    ) -> Result<Self, AddError> {
        if self.allowed_headers.contains_key(&header) {
            Err(AddError::AlreadyAllowedHeader(header, value.clone()))
        } else if let Entry::Vacant(e) = self.denied_headers.entry(header.clone()) {
            e.insert(value);
            Ok(self)
        } else {
            Err(AddError::AlreadyDeniedHeader(header, value))
        }
    }

    /// Removes a header from the denied headers.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn remove_denied_header(mut self, header: &str) -> Self {
        self.denied_headers.remove(header);
        self
    }

    /// Sets the denied headers.
    ///
    /// Note: Ensure header names are lowercased.
    pub fn denied_headers(
        mut self,
        headers: HashMap<String, Option<String>>,
    ) -> Result<Self, AddError> {
        for (header, value) in &headers {
            if self.allowed_headers.contains_key(header) {
                return Err(AddError::AlreadyAllowedHeader(
                    header.clone(),
                    value.clone(),
                ));
            }
        }
        self.denied_headers = headers;
        Ok(self)
    }

    /// Clears the denied headers.
    pub fn clear_denied_headers(mut self) -> Self {
        self.denied_headers.clear();
        self
    }

    /// Adds a URL path to the allowed URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn add_allowed_url_path(mut self, url_path: String) -> Result<Self, AddError> {
        if self.denied_url_paths.contains(&url_path)
            || self.denied_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyDeniedUrlPath(url_path))
        } else if self.allowed_url_paths.contains(&url_path)
            || self.allowed_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyAllowedUrlPath(url_path))
        } else {
            self.allowed_url_paths.push(url_path.clone());
            self.allowed_url_paths_router
                .insert(url_path, ())
                .map_err(|_| AddError::InvalidEntity("Invalid URL path".to_string()))?;
            Ok(self)
        }
    }

    /// Removes a URL path from the allowed URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn remove_allowed_url_path(mut self, url_path: &str) -> Self {
        self.allowed_url_paths.retain(|p| p != url_path);
        self.allowed_url_paths_router = {
            let mut router = Router::new();
            for url_path in &self.allowed_url_paths {
                router
                    .insert(url_path.clone(), ())
                    .expect("failed to insert url path");
            }
            router
        };
        self
    }

    /// Sets the allowed URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn allowed_url_paths(mut self, url_paths: Vec<String>) -> Result<Self, AddError> {
        for url_path in &url_paths {
            if self.denied_url_paths.contains(url_path)
                || self.denied_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::AlreadyDeniedUrlPath(url_path.clone()));
            }
        }
        self.allowed_url_paths_router = Router::new();
        for url_path in &url_paths {
            self.allowed_url_paths_router
                .insert(url_path.clone(), ())
                .map_err(|_| AddError::InvalidEntity(format!("Invalid URL path: {url_path}")))?;
        }
        self.allowed_url_paths = url_paths;
        Ok(self)
    }

    /// Clears the allowed URL paths.
    pub fn clear_allowed_url_paths(mut self) -> Self {
        self.allowed_url_paths.clear();
        self.allowed_url_paths_router = Router::new();
        self
    }

    /// Adds a URL path to the denied URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn add_denied_url_path(mut self, url_path: String) -> Result<Self, AddError> {
        if self.allowed_url_paths.contains(&url_path)
            || self.allowed_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyAllowedUrlPath(url_path))
        } else if self.denied_url_paths.contains(&url_path)
            || self.denied_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyDeniedUrlPath(url_path))
        } else {
            self.denied_url_paths.push(url_path.clone());
            self.denied_url_paths_router
                .insert(url_path, ())
                .map_err(|_| AddError::InvalidEntity("Invalid URL path".to_string()))?;
            Ok(self)
        }
    }

    /// Removes a URL path from the denied URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn remove_denied_url_path(mut self, url_path: &str) -> Self {
        self.denied_url_paths.retain(|p| p != url_path);
        self.denied_url_paths_router = {
            let mut router = Router::new();
            for url_path in &self.denied_url_paths {
                router
                    .insert(url_path.clone(), ())
                    .expect("failed to insert url path");
            }
            router
        };
        self
    }

    /// Sets the denied URL paths.
    ///
    /// Note: URL paths should start with a '/' and be properly URL-encoded.
    pub fn denied_url_paths(mut self, url_paths: Vec<String>) -> Result<Self, AddError> {
        for url_path in &url_paths {
            if self.allowed_url_paths.contains(url_path)
                || self.allowed_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::AlreadyAllowedUrlPath(url_path.clone()));
            }
        }
        self.denied_url_paths_router = Router::new();
        for url_path in &url_paths {
            self.denied_url_paths_router
                .insert(url_path.clone(), ())
                .map_err(|_| AddError::InvalidEntity(format!("Invalid URL path: {url_path}")))?;
        }
        self.denied_url_paths = url_paths;
        Ok(self)
    }

    /// Clears the denied URL paths.
    pub fn clear_denied_url_paths(mut self) -> Self {
        self.denied_url_paths.clear();
        self.denied_url_paths_router = Router::new();
        self
    }

    /// Builds the [`HttpAcl`], without any [`HttpAclHooks`] attached.
    ///
    /// This does not validate the configuration (uniqueness, overlaps, non-global IP
    /// ranges); use [`Self::try_build`] instead if the builder wasn't assembled
    /// entirely through this type's own fallible `add_*`/`allowed_*`/`denied_*`
    /// methods, e.g. if it was deserialized. See [`Self::try_build`] for details.
    pub fn build(self) -> HttpAcl {
        self.build_full(HttpAclHooks::default())
    }

    /// Builds the [`HttpAcl`] with the given [`HttpAclHooks`] attached.
    ///
    /// This is the only way to attach a `ValidateFn`, `ModifyRequestFn`, or
    /// `ModifyResponseFn`; there is no dedicated builder setter for any of them.
    /// Like [`Self::build`], this does not validate the configuration; use
    /// [`Self::try_build_full`] for that.
    pub fn build_full(self, hooks: HttpAclHooks) -> HttpAcl {
        HttpAcl {
            allow_http: self.allow_http,
            allow_https: self.allow_https,
            allowed_methods: self.allowed_methods.into_iter().collect(),
            denied_methods: self.denied_methods.into_iter().collect(),
            allowed_hosts: self
                .allowed_hosts
                .into_iter()
                .filter(|h| !is_wildcard_host(h))
                .map(|x| x.into_boxed_str())
                .collect(),
            denied_hosts: self
                .denied_hosts
                .into_iter()
                .filter(|h| !is_wildcard_host(h))
                .map(|x| x.into_boxed_str())
                .collect(),
            allowed_host_patterns: self.allowed_host_patterns.into_boxed_slice(),
            denied_host_patterns: self.denied_host_patterns.into_boxed_slice(),
            allowed_port_ranges: self.allowed_port_ranges.into_boxed_slice(),
            denied_port_ranges: self.denied_port_ranges.into_boxed_slice(),
            allowed_ip_ranges: self.allowed_ip_ranges.into_boxed_slice(),
            denied_ip_ranges: self.denied_ip_ranges.into_boxed_slice(),
            allowed_headers: self
                .allowed_headers
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v.map(|s| s.into_boxed_str())))
                .collect(),
            denied_headers: self
                .denied_headers
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v.map(|s| s.into_boxed_str())))
                .collect(),
            allowed_url_paths_router: self.allowed_url_paths_router,
            denied_url_paths_router: self.denied_url_paths_router,
            static_dns_mapping: self
                .static_dns_mapping
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v))
                .collect(),
            trusted_static_dns_mapping: self
                .trusted_static_dns_mapping
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v))
                .collect(),
            validate_fn: hooks.validate_fn,
            modify_request_fn: hooks.modify_request_fn,
            modify_response_fn: hooks.modify_response_fn,
            allow_non_global_ip_ranges: self.allow_non_global_ip_ranges,
            method_acl_default: self.method_acl_default,
            host_acl_default: self.host_acl_default,
            port_acl_default: self.port_acl_default,
            ip_acl_default: self.ip_acl_default,
            header_acl_default: self.header_acl_default,
            url_path_acl_default: self.url_path_acl_default,
        }
    }

    /// Builds the [`HttpAcl`] with the given [`HttpAclHooks`] attached, validating
    /// the configuration first.
    ///
    /// Checks each category for unique entries, non-overlapping ranges, and no host
    /// (or port range, IP range, header, and so on) present on both the allowed and
    /// denied lists, returning [`AddError`] on the first problem found. It also
    /// enforces that IP ranges are global unless [`Self::non_global_ip_ranges`] was
    /// set to `true`, which [`Self::add_allowed_ip_range`]/
    /// [`Self::add_denied_ip_range`] do not check themselves.
    ///
    /// Prefer this over [`Self::build_full`] whenever the builder wasn't assembled
    /// entirely through this type's own fallible methods, most notably a builder
    /// deserialized from an untrusted source: deserialization writes fields directly
    /// and bypasses the checks each `add_*` method normally performs, so this is also
    /// what rebuilds the URL path routers and wildcard host patterns skipped for that
    /// reason.
    pub fn try_build_full(mut self, hooks: HttpAclHooks) -> Result<HttpAcl, AddError> {
        if !utils::has_unique_elements(&self.allowed_methods) {
            return Err(AddError::NotUnique(
                "Allowed methods must be unique.".to_string(),
            ));
        }
        for method in &self.allowed_methods {
            if self.denied_methods.contains(method) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Method `{}`",
                    method.as_str()
                )));
            }
        }
        if !utils::has_unique_elements(&self.denied_methods) {
            return Err(AddError::NotUnique(
                "Denied methods must be unique.".to_string(),
            ));
        }
        for method in &self.denied_methods {
            if self.allowed_methods.contains(method) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Method `{}`",
                    method.as_str()
                )));
            }
        }
        if !utils::has_unique_elements(&self.allowed_hosts) {
            return Err(AddError::NotUnique(
                "Allowed hosts must be unique.".to_string(),
            ));
        }
        for host in &self.allowed_hosts {
            if is_wildcard_host(host) {
                match HostPattern::parse(host) {
                    Some(pattern) => {
                        if !self.allowed_host_patterns.contains(&pattern) {
                            self.allowed_host_patterns.push(pattern);
                        }
                    }
                    None => return Err(AddError::InvalidEntity(host.to_string())),
                }
            } else if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
            if self.denied_hosts.contains(host) {
                return Err(AddError::BothAllowedAndDenied(format!("Host `{host}`")));
            }
        }
        if !utils::has_unique_elements(&self.denied_hosts) {
            return Err(AddError::NotUnique(
                "Denied hosts must be unique.".to_string(),
            ));
        }
        for host in &self.denied_hosts {
            if is_wildcard_host(host) {
                match HostPattern::parse(host) {
                    Some(pattern) => {
                        if !self.denied_host_patterns.contains(&pattern) {
                            self.denied_host_patterns.push(pattern);
                        }
                    }
                    None => return Err(AddError::InvalidEntity(host.to_string())),
                }
            } else if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
            if self.allowed_hosts.contains(host) {
                return Err(AddError::BothAllowedAndDenied(format!("Host `{host}`")));
            }
        }
        if !utils::has_unique_elements(&self.allowed_port_ranges) {
            return Err(AddError::NotUnique(
                "Allowed port ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.allowed_port_ranges) {
            return Err(AddError::Overlaps(
                "Allowed port ranges must not overlap.".to_string(),
            ));
        }
        for port_range in &self.allowed_port_ranges {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Port range `{port_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.denied_port_ranges) {
            return Err(AddError::NotUnique(
                "Denied port ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.denied_port_ranges) {
            return Err(AddError::Overlaps(
                "Denied port ranges must not overlap.".to_string(),
            ));
        }
        for port_range in &self.denied_port_ranges {
            if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Port range `{port_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.allowed_ip_ranges) {
            return Err(AddError::NotUnique(
                "Allowed IP ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.allowed_ip_ranges) {
            return Err(AddError::Overlaps(
                "Allowed IP ranges must not overlap.".to_string(),
            ));
        }
        for ip_range in &self.allowed_ip_ranges {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "IP range `{ip_range:?}`"
                )));
            }

            if (!utils::ip::is_global_ip(ip_range.start())
                || !utils::ip::is_global_ip(ip_range.end()))
                && !self.allow_non_global_ip_ranges
            {
                return Err(AddError::NonGlobalIpRange(ip_range.clone()));
            }
        }
        if !utils::has_unique_elements(&self.denied_ip_ranges) {
            return Err(AddError::NotUnique(
                "Denied IP ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.denied_ip_ranges) {
            return Err(AddError::Overlaps(
                "Denied IP ranges must not overlap.".to_string(),
            ));
        }
        for ip_range in &self.denied_ip_ranges {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "IP range `{ip_range:?}`"
                )));
            }

            if (!utils::ip::is_global_ip(ip_range.start())
                || !utils::ip::is_global_ip(ip_range.end()))
                && !self.allow_non_global_ip_ranges
            {
                return Err(AddError::NonGlobalIpRange(ip_range.clone()));
            }
        }
        if !utils::has_unique_elements(&self.static_dns_mapping) {
            return Err(AddError::NotUnique(
                "Static DNS mapping must be unique.".to_string(),
            ));
        }
        for (host, addr) in &self.static_dns_mapping {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
            if self.trusted_static_dns_mapping.contains_key(host) {
                return Err(AddError::AlreadyPresentTrustedStaticDnsMapping(
                    host.to_string(),
                    *addr,
                ));
            }
        }
        if !utils::has_unique_elements(&self.trusted_static_dns_mapping) {
            return Err(AddError::NotUnique(
                "Trusted static DNS mapping must be unique.".to_string(),
            ));
        }
        for host in self.trusted_static_dns_mapping.keys() {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
        }
        if !utils::has_unique_elements(&self.allowed_url_paths) {
            return Err(AddError::NotUnique(
                "Allowed URL paths must be unique.".to_string(),
            ));
        }
        for url_path in &self.allowed_url_paths {
            if self.denied_url_paths.contains(url_path)
                || self.denied_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "URL path `{url_path}`"
                )));
            } else if self.allowed_url_paths_router.at(url_path).is_err() {
                self.allowed_url_paths_router
                    .insert(url_path.clone(), ())
                    .map_err(|_| {
                        AddError::InvalidEntity(format!(
                            "Failed to insert allowed URL path `{url_path}`."
                        ))
                    })?;
            }
        }
        if !utils::has_unique_elements(&self.denied_url_paths) {
            return Err(AddError::NotUnique(
                "Denied URL paths must be unique.".to_string(),
            ));
        }
        for url_path in &self.denied_url_paths {
            if self.allowed_url_paths.contains(url_path)
                || self.allowed_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "URL path `{url_path}`"
                )));
            } else if self.denied_url_paths_router.at(url_path).is_err() {
                self.denied_url_paths_router
                    .insert(url_path.clone(), ())
                    .map_err(|_| {
                        AddError::InvalidEntity(format!(
                            "Failed to insert denied URL path `{url_path}`."
                        ))
                    })?;
            }
        }
        Ok(self.build_full(hooks))
    }

    /// Builds the [`HttpAcl`], without any [`HttpAclHooks`] attached, validating
    /// the configuration first. See [`Self::try_build_full`] for what is validated
    /// and when to prefer this over [`Self::build`].
    pub fn try_build(self) -> Result<HttpAcl, AddError> {
        self.try_build_full(HttpAclHooks::default())
    }
}
