//! Contains the [`ModifyRequestFn`], [`ModifyResponseFn`], [`RequestMutation`], and
//! [`ResponseMutation`] types used to attach request/response mutation hooks to an
//! [`HttpAcl`](crate::HttpAcl).

use std::sync::Arc;

use bytes::Bytes;

use crate::utils::authority::Authority;

/// An owned, mutable view of an outgoing request's headers and body, handed to a
/// [`ModifyRequestFn`].
///
/// Headers are a `Vec<(String, String)>` rather than a map, so order is preserved
/// and duplicate header names are kept as separate entries rather than collapsed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RequestMutation {
    /// The request's headers, in wire order.
    pub headers: Vec<(String, String)>,
    /// The request's body, if any and if readable.
    ///
    /// `None` here means there was either no body to begin with, or the body exists
    /// but couldn't be read without consuming a stream (the same limitation
    /// [`HttpAcl::is_valid`](crate::HttpAcl::is_valid)'s body parameter already has).
    /// Leaving this as `None` on the way out never clears an existing body - it is
    /// only ever an instruction to leave the body untouched, so a [`ModifyRequestFn`]
    /// that only wants to touch headers can never accidentally truncate a body it was
    /// never shown. Set it to `Some(bytes)` to replace the body wholesale.
    pub body: Option<Bytes>,
}

/// An owned, mutable view of an incoming response's status, headers, and body,
/// handed to a [`ModifyResponseFn`].
///
/// Unlike [`RequestMutation::body`], this is always the full, already-buffered
/// body - a [`ModifyResponseFn`] is only ever invoked once the whole response has
/// been read into memory. See
/// [`HttpAcl::has_modify_response`](crate::HttpAcl::has_modify_response) for the
/// performance implications of that.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResponseMutation {
    /// The response's HTTP status code.
    pub status: u16,
    /// The response's headers, in wire order. See [`RequestMutation::headers`].
    pub headers: Vec<(String, String)>,
    /// The response's body.
    pub body: Bytes,
}

/// A function that mutates an outgoing request's headers and/or body before it is
/// sent, e.g. to inject a secret or authentication header.
///
/// Called with the request's scheme and authority (host and port), the same context
/// [`ValidateFn`](crate::ValidateFn) gets, so a single [`HttpAcl`](crate::HttpAcl)
/// shared across multiple hosts can scope what it injects to a specific destination
/// rather than leaking it to every host the ACL allows.
///
/// A `ModifyRequestFn` is attached via
/// [`HttpAclBuilder::build_full`](crate::HttpAclBuilder::build_full) or
/// [`HttpAclBuilder::try_build_full`](crate::HttpAclBuilder::try_build_full) (as part
/// of an [`HttpAclHooks`](crate::HttpAclHooks)) rather than a dedicated builder
/// setter, for the same reason [`ValidateFn`](crate::ValidateFn) is: it typically
/// captures state from outside the builder.
pub type ModifyRequestFn = Arc<dyn Fn(&str, &Authority, &mut RequestMutation) + Send + Sync>;

/// A function that mutates an incoming response's status, headers, and/or body
/// before the caller sees it, e.g. to redact sensitive fields.
///
/// Called with the *request's* scheme and authority (i.e. where the response came
/// from) and a [`ResponseMutation`] to mutate in place. See [`ModifyRequestFn`] for
/// why it isn't attached via a dedicated builder setter.
///
/// Attaching a `ModifyResponseFn` forces the entire response body to be buffered
/// into memory and the response rebuilt, for every request the ACL is used with -
/// there is no way to opt in per-request. See
/// [`HttpAcl::has_modify_response`](crate::HttpAcl::has_modify_response).
pub type ModifyResponseFn = Arc<dyn Fn(&str, &Authority, &mut ResponseMutation) + Send + Sync>;
