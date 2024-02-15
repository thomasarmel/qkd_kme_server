//! Routes for the `/api/v1/sae` endpoint, managing SAEs

mod info;

use std::convert::Infallible;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use crate::routes::request_context::RequestContext;

/// Dispatches the request to the correct function
pub(in crate::routes) async fn sae_handler(rcx: &RequestContext<'_>, req: Request<body::Incoming>, uri_segments: &[&str]) -> Result<Response<Full<Bytes>>, Infallible> {
    match (uri_segments, req.method()) {
        (["info", "me"], &hyper::Method::GET) => info::route_get_info_me(rcx, req).await,
        _ => super::EtsiSaeQkdRoutesV1::not_found(),
    }
}