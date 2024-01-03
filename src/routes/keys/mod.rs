use std::convert::Infallible;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use crate::routes::{QKDKMERoutesV1, RequestContext};

mod get_key;

/// Dispatches the request to the correct function
pub(super) async fn key_handler(rcx: &RequestContext<'_>, req: Request<body::Incoming>, uri_segments: &[&str]) -> Result<Response<Full<Bytes>>, Infallible> {
    match (uri_segments, req.method()) {
        // Get the status of key(s) from a master SAE (how many keys are available etc.)
        ([slave_sae_id, "status"], &hyper::Method::GET) => get_key::route_get_status(rcx, req, slave_sae_id),
        // Get key(s) from a master SAE (only 1 key for now)
        ([slave_sae_id, "enc_keys"], &hyper::Method::POST) => get_key::route_get_key(rcx, req, slave_sae_id),
        // Get key(s) from a slave SAE, with ID provided by the master SAE
        ([slave_sae_id, "dec_keys"], &hyper::Method::POST) => get_key::route_get_key_with_id(rcx, req, slave_sae_id).await,
        // Route not found
        _ => QKDKMERoutesV1::not_found(),
    }
}