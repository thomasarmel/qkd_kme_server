use std::convert::Infallible;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use crate::routes::{QKDKMERoutes, RequestContext};

mod get_key;

pub(super) async fn key_handler(rcx: &RequestContext<'_>, req: Request<body::Incoming>, uri_segments: &[&str]) -> Result<Response<Full<Bytes>>, Infallible> {
    match (uri_segments, req.method()) {
        ([slave_sae_id, "status"], &hyper::Method::GET) => get_key::route_get_status(rcx, req, slave_sae_id),
        ([slave_sae_id, "enc_keys"], &hyper::Method::POST) => get_key::route_get_key(rcx, req, slave_sae_id),
        ([slave_sae_id, "dec_keys"], &hyper::Method::POST) => get_key::route_get_key_with_id(rcx, req, slave_sae_id).await,
        _ => QKDKMERoutes::not_found(),
    }
}