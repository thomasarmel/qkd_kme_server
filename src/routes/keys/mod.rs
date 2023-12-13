use hyper::{Body, Request, Response};
use crate::routes::{QKDKMERoutes, RequestContext};

mod get_key;

pub(super) fn key_handler(rcx: &RequestContext, req: Request<Body>, uri_segments: &[&str]) -> Response<Body> {
    match (uri_segments, req.method()) {
        ([slave_sae_id, "status"], &hyper::Method::GET) => get_key::route_get_status(rcx, req, slave_sae_id),
        _ => QKDKMERoutes::not_found(),
    }
}