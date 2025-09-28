//! Routes for the `/api/v1/keys` endpoint, managing QKD keys

use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use crate::routes::RequestContext;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{body, Request, Response};
use std::convert::Infallible;

mod get_key;
mod get_key_with_id;
mod route_entropy;
mod get_status;

/// Dispatches the request to the correct function
pub(in crate::routes) async fn key_handler(rcx: &RequestContext<'_>, req: Request<body::Incoming>, uri_segments: &[&str]) -> Result<Response<Full<Bytes>>, Infallible> {
    match (uri_segments, req.method()) {
        // Get the status of key(s) from a master SAE (how many keys are available etc.)
        ([slave_sae_id, "status"], &hyper::Method::GET) => get_status::route_get_status(rcx, req, slave_sae_id),
        // Get key(s) from a master SAE (only 1 key for now)
        ([slave_sae_id, "enc_keys"], &hyper::Method::GET | &hyper::Method::POST) => get_key::route_get_key(rcx, req, slave_sae_id).await,
        // Get key(s) from a slave SAE, with ID provided by the master SAE
        ([slave_sae_id, "dec_keys"], &hyper::Method::POST) => get_key_with_id::route_get_key_with_id(rcx, req, slave_sae_id).await,
        // Retrieve Shannon's entropy for all stored keys in KME database
        (["entropy", "total"], &hyper::Method::GET) => route_entropy::route_get_entropy_total(rcx, req).await,
        // Route not found
        _ => EtsiSaeQkdRoutesV1::not_found(),
    }
}

/// Casts the SAE ID to an integer, or returns a 400 error if fails
#[macro_export]
macro_rules! ensure_sae_id_format_type {
    ($sae_id:expr) => {
        match $sae_id.parse::<crate::SaeId>() {
            Ok(sae_id) => sae_id,
            Err(_) => {
                use log::warn;
                warn!("Invalid SAE ID, must be an integer");
                return super::EtsiSaeQkdRoutesV1::bad_request();
            }
        }
    }
}

/// Gets the client certificate serial as a raw byte vector, or returns a 401 error if fails (should never happen in a normal scenario)
#[macro_export]
macro_rules! ensure_client_certificate_serial {
    ($request_context:expr) => {
        match $request_context.get_client_certificate_serial_as_raw() {
            Ok(serial) => serial,
            Err(_) => {
                use log::warn;
                warn!("Error getting client certificate serial");
                return super::EtsiSaeQkdRoutesV1::authentication_error();
            }
        }
    }
}