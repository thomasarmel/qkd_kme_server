use hyper::{Body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, req: Request<Body>, slave_sae_id: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    let raw_client_certificate = match rcx.get_client_certificate_serial_as_raw() {
        Ok(serial) => serial,
        Err(_) => {
            return super::QKDKMERoutes::authentication_error();
        }
    };
    let slave_sae_id = match slave_sae_id.parse::<i64>() {
        Ok(sae_id) => sae_id,
        Err(_) => {
            return super::QKDKMERoutes::bad_request();
        }
    };
    match rcx.qkd_manager.get_qkd_key_status(raw_client_certificate, slave_sae_id).unwrap() {
        QkdManagerResponse::Status(key_status) => {
            Response::new(Body::from(key_status.to_json()))
        },
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        },
        _ => {
            super::QKDKMERoutes::internal_server_error()
        },
    }
}

pub(in crate::routes) fn route_get_key(rcx: &RequestContext, req: Request<Body>, slave_sae_id: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    match rcx.qkd_manager.get_qkd_key(slave_sae_id.parse::<i64>().unwrap(), rcx.get_client_certificate_serial_as_raw().unwrap()).unwrap() {
        QkdManagerResponse::Keys(keys) => {
            Response::new(Body::from(keys.to_json()))
        },
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        },
        _ => {
            super::QKDKMERoutes::internal_server_error()
        },
    }
}