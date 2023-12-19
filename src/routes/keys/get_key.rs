use hyper::{Body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, req: Request<Body>, slave_sae_id: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    match rcx.qkd_manager.get_qkd_key_status(rcx.get_client_certificate_serial_as_raw().unwrap(), slave_sae_id.parse::<i64>().unwrap()).unwrap() {
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