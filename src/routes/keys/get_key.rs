use std::convert::Infallible;
use hyper::{body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use std::string::String;
use crate::qkd_manager::http_request_obj::RequestListKeysIds;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
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
            Ok(response_from_str(&key_status.to_json()))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        }
        _ => {
            super::QKDKMERoutes::internal_server_error()
        }
    }
}

pub(in crate::routes) fn route_get_key(rcx: &RequestContext, req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    println!("{}", req.uri().path());
    match rcx.qkd_manager.get_qkd_key(slave_sae_id.parse::<i64>().unwrap(), rcx.get_client_certificate_serial_as_raw().unwrap()).unwrap() {
        QkdManagerResponse::Keys(keys) => {
            Ok(response_from_str(&keys.to_json()))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        }
        _ => {
            super::QKDKMERoutes::internal_server_error()
        }
    }
}

pub(in crate::routes) async fn route_get_key_with_id(rcx: &RequestContext<'_>, req: Request<body::Incoming>, master_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let post_body_bytes = match req.into_body().collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(_) => {
            return super::QKDKMERoutes::bad_request();
        }
    };
    let request_list_keys_ids: RequestListKeysIds = match serde_json::from_slice(&post_body_bytes) {
        Ok(request_list_keys_ids) => request_list_keys_ids,
        Err(_) => {
            return super::QKDKMERoutes::bad_request();
        }
    };
    let keys_uuids: Vec<String> = request_list_keys_ids.key_IDs.iter().map(|key_id| key_id.key_ID.clone()).collect();
    match rcx.qkd_manager.get_qkd_keys_with_ids(master_sae_id.parse::<i64>().unwrap(), rcx.get_client_certificate_serial_as_raw().unwrap(), keys_uuids).unwrap() {
        QkdManagerResponse::Keys(keys) => {
            Ok(response_from_str(&keys.to_json()))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        }
        _ => {
            super::QKDKMERoutes::internal_server_error()
        }
    }
}

fn response_from_str(body: &str) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(String::from(body))))
}