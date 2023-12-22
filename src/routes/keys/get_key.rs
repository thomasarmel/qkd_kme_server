use std::convert::{identity, Infallible};
use hyper::{body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use std::string::String;
use log::{error, warn};
use crate::qkd_manager::http_request_obj::RequestListKeysIds;
use crate::ensure_sae_id_integer;
use crate::ensure_client_certificate_serial;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, _req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let raw_client_certificate = match rcx.get_client_certificate_serial_as_raw() {
        Ok(serial) => serial,
        Err(_) => {
            return super::QKDKMERoutes::authentication_error();
        }
    };
    let slave_sae_id_i64 = ensure_sae_id_integer!(slave_sae_id);
    match rcx.qkd_manager.get_qkd_key_status(raw_client_certificate, slave_sae_id_i64).unwrap_or_else(identity) {
        QkdManagerResponse::Status(key_status) => {
            let key_status_json = match key_status.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing key status");
                    return super::QKDKMERoutes::internal_server_error();
                }
            };
            Ok(response_from_str(&key_status_json))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        }
        _ => {
            super::QKDKMERoutes::internal_server_error()
        }
    }
}

pub(in crate::routes) fn route_get_key(rcx: &RequestContext, _req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let slave_sae_id_i64 = ensure_sae_id_integer!(slave_sae_id);
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);
    match rcx.qkd_manager.get_qkd_key(slave_sae_id_i64, raw_client_certificate_serial).unwrap_or_else(identity) {
        QkdManagerResponse::Keys(keys) => {
            let keys_json = match keys.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing keys");
                    return super::QKDKMERoutes::internal_server_error();
                }
            };
            Ok(response_from_str(&keys_json))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutes::authentication_error()
        }
        QkdManagerResponse::NotFound => {
            super::QKDKMERoutes::not_found()
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
    let master_sae_id_i64 = ensure_sae_id_integer!(master_sae_id);
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);
    match rcx.qkd_manager.get_qkd_keys_with_ids(master_sae_id_i64, raw_client_certificate_serial, keys_uuids).unwrap_or_else(identity) {
        QkdManagerResponse::Keys(keys) => {
            let keys_json = match keys.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing keys");
                    return super::QKDKMERoutes::internal_server_error();
                }
            };
            Ok(response_from_str(&keys_json))
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

#[macro_export]
macro_rules! ensure_sae_id_integer {
    ($sae_id:expr) => {
        match $sae_id.parse::<i64>() {
            Ok(sae_id) => sae_id,
            Err(_) => {
                warn!("Invalid SAE ID, must be an integer");
                return super::QKDKMERoutes::bad_request();
            }
        }
    }
}

#[macro_export]
macro_rules! ensure_client_certificate_serial {
    ($request_context:expr) => {
        match $request_context.get_client_certificate_serial_as_raw() {
            Ok(serial) => serial,
            Err(_) => {
                warn!("Error getting client certificate serial");
                return super::QKDKMERoutes::authentication_error();
            }
        }
    }
}