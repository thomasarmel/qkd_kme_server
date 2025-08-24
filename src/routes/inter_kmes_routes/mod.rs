//! Describes routes for specific inter KME channels over public network, generally to activate keys on remote KMEs

use std::convert::Infallible;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use rustls_pki_types::CertificateDer;
use crate::MAX_QKD_KEY_PER_KEY_ENC_REQUEST;
use crate::qkd_manager::http_request_obj::ActivateKeyRemoteKME;
use crate::qkd_manager::QkdManager;
use crate::routes::Routes;

/// Routes for inter KMEs communication over public network
pub struct InterKMEsRoutes {}

impl Routes for InterKMEsRoutes {
    async fn handle_request(req: Request<Incoming>, _client_cert: Option<&CertificateDer<'_>>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_owned();
        if path != "/keys/activate" {
            return Ok(Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::from(String::from("Not found")))).unwrap());
        }

        let post_body_bytes = match req.into_body().collect().await {
            Ok(bytes) => bytes.to_bytes(),
            Err(_) => {
                return Self::bad_request();
            }
        };

        let key_to_activate_obj: ActivateKeyRemoteKME = match serde_json::from_slice(&post_body_bytes) {
            Ok(request_list_keys_ids) => request_list_keys_ids,
            Err(_) => {
                return Self::bad_request();
            }
        };

        if key_to_activate_obj.key_IDs_list.len() > MAX_QKD_KEY_PER_KEY_ENC_REQUEST {
            return Ok(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!("Too many keys requested, max is {}", MAX_QKD_KEY_PER_KEY_ENC_REQUEST)))).unwrap()
            );
        }

        let response = qkd_manager.activate_key_from_remote(
            key_to_activate_obj.origin_SAE_ID,
            key_to_activate_obj.remote_SAE_ID,
            key_to_activate_obj.key_IDs_list);
        let http_response = match response {
            Ok(_) => Ok(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::from(String::from("OK")))).unwrap()),
            Err(_) => Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(String::from("Cannot activate key")))).unwrap())
        };
        http_response
    }
}

impl InterKMEsRoutes {
    fn bad_request() -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(String::from("Bad request")))).unwrap())
    }
}