mod keys;
mod request_context;

use std::convert::Infallible;
use request_context::RequestContext;

use hyper::{body, Request, Response, StatusCode};
use crate::qkd_manager::{http_response_obj, QkdManager};
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use log::error;
use rustls_pki_types::CertificateDer;
use crate::RESPONSE_ERROR_FUNCTION;


#[async_trait]
pub trait Routes {
    async fn handle_request(req: Request<body::Incoming>, client_cert: Option<&CertificateDer>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible>;
}


pub struct QKDKMERoutes {}

#[async_trait]
impl Routes for QKDKMERoutes {
    async fn handle_request(req: Request<body::Incoming>, client_cert: Option<&CertificateDer>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_owned();

        let rcx = match RequestContext::new(client_cert, qkd_manager) {
            Ok(context) => context,
            Err(e) => {
                error!("Error creating context: {}", e.to_string());
                return Self::internal_server_error();
            }
        };

        let segments: Vec<&str> =
            path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 3 || segments[0] != "api" || segments[1] != "v1" {
            return Self::not_found();
        }
        match segments[2] {
            "keys" => keys::key_handler(&rcx, req, &segments[3..]).await,
            &_ => Self::not_found(),
        }
    }
}


#[allow(dead_code)]
impl QKDKMERoutes {
    RESPONSE_ERROR_FUNCTION!(internal_server_error, "Internal server error");
    RESPONSE_ERROR_FUNCTION!(not_found, "Element not found");
    RESPONSE_ERROR_FUNCTION!(authentication_error, "Authentication error");
    RESPONSE_ERROR_FUNCTION!(bad_request, "Bad request");
}

#[allow(non_snake_case)]
#[macro_export]
macro_rules! RESPONSE_ERROR_FUNCTION {
    ($function_name:tt, $error_message:expr) => {
        fn $function_name() -> Result<Response<Full<Bytes>>, Infallible> {
            let error_body = http_response_obj::ResponseError {
                message: String::from($error_message),
            };
            Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(error_body.to_json().unwrap()))).unwrap())
        }
    }
}