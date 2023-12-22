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
use rustls_pki_types::CertificateDer;


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
                eprintln!("Error creating context: {}", e.to_string());
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
    // TODO: macro would be cleaner :)
    fn internal_server_error() -> Result<Response<Full<Bytes>>, Infallible> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Internal server error"),
        };
        Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::from(error_body.to_json()))).unwrap())
    }

    fn not_found() -> Result<Response<Full<Bytes>>, Infallible> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Element not found"),
        };
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::from(error_body.to_json()))).unwrap())
    }

    fn authentication_error() -> Result<Response<Full<Bytes>>, Infallible> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Authentication error"),
        };
        Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Full::new(Bytes::from(error_body.to_json()))).unwrap())
    }

    fn bad_request() -> Result<Response<Full<Bytes>>, Infallible> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Bad request"),
        };
        Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(error_body.to_json()))).unwrap())
    }
}