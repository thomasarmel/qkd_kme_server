//! Route definitions for the server

mod keys;
mod request_context;
mod sae;
pub mod inter_kmes_routes;

use std::convert::Infallible;
use request_context::RequestContext;

use hyper::{body, Request, Response, StatusCode};
use crate::qkd_manager::{http_response_obj, QkdManager};
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use log::error;
use rustls_pki_types::CertificateDer;
use crate::RESPONSE_ERROR_FUNCTION;


/// Trait representing the routes of the server
/// Implement this trait to create a new routing system
/// Should be implemented by the struct that will be used as a router, for example at each version of the API
#[async_trait]
pub trait Routes {
    /// Function that handles the API request
    /// # Arguments
    /// * `req` - The request received by the server, in hyper format
    /// * `client_cert` - A reference to the client certificate, if present
    /// * `qkd_manager` - A clone of the QKD manager, to be used to access the QKD system
    /// # Returns
    /// A response to the request, in hyper format
    async fn handle_request(req: Request<body::Incoming>, client_cert: Option<&CertificateDer>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible>;
}

/// Struct representing the routes of the server for the v1 version of the API
pub struct EtsiSaeQkdRoutesV1 {}

#[async_trait]
impl Routes for EtsiSaeQkdRoutesV1 {
    async fn handle_request(req: Request<body::Incoming>, client_cert: Option<&CertificateDer>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_owned();

        // Create the request context
        let rcx = match RequestContext::new(client_cert, qkd_manager) {
            Ok(context) => context,
            Err(e) => {
                error!("Error creating context: {}", e.to_string());
                return Self::internal_server_error();
            }
        };

        // Split the path into segments, eg "/api/v1/keys" -> ["api", "v1", "keys"]
        let segments: Vec<&str> =
            path.split('/').filter(|s| !s.is_empty()).collect();

        // If path has less than 3 segments, or the first two segments are not "api" and "v1", return 404
        if segments.len() < 3 || segments[0] != "api" || segments[1] != "v1" {
            return Self::not_found();
        }

        // Call the correct handler based on the third segment
        match segments[2] {
            "keys" => keys::key_handler(&rcx, req, &segments[3..]).await,
            "sae" => sae::sae_handler(&rcx, req, &segments[3..]).await,
            &_ => Self::not_found(), // Third segment must be "keys"
        }
    }
}


#[allow(dead_code)]
impl EtsiSaeQkdRoutesV1 {
    RESPONSE_ERROR_FUNCTION!(internal_server_error, StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    RESPONSE_ERROR_FUNCTION!(not_found, StatusCode::NOT_FOUND, "Element not found");
    RESPONSE_ERROR_FUNCTION!(authentication_error, StatusCode::UNAUTHORIZED, "Authentication error");
    RESPONSE_ERROR_FUNCTION!(bad_request, StatusCode::BAD_REQUEST, "Bad request");

    /// Creates a HTTP response 200 from a string (likely a JSON)
    /// # Arguments
    /// * `body` - The body of the response, as a string
    /// # Returns
    /// A HTTP response with status code 200 and the body as a JSON content type
    fn json_response_from_str(body: &str) -> Response<Full<Bytes>> {
        const JSON_CONTENT_TYPE: &'static str = "application/json";
        Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, JSON_CONTENT_TYPE).body(Full::new(Bytes::from(String::from(body)))).unwrap()
    }
}

/// Macro to generate the functions that return the error responses
#[allow(non_snake_case)]
#[macro_export]
macro_rules! RESPONSE_ERROR_FUNCTION {
    ($function_name:tt, $status_code:expr, $error_message:expr) => {
        fn $function_name() -> Result<Response<Full<Bytes>>, Infallible> {
            // Create the body of the error response
            let error_body = http_response_obj::ResponseError {
                message: String::from($error_message),
            };
            // Send back HTTP error code and JSON message, following ETSI standard
            Ok(Response::builder().status($status_code).body(Full::new(Bytes::from(error_body.to_json().unwrap()))).unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use hyper::StatusCode;

    #[tokio::test]
    async fn test_internal_server_error() {
        let response = super::EtsiSaeQkdRoutesV1::internal_server_error().unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(body, "{\n  \"message\": \"Internal server error\"\n}");
    }

    #[tokio::test]
    async fn test_not_found() {
        let response = super::EtsiSaeQkdRoutesV1::not_found().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(body, "{\n  \"message\": \"Element not found\"\n}");
    }

    #[tokio::test]
    async fn test_authentication_error() {
        let response = super::EtsiSaeQkdRoutesV1::authentication_error().unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(body, "{\n  \"message\": \"Authentication error\"\n}");
    }

    #[tokio::test]
    async fn test_bad_request() {
        let response = super::EtsiSaeQkdRoutesV1::bad_request().unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(body, "{\n  \"message\": \"Bad request\"\n}");
    }

    #[tokio::test]
    async fn test_json_response_from_str() {
        let response = super::EtsiSaeQkdRoutesV1::json_response_from_str("{\"variable\": \"value\"}");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert_eq!(body, "{\"variable\": \"value\"}");
    }
}