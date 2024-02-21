//! Route definitions for the server

mod request_context;
pub mod inter_kmes_routes;
pub mod sae_zone_routes;

use std::convert::Infallible;
use request_context::RequestContext;

use hyper::{body, Request, Response};
use crate::qkd_manager::QkdManager;
use http_body_util::Full;
use hyper::body::Bytes;
use rustls_pki_types::CertificateDer;


/// Trait representing the routes of the server
/// Implement this trait to create a new routing system
/// Should be implemented by the struct that will be used as a router, for example at each version of the API
pub trait Routes {
    /// Function that handles the API request
    /// # Arguments
    /// * `req` - The request received by the server, in hyper format
    /// * `client_cert` - A reference to the client certificate, if present
    /// * `qkd_manager` - A clone of the QKD manager, to be used to access the QKD system
    /// # Returns
    /// A response to the request, in hyper format
    fn handle_request(req: Request<body::Incoming>, client_cert: Option<&CertificateDer>, qkd_manager: QkdManager) -> impl std::future::Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send; // Replacement for async_trait since Rust 1.75
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