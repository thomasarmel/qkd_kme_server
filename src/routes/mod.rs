mod keys;
mod request_context;

use request_context::RequestContext;

use hyper::{Body, Request, Response, StatusCode};
use rustls::Certificate;
use crate::qkd_manager::{http_response_obj, QkdManager};
use crate::qkd_manager::http_response_obj::HttpResponseBody;


pub trait Routes {
    fn handle_request(req: Request<Body>, client_cert: Option<&Certificate>, qkd_manager: QkdManager) -> Response<Body>;
}

pub struct QKDKMERoutes {}

impl Routes for QKDKMERoutes {
    fn handle_request(req: Request<Body>, client_cert: Option<&Certificate>, qkd_manager: QkdManager) -> Response<Body> {
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
            "keys" => keys::key_handler(&rcx, req, &segments[3..]),
            &_ => Self::not_found(),
        }
    }
}


#[allow(dead_code)]
impl QKDKMERoutes {
    // TODO: macro would be cleaner :)
    fn internal_server_error() -> Response<Body> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Internal server error"),
        };
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(error_body.to_json()))
            .unwrap()
    }

    fn not_found() -> Response<Body> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Element not found"),
        };
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(error_body.to_json()))
            .unwrap()
    }

    fn authentication_error() -> Response<Body> {
        let error_body = http_response_obj::ResponseError {
            message: String::from("Authentication error"),
        };
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from(error_body.to_json()))
            .unwrap()
    }
}