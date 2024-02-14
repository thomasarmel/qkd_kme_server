use std::convert::Infallible;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::error;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::request_context::RequestContext;

pub(in crate::routes) async fn route_get_entropy_total(rcx: &RequestContext<'_>, _req: Request<body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    // Get the total entropy from stored keys
    let entropy = match rcx.qkd_manager.get_total_keys_shannon_entropy().await {
        Ok(entropy) => entropy,
        Err(e) => {
            error!("Error getting total entropy: {}", e.to_string());
            return super::EtsiSaeQkdRoutesV1::internal_server_error();
        }
    };
    let total_entropy_response_obj = crate::qkd_manager::http_response_obj::ResponseTotalKeysEntropy {
        total_entropy: entropy,
    };
    // Return the total entropy as a JSON object response
    let total_entropy_response_obj_json = match total_entropy_response_obj.to_json() {
        Ok(json) => json,
        Err(_) => {
            error!("Error serializing total entropy object");
            return super::EtsiSaeQkdRoutesV1::internal_server_error();
        }
    };
    Ok(crate::routes::EtsiSaeQkdRoutesV1::json_response_from_str(&total_entropy_response_obj_json))
}