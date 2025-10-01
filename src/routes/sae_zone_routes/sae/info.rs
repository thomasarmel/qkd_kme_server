//! sae/info route
//! Retrieve information about a SAE

use std::convert::Infallible;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::error;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::request_context::RequestContext;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;

/// Allows a SAE to retrieve its own information
/// eg `GET /api/v1/sae/info/me`
pub(in crate::routes) async fn route_get_info_me(rcx: &RequestContext<'_>, _req: Request<body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check if the client certificate serial is present, should always be the case
    let client_cert_serial = match rcx.get_client_certificate_serial_as_raw() {
        Ok(serial) => serial,
        Err(_) => {
            return EtsiSaeQkdRoutesV1::authentication_error()
        }
    };
    // Retrieve the SAE ID from the QKD manager, given the client certificate serial
    let sae_info = match rcx.qkd_manager.get_sae_info_from_client_auth_certificate(&client_cert_serial).await {
        Ok(sae_info) => sae_info,
        Err(_) => {
            // Client certificate serial isn't registered in the QKD manager
            return EtsiSaeQkdRoutesV1::not_found()
        }
    };

    // Create the response object
    let sae_info_response_obj = crate::qkd_manager::http_response_obj::ResponseQkdSAEInfo {
        SAE_ID: sae_info.sae_id,
        KME_ID: sae_info.kme_id,
    };
    match sae_info_response_obj.to_json() {
        Ok(json) => {
            Ok(EtsiSaeQkdRoutesV1::json_response_from_str(&json))
        }
        Err(_) => {
            // Error serializing the response object, should never happen
            error!("Error serializing SAE info");
            EtsiSaeQkdRoutesV1::internal_server_error()
        }
    }
}