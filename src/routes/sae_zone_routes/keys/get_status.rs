use std::convert::{identity, Infallible};
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::error;
use crate::ensure_sae_id_format_type;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::qkd_manager::QkdManagerResponse;
use crate::routes::request_context::RequestContext;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;

/// Route to get the key status (how many keys are available etc.) from a master SAE
/// eg GET /api/v1/keys/{slave SAE id integer}/status
pub(in crate::routes) fn route_get_status(rcx: &RequestContext, _req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check if the client certificate serial is present
    let raw_client_certificate = match rcx.get_client_certificate_serial_as_raw() {
        Ok(serial) => serial,
        Err(_) => {
            return EtsiSaeQkdRoutesV1::authentication_error();
        }
    };

    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_format_type!(slave_sae_id);

    // Retrieve the key status from the QKD manager
    match rcx.qkd_manager.get_qkd_key_status(&raw_client_certificate, slave_sae_id_i64).unwrap_or_else(identity) {
        QkdManagerResponse::Status(key_status) => {
            // Serialize the key status to JSON
            let key_status_json = match key_status.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing key status");
                    return EtsiSaeQkdRoutesV1::internal_server_error();
                }
            };
            // Return the key status as a response
            Ok(EtsiSaeQkdRoutesV1::json_response_from_str(&key_status_json))
        }
        QkdManagerResponse::AuthenticationError => {
            EtsiSaeQkdRoutesV1::authentication_error()
        }
        _ => {
            EtsiSaeQkdRoutesV1::internal_server_error()
        }
    }
}