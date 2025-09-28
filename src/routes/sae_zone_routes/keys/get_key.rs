//! Routes used to get keys from slave or master SAE, and key status

use std::convert::{identity, Infallible};
use hyper::{body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use log::{error, info, warn};
use crate::qkd_manager::http_request_obj::MasterKeyRequestObj;
use crate::{ensure_sae_id_format_type, RequestedKeyCount};
use crate::ensure_client_certificate_serial;
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

/// Route to get key(s) from a master SAE (only 1 key for now)
/// eg `POST /api/v1/keys/{slave SAE id integer}/enc_keys`
//
// # Request body (optional)
// ```json
// {
// "number": [number of keys requested, default is 1]
// }
// ```
// # Response
// ```json
// {
//   "keys": [
//     {
//       "key_ID": "[key id in UUID format]",
//       "key": "[key encoded in base64 format]"
//     }
//   ]
// }
// ```
pub(in crate::routes) async fn route_get_key(rcx: &RequestContext<'_>, req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    const DEFAULT_KEY_REQUEST_COUNT: usize = 1;
    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_format_type!(slave_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);

    let requested_keys_count = RequestedKeyCount::new(match req.into_body().collect().await {
        Ok(bytes) => {
                match serde_json::from_slice::<MasterKeyRequestObj>(&bytes.to_bytes()) {
                    Ok(body) => body.number.unwrap_or(DEFAULT_KEY_REQUEST_COUNT),
                    Err(_) => {
                        DEFAULT_KEY_REQUEST_COUNT
                    }
                }
            }
        Err(_) => {
            DEFAULT_KEY_REQUEST_COUNT
        }
    });

    let requested_keys_count = match requested_keys_count {
        Some(count) => count,
        None => {
            error!("Too many keys requested, max is {}", RequestedKeyCount::MAX_VALUE);
            return EtsiSaeQkdRoutesV1::bad_request();
        }
    };

    info!("{} keys have been requested", requested_keys_count);

    // Retrieve the key from the QKD manager
    match rcx.qkd_manager.get_qkd_keys(slave_sae_id_i64, &raw_client_certificate_serial, requested_keys_count).await.unwrap_or_else(identity) {
        QkdManagerResponse::Keys(keys) => {
            // Serialize the keys to JSON
            let keys_json = match keys.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing keys");
                    return EtsiSaeQkdRoutesV1::internal_server_error();
                }
            };
            // Return the key(s) as a response
            Ok(EtsiSaeQkdRoutesV1::json_response_from_str(&keys_json))
        }
        QkdManagerResponse::AuthenticationError => {
            EtsiSaeQkdRoutesV1::authentication_error()
        }
        QkdManagerResponse::NotFound => {
            EtsiSaeQkdRoutesV1::not_found()
        }
        QkdManagerResponse::RemoteKmeCommunicationError => {
            EtsiSaeQkdRoutesV1::gateway_timeout()
        }
        QkdManagerResponse::MissingRemoteKmeConfiguration => {
            EtsiSaeQkdRoutesV1::precondition_failed()
        }
        QkdManagerResponse::RemoteKmeAcceptError => {
            EtsiSaeQkdRoutesV1::conflict()
        }
        _ => {
            EtsiSaeQkdRoutesV1::internal_server_error()
        }
    }
}