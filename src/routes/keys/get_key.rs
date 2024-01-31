//! Routes used to get keys from slave or master SAE, and key status

use std::convert::{identity, Infallible};
use hyper::{body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::routes::RequestContext;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use std::string::String;
use log::{error, warn};
use crate::qkd_manager::http_request_obj::RequestListKeysIds;
use crate::ensure_sae_id_integer;
use crate::ensure_client_certificate_serial;


/// Route to get the key status (how many keys are available etc.) from a master SAE
/// eg GET /api/v1/keys/{slave SAE id integer}/status
pub(in crate::routes) fn route_get_status(rcx: &RequestContext, _req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check if the client certificate serial is present
    let raw_client_certificate = match rcx.get_client_certificate_serial_as_raw() {
        Ok(serial) => serial,
        Err(_) => {
            return super::QKDKMERoutesV1::authentication_error();
        }
    };

    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_integer!(slave_sae_id);

    // Retrieve the key status from the QKD manager
    match rcx.qkd_manager.get_qkd_key_status(raw_client_certificate, slave_sae_id_i64).unwrap_or_else(identity) {
        QkdManagerResponse::Status(key_status) => {
            // Serialize the key status to JSON
            let key_status_json = match key_status.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing key status");
                    return super::QKDKMERoutesV1::internal_server_error();
                }
            };
            // Return the key status as a response
            Ok(crate::routes::QKDKMERoutesV1::json_response_from_str(&key_status_json))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutesV1::authentication_error()
        }
        _ => {
            super::QKDKMERoutesV1::internal_server_error()
        }
    }
}

/// Route to get key(s) from a master SAE (only 1 key for now)
/// eg `POST /api/v1/keys/{slave SAE id integer}/enc_keys`
//
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
pub(in crate::routes) fn route_get_key(rcx: &RequestContext, _req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_integer!(slave_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);

    // Retrieve the key from the QKD manager
    match rcx.qkd_manager.get_qkd_key(slave_sae_id_i64, raw_client_certificate_serial).unwrap_or_else(identity) {
        QkdManagerResponse::Keys(keys) => {
            // Serialize the keys to JSON
            let keys_json = match keys.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing keys");
                    return super::QKDKMERoutesV1::internal_server_error();
                }
            };
            // Return the key(s) as a response
            Ok(crate::routes::QKDKMERoutesV1::json_response_from_str(&keys_json))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutesV1::authentication_error()
        }
        QkdManagerResponse::NotFound => {
            super::QKDKMERoutesV1::not_found()
        }
        _ => {
            super::QKDKMERoutesV1::internal_server_error()
        }
    }
}

/// Route to get key(s) from a slave SAE
/// eg `POST /api/v1/keys/{master SAE id integer}/dec_keys`
//
// # Request
// ```json
// {
//     "key_IDs": [
//         {
//             "key_ID": "[key id in UUID format, provided by master SAE]"
//         },
//         {
//             "key_ID": "[key id in UUID format, provided by master SAE]"
//         }
//     ]
// }```
//
// # Response
// ```json
// {
//   "keys": [
//     {
//       "key_ID": "[key id in UUID format]",
//       "key": "[key encoded in base64 format]"
//     },
//     {
//       "key_ID": "[key id in UUID format]",
//       "key": "[key encoded in base64 format]"
//     }
//   ]
// }
// ```
pub(in crate::routes) async fn route_get_key_with_id(rcx: &RequestContext<'_>, req: Request<body::Incoming>, master_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    // Get the request body as bytes
    let post_body_bytes = match req.into_body().collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(_) => {
            return super::QKDKMERoutesV1::bad_request();
        }
    };

    // Deserialize the request body to a RequestListKeysIds object
    let request_list_keys_ids: RequestListKeysIds = match serde_json::from_slice(&post_body_bytes) {
        Ok(request_list_keys_ids) => request_list_keys_ids,
        Err(_) => {
            return super::QKDKMERoutesV1::bad_request();
        }
    };

    // All requested keys IDs
    let keys_uuids: Vec<String> = request_list_keys_ids.key_IDs.iter().map(|key_id| key_id.key_ID.clone()).collect();

    // Ensure the SAE ID is an integer
    let master_sae_id_i64 = ensure_sae_id_integer!(master_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);
    match rcx.qkd_manager.get_qkd_keys_with_ids(master_sae_id_i64, raw_client_certificate_serial, keys_uuids).unwrap_or_else(identity) {
        // Serialize the keys to JSON
        QkdManagerResponse::Keys(keys) => {
            let keys_json = match keys.to_json() {
                Ok(json) => json,
                Err(_) => {
                    error!("Error serializing keys");
                    return super::QKDKMERoutesV1::internal_server_error();
                }
            };
            // Return the key(s) as a response
            Ok(crate::routes::QKDKMERoutesV1::json_response_from_str(&keys_json))
        }
        QkdManagerResponse::AuthenticationError => {
            super::QKDKMERoutesV1::authentication_error()
        }
        QkdManagerResponse::NotFound => {
            super::QKDKMERoutesV1::not_found()
        }
        _ => {
            super::QKDKMERoutesV1::internal_server_error()
        }
    }
}

/// Casts the SAE ID to an integer, or returns a 400 error if fails
#[macro_export]
macro_rules! ensure_sae_id_integer {
    ($sae_id:expr) => {
        match $sae_id.parse::<i64>() {
            Ok(sae_id) => sae_id,
            Err(_) => {
                warn!("Invalid SAE ID, must be an integer");
                return super::QKDKMERoutesV1::bad_request();
            }
        }
    }
}

/// Gets the client certificate serial as a raw byte vector, or returns a 401 error if fails (should never happen in a normal scenario)
#[macro_export]
macro_rules! ensure_client_certificate_serial {
    ($request_context:expr) => {
        match $request_context.get_client_certificate_serial_as_raw() {
            Ok(serial) => serial,
            Err(_) => {
                warn!("Error getting client certificate serial");
                return super::QKDKMERoutesV1::authentication_error();
            }
        }
    }
}