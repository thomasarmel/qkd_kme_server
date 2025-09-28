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
use crate::{ensure_sae_id_format_type, RequestedKeyCount, DEFAULT_KEY_REQUEST_COUNT};
use crate::ensure_client_certificate_serial;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;


/// Route to get key(s) from a master SAE
/// eg `POST /api/v1/keys/{slave SAE id integer}/enc_keys` or `GET /api/v1/keys/{slave SAE id integer}/enc_keys[?number=n]`
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
    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_format_type!(slave_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);

    let request_params = extract_key_request_options(req).await;
    let requested_keys_count = RequestedKeyCount::new(
        request_params.number.unwrap_or(DEFAULT_KEY_REQUEST_COUNT)
    );

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

async fn extract_key_request_options(req: Request<body::Incoming>) -> MasterKeyRequestObj {
    match req.method() {
        &hyper::Method::POST => {
            match req.into_body().collect().await {
                Ok(bytes) => serde_json::from_slice::<MasterKeyRequestObj>(&bytes.to_bytes()).unwrap_or_else(|_| {
                        MasterKeyRequestObj::default()
                    }),
                Err(_) => MasterKeyRequestObj::default(),
            }
        }
        _ => {
            match req.uri().query() {
                None => MasterKeyRequestObj::default(),
                Some(query_params) => {
                    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(query_params.as_bytes()).into_owned().collect();
                    match params.get("number") {
                        None => MasterKeyRequestObj::default(),
                        Some(number_str) => {
                            match number_str.parse::<usize>() {
                                Ok(number) => MasterKeyRequestObj { number: Some(number) },
                                Err(_) => MasterKeyRequestObj::default(),
                            }
                        }
                    }
                }
            }
        }
    }
}