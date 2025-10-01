use std::convert::{identity, Infallible};
use std::io;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::{error, warn};
use crate::{ensure_client_certificate_serial, ensure_sae_id_format_type, io_err};
use crate::qkd_manager::http_request_obj::{RequestKeyId, RequestListKeysIds};
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::qkd_manager::QkdManagerResponse;
use crate::routes::request_context::RequestContext;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use http_body_util::BodyExt;

/// Route to get key(s) from a slave SAE
/// eg `POST /api/v1/keys/{master SAE id integer}/dec_keys` or `GET /api/v1/keys/{master SAE id integer}/dec_keys?key_ID=[uuid]`
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
    let request_list_keys_ids = match extract_key_list_from_request(req).await {
        Ok(key_ids) => key_ids,
        Err(e) => {
            warn!("Error extracting key IDs from request: {}", e);
            return EtsiSaeQkdRoutesV1::bad_request();
        }
    };

    // All requested keys IDs
    let keys_uuids: Vec<String> = request_list_keys_ids.key_IDs.iter().map(|key_id| key_id.key_ID.clone()).collect();

    // Ensure the SAE ID is an integer
    let master_sae_id_i64 = ensure_sae_id_format_type!(master_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);
    match rcx.qkd_manager.get_qkd_keys_with_ids(master_sae_id_i64, &raw_client_certificate_serial, keys_uuids).await.unwrap_or_else(identity) {
        // Serialize the keys to JSON
        QkdManagerResponse::Keys(keys) => {
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
        _ => {
            EtsiSaeQkdRoutesV1::internal_server_error()
        }
    }
}

async fn extract_key_list_from_request(req: Request<body::Incoming>) -> Result<RequestListKeysIds, io::Error> {
    match req.method() {
        &hyper::Method::POST => {
            let post_body_bytes = match req.into_body().collect().await {
                Ok(bytes) => bytes.to_bytes(),
                Err(e) => Err(io_err(format!("Cannot read request body: {}", e).as_str()))?
            };
            match serde_json::from_slice(&post_body_bytes) {
                Ok(request_list_keys_ids) => Ok(request_list_keys_ids),
                Err(e) => Err(io_err(format!("Cannot parse request body as JSON: {}", e).as_str()))
            }
        }
        _ => {
            match req.uri().query() {
                Some(query_params) => {
                    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(query_params.as_bytes()).into_owned().collect();
                    match params.get("key_ID") {
                        Some(key_id) => Ok(RequestListKeysIds {
                            key_IDs: vec![RequestKeyId { key_ID: key_id.to_string() }]
                        }),
                        None => Ok(RequestListKeysIds::default())
                    }
                }
                None => Ok(RequestListKeysIds::default())
            }
        },
    }
}