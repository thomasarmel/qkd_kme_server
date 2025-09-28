use std::convert::{identity, Infallible};
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::error;
use crate::{ensure_client_certificate_serial, ensure_sae_id_format_type};
use crate::qkd_manager::http_request_obj::RequestListKeysIds;
use crate::qkd_manager::http_response_obj::HttpResponseBody;
use crate::qkd_manager::QkdManagerResponse;
use crate::routes::request_context::RequestContext;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use http_body_util::BodyExt;

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
            return EtsiSaeQkdRoutesV1::bad_request();
        }
    };

    // Deserialize the request body to a RequestListKeysIds object
    let request_list_keys_ids: RequestListKeysIds = match serde_json::from_slice(&post_body_bytes) {
        Ok(request_list_keys_ids) => request_list_keys_ids,
        Err(_) => {
            return EtsiSaeQkdRoutesV1::bad_request();
        }
    };

    // All requested keys IDs
    let keys_uuids: Vec<String> = request_list_keys_ids.key_IDs.iter().map(|key_id| key_id.key_ID.clone()).collect();

    // Ensure the SAE ID is an integer
    let master_sae_id_i64 = ensure_sae_id_format_type!(master_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);
    match rcx.qkd_manager.get_qkd_keys_with_ids(master_sae_id_i64, &raw_client_certificate_serial, keys_uuids).unwrap_or_else(identity) {
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