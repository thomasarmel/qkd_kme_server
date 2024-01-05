//! Objects serialized to HTTP response body

use std::io;

/// Trait to be implemented by objects that can be serialized to JSON
pub(crate) trait HttpResponseBody where Self: serde::Serialize {
    fn to_json(&self) -> Result<String, io::Error> {
        Ok(serde_json::to_string_pretty(&self).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Error serializing HTTP response body")
        })?)
    }
}

/// All HTTP errors that can be returned by the QKD manager
#[derive(serde::Serialize)]
pub(crate) struct ResponseError {
    pub(crate) message: String,
}
impl HttpResponseBody for ResponseError {} // can't use Derive macro because of the generic constraint

/// Status of the QKD keys (how many available etc.)
/// Shall be called by master SAE to know if keys can be delivered to the slave SAE.
#[derive(serde::Serialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdKeysStatus {
    /// KME ID of the KME
    pub(crate) source_KME_ID: String,

    /// KME ID of the target KME
    pub(crate) target_KME_ID: String,

    /// SAE ID of the calling master SAE
    pub(crate) master_SAE_ID: String,

    /// SAE ID of the specified slave SAE
    pub(crate) slave_SAE_ID: String,

    /// Default size of key the KME can deliver to the SAE (in bit)
    pub(crate) key_size: usize,

    /// Number of stored keys KME can deliver to the SAE
    pub(crate) stored_key_count: usize,

    /// Maximum number of stored_key_count
    pub(crate) max_key_count: usize,

    /// Maximum number of keys per request
    pub(crate) max_key_per_request: usize,

    /// Maximum size of key the KME can deliver to the SAE (in bit)
    pub(crate) max_key_size: usize,

    /// Minimum size of key the KME can deliver to the SAE (in bit)
    pub(crate) min_key_size: usize,

    /// Maximum number of additional_slave_SAE_IDs the KME allows. "0" when the KME does not support key multicast
    pub(crate) max_SAE_ID_count: usize,
    // status_extension -> to be implemented in the future
}
impl HttpResponseBody for ResponseQkdKeysStatus {} // can't use Derive macro because of the generic constraint

/// Key data
#[derive(serde::Serialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdKey {
    /// ID of the key: UUID format (example: "550e8400-e29b-41d4-a716-446655440000").
    pub(crate) key_ID: String,

    // key_ID_extension -> to be implemented in the future

    /// Key data encoded by base64 [7]. The key size is specified by the "size"
    /// parameter in "Get key". If not specified, the "key_size" value in Status data model is used as the default size.
    pub(crate) key: String,

    // key_extension -> to be implemented in the future
}

/// SAE information
/// Used to specify the SAE ID, and likely other information in the future
/// Could be called when the SAE has to know its own id for example
#[derive(serde::Serialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdSAEInfo {
    /// SAE ID of the SAE
    pub(crate) SAE_ID: i64,
    // TODO: KME ID ?
}

impl HttpResponseBody for ResponseQkdSAEInfo {} // can't use Derive macro because of the generic constraint

/// List of keys
#[derive(serde::Serialize, Debug, PartialEq)]
pub(crate) struct ResponseQkdKeysList {
    /// Array of keys. The number of keys is specified by the "number" parameter in "Get key". If not specified, the default number of keys is 1.
    pub(crate) keys: Vec<ResponseQkdKey>,
}
impl HttpResponseBody for ResponseQkdKeysList {}

#[cfg(test)]
mod test {
    use crate::qkd_manager::http_response_obj::HttpResponseBody;

    #[test]
    fn test_serialize_response_error() {
        let response_error = super::ResponseError {
            message: "test".to_string(),
        };
        let response_error_json = response_error.to_json().unwrap();
        assert_eq!(response_error_json, "{\n  \"message\": \"test\"\n}");
    }

    #[test]
    fn test_serialize_response_qkd_keys_status() {
        let response_qkd_keys_status = super::ResponseQkdKeysStatus {
            source_KME_ID: "source_KME_ID".to_string(),
            target_KME_ID: "target_KME_ID".to_string(),
            master_SAE_ID: "master_SAE_ID".to_string(),
            slave_SAE_ID: "slave_SAE_ID".to_string(),
            key_size: 128,
            stored_key_count: 1,
            max_key_count: 1,
            max_key_per_request: 1,
            max_key_size: 128,
            min_key_size: 128,
            max_SAE_ID_count: 1,
        };
        let response_qkd_keys_status_json = response_qkd_keys_status.to_json().unwrap();
        assert_eq!(response_qkd_keys_status_json, "{\n  \"source_KME_ID\": \"source_KME_ID\",\n  \"target_KME_ID\": \"target_KME_ID\",\n  \"master_SAE_ID\": \"master_SAE_ID\",\n  \"slave_SAE_ID\": \"slave_SAE_ID\",\n  \"key_size\": 128,\n  \"stored_key_count\": 1,\n  \"max_key_count\": 1,\n  \"max_key_per_request\": 1,\n  \"max_key_size\": 128,\n  \"min_key_size\": 128,\n  \"max_SAE_ID_count\": 1\n}");
    }

    #[test]
    fn test_serialize_response_qkd_key_list() {
        let response_qkd_key = super::ResponseQkdKey {
            key_ID: "key_ID".to_string(),
            key: "key".to_string(),
        };
        let response_qkd_key_list_json = super::ResponseQkdKeysList {
            keys: vec![response_qkd_key],
        }.to_json().unwrap();
        assert_eq!(response_qkd_key_list_json, "{\n  \"keys\": [\n    {\n      \"key_ID\": \"key_ID\",\n      \"key\": \"key\"\n    }\n  ]\n}");
    }

    #[test]
    fn test_serialize_response_qkd_sae_info() {
        let response_qkd_sae_info = super::ResponseQkdSAEInfo {
            SAE_ID: 1,
        };
        let response_qkd_sae_info_json = response_qkd_sae_info.to_json().unwrap();
        assert_eq!(response_qkd_sae_info_json, "{\n  \"SAE_ID\": 1\n}");
    }
}