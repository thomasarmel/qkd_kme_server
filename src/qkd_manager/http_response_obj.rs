use std::io;
use serde::Serialize;

pub(crate) trait HttpResponseBody where Self: serde::Serialize {
    fn to_json(&self) -> Result<String, io::Error> {
        Ok(serde_json::to_string_pretty(&self).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Error serializing HTTP response body")
        })?)
    }
}

#[derive(Serialize)]
pub(crate) struct ResponseError {
    pub(crate) message: String,
}
impl HttpResponseBody for ResponseError {} // can't use Derive macro because of the generic constraint

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
/// Shall be called by master SAE to know if keys can be delivered to the slave SAE.
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

#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
pub(crate) struct ResponseQkdKeysList {
    /// Array of keys. The number of keys is specified by the "number" parameter in "Get key". If not specified, the default number of keys is 1.
    pub(crate) keys: Vec<ResponseQkdKey>,
}
impl HttpResponseBody for ResponseQkdKeysList {}