use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct MasterKeyRequestObj {
    pub number: Option<usize>
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct ResponseQkdKey {
    pub key_ID: String,
    pub key: String,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
pub struct ResponseQkdKeysList {
    pub keys: Vec<ResponseQkdKey>,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct RequestKeyId {
    pub key_ID: String,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct RequestListKeysIds {
    pub key_IDs: Vec<RequestKeyId>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdKeysStatus {
    pub source_KME_ID: String,
    pub target_KME_ID: String,
    pub master_SAE_ID: String,
    pub slave_SAE_ID: String,
    pub key_size: usize,
    pub stored_key_count: usize,
    pub max_key_count: usize,
    pub max_key_per_request: usize,
    pub max_key_size: usize,
    pub min_key_size: usize,
    pub max_SAE_ID_count: usize,
}