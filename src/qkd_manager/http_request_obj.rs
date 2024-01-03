//! Objects deserialized from HTTP request body

use serde::Deserialize;

/// Request from the slave SAE to get key(s) from UUIDs provided by the master SAE
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestKeyId {
    pub(crate) key_ID: String,
}

/// List of key IDs requested by the slave SAE
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestListKeysIds {
    pub(crate) key_IDs: Vec<RequestKeyId>,
}