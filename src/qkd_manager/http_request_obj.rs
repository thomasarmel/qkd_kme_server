//! Objects deserialized from HTTP request body

use serde::{Deserialize, Serialize};
use crate::SaeId;

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

#[derive(Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub(crate) struct MasterKeyRequestObj {
    pub(crate) number: Option<usize>
}

/// From inter-KME network: a key has been requested on a remote KME for a specific target SAE
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct ActivateKeyRemoteKME {
    pub(crate) key_IDs_list: Vec<String>,
    /// Master SAE that requested the key
    pub(crate) origin_SAE_ID: SaeId,
    pub(crate) remote_SAE_ID: SaeId,
}