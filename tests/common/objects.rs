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