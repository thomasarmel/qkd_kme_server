use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestKeyId {
    pub(crate) key_ID: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestListKeysIds {
    pub(crate) key_IDs: Vec<RequestKeyId>,
}