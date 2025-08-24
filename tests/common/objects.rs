use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct MasterKeyRequestObj {
    pub number: Option<usize>
}