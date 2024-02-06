//! Configuration module, contains structs used to deserialize JSON configuration and other material extraction functions

use std::io;
use serde::{Deserialize, Serialize};
use crate::{io_err, KmeId, SaeClientCertSerial, SaeId};

/// Whole KME config, to be extracted from JSON
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// Config for this specific KME, including its ID and paths to certificates
    #[serde(rename = "this_kme")]
    pub this_kme_config: ThisKmeConfig,
    /// Configs for other KMEs, including their IDs and paths to directories to watch for new keys
    #[serde(rename = "other_kmes")]
    pub(crate) other_kme_configs: Vec<OtherKmeConfig>,
    /// Configs for SAEs, including their IDs, KMEs they are associated with and optional client certificate serials, if SAEs belong to this KME
    #[serde(rename = "saes")]
    pub(crate) sae_configs: Vec<SaeConfig>
}

impl Config {
    /// Extract configuration from JSON file
    pub fn from_json_path(json_config_file_path: &str) -> Result<Self, io::Error> {
        let config: Self = match std::fs::read_to_string(json_config_file_path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(config) => config,
                Err(_) => return Err(io_err("Error deserializing JSON"))
            },
            Err(_) => return Err(io_err("Error reading JSON file"))
        };
        Ok(config)
    }
}

/// Config for this specific KME, including its ID and paths to certificates
#[derive(Serialize, Deserialize, Debug)]
pub struct ThisKmeConfig {
    /// ID of this KME, in the QKD network
    pub(crate) id: KmeId,
    /// Path to SQLite database file, used to store keys, certificates and other data
    /// You can use `:memory:` to use in-memory database
    pub(crate) sqlite_db_path: String,
    /// Address to listen for HTTPS connections
    pub https_listen_address: String,
    /// Server certificate authority certificate path, used to authenticate client SAEs
    pub https_ca_client_cert_path: String,
    /// Server HTTPS certificate path
    pub https_server_cert_path: String,
    /// Server HTTPS private key path
    pub https_server_key_path: String
}

/// Configs for other KMEs, including their IDs and paths to directories to watch for new keys
#[derive(Serialize, Deserialize, Debug)]
pub struct OtherKmeConfig {
    /// ID of the other KME, in the QKD network
    pub(crate) id: KmeId,
    /// Path to directory to read and watch for new keys, files must have [crate::QKD_KEY_FILE_EXTENSION](crate::QKD_KEY_FILE_EXTENSION) extension
    pub(crate) key_directory_to_watch: String,
    /// IP address of the other KME, used to send keys to it using "classical channel"
    pub(crate) ip_address: String,
}

/// Config for specific SAE: its ID, KME ID and optional client certificate serial
#[derive(Serialize, Deserialize, Debug)]
pub struct SaeConfig {
    /// ID of the SAE in QKD network
    pub(crate) id: SaeId,
    /// ID of the KME this SAE belongs to
    pub(crate) kme_id: KmeId,
    /// Client certificate serial number, used to authenticate SAEs to this KME if it belongs to, None otherwise
    pub(crate) https_client_certificate_serial: Option<SaeClientCertSerial>
}