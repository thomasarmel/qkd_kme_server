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
    /// Directory for keys used in the same KME zone
    /// # Note you could use classical encryption in this case, it's just for compatibility purpose
    pub(crate) key_directory_to_watch: String,
    /// Config for internal HTTPS interface for SAEs
    /// # Note you should listen only on secured internal network
    pub saes_https_interface: SAEsHttpsInterfaceConfig,
    /// Config for external HTTPS interface for other KMEs
    pub kmes_https_interface: KMEsHttpsInterfaceConfig
}

/// Config for internal HTTPS interface for SAEs (likely secured local network)
#[derive(Serialize, Deserialize, Debug)]
pub struct SAEsHttpsInterfaceConfig {
    /// Address to listen for HTTPS connections, it should be a secured internal network
    pub listen_address: String,
    /// Server certificate authority certificate path, used to authenticate client SAEs
    pub ca_client_cert_path: String,
    /// Server HTTPS certificate path
    pub server_cert_path: String,
    /// Server HTTPS private key path
    pub server_key_path: String
}

/// Config for external HTTPS interface for other KME network (likely global network
#[derive(Serialize, Deserialize, Debug)]
pub struct KMEsHttpsInterfaceConfig {
    /// Address to listen for HTTPS connections, it could be the public IP address
    pub listen_address: String,
    /// Server certificate authority certificate path, used to authenticate client SAEs
    pub ca_client_cert_path: String,
    /// Server HTTPS certificate path
    pub server_cert_path: String,
    /// Server HTTPS private key path
    pub server_key_path: String
}

/// Configs for other KMEs, including their IDs and paths to directories to watch for new keys
#[derive(Serialize, Deserialize, Debug)]
pub struct OtherKmeConfig {
    /// ID of the other KME, in the QKD network
    pub(crate) id: KmeId,
    /// Path to directory to read and watch for new keys, files must have [crate::QKD_KEY_FILE_EXTENSION](crate::QKD_KEY_FILE_EXTENSION) extension
    pub(crate) key_directory_to_watch: String,
    /// IP address of the other KME, used to send keys to it using "classical channel"
    pub(crate) inter_kme_bind_address: String,
    /// If true, the KME will ignore system proxy settings when contacting the other KME
    pub(crate) ignore_system_proxy_settings: bool,
    /// Client certificate for inter KME HTTPS authentication
    pub(crate) https_client_authentication_certificate: String,
    /// Password for the client certificate
    pub(crate) https_client_authentication_certificate_password: String
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

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_config_deserialization() {
        const JSON_CONFIG_PATH: &'static str = "tests/data/test_kme_config.json";
        let config = Config::from_json_path(JSON_CONFIG_PATH).unwrap();
        assert_eq!(config.this_kme_config.id, 1);
        assert_eq!(config.this_kme_config.sqlite_db_path, ":memory:");
        assert_eq!(config.this_kme_config.key_directory_to_watch, "tests/data/raw_keys/kme-1-1");
        assert_eq!(config.this_kme_config.saes_https_interface.listen_address, "127.0.0.1:3000");
        assert_eq!(config.this_kme_config.saes_https_interface.ca_client_cert_path, "certs/zone1/CA-zone1.crt");
        assert_eq!(config.this_kme_config.saes_https_interface.server_cert_path, "certs/zone1/kme1.crt");
        assert_eq!(config.this_kme_config.saes_https_interface.server_key_path, "certs/zone1/kme1.key");
        assert_eq!(config.this_kme_config.kmes_https_interface.listen_address, "0.0.0.0:3001");
        assert_eq!(config.this_kme_config.kmes_https_interface.ca_client_cert_path, "certs/inter_kmes/root-ca-kme1.crt");
        assert_eq!(config.this_kme_config.kmes_https_interface.server_cert_path, "certs/zone1/kme1.crt");
        assert_eq!(config.this_kme_config.kmes_https_interface.server_key_path, "certs/zone1/kme1.key");
        assert_eq!(config.other_kme_configs.len(), 1);
        assert_eq!(config.other_kme_configs[0].id, 2);
        assert_eq!(config.other_kme_configs[0].key_directory_to_watch, "tests/data/raw_keys/kme-1-2");
        assert_eq!(config.other_kme_configs[0].inter_kme_bind_address, "127.0.0.1:4001");
        assert_eq!(config.other_kme_configs[0].https_client_authentication_certificate, "certs/inter_kmes/client-kme1-to-kme2.pfx");
        assert_eq!(config.other_kme_configs[0].https_client_authentication_certificate_password, "");
        assert_eq!(config.sae_configs.len(), 3);
        assert_eq!(config.sae_configs[0].id, 1);
        assert_eq!(config.sae_configs[0].kme_id, 1);
        assert_eq!(config.sae_configs[0].https_client_certificate_serial, Some([0x70, 0xF4, 0x4F, 0x56, 0x0C, 0x3F, 0x27, 0xD4, 0xB2, 0x11, 0xA4, 0x78, 0x13, 0xAF, 0xD0, 0x3C, 0x03, 0x81, 0x3B, 0x8E]));
        assert_eq!(config.sae_configs[1].id, 2);
        assert_eq!(config.sae_configs[1].kme_id, 1);
        assert_eq!(config.sae_configs[1].https_client_certificate_serial, Some([0x70, 0xF4, 0x4F, 0x56, 0x0C, 0x3F, 0x27, 0xD4, 0xB2, 0x11, 0xA4, 0x78, 0x13, 0xAF, 0xD0, 0x3C, 0x03, 0x81, 0x3B, 0x92]));
        assert_eq!(config.sae_configs[2].id, 3);
        assert_eq!(config.sae_configs[2].kme_id, 2);
        assert_eq!(config.sae_configs[2].https_client_certificate_serial, None);
    }

    #[test]
    fn test_config_deserialization_error() {
        const JSON_CONFIG_PATH: &'static str = "tests/data/test_kme_config_json_error.json";
        let config = Config::from_json_path(JSON_CONFIG_PATH);
        assert!(config.is_err());
        assert_eq!(config.unwrap_err().to_string(), "Error deserializing JSON");
    }

    #[test]
    fn test_config_deserialization_file_not_found() {
        const JSON_CONFIG_PATH: &'static str = "this_config_json_file_doesnt_exist.json";
        let config = Config::from_json_path(JSON_CONFIG_PATH);
        assert!(config.is_err());
        assert_eq!(config.unwrap_err().to_string(), "Error reading JSON file");
    }
}