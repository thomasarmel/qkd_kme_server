//! QKD KME server: an HTTPS server with bilateral authentication that implements the ETSI GS QKD 014 V1.1.1 (2019-02) standard

#![forbid(unsafe_code, unused_must_use)]
#![deny(
missing_docs,
unreachable_pub,
unused_import_braces,
unused_extern_crates,
unused_qualifications
)]

use std::io;
use bounded_integer::BoundedUsize;

pub mod server;
pub mod routes;
pub mod qkd_manager;
pub mod config;
pub(crate) mod entropy;
pub mod event_subscription;


/// Cast a string to an io::Error
/// # Arguments
/// * `e` - The string to cast
/// # Returns
/// An io::Error from type io::ErrorKind::Other with the string as the error message
fn io_err(e: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}


/// The size of the QKD key in bytes. This is equal to QKD_MIN_KEY_SIZE_BITS and QKD_MAX_KEY_SIZE_BITS, as we offer no flexibility in key size
pub const QKD_KEY_SIZE_BITS: usize = 256;

/// The size of the QKD key in bytes
pub const QKD_KEY_SIZE_BYTES: usize = QKD_KEY_SIZE_BITS / 8;

/// The minimum size of the QKD key in bits, returned in HTTP responses
pub const QKD_MIN_KEY_SIZE_BITS: usize = 256;

/// The maximum size of the QKD key in bits, returned in HTTP responses
pub const QKD_MAX_KEY_SIZE_BITS: usize = 256;

/// How many keys can be returned in a single request
pub const MAX_QKD_KEYS_PER_REQUEST: usize = 10;

/// How many SAEs can share a single key (useful for key multicasting)
pub const MAX_QKD_KEY_SAE_IDS: usize = 0; // We don't support key multicast yet

/// How many keys can be stored in the KME for a given SAE
pub const MAX_QKD_KEYS_PER_SAE: usize = 10;

/// Location of the SQLite database file used by the KME to store keys, use ":memory:" for in-memory database
pub const MEMORY_SQLITE_DB_PATH: &'static str = ":memory:";

/// File extension for newly exchanged QKD keys
pub const QKD_KEY_FILE_EXTENSION: &'static str = "cor";

/// For inter-KME communication over public network, the environment variable to set to ignore certificate validation
/// This should be set to "Y" to ignore certificate validation
/// NOTE: This is a dangerous setting as it breaks the whole protocol security and should only be used for testing
pub const DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE: &'static str = "QKD_KME_SERVER_DANGER_INTER_KME_IGNORE_CERT";

/// The value of any boolean environment variable to be considered as activated
pub const ACTIVATED_ENV_VARIABLE_VALUE: &'static str = "Y";

/// If config parameter ignore_system_proxy_settings is not set, this is the default value
pub const DEFAULT_SHOULD_IGNORE_SYSTEM_PROXY_INTER_KME: bool = false;

/// The type of SAE ID
pub type SaeId = i64;

/// The type of KME ID
pub type KmeId = i64;

/// Type for QKD encryption key: basically a byte array
pub type QkdEncKey = [u8; QKD_KEY_SIZE_BYTES];

/// Type for SAE certificate serial number
pub type SaeClientCertSerial = Vec<u8>;

/// Type representing the number of keys requested by the SAE, bounded to [0, MAX_QKD_KEY_PER_KEY_ENC_REQUEST]
pub type RequestedKeyCount = BoundedUsize<0, MAX_QKD_KEYS_PER_REQUEST>;

/// Default number of keys to request if not specified in the request body
pub const DEFAULT_KEY_REQUEST_COUNT: usize = 1;

#[cfg(test)]
mod test {
    #[test]
    fn test_io_err() {
        let err = super::io_err("test");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "test");
    }
}