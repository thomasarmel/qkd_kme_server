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

pub mod server;
pub mod routes;
pub mod qkd_manager;
pub mod config;


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
pub const MAX_QKD_KEYS_PER_REQUEST: usize = 1;

/// How many SAEs can share a single key (useful for key multicasting)
pub const MAX_QKD_KEY_SAE_IDS: usize = 0; // We don't support key multicast yet

/// How many keys can be stored in the KME for a given SAE
pub const MAX_QKD_KEYS_PER_SAE: usize = 10;

/// The size of the client certificate serial number in bytes, constant
pub const CLIENT_CERT_SERIAL_SIZE_BYTES: usize = 20;

/// Location of the SQLite database file used by the KME to store keys, use ":memory:" for in-memory database
pub const MEMORY_SQLITE_DB_PATH: &'static str = ":memory:";

/// File extension for newly exchanged QKD keys
pub const QKD_KEY_FILE_EXTENSION: &'static str = "cor";

/// The type of SAE ID
pub type SaeId = i64;

/// The type of KME ID
pub type KmeId = i64;

/// Type for QKD encryption key: basically a byte array
pub type QkdEncKey = [u8; QKD_KEY_SIZE_BYTES];

/// Type for SAE certificate serial number
pub type SaeClientCertSerial = [u8; CLIENT_CERT_SERIAL_SIZE_BYTES];

#[cfg(test)]
mod test {
    #[test]
    fn test_io_err() {
        let err = super::io_err("test");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "test");
    }
}