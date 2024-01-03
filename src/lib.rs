use std::io;

pub mod server;
pub mod routes;
pub mod qkd_manager;


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

/// The ID of this KME, used to identify the KME in the database and across the network
pub const THIS_KME_ID: i64 = 1; // TODO: change

#[cfg(test)]
mod test {
    #[test]
    fn test_io_err() {
        let err = super::io_err("test");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "test");
    }
}