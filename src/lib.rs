use std::io;

pub mod server;
pub mod routes;
pub mod qkd_manager;


fn io_err(e: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}


pub const QKD_KEY_SIZE_BITS: usize = 256;
pub const QKD_MIN_KEY_SIZE_BITS: usize = 256;
pub const QKD_MAX_KEY_SIZE_BITS: usize = 256;
pub const MAX_QKD_KEYS_PER_REQUEST: usize = 1;
pub const MAX_QKD_KEY_SAE_IDS: usize = 0; // We don't support key multicast yet

/// How many keys can be stored in the KME for a given SAE
pub const MAX_QKD_KEYS_PER_SAE: usize = 10;
pub const CLIENT_CERT_SERIAL_SIZE_BYTES: usize = 20;
pub const MEMORY_SQLITE_DB_PATH: &'static str = ":memory:";
pub const THIS_KME_ID: i64 = 1; // TODO: change