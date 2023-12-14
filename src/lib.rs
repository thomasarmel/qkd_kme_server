use std::io;

pub mod server;
pub mod routes;
pub mod qkd_manager;


fn io_err(e: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}