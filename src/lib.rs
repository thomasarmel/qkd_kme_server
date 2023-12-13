use std::io;

pub mod server;
pub mod routes;


fn io_err(e: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}