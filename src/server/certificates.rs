use std::fs::File;
use std::io;
use std::io::BufReader;
use rustls::{Certificate, PrivateKey};
use crate::io_err;

/// Load the server certificate
pub(super) fn load_cert(filename: &str) -> Result<Vec<Certificate>, io::Error> {
    let certfile = File::open(filename).map_err(|_| {
        io_err("cannot open server certificate file")
    })?;
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).map_err(|_| {
        io_err("invalid server certificate file")
    })
}

/// Load the server private key
pub(super) fn load_pkey(filename: &str) -> Result<Vec<PrivateKey>, io::Error> {
    let keyfile = File::open(filename).map_err(|_| {
        io_err("cannot open server private key file")
    })?;
    let mut reader = BufReader::new(keyfile);
    rustls::internal::pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
        io_err("invalid server private key file")
    })
}