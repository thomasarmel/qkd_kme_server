use std::fs::File;
use std::io;
use std::io::BufReader;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::io_err;

/// Load the server certificate
pub(super) fn load_cert(filename: &str) -> Result<Vec<CertificateDer<'static>>, io::Error> {
    let certfile = File::open(filename).map_err(|_| {
        io_err("Cannot open server certificate file")
    })?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .into_iter()
        .map(|cert| {
            match cert {
                Ok(cert) => Ok(cert.into_owned()),
                Err(e) => Err(e)
            }
        })
        .collect::<Result<Vec<CertificateDer>, _>>()?;
    Ok(certs)
}

/// Load the server private key
pub(super) fn load_pkey(filename: &str) -> Result<Vec<PrivateKeyDer<'static>>, io::Error> {
    let keyfile = File::open(filename).map_err(|_| {
        io_err("Cannot open server private key file")
    })?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .into_iter()
        .map(|pk| {
            match pk {
                Ok(key) => {
                    Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec())))
                    //Ok(PrivateKeyDer::from(key))
                },
                Err(e) => Err(e)
            }
        })
        .collect::<Result<Vec<PrivateKeyDer>, _>>()?;
    Ok(keys)
}