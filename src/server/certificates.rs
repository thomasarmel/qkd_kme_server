//! SSL certificate and private key loading from files

use std::fs::File;
use std::io;
use std::io::BufReader;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::io_err;

/// Load SSL certificate(s) from a file path
/// # Arguments
/// * `filename` - The path to the file containing the certificate(s), .crt
/// # Returns
/// A vector of CertificateDer objects, containing the certificate(s). The certificates have a static lifetime
/// # Errors
/// If the file cannot be opened, or the certificate(s) cannot be parsed
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

/// Load SSL private key(s) from a file path
/// # Arguments
/// * `filename` - The path to the file containing the private key(s), .key
/// # Returns
/// A vector of PrivateKeyDer objects, containing the private key(s). The private keys have a static lifetime
/// # Errors
/// If the file cannot be opened, or the private key(s) cannot be parsed
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
                },
                Err(e) => Err(e)
            }
        })
        .collect::<Result<Vec<PrivateKeyDer>, _>>()?;
    Ok(keys)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_load_cert() {
        const CERT_FILENAME: &'static str = "certs/kme1.crt";
        let certs = super::load_cert(CERT_FILENAME).unwrap();
        assert_eq!(certs.len(), 1);

        const CERT_FILENAME_NO_EXIST: &'static str = "certs/no_exist.crt";
        let certs = super::load_cert(CERT_FILENAME_NO_EXIST);
        assert!(certs.is_err());
    }

    #[test]
    fn test_load_pkey() {
        const PKEY_FILENAME: &'static str = "certs/kme1.key";
        let keys = super::load_pkey(PKEY_FILENAME).unwrap();
        assert_eq!(keys.len(), 1);

        const PKEY_FILENAME_NO_EXIST: &'static str = "certs/no_exist.key";
        let keys = super::load_pkey(PKEY_FILENAME_NO_EXIST);
        assert!(keys.is_err());
    }
}