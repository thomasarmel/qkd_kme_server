//! Request context, used to store and share information about the current request

use std::io;
use rustls_pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use crate::{io_err, SaeClientCertSerial};
use crate::qkd_manager::QkdManager;

/// Context created for each request,
/// to be transmitted recursively to each function managing the request as a mutable reference
pub(super) struct RequestContext<'a> {
    client_cert: Option<X509Certificate<'a>>,
    /// The QKD manager, used to store and retrieve QKD keys
    /// (moved once at the beginning of the request)
    pub(crate) qkd_manager: QkdManager,
}

#[allow(dead_code)]
impl<'a> RequestContext<'a> {

    /// Create a new request context
    /// # Arguments
    /// * `client_cert` - The client certificate, if any
    /// * `qkd_manager` - The QKD manager, used to store and retrieve QKD keys
    /// # Returns
    /// A new request context
    /// # Errors
    /// If the client certificate is invalid
    pub(crate) fn new(client_cert: Option<&'a CertificateDer>, qkd_manager: QkdManager) -> Result<Self, io::Error> {
        Ok(Self {
            client_cert: match client_cert {
                None => None,
                Some(cert) => {
                    Some(X509Certificate::from_der(cert.as_ref()).map_err(|_| io_err("Invalid client certificate"))?.1)
                }
            },
            qkd_manager,
        })
    }

    /// Check if the client associated with this request has a client certificate for authentication
    /// # Returns
    /// True in case a client certificate is associated with the request context, false otherwise
    pub(crate) fn has_client_certificate(&self) -> bool {
        self.client_cert.is_some()
    }

    /// Get the client certificate common name
    /// # Returns
    /// The client certificate common name as a string slice if the client has a certificate
    /// # Errors
    /// io::Error if the client does not have a certificate, or if the certificate does not contain a common name
    pub(crate) fn get_client_certificate_cn(&self) -> Result<&str, io::Error>  {
        let cert = self.certificate_or_error()?;
        let cert_subject = cert.subject();
        let cn_entry = cert_subject.iter_common_name().next().ok_or_else(|| {
            io_err("peer certificate does not contain a subject commonName")
        })?;
        let cn = cn_entry.as_str().map_err(|_| {
            io_err("peer certificate commonName is not valid UTF-8")
        })?;
        Ok(cn)
    }

    /// Get the client certificate serial number as a String
    /// # Returns
    /// The client certificate serial number as a String if the client has a certificate
    /// # Errors
    /// io::Error if the client does not have a certificate
    pub(crate) fn get_client_certificate_serial_as_string(&self) -> Result<String, io::Error> {
        let cert = self.certificate_or_error()?;
        Ok(cert.raw_serial_as_string())
    }

    /// Get the client certificate serial number as a raw byte array
    /// # Returns
    /// The client certificate serial number as a raw byte array if the client has a certificate
    /// # Errors
    /// io::Error if the client does not have a certificate
    pub(crate) fn get_client_certificate_serial_as_raw(&self) -> Result<SaeClientCertSerial, io::Error> {
        let cert = self.certificate_or_error()?;
        Ok(Vec::from(cert.raw_serial()).try_into().map_err(|_| {
            io_err("Invalid client certificate serial")
        })?)
    }

    fn certificate_or_error(&self) -> Result<&X509Certificate, io::Error> {
        self.client_cert.as_ref().ok_or_else(|| {
            io_err("No client certificate in current context")
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io;
    use std::io::BufReader;
    use rustls_pki_types::CertificateDer;
    use crate::io_err;

    #[test]
    fn test_context_no_cert() {
        let context = super::RequestContext::new(None, crate::qkd_manager::QkdManager::new(":memory:", 1)).unwrap();
        assert!(!context.has_client_certificate());
        assert!(context.get_client_certificate_cn().is_err());
        assert!(context.get_client_certificate_serial_as_string().is_err());
        assert!(context.get_client_certificate_serial_as_raw().is_err());
    }

    #[test]
    fn test_context_with_cert() {
        const CERT_FILENAME: &'static str = "certs/zone1/kme1.crt";
        let certs = load_cert(CERT_FILENAME).unwrap();
        assert_eq!(certs.len(), 1);
        let context = super::RequestContext::new(Some(&certs[0]), crate::qkd_manager::QkdManager::new(":memory:", 1)).unwrap();
        assert!(context.has_client_certificate());
        assert_eq!(context.get_client_certificate_cn().unwrap(), "localhost");
        assert_eq!(context.get_client_certificate_serial_as_string().unwrap(), "70:f4:4f:56:0c:3f:27:d4:b2:11:a4:78:13:af:d0:3c:03:81:3b:8d");
        assert_eq!(context.get_client_certificate_serial_as_raw().unwrap(), &[0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8d]);
    }


    fn load_cert(filename: &str) -> Result<Vec<CertificateDer<'static>>, io::Error> {
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
}