use std::io;
use rustls::Certificate;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use crate::io_err;
use crate::qkd_manager::QkdManager;

pub(super) struct RequestContext<'a> {
    client_cert: Option<X509Certificate<'a>>,
    pub(crate) qkd_manager: QkdManager,
}

#[allow(dead_code)]
impl<'a> RequestContext<'a> {
    pub(crate) fn new(client_cert: Option<&'a Certificate>, qkd_manager: QkdManager) -> Result<Self, io::Error> {
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

    pub(crate) fn has_client_certificate(&self) -> bool {
        self.client_cert.is_some()
    }

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

    pub(crate) fn get_client_certificate_serial_as_string(&self) -> Result<String, io::Error> {
        let cert = self.certificate_or_error()?;
        Ok(cert.raw_serial_as_string())
    }

    pub(crate) fn get_client_certificate_serial_as_raw(&self) -> Result<&[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], io::Error> {
        let cert = self.certificate_or_error()?;
        Ok(<&[u8; 20]>::try_from(cert.raw_serial()).map_err(|_| {
            io_err("Invalid client certificate serial")
        })?)
    }

    fn certificate_or_error(&self) -> Result<&X509Certificate, io::Error> {
        self.client_cert.as_ref().ok_or_else(|| {
            io_err("No client certificate in current context")
        })
    }
}