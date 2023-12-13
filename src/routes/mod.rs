mod keys;

use std::io;
use hyper::{Body, Request, Response, StatusCode};
use rustls::Certificate;
use x509_parser::prelude::{FromDer, X509Certificate};
use crate::io_err;


pub trait Routes {
    fn handle_request(req: Request<Body>, client_cert: Option<&Certificate>) -> Response<Body>;
}

pub struct QKDKMERoutes {}

impl Routes for QKDKMERoutes {
    fn handle_request(req: Request<Body>, client_cert: Option<&Certificate>) -> Response<Body> {
        let path = req.uri().path().to_owned();

        let rcx = match RequestContext::new(client_cert) {
            Ok(context) => context,
            Err(e) => {
                eprintln!("Error creating context: {}", e.to_string());
                return Self::internal_server_error();
            }
        };

        let segments: Vec<&str> =
            path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 3 || segments[0] != "api" || segments[1] != "v1" {
            return Self::not_found();
        }
        match segments[2] {
            "keys" => keys::key_handler(&rcx, req, &segments[3..]),
            &_ => Self::not_found(),
        }
    }
}


#[allow(dead_code)]
impl QKDKMERoutes {
    fn internal_server_error() -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()
    }

    fn not_found() -> Response<Body> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Page not found"))
            .unwrap()
    }
}

struct RequestContext<'a> {
    client_cert: Option<X509Certificate<'a>>,
}

#[allow(dead_code)]
impl<'a> RequestContext<'a> {
    pub(crate) fn new(client_cert: Option<&'a Certificate>) -> Result<Self, io::Error> {
        Ok(Self {
            client_cert: match client_cert {
                None => None,
                Some(cert) => {
                    Some(X509Certificate::from_der(cert.as_ref()).map_err(|_| io_err("Invalid client certificate"))?.1)
                }
            }
        })
    }

    pub(crate) fn has_client_certificate(&self) -> bool {
        self.client_cert.is_some()
    }

    pub(crate) fn get_client_certificate_cn(&self) -> Result<&str, io::Error>  {
        let cert = self.certificate_or_error()?;
        let cert_subject = cert.subject();
        //println!("{:?}", cert.raw_serial_as_string());
        let cn_entry = cert_subject.iter_common_name().next().ok_or_else(|| {
            io_err("peer certificate does not contain a subject commonName")
        })?;
        let cn = cn_entry.as_str().map_err(|_| {
            io_err("peer certificate commonName is not valid UTF-8")
        })?;
        Ok(cn)
    }

    fn get_client_certificate_serial_as_string(&self) -> Result<String, io::Error> {
        let cert = self.certificate_or_error()?;
        Ok(cert.raw_serial_as_string())
    }

    fn certificate_or_error(&self) -> Result<&X509Certificate, io::Error> {
        self.client_cert.as_ref().ok_or_else(|| {
            io_err("No client certificate in current context")
        })
    }
}