mod certificates;

extern crate hyper;
extern crate rustls;
extern crate tokio;
extern crate tokio_rustls;

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::sync::Arc;

use hyper::server::conn::Http;
use hyper::service::service_fn_ok;
use tokio::net::TcpListener;
use tokio::prelude::{Future, Stream};
use tokio_rustls::rustls::{AllowAnyAuthenticatedClient, RootCertStore, ServerConfig, Session};
use tokio_rustls::TlsAcceptor;
use crate::io_err;
use crate::server::certificates::{load_cert, load_pkey};

pub struct Server {
    pub listen_addr: String,
    pub ca_client_cert_path: String,
    pub server_cert_path: String,
    pub server_key_path: String,
}

impl Server {
    pub fn run<T: crate::routes::Routes>(&self) -> Result<(), io::Error> {
        let addr = self.listen_addr.parse().map_err(|e| {
            io_err(&format!(
                "invalid listen address {:?}: {:?}",
                self.listen_addr, e
            ))
        })?;
        let config = self.get_ssl_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let socket = TcpListener::bind(&addr).map_err(|e| {
            io_err(&format!(
                "cannot bind to {:?}: {:?}",
                self.listen_addr, e
            ))
        })?;

        let future = socket.incoming().for_each(move |tcp_stream| {
            let handler = acceptor
                .accept(tcp_stream) // Decrypts the TCP stream
                .and_then(move |tls_stream| {
                    let (tcp_stream, session) = tls_stream.get_ref();
                    println!(
                        "Received connection from peer {}",
                        tcp_stream.peer_addr().unwrap()
                    );

                    // Get peer certificates from session
                    let client_cert = match session.get_peer_certificates() {
                        None => return Err(io_err("did not receive any peer certificates")),
                        Some(mut peer_certs) => peer_certs.remove(0), // Get the first cert
                    };

                    /*let (_, cert) = X509Certificate::from_der(client_cert.as_ref()).map_err(|_| {
                        io_err("invalid X.509 peer certificate")
                    })?;
                    let cert_subject = cert.subject();
                    println!("{:?}", cert.raw_serial_as_string());
                    let cn_entry = cert_subject.iter_common_name().next().ok_or_else(|| {
                        io_err("peer certificate does not contain a subject commonName")
                    })?;
                    let cn = cn_entry.as_str().map_err(|_| {
                        io_err("peer certificate commonName is not valid UTF-8")
                    })?;*/

                    Ok((tls_stream, client_cert))
                })
                .and_then(move |(tls_stream, cert)| {
                    // Create a Hyper service to handle HTTP
                    let service = service_fn_ok(move |req| {
                        T::handle_request(req, Some(&cert))
                    });

                    // Use the Hyper service using the decrypted stream
                    let http = Http::new();
                    http.serve_connection(tls_stream, service)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
            tokio::spawn(handler.map_err(|e| eprintln!("Error: {:}", e)));
            Ok(())
        });

        Ok(tokio::run(future.map_err(drop)))
    }

    /// Load the SSL configuration for rustls
    fn get_ssl_config(&self) -> Result<ServerConfig, io::Error> {
        // Trusted CA for client certificates
        let mut roots = RootCertStore::empty();
        let cafile = File::open(self.ca_client_cert_path.as_str()).map_err(|_| {
            io_err("cannot open client CA certificate file")
        })?;
        let mut reader = BufReader::new(cafile);
        roots.add_pem_file(&mut reader).map_err(|_| {
            io_err("invalid client CA certificate file")
        })?;

        let mut config = ServerConfig::new(AllowAnyAuthenticatedClient::new(roots));
        let server_cert = load_cert(self.server_cert_path.as_str())?;
        let server_key = load_pkey(self.server_key_path.as_str())?.remove(0);
        config
            .set_single_cert(server_cert, server_key)
            .map_err(|_| io_err("invalid server certificate or key"))?;

        Ok(config)
    }
}