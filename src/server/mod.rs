mod certificates;

extern crate hyper;
extern crate rustls;
extern crate tokio;
extern crate tokio_rustls;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use hyper::Request;
use hyper::server::conn::http1;
use hyper::service::service_fn;

use hyper_util::rt::TokioIo;
use log::{error, info, warn};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use crate::io_err;
use crate::qkd_manager::QkdManager;
use crate::server::certificates::{load_cert, load_pkey};

pub struct Server {
    pub listen_addr: String,
    pub ca_client_cert_path: String,
    pub server_cert_path: String,
    pub server_key_path: String,
}

impl Server {
    pub async fn run<T: crate::routes::Routes>(&self, qkd_manager: &QkdManager) -> Result<(), io::Error> {
        let addr = self.listen_addr.parse::<SocketAddr>().map_err(|e| {
            io_err(&format!(
                "invalid listen address {:?}: {:?}",
                self.listen_addr, e
            ))
        })?;
        let config = self.get_ssl_config()?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(config));
        let socket = TcpListener::bind(&addr).await.map_err(|e| {
            io_err(&format!(
                "cannot bind to {:?}: {:?}",
                self.listen_addr, e
            ))
        })?;

        loop {
            info!("Waiting for incoming connection");
            let Ok(stream) = tls_acceptor.accept(socket.accept().await?.0).await else {
                warn!("Error accepting connection, maybe client certificate is missing?");
                continue;
            };
            info!("Received connection from peer {}", stream.get_ref().0.peer_addr().map_err(|_| {
                io_err("Error getting peer address")
            })?);
            let (_, server_session) = stream.get_ref();
            let client_cert = Arc::new(server_session.peer_certificates()
                .ok_or(io_err("Error: no client certificate, this is unexpected"))?
                .first()
                .ok_or(io_err("Error fetching client certificate, this is unexpected"))?
                .clone().into_owned());

            let io = TokioIo::new(stream);
            let qkd_manager = qkd_manager.clone();

            tokio::task::spawn(async move {
                let response_service = service_fn(|req: Request<hyper::body::Incoming>| {
                    let local_client_cert_serial_str = Arc::clone(&client_cert);
                    let qkd_manager = qkd_manager.clone();
                    async move {
                        T::handle_request(req, Some(&local_client_cert_serial_str), qkd_manager).await
                    }
                });
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, response_service)
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });

        }

    }

    /// Load the SSL configuration for rustls
    fn get_ssl_config(&self) -> Result<ServerConfig, io::Error> {
        // Trusted CA for client certificates
        let mut roots = RootCertStore::empty();
        let ca_cert_binding = load_cert(self.ca_client_cert_path.as_str())?;
        let ca_cert = ca_cert_binding.first().ok_or(io_err("Invalid client CA certificate file"))?;
        roots.add(ca_cert.clone()).map_err(|_| {
            io_err("Error adding CA certificate")
        })?;
        let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().map_err(|_| {
            io_err("Error building client verifier")
        })?;

        let server_cert = load_cert(self.server_cert_path.as_str())?;
        let server_key = load_pkey(self.server_key_path.as_str())?.remove(0);

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert, server_key)
            .map_err(|_| {
                io_err("Error building server configuration")
            })?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_ssl_config() {
        const CA_CERT_FILENAME: &'static str = "certs/CA-zone1.crt";
        const SERVER_CERT_FILENAME: &'static str = "certs/kme1.crt";
        const SERVER_KEY_FILENAME: &'static str = "certs/kme1.key";
        let server = super::Server {
            listen_addr: "127.0.0.1:3000".to_string(),
            ca_client_cert_path: CA_CERT_FILENAME.to_string(),
            server_cert_path: SERVER_CERT_FILENAME.to_string(),
            server_key_path: SERVER_KEY_FILENAME.to_string(),
        };
        let config = server.get_ssl_config();
        assert!(config.is_ok());

        const CA_CERT_FILE_WRONG_FORMAT: &'static str = "certs/sae1.pfx";
        let server = super::Server {
            listen_addr: "127.0.0.1:3000".to_string(),
            ca_client_cert_path: CA_CERT_FILE_WRONG_FORMAT.to_string(),
            server_cert_path: SERVER_CERT_FILENAME.to_string(),
            server_key_path: SERVER_KEY_FILENAME.to_string(),
        };
        let config = server.get_ssl_config();
        assert!(config.is_err());
    }
}