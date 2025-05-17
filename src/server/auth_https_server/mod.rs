//! HTTPS server implementation

mod certificates;

use hyper;
use rustls;
use tokio;
use tokio_rustls;

use std::io;
use std::marker::PhantomData;
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
use crate::server::auth_https_server::certificates::{load_cert, load_pkey};


/// QKD KME server
/// A KME REST API server that implements the ETSI protocol (cf docs/etsi_qkd_standard_definition.pdf)
/// # Note
/// * SAE clients are authenticated using client certificates, and the server is authenticated using a server certificate
/// * SAE client certificate must be signed by the CA certificate specified in the configuration, and authorized client certificates are discriminated by their serial number
#[derive(Debug)]
pub struct AuthHttpsServer<T: crate::routes::Routes> {
    phantom: PhantomData<T>,
    /// HTTPS listen address, e.g. "0.0.0.0:443"
    pub listen_addr: String,
    /// Path to the CA certificate used to verify client certificates
    /// # Note
    /// * The CA certificate must be in CRT format
    /// * The client need a certificate signed by this CA to be able to connect to the server
    /// * Once connected, client are authenticated using their certificate serial number
    pub ca_client_cert_path: String,
    /// Path to the server certificate, CRT format
    /// # Note
    /// * Be aware that your SAE clients will need to trust this certificate
    pub server_cert_path: String,
    /// Path to the server private key, KEY format
    pub server_key_path: String,
}

impl<T: crate::routes::Routes> AuthHttpsServer<T> {

    /// Create a new HTTPS server
    /// # Arguments
    /// * `listen_addr` - The address to listen for HTTPS connections, e.g. "0.0.0.0:443", or "192.168.1.2:443" for local network (SAE internal network?)
    /// * `ca_client_cert_path` - The path to the CA certificate used to verify client certificates
    /// * `server_cert_path` - The path to the server certificate
    /// * `server_key_path` - The path to the server private key
    /// # Parameters
    /// * `T` - The type of the routes to use, type implements `crate::routes::Routes`
    /// # Returns
    /// A new AuthHttpsServer
    pub fn new(listen_addr: &str, ca_client_cert_path: &str, server_cert_path: &str, server_key_path: &str) -> AuthHttpsServer<T> {
        #[cfg(target_os = "macos")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        AuthHttpsServer {
            phantom: PhantomData,
            listen_addr: listen_addr.to_string(),
            ca_client_cert_path: ca_client_cert_path.to_string(),
            server_cert_path: server_cert_path.to_string(),
            server_key_path: server_key_path.to_string(),
        }
    }

    /// Run the REST HTTPS server asynchronously
    /// # Type parameters
    /// * `T` - The type of the routes to use, type implements the REST API routes
    /// # Arguments
    /// * `qkd_manager` - The QKD manager, needed to store and retrieve QKD keys
    /// # Returns
    /// An io::Error if the server cannot be started (check the logs for more information)
    pub async fn run(&self, qkd_manager: &QkdManager) -> Result<(), io::Error> {
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
            info!("[KME{}] Waiting for incoming connection on port {}...", qkd_manager.kme_id, addr.port());
            let Ok(stream) = tls_acceptor.accept(socket.accept().await?.0).await else {
                warn!("Error accepting connection, maybe client certificate is missing?");
                continue;
            };
            info!("[KME{}] Received connection from peer {}", qkd_manager.kme_id, stream.get_ref().0.peer_addr().map_err(|_| {
                io_err("Error getting peer address")
            })?);
            let (_, server_session) = stream.get_ref();
            let client_cert = Arc::new(server_session.peer_certificates()
                .ok_or(io_err("Error: no client certificate, this is unexpected"))?
                .first()
                .ok_or(io_err("Error fetching client certificate, this is unexpected"))?
                .clone().into_owned());

            let io = TokioIo::new(stream);
            let qkd_manager = qkd_manager.clone(); // Must be cloned to be moved into each new task

            tokio::task::spawn(async move {
                let response_service = service_fn(|req: Request<hyper::body::Incoming>| {
                    let local_client_cert_serial_str = Arc::clone(&client_cert);
                    let qkd_manager = qkd_manager.clone(); // Must be cloned in each new task
                    async move {
                        // Let the route type handle the request
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

    /// Load the SSL configuration for RusTLS layer
    /// # Returns
    /// A ServerConfig object, containing the RusTLS SSL configuration
    /// # Errors
    /// If the configuration cannot be loaded (e.g. invalid certificate file, check the logs for more information)
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

        // We retrieve the first key, as we only support one key per server
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
    use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;

    #[test]
    fn test_get_ssl_config() {
        const CA_CERT_FILENAME: &'static str = "certs/zone1/CA-zone1.crt";
        const SERVER_CERT_FILENAME: &'static str = "certs/zone1/kme1.crt";
        const SERVER_KEY_FILENAME: &'static str = "certs/zone1/kme1.key";
        let server = super::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
            "127.0.0.1:3000",
            CA_CERT_FILENAME,
            SERVER_CERT_FILENAME,
            SERVER_KEY_FILENAME,
        );
        let config = server.get_ssl_config();
        assert!(config.is_ok());

        const CA_CERT_FILE_WRONG_FORMAT: &'static str = "certs/zone1/sae1.pfx";
        let server = super::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
            "127.0.0.1:3000",
            CA_CERT_FILE_WRONG_FORMAT,
            SERVER_CERT_FILENAME,
            SERVER_KEY_FILENAME,
        );
        let config = server.get_ssl_config();
        assert!(config.is_err());
    }
}