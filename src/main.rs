use qkd_kme_server::routes::QKDKMERoutes;

fn main() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    server.run::<QKDKMERoutes>().unwrap();
}