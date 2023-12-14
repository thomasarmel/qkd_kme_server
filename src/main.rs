use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::QKDKMERoutes;

fn main() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    let qkd_manager = QkdManager::new();
    qkd_manager.add_qkd_key("slave1", qkd_kme_server::qkd_manager::QkdKey::new(
        "secretkey1",
        &[0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e],
    )).unwrap();

    server.run::<QKDKMERoutes>(&qkd_manager).unwrap();
}