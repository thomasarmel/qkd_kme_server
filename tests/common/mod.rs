#![allow(dead_code)]

use std::fs::File;
use std::io::Read;
use qkd_kme_server::qkd_manager::{QkdKey, QkdManager};
use qkd_kme_server::routes::QKDKMERoutes;

pub const HOST_PORT: &'static str = "localhost:3000";

pub fn setup() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    let qkd_manager = QkdManager::new(":memory:");
    qkd_manager.add_sae(1,
                        &[0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e]
    ).unwrap();

    let qkd_key_1 = QkdKey::new(
        1,
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap();

    qkd_manager.add_qkd_key(qkd_key_1).unwrap();
    let qkd_key_2 = QkdKey::new(
        1,
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap();
    qkd_manager.add_qkd_key(qkd_key_2).unwrap();

    tokio::spawn(async move {server.run::<QKDKMERoutes>(&qkd_manager).await.unwrap();});
}

pub fn setup_cert_auth_reqwest_client() -> reqwest::Client {
    let mut buf = Vec::new();
    File::open("certs/sae1.pfx").unwrap().read_to_end(&mut buf).unwrap();
    let client_cert_id = reqwest::Identity::from_pkcs12_der(&buf, "").unwrap();
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_bad_client() -> reqwest::Client {
    let mut buf = Vec::new();
    File::open("tests/data/bad_certs/bad_client.pfx").unwrap().read_to_end(&mut buf).unwrap();
    let client_cert_id = reqwest::Identity::from_pkcs12_der(&buf, "").unwrap();
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}