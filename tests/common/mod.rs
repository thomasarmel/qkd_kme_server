#![allow(dead_code)]

use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio::select;
use qkd_kme_server::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};
use qkd_kme_server::routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;

pub const HOST_PORT: &'static str = "localhost:3000";
pub const REMOTE_KME_HOST_PORT: &'static str = "localhost:4000";

pub fn setup() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/zone1/CA-zone1.crt".to_string(),
        server_cert_path: "certs/zone1/kme1.crt".to_string(),
        server_key_path: "certs/zone1/kme1.key".to_string(),
    };

    let qkd_manager = QkdManager::new(":memory:", 1);
    qkd_manager.add_sae(1,
                        1,
                        &Some([0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();

    let qkd_key_1 = PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap();

    qkd_manager.add_pre_init_qkd_key(qkd_key_1).unwrap();
    let qkd_key_2 = PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap();
    qkd_manager.add_pre_init_qkd_key(qkd_key_2).unwrap();

    tokio::spawn(async move {server.run::<EtsiSaeQkdRoutesV1>(&qkd_manager).await.unwrap();});
}

pub fn setup_cert_auth_reqwest_client() -> reqwest::Client {
    let mut buf = Vec::new();
    File::open("certs/zone1/sae1.pfx").unwrap().read_to_end(&mut buf).unwrap();
    let client_cert_id = reqwest::Identity::from_pkcs12_der(&buf, "").unwrap();
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_client_remote_kme() -> reqwest::Client {
    let mut buf = Vec::new();
    File::open("certs/zone2/sae3.pfx").unwrap().read_to_end(&mut buf).unwrap();
    let client_cert_id = reqwest::Identity::from_pkcs12_der(&buf, "").unwrap();
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_client_unregistered_sae() -> reqwest::Client {
    let mut buf = Vec::new();
    // SAE2 is not registered in SAEs database
    File::open("certs/zone1/sae2.pfx").unwrap().read_to_end(&mut buf).unwrap();
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

pub fn setup_2_kmes_network() {
    let kme1_internal_sae_server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/zone1/CA-zone1.crt".to_string(),
        server_cert_path: "certs/zone1/kme1.crt".to_string(),
        server_key_path: "certs/zone1/kme1.key".to_string(),
    };
    let kme2_internal_sae_server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:4000".to_string(),
        ca_client_cert_path: "certs/zone2/CA-zone2.crt".to_string(),
        server_cert_path: "certs/zone2/kme2.crt".to_string(),
        server_key_path: "certs/zone2/kme2.key".to_string(),
    };

    let kme2_external_inter_kmes_server = qkd_kme_server::server::Server {
        listen_addr: "0.0.0.0:4001".to_string(),
        ca_client_cert_path: "certs/inter_kmes/root-ca-kme2.crt".to_string(),
        server_cert_path: "certs/zone2/kme2.crt".to_string(),
        server_key_path: "certs/zone2/kme2.key".to_string(),
    };

    let kme1_qkd_manager = Arc::new(QkdManager::new(":memory:", 1));
    kme1_qkd_manager.add_sae(1,
                             1,
                             &Some([0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();
    kme1_qkd_manager.add_sae(2,
                             2,
                             &None
    ).unwrap();
    kme1_qkd_manager.add_kme_classical_net_info(2, "127.0.0.1:4001", "certs/inter_kmes/client-kme1-to-kme2.pfx", "").unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();

    let kme2_qkd_manager = Arc::new(QkdManager::new(":memory:", 2));
    kme2_qkd_manager.add_sae(1,
                             1,
                             &None
    ).unwrap();
    kme2_qkd_manager.add_sae(2,
                             2,
                             &Some([0x2d, 0x28, 0x6e, 0xc1, 0x77, 0x46, 0x5a, 0xb8, 0xdf, 0x00, 0x90, 0xdb, 0x04, 0x69, 0xa0, 0xab, 0x0a, 0x97, 0x38, 0x51])
    ).unwrap();
    kme2_qkd_manager.add_kme_classical_net_info(1, "127.0.0.1:3001", "certs/inter_kmes/client-kme2-to-kme1.pfx", "").unwrap();
    kme2_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();

    tokio::spawn(async move {
        select! {
            x = kme1_internal_sae_server.run::<EtsiSaeQkdRoutesV1>(&kme1_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme2_internal_sae_server.run::<EtsiSaeQkdRoutesV1>(&kme2_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme2_external_inter_kmes_server.run::<InterKMEsRoutes>(&kme2_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
        }
    });
}