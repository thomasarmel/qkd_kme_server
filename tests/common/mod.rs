#![allow(dead_code)]

pub mod util;
pub mod objects;

use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio::select;
use qkd_kme_server::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};
use qkd_kme_server::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;

pub const HOST_PORT: &'static str = "localhost:3000";
pub const REMOTE_KME_HOST_PORT: &'static str = "localhost:4000";

pub fn setup() {
    let server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );

    let qkd_manager = QkdManager::new(":memory:", 1, &Some("Alice".to_string()));
    qkd_manager.add_sae(1,
                        1,
                        &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
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

    let qkd_key_3 = PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_3_of_32_bytes",
    ).unwrap();
    qkd_manager.add_pre_init_qkd_key(qkd_key_3).unwrap();

    tokio::spawn(async move {server.run(&qkd_manager).await.unwrap();});
}

pub fn setup_lot_of_stored_keys() {
    let server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );

    let qkd_manager = QkdManager::new(":memory:", 1, &Some("Alice".to_string()));
    qkd_manager.add_sae(1,
                        1,
                        &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();

    for _ in 0..1024 {
        let qkd_key = PreInitQkdKeyWrapper::new(
            1,
            b"this_is_secret_key_1_of_32_bytes",
        ).unwrap();

        qkd_manager.add_pre_init_qkd_key(qkd_key).unwrap();
    }

    tokio::spawn(async move {server.run(&qkd_manager).await.unwrap();});
}

pub fn setup_cert_auth_reqwest_client() -> reqwest::Client {
    #[cfg(not(target_os = "macos"))]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone1/sae1.pfx";
    #[cfg(target_os = "macos")]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone1/sae1.pem";

    #[cfg(not(target_os = "macos"))]
    let client_cert_id = generate_reqwest_cert_identity_nativetls(SAE_AUTH_CLIENT_CERT_PATH, "");
    #[cfg(target_os = "macos")]
    let client_cert_id = generate_reqwest_cert_identity_rustls(SAE_AUTH_CLIENT_CERT_PATH);
    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_client_remote_kme() -> reqwest::Client {
    #[cfg(not(target_os = "macos"))]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone2/sae3.pfx";
    #[cfg(target_os = "macos")]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone2/sae3.pem";

    #[cfg(not(target_os = "macos"))]
    let client_cert_id = generate_reqwest_cert_identity_nativetls(SAE_AUTH_CLIENT_CERT_PATH, "");
    #[cfg(target_os = "macos")]
    let client_cert_id = generate_reqwest_cert_identity_rustls(SAE_AUTH_CLIENT_CERT_PATH);

    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_client_unregistered_sae() -> reqwest::Client {
    #[cfg(not(target_os = "macos"))]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone1/sae2.pfx";
    #[cfg(target_os = "macos")]
    const SAE_AUTH_CLIENT_CERT_PATH: &'static str = "certs/zone1/sae2.pem";

    #[cfg(not(target_os = "macos"))]
    let client_cert_id = generate_reqwest_cert_identity_nativetls(SAE_AUTH_CLIENT_CERT_PATH, "");
    #[cfg(target_os = "macos")]
    let client_cert_id = generate_reqwest_cert_identity_rustls(SAE_AUTH_CLIENT_CERT_PATH);

    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_cert_auth_reqwest_bad_client() -> reqwest::Client {
    #[cfg(not(target_os = "macos"))]
    const BAD_CLIENT_CLIENT_CERT_PATH: &'static str = "tests/data/bad_certs/bad_client.pfx";
    #[cfg(target_os = "macos")]
    const BAD_CLIENT_CLIENT_CERT_PATH: &'static str = "tests/data/bad_certs/bad_client.pem";

    #[cfg(not(target_os = "macos"))]
    let client_cert_id = generate_reqwest_cert_identity_nativetls(BAD_CLIENT_CLIENT_CERT_PATH, "");
    #[cfg(target_os = "macos")]
    let client_cert_id = generate_reqwest_cert_identity_rustls(BAD_CLIENT_CLIENT_CERT_PATH);

    reqwest::Client::builder()
        .identity(client_cert_id)
        .danger_accept_invalid_certs(true) // Instead of importing root certificate
        .build().unwrap()
}

pub fn setup_2_kmes_network() {
    #[cfg(not(target_os = "macos"))]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pfx";
    #[cfg(target_os = "macos")]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pem";

    #[cfg(not(target_os = "macos"))]
    const KME2_TO_KME1_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme2-to-kme1.pfx";
    #[cfg(target_os = "macos")]
    const KME2_TO_KME1_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme2-to-kme1.pem";

    let kme1_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme2_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:4000",
        "certs/zone2/CA-zone2.crt",
        "certs/zone2/kme2.crt",
        "certs/zone2/kme2.key",
    );

    let kme1_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:3001",
        "certs/inter_kmes/root-ca-kme1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme2_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:4001",
        "certs/inter_kmes/root-ca-kme2.crt",
        "certs/zone2/kme2.crt",
        "certs/zone2/kme2.key",
    );

    let kme1_qkd_manager = Arc::new(QkdManager::new(":memory:", 1, &Some("Alice".to_string())));
    kme1_qkd_manager.add_sae(1,
                             1,
                             &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();
    kme1_qkd_manager.add_sae(2,
                             2,
                             &None
    ).unwrap();
    kme1_qkd_manager.add_kme_classical_net_info(2, "127.0.0.1:4001", KME1_TO_KME2_CERT_AUTH_PATH, "", true).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_2_of_32_bytes",
    ).unwrap()).unwrap();

    let kme2_qkd_manager = Arc::new(QkdManager::new(":memory:", 2, &Some("Bob".to_string())));
    kme2_qkd_manager.add_sae(1,
                             1,
                             &None
    ).unwrap();
    kme2_qkd_manager.add_sae(2,
                             2,
                             &Some(vec![0x2d, 0x28, 0x6e, 0xc1, 0x77, 0x46, 0x5a, 0xb8, 0xdf, 0x00, 0x90, 0xdb, 0x04, 0x69, 0xa0, 0xab, 0x0a, 0x97, 0x38, 0x51])
    ).unwrap();
    kme2_qkd_manager.add_kme_classical_net_info(1, "127.0.0.1:3001", KME2_TO_KME1_CERT_AUTH_PATH, "", true).unwrap();
    kme2_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();
    kme2_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        1,
        b"this_is_secret_key_2_of_32_bytes",
    ).unwrap()).unwrap();

    tokio::spawn(async move {
        select! {
            x = kme1_internal_sae_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme1_external_inter_kmes_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
            x = kme2_internal_sae_server.run(&kme2_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme2_external_inter_kmes_server.run(&kme2_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
        }
    });
}

pub fn setup_2_kmes_network_keys_not_sync() {
    #[cfg(not(target_os = "macos"))]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pfx";
    #[cfg(target_os = "macos")]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pem";

    #[cfg(not(target_os = "macos"))]
    const KME2_TO_KME1_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme2-to-kme1.pfx";
    #[cfg(target_os = "macos")]
    const KME2_TO_KME1_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme2-to-kme1.pem";

    let kme1_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme2_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:4000",
        "certs/zone2/CA-zone2.crt",
        "certs/zone2/kme2.crt",
        "certs/zone2/kme2.key",
    );

    let kme1_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:3001",
        "certs/inter_kmes/root-ca-kme1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme2_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:4001",
        "certs/inter_kmes/root-ca-kme2.crt",
        "certs/zone2/kme2.crt",
        "certs/zone2/kme2.key",
    );

    let kme1_qkd_manager = Arc::new(QkdManager::new(":memory:", 1, &Some("Alice".to_string())));
    kme1_qkd_manager.add_sae(1,
                             1,
                             &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();
    kme1_qkd_manager.add_sae(2,
                             2,
                             &None
    ).unwrap();
    kme1_qkd_manager.add_kme_classical_net_info(2, "127.0.0.1:4001", KME1_TO_KME2_CERT_AUTH_PATH, "", true).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();

    let kme2_qkd_manager = Arc::new(QkdManager::new(":memory:", 2, &Some("Bob".to_string())));
    kme2_qkd_manager.add_sae(1,
                             1,
                             &None
    ).unwrap();
    kme2_qkd_manager.add_sae(2,
                             2,
                             &Some(vec![0x2d, 0x28, 0x6e, 0xc1, 0x77, 0x46, 0x5a, 0xb8, 0xdf, 0x00, 0x90, 0xdb, 0x04, 0x69, 0xa0, 0xab, 0x0a, 0x97, 0x38, 0x51])
    ).unwrap();
    kme2_qkd_manager.add_kme_classical_net_info(1, "127.0.0.1:3001", KME2_TO_KME1_CERT_AUTH_PATH, "", true).unwrap();
    kme2_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        1,
        // Aie aie aie, this is not the same key :o
        b"this_is_secret_key_2_of_32_bytes",
    ).unwrap()).unwrap();

    tokio::spawn(async move {
        select! {
            x = kme1_internal_sae_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme1_external_inter_kmes_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
            x = kme2_internal_sae_server.run(&kme2_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme2_external_inter_kmes_server.run(&kme2_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
        }
    });
}

pub fn setup_2_kmes_network_1_kme_down() {
    #[cfg(not(target_os = "macos"))]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pfx";
    #[cfg(target_os = "macos")]
    const KME1_TO_KME2_CERT_AUTH_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pem";

    let kme1_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme1_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:3001",
        "certs/inter_kmes/root-ca-kme1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );

    let kme1_qkd_manager = Arc::new(QkdManager::new(":memory:", 1, &Some("Alice".to_string())));
    kme1_qkd_manager.add_sae(1,
                             1,
                             &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();
    kme1_qkd_manager.add_sae(2,
                             2,
                             &None
    ).unwrap();
    kme1_qkd_manager.add_kme_classical_net_info(2, "127.0.0.1:4001", KME1_TO_KME2_CERT_AUTH_PATH, "", true).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_2_of_32_bytes",
    ).unwrap()).unwrap();


    tokio::spawn(async move {
        select! {
            x = kme1_internal_sae_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme1_external_inter_kmes_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
        }
    });
}

pub fn setup_2_kmes_network_missing_conf() {
    let kme1_internal_sae_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        "127.0.0.1:3000",
        "certs/zone1/CA-zone1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );
    let kme1_external_inter_kmes_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        "0.0.0.0:3001",
        "certs/inter_kmes/root-ca-kme1.crt",
        "certs/zone1/kme1.crt",
        "certs/zone1/kme1.key",
    );

    let kme1_qkd_manager = Arc::new(QkdManager::new(":memory:", 1, &Some("Alice".to_string())));
    kme1_qkd_manager.add_sae(1,
                             1,
                             &Some(vec![0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).unwrap();
    kme1_qkd_manager.add_sae(2,
                             2,
                             &None
    ).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ).unwrap()).unwrap();
    kme1_qkd_manager.add_pre_init_qkd_key(PreInitQkdKeyWrapper::new(
        2,
        b"this_is_secret_key_2_of_32_bytes",
    ).unwrap()).unwrap();


    tokio::spawn(async move {
        select! {
            x = kme1_internal_sae_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running internal SAE server: {:?}", x);
            },
            x = kme1_external_inter_kmes_server.run(&kme1_qkd_manager) => {
                eprintln!("Error running external inter-KMEs server: {:?}", x);
            },
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn generate_reqwest_cert_identity_nativetls(client_auth_cert_path: &str, password: &str) -> reqwest::tls::Identity {
    let mut buf = Vec::new();
    File::open(client_auth_cert_path).unwrap().read_to_end(&mut buf).unwrap();
    reqwest::Identity::from_pkcs12_der(&buf, password).unwrap()
}

#[cfg(target_os = "macos")]
fn generate_reqwest_cert_identity_rustls(client_auth_cert_path: &str) -> reqwest::tls::Identity {
    let mut buf = Vec::new();
    File::open(client_auth_cert_path).unwrap().read_to_end(&mut buf).unwrap();
    reqwest::Identity::from_pem(&buf).unwrap()
}