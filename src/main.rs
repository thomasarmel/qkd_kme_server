use log::error;
use qkd_kme_server::qkd_manager::{QkdKey, QkdManager};
use qkd_kme_server::routes::QKDKMERoutes;

#[tokio::main]
async fn main() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    let qkd_manager = QkdManager::new(qkd_kme_server::MEMORY_SQLITE_DB_PATH);
    if qkd_manager.add_sae(1,
    &[0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e]
    ).is_err() {
        error!("Error adding SAE to QKD manager");
        return;
    }

    let qkd_key_1 = match QkdKey::new(
        1,
        2,
        b"this_is_secret_key_1_of_32_bytes",
    ) {
        Ok(qkd_key) => qkd_key,
        Err(_) => {
            error!("Error creating QKD key");
            return;
        }
    };

    if qkd_manager.add_qkd_key(qkd_key_1).is_err() {
        error!("Error adding key to QKD manager");
        return;
    }

    let qkd_key_2 = match QkdKey::new(
        1,
        1,
        b"this_is_secret_key_1_of_32_bytes",
    ) {
        Ok(qkd_key) => qkd_key,
        Err(_) => {
            error!("Error creating QKD key");
            return;
        }
    };

    if qkd_manager.add_qkd_key(qkd_key_2).is_err() {
        error!("Error adding key to QKD manager");
        return;
    }

    if server.run::<QKDKMERoutes>(&qkd_manager).await.is_err() {
        error!("Error running HTTP server");
        return;
    }
}