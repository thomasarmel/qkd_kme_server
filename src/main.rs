use rand::Rng;
use sha1::{Digest, Sha1};
use uuid::{Bytes};
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::QKDKMERoutes;

#[tokio::main]
async fn main() {
    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    let mut hasher = Sha1::new();

    hasher.update(b"hello world");

    let uuid = get_random_key_uuid();
    println!("uuid: {:?}", uuid);

    let qkd_manager = QkdManager::new(qkd_kme_server::MEMORY_SQLITE_DB_PATH);
    qkd_manager.add_sae(1,
    &[0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e]
    ).unwrap();


    qkd_manager.add_qkd_key(qkd_kme_server::qkd_manager::QkdKey::new(
        1,
        2,
        b"this_is_secret_key_1_of_32_bytes",
        )).unwrap();

    qkd_manager.add_qkd_key(qkd_kme_server::qkd_manager::QkdKey::new(
        1,
        1,
        b"this_is_secret_key_1_of_32_bytes",
    )).unwrap();

    server.run::<QKDKMERoutes>(&qkd_manager).await.unwrap();
}

fn mock_generate_random_qkd_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; qkd_kme_server::QKD_KEY_SIZE_BITS / 8]>();
    key.to_vec()
}

// todo: move to crate
fn get_random_key_uuid() -> Bytes {
    let mut hasher = Sha1::new();
    hasher.update(&mock_generate_random_qkd_key());
    let result = &hasher.finalize()[..];
    let result = &result[..16];
    let result = Bytes::try_from(result).unwrap();
    println!("result: {:?}", result);
    uuid::Builder::from_sha1_bytes(result).as_uuid().to_bytes_le()
}