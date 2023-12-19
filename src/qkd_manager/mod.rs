mod key_handler;
pub(crate) mod http_response_obj;

use std::thread;
use sha1::Digest;
use crate::qkd_manager::QkdManagerResponse::TransmissionError;

#[derive(Clone)]
pub struct QkdManager {
    command_tx: crossbeam_channel::Sender<QkdManagerCommand>,
    response_rx: crossbeam_channel::Receiver<QkdManagerResponse>,
}

impl QkdManager {
    pub fn new(sqlite_db_path: &str) -> Self {
        let (command_tx, command_rx) = crossbeam_channel::unbounded::<QkdManagerCommand>();
        let (response_tx, response_rx) = crossbeam_channel::unbounded::<QkdManagerResponse>();
        let sqlite_db_path = String::from(sqlite_db_path);
        thread::spawn(move || {
            let mut key_handler = key_handler::KeyHandler::new(&sqlite_db_path, command_rx, response_tx);
            key_handler.run();
        });
        Self {
            command_tx,
            response_rx,
        }
    }

    pub fn add_qkd_key(&self, key: QkdKey) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::AddKey(key)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Ok => Ok(QkdManagerResponse::Ok),
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /*pub fn get_qkd_key(&self, sae_id: &str, auth_client_cert_serial: &[u8]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKey(String::from(sae_id))).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Key(key) => {
                if key.auth_client_cert_serial != auth_client_cert_serial {
                    return Err(QkdManagerResponse::AuthenticationError);
                }
                Ok(QkdManagerResponse::Key(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }*/

    pub fn add_sae(&self, sae_id: i64, sae_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::AddSae(sae_id, *sae_certificate_serial)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Ok => Ok(QkdManagerResponse::Ok),
            qkd_response_error => Err(qkd_response_error),
        }
    }

    pub fn get_qkd_key_status(&self, origin_sae_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], target_sae_id: i64) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetStatus(*origin_sae_certificate_serial, target_sae_id)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Status(status) => Ok(QkdManagerResponse::Status(status)),
            qkd_response_error => Err(qkd_response_error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QkdKey {
    pub(crate) origin_sae_id: i64,
    pub(crate) target_sae_id: i64,
    pub(crate) key: [u8; Self::QKD_KEY_SIZE_BYTES],
    pub(crate) key_uuid: uuid::Bytes,
}

impl QkdKey {
    const QKD_KEY_SIZE_BYTES: usize = crate::QKD_KEY_SIZE_BITS / 8;

    pub fn new(origin_sae_id: i64, target_sae_id: i64, key: &[u8; Self::QKD_KEY_SIZE_BYTES]) -> Self {
        Self {
            origin_sae_id,
            target_sae_id,
            key: *key,
            key_uuid: Self::generate_key_uuid(key),
        }
    }

    fn generate_key_uuid(key: &[u8; Self::QKD_KEY_SIZE_BYTES]) -> uuid::Bytes {
        let mut hasher = sha1::Sha1::new();
        hasher.update(key);
        let hash_sub_bytes = uuid::Bytes::try_from(&hasher.finalize()[..16]).unwrap();
        uuid::Builder::from_sha1_bytes(hash_sub_bytes).as_uuid().to_bytes_le()
    }

    pub fn get_uuid(&self) -> uuid::Bytes {
        self.key_uuid
    }
}

enum QkdManagerCommand {
    AddKey(QkdKey),
    GetKey(String),
    GetStatus([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], i64), // origin certificate + target id
    AddSae(i64, [u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]),
}

#[allow(private_interfaces)]
#[derive(Debug)]
pub enum QkdManagerResponse {
    Ok,
    Ko,
    TransmissionError,
    AuthenticationError,
    Key(QkdKey),
    Status(http_response_obj::ResponseQkdKeysStatus),
}
