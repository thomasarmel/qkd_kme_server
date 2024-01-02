mod key_handler;
pub(crate) mod http_response_obj;
pub(crate) mod http_request_obj;

use std::{io, thread};
use log::error;
use sha1::Digest;
use crate::qkd_manager::http_response_obj::ResponseQkdKeysList;
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
            let mut key_handler = match key_handler::KeyHandler::new(&sqlite_db_path, command_rx, response_tx) {
                Ok(handler) => handler,
                Err(_) => {
                    error!("Error creating key handler");
                    return;
                }
            };
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

    pub fn get_qkd_key(&self, target_sae_id: i64, auth_client_cert_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKeys(*auth_client_cert_serial, target_sae_id)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Keys(key) => {
                Ok(QkdManagerResponse::Keys(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }

    pub fn get_qkd_keys_with_ids(&self, source_sae_id: i64, auth_client_cert_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKeysWithIds(*auth_client_cert_serial, source_sae_id, keys_uuids)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Keys(key) => {
                Ok(QkdManagerResponse::Keys(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }

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

    pub fn new(origin_sae_id: i64, target_sae_id: i64, key: &[u8; Self::QKD_KEY_SIZE_BYTES]) -> Result<Self, io::Error> {
        Ok(Self {
            origin_sae_id,
            target_sae_id,
            key: *key,
            key_uuid: Self::generate_key_uuid(key)?,
        })
    }

    fn generate_key_uuid(key: &[u8; Self::QKD_KEY_SIZE_BYTES]) -> Result<uuid::Bytes, io::Error> {
        let mut hasher = sha1::Sha1::new();
        hasher.update(key);
        let hash_sub_bytes = uuid::Bytes::try_from(&hasher.finalize()[..16]).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Error creating key UUID from key hash")
        })?;
        Ok(uuid::Builder::from_sha1_bytes(hash_sub_bytes).as_uuid().to_bytes_le())
    }

    pub fn get_uuid(&self) -> uuid::Bytes {
        self.key_uuid
    }
}

enum QkdManagerCommand {
    AddKey(QkdKey),
    GetKeys([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], i64),
    GetKeysWithIds([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], i64, Vec<String>),
    GetStatus([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], i64), // origin certificate + target id
    AddSae(i64, [u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]),
}

#[allow(private_interfaces)]
#[derive(Debug, PartialEq)]
pub enum QkdManagerResponse {
    Ok,
    Ko,
    NotFound,
    TransmissionError,
    AuthenticationError,
    Keys(ResponseQkdKeysList),
    Status(http_response_obj::ResponseQkdKeysStatus),
}


#[cfg(test)]
mod test {
    use crate::CLIENT_CERT_SERIAL_SIZE_BYTES;

    #[test]
    fn test_add_qkd_key() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH);
        let key = super::QkdKey::new(1, 2, &[0; super::QkdKey::QKD_KEY_SIZE_BYTES]).unwrap();
        let response = qkd_manager.add_qkd_key(key);
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), super::QkdManagerResponse::Ok);
    }

    #[test]
    fn test_add_sae() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH);
        let response = qkd_manager.add_sae(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), super::QkdManagerResponse::Ok);
    }

    #[test]
    fn test_get_qkd_key() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH);
        qkd_manager.add_sae(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        qkd_manager.add_sae(2, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        let key = super::QkdKey::new(1, 2, &[0; super::QkdKey::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_key(2, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_key(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
    }

    #[test]
    fn test_get_qkd_keys_with_ids() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH);
        qkd_manager.add_sae(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        qkd_manager.add_sae(2, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        let key = super::QkdKey::new(1, 2, &[0; super::QkdKey::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        qkd_manager.add_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_keys_with_ids(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys_with_ids(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_ok());
    }

    #[test]
    fn test_get_qkd_key_status() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH);
        qkd_manager.add_sae(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        qkd_manager.add_sae(2, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES]).unwrap();
        let key = super::QkdKey::new(1, 2, &[0; super::QkdKey::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_key_status(&[1; CLIENT_CERT_SERIAL_SIZE_BYTES], 2);
        assert!(response.is_ok());
        assert!(matches!(response.unwrap(), super::QkdManagerResponse::Status(_)));
    }

    #[test]
    fn test_key_uuid() {
        let key = super::QkdKey::new(1, 2, &[0; super::QkdKey::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        assert_eq!(key_uuid_str, "7b848ade-8cff-3d54-a9b8-53a215e6ee77");
    }
}