use std::convert::identity;
use uuid::Bytes;
use x509_parser::nom::AsBytes;
use crate::qkd_manager;
use crate::qkd_manager::{QkdKey, QkdManagerCommand, QkdManagerResponse};
use base64::{engine::general_purpose, Engine as _};
use crate::qkd_manager::http_response_obj::ResponseQkdKeysList;

pub(super) struct KeyHandler {
    command_rx: crossbeam_channel::Receiver<QkdManagerCommand>,
    response_tx: crossbeam_channel::Sender<QkdManagerResponse>,
    sqlite_db: sqlite::Connection,
}

impl KeyHandler {
    pub(super) fn new(sqlite_db_path: &str, command_rx: crossbeam_channel::Receiver<QkdManagerCommand>, response_tx: crossbeam_channel::Sender<QkdManagerResponse>) -> Self {
        let key_handler = Self {
            command_rx,
            response_tx,
            sqlite_db: sqlite::open(sqlite_db_path).unwrap(),
        };
        key_handler.sqlite_db.execute(
            "CREATE TABLE IF NOT EXISTS keys (
                    key_uuid BLOB PRIMARY KEY NOT NULL,
                    key BLOB NOT NULL,
                    origin_sae_id INTEGER NOT NULL,
                    target_sae_id INTEGER NOT NULL,
                    FOREIGN KEY (origin_sae_id) REFERENCES saes(sae_id),
                    FOREIGN KEY (target_sae_id) REFERENCES saes(sae_id));
                CREATE TABLE IF NOT EXISTS saes (
                    sae_id INTEGER PRIMARY KEY NOT NULL,
                    sae_certificate_serial BLOB NOT NULL);").unwrap();
        key_handler
    }

    pub(super) fn run(&mut self) {
        loop {
            match self.command_rx.recv() {
                Ok(cmd) => {
                    match cmd {
                        QkdManagerCommand::AddKey(key) => {
                            println!("Adding key for SAE ID {}", key.target_sae_id);
                            self.response_tx.send(self.add_key(key).unwrap_or_else(identity)).unwrap();
                        },
                        QkdManagerCommand::GetKeys(sae_certificate_serial, sae_id) => {
                            println!("Getting key for SAE ID {}", sae_id);
                            self.response_tx.send(self.get_sae_keys(&sae_certificate_serial, sae_id).unwrap_or_else(identity)).unwrap();
                        },
                        QkdManagerCommand::AddSae(sae_id, sae_certificate_serial) => {
                            println!("Adding SAE ID {}", sae_id);
                            self.response_tx.send(self.add_sae(sae_id, &sae_certificate_serial).unwrap_or_else(identity)).unwrap();
                        },
                        QkdManagerCommand::GetStatus(origin_sae_certificate, target_sae_id) => {
                            println!("Getting status for SAE ID {}", target_sae_id);
                            self.response_tx.send(self.get_sae_status(&origin_sae_certificate, target_sae_id).unwrap_or_else(identity)).unwrap();
                        },
                    }
                }
                Err(e) => {
                    println!("Error receiving command: {:?}", e);
                }
            }
        }
    }

    fn add_sae(&self, sae_id: i64, sae_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let mut stmt = self.sqlite_db.prepare("INSERT INTO saes (sae_id, sae_certificate_serial) VALUES (?, ?)").unwrap();
        stmt.bind((1, sae_id)).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.bind((2, sae_certificate_serial.as_bytes())).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.next().map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    fn add_key(&self, key: QkdKey) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let mut stmt = self.sqlite_db.prepare("INSERT INTO keys (key_uuid, key, origin_sae_id, target_sae_id) VALUES (?, ?, ?, ?)").unwrap();
        stmt.bind((1, key.key_uuid.as_bytes())).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.bind((2, key.key.as_bytes())).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.bind((3, key.origin_sae_id)).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.bind((4, key.target_sae_id)).map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        stmt.next().map_err(|_| {
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    fn get_sae_status(&self, origin_sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], target_sae_id: i64) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).ok_or(QkdManagerResponse::AuthenticationError)?;

        let mut stmt = self.sqlite_db.prepare("SELECT COUNT(*) FROM keys WHERE target_sae_id = ? and origin_sae_id = ?").unwrap();
        stmt.bind((1, target_sae_id)).unwrap();
        stmt.bind((2, origin_sae_id)).unwrap();
        stmt.next().unwrap();
        let key_count: i64 = stmt.read::<i64, usize>(0).unwrap();

        let response_qkd_key_status = crate::qkd_manager::http_response_obj::ResponseQkdKeysStatus {
            source_KME_ID: crate::THIS_KME_ID.to_string(),
            target_KME_ID: "?? TODO".to_string(),
            master_SAE_ID: origin_sae_id.to_string(),
            slave_SAE_ID: target_sae_id.to_string(),
            key_size: crate::QKD_KEY_SIZE_BITS,
            stored_key_count: key_count as usize,
            max_key_count: crate::MAX_QKD_KEYS_PER_SAE,
            max_key_per_request: crate::MAX_QKD_KEYS_PER_REQUEST,
            max_key_size: crate::QKD_MAX_KEY_SIZE_BITS,
            min_key_size: crate::QKD_MIN_KEY_SIZE_BITS,
            max_SAE_ID_count: crate::MAX_QKD_KEY_SAE_IDS,
        };
        println!("Key count for SAE ID {}: {}", target_sae_id, key_count);

        Ok(QkdManagerResponse::Status(response_qkd_key_status))
    }

    fn get_sae_keys(&self, origin_sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], target_sae_id: i64) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).ok_or(QkdManagerResponse::AuthenticationError)?;

        let mut stmt = self.sqlite_db.prepare("SELECT key_uuid, key FROM keys WHERE target_sae_id = ? and origin_sae_id = ? LIMIT 1").unwrap();
        stmt.bind((1, target_sae_id)).unwrap();
        stmt.bind((2, origin_sae_id)).unwrap();
        stmt.next().unwrap();
        let key_uuid: Vec<u8> = stmt.read::<Vec<u8>, usize>(0).unwrap();
        let key: Vec<u8> = stmt.read::<Vec<u8>, usize>(1).unwrap();

        let response_qkd_key = qkd_manager::http_response_obj::ResponseQkdKey {
            key_ID: uuid::Uuid::from_bytes(Bytes::try_from(key_uuid).unwrap()).to_string(),
            key: general_purpose::STANDARD.encode(&key)
        };

        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys: vec![response_qkd_key],
        }))
    }

    fn get_sae_id_from_certificate(&self, sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Option<i64> {
        let mut stmt = self.sqlite_db.prepare("SELECT sae_id FROM saes WHERE sae_certificate_serial = ?").unwrap();
        stmt.bind((1, sae_certificate.as_bytes())).unwrap();
        stmt.next().unwrap();
        let sae_id: i64 = stmt.read::<i64, usize>(0).unwrap();
        Some(sae_id)
    }
}