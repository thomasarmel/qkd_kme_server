use std::convert::identity;
use std::io;
use uuid::Bytes;
use x509_parser::nom::AsBytes;
use crate::qkd_manager;
use crate::qkd_manager::{QkdKey, QkdManagerCommand, QkdManagerResponse};
use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use crate::qkd_manager::http_response_obj::{ResponseQkdKey, ResponseQkdKeysList};
use crate::ensure_prepared_statement_ok;

pub(super) struct KeyHandler {
    command_rx: crossbeam_channel::Receiver<QkdManagerCommand>,
    response_tx: crossbeam_channel::Sender<QkdManagerResponse>,
    sqlite_db: sqlite::Connection,
}

impl KeyHandler {
    pub(super) fn new(sqlite_db_path: &str, command_rx: crossbeam_channel::Receiver<QkdManagerCommand>, response_tx: crossbeam_channel::Sender<QkdManagerResponse>) -> Result<Self, io::Error> {
        let key_handler = Self {
            command_rx,
            response_tx,
            sqlite_db: sqlite::open(sqlite_db_path).map_err(|e| {
                io::Error::new(io::ErrorKind::NotConnected, format!("Error opening sqlite database: {:?}", e))
            })?,
        };
        key_handler.sqlite_db.execute(
            "CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                    key_uuid TEXT NOT NULL,
                    key BLOB NOT NULL,
                    origin_sae_id INTEGER NOT NULL,
                    target_sae_id INTEGER NOT NULL,
                    FOREIGN KEY (origin_sae_id) REFERENCES saes(sae_id),
                    FOREIGN KEY (target_sae_id) REFERENCES saes(sae_id));
                CREATE TABLE IF NOT EXISTS saes (
                    sae_id INTEGER PRIMARY KEY NOT NULL,
                    sae_certificate_serial BLOB NOT NULL);").map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Error creating sqlite tables: {:?}", e))
        })?;
        Ok(key_handler)
    }

    pub(super) fn run(&mut self) {
        loop {
            match self.command_rx.recv() {
                Ok(cmd) => {
                    match cmd {
                        QkdManagerCommand::AddKey(key) => {
                            info!("Adding key for SAE ID {}", key.target_sae_id);
                            if self.response_tx.send(self.add_key(key).unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::GetKeys(sae_certificate_serial, sae_id) => {
                            info!("Getting key for SAE ID {}", sae_id);
                            if self.response_tx.send(self.get_sae_keys(&sae_certificate_serial, sae_id).unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::GetKeysWithIds(sae_certificate_serial, master_sae_id, keys_uuids) => {
                            info!("Getting keys from SAE ID {}", master_sae_id);
                            if self.response_tx.send(self.get_sae_keys_with_ids(&sae_certificate_serial, master_sae_id, keys_uuids).unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::AddSae(sae_id, sae_certificate_serial) => {
                            info!("Adding SAE ID {}", sae_id);
                            if self.response_tx.send(self.add_sae(sae_id, &sae_certificate_serial).unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::GetStatus(origin_sae_certificate, target_sae_id) => {
                            info!("Getting status for SAE ID {}", target_sae_id);
                            if self.response_tx.send(self.get_sae_status(&origin_sae_certificate, target_sae_id).unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                    }
                }
                Err(e) => {
                    error!("Error receiving command: {:?}", e);
                }
            }
        }
    }

    fn add_sae(&self, sae_id: i64, sae_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "INSERT INTO saes (sae_id, sae_certificate_serial) VALUES (?, ?);";

        let mut stmt = ensure_prepared_statement_ok!(self.sqlite_db, PREPARED_STATEMENT);
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
        const PREPARED_STATEMENT: &'static str = "INSERT INTO keys (key_uuid, key, origin_sae_id, target_sae_id) VALUES (?, ?, ?, ?);";

        let mut stmt = ensure_prepared_statement_ok!(self.sqlite_db, PREPARED_STATEMENT);
        let uuid_bytes = Bytes::try_from(key.key_uuid).map_err(|_| {
            error!("Error converting UUID to bytes");
            QkdManagerResponse::Ko
        })?;
        let uuid_str = uuid::Uuid::from_bytes(uuid_bytes).to_string();
        stmt.bind((1, uuid_str.as_str())).map_err(|_| {
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
        const PREPARED_STATEMENT: &'static str = "SELECT COUNT(*) FROM keys WHERE target_sae_id = ? and origin_sae_id = ?;";

        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).ok_or(QkdManagerResponse::AuthenticationError)?;

        let mut stmt = ensure_prepared_statement_ok!(self.sqlite_db, PREPARED_STATEMENT);
        stmt.bind((1, target_sae_id)).map_err(|_| {
            error!("Error binding target SAE ID");
            QkdManagerResponse::Ko
        })?;
        stmt.bind((2, origin_sae_id)).map_err(|_| {
            error!("Error binding origin SAE ID");
            QkdManagerResponse::Ko
        })?;
        stmt.next().map_err(|_| {
            error!("Error executing SQL statement");
            QkdManagerResponse::Ko
        })?;
        let key_count: i64 = stmt.read::<i64, usize>(0).map_err(|_| {
            error!("Error reading SQL statement result");
            QkdManagerResponse::Ko
        })?;

        let response_qkd_key_status = qkd_manager::http_response_obj::ResponseQkdKeysStatus {
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

        Ok(QkdManagerResponse::Status(response_qkd_key_status))
    }

    fn get_sae_keys(&self, origin_sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], target_sae_id: i64) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT key_uuid, key FROM keys WHERE target_sae_id = ? and origin_sae_id = ? LIMIT 1;";
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).ok_or(QkdManagerResponse::AuthenticationError)?;

        let mut stmt = ensure_prepared_statement_ok!(self.sqlite_db, PREPARED_STATEMENT);
        stmt.bind((1, target_sae_id)).map_err(|_| {
            error!("Error binding target SAE ID");
            QkdManagerResponse::Ko
        })?;
        stmt.bind((2, origin_sae_id)).map_err(|_| {
            error!("Error binding origin SAE ID");
            QkdManagerResponse::Ko
        })?;
        let sql_execution_state = stmt.next().map_err(|_| {
            error!("Error executing SQL statement");
            QkdManagerResponse::Ko
        })?;
        if sql_execution_state != sqlite::State::Row {
            return Err(QkdManagerResponse::NotFound);
        }
        let key_uuid: String = stmt.read::<String, usize>(0).map_err(|_| {
            error!("Error reading SQL statement result");
            QkdManagerResponse::Ko
        })?;
        let key: Vec<u8> = stmt.read::<Vec<u8>, usize>(1).map_err(|_| {
            error!("Error reading SQL statement result");
            QkdManagerResponse::Ko
        })?;

        let response_qkd_key = ResponseQkdKey {
            key_ID: key_uuid,
            key: general_purpose::STANDARD.encode(&key)
        };

        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys: vec![response_qkd_key],
        }))
    }

    fn get_sae_keys_with_ids(&self, current_sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], origin_sae_id: i64, keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT key_uuid, key FROM keys WHERE target_sae_id = ? AND origin_sae_id = ? AND key_uuid = ? LIMIT 1;";
        let current_sae_id = self.get_sae_id_from_certificate(current_sae_certificate).ok_or(QkdManagerResponse::AuthenticationError)?;

        let keys = keys_uuids.iter().map(|key_uuid| {
            let mut stmt = ensure_prepared_statement_ok!(self.sqlite_db, PREPARED_STATEMENT);
            stmt.bind((1, current_sae_id)).map_err(|_| {
                error!("Error binding current SAE ID");
                QkdManagerResponse::Ko
            })?;
            stmt.bind((2, origin_sae_id)).map_err(|_| {
                error!("Error binding origin SAE ID");
                QkdManagerResponse::Ko
            })?;
            stmt.bind((3, key_uuid.as_str())).map_err(|_| {
                error!("Error binding key UUID");
                QkdManagerResponse::Ko
            })?;

            let sql_execution_state = stmt.next().map_err(|_| {
                error!("Error executing SQL statement");
                QkdManagerResponse::Ko
            })?;

            if sql_execution_state != sqlite::State::Row {
                return Err(QkdManagerResponse::NotFound);
            }
            let key_uuid: String = stmt.read::<String, usize>(0).map_err(|_| {
                error!("Error reading SQL statement result");
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = stmt.read::<Vec<u8>, usize>(1).map_err(|_| {
                error!("Error reading SQL statement result");
                QkdManagerResponse::Ko
            })?;
            Ok(ResponseQkdKey {
                key_ID: key_uuid,
                key: general_purpose::STANDARD.encode(&key),
            })
        }).collect::<Result<Vec<ResponseQkdKey>, QkdManagerResponse>>()?;

        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys,
        }))
    }

    fn get_sae_id_from_certificate(&self, sae_certificate: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Option<i64> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id FROM saes WHERE sae_certificate_serial = ? LIMIT 1;";
        let mut stmt = match self.sqlite_db.prepare(PREPARED_STATEMENT) {
            Ok(stmt) => stmt,
            Err(_) => {
                error!("Error preparing SQL statement");
                return None;
            }
        };
        stmt.bind((1, sae_certificate.as_bytes())).map_err(|_| {
            error!("Error binding SAE certificate serial");
            ()
        }).ok();
        let sql_execution_state = stmt.next().map_err(|_| {
            error!("Error executing SQL statement");
            ()
        }).ok()?;
        if sql_execution_state != sqlite::State::Row {
            info!("SAE certificate not found in database");
            return None;
        }
        let sae_id: i64 = stmt.read::<i64, usize>(0).map_err(|_| {
            error!("Error reading SQL statement result");
            ()
        }).ok()?;
        Some(sae_id)
    }
}

#[macro_export]
macro_rules! ensure_prepared_statement_ok {
    ($sqlite_connection:expr, $statement:expr) => {
        match $sqlite_connection.prepare($statement) {
            Ok(stmt) => stmt,
            Err(_) => {
                error!("Error preparing SQL statement");
                return Err(QkdManagerResponse::Ko);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_get_sae_id_from_certificate() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx).unwrap();
        let sae_id = 1;
        let sae_certificate_serial = [0u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, &sae_certificate_serial).unwrap();
        assert_eq!(key_handler.get_sae_id_from_certificate(&sae_certificate_serial).unwrap(), sae_id);

        let fake_sae_certificate_serial = [1u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES];
        assert_eq!(key_handler.get_sae_id_from_certificate(&fake_sae_certificate_serial), None);
    }
}