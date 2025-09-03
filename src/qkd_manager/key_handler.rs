//! QKD manager key handler, supposed to run in a separate thread

use crate::{ensure_prepared_statement_ok, MEMORY_SQLITE_DB_PATH};
use crate::event_subscription::ImportantEventSubscriber;
use crate::export_important_logging_message;
use crate::prepare_sql_arguments;
use crate::qkd_manager::http_response_obj::{ResponseQkdKey, ResponseQkdKeysList};
use crate::qkd_manager::{http_request_obj, router, KMEInfo, PreInitQkdKeyWrapper, QkdManagerCommand, QkdManagerResponse, SAEInfo};
use crate::{io_err, qkd_manager, KmeId, RequestedKeyCount, SaeClientCertSerial, SaeId};
use base64::{engine::general_purpose, Engine as _};
use futures::future::join_all;
use futures::{TryFutureExt, TryStreamExt};
use log::{error, info, warn};
use sqlx::{Arguments, Execute, Executor, QueryBuilder, Row, Statement};
use std::convert::identity;
use std::sync::Arc;
use std::{io, vec};
use std::cmp::PartialEq;
use sqlx::any::{AnyArguments, AnyPoolOptions};
use uuid::Bytes;
use x509_parser::nom::AsBytes;

/// Supported database management systems
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum DbmsType {
    Sqlite,
    Postgres,
    MySQL,
}

impl std::fmt::Display for DbmsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbmsType::Sqlite => write!(f, "SQLite"),
            DbmsType::Postgres => write!(f, "PostgreSQL"),
            DbmsType::MySQL => write!(f, "MySQL"),
        }
    }
}

/// Describes the key handler that will check authentication and manage the QKD keys in the database in a separate thread
pub(super) struct KeyHandler {
    /// Channel to receive commands from the QKD manager (main thread)
    command_rx: crossbeam_channel::Receiver<QkdManagerCommand>,
    /// Channel to send responses to the QKD manager (main thread)
    response_tx: crossbeam_channel::Sender<QkdManagerResponse>,
    /// Connection to the sqlite database (in memory or on disk)
    db: sqlx::AnyPool,
    /// The type of database management system used
    dbms_type: DbmsType,
    /// The ID of this KME
    this_kme_id: KmeId,
    /// Router on classical network, used to connect to other KMEs over unsecure classical network
    qkd_router: router::QkdRouter,
    /// Subscribers to important events, for demonstration purpose
    event_notification_subscribers: Vec<Arc<dyn ImportantEventSubscriber>>,
    /// Optional nickname for this KME, used for debugging purposes (eg "Alice" or "Bob")
    nickname: Option<String>,
}

impl KeyHandler {

    /// Create a new key handler
    /// # Arguments
    /// * `db_uri` - Database URI (eg `sqlite://:memory:` or `sqlite://path/to/db.sqlite3`)
    /// * `command_rx` - The channel to receive commands from the QKD manager (main thread)
    /// * `response_tx` - The channel to send responses to the QKD manager (main thread)
    /// * `this_kme_id` - The ID of this KME
    /// * `kme_nickname` - The nickname of this KME, for debugging purposes
    /// # Returns
    /// A new key handler
    /// # Errors
    /// If the sqlite database cannot be opened or if the tables cannot be created
    pub(super) async fn new(db_uri: &str, command_rx: crossbeam_channel::Receiver<QkdManagerCommand>, response_tx: crossbeam_channel::Sender<QkdManagerResponse>, this_kme_id: KmeId, kme_nickname: Option<String>) -> Result<Self, io::Error> {
        const SQLITE_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_sqlite.sql");
        const POSTGRES_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_postgres.sql");
        const MYSQL_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_mysql.sql");
        const IN_MEMORY_SQLITE_URI: &'static str = "sqlite::memory:";

        let dbms_type = Self::get_dbms_type_from_uri(db_uri)?;

        info!("Detected database type: {}", dbms_type);

        let database_initialization_req = match dbms_type {
            DbmsType::Sqlite => SQLITE_DATABASE_INIT_REQ,
            DbmsType::Postgres => POSTGRES_DATABASE_INIT_REQ,
            DbmsType::MySQL => MYSQL_DATABASE_INIT_REQ,
        };

        sqlx::any::install_default_drivers();

        let in_memory_database = db_uri == MEMORY_SQLITE_DB_PATH;

        let dbpool = AnyPoolOptions::new();
        let dbpool = if in_memory_database {
            dbpool
                .max_connections(1) // In memory database works only with a single connection
                .idle_timeout(None)
                .max_lifetime(None)
                .connect(IN_MEMORY_SQLITE_URI)
                .await
        } else {
            dbpool.connect_lazy(db_uri) // Save costs on Cloud bill
        }.map_err(|e| {
                io::Error::new(io::ErrorKind::NotConnected, format!("Error opening database: {:?}", e))
            })?;

        let key_handler = Self {
            command_rx,
            response_tx,
            db: dbpool,
            dbms_type,
            this_kme_id,
            qkd_router: router::QkdRouter::new(),
            event_notification_subscribers: vec![],
            nickname: kme_nickname,
        };
        // Create the tables if they do not exist
        key_handler.db.execute(database_initialization_req).await.map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Error creating database tables: {:?}", e))
        })?;
        Ok(key_handler)
    }

    fn get_dbms_type_from_uri(db_uri: &str) -> Result<DbmsType, io::Error> {
        if db_uri == MEMORY_SQLITE_DB_PATH {
            return Ok(DbmsType::Sqlite);
        };
        let parsed_uri = uriparse::URI::try_from(db_uri).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid database URI: {}", db_uri))
        })?;
        match parsed_uri.scheme().as_str() {
            "sqlite" => Ok(DbmsType::Sqlite),
            "postgres" | "postgresql" => Ok(DbmsType::Postgres),
            "mysql" => Ok(DbmsType::MySQL),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid database URI: {}", db_uri)))
        }
    }

    /// Run the key handler, in a separate thread (infinite loop)
    /// # Note
    /// The calling SAE is authenticated by its certificate serial number, and designates the counterpart SAE by its SAE ID
    pub(super) async fn run(&mut self) -> ! {
        // Infinite loop to receive commands and send responses
        loop {
            // Receive a command
            match self.command_rx.recv() {
                Ok(cmd) => {
                    match cmd {
                        // Insert a key into the database, each time a QKD exchange occurs
                        QkdManagerCommand::AddPreInitKey(key) => {
                            info!("Adding key for KME ID {} and {}", self.this_kme_id, key.other_kme_id);
                            if self.response_tx.send(self.add_preinit_qkd_key(key).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        // Insert multiple keys into the database, each time a QKD exchange occurs
                        QkdManagerCommand::AddMultiplePreInitKeys(keys) => {
                            for key in &keys {
                                info!("Adding key for KME ID {} and {}", self.this_kme_id, key.other_kme_id);
                            }
                            if self.response_tx.send(self.add_multiple_preinit_qkd_keys(keys).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        }
                        // The master SAE asks for keys ready to be sent to the slave SAE
                        QkdManagerCommand::GetKeys(sae_certificate_serial, slave_sae_id, keys_count) => {
                            info!("Getting key for SAE ID {}", slave_sae_id);
                            if self.response_tx.send(self.get_sae_keys(&sae_certificate_serial, slave_sae_id, keys_count).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        }
                        // The slave SAE gets keys generated by the master SAE by their IDs
                        QkdManagerCommand::GetKeysWithIds(sae_certificate_serial, master_sae_id, keys_uuids) => {
                            info!("Getting keys from SAE ID {}", master_sae_id);
                            if self.response_tx.send(self.get_sae_keys_with_ids(&sae_certificate_serial, master_sae_id, keys_uuids).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        // Add a new SAE ID to the database
                        QkdManagerCommand::AddSae(sae_id, kme_id, sae_certificate_serial) => {
                            info!("Adding SAE ID {}", sae_id);
                            if self.response_tx.send(self.add_sae(sae_id, kme_id, &sae_certificate_serial).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        // Get keys status between origin SAE and target SAE
                        QkdManagerCommand::GetStatus(origin_sae_certificate, target_sae_id) => {
                            info!("Getting status for SAE ID {}", target_sae_id);
                            if self.response_tx.send(self.get_sae_status(&origin_sae_certificate, target_sae_id).await.unwrap_or_else(identity)).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::GetSaeInfoFromCertificate(sae_certificate) => {
                            info!("Getting SAE info from certificate");
                            let sae_info_response = self.get_sae_infos_from_certificate(&sae_certificate).await.unwrap_or_else(identity);
                            if self.response_tx.send(sae_info_response).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::GetKmeIdFromSaeId(sae_id) => {
                            let kme_id = self.get_kme_id_from_sae_id(sae_id).await;
                            let response = match kme_id {
                                Some(kme_id) => QkdManagerResponse::KmeInfo(KMEInfo {
                                    kme_id,
                                }),
                                None => {
                                    warn!("Get KME ID from SAE ID: SAE ID not found in database");
                                    QkdManagerResponse::NotFound
                                },
                            };
                            if self.response_tx.send(response).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        },
                        QkdManagerCommand::ActivateKeyFromRemote(origin_sae_id, target_sae_id, target_key_uuids_list) => {
                            let key_activate_response = self.activate_key_uuids_sae(origin_sae_id, target_sae_id, target_key_uuids_list).await.unwrap_or_else(identity);
                            if self.response_tx.send(key_activate_response).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        }
                        QkdManagerCommand::AddKmeClassicalNetInfo(kme_id, kme_addr_or_domain, conn_client_cert, conn_cert_password, should_ignore_sysetem_proxy_settings) => {
                            let add_kme_response = match self.qkd_router.add_kme_to_ip_domain_port_association(kme_id,
                                                                                                               &kme_addr_or_domain,
                                                                                                               &conn_client_cert, &conn_cert_password,
                                                                                                               should_ignore_sysetem_proxy_settings) {
                                Ok(_) => QkdManagerResponse::Ok,
                                Err(e) => {
                                    error!("Error adding KME classical network info: {:?}", e);
                                    QkdManagerResponse::Ko
                                },
                            };
                            if self.response_tx.send(add_kme_response).is_err() {
                                error!("Error QKD manager sending response");
                            }
                        }
                        QkdManagerCommand::AddImportantEventSubscriber(subscriber) => {
                            self.event_notification_subscribers.push(subscriber);
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving command: {:?}", e);
                }
            }
        }
    }

    /// Add a new SAE ID to the database
    /// # Arguments
    /// * `sae_id` - The SAE ID to add
    /// * `kme_id` - The KME ID to associate with the SAE ID
    /// * `sae_certificate_serial` - The SAE certificate serial number, None if the SAE isn't supposed to authenticate to this KME
    async fn add_sae(&self, sae_id: SaeId, kme_id: KmeId, sae_certificate_serial: &Option<SaeClientCertSerial>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_INSERT_STATEMENT_KNOWN_CERT: &'static str = "INSERT INTO saes (sae_id, kme_id, sae_certificate_serial) VALUES ($1, $2, $3);";
        const PREPARED_INSERT_STATEMENT_KNOWN_CERT_MYSQL: &'static str = "INSERT INTO saes (sae_id, kme_id, sae_certificate_serial) VALUES (?, ?, ?);";
        const PREPARED_INSERT_STATEMENT_NO_CERT: &'static str = "INSERT INTO saes (sae_id, kme_id) VALUES ($1, $2);";
        const PREPARED_INSERT_STATEMENT_NO_CERT_MYSQL: &'static str = "INSERT INTO saes (sae_id, kme_id) VALUES (?, ?);";
        const PREPARED_UPDATE_STATEMENT_KNOWN_CERT: &'static str = "UPDATE saes SET kme_id = $1, sae_certificate_serial = $2 WHERE sae_id = $3;";
        const PREPARED_UPDATE_STATEMENT_KNOWN_CERT_MYSQL: &'static str = "UPDATE saes SET kme_id = ?, sae_certificate_serial = ? WHERE sae_id = ?;";
        const PREPARED_UPDATE_STATEMENT_NO_CERT: &'static str = "UPDATE saes SET kme_id = $1, sae_certificate_serial = NULL WHERE sae_id = $2;";
        const PREPARED_UPDATE_STATEMENT_NO_CERT_MYSQL: &'static str = "UPDATE saes SET kme_id = ?, sae_certificate_serial = NULL WHERE sae_id = ?;";

        let has_provided_certificate = sae_certificate_serial.is_some();
        let is_this_kme = kme_id == self.this_kme_id;
        // Has given certificate and doesn't belong to this KME, or doesn't have a certificate and belongs to this KME
        if has_provided_certificate != is_this_kme {
            return Err(QkdManagerResponse::InconsistentSaeData);
        }

        let (insert_statement, update_statement) = match self.dbms_type {
            DbmsType::MySQL => {
                match sae_certificate_serial {
                    Some(_) => (PREPARED_INSERT_STATEMENT_KNOWN_CERT_MYSQL, PREPARED_UPDATE_STATEMENT_KNOWN_CERT_MYSQL),
                    None => (PREPARED_INSERT_STATEMENT_NO_CERT_MYSQL, PREPARED_UPDATE_STATEMENT_NO_CERT_MYSQL),
                }
            },
            DbmsType::Postgres | DbmsType::Sqlite => {
                match sae_certificate_serial {
                    Some(_) => (PREPARED_INSERT_STATEMENT_KNOWN_CERT, PREPARED_UPDATE_STATEMENT_KNOWN_CERT),
                    None => (PREPARED_INSERT_STATEMENT_NO_CERT, PREPARED_UPDATE_STATEMENT_NO_CERT),
                }
            }
        };

        let mut query_args_update = prepare_sql_arguments!(kme_id)?;

        if sae_certificate_serial.is_some() {
            query_args_update.add(sae_certificate_serial.as_ref().unwrap().as_bytes()).map_err(|e| {
                error!("Error binding parameter to SQL statement: {}", e);
                QkdManagerResponse::Ko
            })?;
        }
        query_args_update.add(sae_id).map_err(|e| {
            error!("Error binding parameter to SQL statement: {}", e);
            QkdManagerResponse::Ko
        })?;

        let update_stmt = ensure_prepared_statement_ok!(self.db, update_statement)?;
        let update_query_affected_rows = update_stmt.query_with(query_args_update).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?.rows_affected();

        if update_query_affected_rows > 1 {
            error!("Error: more than one row affected when updating SAE ID {}", sae_id);
            return Err(QkdManagerResponse::Ko);
        } else if update_query_affected_rows == 1 {
            // Successfully updated existing SAE ID
            return Ok(QkdManagerResponse::Ok);
        }

        let mut query_args_insert = prepare_sql_arguments!(sae_id, kme_id)?;

        if sae_certificate_serial.is_some() {
            query_args_insert.add(sae_certificate_serial.as_ref().unwrap().as_bytes()).map_err(|_| {
                error!("Error binding parameter to SQL statement");
                QkdManagerResponse::Ko
            })?;
        }

        let insert_stmt = ensure_prepared_statement_ok!(self.db, insert_statement)?;
        insert_stmt.query_with(query_args_insert).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    async fn add_preinit_qkd_key(&self, pre_init_key: PreInitQkdKeyWrapper) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) VALUES ($1, $2, $3);";
        const PREPARED_STATEMENT_MYSQL: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) VALUES (?, ?, ?);";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let uuid_bytes = Bytes::try_from(pre_init_key.key_uuid).map_err(|_| {
            error!("Error converting UUID to bytes");
            QkdManagerResponse::Ko
        })?;
        let uuid_str = uuid::Uuid::from_bytes(uuid_bytes).to_string();
        let query_args = prepare_sql_arguments!(uuid_str.as_str(), pre_init_key.key.as_bytes(), pre_init_key.other_kme_id)?;
        stmt.query_with(query_args).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    async fn add_multiple_preinit_qkd_keys(&self, pre_init_keys: Vec<PreInitQkdKeyWrapper>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) "; // QueryBuilder will add the VALUES part

        let mut qb = QueryBuilder::new(PREPARED_STATEMENT);

        let pre_init_keys_transformed = pre_init_keys.iter().map(|pre_init_key| {
            let uuid_bytes = Bytes::try_from(pre_init_key.key_uuid).map_err(|_| {
                error!("Error converting UUID to bytes");
                QkdManagerResponse::Ko
            })?;
            let uuid_str = uuid::Uuid::from_bytes(uuid_bytes).to_string();
            Ok((uuid_str, pre_init_key.key.as_bytes(), pre_init_key.other_kme_id))
        }).collect::<Result<Vec<_>, QkdManagerResponse>>()?;

        qb.push_values(pre_init_keys_transformed.clone(), |mut b, (uuid_str, key_bytes, other_kme_id)| {
            b.push_bind(uuid_str)
                .push_bind(key_bytes)
                .push_bind(other_kme_id);
        });
        let mut query = qb.build();
        let query_sql = query.sql();
        let mut sql_modified_for_postgres = String::with_capacity(query_sql.len());

        if self.dbms_type == DbmsType::Postgres {
            let mut param_idx = 1;

            for ch in query_sql.chars() {
                if ch == '?' {
                    sql_modified_for_postgres.push_str(&format!("${}", param_idx));
                    param_idx += 1;
                } else {
                    sql_modified_for_postgres.push(ch);
                }
            }
            query = sqlx::query(&sql_modified_for_postgres);
            for (uuid_str, key_bytes, other_kme_id) in pre_init_keys_transformed {
                query = query.bind(uuid_str)
                    .bind(key_bytes)
                    .bind(other_kme_id);
            }
        }



        query.execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        Ok(QkdManagerResponse::Ok)
    }

    async fn get_sae_status(&self, origin_sae_certificate: &SaeClientCertSerial, target_sae_id: SaeId) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT COUNT(*) FROM uninit_keys WHERE other_kme_id = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT COUNT(*) FROM uninit_keys WHERE other_kme_id = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let target_kme_id = self.get_kme_id_from_sae_id(target_sae_id).await.ok_or(QkdManagerResponse::NotFound)?;

        // Ensure the origin (master) SAE ID is valid, and get its SAE id
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let query_args = prepare_sql_arguments!(target_kme_id)?;
        let key_count: i64 = stmt.query_scalar_with(query_args).fetch_one(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        let source_kme_id = self.this_kme_id; // This KME
        let stored_key_count = std::cmp::min(key_count as usize, crate::MAX_QKD_KEYS_PER_SAE);

        // Create key exchange status response object
        let response_qkd_key_status = qkd_manager::http_response_obj::ResponseQkdKeysStatus {
            source_KME_ID: source_kme_id.to_string(),
            target_KME_ID: target_kme_id.to_string(),
            master_SAE_ID: origin_sae_id.to_string(),
            slave_SAE_ID: target_sae_id.to_string(),
            key_size: crate::QKD_KEY_SIZE_BITS,
            stored_key_count,
            max_key_count: crate::MAX_QKD_KEYS_PER_SAE,
            max_key_per_request: crate::MAX_QKD_KEYS_PER_REQUEST,
            max_key_size: crate::QKD_MAX_KEY_SIZE_BITS,
            min_key_size: crate::QKD_MIN_KEY_SIZE_BITS,
            max_SAE_ID_count: crate::MAX_QKD_KEY_SAE_IDS,
        };

        Ok(QkdManagerResponse::Status(response_qkd_key_status))
    }

    async fn get_sae_keys(&self, origin_sae_certificate: &SaeClientCertSerial, target_sae_id: SaeId, key_count: RequestedKeyCount) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const FETCH_PREINIT_KEY_PREPARED_STATEMENT: &'static str = "SELECT id, key_uuid, qkd_key, other_kme_id FROM uninit_keys WHERE other_kme_id = $1 LIMIT $2;";
        const FETCH_PREINIT_KEY_PREPARED_STATEMENT_MYSQL: &'static str = "SELECT id, key_uuid, qkd_key, other_kme_id FROM uninit_keys WHERE other_kme_id = ? LIMIT ?;";

        let fetch_preinit_key_prepared_statement = match self.dbms_type {
            DbmsType::MySQL => FETCH_PREINIT_KEY_PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => FETCH_PREINIT_KEY_PREPARED_STATEMENT,
        };

        let key_count = key_count.get();
        if key_count == 0 {
            return Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
                keys: vec![],
            }))
        }

        // Ensure the origin (master) SAE ID is valid, and get its SAE id
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;
        let origin_kme_id = self.this_kme_id;
        let target_kme_id = self.get_kme_id_from_sae_id(target_sae_id).await.ok_or(QkdManagerResponse::NotFound)?;

        export_important_logging_message!(&self, &format!("SAE {} requested a key to communicate with {}", origin_sae_id, target_sae_id));

        let stmt = ensure_prepared_statement_ok!(self.db, fetch_preinit_key_prepared_statement)?;
        let query_args = prepare_sql_arguments!(target_kme_id, key_count as i64)?;

        let mut fetched_preinit_keys: Vec<(i64, String, Vec<u8>)> = Vec::with_capacity(key_count);

        let mut sql_execution_rows = stmt.query_with(query_args).fetch(&self.db);

        while let Some(row) = sql_execution_rows.try_next().await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })? {
            let id: i64 = row.try_get("id").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key_uuid: String = row.try_get("key_uuid").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = row.try_get("qkd_key").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            fetched_preinit_keys.push((id, key_uuid, key));
        }

        if fetched_preinit_keys.len() == 0 && key_count != 0 {
            warn!("No key available for SAE {} to communicate with SAE {}", origin_sae_id, target_sae_id);
            return Err(QkdManagerResponse::NotFound);
        }

        if fetched_preinit_keys.len() < key_count {
            warn!("Only {} keys available for SAE {} to communicate with SAE {}, while {} were requested", fetched_preinit_keys.len(), origin_sae_id, target_sae_id, key_count);
        }

        if origin_kme_id != target_kme_id {
            // send key to other KME
            // We must ensure:
            // - other KME is authenticated (client certificate and operating system trust store)
            // - other SAE belongs to other KME (statically managed for now)
            let uuids_list = fetched_preinit_keys.iter().map(|(_, key_uuid, _)| key_uuid.clone()).collect::<Vec<_>>();

            self.activate_keys_on_other_kme(origin_sae_id, target_kme_id, target_sae_id, uuids_list).map_err(|qkd_manager_activation_error| {
                error!("Error activating key on other KME");
                qkd_manager_activation_error
            }).await?;
            export_important_logging_message!(&self, &format!("As SAE {} belongs to KME {}, activating it through inter KMEs network", target_sae_id, target_kme_id));
        }

        for (key_id, key_uuid, key) in &fetched_preinit_keys {
            self.delete_pre_init_key_with_id(*key_id).await.map_err(|e| {
                error!("Error deleting pre-init key {}: {:?}", key_id, e);
                QkdManagerResponse::Ko
            })?;

            info!("Saving key {} in init keys", key_uuid);

            self.insert_activated_key(&key_uuid, &key, origin_sae_id, target_sae_id).map_err(|e| {
                error!("Error inserting activated key: {:?}", e);
                QkdManagerResponse::Ko
            }).await?;
        }

        let keys_response = fetched_preinit_keys.iter().map(|(_, key_uuid, key)| {
            // Encode the key in base64
            ResponseQkdKey {
                key_ID: key_uuid.clone(),
                key: general_purpose::STANDARD.encode(&key)
            }
        }).collect::<Vec<_>>();

        // Return a list of key objects
        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys: keys_response,
        }))
    }

    async fn activate_key_uuids_sae(&self, origin_sae_id: SaeId, target_sae_id: SaeId, key_uuids_list: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const GET_PRE_INIT_KEY_PREPARED_STATEMENT: &'static str = "SELECT id, qkd_key, other_kme_id FROM uninit_keys WHERE key_uuid = $1 LIMIT 1;";
        const GET_PRE_INIT_KEY_PREPARED_STATEMENT_MYSQL: &'static str = "SELECT id, qkd_key, other_kme_id FROM uninit_keys WHERE key_uuid = ? LIMIT 1;";

        let get_pre_init_key_prepared_statement = match self.dbms_type {
            DbmsType::MySQL => GET_PRE_INIT_KEY_PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => GET_PRE_INIT_KEY_PREPARED_STATEMENT,
        };

        let retrieved_preinit_key_tuples_futures = key_uuids_list.iter().map(async |key_uuid| {
            let stmt = ensure_prepared_statement_ok!(self.db, get_pre_init_key_prepared_statement)?;
            let query_args = prepare_sql_arguments!(key_uuid.as_str())?;

            let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            let sql_execution_row = match sql_execution_row {
                Some(row) => row,
                None => {
                    return Err(QkdManagerResponse::NotFound);
                }
            };

            let key_id: i64 = sql_execution_row.try_get("id").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = sql_execution_row.try_get("qkd_key").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            Ok((key_uuid.clone(), key_id, key))
        });

        let retrieved_preinit_key_tuples: Vec<(String, i64, Vec<u8>)> = join_all(retrieved_preinit_key_tuples_futures).await.into_iter().collect::<Result<Vec<_>, _>>()?;

        for (key_uuid, key_id, key) in retrieved_preinit_key_tuples {
            self.insert_activated_key(&key_uuid, &key, origin_sae_id, target_sae_id).map_err(|e| {
                error!("Error inserting activated key: {:?}", e);
                QkdManagerResponse::Ko
            }).await?;
            self.delete_pre_init_key_with_id(key_id).await.map_err(|e| {
                error!("Error deleting pre-init key {}: {:?}", key_id, e);
                QkdManagerResponse::Ko
            })?;

            info!("Key {} activated between saes {} and {}", key_uuid, origin_sae_id, target_sae_id);
        }

        Ok(QkdManagerResponse::Ok)
    }

    async fn activate_keys_on_other_kme(&self, caller_master_sae_id: SaeId, other_kme_id: KmeId, other_sae_id: SaeId, key_uuids: Vec<String>) -> Result<(), QkdManagerResponse> {
        let danger_should_ignore_remote_kme_cert = match std::env::var(crate::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE) {
            Ok(val) => val == crate::ACTIVATED_ENV_VARIABLE_VALUE,
            Err(_) => false,
        };

        let req_body = http_request_obj::ActivateKeyRemoteKME {
            key_IDs_list: key_uuids,
            origin_SAE_ID: caller_master_sae_id,
            remote_SAE_ID: other_sae_id,
        };
        let kme_classical_info = match self.qkd_router.get_classical_connection_info_from_kme_id(other_kme_id) {
            Some(info) => info,
            None => {
                error!("KME ID not found");
                return Err(QkdManagerResponse::MissingRemoteKmeConfiguration);
            },
        };

        let kme_client_builder = reqwest::Client::builder().identity(kme_classical_info.tls_client_cert_identity.clone());

        let kme_client_builder = if danger_should_ignore_remote_kme_cert {
            warn!("Because of {}, remote KME server certificate check is disabled. This is a dangerous setting, it breaks the whole protocol security", crate::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE);
            kme_client_builder.danger_accept_invalid_certs(true)
        } else {
            info!("Remote KME server certificate check is enabled. This is the default setting");
            kme_client_builder
        };
        let kme_client_builder = if kme_classical_info.should_ignore_system_proxy_settings {
            info!("Ignoring system proxy settings for remote KME route");
            kme_client_builder.no_proxy()
        } else {
            info!("Using system proxy settings for remote KME route");
            kme_client_builder
        };
        let kme_client = kme_client_builder.build()
            .map_err(|_| {
                error!("Error building reqwest client");
                QkdManagerResponse::Ko
            })?;

        let response = kme_client.post(&format!("https://{}/keys/activate", kme_classical_info.ip_domain_port))
            .json(&req_body)
            .send().await
            .map_err(|http_error| {
                error!("Error sending HTTP request: {}", http_error);
                QkdManagerResponse::RemoteKmeCommunicationError
            })?;

        if response.status() != reqwest::StatusCode::OK {
            error!("Error activating key on other KME");
            return Err(QkdManagerResponse::RemoteKmeAcceptError);
        }

        Ok(())
    }

    async fn insert_activated_key(&self, key_uuid: &str, key: &[u8], origin_sae_id: SaeId, target_sae_id: SaeId)-> Result<QkdManagerResponse, QkdManagerResponse> {
        const INSERT_INIT_KEY_PREPARED_STATEMENT: &'static str = "INSERT INTO activated_keys (key_uuid, qkd_key, origin_sae_id, target_sae_id) VALUES ($1, $2, $3, $4);";
        const INSERT_INIT_KEY_PREPARED_STATEMENT_MYSQL: &'static str = "INSERT INTO activated_keys (key_uuid, qkd_key, origin_sae_id, target_sae_id) VALUES (?, ?, ?, ?);";

        let insert_init_key_prepared_statement = match self.dbms_type {
            DbmsType::MySQL => INSERT_INIT_KEY_PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => INSERT_INIT_KEY_PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, insert_init_key_prepared_statement)?;
        let query_args = prepare_sql_arguments!(key_uuid, key, origin_sae_id, target_sae_id)?;
        stmt.query_with(query_args).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        export_important_logging_message!(&self, &format!("Key {} activated between SAEs {} and {}", key_uuid, origin_sae_id, target_sae_id));
        Ok(QkdManagerResponse::Ok)
    }

    /// Delete a pre-init key from the pre-init keys database
    /// Called when master SAE requested the key: it becomes an init key
    /// So that the same key isn't requested again by a master SAE
    /// # Arguments
    /// * `key_id` - The ID of the pre init key to delete
    /// # Returns
    /// Ok if the key was deleted, an error otherwise
    async fn delete_pre_init_key_with_id(&self, key_id: i64) -> Result<(), io::Error> {
        const PREPARED_STATEMENT: &'static str = "DELETE FROM uninit_keys WHERE id = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "DELETE FROM uninit_keys WHERE id = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement).map_err(|e| {
            io_err(format!("Error preparing SQL statement: {:?}", e).as_str())
        })?;
        let query_args = prepare_sql_arguments!(key_id).map_err(|e| {
            io_err(format!("Error binding key ID: {:?}", e).as_str())
        })?;
        stmt.query_with(query_args).execute(&self.db).await.map_err(|e| {
            io_err(format!("Error executing SQL statement, maybe key ID not found in pre init keys database?: {:?}", e).as_str())
        })?;
        Ok(())
    }

    async fn get_sae_keys_with_ids(&self, current_sae_certificate: &SaeClientCertSerial, origin_sae_id: SaeId, keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT key_uuid, qkd_key FROM activated_keys WHERE target_sae_id = $1 AND origin_sae_id = $2 AND key_uuid = $3 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT key_uuid, qkd_key FROM activated_keys WHERE target_sae_id = ? AND origin_sae_id = ? AND key_uuid = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        // Ensure the caller (slave) SAE ID is valid and authenticated, and get its SAE id
        let current_sae_id = self.get_sae_id_from_certificate(current_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;

        // For each key UUID, retrieve the key from the database if it exists and is applicable to the caller SAE ID
        let keys_futures = keys_uuids.iter().map(async |key_uuid| {
            let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
            let query_args = prepare_sql_arguments!(current_sae_id, origin_sae_id, key_uuid.as_str())?;

            let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            // Only 1 key should be returned by UUID
            let sql_execution_row = match sql_execution_row {
                Some(row) => row,
                None => {
                    return Err(QkdManagerResponse::NotFound);
                }
            };

            let key_uuid: String = sql_execution_row.try_get("key_uuid").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = sql_execution_row.try_get("qkd_key").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;

            export_important_logging_message!(&self, &format!("SAE {} requested key {} (from {})", current_sae_id, key_uuid, origin_sae_id));

            // Encode the key in base64
            Ok(ResponseQkdKey {
                key_ID: key_uuid,
                key: general_purpose::STANDARD.encode(&key),
            })
        });

        let keys = join_all(keys_futures).await.into_iter().collect::<Result<Vec<_>, _>>()?;

        // Return a list of key objects
        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys,
        }))
    }

    /// Get the SAE ID from associated client certificate serial number
    /// # Arguments
    /// * `sae_certificate` - The client certificate serial number
    /// # Returns
    /// The SAE ID if the certificate serial number is found in the database, None otherwise
    async fn get_sae_id_from_certificate(&self, sae_certificate: &SaeClientCertSerial) -> Option<SaeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id FROM saes WHERE sae_certificate_serial = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT sae_id FROM saes WHERE sae_certificate_serial = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement).ok()?;
        let query_args = prepare_sql_arguments!(sae_certificate.as_bytes()).ok()?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            ()
        }).ok()?;
        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                info!("SAE certificate not found in database");
                return None;
            }
        };
        let sae_id: SaeId = sql_execution_row.try_get("sae_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            ()
        }).ok()?;
        Some(sae_id)
    }

    /// Get the KME ID from associated SAE ID
    /// # Arguments
    /// * `sae_id` - The SAE ID
    /// # Returns
    /// The KME ID if the SAE ID is found in the database, None otherwise
    async fn get_kme_id_from_sae_id(&self, sae_id: SaeId) -> Option<KmeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT kme_id FROM saes WHERE sae_id = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT kme_id FROM saes WHERE sae_id = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement).ok()?;
        let query_args = prepare_sql_arguments!(sae_id).ok()?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            ()
        }).ok()?;
        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                info!("KME ID not found in database");
                return None;
            }
        };
        let kme_id: KmeId = sql_execution_row.try_get("kme_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            ()
        }).ok()?;
        Some(kme_id)
    }

    /// Directly fetch SAE info from the certificate serial number, including the SAE ID and KME ID
    /// # Arguments
    /// * `sae_certificate` - The client SAE certificate serial number
    /// # Returns
    /// The SAE info, including KME ID, if the certificate serial number is found in the database, an error otherwise
    async fn get_sae_infos_from_certificate(&self, sae_certificate: &SaeClientCertSerial) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id, kme_id FROM saes WHERE sae_certificate_serial = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT sae_id, kme_id FROM saes WHERE sae_certificate_serial = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let query_args = prepare_sql_arguments!(sae_certificate.as_bytes())?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                return Err(QkdManagerResponse::NotFound);
            }
        };

        let sae_id: i64 = sql_execution_row.try_get("sae_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            QkdManagerResponse::Ko
        })?;
        let kme_id: i64 = sql_execution_row.try_get("kme_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            QkdManagerResponse::Ko
        })?;

        Ok(QkdManagerResponse::SaeInfo(SAEInfo {
            sae_id,
            kme_id,
            sae_certificate_serial: sae_certificate.clone(),
        }))
    }
}

/// Check SQL statement preparation and return the statement
#[macro_export]
macro_rules! ensure_prepared_statement_ok {
    ($sql_connection:expr, $statement:expr) => {
        $sql_connection.prepare($statement).await.map_err(|e| {
            error!("Error preparing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })
    }
}

/// Prepare SQL arguments for a prepared statement
/// # Arguments
/// * `$arg` - The arguments to bind to the prepared statement, in the order they should be bound
/// # Returns
/// The prepared arguments, or an error if binding failed
#[macro_export]
macro_rules! prepare_sql_arguments {
    ($( $arg:expr ),* $(,)? ) => {
        {
            let mut query_args = AnyArguments::default();
            let mut result: Result<_, QkdManagerResponse> = Ok(());
            $(
                if result.is_ok(){
                    if let Err(e) = query_args.add($arg) {
                        error!("Error binding parameter to SQL statement: {}", e);
                        result = Err(QkdManagerResponse::Ko);
                    }
                }
            )*
            match result {
                Ok(_) => Ok(query_args),
                Err(e) => Err(e)
            }
        }
    };
}

/// Notify all subscribers of an event
/// # Arguments
/// * `key_handler_reference` - The reference to the key handler, like `&self`
/// * `message` - The message to notify, as string slice
#[macro_export]
macro_rules! export_important_logging_message {
    ($key_handler_reference:expr, $message:expr) => {
        let displayed_producer = match $key_handler_reference.nickname {
            Some(ref nickname) => nickname.to_owned(),
            None => std::string::String::from(&format!("KME {}", $key_handler_reference.this_kme_id)),
        };
        let message = &format!("[{}] {}", displayed_producer, $message);
        info!("{}", $message);
        for subscriber in $key_handler_reference.event_notification_subscribers.iter() {
            let _ = subscriber.notify(message); // We ignore the result here
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::event_subscription::ImportantEventSubscriber;
    use crate::qkd_manager::http_response_obj::HttpResponseBody;
    use crate::qkd_manager::QkdManagerResponse;
    use crate::RequestedKeyCount;
    use std::io::Error;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio::runtime::Runtime;

    const CLIENT_CERT_SERIAL_SIZE_BYTES: usize = 20;

    struct TestImportantEventSubscriber {
        events: Mutex<Vec<String>>,
    }
    impl TestImportantEventSubscriber {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }
    impl ImportantEventSubscriber for TestImportantEventSubscriber {
        fn notify(&self, message: &str) -> Result<(), Error> {
            self.events.lock().unwrap().push(message.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_add_sae() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        let recv = key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);

        let recv = key_handler.add_sae(2, 1, &None).await.unwrap_err();
        assert_eq!(recv, QkdManagerResponse::InconsistentSaeData); // Must provide a client certificate if belongs to this SAE

        let recv = key_handler.add_sae(2, 2, &Some(sae_certificate_serial.clone())).await.unwrap_err();
        assert_eq!(recv, QkdManagerResponse::InconsistentSaeData); // Must not provide a client certificate if doesn't belong to this SAE

        let recv = key_handler.add_sae(2, 2, &None).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);

        // Adding same SAE twice should not fail, it should just get ignored:
        let recv = key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);
        let recv = key_handler.add_sae(2, 2, &None).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);
    }

    #[tokio::test]
    async fn test_get_sae_id_from_certificate() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(key_handler.get_sae_id_from_certificate(&sae_certificate_serial).await.unwrap(), sae_id);

        let fake_sae_certificate_serial = vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        assert_eq!(key_handler.get_sae_id_from_certificate(&fake_sae_certificate_serial).await, None);
    }

    #[tokio::test]
    async fn test_add_preinit_key() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_multiple_preinit_qkd_keys() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let keys = vec![
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 1,
                key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
                key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 2,
                key_uuid: *uuid::Uuid::from_bytes([1u8; 16]).as_bytes(),
                key: [1u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 3,
                key_uuid: *uuid::Uuid::from_bytes([2u8; 16]).as_bytes(),
                key: [2u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
        ];
        key_handler.add_multiple_preinit_qkd_keys(keys).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_sae_status() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, sae_id).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap().replace("\r", ""), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"1\",\n  \"key_size\": 256,\n  \"stored_key_count\": 0,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");


        // add key for another KME id
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(2, 1, &Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap(), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"2\",\n  \"key_size\": 256,\n  \"stored_key_count\": 0,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap(), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"2\",\n  \"key_size\": 256,\n  \"stored_key_count\": 1,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");
    }

    #[tokio::test]
    async fn test_get_sae_keys() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, sae_id, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([1u8; 16]).as_bytes(),
            key: [1u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([2u8; 16]).as_bytes(),
            key: [2u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([3u8; 16]).as_bytes(),
            key: [3u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(2, kme_id, &Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);
        assert_eq!(response_keys.keys[0].key_ID, "00000000-0000-0000-0000-000000000000");
        assert_eq!(response_keys.keys[0].key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert_eq!(response_keys.to_json().unwrap(), "{\n  \"keys\": [\n    {\n      \"key_ID\": \"00000000-0000-0000-0000-000000000000\",\n      \"key\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n    }\n  ]\n}");


        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(2).unwrap()).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 2);
        assert_eq!(response_keys.keys[0].key_ID, "01010101-0101-0101-0101-010101010101");
        assert_eq!(response_keys.keys[0].key, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
        assert_eq!(response_keys.keys[1].key_ID, "02020202-0202-0202-0202-020202020202");
        assert_eq!(response_keys.keys[1].key, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        assert_eq!(response_keys.to_json().unwrap(), "{\n  \"keys\": [\n    {\n      \"key_ID\": \"01010101-0101-0101-0101-010101010101\",\n      \"key\": \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"\n    },\n    {\n      \"key_ID\": \"02020202-0202-0202-0202-020202020202\",\n      \"key\": \"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\"\n    }\n  ]\n}");

        // Not enough keys
        let qkd_manager_response = key_handler.get_sae_keys(
            &sae_certificate_serial,
            2,
            RequestedKeyCount::new(2).unwrap()
        ).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);
        // Not the same key
        assert_eq!(response_keys.keys[0].key_ID, "03030303-0303-0303-0303-030303030303");
        assert_eq!(response_keys.keys[0].key, "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=");
        assert_eq!(response_keys.to_json().unwrap(), "{\n  \"keys\": [\n    {\n      \"key_ID\": \"03030303-0303-0303-0303-030303030303\",\n      \"key\": \"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\"\n    }\n  ]\n}");
    }

    #[tokio::test]
    async fn test_get_sae_keys_with_ids() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_1_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        let sae_2_certificate_serial = vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_1_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, kme_id, &Some(sae_2_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_1_certificate_serial, sae_id, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // SAE1 has to pre fetch the key first
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        assert!(matches!(key_handler.get_sae_keys(&sae_1_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await.unwrap(), QkdManagerResponse::Keys(_)));
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await.unwrap();

        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);
        assert_eq!(response_keys.keys[0].key_ID, "00000000-0000-0000-0000-000000000000");
        assert_eq!(response_keys.keys[0].key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        // Revert origin and target SAE IDs
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_1_certificate_serial, 2, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_get_kme_id_from_sae() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_1_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_1_certificate_serial)).await.unwrap();
        let kme_id = key_handler.get_kme_id_from_sae_id(sae_id).await.unwrap();
        assert_eq!(kme_id, 1);
        let kme_id = key_handler.get_kme_id_from_sae_id(2).await;
        assert!(matches!(kme_id, None));
    }

    #[tokio::test]
    async fn test_get_sae_infos_from_certificate() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;

        let sae_info = key_handler.get_sae_infos_from_certificate(&vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES]).await;
        assert!(matches!(sae_info, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(sae_id, kme_id, &Some(vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let sae_info = key_handler.get_sae_infos_from_certificate(&vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES]).await.unwrap();
        assert!(matches!(sae_info, QkdManagerResponse::SaeInfo(_)));
        assert_eq!(sae_info, QkdManagerResponse::SaeInfo(super::SAEInfo {
            sae_id,
            kme_id,
            sae_certificate_serial: vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES],
        }));
    }

    #[tokio::test]
    async fn test_delete_pre_init_key_with_id() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let key_id = 1; // As it's the first key, we can assume it's the ID
        key_handler.delete_pre_init_key_with_id(key_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_important_event_subscriber_without_nickname() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let mut key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, None).await.unwrap();

        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let subscriber2 = Arc::new(TestImportantEventSubscriber::new());

        key_handler.event_notification_subscribers.push(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>);
        key_handler.event_notification_subscribers.push(Arc::clone(&subscriber2) as Arc<dyn ImportantEventSubscriber>);
        assert_eq!(key_handler.event_notification_subscribers.len(), 2);
        assert_eq!(subscriber.events.lock().unwrap().len(), 0);
        assert_eq!(subscriber2.events.lock().unwrap().len(), 0);

        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_preinit_qkd_key(crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        }).await.unwrap();
        key_handler.get_sae_keys(&sae_certificate_serial, 1, RequestedKeyCount::new(1).unwrap()).await.unwrap();

        assert_eq!(subscriber.events.lock().unwrap().len(), 2);
        assert_eq!(subscriber2.events.lock().unwrap().len(), 2);
        assert_eq!(subscriber.events.lock().unwrap()[0], "[KME 1] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber.events.lock().unwrap()[1], "[KME 1] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
        assert_eq!(subscriber2.events.lock().unwrap()[0], "[KME 1] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber2.events.lock().unwrap()[1], "[KME 1] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
    }

    #[tokio::test]
    async fn test_add_important_event_subscriber_with_nickname() {
        let (_, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, _) = crossbeam_channel::unbounded();
        let mut key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, Some("Alice".to_string())).await.unwrap();

        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let subscriber2 = Arc::new(TestImportantEventSubscriber::new());

        key_handler.event_notification_subscribers.push(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>);
        key_handler.event_notification_subscribers.push(Arc::clone(&subscriber2) as Arc<dyn ImportantEventSubscriber>);
        assert_eq!(key_handler.event_notification_subscribers.len(), 2);
        assert_eq!(subscriber.events.lock().unwrap().len(), 0);
        assert_eq!(subscriber2.events.lock().unwrap().len(), 0);

        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_preinit_qkd_key(crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        }).await.unwrap();
        key_handler.get_sae_keys(&sae_certificate_serial, 1, RequestedKeyCount::new(1).unwrap()).await.unwrap();

        assert_eq!(subscriber.events.lock().unwrap().len(), 2);
        assert_eq!(subscriber2.events.lock().unwrap().len(), 2);
        assert_eq!(subscriber.events.lock().unwrap()[0], "[Alice] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber.events.lock().unwrap()[1], "[Alice] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
        assert_eq!(subscriber2.events.lock().unwrap()[0], "[Alice] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber2.events.lock().unwrap()[1], "[Alice] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
    }

    #[tokio::test]
    async fn test_run() {
        #[cfg(not(target_os = "macos"))]
        const KME1_TO_KME2_CLIENT_AUTH_CERT_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pfx";
        #[cfg(target_os = "macos")]
        const KME1_TO_KME2_CLIENT_AUTH_CERT_PATH: &'static str = "certs/inter_kmes/client-kme1-to-kme2.pem";

        let (command_tx, command_channel_rx) = crossbeam_channel::unbounded();
        let (response_channel_tx, response_rx) = crossbeam_channel::unbounded();
        let mut key_handler = super::KeyHandler::new(":memory:", command_channel_rx, response_channel_tx, 1, Some("Alice".to_string())).await.unwrap();

        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        key_handler.event_notification_subscribers.push(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>);

        let sae_id = 1;
        let kme_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async move {
                key_handler.run().await;
            });
        });
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;

        command_tx.send(super::QkdManagerCommand::AddSae(sae_id, kme_id, Some(sae_certificate_serial.clone()))).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ok);

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        command_tx.send(super::QkdManagerCommand::AddPreInitKey(key)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ok);

        command_tx.send(super::QkdManagerCommand::GetKeysWithIds(sae_certificate_serial.clone(), 1, vec!["00000000-0000-0000-0000-000000000000".to_string()])).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        assert_eq!(subscriber.events.lock().unwrap().len(), 1);
        assert_eq!(subscriber.events.lock().unwrap()[0], "[Alice] SAE 1 requested a key to communicate with 1");

        command_tx.send(super::QkdManagerCommand::GetStatus(sae_certificate_serial.clone(), 2)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        command_tx.send(super::QkdManagerCommand::AddSae(2, kme_id, Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES]))).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ok);

        command_tx.send(super::QkdManagerCommand::GetStatus(sae_certificate_serial.clone(), 2)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));

        command_tx.send(super::QkdManagerCommand::GetSaeInfoFromCertificate(sae_certificate_serial.clone())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::SaeInfo(_)));
        assert_eq!(qkd_manager_response, QkdManagerResponse::SaeInfo(super::SAEInfo {
            sae_id,
            kme_id,
            sae_certificate_serial: sae_certificate_serial.clone(),
        }));

        command_tx.send(super::QkdManagerCommand::GetSaeInfoFromCertificate(vec![2u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        command_tx.send(super::QkdManagerCommand::GetKmeIdFromSaeId(sae_id)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::KmeInfo(_)));
        assert_eq!(qkd_manager_response, QkdManagerResponse::KmeInfo(super::KMEInfo {
            kme_id,
        }));
        command_tx.send(super::QkdManagerCommand::GetKmeIdFromSaeId(3)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        command_tx.send(super::QkdManagerCommand::AddKmeClassicalNetInfo(kme_id,
                                                                         String::from("wrong_data"),
                                                                         String::from("wrong_data"),
                                                                         String::from("wrong_data"),
                                                                         true)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ko);
        command_tx.send(super::QkdManagerCommand::AddKmeClassicalNetInfo(kme_id,
                                                                         String::from("test.fr:1234"),
                                                                         String::from(KME1_TO_KME2_CLIENT_AUTH_CERT_PATH),
                                                                         String::from(""),
                                                                         true)).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ok);

        assert_eq!(subscriber.events.lock().unwrap().len(), 1);

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);

        // add multiple keys
        let key1 = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([1u8; 16]).as_bytes(),
            key: [1u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        let key2 = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([2u8; 16]).as_bytes(),
            key: [2u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        command_tx.send(super::QkdManagerCommand::AddMultiplePreInitKeys(vec![key1, key2])).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::Ok);

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));

        command_tx.send(super::QkdManagerCommand::GetKeys(sae_certificate_serial.clone(), sae_id, RequestedKeyCount::new(1).unwrap())).unwrap();
        let qkd_manager_response = response_rx.recv().unwrap();
        assert_eq!(qkd_manager_response, QkdManagerResponse::NotFound);
    }
}