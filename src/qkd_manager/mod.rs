//! QKD key handler interface, to communicate with QKD manager thread (authentication, database...)

mod key_handler;
pub(crate) mod http_response_obj;
pub(crate) mod http_request_obj;
mod router;

use std::{io, thread};
use log::error;
use sha1::Digest;
use crate::qkd_manager::http_response_obj::ResponseQkdKeysList;
use crate::qkd_manager::QkdManagerResponse::TransmissionError;
use crate::{KmeId, QkdEncKey, SaeId};

/// QKD manager interface, can be cloned for instance in each request handler task
#[derive(Clone)]
pub struct QkdManager {
    /// Channel to send commands to the key handler
    command_tx: crossbeam_channel::Sender<QkdManagerCommand>,
    /// Channel to receive responses from the key handler
    response_rx: crossbeam_channel::Receiver<QkdManagerResponse>,
}

impl QkdManager {
    /// Create a new QKD manager handler
    /// # Arguments
    /// * `sqlite_db_path` - The path to the SQLite database file, or ":memory:" to use an in-memory database
    /// # Returns
    /// A new QKD manager handler
    /// # Notes
    /// This function spawns a new thread to handle the QKD manager
    pub fn new(sqlite_db_path: &str, this_kme_id: i64) -> Self {
        // crossbeam_channel allows cloning the sender and receiver
        let (command_tx, command_rx) = crossbeam_channel::unbounded::<QkdManagerCommand>();
        let (response_tx, response_rx) = crossbeam_channel::unbounded::<QkdManagerResponse>();
        let sqlite_db_path = String::from(sqlite_db_path);

        // Spawn a new thread to handle the QKD manager
        thread::spawn(move || {
            let mut key_handler = match key_handler::KeyHandler::new(&sqlite_db_path, command_rx, response_tx, this_kme_id) {
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

    /// Add a new QKD key to the database
    /// # Arguments
    /// * `key` - The QKD key to add (key + origin SAE ID + target SAE ID)
    /// # Returns
    /// Ok if the key was added successfully, an error otherwise
    pub fn add_pre_init_qkd_key(&self, key: PreInitQkdKeyWrapper) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::AddPreInitKey(key)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Ok => Ok(QkdManagerResponse::Ok), // Ok is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Get a QKD key from the database (shall be called by the master SAE)
    /// # Arguments
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate
    /// * `auth_client_cert_serial` - The serial number of the client certificate of caller the master SAE, to authenticate and identify the caller
    /// # Returns
    /// The requested QKD key if the key was found and the caller is authorized to retrieve it, an error otherwise
    pub fn get_qkd_key(&self, target_sae_id: i64, auth_client_cert_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKeys(*auth_client_cert_serial, target_sae_id)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Keys(key) => { // Keys is the QkdManagerResponse expected here
                Ok(QkdManagerResponse::Keys(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Get a list of QKD keys from the database (shall be called by the slave SAE)
    /// # Arguments
    /// * `source_sae_id` - The ID of the source (master) SAE, to which slave SAE has been asked to communicate
    /// * `auth_client_cert_serial` - The serial number of the client certificate of caller the slave SAE, to authenticate and identify the it
    /// * `keys_uuids` - The list of UUIDs of the keys sent by master SAE that the slave SAE wants to retrieve
    /// # Returns
    /// The requested QKD keys if the keys were found and the caller is authorized to retrieve them, an error otherwise
    pub fn get_qkd_keys_with_ids(&self, source_sae_id: i64, auth_client_cert_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKeysWithIds(*auth_client_cert_serial, source_sae_id, keys_uuids)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Keys(key) => { // Keys is the QkdManagerResponse expected here
                Ok(QkdManagerResponse::Keys(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Add a new SAE to the database (shall be called before SAEs start requesting KME)
    /// # Arguments
    /// * `sae_id` - The ID of the SAE to add
    /// * `sae_certificate_serial` - The serial number of the client certificate identifying the SAE to add
    /// # Returns
    /// Ok if the SAE was added successfully, an error otherwise
    /// # Notes
    /// It will fail if the SAE ID is already in the database
    pub fn add_sae(&self, sae_id: SaeId, kme_id: KmeId, sae_certificate_serial: &Option<[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::AddSae(sae_id, kme_id, *sae_certificate_serial)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Ok => Ok(QkdManagerResponse::Ok), // Ok is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Get the status of a key exchange between two SAEs (shall be called by the master SAE)
    /// # Arguments
    /// * `origin_sae_certificate_serial` - The serial number of the client certificate of the master SAE, to authenticate and identify the caller
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate
    /// # Returns
    /// The status of the key exchange if the key exchange was found and the caller is authorized to retrieve it, an error otherwise
    pub fn get_qkd_key_status(&self, origin_sae_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], target_sae_id: SaeId) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetStatus(*origin_sae_certificate_serial, target_sae_id)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Status(status) => Ok(QkdManagerResponse::Status(status)), // Status is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Get information about a SAE from its client auth certificate (SAE id)
    /// # Arguments
    /// * `client_certificate_serial` - The serial number of the client certificate of the SAE, to authenticate and identify the caller
    /// # Returns
    /// The SAE information (like SAE ID) if the SAE was found, an error otherwise
    pub fn get_sae_info_from_client_auth_certificate(&self, client_certificate_serial: &[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]) -> Result<SAEInfo, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetSaeInfoFromCertificate(*client_certificate_serial)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::SaeInfo(sae_info) => Ok(sae_info), // SaeInfo is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error), // Likely not found
        }
    }

    /// GET the KME ID from belonging SAE ID
    /// # Arguments
    /// * `sae_id` - The ID of the SAE
    /// # Returns
    /// The KME ID if the SAE was found, None otherwise
    pub fn get_kme_id_from_sae_id(&self, sae_id: SaeId) -> Option<KMEInfo> {
        self.command_tx.send(QkdManagerCommand::GetKmeIdFromSaeId(sae_id)).map_err(|_| {
            TransmissionError
        }).ok()?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        }).ok()? {
            QkdManagerResponse::KmeInfo(kme_info) => Some(kme_info), // KmeInfo is the QkdManagerResponse expected here
            _ => None,
        }
    }
}

/// A Pre-init QKD key, with its origin and target KME IDs
/// This is the key supposed to be added to the database
/// A master SAE, belonging to the KME, will then request the key
/// Its status will become "initialized", meaning that instead of being associated to a KME, it will be associated to a pair of SAEs
/// The slave SAE would then request the key to this KME or another KME, depending on the KME the slave SAE belong to
#[derive(Debug, Clone)]
pub struct PreInitQkdKeyWrapper {
    pub(crate) other_kme_id: KmeId,
    pub(crate) key: QkdEncKey,
    pub(crate) key_uuid: uuid::Bytes,
}

impl PreInitQkdKeyWrapper {
    /// Create a new pre init QKD key for a future communication between SAEs
    /// # Arguments
    /// * `origin_sae_id` - The ID of the origin (master) SAE
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate
    /// * `key` - The QKD key, of size [QKD_KEY_SIZE_BITS](crate::QKD_KEY_SIZE_BITS) bits
    /// # Returns
    /// A new QKD key
    /// # Errors
    /// If key UUID generation fails, which should never happen
    pub fn new(other_kme_id: KmeId, key: &QkdEncKey) -> Result<Self, io::Error> {
        Ok(Self {
            other_kme_id,
            key: *key,
            key_uuid: Self::generate_key_uuid(key)?,
        })
    }

    /// Generate a UUID from a key sha1 hash
    fn generate_key_uuid(key: &QkdEncKey) -> Result<uuid::Bytes, io::Error> {
        const UUID_SIZE_BYTES: usize = 16;

        let mut hasher = sha1::Sha1::new();
        hasher.update(key);
        let hash_sub_bytes = uuid::Bytes::try_from(&hasher.finalize()[..UUID_SIZE_BYTES]).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Error creating key UUID from key hash")
        })?;
        Ok(uuid::Builder::from_sha1_bytes(hash_sub_bytes).as_uuid().to_bytes_le())
    }

    /// Get the UUID of the key
    /// # Returns
    /// The UUID of the key, in uuid::Bytes format
    pub fn get_uuid(&self) -> uuid::Bytes {
        self.key_uuid
    }
}

/// Describes information about a SAE
#[derive(Debug, Clone, PartialEq)]
pub struct SAEInfo {
    /// The ID of the SAE
    pub(crate) sae_id: SaeId,
    /// The ID of the KME the SAE belongs to
    pub(crate) kme_id: KmeId,
    /// The serial number of the client certificate identifying the SAE
    pub(crate) sae_certificate_serial: [u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES],
}

/// Describes information about a KME
#[derive(Debug, Clone, PartialEq)]
pub struct KMEInfo {
    pub(crate) kme_id: KmeId,
}

/// All possible commands to the QKD manager
/// # Note
/// For QKD manager internal usage, interface should be managed from [QkdManager](QkdManager) implementation functions
enum QkdManagerCommand {
    /// Add a new pre-init QKD key to the database: it will be available for SAEs to request it if there are connected to the right KMEs
    AddPreInitKey(PreInitQkdKeyWrapper),
    /// Get a QKD key from the database (shall be called by the master SAE)
    GetKeys([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], SaeId), // origin certificate + target id
    /// Get a list of QKD keys from the database (shall be called by the slave SAE)
    GetKeysWithIds([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], SaeId, Vec<String>), // origin certificate + target id
    /// Get the status of a key exchange between two SAEs (shall be called by the master SAE)
    GetStatus([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES], SaeId), // origin certificate + target id
    /// Add a new SAE to the database (shall be called before SAEs start requesting KME)
    AddSae(SaeId, KmeId, Option<[u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]>), // target id + KME id + target certificate
    /// Get information about a SAE from its client auth certificate
    GetSaeInfoFromCertificate([u8; crate::CLIENT_CERT_SERIAL_SIZE_BYTES]), // caller's certificate
    /// Returns the KME ID from belonging SAE ID
    GetKmeIdFromSaeId(SaeId), // SAE id
}

/// All possible responses from the QKD manager
#[allow(private_interfaces)]
#[derive(Debug, PartialEq)]
pub enum QkdManagerResponse {
    /// The operation was successful, no more information is provided (e.g. after adding a key or a SAE into the database)
    Ok,
    /// The operation was not successful, the reason is unknown
    Ko,
    /// The requested element hasn't been found in the database (like a key)
    NotFound,
    /// Error during transmission between the QKD manager and the key handler, should never happen
    TransmissionError,
    /// The operation was not successful, the provided SAE data is inconsistent (like an authentication key if the SAE doesn't belong to the KME)
    InconsistentSaeData,
    /// Caller authentication error (likely the provided client certificate serial is not in the database or not authorized to retrieve specified resources)
    AuthenticationError,
    /// The operation was successful, the requested key(s) are returned
    Keys(ResponseQkdKeysList),
    /// The operation was successful, the requested key exchange status is returned
    Status(http_response_obj::ResponseQkdKeysStatus),
    /// The operation was successful, the requested SAE information is returned (for example if GetSaeInfoFromCertificate is called)
    SaeInfo(SAEInfo),
    /// The operation was successful, the requested KME information is returned (for example if GetKmeIdFromSaeId is called)
    KmeInfo(KMEInfo),
}


#[cfg(test)]
mod test {
    use crate::CLIENT_CERT_SERIAL_SIZE_BYTES;

    #[test]
    fn test_add_qkd_key() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let response = qkd_manager.add_pre_init_qkd_key(key);
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), super::QkdManagerResponse::Ok);
    }

    #[test]
    fn test_add_sae() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        let response = qkd_manager.add_sae(1,  1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES]));
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), super::QkdManagerResponse::Ok);

        // Duplicate SAE ID
        let response = qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES]));
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::Ko);

        // Add SAE with key if it doesn't belong to KME1
        let response = qkd_manager.add_sae(2, 2, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES]));
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::InconsistentSaeData);

        // Add SAE without key if it doesn't belong to KME1
        let response = qkd_manager.add_sae(2, 2, &None);
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), super::QkdManagerResponse::Ok);

        // Add SAE without key if it belongs to KME1
        let response = qkd_manager.add_sae(1, 1, &None);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::InconsistentSaeData);
    }

    #[test]
    fn test_get_qkd_key() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        qkd_manager.add_sae(2, 2, &None).unwrap(); // No certificate as this SAE doesn't belong to KME1
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_key(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_key(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::AuthenticationError);


        let response = qkd_manager.get_qkd_key(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
    }

    #[test]
    fn test_get_qkd_keys_with_ids() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        qkd_manager.add_sae(2, 1, &Some([1; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1,&[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_keys_with_ids(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys_with_ids(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_key(1, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_key(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_err());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);


        let key = super::PreInitQkdKeyWrapper::new(1,&[1; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key).unwrap();

        let response = qkd_manager.get_qkd_key(2, &[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &[1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]);
        assert!(response.is_ok());
        assert!(matches!(response.unwrap(), super::QkdManagerResponse::Keys(_)));
    }

    #[test]
    fn test_get_qkd_key_status() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        qkd_manager.add_sae(2, 1, &Some([1; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).unwrap();
        let response = qkd_manager.get_qkd_key_status(&[1; CLIENT_CERT_SERIAL_SIZE_BYTES], 2);
        assert!(response.is_ok());
        assert!(matches!(response.unwrap(), super::QkdManagerResponse::Status(_)));
    }

    #[test]
    fn test_key_uuid() {
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        assert_eq!(key_uuid_str, "7b848ade-8cff-3d54-a9b8-53a215e6ee77");
    }

    #[test]
    fn test_get_sae_info_from_client_auth_certificate() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        let response = qkd_manager.get_sae_info_from_client_auth_certificate(&[0; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.sae_id, 1);
        assert_eq!(response.kme_id, 1);

        // SAE certificate not present in database
        let response = qkd_manager.get_sae_info_from_client_auth_certificate(&[1; CLIENT_CERT_SERIAL_SIZE_BYTES]);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), super::QkdManagerResponse::NotFound);
    }

    #[test]
    fn test_get_kme_id_from_sae_id() {
        const SQLITE_DB_PATH: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(SQLITE_DB_PATH, 1);
        qkd_manager.add_sae(1, 1, &Some([0; CLIENT_CERT_SERIAL_SIZE_BYTES])).unwrap();
        let response = qkd_manager.get_kme_id_from_sae_id(1);
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.kme_id, 1);

        // SAE ID not present in database
        let response = qkd_manager.get_kme_id_from_sae_id(2);
        assert!(response.is_none());
    }
}