//! QKD key handler interface, to communicate with QKD manager thread (authentication, database...)

mod key_handler;
pub(crate) mod http_response_obj;
pub(crate) mod http_request_obj;
mod router;
mod config_extractor;

use crate::entropy::{EntropyAccumulator, ShannonEntropyAccumulator};
use crate::event_subscription::ImportantEventSubscriber;
use crate::qkd_manager::http_response_obj::ResponseQkdKeysList;
use crate::qkd_manager::key_handler::KeyHandler;
use crate::{KmeId, QkdEncKey, RequestedKeyCount, SaeClientCertSerial, SaeId};
use log::warn;
use sha1::Digest;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;

/// QKD manager interface, can be cloned for instance in each request handler task
#[derive(Clone)]
pub struct QkdManager {
    /// Directory watchers for other KME keys, placed here because watch stops when dropped
    pub(crate) dir_watcher: Arc<Mutex<Vec<notify::RecommendedWatcher>>>,
    /// The ID of the KME this QKD manager belongs to
    pub kme_id: KmeId,
    /// Shannon's entropy calculator for keys stored in the database
    shannon_entropy_calculator: Arc<Mutex<ShannonEntropyAccumulator>>,
    /// KME's nickname if any (eg: Alice, Bob...)
    pub nick_name: Option<String>,
    /// The key handler, to handle all database operations and key management
    pub(crate) key_handler: KeyHandler,
}

impl QkdManager {
    /// Create a new QKD manager handler
    /// # Arguments
    /// * `db_uri` - Database URI, or ":memory:" to use an in-memory database
    /// * `this_kme_id` - The ID of the KME this QKD manager belongs to
    /// * `kme_nickname` - The nickname of the KME, if any (eg: `"Alice"`, `"Bob"`...)
    /// # Returns
    /// A new QKD manager handler
    /// # Notes
    /// This function spawns a new thread to handle the QKD manager
    pub async fn new(db_uri: &str, this_kme_id: KmeId, kme_nickname: &Option<String>) -> Result<Self, io::Error> {
        let db_uri = String::from(db_uri);

        // Spawn a new thread to handle the QKD manager
        let nickname = kme_nickname.to_owned();

        let dir_watcher = Arc::new(Mutex::new(Vec::new()));

        let key_handler = KeyHandler::new(&db_uri, this_kme_id, nickname.to_owned()).await?;

        Ok(Self {
            dir_watcher,
            kme_id: this_kme_id,
            shannon_entropy_calculator: Arc::new(Mutex::new(ShannonEntropyAccumulator::new())),
            nick_name: kme_nickname.to_owned(),
            key_handler
        })
    }

    /// Create a new QKD manager handler from a configuration
    /// # Arguments
    /// * `config` - The configuration to use to create the QKD manager
    /// # Returns
    /// A new QKD manager handler if the configuration is valid, an error otherwise
    pub async fn from_config(config: &crate::config::Config) -> Result<Arc<Self>, io::Error> {
        let qkd_manager = config_extractor::ConfigExtractor::extract_config_to_qkd_manager(config).await?;
        Ok(qkd_manager)
    }

    /// Add a new QKD key to the database
    /// Increases the total entropy of all keys in the database
    /// # Arguments
    /// * `key` - The QKD key to add (key + origin SAE ID + target SAE ID)
    /// # Returns
    /// Ok if the key was added successfully, an error otherwise
    pub async fn add_pre_init_qkd_key(&self, key: PreInitQkdKeyWrapper) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const EXPECTED_QKD_MANAGER_RESPONSE: QkdManagerResponse = QkdManagerResponse::Ok;
        let add_key_status = self.key_handler.add_preinit_qkd_key(key.to_owned()).await?;
        if add_key_status != EXPECTED_QKD_MANAGER_RESPONSE {
            return Err(add_key_status);
        }

        self.shannon_entropy_calculator.lock().await.add_bytes(&key.key);
        Ok(EXPECTED_QKD_MANAGER_RESPONSE)
    }

    /// Add multiple new QKD keys to the database
    /// Increases the total entropy of all keys in the database
    /// # Arguments
    /// * `keys` - The QKD keys to add (key + origin SAE ID + target SAE ID)
    /// # Returns
    /// Ok if the keys were added successfully, an error otherwise
    pub async fn add_multiple_pre_init_qkd_keys(&self, keys: Vec<PreInitQkdKeyWrapper>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const EXPECTED_QKD_MANAGER_RESPONSE: QkdManagerResponse = QkdManagerResponse::Ok;

        let add_keys_status = self.key_handler.add_multiple_preinit_qkd_keys(keys.to_owned()).await?;

        if add_keys_status != EXPECTED_QKD_MANAGER_RESPONSE {
            return Err(add_keys_status);
        }

        for k in keys.iter() {
            self.shannon_entropy_calculator.lock().await.add_bytes(&k.key);
        }

        Ok(EXPECTED_QKD_MANAGER_RESPONSE)
    }

    /// Get a QKD key from the database (shall be called by the master SAE)
    /// # Arguments
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate
    /// * `auth_client_cert_serial` - The serial number of the client certificate of caller the master SAE, to authenticate and identify the caller
    /// # Returns
    /// The requested QKD key if the key was found and the caller is authorized to retrieve it, an error otherwise
    pub async fn get_qkd_keys(&self, target_sae_id: SaeId, auth_client_cert_serial: &SaeClientCertSerial, keys_count: RequestedKeyCount) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let get_qkd_key_manager_response = self.key_handler.get_sae_keys(auth_client_cert_serial, target_sae_id, keys_count).await?;
        match get_qkd_key_manager_response {
            QkdManagerResponse::Keys(keys) => { // Keys is the QkdManagerResponse expected here
                Ok(QkdManagerResponse::Keys(keys))
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
    pub async fn get_qkd_keys_with_ids(&self, source_sae_id: SaeId, auth_client_cert_serial: &SaeClientCertSerial, keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let get_qkd_key_id_manager_response = self.key_handler.get_sae_keys_with_ids(auth_client_cert_serial, source_sae_id, keys_uuids).await?;
        match get_qkd_key_id_manager_response {
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
    pub async fn add_sae(&self, sae_id: SaeId, kme_id: KmeId, sae_certificate_serial: &Option<SaeClientCertSerial>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const EXPECTED_QKD_MANAGER_RESPONSE: QkdManagerResponse = QkdManagerResponse::Ok;

        let add_sae_response =  self.key_handler.add_sae(sae_id, kme_id, sae_certificate_serial).await?;

        if add_sae_response != EXPECTED_QKD_MANAGER_RESPONSE {
            return Err(add_sae_response);
        }

        Ok(EXPECTED_QKD_MANAGER_RESPONSE)
    }

    /// Get the status of a key exchange between two SAEs (shall be called by the master SAE)
    /// # Arguments
    /// * `origin_sae_certificate_serial` - The serial number of the client certificate of the master SAE, to authenticate and identify the caller
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate
    /// # Returns
    /// The status of the key exchange if the key exchange was found and the caller is authorized to retrieve it, an error otherwise
    pub async fn get_qkd_key_status(&self, origin_sae_certificate_serial: &SaeClientCertSerial, target_sae_id: SaeId) -> Result<QkdManagerResponse, QkdManagerResponse> {
        let get_sae_status_qkd_manager_response = self.key_handler.get_sae_status(origin_sae_certificate_serial, target_sae_id).await?;
        match get_sae_status_qkd_manager_response {
            QkdManagerResponse::Status(status) => Ok(QkdManagerResponse::Status(status)), // Status is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error),
        }
    }

    /// Get information about a SAE from its client auth certificate (SAE id)
    /// # Arguments
    /// * `client_certificate_serial` - The serial number of the client certificate of the SAE, to authenticate and identify the caller
    /// # Returns
    /// The SAE information (like SAE ID) if the SAE was found, an error otherwise
    pub async fn get_sae_info_from_client_auth_certificate(&self, client_certificate_serial: &SaeClientCertSerial) -> Result<SAEInfo, QkdManagerResponse> {
        match self.key_handler.get_sae_infos_from_certificate(client_certificate_serial).await? {
            QkdManagerResponse::SaeInfo(sae_info) => Ok(sae_info), // SaeInfo is the QkdManagerResponse expected here
            qkd_response_error => Err(qkd_response_error), // Likely not found
        }
    }

    /// GET the KME ID from belonging SAE ID
    /// # Arguments
    /// * `sae_id` - The ID of the SAE
    /// # Returns
    /// The KME ID if the SAE was found, None otherwise
    pub async fn get_kme_id_from_sae_id(&self, sae_id: SaeId) -> Option<KMEInfo> {
        match self.key_handler.get_kme_id_from_sae_id(sae_id).await {
            Some(kme_id) => KMEInfo {
                kme_id,
            }.into(),
            None => {
                warn!("Get KME ID from SAE ID: SAE ID not found in database");
                None
            },
        }
    }

    /// From a remote KME, activate a key after master SAE requested it, to be requested by the slave SAE
    /// # Arguments
    /// * `origin_sae_id` - The ID of the origin (master) SAE, belonging to another KME
    /// * `target_sae_id` - The ID of the target (slave) SAE, to which master SAE wants to communicate, belonging to this KME
    /// * `key_uuid` - The UUID of the key to activate
    /// # Returns
    /// Ok if the key was activated successfully, an error otherwise
    pub async fn activate_key_from_remote(&self, origin_sae_id: SaeId, target_sae_id: SaeId, key_uuids_list: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const EXPECTED_QKD_MANAGER_RESPONSE: QkdManagerResponse = QkdManagerResponse::Ok;

        let activate_key_uuid_qkd_manager_response = self.key_handler.activate_key_uuids_sae(origin_sae_id, target_sae_id, key_uuids_list).await?;

        if activate_key_uuid_qkd_manager_response != EXPECTED_QKD_MANAGER_RESPONSE {
            return Err(activate_key_uuid_qkd_manager_response);
        }
        Ok(EXPECTED_QKD_MANAGER_RESPONSE)
    }

    /// Add classical network information to a KME, used to activate keys on it for slave KMEs using "classical channel"
    /// # Arguments
    /// * `kme_id` - The ID of the KME
    /// * `kme_addr` - The IP address or domain of the KME on the classical network
    /// * `client_auth_certificate_path` - The path to the client authentication certificate of the KME
    /// * `client_auth_certificate_password` - The password of the client authentication certificate of the KME
    /// # Returns
    /// Ok if the KME classical network information was added successfully, an error otherwise
    /// # Notes
    /// You should also add target KME's CA certificate to the trust store of the source KME operating system
    pub async fn add_kme_classical_net_info(&self, kme_id: KmeId, kme_addr: &str, client_auth_certificate_path: &str, client_auth_certificate_password: &str, should_ignore_system_proxy_config: bool) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const EXPECTED_QKD_MANAGER_RESPONSE: QkdManagerResponse = QkdManagerResponse::Ok;

        let add_kme_info_qkd_manager_response = self.key_handler.add_kme_classical_net_info(
            kme_id, kme_addr, client_auth_certificate_path, client_auth_certificate_password, should_ignore_system_proxy_config
        ).await?;

        if add_kme_info_qkd_manager_response != EXPECTED_QKD_MANAGER_RESPONSE {
            return Err(add_kme_info_qkd_manager_response);
        }
        Ok(EXPECTED_QKD_MANAGER_RESPONSE)
    }

    /// Get the Shannon entropy of all stored keys
    /// # Returns
    /// The total Shannon entropy of all stored keys, an error in case of concurrency issues
    pub async fn get_total_keys_shannon_entropy(&self) -> Result<f64, io::Error> {
        let entropy_calculator = Arc::clone(&self.shannon_entropy_calculator);
        let x = Ok::<f64, io::Error>(entropy_calculator
                                 .lock()
                                 .await
                                 .get_entropy());
        x
    }

    /// ## [demonstration purpose]
    /// Add subscriber implementing ImportantEventSubscriber trait, that will receive message for all important events.
    /// Events are something like "SAE 1 requested a key for SAE2", or "KME 1 activated a key for SAE 2"
    /// # Arguments
    /// * `subscriber` - The subscriber to add, must implement ImportantEventSubscriber trait
    /// # Returns
    /// Ok if the subscriber was added successfully, an error otherwise (likely thread communication error)
    pub async fn add_important_event_subscriber(&self, subscriber: Arc<dyn ImportantEventSubscriber>) -> Result<(), io::Error> {
        self.key_handler.add_important_event_subscriber(subscriber).await
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
    pub(crate) sae_certificate_serial: SaeClientCertSerial,
}

/// Describes information about a KME
#[derive(Debug, Clone, PartialEq)]
pub struct KMEInfo {
    pub(crate) kme_id: KmeId,
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
    /// Cannot reach other KME because it's not present on router's configuration
    MissingRemoteKmeConfiguration,
    /// Communication with remote KME failed, likely because of a bad configuration or a network failure
    RemoteKmeCommunicationError,
    /// Remote KME didn't accept the request, maybe its configuration isn't well synced with this KME
    RemoteKmeAcceptError,
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
    use crate::event_subscription::ImportantEventSubscriber;
    use crate::qkd_manager::QkdManagerResponse;
    use crate::{QkdEncKey, RequestedKeyCount};
    use serial_test::serial;
    use std::future::Future;
    use std::io::Error;
    use std::ops::{Deref, DerefMut};
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    const CLIENT_CERT_SERIAL_SIZE_BYTES: usize = 20;

    #[tokio::test]
    async fn test_add_qkd_key() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let response = qkd_manager.add_pre_init_qkd_key(key).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);
        assert_eq!(qkd_manager.get_total_keys_shannon_entropy().await.unwrap(), 0.0);
    }

    #[tokio::test]
    async fn add_multiple_pre_init_qkd_keys() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        let key1 = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key2 = super::PreInitQkdKeyWrapper::new(1, &[1; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let response = qkd_manager.add_multiple_pre_init_qkd_keys(vec![key1, key2]).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);
        assert_eq!(qkd_manager.get_total_keys_shannon_entropy().await.unwrap(), 1.0);
    }

    #[tokio::test]
    async fn test_stored_keys_entropy() {
        const DB_URI: &'static str = ":memory:";
        let first_key: QkdEncKey = <[u8; crate::QKD_KEY_SIZE_BYTES]>::try_from("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".as_bytes()).unwrap();
        let second_key: QkdEncKey = <[u8; crate::QKD_KEY_SIZE_BYTES]>::try_from("6789+-abcdefghijklmnopqrstuvwxyz".as_bytes()).unwrap();

        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &first_key).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        assert_eq!(qkd_manager.get_total_keys_shannon_entropy().await.unwrap(), 5.0);
        let key = super::PreInitQkdKeyWrapper::new(1, &second_key).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        assert_eq!(qkd_manager.get_total_keys_shannon_entropy().await.unwrap(), 6.0);
    }

    #[tokio::test]
    async fn test_add_sae() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        let response = qkd_manager.add_sae(1,  1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);

        // Duplicate SAE ID allowed
        let response = qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);

        // Add SAE with key if it doesn't belong to KME1
        let response = qkd_manager.add_sae(2, 2, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::InconsistentSaeData);

        // Add SAE without key if it doesn't belong to KME1
        let response = qkd_manager.add_sae(2, 2, &None).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);

        // Add SAE without key if it belongs to KME1
        let response = qkd_manager.add_sae(1, 1, &None).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::InconsistentSaeData);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_qkd_key() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        qkd_manager.add_sae(2, 2, &None).await.unwrap(); // No certificate as this SAE doesn't belong to KME1
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        let response = qkd_manager.get_qkd_keys(
            2,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys(
            1,
            &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::AuthenticationError);


        let response = qkd_manager.get_qkd_keys(
            1,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_get_qkd_key_multiple() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        qkd_manager.add_sae(2, 2, &None).await.unwrap(); // No certificate as this SAE doesn't belong to KME1
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();

        let key = super::PreInitQkdKeyWrapper::new(1, &[1; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();

        let key = super::PreInitQkdKeyWrapper::new(1, &[2; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();

        let response = qkd_manager.get_qkd_keys(1,
                                                &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
                                                RequestedKeyCount::new(0).unwrap()
        ).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 0);
            },
            _ => panic!("Expected Keys response"),
        }

        let response = qkd_manager.get_qkd_keys(1,
                                                &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
                                                RequestedKeyCount::new(0).unwrap()
        ).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 0);
            },
            _ => panic!("Expected Keys response"),
        }

        let response = qkd_manager.get_qkd_keys(1,
                                                &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
                                                RequestedKeyCount::new(2).unwrap()
        ).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 2);
            },
            _ => panic!("Expected Keys response"),
        }

        let response = qkd_manager.get_qkd_keys(1,
                                                &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
                                                RequestedKeyCount::new(2).unwrap()
        ).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 1);
            },
            _ => panic!("Expected Keys response"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_get_qkd_keys_with_ids() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        qkd_manager.add_sae(2, 1, &Some(vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1,&[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        let response = qkd_manager.get_qkd_keys_with_ids(2, &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys_with_ids(1, &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys(
            1,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_ok());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);

        let response = qkd_manager.get_qkd_keys(
            2,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_err());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);


        let key = super::PreInitQkdKeyWrapper::new(1,&[1; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();

        let response = qkd_manager.get_qkd_keys(
            2,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_ok());
        let response = qkd_manager.get_qkd_keys_with_ids(1, &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key_uuid_str.clone()]).await;
        assert!(response.is_ok());
        assert!(matches!(response.unwrap(), QkdManagerResponse::Keys(_)));
    }

    #[tokio::test]
    #[serial]
    async fn test_get_multiple_qkd_keys_with_ids() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        qkd_manager.add_sae(2, 1, &Some(vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key1 = super::PreInitQkdKeyWrapper::new(1,&[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key1_uuid = key1.get_uuid();
        let key1_uuid_str = uuid::Uuid::from_bytes(key1_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key1).await.unwrap();

        let key2 = super::PreInitQkdKeyWrapper::new(1,&[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key2_uuid = key2.get_uuid();
        let key2_uuid_str = uuid::Uuid::from_bytes(key2_uuid).to_string();
        qkd_manager.add_pre_init_qkd_key(key2).await.unwrap();

        let response = qkd_manager.get_qkd_keys(
            2,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(2).unwrap()
        ).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 2);
                assert_eq!(keys.keys[0].key_ID, key1_uuid_str);
                assert_eq!(keys.keys[1].key_ID, key2_uuid_str);
            },
            _ => panic!("Expected Keys response"),
        }

        let response = qkd_manager.get_qkd_keys_with_ids(1, &vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], vec![key1_uuid_str.clone(), key2_uuid_str.clone()]).await;
        assert!(response.is_ok());
        match response.unwrap() {
            QkdManagerResponse::Keys(keys) => {
                assert_eq!(keys.keys.len(), 2);
                assert_eq!(keys.keys[0].key_ID, key1_uuid_str);
                assert_eq!(keys.keys[1].key_ID, key2_uuid_str);
            },
            _ => panic!("Expected Keys response"),
        }
    }

    #[tokio::test]
    async fn test_get_qkd_key_status() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        qkd_manager.add_sae(2, 1, &Some(vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        let response = qkd_manager.get_qkd_key_status(&vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES], 2).await;
        assert!(response.is_ok());
        assert!(matches!(response.unwrap(), QkdManagerResponse::Status(_)));
    }

    #[test]
    fn test_key_uuid() {
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        let key_uuid = key.get_uuid();
        let key_uuid_str = uuid::Uuid::from_bytes(key_uuid).to_string();
        assert_eq!(key_uuid_str, "7b848ade-8cff-3d54-a9b8-53a215e6ee77");
    }

    #[tokio::test]
    async fn test_get_sae_info_from_client_auth_certificate() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let response = qkd_manager.get_sae_info_from_client_auth_certificate(&vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES]).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.sae_id, 1);
        assert_eq!(response.kme_id, 1);

        // SAE certificate not present in database
        let response = qkd_manager.get_sae_info_from_client_auth_certificate(&vec![1; CLIENT_CERT_SERIAL_SIZE_BYTES]).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), QkdManagerResponse::NotFound);
    }

    #[tokio::test]
    async fn test_get_kme_id_from_sae_id() {
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let response = qkd_manager.get_kme_id_from_sae_id(1).await;
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.kme_id, 1);

        // SAE ID not present in database
        let response = qkd_manager.get_kme_id_from_sae_id(2).await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn test_add_kme_classical_net_info() {
        const DB_URI: &'static str = ":memory:";

        #[cfg(not(target_os = "macos"))]
        const KME1_TO_KME2_CLIENT_AUTH_CERT_PATH: &'static str = "certs/inter_kmes/kme1-to-kme2.pfx";
        #[cfg(target_os = "macos")]
        const KME1_TO_KME2_CLIENT_AUTH_CERT_PATH: &'static str = "certs/inter_kmes/kme1-to-kme2.pem";

        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();

        let response = qkd_manager.add_kme_classical_net_info(1, "test.fr:1234;bad_addr", KME1_TO_KME2_CLIENT_AUTH_CERT_PATH, "password", true).await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap(), QkdManagerResponse::Ko);

        let response = qkd_manager.add_kme_classical_net_info(1, "test.fr:1234", "not-exists.pfx", "", true).await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap(), QkdManagerResponse::Ko);

        #[cfg(not(target_os = "macos"))]
        {
        let response = qkd_manager.add_kme_classical_net_info(1, "test.fr:1234", "certs/inter_kmes/kme1-to-kme2.pfx", "bad_password", true).await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap(), QkdManagerResponse::Ko);
        }

        let response = qkd_manager.add_kme_classical_net_info(1, "test.fr:1234", "tests/data/bad_certs/invalid_client_cert_data.pfx", "", true).await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap(), QkdManagerResponse::Ko);

        let response = qkd_manager.add_kme_classical_net_info(1, "test.fr:1234", KME1_TO_KME2_CLIENT_AUTH_CERT_PATH, "password", true).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), QkdManagerResponse::Ok);
    }

    #[tokio::test]
    #[serial]
    async fn test_add_important_event_subscriber_with_nickname() {
        struct TestImportantEventSubscriber {
            events: RwLock<Vec<String>>,
        }
        impl TestImportantEventSubscriber {
            fn new() -> Self {
                Self {
                    events: RwLock::new(Vec::new()),
                }
            }
        }
        impl ImportantEventSubscriber for TestImportantEventSubscriber {
            fn notify(&self, message: &str) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>>  {
                let message = message.to_string();
                Box::pin(async move {
                    self.events
                        .write().await
                        .push(message);
                    Ok(())
                })
            }
        }
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &Some("Alice".to_string())).await.unwrap();
        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let response = qkd_manager.add_important_event_subscriber(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>).await;
        assert!(response.is_ok());
        assert_eq!(subscriber.events.read().await.deref().len(), 0);

        // Request a key
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        let response = qkd_manager.get_qkd_keys(
            1,
            &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
            RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_ok());

        assert_eq!(subscriber.events.read().await.deref().len(), 2);
        assert_eq!(subscriber.events.write().await.deref_mut().pop(), Some("[Alice] Key 7b848ade-8cff-3d54-a9b8-53a215e6ee77 activated between SAEs 1 and 1".to_string()));
        assert_eq!(subscriber.events.write().await.deref_mut().pop(), Some("[Alice] SAE 1 requested a key to communicate with 1".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_add_important_event_subscriber_without_nickname() {
        struct TestImportantEventSubscriber {
            events: RwLock<Vec<String>>,
        }
        impl TestImportantEventSubscriber {
            fn new() -> Self {
                Self {
                    events: RwLock::new(Vec::new()),
                }
            }
        }
        impl ImportantEventSubscriber for TestImportantEventSubscriber {
            fn notify(&self, message: &str) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>>  {
                let message = message.to_string();
                Box::pin(async move {
                    self.events
                        .write().await
                        .push(message);
                    Ok(())
                })
                /*self.events.lock().unwrap().push(message.to_string());
                Ok(())*/
            }
        }
        const DB_URI: &'static str = ":memory:";
        let qkd_manager = super::QkdManager::new(DB_URI, 1, &None).await.unwrap();
        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let response = qkd_manager.add_important_event_subscriber(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>).await;
        assert!(response.is_ok());
        assert_eq!(subscriber.events.read().await.deref().len(), 0);

        // Request a key
        qkd_manager.add_sae(1, 1, &Some(vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key = super::PreInitQkdKeyWrapper::new(1, &[0; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        qkd_manager.add_pre_init_qkd_key(key).await.unwrap();
        let response = qkd_manager.get_qkd_keys(1,
                                                &vec![0; CLIENT_CERT_SERIAL_SIZE_BYTES],
                                                RequestedKeyCount::new(1).unwrap()
        ).await;
        assert!(response.is_ok());

        assert_eq!(subscriber.events.read().await.deref().len(), 2);
        assert_eq!(subscriber.events.write().await.deref_mut().pop(), Some("[KME 1] Key 7b848ade-8cff-3d54-a9b8-53a215e6ee77 activated between SAEs 1 and 1".to_string()));
        assert_eq!(subscriber.events.write().await.deref_mut().pop(), Some("[KME 1] SAE 1 requested a key to communicate with 1".to_string()));
    }
}