use std::io;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use log::error;
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecursiveMode, Watcher};
use crate::config::Config;
use crate::{io_err, KmeId};
use crate::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};

pub(super) struct ConfigExtractor {}

impl ConfigExtractor {
    pub(super) fn extract_config_to_qkd_manager(config: &Config) -> Result<Arc<QkdManager>, io::Error> {
        let qkd_manager = Arc::new(QkdManager::new(&config.this_kme_config.sqlite_db_path, config.this_kme_config.id, &config.this_kme_config.nickname));
        Self::extract_all_saes(Arc::clone(&qkd_manager), config)?;
        Self::extract_other_kmes_and_keys(Arc::clone(&qkd_manager), config)?;
        Self::add_classical_net_routing_info_kmes(Arc::clone(&qkd_manager), config)?;
        Ok(qkd_manager)
    }

    fn extract_other_kmes_and_keys(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for other_kme_config in &config.other_kme_configs {
            let kme_id = other_kme_config.id;
            let kme_keys_dir = other_kme_config.key_directory_to_watch.as_str();
            Self::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), kme_id, kme_keys_dir)?;
        }
        Self::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), config.this_kme_config.id, config.this_kme_config.key_directory_to_watch.as_str())?;
        Ok(())
    }

    fn extract_and_watch_raw_keys_dir(qkd_manager: Arc<QkdManager>, kme_id: KmeId, kme_keys_dir: &str) -> Result<(), io::Error> {
        let mut dir_watchers = qkd_manager.dir_watcher.lock().map_err(|e|
            io_err(&format!("Cannot lock dir watcher mutex: {:?}", e))
        )?;
        let qkd_manager = Arc::clone(&qkd_manager);
        Self::extract_all_keys_from_dir(Arc::clone(&qkd_manager), kme_keys_dir, kme_id)?;

        let mut key_dir_watcher_callback = match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if let EventKind::Access(AccessKind::Close(AccessMode::Write)) = event.kind {
                        let event_path = match event.paths[0].to_str() {
                            None => {
                                error!("Error converting path to string");
                                return;
                            }
                            Some(p) => p
                        };
                        if Self::check_file_extension_qkd_keys(event_path) {
                            Self::extract_all_keys_from_file(Arc::clone(&qkd_manager), event_path, kme_id).map_err(|e|
                                error!("Error extracting keys from file: {:?}", e)
                            ).unwrap_or(());
                        }
                    }
                }
                Err(e) => {
                    error!("Watch error: {:?}", e);
                    return;
                }
            }
        }) {
            Ok(watcher) => watcher,
            Err(e) => {
                return Err(io_err(&format!("Error creating watcher: {:?}", e)));
            }
        };
        if key_dir_watcher_callback.watch(Path::new(kme_keys_dir), RecursiveMode::NonRecursive).is_err() {
            return Err(io_err(&format!("Error watching directory: {:?}", kme_keys_dir)));
        }
        dir_watchers.push(key_dir_watcher_callback);
        Ok(())
    }

    fn extract_all_saes(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for sae_config in &config.sae_configs {
            qkd_manager.add_sae(sae_config.id, sae_config.kme_id, &sae_config.https_client_certificate_serial)
                .map_err(|e|
                    io_err(&format!("Cannot add SAE config: {:?}", e))
                )?;
        }
        Ok(())
    }


    fn extract_all_keys_from_file(qkd_manager: Arc<QkdManager>, file_path: &str, other_kme_id: i64) -> Result<(), io::Error> {
        if !std::fs::metadata(file_path).map_err(|e|
            io_err(&format!("Cannot read file metadata: {:?}", e))
        )?.is_file() {
            return Err(io_err("Path is not a file"));
        }
        let file = std::fs::File::open(file_path).map_err(|e|
            io_err(&format!("Cannot open file: {:?}", e))
        )?;
        let mut reader = BufReader::with_capacity(32, file);
        let mut buffer = [0; 32];
        while let Ok(_) = reader.read_exact(&mut buffer) {
            let qkd_key = PreInitQkdKeyWrapper::new(
                other_kme_id,
                &buffer,
            ).map_err(|e|
                io_err(&format!("Cannot create QKD key: {:?}", e))
            )?;
            qkd_manager.add_pre_init_qkd_key(qkd_key).map_err(|e|
                io_err(&format!("Cannot import QKD key: {:?}", e))
            )?;
        }
        Ok(())
    }

    fn extract_all_keys_from_dir(qkd_manager: Arc<QkdManager>, dir_path: &str, other_kme_id: i64) -> Result<(), io::Error> {
        let paths = std::fs::read_dir(dir_path).map_err(|e|
            io_err(&format!("Cannot read directory: {:?}", e))
        )?;
        for path in paths {
            let path = match path {
                Ok(p) => p.path(),
                Err(ref e) => {
                    error!("Error reading directory entry: {:?}, {:?}", e, path);
                    continue;
                }
            };
            if path.is_file() {
                let path = path.to_str().ok_or(io_err("Error converting path to string"))?;
                if Self::check_file_extension_qkd_keys(path) {
                    Self::extract_all_keys_from_file(Arc::clone(&qkd_manager), path, other_kme_id)?;
                }
            }
        }
        Ok(())
    }

    fn check_file_extension_qkd_keys(file_path: &str) -> bool {
        let file_ext = Path::new(file_path).extension();
        if let Some(ext) = file_ext {
            return ext == crate::QKD_KEY_FILE_EXTENSION;
        }
        false
    }

    fn add_classical_net_routing_info_kmes(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for other_kme_config in &config.other_kme_configs {
            qkd_manager.add_kme_classical_net_info(other_kme_config.id,
                                                   &other_kme_config.inter_kme_bind_address,
                                                   &other_kme_config.https_client_authentication_certificate,
                                                   &other_kme_config.https_client_authentication_certificate_password,
                                                    other_kme_config.ignore_system_proxy_settings)
                .map_err(|e|
                    io_err(&format!("Cannot add KME classical network info: {:?}", e))
                )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use serial_test::serial;
    use crate::config::Config;
    use crate::qkd_manager::config_extractor::ConfigExtractor;

    #[tokio::test]
    #[serial]
    async fn test_extract_config_to_qkd_manager() {
        #[cfg(not(target_os = "macos"))]
        const CONFIG_PATH: &'static str = "tests/data/test_kme_config.json";
        #[cfg(target_os = "macos")]
        const CONFIG_PATH: &'static str = "tests/data/test_kme_config_macos.json";

        let config = Config::from_json_path(CONFIG_PATH).unwrap();
        let qkd_manager = ConfigExtractor::extract_config_to_qkd_manager(&config).unwrap();
        assert_eq!(qkd_manager.kme_id, 1);
        assert!(qkd_manager.get_qkd_key(2, &vec![0x70, 0xF4, 0x4F, 0x56, 0x0C, 0x3F, 0x27, 0xD4, 0xB2, 0x11, 0xA4, 0x78, 0x13, 0xAF, 0xD0, 0x3C, 0x03, 0x81, 0x3B, 0x8E]).await.is_ok());
    }

    #[test]
    fn test_file_extension_check() {
        assert!(ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file.cor"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("test_file.bad_ext"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file.bad_ext"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("test_file"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file"));
    }

    #[test]
    fn test_extract_all_keys_from_dir() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None));
        assert!(ConfigExtractor::extract_all_keys_from_dir(Arc::clone(&qkd_manager), "raw_keys/kme-1-1", 1).is_ok());
        assert!(ConfigExtractor::extract_all_keys_from_dir(qkd_manager, "unexisting/directory", 1).is_err());
    }

    #[test]
    fn test_extract_all_keys_from_file() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None));
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "raw_keys/", 1).is_err());
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "path/to/unexisting/file", 1).is_err());
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "raw_keys/kme-1-1/211202_1159_CD6ADBF2.cor", 1).is_ok());
    }

    #[test]
    fn test_extract_and_watch_raw_keys_dir() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None));
        assert!(ConfigExtractor::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), 1, "raw_keys/kme-1-1").is_ok());
        assert!(ConfigExtractor::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), 1, "unexisting/directory").is_err());
    }
}