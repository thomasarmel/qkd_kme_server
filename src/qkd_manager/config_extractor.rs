use std::io;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecursiveMode, Watcher};
use crate::config::Config;
use crate::io_err;
use crate::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};

pub(super) struct ConfigExtractor {}

impl ConfigExtractor {
    pub(super) fn extract_config_to_qkd_manager(config: &Config) -> Result<Arc<QkdManager>, io::Error> {
        let qkd_manager = Arc::new(QkdManager::new(&config.this_kme_config.sqlite_db_path, config.this_kme_config.id));
        Self::extract_all_saes(Arc::clone(&qkd_manager), config)?;
        Self::extract_other_kmes_and_keys(Arc::clone(&qkd_manager), config)?;
        Ok(qkd_manager)
    }

    fn extract_other_kmes_and_keys(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for other_kme_config in &config.other_kme_configs {
            let kme_id = other_kme_config.id;
            let kme_keys_dir = other_kme_config.key_directory_to_watch.as_str();
            let mut dir_watchers = qkd_manager.dir_watcher.lock().unwrap();
            let qkd_manager = Arc::clone(&qkd_manager);
            Self::extract_all_keys_from_dir(Arc::clone(&qkd_manager), kme_keys_dir, other_kme_config.id);

            dir_watchers.push(match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        if let EventKind::Access(AccessKind::Close(AccessMode::Write)) = event.kind {
                            if Self::check_file_extension_qkd_keys(event.paths[0].to_str().unwrap()) {
                                Self::extract_all_keys_from_file(Arc::clone(&qkd_manager), &event.paths[0].to_str().unwrap(), kme_id);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Watch error: {:?}", e);
                        return;
                    }
                }
            }) {
                Ok(watcher) => watcher,
                Err(e) => {
                    return Err(io_err(&format!("Error creating watcher: {:?}", e)));
                }
            });
            if dir_watchers.iter_mut().last().unwrap().watch(Path::new(kme_keys_dir), RecursiveMode::NonRecursive).is_err() {
                return Err(io_err(&format!("Error watching directory: {:?}", kme_keys_dir)));
            }
        }
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


    fn extract_all_keys_from_file(qkd_manager: Arc<QkdManager>, file_path: &str, other_kme_id: i64) {
        let file = std::fs::File::open(file_path).unwrap();
        let mut reader = BufReader::with_capacity(32, file);
        let mut buffer = [0; 32];
        while let Ok(_) = reader.read_exact(&mut buffer) {
            let qkd_key = PreInitQkdKeyWrapper::new(
                other_kme_id,
                &buffer,
            ).unwrap();
            qkd_manager.add_pre_init_qkd_key(qkd_key).unwrap();
        }
    }

    fn extract_all_keys_from_dir(qkd_manager: Arc<QkdManager>, dir_path: &str, other_kme_id: i64) {
        let paths = std::fs::read_dir(dir_path).unwrap();
        for path in paths {
            let path = path.unwrap().path();
            if path.is_file() {
                if Self::check_file_extension_qkd_keys(path.to_str().unwrap()) {
                    Self::extract_all_keys_from_file(Arc::clone(&qkd_manager), path.to_str().unwrap(), other_kme_id);
                }
            }
        }
    }

    fn check_file_extension_qkd_keys(file_path: &str) -> bool {
        let file_ext = Path::new(file_path).extension();
        file_ext.is_some() && file_ext.unwrap() == crate::QKD_KEY_FILE_EXTENSION
    }
}