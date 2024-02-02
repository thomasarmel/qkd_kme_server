use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use log::error;
use clap::Parser;
use notify::{EventKind, RecursiveMode, Watcher};
use notify::event::{AccessKind, AccessMode};
use qkd_kme_server::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};
use qkd_kme_server::routes::QKDKMERoutesV1;

#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::new().init().unwrap();
    let args = Args::parse();

    println!("{:?}", args);


    let server = qkd_kme_server::server::Server {
        listen_addr: "127.0.0.1:3000".to_string(),
        ca_client_cert_path: "certs/CA-zone1.crt".to_string(),
        server_cert_path: "certs/kme1.crt".to_string(),
        server_key_path: "certs/kme1.key".to_string(),
    };

    let qkd_manager = Arc::new(QkdManager::new(qkd_kme_server::MEMORY_SQLITE_DB_PATH, args.this_kme_id));
    if qkd_manager.add_sae(1,
                           1,
                           &Some([0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x8e])
    ).is_err() {
        error!("Error adding SAE to QKD manager");
        return;
    }
    if qkd_manager.add_sae(2,
                           1,
                           &Some([0x70, 0xf4, 0x4f, 0x56, 0x0c, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x03, 0x81, 0x3b, 0x92])
    ).is_err() {
        error!("Error adding SAE to QKD manager");
        return;
    }

    let mut watchers: Vec<notify::RecommendedWatcher> = Vec::new();

    for kme_dir in args.dirs_to_watch_other_kme_ids {
        extract_all_keys_from_dir(&kme_dir.dir, kme_dir.kme_id, &qkd_manager);
        let kme_id = kme_dir.kme_id;
        let qkd_manager = Arc::clone(&qkd_manager);
        watchers.push(match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if let EventKind::Access(AccessKind::Close(AccessMode::Write)) = event.kind {
                        extract_all_keys_from_file(&event.paths[0].to_str().unwrap(), kme_id, &qkd_manager);
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
                error!("Error creating watcher: {:?}", e);
                return;
            }
        });
        if watchers.iter_mut().last().unwrap().watch(Path::new(&kme_dir.dir), RecursiveMode::NonRecursive).is_err() {
            error!("Error watching directory: {:?}", kme_dir.dir);
            return;
        }
    }

    if server.run::<QKDKMERoutesV1>(&qkd_manager).await.is_err() {
        error!("Error running HTTP server");
        return;
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    this_kme_id: i64,
    #[arg(long("kme_id,dir_watch"))]
    dirs_to_watch_other_kme_ids: Vec<DirWatchOtherKmesArgs>,
}

#[derive(Debug, Clone)]
struct DirWatchOtherKmesArgs {
    dir: String,
    kme_id: i64,
}

impl std::str::FromStr for DirWatchOtherKmesArgs {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kme_id_and_dir = s.split(",").collect::<Vec<&str>>();
        if kme_id_and_dir.len() != 2 {
            return Err(std::io::Error::other("Invalid format"));
        }
        let kme_id = i64::from_str(kme_id_and_dir[0]).map_err(|_| std::io::Error::other("Invalid format"))?;
        Ok(Self {
            dir: kme_id_and_dir[1].to_string(),
            kme_id,
        })
    }
}

// TODO: move to QKD manager struct
fn extract_all_keys_from_file(file_path: &str, other_kme_id: i64, qkd_manager: &QkdManager) {
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

fn extract_all_keys_from_dir(dir_path: &str, other_kme_id: i64, qkd_manager: &QkdManager) {
    let paths = std::fs::read_dir(dir_path).unwrap();
    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() {
            extract_all_keys_from_file(path.to_str().unwrap(), other_kme_id, qkd_manager);
        }
    }
}