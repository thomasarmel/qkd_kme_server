use log::error;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::EtsiSaeQkdRoutesV1;

#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::new().init().unwrap();

    if std::env::args().len() != 2 {
        eprintln!("Usage: {} <path to json config file>", std::env::args().nth(0).unwrap());
        return;
    }

    let config = match qkd_kme_server::config::Config::from_json_path(&std::env::args().nth(1).unwrap()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config: {:?}", e);
            return;
        }
    };

    let sae_https_server = qkd_kme_server::server::Server {
        listen_addr: config.this_kme_config.saes_https_interface.listen_address.clone(),
        ca_client_cert_path: config.this_kme_config.saes_https_interface.ca_client_cert_path.clone(),
        server_cert_path: config.this_kme_config.saes_https_interface.server_cert_path.clone(),
        server_key_path: config.this_kme_config.saes_https_interface.server_key_path.clone(),
    };

    let inter_kme_https_server = qkd_kme_server::server::Server {
        listen_addr: config.this_kme_config.kmes_https_interface.listen_address.clone(),
        ca_client_cert_path: config.this_kme_config.kmes_https_interface.ca_client_cert_path.clone(),
        server_cert_path: config.this_kme_config.kmes_https_interface.server_cert_path.clone(),
        server_key_path: config.this_kme_config.kmes_https_interface.server_key_path.clone(),
    };

    let qkd_manager= QkdManager::from_config(&config);
    println!("{:?}", qkd_manager.is_err());
    let qkd_manager = qkd_manager.unwrap();

    if sae_https_server.run::<EtsiSaeQkdRoutesV1>(&qkd_manager).await.is_err() {
        error!("Error running SAEs HTTPS server");
        return;
    }
}