use std::sync::Arc;
use log::error;
use tokio::select;
use qkd_kme_server::event_subscription::ImportantEventSubscriber;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;
use qkd_kme_server::server::auth_https_server::AuthHttpsServer;
use qkd_kme_server::server::log_http_server::LoggingHttpServer;

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
            eprintln!("Error reading config: {}", e);
            return;
        }
    };

    let sae_https_server = AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        &config.this_kme_config.saes_https_interface.listen_address,
        &config.this_kme_config.saes_https_interface.ca_client_cert_path,
        &config.this_kme_config.saes_https_interface.server_cert_path,
        &config.this_kme_config.saes_https_interface.server_key_path
    );

    let inter_kme_https_server = AuthHttpsServer::<InterKMEsRoutes>::new(
        &config.this_kme_config.kmes_https_interface.listen_address,
        &config.this_kme_config.kmes_https_interface.ca_client_cert_path,
        &config.this_kme_config.kmes_https_interface.server_cert_path,
        &config.this_kme_config.kmes_https_interface.server_key_path
    );

    let qkd_manager = QkdManager::from_config(&config).await.unwrap();

    match config.this_kme_config.debugging_http_interface {
        Some(listen_addr) => {
            let logging_http_server = Arc::new(LoggingHttpServer::new(&listen_addr));
            qkd_manager.add_important_event_subscriber(Arc::clone(&logging_http_server) as Arc<dyn ImportantEventSubscriber>).await.unwrap();
            select! {
                x = inter_kme_https_server.run(&qkd_manager) => {
                    error!("Error running inter-KMEs HTTPS server: {:?}", x);
                },
                x = sae_https_server.run(&qkd_manager) => {
                    error!("Error running SAEs HTTPS server: {:?}", x);
                },
                x = logging_http_server.run() => {
                    error!("Error running logging HTTP server: {:?}", x);
                }
            }
        },
        None => {
            select! {
                x = inter_kme_https_server.run(&qkd_manager) => {
                    error!("Error running inter-KMEs HTTPS server: {:?}", x);
                },
                x = sae_https_server.run(&qkd_manager) => {
                    error!("Error running SAEs HTTPS server: {:?}", x);
                }
            }
        }
    }
}