use std::sync::Arc;
use const_format::concatcp;
use log::error;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use tokio::select;
use qkd_kme_server::event_subscription::ImportantEventSubscriber;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;
use qkd_kme_server::server::log_http_server::LoggingHttpServer;

mod common;

#[tokio::test]
#[serial]
async fn test_key_transfer_from_file_config() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);

    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config.json";
    const CONFIG_FILE_PATH_KME2: &'static str = "tests/data/test_kme2_config.json";

    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/3/enc_keys");
    const INIT_POST_KEY_REQUEST_URL_2: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/enc_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL_2: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/3/dec_keys");
    const LOG_DEMO_REQUEST_URL_INDEX: &'static str = concatcp!("http://localhost:8080");
    const LOG_DEMO_REQUEST_URL_JSON_DATA: &'static str = concatcp!("http://localhost:8080/messages");

    const LOG_MESSAGE_STEP_1: &'static str = "[]";
    const LOG_MESSAGE_STEP_2: &'static str = "[\"[KME 1] SAE 1 requested a key to communicate with 3\",\"[KME 1] As SAE 3 belongs to KME 2, activating it through inter KMEs network\",\"[KME 1] Key 2ae3e385-4e51-7458-b1c1-69066a4cb6d7 activated between SAEs 1 and 3\"]";
    const LOG_MESSAGE_STEP_3: &'static str = "[\"[KME 1] SAE 1 requested a key to communicate with 3\",\"[KME 1] As SAE 3 belongs to KME 2, activating it through inter KMEs network\",\"[KME 1] Key 2ae3e385-4e51-7458-b1c1-69066a4cb6d7 activated between SAEs 1 and 3\",\"[KME 1] Key 9768257a-1c59-d255-a93d-d4bb1b693651 activated between SAEs 3 and 1\",\"[KME 1] SAE 1 requested key 9768257a-1c59-d255-a93d-d4bb1b693651 (from 3)\"]";

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME2).await;
    });

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();
    let log_demo_reqwest_client = reqwest::Client::new();

    let log_index_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_INDEX).send().await.unwrap();
    assert_eq!(log_index_response.status(), 200);
    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    assert_eq!(log_data_response.text().await.unwrap(), LOG_MESSAGE_STEP_1);

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    const EXPECTED_INIT_KEY_RESPONSE_BODY: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\",\n      \"key\": \"m0gAbsCqIwYgM2HMOcc8nkh6nhZG3EBAxuL6rgas1FU=\"\n    }\n  ]\n}";
    assert_eq!(post_key_response.text().await.unwrap().replace("\r", ""), EXPECTED_INIT_KEY_RESPONSE_BODY);

    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    assert_eq!(log_data_response.text().await.unwrap(), LOG_MESSAGE_STEP_2);

    const REMOTE_DEC_KEYS_REQ_BODY: &'static str = "{\n\"key_IDs\": [{\"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\"}]\n}";
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(REMOTE_DEC_KEYS_REQ_BODY).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    const REMOTE_DEC_KEYS_EPECTED_RESP_BODY: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\",\n      \"key\": \"m0gAbsCqIwYgM2HMOcc8nkh6nhZG3EBAxuL6rgas1FU=\"\n    }\n  ]\n}";
    assert_eq!(req_key_remote_response.text().await.unwrap().replace("\r", ""), REMOTE_DEC_KEYS_EPECTED_RESP_BODY);

    let post_key_response = sae2_reqwest_client.post(INIT_POST_KEY_REQUEST_URL_2).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    const EXPECTED_BODY_ENC_KEY_2: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"9768257a-1c59-d255-a93d-d4bb1b693651\",\n      \"key\": \"zNK/zOIUDAFyuKRM0dSJLLZVYaDTuhzhAIACBgWABfY=\"\n    }\n  ]\n}";
    assert_eq!(post_key_response.text().await.unwrap().replace("\r", ""), EXPECTED_BODY_ENC_KEY_2);

    const DEC_REK_REQ_BODY_2: &'static str = "{\n\"key_IDs\": [{\"key_ID\": \"9768257a-1c59-d255-a93d-d4bb1b693651\"}]\n}";
    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(DEC_REK_REQ_BODY_2).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    const EXPECTED_BODY_DEC_KEY_2: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"9768257a-1c59-d255-a93d-d4bb1b693651\",\n      \"key\": \"zNK/zOIUDAFyuKRM0dSJLLZVYaDTuhzhAIACBgWABfY=\"\n    }\n  ]\n}";
    assert_eq!(req_key_remote_response.text().await.unwrap().replace("\r", ""), EXPECTED_BODY_DEC_KEY_2);

    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    assert_eq!(log_data_response.text().await.unwrap(), LOG_MESSAGE_STEP_3);
}

// Quite similar to program's main function
async fn launch_kme_from_config_file(config_file_path: &str) {
    let config = qkd_kme_server::config::Config::from_json_path(config_file_path).unwrap();

    let sae_https_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        &config.this_kme_config.saes_https_interface.listen_address,
        &config.this_kme_config.saes_https_interface.ca_client_cert_path,
        &config.this_kme_config.saes_https_interface.server_cert_path,
        &config.this_kme_config.saes_https_interface.server_key_path,
    );

    let inter_kme_https_server = qkd_kme_server::server::auth_https_server::AuthHttpsServer::<InterKMEsRoutes>::new(
        &config.this_kme_config.kmes_https_interface.listen_address,
        &config.this_kme_config.kmes_https_interface.ca_client_cert_path,
        &config.this_kme_config.kmes_https_interface.server_cert_path,
        &config.this_kme_config.kmes_https_interface.server_key_path,
    );

    let qkd_manager = QkdManager::from_config(&config);
    let qkd_manager = qkd_manager.unwrap();

    match config.this_kme_config.debugging_http_interface {
        Some(listen_addr) => {
            let logging_http_server = Arc::new(LoggingHttpServer::new(&listen_addr));
            qkd_manager.add_important_event_subscriber(Arc::clone(&logging_http_server) as Arc<dyn ImportantEventSubscriber>).unwrap();
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