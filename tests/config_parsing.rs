use const_format::concatcp;
use log::error;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use tokio::select;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;

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

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME2).await;
    });

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    const EXPECTED_INIT_KEY_RESPONSE_BODY: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\",\n      \"key\": \"m0gAbsCqIwYgM2HMOcc8nkh6nhZG3EBAxuL6rgas1FU=\"\n    }\n  ]\n}";
    assert_eq!(post_key_response.text().await.unwrap().replace("\r", ""), EXPECTED_INIT_KEY_RESPONSE_BODY);

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
}

// Quite similar to program's main function
async fn launch_kme_from_config_file(config_file_path: &str) {
    let config = qkd_kme_server::config::Config::from_json_path(config_file_path).unwrap();

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

    let qkd_manager = QkdManager::from_config(&config);
    let qkd_manager = qkd_manager.unwrap();

    select! {
        x = inter_kme_https_server.run::<InterKMEsRoutes>(&qkd_manager) => {
            error!("Error running inter-KMEs HTTPS server: {:?}", x);
        },
        x = sae_https_server.run::<EtsiSaeQkdRoutesV1>(&qkd_manager) => {
            error!("Error running SAEs HTTPS server: {:?}", x);
        }
    }
}