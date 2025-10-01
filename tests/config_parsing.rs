use crate::common::launch_kme_from_config_file;
use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use crate::common::objects::{RequestKeyId, RequestListKeysIds, ResponseQkdKeysList};

mod common;

#[tokio::test]
#[serial]
async fn test_key_transfer_from_file_config() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);

    #[cfg(not(target_os = "macos"))]
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config.json5";
    #[cfg(target_os = "macos")]
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config_macos.json5";
    #[cfg(not(target_os = "macos"))]
    const CONFIG_FILE_PATH_KME2: &'static str = "tests/data/test_kme2_config.json5";
    #[cfg(target_os = "macos")]
    const CONFIG_FILE_PATH_KME2: &'static str = "tests/data/test_kme2_config_macos.json5";

    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/3/enc_keys");
    const INIT_POST_KEY_REQUEST_URL_2: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/enc_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL_2: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/3/dec_keys");
    const LOG_DEMO_REQUEST_URL_INDEX: &'static str = concatcp!("http://localhost:8080");
    const LOG_DEMO_REQUEST_URL_JSON_DATA: &'static str = concatcp!("http://localhost:8080/messages");


    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME2).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();
    let log_demo_reqwest_client = reqwest::Client::new();

    let log_index_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_INDEX).send().await.unwrap();
    assert_eq!(log_index_response.status(), 200);
    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    assert_eq!(log_data_response.text().await.unwrap(), "[]");

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let post_key_response = post_key_response.text().await.unwrap();
    let post_key_response_list: ResponseQkdKeysList = serde_json::from_str(&post_key_response).unwrap();
    assert_eq!(post_key_response_list.keys.len(), 1);

    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    let text_log_message = log_data_response.text().await.unwrap();
    assert!(text_log_message.contains("[Alice] SAE 1 requested a key to communicate with 3"));
    assert!(text_log_message.contains("[Alice] As SAE 3 belongs to KME 2, activating it through inter KMEs network"));
    assert!(text_log_message.contains(format!("[Alice] Key {} activated between SAEs 1 and 3", post_key_response_list.keys[0].key_ID).as_str()));

    let remote_dec_keys_req = RequestListKeysIds {
        key_IDs: vec![RequestKeyId { key_ID: post_key_response_list.keys[0].key_ID.clone() }]
    };
    let remote_dec_keys_req_body = serde_json::to_string(&remote_dec_keys_req).unwrap();
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(remote_dec_keys_req_body).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    let req_key_remote_response_text = req_key_remote_response.text().await.unwrap();
    let req_key_remote_response_list: ResponseQkdKeysList = serde_json::from_str(&req_key_remote_response_text).unwrap();
    assert_eq!(req_key_remote_response_list, post_key_response_list);

    let post_key_response = sae2_reqwest_client.post(INIT_POST_KEY_REQUEST_URL_2).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let post_key_response2 = post_key_response.text().await.unwrap();
    let post_key_response_list2: ResponseQkdKeysList = serde_json::from_str(&post_key_response2).unwrap();
    assert_eq!(post_key_response_list2.keys.len(), 1);

    let remote_dec_keys_req2 = RequestListKeysIds {
        key_IDs: vec![RequestKeyId { key_ID: post_key_response_list2.keys[0].key_ID.clone() }]
    };
    let remote_dec_keys_req_body2 = serde_json::to_string(&remote_dec_keys_req2).unwrap();
    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(remote_dec_keys_req_body2).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    let req_key_remote_response_text2 = req_key_remote_response.text().await.unwrap();
    let req_key_remote_response_list2: ResponseQkdKeysList = serde_json::from_str(&req_key_remote_response_text2).unwrap();
    assert_eq!(req_key_remote_response_list2, post_key_response_list2);

    let log_data_response = log_demo_reqwest_client.get(LOG_DEMO_REQUEST_URL_JSON_DATA).send().await.unwrap();
    assert_eq!(log_data_response.status(), 200);
    let text_log_message = log_data_response.text().await.unwrap();
    assert!(text_log_message.contains("[Alice] SAE 1 requested a key to communicate with 3"));
    assert!(text_log_message.contains("[Alice] As SAE 3 belongs to KME 2, activating it through inter KMEs network"));
    assert!(text_log_message.contains(format!("[Alice] Key {} activated between SAEs 1 and 3", req_key_remote_response_list.keys[0].key_ID).as_str()));
    assert!(text_log_message.contains(format!("[Alice] Key {} activated between SAEs 3 and 1", req_key_remote_response_list2.keys[0].key_ID).as_str()));
    assert!(text_log_message.contains(format!("[Alice] SAE 1 requested key {} (from 3)", req_key_remote_response_list2.keys[0].key_ID).as_str()));
}