use crate::common::launch_kme_from_config_file;
use crate::common::objects::{RequestKeyId, RequestListKeysIds, ResponseQkdKeysList};
use const_format::concatcp;
use hyper::header::CONTENT_TYPE;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
#[ignore]
async fn test_sqlite_file() {
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config_sqlite.json5";

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    generic_persistency_test().await
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_postgres() {
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config_postgres.json5";

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    generic_persistency_test().await
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_mysql() {
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config_mysql.json5";

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });
    generic_persistency_test().await
}

async fn generic_persistency_test() {
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const STATUS_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/status");

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_2();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let enc_response_text = post_key_response.text().await.unwrap();

    let enc_keys_list: ResponseQkdKeysList = serde_json::from_str(&enc_response_text).unwrap();
    assert_eq!(enc_keys_list.keys.len(), 1);

    let req_dec_key_obj = RequestListKeysIds {
        key_IDs: vec![RequestKeyId { key_ID: enc_keys_list.keys[0].key_ID.clone() }],
    };
    let req_key_remote_response = sae2_reqwest_client
        .post(DEC_KEYS_REQUEST_URL)
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_string_pretty(&req_dec_key_obj).unwrap())
        .send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);

    let dec_response_text = req_key_remote_response.text().await.unwrap();
    let dec_keys_list: ResponseQkdKeysList = serde_json::from_str(&dec_response_text).unwrap();
    assert_eq!(dec_keys_list.keys.len(), 1);
    assert_eq!(dec_keys_list.keys[0], enc_keys_list.keys[0]);

    // Another request to check if DELETE worked correctly
    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let enc_response_text = post_key_response.text().await.unwrap();

    let enc_keys_list2: ResponseQkdKeysList = serde_json::from_str(&enc_response_text).unwrap();
    assert_eq!(enc_keys_list2.keys.len(), 1);

    let req_dec_key_obj = RequestListKeysIds {
        key_IDs: vec![RequestKeyId { key_ID: enc_keys_list2.keys[0].key_ID.clone() }],
    };
    let req_key_remote_response = sae2_reqwest_client
        .post(DEC_KEYS_REQUEST_URL)
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_string_pretty(&req_dec_key_obj).unwrap())
        .send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);

    let dec_response_text = req_key_remote_response.text().await.unwrap();
    let dec_keys_list2: ResponseQkdKeysList = serde_json::from_str(&dec_response_text).unwrap();
    assert_eq!(dec_keys_list2.keys.len(), 1);
    assert_eq!(dec_keys_list2.keys[0], enc_keys_list2.keys[0]);
    assert_ne!(dec_keys_list.keys[0], dec_keys_list2.keys[0]);

    let status_key_response = sae1_reqwest_client.get(STATUS_REQUEST_URL).send().await;
    assert!(status_key_response.is_ok());
    let status_key_response = status_key_response.unwrap();
    assert_eq!(status_key_response.status(), 200);
    let status_response_text = status_key_response.text().await.unwrap();
    let status_obj: common::objects::ResponseQkdKeysStatus = serde_json::from_str(&status_response_text).unwrap();
    assert_eq!(status_obj.source_KME_ID, "1");
    assert_eq!(status_obj.target_KME_ID, "1");
    assert_eq!(status_obj.master_SAE_ID, "1");
    assert_eq!(status_obj.slave_SAE_ID, "2");
    assert_eq!(status_obj.stored_key_count, 10);
    assert_eq!(status_obj.max_key_count, 10);
    assert_eq!(status_obj.max_key_per_request, 10);
}