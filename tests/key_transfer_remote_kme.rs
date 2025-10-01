use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use crate::common::objects::{MasterKeyRequestObj, RequestKeyId, RequestListKeysIds, ResponseQkdKeysList};
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const INIT_POST_KEY_REQUEST_URL_2: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/enc_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL_2: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/dec_keys");
    const NOT_FOUND_BODY: &'static str = include_str!("data/not_found_body.json");

    common::setup_2_kmes_network().await;

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let post_response_text = post_key_response.text().await.unwrap();
    let post_response: ResponseQkdKeysList = serde_json::from_str(&post_response_text).unwrap();
    assert_eq!(post_response.keys.len(), 1);

    let req_key_list = RequestListKeysIds {
        key_IDs: vec![
            RequestKeyId {
                key_ID: post_response.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: post_response.keys[0].key_ID.clone()
            }
        ],
    };
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(serde_json::to_string(&req_key_list).unwrap()).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    let response_text = req_key_remote_response.text().await.unwrap();
    let response_remote: ResponseQkdKeysList = serde_json::from_str(&response_text).unwrap();
    assert_eq!(response_remote.keys.len(), 2);
    assert_eq!(response_remote.keys[0], post_response.keys[0]);

    let post_key_response = sae2_reqwest_client.post(INIT_POST_KEY_REQUEST_URL_2).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let post_response_text = post_key_response.text().await.unwrap();
    let post_response: ResponseQkdKeysList = serde_json::from_str(&post_response_text).unwrap();
    assert_eq!(post_response.keys.len(), 1);

    let req_key_list2 = RequestListKeysIds {
        key_IDs: vec![
            RequestKeyId {
                key_ID: post_response.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: post_response.keys[0].key_ID.clone()
            }
        ],
    };
    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(serde_json::to_string(&req_key_list).unwrap()).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 404);
    assert_string_equal(&req_key_remote_response.text().await.unwrap(), NOT_FOUND_BODY);

    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(serde_json::to_string(&req_key_list2).unwrap()).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    let response_text = req_key_remote_response.text().await.unwrap();
    let response_remote: ResponseQkdKeysList = serde_json::from_str(&response_text).unwrap();
    assert_eq!(response_remote.keys.len(), 2);
    assert_eq!(response_remote.keys[0], post_response.keys[0]);
}

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme_multiple() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");

    common::setup_2_kmes_network().await;

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(2)
    };

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let response_text = post_key_response.text().await.unwrap();
    let response: ResponseQkdKeysList = serde_json::from_str(&response_text).unwrap();

    // one key is not activated
    let req_key_list_one_not_activated = RequestListKeysIds {
        key_IDs: vec![
            RequestKeyId {
                key_ID: response.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: response.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: "6f618eb1-c354-4851-0000-bd9685766569".to_string()
            }
        ],
    };
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(serde_json::to_string(&req_key_list_one_not_activated).unwrap()).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 404);

    let req_key_list_all_activated = RequestListKeysIds {
        key_IDs: vec![
            RequestKeyId {
                key_ID: response.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: response.keys[1].key_ID.clone()
            }
        ],
    };
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(serde_json::to_string(&req_key_list_all_activated).unwrap()).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    let response_text = req_key_remote_response.text().await.unwrap();
    let response_remote: ResponseQkdKeysList = serde_json::from_str(&response_text).unwrap();
    assert_eq!(response_remote, response);
}

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme_down() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_BODY_GATEWAY_ERROR: &'static str = include_str!("data/gateway_timeout_kme_body.json");

    common::setup_2_kmes_network_1_kme_down().await;

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 504);
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_BODY_GATEWAY_ERROR);
}

#[tokio::test]
#[serial]
async fn test_key_transfer_missing_other_kme_conf() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_BODY_PRECONDITION_FAILED: &'static str = include_str!("data/precondition_failed_body.json");

    common::setup_2_kmes_network_missing_conf().await;

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 412);
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_BODY_PRECONDITION_FAILED);
}

#[tokio::test]
#[serial]
async fn test_key_transfer_keys_not_sync() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_CONFLICT: &'static str = include_str!("data/conflict_body.json");

    common::setup_2_kmes_network_keys_not_sync().await;

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 409);
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_CONFLICT);
}