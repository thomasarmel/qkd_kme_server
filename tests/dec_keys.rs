use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use crate::common::objects::{MasterKeyRequestObj, RequestKeyId, RequestListKeysIds, ResponseQkdKeysList};
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn post_dec_keys() {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();


    let post_key_response = reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let post_key_response_text = post_key_response.text().await.unwrap();
    let post_key_response_list: ResponseQkdKeysList = serde_json::from_str(&post_key_response_text).unwrap();
    assert_eq!(post_key_response_list.keys.len(), 1);

    let dec_key_list = RequestListKeysIds {
        key_IDs: vec![
            RequestKeyId {
                key_ID: post_key_response_list.keys[0].key_ID.clone()
            },
            RequestKeyId {
                key_ID: post_key_response_list.keys[0].key_ID.clone()
            }
        ]
    };
    let dec_key_list_body = serde_json::to_string(&dec_key_list).unwrap();
    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(dec_key_list_body).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    let response_list: ResponseQkdKeysList = serde_json::from_str(&response_body).unwrap();
    assert_eq!(response_list.keys.len(), 2);
}

#[tokio::test]
#[serial]
async fn get_dec_keys() {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();


    let post_key_response = reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    let response_body = post_key_response.text().await.unwrap();
    let response_body_obj: ResponseQkdKeysList = serde_json::from_str(&response_body).unwrap();
    assert_eq!(response_body_obj.keys.len(), 1);

    let response = reqwest_client.get(format!("{}?key_ID={}", REQUEST_URL, response_body_obj.keys[0].key_ID)).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    let response_body_obj: ResponseQkdKeysList = serde_json::from_str(&response_body).unwrap();
    assert_eq!(response_body_obj, response_body_obj);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_multiple() {
    const EXPECTED_BODY: &'static str = include_str!("data/dec_keys_multiple.json");
    const SENT_BODY: &'static str = include_str!("data/dec_keys_post_req_body_multiple.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(3)
    };

    let post_key_response = reqwest_client.post(INIT_POST_KEY_REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_multiple_all_inserted_at_once() {
    const EXPECTED_BODY: &'static str = include_str!("data/dec_keys_multiple.json");
    const SENT_BODY: &'static str = include_str!("data/dec_keys_post_req_body_multiple.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup_all_keys_inserted_at_once().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(3)
    };

    let post_key_response = reqwest_client.post(INIT_POST_KEY_REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_not_init() {
    const EXPECTED_BODY: &'static str = include_str!("data/not_found_body.json");
    const SENT_BODY: &'static str = include_str!("data/dec_keys_post_req_body.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 404);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_no_body() {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_wrong_body() {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const SENT_BODY: &'static str = include_str!("data/dec_keys_post_req_wrong_body.json");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 400);
}