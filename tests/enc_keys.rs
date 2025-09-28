use const_format::concatcp;
use std::collections::HashMap;
use serial_test::serial;
use crate::common::objects::MasterKeyRequestObj;
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn post_enc_keys() {
    const EXPECTED_BODY: &'static str = include_str!("data/enc_keys.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn get_enc_keys() {
    const EXPECTED_BODY: &'static str = include_str!("data/enc_keys.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_enc_keys_fuzz1() {
    const EXPECTED_BODY: &'static str = include_str!("data/enc_keys.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    // POST body = "null"
    let response = reqwest_client.post(REQUEST_URL).json(&None::<MasterKeyRequestObj>).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);

    // POST body = "[]"
    let response = reqwest_client.post(REQUEST_URL).json(&Vec::<MasterKeyRequestObj>::new()).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_enc_keys_fuzz2() {
    const EXPECTED_BODY: &'static str = include_str!("data/enc_keys.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    // POST body = "{}"
    let response = reqwest_client.post(REQUEST_URL).json(&HashMap::<i64, i64>::new()).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_enc_keys_multiple() {
    const EXPECTED_BODY_2_KEYS: &'static str = include_str!("data/enc_keys_multiple.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(2)
    };
    let response = reqwest_client.post(REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY_2_KEYS);

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(11)
    };
    let response = reqwest_client.post(REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
#[serial]
async fn get_enc_keys_multiple() {
    const EXPECTED_BODY_2_KEYS: &'static str = include_str!("data/enc_keys_multiple.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.get(concatcp!(REQUEST_URL, "?number=2")).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY_2_KEYS);

    let response = reqwest_client.get(concatcp!(REQUEST_URL, "?number=11")).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
#[serial]
async fn post_enc_keys_not_enough() {
    const EXPECTED_BODY_NOT_ENOUGH: &'static str = include_str!("data/enc_keys_not_enough.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let key_request_json_body = MasterKeyRequestObj {
        number: Some(10)
    };
    let response = reqwest_client.post(REQUEST_URL).json(&key_request_json_body).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY_NOT_ENOUGH);
}

#[tokio::test]
#[serial]
async fn post_enc_keys_sae_not_found() {
    const EXPECTED_BODY: &'static str = include_str!("data/not_found_body.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 404);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}