use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
async fn post_dec_keys() {
    const EXPECTED_BODY: &'static str = include_str!("data/dec_keys.json");
    const SENT_BODY: &'static str = include_str!("data/dec_keys_post_req_body.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_eq!(response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn post_dec_keys_no_body() {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");

    common::setup();
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

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.post(REQUEST_URL).header(CONTENT_TYPE, "application/json").body(SENT_BODY).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 400);
}