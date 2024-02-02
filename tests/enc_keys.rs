use const_format::concatcp;
use serial_test::serial;

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
    assert_eq!(response_body, EXPECTED_BODY);
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
    assert_eq!(response_body, EXPECTED_BODY);
}