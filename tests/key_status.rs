use const_format::concatcp;
use serial_test::serial;
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn get_key_status() {
    const EXPECTED_BODY: &'static str = include_str!("data/key_status.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/status");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}