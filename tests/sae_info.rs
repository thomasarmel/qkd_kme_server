use const_format::concatcp;
use serial_test::serial;
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn get_sae_info_me() {
    const EXPECTED_BODY: &'static str = include_str!("data/sae_info_me.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/sae/info/me");

    common::setup().await;
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
async fn get_sae_info_me_unregistered_sae() {
    const EXPECTED_BODY: &'static str = include_str!("data/not_found_body.json");
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/sae/info/me");

    common::setup().await;
    let reqwest_client = common::setup_cert_auth_reqwest_client_unregistered_sae();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 404);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}