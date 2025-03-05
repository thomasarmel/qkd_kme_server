use const_format::concatcp;
use serial_test::serial;
use crate::common::util::assert_string_equal;

mod common;

const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/");

#[tokio::test]
#[serial]
async fn get_root_directory_good_cert_auth() {
    const EXPECTED_BODY: &'static str = include_str!("data/not_found_body.json");

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_client();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 404);
    let response_body = response.text().await.unwrap();
    assert_string_equal(&response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn get_root_directory_bad_cert_auth() {
    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_bad_client();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_err());
}

#[tokio::test]
#[serial]
async fn get_root_directory_no_cert_auth() {
    common::setup();
    let reqwest_client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_err());
}