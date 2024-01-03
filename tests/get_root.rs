use const_format::concatcp;
use serial_test::serial;

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
    assert_eq!(response_body, EXPECTED_BODY);
}

#[tokio::test]
#[serial]
async fn get_root_directory_bad_cert_auth() {
    const CONNECTION_RESET_ERROR: &'static str = "Connection reset by peer (os error 104)";

    common::setup();
    let reqwest_client = common::setup_cert_auth_reqwest_bad_client();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_err());
    let response_error = response.unwrap_err();
    assert!(response_error.to_string().contains(CONNECTION_RESET_ERROR));
}

#[tokio::test]
#[serial]
async fn get_root_directory_no_cert_auth() {
    const CERTIFICATE_REQUIRED_ERROR: &'static str = "certificate required";

    common::setup();
    let reqwest_client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();

    let response = reqwest_client.get(REQUEST_URL).send().await;
    assert!(response.is_err());
    assert!(response.unwrap_err().to_string().contains(CERTIFICATE_REQUIRED_ERROR));
}