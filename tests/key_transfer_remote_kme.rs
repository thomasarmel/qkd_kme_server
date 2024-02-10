use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;
use crate::common::util::assert_string_equal;

mod common;

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const INIT_POST_KEY_REQUEST_URL_2: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_BODY: &'static str = include_str!("data/enc_keys.json");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL_2: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/dec_keys");
    const REMOTE_DEC_KEYS_REQ_BODY: &'static str = include_str!("data/dec_keys_post_req_body.json");
    const REMOTE_DEC_KEYS_EPECTED_RESP_BODY: &'static str = include_str!("data/dec_keys.json");
    const NOT_FOUND_BODY: &'static str = include_str!("data/not_found_body.json");

    common::setup_2_kmes_network();

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_BODY);

    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(REMOTE_DEC_KEYS_REQ_BODY).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    assert_string_equal(&req_key_remote_response.text().await.unwrap(), REMOTE_DEC_KEYS_EPECTED_RESP_BODY);

    let post_key_response = sae2_reqwest_client.post(INIT_POST_KEY_REQUEST_URL_2).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    const EXPECTED_BODY_ENC_KEY_2: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"4567f16a-843b-f659-9af6-d2126cb97e16\",\n      \"key\": \"dGhpc19pc19zZWNyZXRfa2V5XzJfb2ZfMzJfYnl0ZXM=\"\n    }\n  ]\n}";
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_BODY_ENC_KEY_2);

    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(REMOTE_DEC_KEYS_REQ_BODY).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 404);
    assert_string_equal(&req_key_remote_response.text().await.unwrap(), NOT_FOUND_BODY);

    const DEC_KEY_REQ_BODY_2: &'static str = "{\n\"key_IDs\": [{\"key_ID\": \"4567f16a-843b-f659-9af6-d2126cb97e16\"}]\n}";
    let req_key_remote_response = sae1_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL_2).header(CONTENT_TYPE, "application/json").body(DEC_KEY_REQ_BODY_2).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    const EXPECTED_BODY_DEC_KEY_2: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"4567f16a-843b-f659-9af6-d2126cb97e16\",\n      \"key\": \"dGhpc19pc19zZWNyZXRfa2V5XzJfb2ZfMzJfYnl0ZXM=\"\n    }\n  ]\n}";
    assert_string_equal(&req_key_remote_response.text().await.unwrap(), EXPECTED_BODY_DEC_KEY_2);
}

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme_down() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_BODY_GATEWAY_ERROR: &'static str = include_str!("data/gateway_timeout_kme_body.json");

    common::setup_2_kmes_network_1_kme_down();

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

    common::setup_2_kmes_network_missing_conf();

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

    common::setup_2_kmes_network_keys_not_sync();

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 409);
    assert_string_equal(&post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_CONFLICT);
}