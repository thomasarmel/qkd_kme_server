use const_format::concatcp;
use reqwest::header::CONTENT_TYPE;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
async fn test_key_transfer_other_kme() {
    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);
    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const EXPECTED_INIT_KEY_RESPONSE_BODY: &'static str = include_str!("data/enc_keys.json");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::REMOTE_KME_HOST_PORT ,"/api/v1/keys/1/dec_keys");
    const REMOTE_DEC_KEYS_REQ_BODY: &'static str = include_str!("data/dec_keys_post_req_body.json");
    const REMOTE_DEC_KEYS_EPECTED_RESP_BODY: &'static str = include_str!("data/dec_keys.json");

    common::setup_2_kmes_network();

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_remote_kme();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    assert_eq!(post_key_response.text().await.unwrap(), EXPECTED_INIT_KEY_RESPONSE_BODY);

    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(REMOTE_DEC_KEYS_REQ_BODY).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    assert_eq!(req_key_remote_response.text().await.unwrap(), REMOTE_DEC_KEYS_EPECTED_RESP_BODY);
}

// TODO: non existing, bi directional transfer etc...