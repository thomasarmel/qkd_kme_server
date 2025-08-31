use crate::common::launch_kme_from_config_file;
use const_format::concatcp;
use hyper::header::CONTENT_TYPE;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
async fn test_sqlite_file() {
    const CONFIG_FILE_PATH_KME1: &'static str = "tests/data/test_kme_config_sqlite.json5";

    const INIT_POST_KEY_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/2/enc_keys");
    const REMOTE_DEC_KEYS_REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/1/dec_keys");

    tokio::spawn(async move {
        launch_kme_from_config_file(CONFIG_FILE_PATH_KME1).await;
    });

    let sae1_reqwest_client = common::setup_cert_auth_reqwest_client();
    let sae2_reqwest_client = common::setup_cert_auth_reqwest_client_2();

    let post_key_response = sae1_reqwest_client.post(INIT_POST_KEY_REQUEST_URL).send().await;
    assert!(post_key_response.is_ok());
    let post_key_response = post_key_response.unwrap();
    assert_eq!(post_key_response.status(), 200);
    const EXPECTED_INIT_KEY_RESPONSE_BODY: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\",\n      \"key\": \"m0gAbsCqIwYgM2HMOcc8nkh6nhZG3EBAxuL6rgas1FU=\"\n    }\n  ]\n}";
    assert_eq!(post_key_response.text().await.unwrap().replace("\r", ""), EXPECTED_INIT_KEY_RESPONSE_BODY);

    const REMOTE_DEC_KEYS_REQ_BODY: &'static str = "{\n\"key_IDs\": [{\"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\"}]\n}";
    let req_key_remote_response = sae2_reqwest_client.post(REMOTE_DEC_KEYS_REQUEST_URL).header(CONTENT_TYPE, "application/json").body(REMOTE_DEC_KEYS_REQ_BODY).send().await;
    assert!(req_key_remote_response.is_ok());
    let req_key_remote_response = req_key_remote_response.unwrap();
    assert_eq!(req_key_remote_response.status(), 200);
    const REMOTE_DEC_KEYS_EXPECTED_RESP_BODY: &'static str = "{\n  \"keys\": [\n    {\n      \"key_ID\": \"2ae3e385-4e51-7458-b1c1-69066a4cb6d7\",\n      \"key\": \"m0gAbsCqIwYgM2HMOcc8nkh6nhZG3EBAxuL6rgas1FU=\"\n    }\n  ]\n}";
    assert_eq!(req_key_remote_response.text().await.unwrap().replace("\r", ""), REMOTE_DEC_KEYS_EXPECTED_RESP_BODY);
}