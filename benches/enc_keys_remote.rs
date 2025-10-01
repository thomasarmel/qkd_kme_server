use const_format::concatcp;
use criterion::{criterion_group, criterion_main, Criterion};
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;

mod common;

fn spawn_server() {
    #[cfg(not(target_os = "macos"))]
    const CONFIG_KME1_PATH: &'static str = "benches/data/test_kme_config.json5";
    #[cfg(target_os = "macos")]
    const CONFIG_KME1_PATH: &'static str = "benches/data/test_kme_config_macos.json5";

    #[cfg(not(target_os = "macos"))]
    const CONFIG_KME2_PATH: &'static str = "benches/data/test_kme2_config.json5";
    #[cfg(target_os = "macos")]
    const CONFIG_KME2_PATH: &'static str = "benches/data/test_kme2_config_macos.json5";

    thread::spawn(|| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            common::launch_kme_from_config_file(CONFIG_KME1_PATH).await
        });
    });
    thread::spawn(|| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            common::launch_kme_from_config_file(CONFIG_KME2_PATH).await
        });
    });

    thread::sleep(Duration::from_millis(500));
}

fn bench_enc_keys(c: &mut Criterion) {
    const REQUEST_URL: &'static str = concatcp!("https://", common::HOST_PORT ,"/api/v1/keys/3/enc_keys");

    std::env::set_var(qkd_kme_server::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE, qkd_kme_server::ACTIVATED_ENV_VARIABLE_VALUE);

    spawn_server();

    let rt = Runtime::new().unwrap();
    let client = common::setup_cert_auth_reqwest_client();

    c.bench_function("5 GET enc_keys", |b| {
        b.to_async(&rt).iter(|| async {
            let futures = (0..5).map(|_| client.get(REQUEST_URL).send());
            let responses: Vec<_> = futures::future::join_all(futures).await;

            for resp in responses {
                let resp = resp.unwrap();
                assert!(resp.status().is_success());
            }
        })
    });
}



criterion_group!(benches, bench_enc_keys);
criterion_main!(benches);