// Author: Jeff
// Date: 2026-07-31
// Description: Deterministic in-process SSRF acceptance benchmark
// Notes: All listeners use ephemeral loopback ports and require no Internet access

mod support;

use support::{RequestCounter, SsrfBenchmark};

#[tokio::test]
async fn vulnerable_endpoint_performs_one_outbound_get() {
    let callback = RequestCounter::start().await;
    let target = SsrfBenchmark::start().await;

    let response = reqwest::get(target.vulnerable_url(callback.url("probe-1")))
        .await
        .expect("call vulnerable endpoint");

    assert!(response.status().is_success());
    callback.wait_for_requests(1).await;
    assert_eq!(callback.paths(), vec!["/probe-1"]);
    assert_eq!(target.vulnerable_requests(), 1);
}

#[tokio::test]
async fn secure_endpoint_does_not_contact_supplied_url() {
    let callback = RequestCounter::start().await;
    let target = SsrfBenchmark::start().await;

    let response = reqwest::get(target.secure_url(callback.url("probe-2")))
        .await
        .expect("call secure endpoint");

    assert!(response.status().is_success());
    callback.assert_no_requests().await;
    assert!(callback.paths().is_empty());
    assert_eq!(target.secure_requests(), 1);
}
