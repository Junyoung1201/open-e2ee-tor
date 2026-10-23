//! Real-network check of the embedded Tor client (ignored by default):
//! bootstrap Arti and make an HTTP request to a public onion service.
//!
//! ```text
//! O2EE_TOR_SMOKE_ONION=<address>.onion cargo test -p o2ee --test tor_smoke -- --ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use hyper::Method;
use o2ee::net::Net;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Tor network"]
async fn embedded_tor_reaches_an_onion_service() {
    let onion = std::env::var("O2EE_TOR_SMOKE_ONION").unwrap_or_else(|_| {
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".into()
    });
    let dir = tempfile::tempdir().unwrap();
    let net = Net::tor(&onion, dir.path()).await.unwrap();
    assert!(net.is_tor());
    let res = net
        .send(Method::GET, "/", None, &[], Bytes::new())
        .await
        .unwrap();
    // Any HTTP answer proves the onion circuit and the HTTP layer work.
    assert!(res.status().as_u16() >= 200);
}
