// SPDX-License-Identifier: GPL-2.0-only

//! Provider integration uses isolated container DNS, never the workstation's resolver or APIs.

#[path = "dns_providers/dns.rs"]
mod dns;
#[path = "dns_providers/https.rs"]
mod https;
#[path = "dns_providers/manual.rs"]
mod manual;

use std::{
    error::Error,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use serde_json::json;

use super::{ProcessFixture, RecoveryScenario, challenge::ValidationTarget, prove_lifecycle};

type Failure = Box<dyn Error + Send + Sync>;
const BEARER: &str = "meshspan-test-provider-token-not-a-real-credential";
const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";
const RECORD_ID: &str = "abcdef0123456789abcdef0123456789";
const UNRELATED_TXT: &str = "unrelated-record-must-survive";

#[derive(Clone, Copy)]
enum Provider {
    Cloudflare,
    Webhook,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    name: String,
    value: String,
    ownership: String,
}

#[derive(Default)]
struct Records {
    managed: Option<Record>,
    publications: usize,
    removals: usize,
    positive_probes: usize,
    discovery_queries: usize,
}

type SharedRecords = Arc<Mutex<Records>>;

#[tokio::test]
#[ignore = "requires a dedicated offline Linux container with loopback DNS and HTTPS origins"]
async fn cloudflare_dns01_issues_cleans_and_reuses_one_certificate() -> Result<(), Box<dyn Error>> {
    prove_provider(Provider::Cloudflare).await
}

#[tokio::test]
#[ignore = "requires a dedicated offline Linux container with loopback DNS and HTTPS origins"]
async fn webhook_dns01_issues_cleans_and_reuses_one_certificate() -> Result<(), Box<dyn Error>> {
    prove_provider(Provider::Webhook).await
}

async fn prove_provider(provider: Provider) -> Result<(), Box<dyn Error>> {
    require_isolated_dns().await?;
    let records = SharedRecords::default();
    let dns = dns::Server::start(Arc::clone(&records))
        .await
        .map_err(|error| error.to_string())?;
    let https = https::Server::start(provider, Arc::clone(&records)).await?;
    let settings = match provider {
        Provider::Cloudflare => json!({
            "kind": "dns01_cloudflare", "zone_id": ZONE_ID, "api_token": BEARER
        }),
        Provider::Webhook => json!({
            "kind": "dns01_webhook", "endpoint": https.endpoint, "bearer_token": BEARER
        }),
    };
    let proof = prove_lifecycle(
        ProcessFixture::new()?,
        ValidationTarget::Dns01("127.0.0.1:53".parse()?),
        settings,
        RecoveryScenario::Normal,
        Some(&https.anchor_pem),
    )
    .await;
    let https_result = https.stop().await;
    let dns_result = dns.stop().await.map_err(|error| error.to_string());
    proof?;
    https_result?;
    dns_result?;
    let state = records.lock().map_err(|_| "DNS records poisoned")?;
    assert!(
        state.managed.is_none(),
        "owned TXT record remains published"
    );
    assert_eq!(state.publications, 1, "duplicate TXT creation");
    assert_eq!(state.removals, 1, "exact TXT cleanup did not happen once");
    assert!(
        state.discovery_queries > 0,
        "daemon did not discover DNS authority"
    );
    assert!(
        state.positive_probes >= 2,
        "daemon and CA must both probe actual DNS"
    );
    Ok(())
}

/// Refuse ordinary host execution before opening a privileged listener or contacting a provider.
async fn require_isolated_dns() -> Result<(), Box<dyn Error>> {
    if !cfg!(target_os = "linux")
        || std::env::var("MESHSPAN_DNS_PROVIDER_PROOF").as_deref() != Ok("1")
    {
        return Err("run with the isolated DNS-provider proof container".into());
    }
    let contents = std::fs::read_to_string("/etc/resolv.conf")?;
    let servers = contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next() == Some("nameserver")).then(|| fields.collect::<Vec<_>>())
        })
        .collect::<Vec<_>>();
    if servers != vec![vec!["127.0.0.1"]] {
        return Err("proof resolver must be exclusively container loopback".into());
    }
    for hostname in ["api.cloudflare.com", "ns.meshspan.test"] {
        let addresses = tokio::net::lookup_host((hostname, 443))
            .await?
            .collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| address.ip() != Ipv4Addr::LOCALHOST)
        {
            return Err("proof origins must resolve exclusively to container loopback".into());
        }
    }
    Ok(())
}
