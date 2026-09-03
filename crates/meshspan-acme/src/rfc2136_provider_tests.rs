// SPDX-License-Identifier: GPL-2.0-only

use std::{error::Error, net::SocketAddr, time::Duration};

use meshspan_contracts::{
    BoundedBytes, CertificateChallenge, CertificateChallengeKind, CertificateChallengeRequest,
    ContractError, ContractVersion, RequestContext,
};
use meshspan_domain::{Clock, EntropyError, OperationId, RandomSource, Revision, UnixMicros};

use crate::{
    Dns01Challenge, Dns01Payload, DnsTxtProvider, Rfc2136DnsProvider, Rfc2136DnsSettings,
    Rfc2136ProviderPolicy, Rfc2136TsigAlgorithm, rfc2136_test_server::Rfc2136TestServer,
};

type TestError = Box<dyn Error + Send + Sync>;

#[test]
fn receipt_is_stable_across_provider_reconstruction() -> Result<(), TestError> {
    let first = provider(UnixMicros::new(1_700_000_000_000_000))?;
    let second = provider(UnixMicros::new(1_700_000_000_000_000))?;
    let first_receipt = first.receipt("_acme-challenge.example.test", b"proof", 7);
    assert_eq!(
        first_receipt,
        second.receipt("_acme-challenge.example.test", b"proof", 7)
    );
    assert_ne!(
        first_receipt,
        second.receipt("_acme-challenge.example.test", b"proof", 8)
    );
    Ok(())
}

#[tokio::test]
async fn invalid_authoritative_time_fails_before_network_io() -> Result<(), TestError> {
    let mut provider = provider(UnixMicros::new(-1))?;
    assert_eq!(
        provider
            .publish_txt("_acme-challenge.example.test", b"proof", 7)
            .await,
        Err(ContractError::Unavailable)
    );
    Ok(())
}

#[tokio::test]
async fn publishes_probes_and_removes_through_real_dns_sockets() -> Result<(), TestError> {
    let server = Rfc2136TestServer::start().await?;
    let settings = settings(server.address())?;
    let provider = Rfc2136DnsProvider::new(
        settings,
        FixedRandom,
        FixedClock(UnixMicros::new(1_700_000_000_000_000)),
        Rfc2136ProviderPolicy::new(Duration::from_secs(2), 30, 300)?,
    )?;
    let mut challenge = Dns01Challenge::new(provider);
    let payload = Dns01Payload::new("_acme-challenge.example.test", b"proof")?;
    let request = CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([1; 16])?,
            deadline: UnixMicros::new(1_700_000_010_000_000),
            expected_revision: Some(Revision::new(3)),
        },
        kind: CertificateChallengeKind::Dns01,
        identifier: BoundedBytes::copy_from(b"example.test", 253)?,
        challenge: payload.encode()?,
        expires_at: UnixMicros::new(1_700_000_020_000_000),
        order_epoch: 7,
    };
    let receipt = challenge.publish(&request).await?;
    assert!(challenge.is_visible(&request, receipt).await?);
    challenge.cleanup(&request, receipt).await?;
    assert!(!challenge.is_visible(&request, receipt).await?);
    server.finish().await?;
    Ok(())
}

fn provider(now: UnixMicros) -> Result<Rfc2136DnsProvider<FixedRandom, FixedClock>, TestError> {
    let settings = settings(SocketAddr::from(([127, 0, 0, 1], 53)))?;
    Ok(Rfc2136DnsProvider::new(
        settings,
        FixedRandom,
        FixedClock(now),
        Rfc2136ProviderPolicy::new(Duration::from_secs(2), 30, 300)?,
    )?)
}

fn settings(server: SocketAddr) -> Result<Rfc2136DnsSettings, TestError> {
    Ok(Rfc2136DnsSettings::new(
        server,
        "example.test".to_owned(),
        "meshspan-key.example.test".to_owned(),
        Rfc2136TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )?)
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(7);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct FixedClock(UnixMicros);

impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        self.0
    }
}
