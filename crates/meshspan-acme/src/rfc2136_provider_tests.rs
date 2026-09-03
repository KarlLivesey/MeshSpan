// SPDX-License-Identifier: GPL-2.0-only

use std::{error::Error, net::SocketAddr, time::Duration};

use meshspan_contracts::ContractError;
use meshspan_domain::{Clock, EntropyError, RandomSource, UnixMicros};

use crate::{
    DnsTxtProvider, Rfc2136DnsProvider, Rfc2136DnsSettings, Rfc2136ProviderPolicy,
    Rfc2136TsigAlgorithm,
};

#[test]
fn receipt_is_stable_across_provider_reconstruction() -> Result<(), Box<dyn Error>> {
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
async fn invalid_authoritative_time_fails_before_network_io() -> Result<(), Box<dyn Error>> {
    let mut provider = provider(UnixMicros::new(-1))?;
    assert_eq!(
        provider
            .publish_txt("_acme-challenge.example.test", b"proof", 7)
            .await,
        Err(ContractError::Unavailable)
    );
    Ok(())
}

fn provider(
    now: UnixMicros,
) -> Result<Rfc2136DnsProvider<FixedRandom, FixedClock>, Box<dyn Error>> {
    let settings = Rfc2136DnsSettings::new(
        SocketAddr::from(([127, 0, 0, 1], 53)),
        "example.test".to_owned(),
        "meshspan-key.example.test".to_owned(),
        Rfc2136TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )?;
    Ok(Rfc2136DnsProvider::new(
        settings,
        FixedRandom,
        FixedClock(now),
        Rfc2136ProviderPolicy::new(Duration::from_secs(2), 30, 300)?,
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
