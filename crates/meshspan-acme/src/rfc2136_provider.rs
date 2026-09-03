// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated RFC 2136 implementation of the restart-safe DNS TXT provider boundary.

use std::{sync::Mutex, time::Duration};

use meshspan_contracts::ContractError;
use meshspan_dns::{
    AuthoritativeDnsError, AuthoritativeTxtProbe, DnsName, DnsQuery, Rfc2136Client,
    Rfc2136ClientError, Rfc2136Request, Rfc2136RequestError, Rfc2136ResponseError, Rfc2136TsigKey,
    TsigAlgorithm, TxtUpdate, TxtValue,
};
use meshspan_domain::{Clock, RandomSource};
use sha2::{Digest, Sha256};

use crate::{DnsTxtProvider, DnsTxtReceipt, Rfc2136DnsSettings, Rfc2136TsigAlgorithm};

const MAXIMUM_FUDGE_SECONDS: u16 = 3_600;
const MAXIMUM_TTL_SECONDS: u32 = 86_400;
const MICROS_PER_SECOND: u64 = 1_000_000;

/// Time and cache bounds applied to every RFC 2136 challenge transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rfc2136ProviderPolicy {
    timeout: Duration,
    ttl_seconds: u32,
    fudge_seconds: u16,
}

impl Rfc2136ProviderPolicy {
    /// Creates one finite provider policy.
    ///
    /// # Errors
    ///
    /// Rejects invalid transaction timeouts, zero TTLs or excessive TSIG time windows.
    pub fn new(
        timeout: Duration,
        ttl_seconds: u32,
        fudge_seconds: u16,
    ) -> Result<Self, ContractError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(60)
            || !(1..=MAXIMUM_TTL_SECONDS).contains(&ttl_seconds)
            || !(1..=MAXIMUM_FUDGE_SECONDS).contains(&fudge_seconds)
        {
            return Err(ContractError::InvalidInput);
        }
        Ok(Self {
            timeout,
            ttl_seconds,
            fudge_seconds,
        })
    }
}

/// In-process RFC 2136 publisher using TSIG, direct authoritative probes and injected authority.
pub struct Rfc2136DnsProvider<R, C> {
    client: Rfc2136Client,
    probe: AuthoritativeTxtProbe,
    key: Rfc2136TsigKey,
    random: Mutex<R>,
    clock: C,
    zone: String,
    scope_digest: [u8; 32],
    policy: Rfc2136ProviderPolicy,
}

impl<R, C> Rfc2136DnsProvider<R, C> {
    /// Creates a provider from decrypted settings without contacting DNS.
    ///
    /// The temporary key copy is moved directly into zeroising provider storage; the source
    /// settings zeroise their own copy when construction returns.
    ///
    /// # Errors
    ///
    /// Rejects settings that cannot be represented by the bounded DNS implementation.
    pub fn new(
        settings: Rfc2136DnsSettings,
        random: R,
        clock: C,
        policy: Rfc2136ProviderPolicy,
    ) -> Result<Self, ContractError> {
        let algorithm = match settings.algorithm() {
            Rfc2136TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
            Rfc2136TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
        };
        let client = Rfc2136Client::new(settings.server(), policy.timeout)
            .map_err(|_| ContractError::InvalidInput)?;
        let probe = AuthoritativeTxtProbe::new(settings.server(), policy.timeout)
            .map_err(|_| ContractError::InvalidInput)?;
        let key = Rfc2136TsigKey::new(settings.key_name(), algorithm, settings.secret().to_vec())
            .map_err(map_request_error)?;
        let zone = settings.zone().to_owned();
        DnsName::new(&zone).map_err(|_| ContractError::InvalidInput)?;
        let scope_digest = provider_scope_digest(&settings, algorithm);
        drop(settings);
        Ok(Self {
            client,
            probe,
            key,
            random: Mutex::new(random),
            clock,
            zone,
            scope_digest,
            policy,
        })
    }

    fn query_id(&self) -> Result<u16, ContractError>
    where
        R: RandomSource,
    {
        let mut bytes = [0_u8; 2];
        self.random
            .lock()
            .map_err(|_| ContractError::Unavailable)?
            .fill_bytes(&mut bytes)
            .map_err(|_| ContractError::Unavailable)?;
        let id = u16::from_be_bytes(bytes);
        Ok(if id == 0 { 1 } else { id })
    }

    fn now_seconds(&self) -> Result<u64, ContractError>
    where
        C: Clock,
    {
        u64::try_from(self.clock.now().get())
            .map(|micros| micros / MICROS_PER_SECOND)
            .map_err(|_| ContractError::Unavailable)
    }

    fn signed_request(
        &self,
        name: &str,
        value: &[u8],
        update: TxtUpdate,
    ) -> Result<(meshspan_dns::SignedRfc2136Request, u64), ContractError>
    where
        R: RandomSource,
        C: Clock,
    {
        let now = self.now_seconds()?;
        let request = Rfc2136Request::new(
            self.query_id()?,
            &self.zone,
            name,
            value,
            update,
            now,
            self.policy.fudge_seconds,
        )
        .map_err(map_request_error)?;
        Ok((request.sign(&self.key).map_err(map_request_error)?, now))
    }

    async fn update(&self, name: &str, value: &[u8], update: TxtUpdate) -> Result<(), ContractError>
    where
        R: RandomSource,
        C: Clock,
    {
        let (request, now) = self.signed_request(name, value, update)?;
        self.client
            .execute(&request, &self.key, now)
            .await
            .map_err(|error| map_client_error(&error))
    }
}

impl<R, C> DnsTxtProvider for Rfc2136DnsProvider<R, C>
where
    R: RandomSource + Send,
    C: Clock + Send + Sync,
{
    fn receipt(&self, name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:rfc2136-publication:v1");
        digest.update(self.scope_digest);
        digest_field(&mut digest, name.as_bytes());
        digest_field(&mut digest, value);
        digest.update(order_epoch.to_be_bytes());
        DnsTxtReceipt {
            provider_digest: digest.finalize().into(),
        }
    }

    async fn publish_txt(
        &mut self,
        name: &str,
        value: &[u8],
        order_epoch: u64,
    ) -> Result<DnsTxtReceipt, ContractError> {
        let receipt = self.receipt(name, value, order_epoch);
        self.update(
            name,
            value,
            TxtUpdate::Publish {
                ttl_seconds: self.policy.ttl_seconds,
            },
        )
        .await?;
        Ok(receipt)
    }

    async fn is_txt_visible(
        &self,
        name: &str,
        value: &[u8],
        _receipt: DnsTxtReceipt,
    ) -> Result<bool, ContractError> {
        let dns_name = DnsName::new(name).map_err(|_| ContractError::InvalidInput)?;
        let query =
            DnsQuery::txt(self.query_id()?, dns_name).map_err(|_| ContractError::InvalidInput)?;
        self.probe
            .contains_txt(
                &query,
                &TxtValue::new(value).map_err(|_| ContractError::InvalidInput)?,
            )
            .await
            .map_err(|error| map_probe_error(&error))
    }

    async fn remove_txt(
        &mut self,
        name: &str,
        value: &[u8],
        _receipt: DnsTxtReceipt,
    ) -> Result<(), ContractError> {
        self.update(name, value, TxtUpdate::Remove).await
    }
}

fn provider_scope_digest(settings: &Rfc2136DnsSettings, algorithm: TsigAlgorithm) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan:rfc2136-scope:v1");
    digest_field(&mut digest, settings.server().to_string().as_bytes());
    digest_field(&mut digest, settings.zone().as_bytes());
    digest_field(&mut digest, settings.key_name().as_bytes());
    digest.update([match algorithm {
        TsigAlgorithm::HmacSha256 => 1,
        TsigAlgorithm::HmacSha512 => 2,
    }]);
    digest.finalize().into()
}

fn digest_field(digest: &mut Sha256, field: &[u8]) {
    digest.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(field);
}

fn map_request_error(error: Rfc2136RequestError) -> ContractError {
    match error {
        Rfc2136RequestError::InvalidKey
        | Rfc2136RequestError::InvalidRequest
        | Rfc2136RequestError::Wire(_) => ContractError::InvalidInput,
        Rfc2136RequestError::Capacity => ContractError::ResourceExhausted,
        Rfc2136RequestError::Signing => ContractError::Unavailable,
    }
}

fn map_client_error(error: &Rfc2136ClientError) -> ContractError {
    match error {
        Rfc2136ClientError::InvalidConfiguration => ContractError::InvalidInput,
        Rfc2136ClientError::Capacity => ContractError::ResourceExhausted,
        Rfc2136ClientError::Timeout => ContractError::DeadlineExceeded,
        Rfc2136ClientError::Response(Rfc2136ResponseError::Rejected { .. }) => {
            ContractError::Unauthorized
        }
        Rfc2136ClientError::Io(_) | Rfc2136ClientError::Response(_) => ContractError::Unavailable,
    }
}

fn map_probe_error(error: &AuthoritativeDnsError) -> ContractError {
    match error {
        AuthoritativeDnsError::InvalidConfiguration => ContractError::InvalidInput,
        AuthoritativeDnsError::Timeout => ContractError::DeadlineExceeded,
        AuthoritativeDnsError::Io(_) | AuthoritativeDnsError::Wire(_) => ContractError::Unavailable,
    }
}
