// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe Cloudflare DNS provider policy separated from hostile HTTPS response handling.

use std::future::Future;

use meshspan_contracts::ContractError;
use meshspan_dns::{DnsName, TxtValue};
use sha2::{Digest, Sha256};

use crate::{CloudflareDnsSettings, DnsTxtProvider, DnsTxtReceipt};

const MAXIMUM_TTL_SECONDS: u32 = 86_400;

/// Exact Cloudflare TXT record owned by one fenced `MeshSpan` ACME publication.
pub struct CloudflareTxtRecord<'a> {
    /// Canonical TXT owner name.
    pub name: &'a str,
    /// Exact ACME TXT value.
    pub value: &'a [u8],
    /// Requested provider TTL.
    pub ttl_seconds: u32,
    /// Deterministic non-secret ownership marker recoverable after restart.
    pub ownership_marker: &'a str,
}

/// Narrow Cloudflare v4 API boundary; its concrete implementation validates every HTTPS response.
pub trait CloudflareDnsApi {
    /// Idempotently creates or confirms one exactly marked TXT record.
    ///
    /// # Errors
    ///
    /// Rejects conflicting markers, ambiguous matches, hostile responses and provider failures.
    fn ensure_txt(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send;

    /// Removes only the record matching the complete owner, value and ownership marker tuple.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous or changed records rather than deleting unrelated DNS state.
    fn remove_txt(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send;
}

/// Replaceable authoritative observation boundary shared by automatic DNS providers.
pub trait AuthoritativeTxtObserver {
    /// Proves whether an authoritative server currently returns the exact TXT value.
    ///
    /// # Errors
    ///
    /// Returns unavailable or deadline failure when absence cannot be proven conclusively.
    fn contains_txt(
        &self,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<bool, ContractError>> + Send;
}

/// Cloudflare DNS-01 provider with deterministic ownership and restart-safe cleanup.
pub struct CloudflareDnsProvider<A, O> {
    settings: CloudflareDnsSettings,
    api: A,
    observer: O,
    ttl_seconds: u32,
}

impl<A, O> CloudflareDnsProvider<A, O> {
    /// Creates a provider without contacting Cloudflare or DNS.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive TXT TTLs.
    pub fn new(
        settings: CloudflareDnsSettings,
        api: A,
        observer: O,
        ttl_seconds: u32,
    ) -> Result<Self, ContractError> {
        if ttl_seconds != 1 && !(60..=MAXIMUM_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(ContractError::InvalidInput);
        }
        Ok(Self {
            settings,
            api,
            observer,
            ttl_seconds,
        })
    }

    fn record<'a>(
        name: &'a str,
        value: &'a [u8],
        marker: &'a str,
        ttl_seconds: u32,
    ) -> CloudflareTxtRecord<'a> {
        CloudflareTxtRecord {
            name,
            value,
            ttl_seconds,
            ownership_marker: marker,
        }
    }
}

impl<A, O> DnsTxtProvider for CloudflareDnsProvider<A, O>
where
    A: CloudflareDnsApi + Send + Sync,
    O: AuthoritativeTxtObserver + Send + Sync,
{
    fn receipt(&self, name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:cloudflare-publication:v1");
        digest_field(&mut digest, self.settings.zone_id().as_bytes());
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
        validate_record(name, value)?;
        let receipt = self.receipt(name, value, order_epoch);
        let marker = ownership_marker(receipt);
        let record = Self::record(name, value, &marker, self.ttl_seconds);
        self.api
            .ensure_txt(self.settings.zone_id(), self.settings.api_token(), &record)
            .await?;
        Ok(receipt)
    }

    async fn is_txt_visible(
        &self,
        name: &str,
        value: &[u8],
        _receipt: DnsTxtReceipt,
    ) -> Result<bool, ContractError> {
        validate_record(name, value)?;
        self.observer.contains_txt(name, value).await
    }

    async fn remove_txt(
        &mut self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> Result<(), ContractError> {
        validate_record(name, value)?;
        let marker = ownership_marker(receipt);
        let record = Self::record(name, value, &marker, self.ttl_seconds);
        self.api
            .remove_txt(self.settings.zone_id(), self.settings.api_token(), &record)
            .await
    }
}

fn validate_record(name: &str, value: &[u8]) -> Result<(), ContractError> {
    DnsName::new(name).map_err(|_| ContractError::InvalidInput)?;
    TxtValue::new(value).map_err(|_| ContractError::InvalidInput)?;
    Ok(())
}

fn ownership_marker(receipt: DnsTxtReceipt) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut marker = String::with_capacity(78);
    marker.push_str("meshspan-acme:");
    for byte in receipt.provider_digest {
        marker.push(char::from(HEX[usize::from(byte >> 4)]));
        marker.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    marker
}

fn digest_field(digest: &mut Sha256, field: &[u8]) {
    digest.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(field);
}
