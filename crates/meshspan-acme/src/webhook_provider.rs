// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe DNS webhook provider policy separated from hostile HTTPS handling.

use std::future::Future;

use meshspan_contracts::ContractError;
use meshspan_dns::{DnsName, TxtValue};
use sha2::{Digest, Sha256};

use crate::{AuthoritativeTxtObserver, DnsTxtProvider, DnsTxtReceipt, WebhookDnsSettings};

/// Operation requested from an authenticated DNS automation webhook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookDnsAction {
    /// Idempotently publish the exact TXT value.
    Publish,
    /// Remove only the exact owned TXT value.
    Remove,
}

/// Exact record and stable ownership identity sent to a DNS automation webhook.
pub struct WebhookDnsRecord<'a> {
    /// Canonical TXT owner name.
    pub name: &'a str,
    /// Exact ACME TXT value.
    pub value: &'a [u8],
    /// Deterministic non-secret ownership marker recoverable after restart.
    pub ownership_marker: &'a str,
}

/// Narrow authenticated webhook boundary with strict request and response handling.
pub trait WebhookDnsApi {
    /// Applies one idempotent operation for an exactly owned record.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous acknowledgements, authentication failures and provider failures.
    fn apply(
        &mut self,
        endpoint: &str,
        bearer_token: &[u8],
        action: WebhookDnsAction,
        record: &WebhookDnsRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send;
}

/// Authenticated DNS webhook provider with restart-safe exact cleanup identity.
pub struct WebhookDnsProvider<A, O> {
    settings: WebhookDnsSettings,
    api: A,
    observer: O,
}

impl<A, O> WebhookDnsProvider<A, O> {
    /// Creates a provider without contacting the configured webhook or DNS.
    pub const fn new(settings: WebhookDnsSettings, api: A, observer: O) -> Self {
        Self {
            settings,
            api,
            observer,
        }
    }
}

impl<A, O> DnsTxtProvider for WebhookDnsProvider<A, O>
where
    A: WebhookDnsApi + Send + Sync,
    O: AuthoritativeTxtObserver + Send + Sync,
{
    fn receipt(&self, name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:webhook-dns-publication:v1");
        digest_field(&mut digest, self.settings.endpoint().as_bytes());
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
        self.apply(WebhookDnsAction::Publish, name, value, receipt)
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
        self.apply(WebhookDnsAction::Remove, name, value, receipt)
            .await
    }
}

impl<A, O> WebhookDnsProvider<A, O>
where
    A: WebhookDnsApi,
{
    async fn apply(
        &mut self,
        action: WebhookDnsAction,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> Result<(), ContractError> {
        let marker = ownership_marker(receipt);
        self.api
            .apply(
                self.settings.endpoint(),
                self.settings.bearer_token(),
                action,
                &WebhookDnsRecord {
                    name,
                    value,
                    ownership_marker: &marker,
                },
            )
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
