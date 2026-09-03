// SPDX-License-Identifier: GPL-2.0-only

//! DNS-01 adapter over a narrow replaceable TXT publication boundary.

use std::collections::BTreeMap;
use std::sync::RwLock;

use meshspan_contracts::{
    CertificateChallenge, CertificateChallengeKind, CertificateChallengeReceipt,
    CertificateChallengeRequest, ComponentConfiguration, ComponentLifecycle, ComponentObservation,
    ComponentTransition, ContractError, ImplementationDescriptor,
};
use meshspan_domain::{Revision, UnixMicros};
use sha2::{Digest, Sha256};

use crate::Dns01Payload;
use crate::component::Lifecycle;
use crate::http01::{descriptor, validate_request};

/// Provider-confirmed identity of one exact TXT publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsTxtReceipt {
    /// Provider-owned opaque generation or change identity digest.
    pub provider_digest: [u8; 32],
}

/// Small synchronous boundary implemented by RFC 2136, Cloudflare and automation adapters.
pub trait DnsTxtProvider {
    /// Idempotently publishes an exact TXT value under the supplied order fence.
    ///
    /// # Errors
    ///
    /// Returns stable validation, stale-fence, capacity or provider availability failures.
    fn publish_txt(
        &mut self,
        name: &str,
        value: &[u8],
        order_epoch: u64,
    ) -> Result<DnsTxtReceipt, ContractError>;

    /// Confirms that the provider currently observes the exact value.
    ///
    /// # Errors
    ///
    /// Returns stale for a replaced receipt and unavailable for an inconclusive observation.
    fn is_txt_visible(
        &self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> Result<bool, ContractError>;

    /// Removes only the exact publication represented by the provider receipt.
    ///
    /// # Errors
    ///
    /// Returns stale rather than removing any changed or replacement TXT value.
    fn remove_txt(
        &mut self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> Result<(), ContractError>;
}

/// Certificate-challenge implementation around one configured DNS TXT publisher.
#[derive(Debug)]
pub struct Dns01Challenge<P> {
    lifecycle: Lifecycle,
    provider: P,
    provider_receipts: RwLock<BTreeMap<[u8; 32], DnsTxtReceipt>>,
}

impl<P> Dns01Challenge<P> {
    /// Wraps one ready in-process DNS provider.
    pub fn new(provider: P) -> Self {
        Self {
            lifecycle: Lifecycle::default(),
            provider,
            provider_receipts: RwLock::new(BTreeMap::new()),
        }
    }

    fn receipt(
        request: &CertificateChallengeRequest,
        payload: &Dns01Payload,
        provider: DnsTxtReceipt,
    ) -> CertificateChallengeReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:dns-01-publication:v1");
        digest.update(request.identifier.as_slice());
        digest.update(payload.record_name().as_bytes());
        digest.update(payload.record_value());
        digest.update(request.expires_at.get().to_be_bytes());
        digest.update(request.order_epoch.to_be_bytes());
        digest.update(provider.provider_digest);
        CertificateChallengeReceipt {
            configuration_revision: request.context.expected_revision.unwrap_or(Revision::ZERO),
            order_epoch: request.order_epoch,
            publication_digest: digest.finalize().into(),
        }
    }
}

impl<P: DnsTxtProvider> CertificateChallenge for Dns01Challenge<P> {
    fn publish(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> Result<CertificateChallengeReceipt, ContractError> {
        self.lifecycle.require_active()?;
        validate_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        let provider = self.provider.publish_txt(
            payload.record_name(),
            payload.record_value(),
            request.order_epoch,
        )?;
        let receipt = Self::receipt(request, &payload, provider);
        self.provider_receipts
            .write()
            .map_err(|_| ContractError::Unavailable)?
            .insert(receipt.publication_digest, provider);
        Ok(receipt)
    }

    fn is_visible(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<bool, ContractError> {
        validate_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        if receipt.order_epoch != request.order_epoch {
            return Err(ContractError::Stale);
        }
        let provider = self
            .provider_receipts
            .read()
            .map_err(|_| ContractError::Unavailable)?
            .get(&receipt.publication_digest)
            .copied()
            .ok_or(ContractError::Stale)?;
        if Self::receipt(request, &payload, provider) != receipt {
            return Err(ContractError::Stale);
        }
        self.provider
            .is_txt_visible(payload.record_name(), payload.record_value(), provider)
    }

    fn cleanup(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<(), ContractError> {
        validate_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        if receipt.order_epoch != request.order_epoch {
            return Err(ContractError::Stale);
        }
        let provider = self
            .provider_receipts
            .read()
            .map_err(|_| ContractError::Unavailable)?
            .get(&receipt.publication_digest)
            .copied()
            .ok_or(ContractError::Stale)?;
        if Self::receipt(request, &payload, provider) != receipt {
            return Err(ContractError::Stale);
        }
        self.provider
            .remove_txt(payload.record_name(), payload.record_value(), provider)?;
        self.provider_receipts
            .write()
            .map_err(|_| ContractError::Unavailable)?
            .remove(&receipt.publication_digest);
        Ok(())
    }
}

impl<P> ComponentLifecycle for Dns01Challenge<P> {
    fn describe(&self) -> ImplementationDescriptor {
        descriptor("meshspan-dns-01")
    }

    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError> {
        Lifecycle::validate(configuration)
    }

    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        self.lifecycle.prepare(configuration)
    }

    fn activate(&mut self, revision: Revision) -> Result<ComponentTransition, ContractError> {
        self.lifecycle.activate(revision)
    }

    fn drain(&mut self, _deadline: UnixMicros) -> Result<ComponentTransition, ContractError> {
        Ok(self.lifecycle.drain())
    }

    fn retire(&mut self, revision: Revision) -> Result<ComponentTransition, ContractError> {
        self.lifecycle.retire(revision)
    }

    fn observe(&self, observed_at: UnixMicros) -> ComponentObservation {
        self.lifecycle.observe(observed_at)
    }
}
