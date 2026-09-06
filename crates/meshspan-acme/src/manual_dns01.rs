// SPDX-License-Identifier: GPL-2.0-only

//! Durable manual DNS-01 tasks derived from the same challenge contract as automatic providers.

use std::future::Future;

use meshspan_contracts::{
    CertificateChallenge, CertificateChallengeKind, CertificateChallengeReceipt,
    CertificateChallengeRequest, ComponentConfiguration, ComponentLifecycle, ComponentObservation,
    ComponentTransition, ContractError, ImplementationDescriptor,
};
use meshspan_domain::{Revision, UnixMicros};
use sha2::{Digest, Sha256};

use crate::{AuthoritativeTxtObserver, Dns01Payload};
use crate::{
    component::Lifecycle,
    http01::{descriptor, validate_cleanup_request, validate_request},
};

/// Durable operator-facing phase for one exact manual DNS record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManualDnsTaskPhase {
    /// The exact TXT value must be published before its deadline.
    AwaitingPublication,
    /// Authoritative DNS returned the exact TXT value.
    PublicationObserved,
    /// ACME no longer needs the value and it should be removed.
    AwaitingRemoval,
    /// Authoritative DNS proved the exact value absent.
    Complete,
}

/// Complete non-secret projection an authorised administrator needs to perform manual DNS-01.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualDnsTask {
    /// Deterministic identity for this exact fenced publication.
    pub task_digest: [u8; 32],
    /// Canonical TXT owner name.
    pub record_name: String,
    /// Exact unquoted TXT value.
    pub record_value: Vec<u8>,
    /// Authoritative challenge deadline.
    pub expires_at: UnixMicros,
    /// Fenced ACME order epoch.
    pub order_epoch: u64,
    /// Requested monotonic task phase.
    pub phase: ManualDnsTaskPhase,
}

/// Consensus-backed task boundary used by the manual DNS challenge implementation.
pub trait ManualDnsTaskAuthority {
    /// Idempotently creates or advances one exact task without allowing phase regression.
    ///
    /// # Errors
    ///
    /// Rejects identity conflicts, stale transitions and unavailable durable authority.
    fn advance(
        &self,
        task: &ManualDnsTask,
    ) -> impl Future<Output = Result<(), ContractError>> + Send;
}

/// Manual DNS-01 challenge which persists instructions and independently probes authoritative DNS.
pub struct ManualDns01Challenge<A, O> {
    lifecycle: Lifecycle,
    authority: A,
    observer: O,
}

impl<A, O> ManualDns01Challenge<A, O> {
    /// Composes a durable task authority and authoritative DNS observer.
    pub fn new(authority: A, observer: O) -> Self {
        Self {
            lifecycle: Lifecycle::default(),
            authority,
            observer,
        }
    }

    fn task(
        request: &CertificateChallengeRequest,
        payload: &Dns01Payload,
        phase: ManualDnsTaskPhase,
    ) -> ManualDnsTask {
        ManualDnsTask {
            task_digest: task_digest(request, payload),
            record_name: payload.record_name().to_owned(),
            record_value: payload.record_value().to_vec(),
            expires_at: request.expires_at,
            order_epoch: request.order_epoch,
            phase,
        }
    }

    fn receipt(
        request: &CertificateChallengeRequest,
        payload: &Dns01Payload,
    ) -> CertificateChallengeReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:manual-dns-01-publication:v1");
        digest.update(task_digest(request, payload));
        CertificateChallengeReceipt {
            configuration_revision: request.context.expected_revision.unwrap_or(Revision::ZERO),
            order_epoch: request.order_epoch,
            publication_digest: digest.finalize().into(),
        }
    }

    fn validate_receipt(
        request: &CertificateChallengeRequest,
        payload: &Dns01Payload,
        receipt: CertificateChallengeReceipt,
    ) -> Result<(), ContractError> {
        if receipt.order_epoch != request.order_epoch || Self::receipt(request, payload) != receipt
        {
            return Err(ContractError::Stale);
        }
        Ok(())
    }
}

impl<A, O> CertificateChallenge for ManualDns01Challenge<A, O>
where
    A: ManualDnsTaskAuthority + Send + Sync,
    O: AuthoritativeTxtObserver + Send + Sync,
{
    async fn publish(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> Result<CertificateChallengeReceipt, ContractError> {
        self.lifecycle.require_active()?;
        validate_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        self.authority
            .advance(&Self::task(
                request,
                &payload,
                ManualDnsTaskPhase::AwaitingPublication,
            ))
            .await?;
        Ok(Self::receipt(request, &payload))
    }

    async fn is_visible(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<bool, ContractError> {
        validate_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        Self::validate_receipt(request, &payload, receipt)?;
        let visible = self
            .observer
            .contains_txt(payload.record_name(), payload.record_value())
            .await?;
        if visible {
            self.authority
                .advance(&Self::task(
                    request,
                    &payload,
                    ManualDnsTaskPhase::PublicationObserved,
                ))
                .await?;
        }
        Ok(visible)
    }

    async fn cleanup(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<(), ContractError> {
        validate_cleanup_request(request, CertificateChallengeKind::Dns01)?;
        let payload =
            Dns01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        Self::validate_receipt(request, &payload, receipt)?;
        let visible = self
            .observer
            .contains_txt(payload.record_name(), payload.record_value())
            .await?;
        let phase = if visible {
            ManualDnsTaskPhase::AwaitingRemoval
        } else {
            ManualDnsTaskPhase::Complete
        };
        self.authority
            .advance(&Self::task(request, &payload, phase))
            .await
    }
}

impl<A, O> ComponentLifecycle for ManualDns01Challenge<A, O> {
    fn describe(&self) -> ImplementationDescriptor {
        descriptor("meshspan-manual-dns-01")
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

fn task_digest(request: &CertificateChallengeRequest, payload: &Dns01Payload) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan:manual-dns-task:v1");
    digest.update(request.identifier.as_slice());
    digest.update(payload.record_name().as_bytes());
    digest.update(payload.record_value());
    digest.update(request.expires_at.get().to_be_bytes());
    digest.update(request.order_epoch.to_be_bytes());
    digest.finalize().into()
}
