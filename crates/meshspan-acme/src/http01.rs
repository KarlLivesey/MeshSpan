// SPDX-License-Identifier: GPL-2.0-only

//! Concurrent bounded HTTP-01 publication store shared by every local listener worker.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use meshspan_contracts::{
    CertificateChallenge, CertificateChallengeCleanup, CertificateChallengeKind,
    CertificateChallengeReceipt, CertificateChallengeRequest, ComponentConfiguration,
    ComponentLifecycle, ComponentObservation, ComponentTransition, ContractError, ContractKind,
    ContractLimits, ContractVersion, ImplementationDescriptor,
};
use meshspan_domain::{Revision, UnixMicros};
use sha2::{Digest, Sha256};

use crate::Http01Payload;
use crate::component::Lifecycle;

const VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];
const MAXIMUM_ACTIVE_CHALLENGES: usize = 1_024;

/// In-process HTTP-01 publication catalogue. Clones share the same bounded state.
#[derive(Clone, Debug, Default)]
pub struct Http01Challenge {
    lifecycle: Lifecycle,
    records: Arc<RwLock<BTreeMap<String, PublishedChallenge>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedChallenge {
    key_authorization: Vec<u8>,
    expires_at: UnixMicros,
    order_epoch: u64,
    receipt: CertificateChallengeReceipt,
}

impl Http01Challenge {
    /// Creates an active empty in-process challenge store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the exact response body only while the publication remains current and unexpired.
    ///
    /// # Errors
    ///
    /// Returns unavailable if the shared catalogue lock is poisoned.
    pub fn response(&self, token: &str, now: UnixMicros) -> Result<Option<Vec<u8>>, ContractError> {
        if !valid_token(token) {
            return Ok(None);
        }
        let records = self
            .records
            .read()
            .map_err(|_| ContractError::Unavailable)?;
        Ok(records
            .get(token)
            .filter(|record| record.expires_at > now)
            .map(|record| record.key_authorization.clone()))
    }

    fn receipt(
        request: &CertificateChallengeRequest,
        payload: &Http01Payload,
    ) -> CertificateChallengeReceipt {
        let mut digest = Sha256::new();
        digest.update(b"meshspan:http-01-publication:v1");
        digest.update(request.identifier.as_slice());
        digest.update(payload.token().as_bytes());
        digest.update(payload.key_authorization());
        digest.update(request.expires_at.get().to_be_bytes());
        digest.update(request.order_epoch.to_be_bytes());
        CertificateChallengeReceipt {
            configuration_revision: request.context.expected_revision.unwrap_or(Revision::ZERO),
            order_epoch: request.order_epoch,
            publication_digest: digest.finalize().into(),
        }
    }

    fn publish_now(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> Result<CertificateChallengeReceipt, ContractError> {
        self.lifecycle.require_active()?;
        validate_request(request, CertificateChallengeKind::Http01)?;
        let payload =
            Http01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        let receipt = Self::receipt(request, &payload);
        let record = PublishedChallenge {
            key_authorization: payload.key_authorization().to_vec(),
            expires_at: request.expires_at,
            order_epoch: request.order_epoch,
            receipt,
        };
        let mut records = self
            .records
            .write()
            .map_err(|_| ContractError::Unavailable)?;
        if let Some(existing) = records.get(payload.token()) {
            if existing.order_epoch > request.order_epoch {
                return Err(ContractError::Stale);
            }
            if existing.order_epoch == request.order_epoch {
                return if existing == &record {
                    Ok(receipt)
                } else {
                    Err(ContractError::Conflict)
                };
            }
        } else if records.len() == MAXIMUM_ACTIVE_CHALLENGES {
            return Err(ContractError::ResourceExhausted);
        }
        records.insert(payload.token().to_owned(), record);
        Ok(receipt)
    }

    fn visible_now(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<bool, ContractError> {
        validate_request(request, CertificateChallengeKind::Http01)?;
        let payload =
            Http01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        let records = self
            .records
            .read()
            .map_err(|_| ContractError::Unavailable)?;
        Ok(records.get(payload.token()).is_some_and(|record| {
            record.receipt == receipt && record.receipt == Self::receipt(request, &payload)
        }))
    }

    fn cleanup_now(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<(), ContractError> {
        validate_cleanup_request(request, CertificateChallengeKind::Http01)?;
        let payload =
            Http01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        if receipt != Self::receipt(request, &payload) {
            return Err(ContractError::Stale);
        }
        let mut records = self
            .records
            .write()
            .map_err(|_| ContractError::Unavailable)?;
        let Some(current) = records.get(payload.token()) else {
            // Removal may have succeeded before its checkpoint, or restart may have
            // discarded this process-local catalogue. Exact absence is successful cleanup.
            return Ok(());
        };
        if current.receipt != receipt {
            return Err(ContractError::Stale);
        }
        records.remove(payload.token());
        Ok(())
    }
}

impl CertificateChallenge for Http01Challenge {
    fn publish(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> impl std::future::Future<Output = Result<CertificateChallengeReceipt, ContractError>> + Send
    {
        std::future::ready(self.publish_now(request))
    }

    fn is_visible(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> impl std::future::Future<Output = Result<bool, ContractError>> + Send {
        std::future::ready(self.visible_now(request, receipt))
    }

    fn cleanup(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> impl std::future::Future<Output = Result<CertificateChallengeCleanup, ContractError>> + Send
    {
        std::future::ready(
            self.cleanup_now(request, receipt)
                .map(|()| CertificateChallengeCleanup::Complete),
        )
    }
}

impl ComponentLifecycle for Http01Challenge {
    fn describe(&self) -> ImplementationDescriptor {
        descriptor("meshspan-http-01")
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

pub(crate) fn validate_request(
    request: &CertificateChallengeRequest,
    expected_kind: CertificateChallengeKind,
) -> Result<(), ContractError> {
    validate_cleanup_request(request, expected_kind)?;
    if request.expires_at <= request.context.deadline {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

// Cleanup binds the original publication expiry, not a renewed lifetime. Its
// separately authorised request can therefore finish after that publication expired.
pub(crate) fn validate_cleanup_request(
    request: &CertificateChallengeRequest,
    expected_kind: CertificateChallengeKind,
) -> Result<(), ContractError> {
    if request.context.contract_version != ContractVersion::V1_0 {
        return Err(ContractError::UnsupportedVersion);
    }
    if request.kind != expected_kind
        || request.identifier.is_empty()
        || request.identifier.len() > 253
        || !request.identifier.as_slice().is_ascii()
        || !valid_identifier(request.identifier.as_slice(), expected_kind)
        || request.order_epoch == 0
        || request.expires_at.get() <= 0
        || request.context.deadline.get() <= 0
        || request
            .context
            .expected_revision
            .is_none_or(|revision| revision == Revision::ZERO)
    {
        Err(ContractError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_identifier(value: &[u8], kind: CertificateChallengeKind) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let name = if kind == CertificateChallengeKind::Dns01 {
        value.strip_prefix("*.").unwrap_or(value)
    } else {
        if value.starts_with("*.") {
            return false;
        }
        value
    };
    name.contains('.')
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(crate) fn descriptor(implementation_id: &'static str) -> ImplementationDescriptor {
    ImplementationDescriptor {
        implementation_id,
        contract: ContractKind::CertificateChallenge,
        versions: VERSIONS,
        limits: ContractLimits {
            maximum_control_bytes: 1_024,
            maximum_items: MAXIMUM_ACTIVE_CHALLENGES,
            maximum_concurrency: MAXIMUM_ACTIVE_CHALLENGES,
        },
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
