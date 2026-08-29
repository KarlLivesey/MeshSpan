// SPDX-License-Identifier: GPL-2.0-only

//! Offline federation grants and deterministic admission or quarantine decisions.

use thiserror::Error;

use crate::{
    FederatedPrincipal, FederationGrantId, FederationPolicy, FederationRelationshipId,
    FederationResourceScope, Rights, UnixMicros,
};

/// One signed authority envelope which a peer may use while disconnected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationGrant {
    grant_id: FederationGrantId,
    relationship_id: FederationRelationshipId,
    subject: FederatedPrincipal,
    resource: FederationResourceScope,
    policy: FederationPolicy,
    authority_epoch: u64,
    valid_from: UnixMicros,
    valid_until: Option<UnixMicros>,
}

impl FederationGrant {
    /// Constructs an exact grant after validating time, epoch, resource and policy bounds.
    ///
    /// # Errors
    ///
    /// Rejects a zero epoch, empty/reversed interval, excessive offline duration or a policy for
    /// the wrong resource kind.
    #[allow(
        clippy::too_many_arguments,
        reason = "a security grant must bind every independent authority dimension explicitly"
    )]
    pub fn new(
        grant_id: FederationGrantId,
        relationship_id: FederationRelationshipId,
        subject: FederatedPrincipal,
        resource: FederationResourceScope,
        policy: FederationPolicy,
        authority_epoch: u64,
        valid_from: UnixMicros,
        valid_until: Option<UnixMicros>,
    ) -> Result<Self, FederationGrantError> {
        if authority_epoch == 0 {
            return Err(FederationGrantError::InvalidEpoch);
        }
        validate_resource_policy(resource, policy)?;
        validate_interval(policy, valid_from, valid_until)?;
        Ok(Self {
            grant_id,
            relationship_id,
            subject,
            resource,
            policy,
            authority_epoch,
            valid_from,
            valid_until,
        })
    }

    /// Returns the stable grant identity.
    #[must_use]
    pub const fn grant_id(self) -> FederationGrantId {
        self.grant_id
    }

    /// Returns the mutually approved relationship carrying the grant.
    #[must_use]
    pub const fn relationship_id(self) -> FederationRelationshipId {
        self.relationship_id
    }

    /// Returns the exact remote principal receiving authority.
    #[must_use]
    pub const fn subject(self) -> FederatedPrincipal {
        self.subject
    }

    /// Returns the exact shared resource.
    #[must_use]
    pub const fn resource(self) -> FederationResourceScope {
        self.resource
    }

    /// Returns the already-intersected bilateral/governance policy.
    #[must_use]
    pub const fn policy(self) -> FederationPolicy {
        self.policy
    }

    /// Returns the authority epoch which fences older grants.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the first authorised instant, inclusive.
    #[must_use]
    pub const fn valid_from(self) -> UnixMicros {
        self.valid_from
    }

    /// Returns the expiry instant, exclusive, or `None` for explicit indefinite access.
    #[must_use]
    pub const fn valid_until(self) -> Option<UnixMicros> {
        self.valid_until
    }
}

/// Exact grant-use evidence attached to one disconnected mutation or remote storage operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedMutationEvidence {
    grant_id: FederationGrantId,
    relationship_id: FederationRelationshipId,
    subject: FederatedPrincipal,
    resource: FederationResourceScope,
    authority_epoch: u64,
    accepted_at: UnixMicros,
    required_rights: Rights,
    storage_bytes: u64,
}

impl FederatedMutationEvidence {
    /// Constructs evidence without trusting that the referenced grant permits it.
    #[allow(
        clippy::too_many_arguments,
        reason = "untrusted use evidence must preserve every field checked during reconciliation"
    )]
    #[must_use]
    pub const fn new(
        grant_id: FederationGrantId,
        relationship_id: FederationRelationshipId,
        subject: FederatedPrincipal,
        resource: FederationResourceScope,
        authority_epoch: u64,
        accepted_at: UnixMicros,
        required_rights: Rights,
        storage_bytes: u64,
    ) -> Self {
        Self {
            grant_id,
            relationship_id,
            subject,
            resource,
            authority_epoch,
            accepted_at,
            required_rights,
            storage_bytes,
        }
    }
}

/// Authoritative reconciliation result for one structurally authentic remote operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedMutationAdmission {
    /// The mutation remains inside the exact current/historical authority envelope.
    Admitted,
    /// The mutation remains invisible but its acknowledged immutable bytes are retained.
    Quarantined(QuarantineReason),
}

/// Why an acknowledged disconnected mutation cannot enter the shared namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineReason {
    /// The peer accepted work before the grant became valid.
    BeforeValidity,
    /// The peer accepted work at or after the grant's expiry.
    Expired,
    /// Authoritative revocation was already effective when the peer accepted work.
    Revoked,
    /// The operation requested namespace authority excluded by the effective restrictions.
    OutsideRights,
    /// The remote storage operation exceeded or contradicted its effective capacity policy.
    OutsideStorageLimit,
}

/// Reconciles one grant use against exact authority history.
///
/// `revoked_at` is the authoritative effective instant, not when this process learned about it.
/// Structurally substituted evidence is rejected as an attack; authentic but newly inadmissible
/// work is quarantined so it is neither published nor silently destroyed.
///
/// # Errors
///
/// Rejects evidence which names a different grant, relationship, principal, resource or epoch.
pub fn classify_federated_mutation(
    grant: FederationGrant,
    evidence: FederatedMutationEvidence,
    revoked_at: Option<UnixMicros>,
) -> Result<FederatedMutationAdmission, FederationGrantError> {
    validate_evidence_identity(grant, evidence)?;
    if evidence.accepted_at < grant.valid_from {
        return Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::BeforeValidity,
        ));
    }
    if grant
        .valid_until
        .is_some_and(|valid_until| evidence.accepted_at >= valid_until)
    {
        return Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::Expired,
        ));
    }
    if revoked_at.is_some_and(|revoked_at| evidence.accepted_at >= revoked_at) {
        return Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::Revoked,
        ));
    }
    classify_policy_use(grant.resource, grant.policy, evidence)
}

/// Invalid federation grant or substituted grant-use evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationGrantError {
    /// Authority epochs begin at one and never use the zero sentinel.
    #[error("federation grant authority epoch is invalid")]
    InvalidEpoch,
    /// The validity interval is empty, reversed or exceeds the effective offline policy.
    #[error("federation grant validity interval is invalid")]
    InvalidInterval,
    /// Namespace and storage policy was attached to the wrong resource kind.
    #[error("federation grant policy does not match its resource")]
    InvalidResourcePolicy,
    /// Untrusted use evidence substituted an authority-bound field.
    #[error("federated mutation evidence does not match its grant")]
    EvidenceMismatch,
}

fn validate_interval(
    policy: FederationPolicy,
    valid_from: UnixMicros,
    valid_until: Option<UnixMicros>,
) -> Result<(), FederationGrantError> {
    match (policy.maximum_offline_duration(), valid_until) {
        (Some(_), None) => Err(FederationGrantError::InvalidInterval),
        (maximum, Some(valid_until)) => {
            let duration = valid_until
                .get()
                .checked_sub(valid_from.get())
                .and_then(|value| u64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(FederationGrantError::InvalidInterval)?;
            if maximum.is_some_and(|maximum| duration > maximum.get()) {
                Err(FederationGrantError::InvalidInterval)
            } else {
                Ok(())
            }
        }
        (None, None) => Ok(()),
    }
}

fn validate_resource_policy(
    resource: FederationResourceScope,
    policy: FederationPolicy,
) -> Result<(), FederationGrantError> {
    match (resource, policy) {
        (FederationResourceScope::StorageCapacity { .. }, FederationPolicy::Storage(_))
        | (
            FederationResourceScope::Volume { .. }
            | FederationResourceScope::Subtree { .. }
            | FederationResourceScope::File { .. },
            FederationPolicy::Namespace(_),
        ) => Ok(()),
        _ => Err(FederationGrantError::InvalidResourcePolicy),
    }
}

fn validate_evidence_identity(
    grant: FederationGrant,
    evidence: FederatedMutationEvidence,
) -> Result<(), FederationGrantError> {
    if evidence.grant_id != grant.grant_id
        || evidence.relationship_id != grant.relationship_id
        || evidence.subject != grant.subject
        || evidence.resource != grant.resource
        || evidence.authority_epoch != grant.authority_epoch
    {
        Err(FederationGrantError::EvidenceMismatch)
    } else {
        Ok(())
    }
}

fn classify_policy_use(
    resource: FederationResourceScope,
    policy: FederationPolicy,
    evidence: FederatedMutationEvidence,
) -> Result<FederatedMutationAdmission, FederationGrantError> {
    match (resource, policy) {
        (FederationResourceScope::StorageCapacity { .. }, FederationPolicy::Storage(policy)) => {
            if !evidence.required_rights.is_empty() || evidence.storage_bytes == 0 {
                return Err(FederationGrantError::EvidenceMismatch);
            }
            if evidence.storage_bytes > policy.maximum_storage_bytes() {
                Ok(FederatedMutationAdmission::Quarantined(
                    QuarantineReason::OutsideStorageLimit,
                ))
            } else {
                Ok(FederatedMutationAdmission::Admitted)
            }
        }
        (
            FederationResourceScope::Volume { .. }
            | FederationResourceScope::Subtree { .. }
            | FederationResourceScope::File { .. },
            FederationPolicy::Namespace(policy),
        ) => {
            if evidence.required_rights.is_empty() || evidence.storage_bytes != 0 {
                return Err(FederationGrantError::EvidenceMismatch);
            }
            if policy.access().rights().contains(evidence.required_rights) {
                Ok(FederatedMutationAdmission::Admitted)
            } else {
                Ok(FederatedMutationAdmission::Quarantined(
                    QuarantineReason::OutsideRights,
                ))
            }
        }
        _ => Err(FederationGrantError::InvalidResourcePolicy),
    }
}

#[cfg(test)]
#[path = "federation_access_tests.rs"]
mod tests;
