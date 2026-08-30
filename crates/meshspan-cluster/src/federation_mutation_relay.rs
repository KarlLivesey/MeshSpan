// SPDX-License-Identifier: GPL-2.0-only

//! Verification and countersigning of downstream mutations for an upstream owner.

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, FederatedMutationEvidence,
    FederationGrantId, FederationPolicy, FederationRelationshipId, UnixMicros,
};
use meshspan_filesystem::NamespaceHistoryCommitRecord;
use meshspan_metadata::{AuthoritativeRepository, LocalDatabase, RepositoryError};
use thiserror::Error;

use crate::{
    EffectiveFederationGrantAuthorityError, FederatedHistoryMutationAdmissionError,
    FederationAuthorityError, classify_federated_history_mutation,
    effective_federation_grant_authority, federation_connection_authority,
};

/// Verifies a downstream acknowledgement, then countersigns it for the direct upstream owner.
///
/// The original actor is preserved. The relaying swarm becomes the accountable accepting swarm,
/// so the owner needs no direct relationship with or credentials from the downstream swarm.
///
/// # Errors
///
/// Rejects invalid downstream history, quarantine outcomes, unavailable upstream authority,
/// insufficient rights, scope substitution or a private key not matching committed identity.
#[allow(
    clippy::too_many_arguments,
    reason = "relay admission binds independent history, authority, time and signing inputs"
)]
pub fn relay_federated_history_mutation(
    repository: &AuthoritativeRepository,
    upstream_remote_cache: &LocalDatabase,
    record: &NamespaceHistoryCommitRecord,
    downstream: &FederatedMutationAcknowledgement,
    upstream_relationship_id: FederationRelationshipId,
    upstream_grant_id: FederationGrantId,
    now: UnixMicros,
    signing_key: &SigningKey,
) -> Result<FederatedMutationAcknowledgement, FederationMutationRelayError> {
    let downstream_admission =
        classify_federated_history_mutation(repository, record, downstream, now)?;
    if downstream_admission.admission() != FederatedMutationAdmission::Admitted {
        return Err(FederationMutationRelayError::DownstreamQuarantined);
    }
    let effective = effective_federation_grant_authority(
        repository,
        upstream_remote_cache,
        upstream_relationship_id,
        upstream_grant_id,
        now,
    )?
    .ok_or(FederationMutationRelayError::AuthorityUnavailable)?;
    let connection = federation_connection_authority(repository, upstream_relationship_id, now)?
        .ok_or(FederationMutationRelayError::AuthorityUnavailable)?;
    let grant = &effective.grant;
    let FederationPolicy::Namespace(policy) = grant.policy() else {
        return Err(FederationMutationRelayError::Denied);
    };
    let authority = record.mutation_authority().map_err(|_| {
        FederationMutationRelayError::Downstream(
            FederatedHistoryMutationAdmissionError::BindingMismatch,
        )
    })?;
    if grant.recipient_mesh_id() != connection.local_identity.local_mesh_id
        || grant.issuer_mesh_id() != connection.local_identity.remote_mesh_id
        || !authority.is_within(grant.resource())
        || !policy
            .access()
            .rights()
            .contains(authority.required_rights())
    {
        return Err(FederationMutationRelayError::Denied);
    }
    if signing_key.verifying_key().to_bytes() != connection.local_identity.verifying_key {
        return Err(FederationMutationRelayError::IdentityMismatch);
    }
    let mut relayed = FederatedMutationAcknowledgement {
        source_operation_id: downstream.source_operation_id,
        evidence: FederatedMutationEvidence::new_relayed(
            grant.grant_id(),
            grant.relationship_id(),
            downstream.evidence.actor(),
            connection.local_identity.local_mesh_id,
            grant.resource(),
            grant.authority_epoch(),
            now,
            authority.required_rights(),
            0,
        ),
        payload_digest: downstream.payload_digest,
        signer_generation: connection.local_identity.identity_generation,
        signature: [0; 64],
    };
    relayed.signature = signing_key.sign(&relayed.signing_payload()).to_bytes();
    Ok(relayed)
}

/// Closed relay failures which never collapse quarantine into a retryable authority error.
#[derive(Debug, Error)]
pub enum FederationMutationRelayError {
    /// The downstream acknowledgement or immutable history binding was invalid.
    #[error("downstream federated mutation is invalid")]
    Downstream(#[from] FederatedHistoryMutationAdmissionError),
    /// The downstream acknowledgement was authentic but is quarantined.
    #[error("downstream federated mutation is quarantined")]
    DownstreamQuarantined,
    /// Current exact upstream grant authority is unavailable.
    #[error("upstream federation authority is unavailable")]
    AuthorityUnavailable,
    /// The upstream relationship, grant, scope or rights do not cover the mutation.
    #[error("federated mutation relay is outside upstream authority")]
    Denied,
    /// The private relay key does not match current committed identity.
    #[error("federation relay signing identity does not match committed authority")]
    IdentityMismatch,
    /// Bilateral grant evidence was unavailable or contradictory.
    #[error("upstream bilateral grant authority failed")]
    Grant(#[from] EffectiveFederationGrantAuthorityError),
    /// Current relationship identity evidence was unavailable or inconsistent.
    #[error("upstream federation signing identity authority failed")]
    Identity(#[from] FederationAuthorityError),
    /// Local authoritative metadata was unreadable or corrupt.
    #[error("federation relay metadata failed")]
    Metadata(#[from] RepositoryError),
}
