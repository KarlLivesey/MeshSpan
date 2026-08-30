// SPDX-License-Identifier: GPL-2.0-only

//! Home-swarm authentication and signing for one exact disconnected namespace mutation.

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationEvidence, FederatedPrincipal,
    FederationGrantId, FederationPolicy, FederationRelationshipId, UnixMicros,
};
use meshspan_filesystem::FederatedNamespaceMutationProposal;
use meshspan_metadata::{
    AuthoritativeRepository, LocalDatabase, RepositoryError, SessionAccessDecision,
    SessionAccessDenial, SessionAccessRequest,
};
use thiserror::Error;

use crate::{
    EffectiveFederationGrantAuthorityError, FederationAuthorityError,
    effective_federation_grant_authority, federation_connection_authority,
};

/// Untrusted connector context for authorising one canonical federated mutation proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationMutationAcceptanceRequest {
    /// Mutually approved relationship carrying the namespace grant.
    pub relationship_id: FederationRelationshipId,
    /// Exact bilateral grant claimed for this mutation.
    pub grant_id: FederationGrantId,
    /// Home-swarm session and gateway evidence; raw credentials never enter the branch store.
    pub session: SessionAccessRequest,
    /// Authoritative home-swarm instant at which the mutation becomes durable.
    pub now: UnixMicros,
}

/// Authority facts which a signer may bind only after every current metadata check passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedFederationMutation {
    evidence: FederatedMutationEvidence,
    signer_generation: u64,
    signer_verifying_key: [u8; 32],
}

/// Replaceable authority boundary which cannot alter canonical filesystem mutation facts.
pub trait FederationMutationAcceptanceAuthority {
    /// Stable implementation failure, including denial and unavailable committed authority.
    type Error;

    /// Authenticates the home user and intersects both swarms' current exact grant authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid sessions, stale/revoked authority, insufficient rights or scope mismatch.
    fn admit(
        &self,
        request: FederationMutationAcceptanceRequest,
        proposal: &FederatedNamespaceMutationProposal,
    ) -> Result<AdmittedFederationMutation, Self::Error>;
}

/// Metadata-backed authority using one local consensus projection and authenticated remote cache.
pub struct MetadataFederationMutationAcceptanceAuthority<'a> {
    repository: &'a AuthoritativeRepository,
    remote_cache: &'a LocalDatabase,
}

impl<'a> MetadataFederationMutationAcceptanceAuthority<'a> {
    /// Composes current local authority with the last complete authenticated remote observation.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        remote_cache: &'a LocalDatabase,
    ) -> Self {
        Self {
            repository,
            remote_cache,
        }
    }
}

impl FederationMutationAcceptanceAuthority for MetadataFederationMutationAcceptanceAuthority<'_> {
    type Error = MetadataFederationMutationAcceptanceError;

    fn admit(
        &self,
        request: FederationMutationAcceptanceRequest,
        proposal: &FederatedNamespaceMutationProposal,
    ) -> Result<AdmittedFederationMutation, Self::Error> {
        if request.session.now != request.now || proposal.authority().created_at() > request.now {
            return Err(MetadataFederationMutationAcceptanceError::InvalidRequest);
        }
        let session = match self.repository.evaluate_session_access(request.session)? {
            SessionAccessDecision::Granted(capability) => capability,
            SessionAccessDecision::Denied(denial) => {
                return Err(MetadataFederationMutationAcceptanceError::SessionDenied(
                    denial,
                ));
            }
        };
        let effective = effective_federation_grant_authority(
            self.repository,
            self.remote_cache,
            request.relationship_id,
            request.grant_id,
            request.now,
        )?
        .ok_or(MetadataFederationMutationAcceptanceError::AuthorityUnavailable)?;
        let connection =
            federation_connection_authority(self.repository, request.relationship_id, request.now)?
                .ok_or(MetadataFederationMutationAcceptanceError::AuthorityUnavailable)?;
        let grant = &effective.grant;
        let actor = FederatedPrincipal::new(
            connection.local_identity.local_mesh_id,
            session.principal_id,
        );
        let FederationPolicy::Namespace(policy) = grant.policy() else {
            return Err(MetadataFederationMutationAcceptanceError::InvalidRequest);
        };
        let authority = proposal.authority();
        let exact_actor = grant.recipient_mesh_id() == connection.local_identity.local_mesh_id
            && grant.issuer_mesh_id() == connection.local_identity.remote_mesh_id
            && authority.created_by() == session.principal_id;
        let exact_scope = grant.route().issuer_mesh_id()
            == connection.local_identity.remote_mesh_id
            && authority.is_within(grant.resource());
        let local_assignment = self.repository.evaluate_federation_grant_assignment(
            grant.grant_id(),
            session.principal_id,
            session.identity_revision,
            authority.required_rights(),
            request.now,
        )?;
        if !exact_actor
            || !exact_scope
            || local_assignment.is_none()
            || !policy
                .access()
                .rights()
                .contains(authority.required_rights())
        {
            return Err(MetadataFederationMutationAcceptanceError::Denied);
        }
        Ok(AdmittedFederationMutation {
            evidence: FederatedMutationEvidence::new(
                grant.grant_id(),
                grant.relationship_id(),
                actor,
                grant.resource(),
                grant.authority_epoch(),
                request.now,
                authority.required_rights(),
                0,
            ),
            signer_generation: connection.local_identity.identity_generation,
            signer_verifying_key: connection.local_identity.verifying_key,
        })
    }
}

/// Signs only authority-derived evidence for the exact canonical filesystem proposal.
pub struct FederationMutationAcceptor<'a, A> {
    authority: A,
    signing_key: &'a SigningKey,
}

impl<'a, A> FederationMutationAcceptor<'a, A> {
    /// Binds the current private federation identity to a replaceable admission authority.
    #[must_use]
    pub const fn new(authority: A, signing_key: &'a SigningKey) -> Self {
        Self {
            authority,
            signing_key,
        }
    }
}

impl<A> FederationMutationAcceptor<'_, A>
where
    A: FederationMutationAcceptanceAuthority,
{
    /// Authenticates, authorises and signs one exact immutable branch mutation.
    ///
    /// # Errors
    ///
    /// Rejects authority failure or a private key not matching current committed identity.
    pub fn acknowledge(
        &self,
        request: FederationMutationAcceptanceRequest,
        proposal: &FederatedNamespaceMutationProposal,
    ) -> Result<FederatedMutationAcknowledgement, FederationMutationAcceptanceError<A::Error>> {
        let admitted = self
            .authority
            .admit(request, proposal)
            .map_err(FederationMutationAcceptanceError::Authority)?;
        if self.signing_key.verifying_key().to_bytes() != admitted.signer_verifying_key {
            return Err(FederationMutationAcceptanceError::IdentityMismatch);
        }
        let mut acknowledgement = FederatedMutationAcknowledgement {
            source_operation_id: proposal.authority().operation_id(),
            evidence: admitted.evidence,
            payload_digest: proposal.payload_digest(),
            signer_generation: admitted.signer_generation,
            signature: [0; 64],
        };
        acknowledgement.signature = self
            .signing_key
            .sign(&acknowledgement.signing_payload())
            .to_bytes();
        Ok(acknowledgement)
    }
}

/// Fail-closed production metadata admission failures.
#[derive(Debug, Error)]
pub enum MetadataFederationMutationAcceptanceError {
    /// The connector supplied contradictory time or pre-publication facts.
    #[error("federated mutation acceptance request is invalid")]
    InvalidRequest,
    /// The home session or gateway is not currently usable.
    #[error("home-swarm session denied federated mutation")]
    SessionDenied(SessionAccessDenial),
    /// Either swarm's exact current relationship/grant authority is unavailable.
    #[error("bilateral federation mutation authority is unavailable")]
    AuthorityUnavailable,
    /// The authenticated subject, namespace scope or requested rights are outside the grant.
    #[error("federated mutation is outside current authority")]
    Denied,
    /// Local session metadata was unreadable or corrupt.
    #[error("home-swarm session authority failed")]
    Metadata(#[from] RepositoryError),
    /// Bilateral grant evidence was unavailable or contradictory.
    #[error("bilateral federation grant authority failed")]
    Grant(#[from] EffectiveFederationGrantAuthorityError),
    /// Current relationship identity evidence was unavailable or inconsistent.
    #[error("federation signing identity authority failed")]
    Identity(#[from] FederationAuthorityError),
}

/// Stable signing-boundary failures generic over the selected authority implementation.
#[derive(Debug, Error)]
pub enum FederationMutationAcceptanceError<E> {
    /// The selected committed authority rejected or could not classify the request.
    #[error("federated mutation authority failed")]
    Authority(E),
    /// Supplied private identity does not match current committed public identity.
    #[error("federation signing identity does not match committed authority")]
    IdentityMismatch,
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::error::Error;

    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use meshspan_domain::{
        BranchId, ContentManifestId, FederatedPrincipal, FederationGrantId,
        FederationRelationshipId, FederationResourceScope, FileVersionId, MeshId,
        NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Rights,
        UnixMicros, VolumeId,
    };
    use meshspan_filesystem::{
        FilePublication, ManifestPublication, NamespaceLimits, NamespacePath,
        NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
    };
    use meshspan_metadata::SessionAccessRequest;

    use super::{
        AdmittedFederationMutation, FederationMutationAcceptanceAuthority,
        FederationMutationAcceptanceError, FederationMutationAcceptanceRequest,
        FederationMutationAcceptor,
    };

    #[test]
    fn acceptor_signs_only_authority_derived_canonical_mutation() -> Result<(), Box<dyn Error>> {
        let proposal =
            VersionPublicationStore::root_file_federated_mutation_proposal(&publication()?)?;
        let key = SigningKey::from_bytes(&[40; 32]);
        let admitted = admitted(key.verifying_key().to_bytes())?;
        let acknowledgement = FederationMutationAcceptor::new(StaticAuthority(admitted), &key)
            .acknowledge(request()?, &proposal)?;
        assert_eq!(
            acknowledgement.source_operation_id,
            proposal.authority().operation_id()
        );
        assert_eq!(acknowledgement.payload_digest, proposal.payload_digest());
        assert_eq!(acknowledgement.evidence, admitted.evidence);
        key.verifying_key().verify(
            &acknowledgement.signing_payload(),
            &Signature::from_bytes(&acknowledgement.signature),
        )?;

        let wrong_key = SigningKey::from_bytes(&[41; 32]);
        assert!(matches!(
            FederationMutationAcceptor::new(StaticAuthority(admitted), &wrong_key)
                .acknowledge(request()?, &proposal),
            Err(FederationMutationAcceptanceError::IdentityMismatch)
        ));
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct StaticAuthority(AdmittedFederationMutation);

    impl FederationMutationAcceptanceAuthority for StaticAuthority {
        type Error = Infallible;

        fn admit(
            &self,
            _request: FederationMutationAcceptanceRequest,
            _proposal: &meshspan_filesystem::FederatedNamespaceMutationProposal,
        ) -> Result<AdmittedFederationMutation, Self::Error> {
            Ok(self.0)
        }
    }

    fn admitted(
        signer_verifying_key: [u8; 32],
    ) -> Result<AdmittedFederationMutation, Box<dyn Error>> {
        Ok(AdmittedFederationMutation {
            evidence: meshspan_domain::FederatedMutationEvidence::new(
                FederationGrantId::from_bytes([42; 16])?,
                FederationRelationshipId::from_bytes([43; 16])?,
                FederatedPrincipal::new(
                    MeshId::from_bytes([44; 16])?,
                    PrincipalId::from_bytes([28; 16])?,
                ),
                FederationResourceScope::Volume {
                    owner_mesh_id: MeshId::from_bytes([45; 16])?,
                    volume_id: VolumeId::from_bytes([22; 16])?,
                },
                1,
                UnixMicros::new(20),
                Rights::TRAVERSE
                    .union(Rights::CREATE_CHILD)
                    .union(Rights::WRITE_DATA),
                0,
            ),
            signer_generation: 1,
            signer_verifying_key,
        })
    }

    fn request() -> Result<FederationMutationAcceptanceRequest, Box<dyn Error>> {
        Ok(FederationMutationAcceptanceRequest {
            relationship_id: FederationRelationshipId::from_bytes([43; 16])?,
            grant_id: FederationGrantId::from_bytes([42; 16])?,
            session: SessionAccessRequest {
                token_digest: [46; 32],
                required_assurance: meshspan_domain::AssuranceLevel::SingleFactor,
                gateway_node_id: meshspan_domain::NodeId::from_bytes([47; 16])?,
                gateway_incarnation: 1,
                now: UnixMicros::new(20),
            },
            now: UnixMicros::new(20),
        })
    }

    fn publication() -> Result<RootFilePublication, Box<dyn Error>> {
        Ok(RootFilePublication {
            file: FilePublication {
                operation_id: OperationId::from_bytes([20; 16])?,
                branch_id: BranchId::from_bytes([21; 16])?,
                volume_id: VolumeId::from_bytes([22; 16])?,
                object_id: ObjectId::from_bytes([23; 16])?,
                expected_current_version_id: None,
                version_id: FileVersionId::from_bytes([24; 16])?,
                parent_version_id: None,
                retain_superseded_history: true,
                retention_policy_sequence: 1,
                manifest: ManifestPublication {
                    manifest_id: ContentManifestId::from_bytes([25; 16])?,
                    format_version: 1,
                    logical_length: 4,
                    content_digest: [26; 32],
                    root_digest: [27; 32],
                },
                created_by: PrincipalId::from_bytes([28; 16])?,
                created_at: UnixMicros::new(20),
            },
            root_object_id: ObjectId::from_bytes([29; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([30; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([31; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([32; 16])?,
            path: NamespacePublicationPath::new(
                NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
                Vec::new(),
            )?,
            entry_generation: 1,
        })
    }
}

#[cfg(test)]
#[path = "federation_mutation_acceptance_tests.rs"]
mod metadata_tests;
