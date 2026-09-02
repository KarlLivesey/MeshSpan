// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative command application and exact operation resolution.

mod access_evaluation;
mod access_query;
mod acknowledgement_policy;
#[cfg(test)]
mod acknowledgement_policy_tests;
mod apply;
mod authentication_method;
mod authentication_method_creation;
#[cfg(test)]
mod authentication_method_creation_tests;
mod authentication_method_query;
#[cfg(test)]
mod authentication_method_query_tests;
#[cfg(test)]
mod authentication_method_tests;
mod authentication_policy;
#[cfg(test)]
mod authentication_policy_tests;
mod availability_cell;
#[cfg(test)]
mod availability_cell_tests;
mod backup;
mod bootstrap;
#[cfg(test)]
mod bootstrap_appliance_tests;
mod cleanup_attestation;
mod cleanup_completion;
mod cleanup_inventory;
mod cleanup_permit;
mod cleanup_reclamation;
mod cluster;
mod component;
mod consensus;
mod federation_actor_attestation;
#[cfg(test)]
mod federation_actor_attestation_tests;
mod federation_assignment;
mod federation_authority_snapshot;
#[cfg(test)]
mod federation_backup_test_support;
#[cfg(test)]
mod federation_downstream_tests;
mod federation_grant;
mod federation_grant_cursor;
mod federation_grant_evidence;
mod federation_grant_page;
mod federation_grant_record;
#[cfg(test)]
mod federation_grant_tests;
mod federation_mutation_admission;
#[cfg(test)]
mod federation_mutation_admission_tests;
mod federation_quarantine;
mod federation_quarantine_codec;
mod federation_quarantine_evidence;
#[cfg(test)]
mod federation_quarantine_tests;
mod federation_quarantine_transition;
mod federation_query;
mod federation_relationship;
mod federation_relationship_evidence;
#[cfg(test)]
mod federation_relationship_tests;
mod federation_storage_allocation;
#[cfg(test)]
mod federation_storage_allocation_tests;
mod federation_succession;
mod federation_succession_evidence;
mod federation_succession_graph;
#[cfg(test)]
mod federation_succession_tests;
mod federation_succession_transition;
mod federation_succession_trust;
mod group_closure;
mod identity;
mod kernel;
mod locality_policy;
#[cfg(test)]
mod locality_policy_tests;
mod membership;
mod mesh_identity;
mod namespace;
mod node_wrapping_key;
#[cfg(test)]
mod node_wrapping_key_tests;
mod operation_status;
#[cfg(test)]
mod operation_status_tests;
mod passkey_registration;
#[cfg(test)]
mod passkey_registration_tests;
mod protection_policy;
#[cfg(test)]
mod protection_policy_tests;
mod query;
mod quorum_plan;
mod reachability;
mod receipt;
mod recovery_authority;
#[cfg(test)]
mod recovery_authority_tests;
mod retention;
mod root_delegation;
mod root_delegation_evidence;
mod routing;
mod secret_generation;
#[cfg(test)]
mod secret_generation_tests;
mod session;
mod session_access;
#[cfg(test)]
mod session_tests;
mod smb_export;
mod smb_export_configuration;
#[cfg(test)]
mod smb_export_tests;
mod snapshot;
mod snapshot_schedule;
mod storage_target;
#[cfg(test)]
mod storage_target_tests;
mod tags;
mod topology;
#[cfg(test)]
mod topology_tests;
mod user_snapshot;
mod verify;
mod version_cleanup;
mod volume_head;
mod volume_inventory;
#[cfg(test)]
mod volume_inventory_tests;

use meshspan_domain::{GroupId, OperationId, Revision, ScopeId, ScopeRoute};
use thiserror::Error;

use crate::{MetadataStoreError, PartitionDatabase};

pub use access_evaluation::{
    AccessAuthentication, AccessCapability, AccessDecision, AccessDenial, AccessRequest,
};
pub use access_query::{
    AccessActivationCursor, AccessActivationRecord, ObjectOwnerCursor, ObjectOwnerRecord,
    PermissionGrantRecord, PermissionGrantRevocationRecord, ScopedGrantCursor, SubjectGrantCursor,
};
pub use acknowledgement_policy::{
    AcknowledgementPolicyCursor, AcknowledgementPolicyRecord, VolumeAcknowledgementPolicy,
};
pub use authentication_method::{
    ApiKeyAuthentication, AuthenticationMethodRevocationReplay, PasskeyVerificationMaterial,
    RecoveryCodeVerificationMaterial, SmbVerificationMaterial, TotpVerificationMaterial,
};
pub use authentication_method_query::{
    AuthenticationMethodCursor, AuthenticationMethodRecord, AuthenticationMethodRecordDetails,
};
pub use authentication_policy::AuthenticationPolicy;
pub use availability_cell::{AvailabilityCellCursor, AvailabilityCellRecord};
pub use backup::{PartitionBackupManifest, restore_partition_backup};
pub use cleanup_attestation::{VersionCleanupAttestationProgress, VersionCleanupParticipant};
pub use cleanup_completion::{VersionCleanupCompletion, VersionCleanupItemCompletion};
pub use cleanup_inventory::{
    VersionCleanupInventory, VersionCleanupInventoryState, VersionCleanupItem,
    VersionCleanupItemCursor,
};
pub use cleanup_permit::{
    MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, VersionCleanupPermitAttempt,
    VersionCleanupPermitAuthority,
};
pub use cleanup_reclamation::{VersionCleanupItemReclamation, VersionCleanupReclamation};
pub use cluster::{
    ActiveNodeCertificate, JoinGrantRecord, NodeActivationCandidate, NodeActivationRecord,
    NodeEnrolmentRecord,
};
pub use consensus::{ConsensusStoreError, PartitionConsensusPersistence};
pub use federation_actor_attestation::FederatedActorAttestationRecord;
pub use federation_assignment::FederationGrantAssignmentAuthority;
pub use federation_authority_snapshot::FederationAuthoritySnapshotError;
pub use federation_grant_cursor::{FederationGrantCursor, FederationGrantCursorError};
pub use federation_grant_evidence::{
    FederationGrantRecord, FederationGrantState, FederationGrantTermination,
    FederationGrantTerminationKind,
};
pub use federation_grant_record::FederationGrantRecordCodecError;
pub use federation_mutation_admission::FederatedMutationAdmissionReceipt;
pub use federation_quarantine::{FederationQuarantineRecord, FederationQuarantineState};
pub use federation_query::{
    FederationRelationshipRecord, FederationRelationshipState, FederationTransportAuthority,
    FederationTrustIdentityRecord,
};
pub use federation_storage_allocation::{
    FederationStorageAllocationAuthority, FederationStorageAllocationRecord,
    FederationStorageAllocationState, FederationStorageAuthorityRequest,
};
pub use federation_succession::{FederationSuccessionRecord, FederationSuccessionState};
pub use kernel::{
    AuthoritativeMetadataKernel, RepositoryConformanceCheck, RepositoryConformanceReport,
    RepositoryConformanceVector, run_repository_conformance,
};
pub use locality_policy::{
    LocalityPolicyCursor, LocalityPolicyRecord, LocalityRequirementRecord, VolumeLocalityPolicy,
};
pub use membership::AuthoritativeMembership;
pub use meshspan_domain::AuthenticationService;
pub use node_wrapping_key::NodeWrappingKeyRecord;
pub use operation_status::{
    AuthoritativeOperationCursor, AuthoritativeOperationState, AuthoritativeOperationStatus,
};
pub use passkey_registration::{
    AuthenticationMethodCreationReplay, AuthenticationRegistrationProfile,
    PasskeyRegistrationProfile, PasskeyRegistrationReplay,
};
pub use protection_policy::{
    ProtectionPolicyCursor, ProtectionPolicyRecord, ProtectionScenarioRecord, ProtectionTermRecord,
    VolumeProtectionPolicy,
};
pub use query::{
    GroupMemberCursor, GroupMembershipEventKind, GroupMembershipEventRecord, GroupMembershipRecord,
    NamespaceCursor, NamespaceRecord, Page, PageLimit, PrincipalCursor, PrincipalKind,
    PrincipalRecord,
};
pub use reachability::{
    RetainedNamespaceRoot, RetainedNamespaceRootCursor, RetainedNamespaceRootPage,
    RetainedNamespaceRootSource,
};
pub use receipt::{ApplyDisposition, CommandReceipt, EntityKind, EntityReference, LogPosition};
pub use recovery_authority::{
    MeshRecoveryAuthority, OnlineCertificateAuthorityRecord, RecoveryBundleState,
};
pub use retention::VersionRetentionPolicy;
pub use secret_generation::SecretGenerationRecord;
pub use session::{
    ApiKeySessionReplay, AuthenticationSessionReplay, AuthenticationSessionReplayCredential,
    AuthenticationSessionReplayFactor, PasskeySessionReplay, SessionRevocationReplay,
};
pub use session_access::{
    BrowserSessionAccessRequest, BrowserSessionProtection, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest,
};
pub use smb_export::{SmbExportGatewayPolicy, SmbExportRecord};
pub use snapshot::{PartitionSnapshotManifest, PreservedVote, restore_partition_snapshot};
pub use snapshot_schedule::{SnapshotSchedule, SnapshotScheduleCursor};
pub use storage_target::{StorageTargetProviderContext, StorageTargetRegistrationContext};
pub use topology::{
    FaultGroupCursor, FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord,
    TopologyNodeCursor, TopologyNodeRecord, TopologyTargetCursor, TopologyTargetRecord,
};
pub use user_snapshot::{
    SnapshotCursor, SnapshotExpiryCandidate, SnapshotExpiryCursor, VolumeSnapshot,
};
pub use verify::{InvariantFinding, InvariantKind, InvariantReport};
pub use version_cleanup::{VersionCleanupIntent, VersionCleanupState};
pub use volume_head::ConvergedVolumeHead;
pub use volume_inventory::{VolumeInventoryCursor, VolumeInventoryRecord};

/// Authoritative metadata repository owning one identity-bound partition database.
pub struct AuthoritativeRepository {
    database: PartitionDatabase,
}

/// Read boundary used by a consensus authority before accepting a scope mutation.
pub trait ScopeWriteAuthority {
    /// Returns whether this exact local partition owns the scope at the presented route epoch.
    ///
    /// # Errors
    ///
    /// Fails closed when the route is absent or its durable representation is corrupt.
    fn permits_scope_write(
        &self,
        scope_id: ScopeId,
        routing_epoch: u64,
    ) -> Result<bool, RepositoryError>;
}

impl ScopeWriteAuthority for AuthoritativeRepository {
    fn permits_scope_write(
        &self,
        scope_id: ScopeId,
        routing_epoch: u64,
    ) -> Result<bool, RepositoryError> {
        let route = routing::load_scope(self.database.connection(), scope_id)?;
        Ok(route.permits_write(self.database.partition_id(), routing_epoch))
    }
}

impl AuthoritativeMetadataKernel for AuthoritativeRepository {
    fn current_revision(&self) -> Result<Revision, RepositoryError> {
        Self::current_revision(self)
    }

    fn apply_committed(
        &mut self,
        position: LogPosition,
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
    ) -> Result<CommandReceipt, RepositoryError> {
        Self::apply_committed(self, position, context, command)
    }

    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, RepositoryError> {
        Self::resolve_operation(self, operation_id)
    }

    fn check_invariants(&self, limit: PageLimit) -> Result<InvariantReport, RepositoryError> {
        Self::check_invariants(self, limit)
    }
}

impl AuthoritativeRepository {
    /// Returns the immutable partition identity fixed by the opened database.
    #[must_use]
    pub const fn partition_id(&self) -> meshspan_domain::PartitionId {
        self.database.partition_id()
    }

    /// Returns the root partition's one intrinsic local mesh identity.
    ///
    /// # Errors
    ///
    /// Fails closed if a root partition contains multiple meshes or malformed identity bytes.
    pub fn local_mesh_id(&self) -> Result<Option<meshspan_domain::MeshId>, RepositoryError> {
        mesh_identity::local_mesh_id(&self.database)
    }

    /// Returns immutable issuance facts for one current node join grant.
    ///
    /// # Errors
    ///
    /// Fails closed when stored grant identity, roles, time or revision state is malformed.
    pub fn join_grant(
        &self,
        join_grant_id: meshspan_domain::JoinGrantId,
    ) -> Result<Option<JoinGrantRecord>, RepositoryError> {
        cluster::join_grant(&self.database, join_grant_id)
    }

    /// Returns exact durable admission facts for one pending node activation.
    ///
    /// # Errors
    ///
    /// Fails closed when node, certificate or staged endpoint state is malformed.
    pub fn node_enrolment(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<NodeEnrolmentRecord>, RepositoryError> {
        cluster::node_enrolment(&self.database, node_id)
    }

    /// Returns one admitted node's exact pending private-activation facts.
    ///
    /// # Errors
    ///
    /// Fails closed when admission, certificate, role, endpoint or issuer state is malformed.
    pub fn node_activation_candidate(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<NodeActivationCandidate>, RepositoryError> {
        cluster::node_activation_candidate(&self.database, node_id)
    }

    /// Returns exact durable evidence for one active node.
    ///
    /// # Errors
    ///
    /// Fails closed when activation evidence is malformed.
    pub fn node_activation(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<NodeActivationRecord>, RepositoryError> {
        cluster::node_activation(&self.database, node_id)
    }

    /// Returns the newest active mesh-signed leaf certificate for one active node.
    ///
    /// # Errors
    ///
    /// Fails closed when certificate identity, digest, validity or revision state is malformed.
    pub fn active_node_certificate(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<ActiveNodeCertificate>, RepositoryError> {
        cluster::active_node_certificate(&self.database, node_id)
    }

    /// Wraps one already migrated and identity-verified partition database.
    #[must_use]
    pub const fn new(database: PartitionDatabase) -> Self {
        Self { database }
    }

    /// Returns the currently committed state-machine revision.
    ///
    /// # Errors
    ///
    /// Fails closed if persisted state is absent, malformed or outside the supported range.
    pub fn current_revision(&self) -> Result<Revision, RepositoryError> {
        apply::read_current_revision(&self.database)
    }

    /// Returns one independently validated durable scope route.
    ///
    /// # Errors
    ///
    /// Fails closed when the route is absent or its durable representation is corrupt.
    pub fn scope_route(&self, scope_id: ScopeId) -> Result<ScopeRoute, RepositoryError> {
        routing::load_scope(self.database.connection(), scope_id)
    }

    /// Returns one root-owned delegation-directory entry with exact pending admission evidence.
    ///
    /// # Errors
    ///
    /// Fails closed when scope identity, family/range, route or handoff evidence is inconsistent.
    pub fn root_delegated_route(
        &self,
        scope_id: ScopeId,
    ) -> Result<meshspan_domain::RootDelegatedRoute, RepositoryError> {
        root_delegation_evidence::load_root_route(self.database.connection(), scope_id)
    }

    /// Returns one validated federation relationship projection, if it exists.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identities, states, epochs or relationship shapes.
    pub fn federation_relationship(
        &self,
        relationship_id: meshspan_domain::FederationRelationshipId,
    ) -> Result<Option<FederationRelationshipRecord>, RepositoryError> {
        federation_query::relationship(&self.database, relationship_id)
    }

    /// Returns the active public identity for one exact relationship side.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or multiple active identities.
    pub fn active_federation_trust_identity(
        &self,
        relationship_id: meshspan_domain::FederationRelationshipId,
        owner: crate::FederationIdentityOwner,
    ) -> Result<Option<FederationTrustIdentityRecord>, RepositoryError> {
        federation_query::active_identity(&self.database, relationship_id, owner)
    }

    /// Returns one complete disjoint federation storage allocation, if it exists.
    ///
    /// # Errors
    ///
    /// Fails closed when the stored allocation or lifecycle evidence is malformed.
    pub fn federation_storage_allocation(
        &self,
        allocation_id: meshspan_domain::FederationStorageAllocationId,
    ) -> Result<Option<FederationStorageAllocationRecord>, RepositoryError> {
        federation_storage_allocation::load(self.database.connection(), allocation_id)
    }

    /// Resolves one exact current bilateral allocation authority for a provider request.
    ///
    /// # Errors
    ///
    /// Fails closed when allocation, grant, relationship or node evidence is malformed.
    pub fn active_federation_storage_allocation_authority(
        &self,
        request: FederationStorageAuthorityRequest,
    ) -> Result<Option<FederationStorageAllocationAuthority>, RepositoryError> {
        federation_storage_allocation::active_authority(&self.database, request)
    }

    /// Returns complete current transport authority only for an active or restricted relationship.
    ///
    /// # Errors
    ///
    /// Fails closed if relationship history or either current identity is malformed or incomplete.
    pub fn federation_transport_authority(
        &self,
        relationship_id: meshspan_domain::FederationRelationshipId,
    ) -> Result<Option<FederationTransportAuthority>, RepositoryError> {
        federation_query::transport_authority(&self.database, relationship_id)
    }

    /// Returns one currently usable, independently revalidated federation grant.
    ///
    /// A grant is hidden when revoked, superseded, fenced by a relationship epoch or carried by
    /// a non-active relationship. Stored policy and restriction digests are recomputed first.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed resource, principal, policy or bilateral restriction evidence.
    pub fn active_federation_grant(
        &self,
        grant_id: meshspan_domain::FederationGrantId,
    ) -> Result<Option<FederationGrantRecord>, RepositoryError> {
        federation_grant_evidence::active_grant(&self.database, grant_id)
    }

    /// Returns one grant with its complete retained termination and succession evidence.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed policy, bilateral restrictions, lifecycle or lineage.
    pub fn federation_grant(
        &self,
        grant_id: meshspan_domain::FederationGrantId,
    ) -> Result<Option<FederationGrantRecord>, RepositoryError> {
        federation_grant_evidence::grant(&self.database, grant_id)
    }

    /// Returns a stable bounded page of complete grants changed within one relationship snapshot.
    ///
    /// Every returned grant is reconstructed with bilateral restrictions, termination and
    /// succession evidence. A metadata revision change invalidates the continuation rather than
    /// mixing authority snapshots.
    ///
    /// # Errors
    ///
    /// Rejects stale/mismatched cursors, invalid bounds and corrupt grant or relationship history.
    pub fn federation_grants_page(
        &self,
        relationship_id: meshspan_domain::FederationRelationshipId,
        after_revision: Revision,
        snapshot_revision: Revision,
        after: Option<FederationGrantCursor>,
        limit: PageLimit,
    ) -> Result<Page<FederationGrantRecord, FederationGrantCursor>, RepositoryError> {
        federation_grant_page::grants_by_relationship(
            &self.database,
            relationship_id,
            after_revision,
            snapshot_revision,
            after,
            limit,
        )
    }

    /// Returns one current, signed home-swarm actor lifecycle attestation.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identifiers, state, revision or missing history evidence.
    pub fn federated_actor_attestation(
        &self,
        relationship_id: meshspan_domain::FederationRelationshipId,
        principal: meshspan_domain::FederatedPrincipal,
    ) -> Result<Option<FederatedActorAttestationRecord>, RepositoryError> {
        federation_actor_attestation::attestation(&self.database, relationship_id, principal)
    }

    /// Verifies one accepting-swarm signature and classifies its exact historical grant use.
    ///
    /// Structurally substituted acknowledgements fail closed. Authentic work accepted outside
    /// grant validity, after revocation, beyond policy or by a now-inactive principal is returned
    /// as quarantine rather than silently admitted or destroyed.
    ///
    /// # Errors
    ///
    /// Fails closed for absent/corrupt authority, an unknown principal, or an invalid signature.
    pub fn classify_federated_mutation_acknowledgement(
        &self,
        acknowledgement: &meshspan_domain::FederatedMutationAcknowledgement,
    ) -> Result<meshspan_domain::FederatedMutationAdmission, RepositoryError> {
        federation_mutation_admission::classify(self.database.connection(), acknowledgement)
    }

    /// Resolves the immutable decision for one deterministic federated mutation operation.
    ///
    /// # Errors
    ///
    /// Fails closed if the operation belongs to another command family or its quarantine evidence
    /// is missing, malformed or inconsistent.
    pub fn resolve_federated_mutation_admission(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<FederatedMutationAdmissionReceipt>, RepositoryError> {
        federation_mutation_admission::resolve(&self.database, operation_id)
    }

    /// Returns the active, locally authoritative recovery successor for one retired swarm.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identifiers, epochs or lifecycle state.
    pub fn active_federation_successor(
        &self,
        retiring_mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<FederationSuccessionRecord>, RepositoryError> {
        federation_succession::active_for_retiring(&self.database, retiring_mesh_id)
    }

    /// Returns one independently revalidated federated quarantine item.
    ///
    /// # Errors
    ///
    /// Fails closed for substituted grant evidence, signatures, lifecycle or payload digests.
    pub fn federation_quarantine(
        &self,
        quarantine_id: meshspan_domain::QuarantineId,
    ) -> Result<Option<FederationQuarantineRecord>, RepositoryError> {
        federation_quarantine::quarantine(&self.database, quarantine_id)
    }

    /// Loads and verifies the exact durable consensus state for one membership epoch.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed, discontinuous, digest-mismatched or stale-epoch state.
    pub fn load_consensus_state(
        &self,
        membership_epoch: u64,
    ) -> Result<meshspan_consensus::DurableCoreState, ConsensusStoreError> {
        consensus::load_state(&self.database, membership_epoch)
    }

    /// Applies one vote/log mutation in a single durable SQLite transaction.
    ///
    /// # Errors
    ///
    /// Rejects stale terms, committed-tail truncation, malformed entries and epoch mismatch.
    pub fn persist_consensus_mutation(
        &mut self,
        membership_epoch: u64,
        mutation: &meshspan_consensus::DurableMutation,
        persisted_at: meshspan_domain::UnixMicros,
    ) -> Result<(), ConsensusStoreError> {
        consensus::persist_mutation(&mut self.database, membership_epoch, mutation, persisted_at)
    }

    /// Applies one already-committed log entry atomically and returns durable evidence.
    ///
    /// # Errors
    ///
    /// Rejects discontinuous log positions, stale revisions, conflicting operation reuse,
    /// unauthorised actors, malformed commands and any violated persisted invariant.
    pub fn apply_committed(
        &mut self,
        position: LogPosition,
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
    ) -> Result<CommandReceipt, RepositoryError> {
        apply::apply_committed(&mut self.database, position, context, command)
    }

    /// Executes the exact command transaction and rolls it back before consensus admission.
    ///
    /// # Errors
    ///
    /// Rejects any command which could not be applied immediately after current durable state.
    pub fn preflight_command(
        &mut self,
        preceding: &[(
            LogPosition,
            crate::CommandContext,
            crate::AuthoritativeCommand,
        )],
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
    ) -> Result<(), RepositoryError> {
        apply::preflight_command(&mut self.database, preceding, context, command)
    }

    #[cfg(test)]
    fn apply_committed_with_fault(
        &mut self,
        position: LogPosition,
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
        fault: apply::ApplyFaultPoint,
    ) -> Result<CommandReceipt, RepositoryError> {
        apply::apply_committed_with_fault(&mut self.database, position, context, command, fault)
    }

    /// Resolves the exact durable result stored for an operation, if present.
    ///
    /// # Errors
    ///
    /// Fails closed if any persisted receipt field is malformed or inconsistent.
    pub fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, RepositoryError> {
        receipt::resolve_operation(&self.database, operation_id)
    }

    /// Returns validated current status for one authoritative operation, if present.
    ///
    /// # Errors
    ///
    /// Fails closed when lifecycle, actor, result or timestamp evidence is inconsistent.
    pub fn operation_status(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthoritativeOperationStatus>, RepositoryError> {
        operation_status::read(&self.database, operation_id)
    }

    /// Returns one bounded reverse-chronological page of authoritative operations.
    ///
    /// # Errors
    ///
    /// Fails closed when any listed lifecycle, actor, result or timestamp is inconsistent.
    pub fn operation_statuses(
        &self,
        after: Option<AuthoritativeOperationCursor>,
        limit: PageLimit,
    ) -> Result<Page<AuthoritativeOperationStatus, AuthoritativeOperationCursor>, RepositoryError>
    {
        operation_status::list(&self.database, after, limit)
    }

    /// Resolves the durable delivery facts for one prior API-key session operation.
    ///
    /// # Errors
    ///
    /// Fails closed if the operation targets another command family or retained session state is
    /// malformed, revoked or no longer a single API-key ceremony.
    pub fn resolve_api_key_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeySessionReplay>, RepositoryError> {
        session::resolve_api_key_replay(&self.database, operation_id)
    }

    /// Resolves the durable delivery facts for one prior passkey session operation.
    ///
    /// # Errors
    ///
    /// Fails closed if the operation targets another command family or retained session state is
    /// malformed, revoked or no longer a single passkey ceremony.
    pub fn resolve_passkey_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PasskeySessionReplay>, RepositoryError> {
        session::resolve_passkey_replay(&self.database, operation_id)
    }

    /// Resolves one exact committed session with its complete ordered factor evidence.
    ///
    /// # Errors
    ///
    /// Rejects operations for another entity and fails closed for malformed retained evidence.
    pub fn resolve_authentication_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationSessionReplay>, RepositoryError> {
        session::resolve_session_replay(&self.database, operation_id)
    }

    /// Resolves one exact committed step-up using the now-revoked source presentation.
    ///
    /// # Errors
    ///
    /// Rejects another command family/source and fails closed for malformed retained evidence.
    pub fn resolve_step_up_session(
        &self,
        operation_id: OperationId,
        expected_source: meshspan_domain::SessionId,
        source_token_digest: [u8; 32],
        source_csrf_digest: [u8; 32],
    ) -> Result<Option<AuthenticationSessionReplay>, RepositoryError> {
        session::resolve_step_up_replay(
            &self.database,
            operation_id,
            expected_source,
            source_token_digest,
            source_csrf_digest,
        )
    }

    /// Resolves an exact durable self-service session revocation retry.
    ///
    /// # Errors
    ///
    /// Fails closed when the operation, session, credential evidence or persisted result differs.
    pub fn resolve_session_revocation(
        &self,
        operation_id: OperationId,
        expected_session_id: meshspan_domain::SessionId,
        token_digest: [u8; 32],
        csrf_digest: [u8; 32],
    ) -> Result<Option<SessionRevocationReplay>, RepositoryError> {
        session::resolve_revocation_replay(
            &self.database,
            operation_id,
            expected_session_id,
            token_digest,
            csrf_digest,
        )
    }

    /// Resolves an exact durable authentication-method revocation retry.
    ///
    /// # Errors
    ///
    /// Fails closed when the operation, method lifecycle event or persisted result differs.
    pub fn resolve_authentication_method_revocation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationMethodRevocationReplay>, RepositoryError> {
        authentication_method::resolve_revocation_replay(&self.database, operation_id)
    }

    /// Evaluates one exact connector-neutral namespace operation against committed authority.
    ///
    /// # Errors
    ///
    /// Fails closed if persisted identities, graph edges, grants or revisions are malformed or
    /// exceed their explicit evaluation bounds.
    pub fn evaluate_access(
        &self,
        request: AccessRequest,
    ) -> Result<AccessDecision, RepositoryError> {
        access_evaluation::evaluate(&self.database, request)
    }

    /// Evaluates one filesystem-verified local descendant which has no replicated object row yet.
    ///
    /// The caller must first resolve the object from a verified local namespace. Existing,
    /// retired or foreign replicated object identities never fall back to volume authority; only
    /// an identity wholly absent from the authoritative object catalogue may inherit the active
    /// volume-root grant.
    ///
    /// # Errors
    ///
    /// Fails closed for a known object identity, absent volume root, malformed authority or
    /// inconsistent capability projection.
    pub fn evaluate_unrecorded_descendant_access(
        &self,
        request: AccessRequest,
    ) -> Result<AccessDecision, RepositoryError> {
        let known: i64 = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM namespace_objects WHERE object_id = ?1)",
            [request.object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if known != 0 {
            return Ok(AccessDecision::Denied(AccessDenial::ObjectUnavailable));
        }
        let volume = volume_inventory::volume_inventory_record(&self.database, request.volume_id)?
            .ok_or(RepositoryError::CorruptState)?;
        let root_request = AccessRequest {
            object_id: volume.root_object_id,
            ..request
        };
        let decision = access_evaluation::evaluate(&self.database, root_request)?;
        access_evaluation::retarget_unrecorded_descendant(decision, request)
    }

    /// Authenticates one session and gateway for a non-filesystem administration read.
    ///
    /// The returned capability binds the current identity and system-role projection. It grants
    /// no file rights; callers must still enforce self-only or system-management scope.
    ///
    /// # Errors
    ///
    /// Fails closed if persisted session, gateway, identity or role evidence is malformed.
    pub fn evaluate_session_access(
        &self,
        request: SessionAccessRequest,
    ) -> Result<SessionAccessDecision, RepositoryError> {
        session_access::evaluate(&self.database, request)
    }

    /// Authenticates one browser session and enforces session-bound CSRF for mutations.
    ///
    /// # Errors
    ///
    /// Fails closed if persisted session, CSRF, gateway, identity or role evidence is malformed.
    pub fn evaluate_browser_session_access(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, RepositoryError> {
        session_access::evaluate_browser(&self.database, request)
    }

    /// Evaluates recipient-local user/group authority for one current swarm-targeted grant.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed grant lineage, assignments, group state or activations.
    pub fn evaluate_federation_grant_assignment(
        &self,
        grant_id: meshspan_domain::FederationGrantId,
        principal_id: meshspan_domain::PrincipalId,
        identity_revision: Revision,
        requested_rights: meshspan_domain::Rights,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<FederationGrantAssignmentAuthority>, RepositoryError> {
        federation_assignment::evaluate(
            &self.database,
            grant_id,
            principal_id,
            identity_revision,
            requested_rights,
            now,
        )
    }

    /// Authenticates one presented API-key digest against current user, method,
    /// service, capability and time bounds.
    ///
    /// Absence and every ordinary policy/credential rejection return `None` so an
    /// unauthenticated caller cannot enumerate which field disagreed.
    ///
    /// # Errors
    ///
    /// Fails closed when matching persisted evidence is structurally invalid.
    pub fn authenticate_api_key(
        &self,
        presented_key_digest: [u8; 32],
        service: AuthenticationService,
        required_scopes: u64,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, RepositoryError> {
        authentication_method::authenticate_api_key(
            self.database.connection(),
            presented_key_digest,
            service,
            required_scopes,
            now,
        )
    }

    /// Authenticates a direct API key against current credential and operation-policy bounds.
    ///
    /// Absence and ordinary scope, service, time or policy rejection return `None` without
    /// disclosing which authority did not match.
    ///
    /// # Errors
    ///
    /// Fails closed when matching persisted evidence is structurally invalid.
    pub fn authenticate_api_key_for_operation(
        &self,
        presented_key_digest: [u8; 32],
        service: AuthenticationService,
        required_scopes: u64,
        required_assurance: meshspan_domain::AssuranceLevel,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, RepositoryError> {
        authentication_method::authenticate_api_key_for_operation(
            self.database.connection(),
            presented_key_digest,
            service,
            required_scopes,
            required_assurance,
            now,
        )
    }

    /// Resolves current encrypted SMB verification materials for one validated user name.
    ///
    /// The result is bounded so an unauthenticated attempt cannot cause unbounded verifier work.
    /// Absence and ordinary lifecycle rejection return an empty set.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted state or an excessive active credential set.
    pub fn smb_verification_materials(
        &self,
        user_name: &crate::RecordName,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Vec<SmbVerificationMaterial>, RepositoryError> {
        authentication_method::smb_verification_materials(
            self.database.connection(),
            user_name.canonical(),
            now,
        )
    }

    /// Resolves current public passkey verification material without authenticating the caller.
    ///
    /// Absence and ordinary inactive/expired/service-policy rejection return `None`; the caller
    /// must still verify the complete assertion before treating the principal as authenticated.
    ///
    /// # Errors
    ///
    /// Fails closed when matching persisted evidence is structurally invalid.
    pub fn passkey_verification_material(
        &self,
        credential_id: &[u8],
        service: AuthenticationService,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<PasskeyVerificationMaterial>, RepositoryError> {
        authentication_method::passkey_verification_material(
            self.database.connection(),
            credential_id,
            service,
            now,
        )
    }

    /// Resolves every bounded active TOTP verifier for one already-authenticated user.
    ///
    /// The returned seeds remain encrypted. Absence and ordinary inactive, expired or
    /// service-policy rejection produce an empty list.
    ///
    /// # Errors
    ///
    /// Fails closed when matching persisted evidence is malformed or exceeds its hard bound.
    pub fn totp_verification_materials(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        service: AuthenticationService,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Vec<TotpVerificationMaterial>, RepositoryError> {
        authentication_method::totp_verification_materials(
            self.database.connection(),
            principal_id,
            service,
            now,
        )
    }

    /// Resolves one exact recovery-code verifier for an already-authenticated user.
    ///
    /// Absence and ordinary digest, lifecycle, expiry or service rejection return `None`.
    /// A used code remains visible only as typed evidence so an exact committed retry can be
    /// distinguished from a forbidden new consumption.
    ///
    /// # Errors
    ///
    /// Fails closed when matching persisted evidence is malformed.
    pub fn recovery_code_verification_material(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        code_id: meshspan_domain::RecoveryCodeId,
        presented_digest: [u8; 32],
        service: AuthenticationService,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<RecoveryCodeVerificationMaterial>, RepositoryError> {
        authentication_method::recovery_code_verification_material(
            self.database.connection(),
            principal_id,
            code_id,
            presented_digest,
            service,
            now,
        )
    }

    /// Returns the current active user identity and a bounded passkey-exclusion hint.
    ///
    /// The credential list is a browser convenience only. Authoritative creation still enforces
    /// global credential uniqueness, including when a user owns more than the returned bound.
    ///
    /// # Errors
    ///
    /// Fails closed when identity or credential evidence is malformed.
    pub fn passkey_registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<PasskeyRegistrationProfile>, RepositoryError> {
        passkey_registration::profile(&self.database, principal_id)
    }

    /// Returns the current active user identity for a non-passkey registration ceremony.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated identity evidence is malformed.
    pub fn authentication_registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<AuthenticationRegistrationProfile>, RepositoryError> {
        passkey_registration::authentication_profile(&self.database, principal_id)
    }

    /// Resolves one exact committed passkey-registration operation.
    ///
    /// # Errors
    ///
    /// Rejects an operation naming another command family and fails closed for malformed method
    /// or receipt evidence.
    pub fn resolve_passkey_registration(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<PasskeyRegistrationReplay>, RepositoryError> {
        passkey_registration::resolve_replay(&self.database, operation_id)
    }

    /// Resolves one exact authentication-method creation of the expected credential family.
    ///
    /// # Errors
    ///
    /// Fails closed when the operation targets another command family, another method kind or
    /// malformed retained authority state.
    pub fn resolve_authentication_method_creation(
        &self,
        operation_id: OperationId,
        expected_kind: meshspan_domain::AuthenticationMethodKind,
    ) -> Result<Option<AuthenticationMethodCreationReplay>, RepositoryError> {
        passkey_registration::resolve_method_creation(&self.database, operation_id, expected_kind)
    }

    /// Returns the current immutable authentication policy for one service and operation class.
    ///
    /// # Errors
    ///
    /// Fails closed if policy history is missing, discontinuous or structurally invalid.
    pub fn authentication_policy(
        &self,
        service: AuthenticationService,
        operation_class: meshspan_domain::AuthenticationOperationClass,
    ) -> Result<AuthenticationPolicy, RepositoryError> {
        authentication_policy::load(&self.database, service, operation_class)
    }

    /// Returns a stable bounded page from one object's current immutable owner set.
    ///
    /// A continuation fails stale if the object changes owner set between pages.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed ownership evidence, cursor substitution or database failure.
    pub fn object_owners(
        &self,
        object_id: meshspan_domain::ObjectId,
        after: Option<ObjectOwnerCursor>,
        limit: PageLimit,
    ) -> Result<Option<Page<ObjectOwnerRecord, ObjectOwnerCursor>>, RepositoryError> {
        access_query::object_owners(&self.database, object_id, after, limit)
    }

    /// Returns one stable bounded page of current grants attached to an exact scope.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed grants, cursor substitution or database failure.
    pub fn permission_grants_for_scope(
        &self,
        scope: crate::PermissionScope,
        after: Option<ScopedGrantCursor>,
        limit: PageLimit,
    ) -> Result<Page<PermissionGrantRecord, ScopedGrantCursor>, RepositoryError> {
        access_query::permission_grants_for_scope(&self.database, scope, after, limit)
    }

    /// Returns one exact active permission grant.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted authority or database failure.
    pub fn permission_grant(
        &self,
        grant_id: meshspan_domain::GrantId,
    ) -> Result<Option<PermissionGrantRecord>, RepositoryError> {
        access_query::permission_grant(&self.database, grant_id)
    }

    /// Returns durable revocation evidence for one exact grant.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted authority or database failure.
    pub fn permission_grant_revocation(
        &self,
        grant_id: meshspan_domain::GrantId,
    ) -> Result<Option<PermissionGrantRevocationRecord>, RepositoryError> {
        access_query::permission_grant_revocation(&self.database, grant_id)
    }

    /// Returns one stable bounded page of current grants assigned to one user or group.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed grants, cursor substitution or database failure.
    pub fn permission_grants_for_subject(
        &self,
        subject_principal_id: meshspan_domain::PrincipalId,
        after: Option<SubjectGrantCursor>,
        limit: PageLimit,
    ) -> Result<Page<PermissionGrantRecord, SubjectGrantCursor>, RepositoryError> {
        access_query::permission_grants_for_subject(
            &self.database,
            subject_principal_id,
            after,
            limit,
        )
    }

    /// Returns nominally live activation records at one authoritative instant.
    ///
    /// A continuation is bound to the original principal and instant. This administration view
    /// does not grant access: operation-time evaluation rechecks every source and session.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed activation evidence, cursor substitution or database failure.
    pub fn unrevoked_access_activations(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        observed_at: meshspan_domain::UnixMicros,
        after: Option<AccessActivationCursor>,
        limit: PageLimit,
    ) -> Result<Page<AccessActivationRecord, AccessActivationCursor>, RepositoryError> {
        access_query::unrevoked_access_activations(
            &self.database,
            principal_id,
            observed_at,
            after,
            limit,
        )
    }

    /// Reads one exact user or group principal.
    ///
    /// # Errors
    ///
    /// Fails closed if stored identity bytes or enum values are malformed.
    pub fn principal(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<PrincipalRecord>, RepositoryError> {
        query::principal(&self.database, principal_id)
    }

    /// Reports whether one active principal currently carries direct system-management authority.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed role projections or database failure.
    pub fn principal_is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, RepositoryError> {
        session_access::is_system_manager(&self.database, principal_id, now)
    }

    /// Resolves the current mesh, host and system-manager authority for local target registration.
    ///
    /// Returns none until exactly one mesh, the requested active node and host, and at least one
    /// current non-activated system manager all exist.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed authoritative identities or database failure.
    pub fn storage_target_registration_context(
        &self,
        node_id: meshspan_domain::NodeId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, RepositoryError> {
        storage_target::registration_context(&self.database, node_id, now)
    }

    /// Returns the current active replicated configuration for one node-local storage provider.
    ///
    /// A draining, retired, foreign or inactive target returns `None`. The returned catalogue
    /// revision is the complete applied state against which removal authority must be fenced.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed target, topology, policy or revision state.
    pub fn storage_target_provider_context(
        &self,
        node_id: meshspan_domain::NodeId,
        target_id: meshspan_domain::TargetId,
    ) -> Result<Option<StorageTargetProviderContext>, RepositoryError> {
        storage_target::provider_context(&self.database, node_id, target_id)
    }

    /// Returns the current active replicated configuration for one globally unique target.
    ///
    /// This lookup is used by a gateway routing an already-authorised immutable shard read. A
    /// draining, retired or inactive target returns `None` rather than a stale node route.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed target, topology, policy or revision state.
    pub fn storage_target_provider_context_by_target(
        &self,
        target_id: meshspan_domain::TargetId,
    ) -> Result<Option<StorageTargetProviderContext>, RepositoryError> {
        storage_target::provider_context_by_target(&self.database, target_id)
    }

    /// Returns a bounded stable page of daemon nodes and their machine boundaries.
    ///
    /// # Errors
    ///
    /// Fails closed when stored identities, roles or lifecycle state are malformed.
    pub fn topology_nodes(
        &self,
        after: Option<&TopologyNodeCursor>,
        limit: PageLimit,
    ) -> Result<Page<TopologyNodeRecord, TopologyNodeCursor>, RepositoryError> {
        topology::nodes(&self.database, after, limit)
    }

    /// Returns a bounded stable page of mesh-wide targets without node-local paths.
    ///
    /// # Errors
    ///
    /// Fails closed when stored topology, capacity or lifecycle state are malformed.
    pub fn topology_targets(
        &self,
        after: Option<&TopologyTargetCursor>,
        limit: PageLimit,
    ) -> Result<Page<TopologyTargetRecord, TopologyTargetCursor>, RepositoryError> {
        topology::targets(&self.database, after, limit)
    }

    /// Returns a bounded stable page of administrator-defined shared-failure groups.
    ///
    /// # Errors
    ///
    /// Fails closed when stored identities, names or revisions are malformed.
    pub fn fault_groups(
        &self,
        after: Option<&FaultGroupCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, RepositoryError> {
        topology::fault_groups(&self.database, after, limit)
    }

    /// Returns one current shared-failure group by exact identity.
    ///
    /// # Errors
    ///
    /// Fails closed when its persisted class, names or revision are malformed.
    pub fn fault_group(
        &self,
        group_id: meshspan_domain::FaultGroupId,
    ) -> Result<Option<FaultGroupRecord>, RepositoryError> {
        topology::fault_group(&self.database, group_id)
    }

    /// Returns a bounded stable page of overlapping machine/group membership edges.
    ///
    /// # Errors
    ///
    /// Fails closed when stored identities or revisions are malformed.
    pub fn fault_group_memberships(
        &self,
        after: Option<FaultGroupMembershipCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>, RepositoryError> {
        topology::fault_group_memberships(&self.database, after, limit)
    }

    /// Returns the active immutable data-survival policy selected by one volume.
    ///
    /// `None` means the volume still uses the built-in topology-aware default; it never means that
    /// storage is unprotected.
    ///
    /// # Errors
    ///
    /// Fails closed when policy, scenario, term or revision state is malformed.
    pub fn volume_protection_policy(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<VolumeProtectionPolicy>, RepositoryError> {
        protection_policy::for_volume(&self.database, volume_id)
    }

    /// Returns one bounded stable page of immutable data-survival policies.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, scenarios or revisions are malformed.
    pub fn protection_policies(
        &self,
        after: Option<&ProtectionPolicyCursor>,
        limit: PageLimit,
    ) -> Result<Page<ProtectionPolicyRecord, ProtectionPolicyCursor>, RepositoryError> {
        protection_policy::policies(&self.database, after, limit)
    }

    /// Returns one exact immutable data-survival policy.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, scenarios or revisions are malformed.
    pub fn protection_policy(
        &self,
        policy_id: meshspan_domain::ProtectionPolicyId,
    ) -> Result<Option<ProtectionPolicyRecord>, RepositoryError> {
        protection_policy::policy(&self.database, policy_id)
    }

    /// Returns one bounded stable page of named availability cells.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, hierarchy or revisions are malformed.
    pub fn availability_cells(
        &self,
        after: Option<&AvailabilityCellCursor>,
        limit: PageLimit,
    ) -> Result<Page<AvailabilityCellRecord, AvailabilityCellCursor>, RepositoryError> {
        availability_cell::cells(&self.database, after, limit)
    }

    /// Returns one exact active availability cell.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, hierarchy or revisions are malformed.
    pub fn availability_cell(
        &self,
        cell_id: meshspan_domain::AvailabilityCellId,
    ) -> Result<Option<AvailabilityCellRecord>, RepositoryError> {
        availability_cell::cell(&self.database, cell_id)
    }

    /// Resolves direct and inherited availability cells for one target and machine.
    ///
    /// # Errors
    ///
    /// Fails closed when membership or cell hierarchy state is malformed.
    pub fn target_availability_cells(
        &self,
        target_id: meshspan_domain::TargetId,
        host_id: meshspan_domain::HostId,
    ) -> Result<Vec<meshspan_domain::AvailabilityCellId>, RepositoryError> {
        availability_cell::target_cells(&self.database, target_id, host_id)
    }

    /// Returns the immutable desired-locality policy selected by one volume.
    ///
    /// `None` means no explicit complete-local copy has been requested beyond the built-in local
    /// placement preference.
    ///
    /// # Errors
    ///
    /// Fails closed when policy, requirement, cell or revision state is malformed.
    pub fn volume_locality_policy(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<VolumeLocalityPolicy>, RepositoryError> {
        locality_policy::for_volume(&self.database, volume_id)
    }

    /// Returns one bounded stable page of immutable desired-locality policies.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, requirements or revisions are malformed.
    pub fn locality_policies(
        &self,
        after: Option<&LocalityPolicyCursor>,
        limit: PageLimit,
    ) -> Result<Page<LocalityPolicyRecord, LocalityPolicyCursor>, RepositoryError> {
        locality_policy::policies(&self.database, after, limit)
    }

    /// Returns one exact immutable desired-locality policy.
    ///
    /// # Errors
    ///
    /// Fails closed when stored names, identities, requirements or revisions are malformed.
    pub fn locality_policy(
        &self,
        policy_id: meshspan_domain::LocalityPolicyId,
    ) -> Result<Option<LocalityPolicyRecord>, RepositoryError> {
        locality_policy::policy(&self.database, policy_id)
    }

    /// Returns the immutable write-acknowledgement policy selected by one volume.
    ///
    /// `None` means the volume uses the built-in availability-first eventual default.
    ///
    /// # Errors
    ///
    /// Fails closed when policy, scenario, cell or revision state is malformed.
    pub fn volume_acknowledgement_policy(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<VolumeAcknowledgementPolicy>, RepositoryError> {
        acknowledgement_policy::for_volume(&self.database, volume_id)
    }

    /// Returns one bounded stable page of immutable write-acknowledgement policies.
    ///
    /// # Errors
    ///
    /// Fails closed when stored policy predicates or revisions are malformed.
    pub fn acknowledgement_policies(
        &self,
        after: Option<&AcknowledgementPolicyCursor>,
        limit: PageLimit,
    ) -> Result<Page<AcknowledgementPolicyRecord, AcknowledgementPolicyCursor>, RepositoryError>
    {
        acknowledgement_policy::policies(&self.database, after, limit)
    }

    /// Returns one exact immutable write-acknowledgement policy.
    ///
    /// # Errors
    ///
    /// Fails closed when stored policy predicates or revisions are malformed.
    pub fn acknowledgement_policy(
        &self,
        policy_id: meshspan_domain::AcknowledgementPolicyId,
    ) -> Result<Option<AcknowledgementPolicyRecord>, RepositoryError> {
        acknowledgement_policy::policy(&self.database, policy_id)
    }

    /// Returns the current public secret-wrapping-key generation for one node.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed stored public material or database failure.
    pub fn node_wrapping_key(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<NodeWrappingKeyRecord>, RepositoryError> {
        node_wrapping_key::current(&self.database, node_id)
    }

    /// Returns one exact encrypted secret generation and its complete recipient set.
    ///
    /// # Errors
    ///
    /// Fails closed for incomplete, substituted or malformed stored cryptographic evidence.
    pub fn secret_generation(
        &self,
        context: meshspan_secret_envelope::SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, RepositoryError> {
        secret_generation::load(&self.database, context)
    }

    /// Returns the newest committed volume content-key generation.
    ///
    /// Content envelopes retain their exact generation for reads; only new content uses this
    /// append-only head. A missing volume key returns `None` rather than inventing generation one.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed generation state or database failure.
    pub fn latest_volume_key_generation(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<u64>, RepositoryError> {
        secret_generation::latest_volume_generation(&self.database, volume_id)
    }

    /// Returns the newest committed mesh storage-permit key generation.
    ///
    /// Providers verify permits with this append-only head while in-flight permits retain their
    /// exact generation during rotation. A missing key returns `None` rather than inventing an
    /// initial generation.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed generation state or database failure.
    pub fn latest_storage_permit_generation(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, RepositoryError> {
        secret_generation::latest_storage_permit_generation(&self.database, mesh_id)
    }

    /// Returns the newest committed gateway-only authentication-root generation.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed generation state or database failure.
    pub fn latest_authentication_root_generation(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, RepositoryError> {
        secret_generation::latest_authentication_root_generation(&self.database, mesh_id)
    }

    /// Returns the newest committed online node-certificate authority key generation.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed generation state or database failure.
    pub fn latest_online_authority_generation(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, RepositoryError> {
        secret_generation::latest_online_authority_generation(&self.database, mesh_id)
    }

    /// Returns every current gateway and the exact verified offline recovery recipient.
    ///
    /// Storage-only nodes are deliberately excluded because they retain encrypted shards without
    /// receiving volume-content keys.
    ///
    /// # Errors
    ///
    /// Fails closed for absent recovery evidence, excessive recipients or malformed key state.
    pub fn volume_key_recipients(
        &self,
    ) -> Result<Vec<meshspan_secret_envelope::WrappingPublicKey>, RepositoryError> {
        secret_generation::volume_key_recipients(&self.database)
    }

    /// Returns the public offline authority and recovery-bundle verification state for one mesh.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed keys, certificates, lifecycle evidence or database failure.
    pub fn mesh_recovery_authority(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<MeshRecoveryAuthority>, RepositoryError> {
        recovery_authority::current(&self.database, mesh_id)
    }

    /// Returns the current root-signed online node-certificate authority certificate.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed certificate, generation or digest state.
    pub fn online_certificate_authority(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<OnlineCertificateAuthorityRecord>, RepositoryError> {
        recovery_authority::current_online_authority(&self.database, mesh_id)
    }

    /// Returns one stable, bounded page of principals in a selected family.
    ///
    /// # Errors
    ///
    /// Rejects cursor-family substitution, malformed stored values and database failures.
    pub fn principals(
        &self,
        kind: PrincipalKind,
        after: Option<&PrincipalCursor>,
        limit: PageLimit,
    ) -> Result<Page<PrincipalRecord, PrincipalCursor>, RepositoryError> {
        query::principals(&self.database, kind, after, limit)
    }

    /// Returns one stable, bounded page of one user's authentication methods without secrets.
    ///
    /// # Errors
    ///
    /// Rejects cursor-owner substitution, malformed credential projections and database failures.
    pub fn authentication_methods(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        after: Option<AuthenticationMethodCursor>,
        limit: PageLimit,
    ) -> Result<Page<AuthenticationMethodRecord, AuthenticationMethodCursor>, RepositoryError> {
        authentication_method_query::authentication_methods(
            &self.database,
            principal_id,
            after,
            limit,
        )
    }

    /// Returns one stable bounded page of logical volumes before caller-specific access filtering.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed stored identities, names, lifecycle or revision values.
    pub fn volume_inventory_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, RepositoryError> {
        volume_inventory::volume_inventory_candidates(&self.database, after, limit)
    }

    /// Returns one exact logical-volume record and its stable root identity.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed stored identities, names, lifecycle or revision values.
    pub fn volume_inventory_record(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<VolumeInventoryRecord>, RepositoryError> {
        volume_inventory::volume_inventory_record(&self.database, volume_id)
    }

    /// Returns every active SMB export assigned to one gateway under replicated desired state.
    ///
    /// # Errors
    ///
    /// Fails closed for excessive exports, malformed roots, invalid identities or database errors.
    pub fn smb_exports_for_gateway(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Vec<SmbExportRecord>, RepositoryError> {
        smb_export::smb_exports_for_gateway(&self.database, node_id)
    }

    /// Returns one stable, bounded page of active namespace children.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identifiers and database failures.
    pub fn namespace_children(
        &self,
        volume_id: meshspan_domain::VolumeId,
        parent_object_id: meshspan_domain::ObjectId,
        after: Option<&NamespaceCursor>,
        limit: PageLimit,
    ) -> Result<Page<NamespaceRecord, NamespaceCursor>, RepositoryError> {
        query::namespace_children(&self.database, volume_id, parent_object_id, after, limit)
    }

    /// Returns the latest replicated globally converged namespace head for one volume.
    ///
    /// # Errors
    ///
    /// Fails closed if any stored identity, digest, sequence or evidence shape is malformed.
    pub fn converged_volume_head(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<ConvergedVolumeHead>, RepositoryError> {
        volume_head::load(&self.database, volume_id)
    }

    /// Returns one stable bounded page of active or expiring read-only volume snapshots.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identifiers, states or bounds and database failure.
    pub fn volume_snapshots(
        &self,
        volume_id: meshspan_domain::VolumeId,
        after: Option<&SnapshotCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeSnapshot, SnapshotCursor>, RepositoryError> {
        user_snapshot::list(&self.database, volume_id, after, limit)
    }

    /// Returns one stable page of every metadata root retaining a volume namespace.
    ///
    /// Every page must present the same exact current `catalogue_revision`; any intervening
    /// authoritative mutation makes continuation fail stale rather than yielding a mixed root set.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, absent converged heads, malformed roots and invalid page bounds.
    pub fn retained_namespace_roots(
        &self,
        volume_id: meshspan_domain::VolumeId,
        catalogue_revision: Revision,
        after: Option<RetainedNamespaceRootCursor>,
        limit: PageLimit,
    ) -> Result<RetainedNamespaceRootPage, RepositoryError> {
        reachability::retained_roots(&self.database, volume_id, catalogue_revision, after, limit)
    }

    /// Returns a bounded page of currently eligible automatic snapshot expiries.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed snapshots, schedules or retention ledgers.
    pub fn due_snapshot_expiries(
        &self,
        now: meshspan_domain::UnixMicros,
        after: Option<&SnapshotExpiryCursor>,
        limit: PageLimit,
    ) -> Result<Page<SnapshotExpiryCandidate, SnapshotExpiryCursor>, RepositoryError> {
        user_snapshot::due_expiries(&self.database, now, after, limit)
    }

    /// Returns the current authoritative configuration and due state of one snapshot schedule.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed stored identifiers, intervals, counts or revisions.
    pub fn snapshot_schedule(
        &self,
        schedule_id: meshspan_domain::SnapshotScheduleId,
    ) -> Result<Option<SnapshotSchedule>, RepositoryError> {
        snapshot_schedule::load(&self.database, schedule_id)
    }

    /// Returns one stable bounded page of enabled snapshot schedules due at `now`.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored schedules and invalid query bounds.
    pub fn due_snapshot_schedules(
        &self,
        now: meshspan_domain::UnixMicros,
        after: Option<&SnapshotScheduleCursor>,
        limit: PageLimit,
    ) -> Result<Page<SnapshotSchedule, SnapshotScheduleCursor>, RepositoryError> {
        snapshot_schedule::due(&self.database, now, after, limit)
    }

    /// Returns the exact currently selected version-retention policy for one volume.
    ///
    /// # Errors
    ///
    /// Fails closed for sequence gaps, malformed values or database failure.
    pub fn version_retention_policy(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<VersionRetentionPolicy>, RepositoryError> {
        retention::load(&self.database, volume_id)
    }

    /// Returns one independently revalidated replicated version-cleanup intent.
    ///
    /// # Errors
    ///
    /// Fails closed if stored identities, proof digests, state or revisions are malformed.
    pub fn version_cleanup_intent(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VersionCleanupIntent>, RepositoryError> {
        version_cleanup::load(&self.database, operation_id)
    }

    /// Returns bounded aggregate cleanup-attestation coverage without exposing signatures.
    ///
    /// # Errors
    ///
    /// Fails closed if proposal and participant counts disagree or durable values are malformed.
    pub fn version_cleanup_attestation_progress(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VersionCleanupAttestationProgress>, RepositoryError> {
        cleanup_attestation::progress(&self.database, operation_id)
    }

    /// Returns one independently signature-verified participant scan.
    ///
    /// # Errors
    ///
    /// Rejects malformed or signature-inconsistent persisted attestation state.
    pub fn version_cleanup_participant(
        &self,
        operation_id: OperationId,
        node_id: meshspan_domain::NodeId,
    ) -> Result<Option<VersionCleanupParticipant>, RepositoryError> {
        cleanup_attestation::participant(&self.database, operation_id, node_id)
    }

    /// Returns one independently validated physical cleanup-inventory summary.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed counts, digests or partial terminal state.
    pub fn version_cleanup_inventory(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VersionCleanupInventory>, RepositoryError> {
        cleanup_inventory::load(&self.database, operation_id)
    }

    /// Returns one bounded keyset page from a sealed physical cleanup inventory.
    ///
    /// # Errors
    ///
    /// Rejects unsealed inventories, foreign cursors, malformed bounds and corrupt rows.
    pub fn version_cleanup_items(
        &self,
        operation_id: OperationId,
        after: Option<&VersionCleanupItemCursor>,
        limit: PageLimit,
    ) -> Result<Page<VersionCleanupItem, VersionCleanupItemCursor>, RepositoryError> {
        cleanup_inventory::page(&self.database, operation_id, after, limit)
    }

    /// Returns the exact current inputs for constructing one removal-permit attempt.
    ///
    /// # Errors
    ///
    /// Rejects unsealed, missing or corrupt inventory state.
    pub fn version_cleanup_permit_authority(
        &self,
        operation_id: OperationId,
        item_index: u64,
    ) -> Result<VersionCleanupPermitAuthority, RepositoryError> {
        cleanup_permit::authority(&self.database, operation_id, item_index)
    }

    /// Returns the latest independently validated permit attempt for one item.
    ///
    /// # Errors
    ///
    /// Rejects unsealed, missing or corrupt inventory and permit state.
    pub fn version_cleanup_permit_attempt(
        &self,
        operation_id: OperationId,
        item_index: u64,
    ) -> Result<Option<VersionCleanupPermitAttempt>, RepositoryError> {
        cleanup_permit::latest(&self.database, operation_id, item_index)
    }

    /// Returns one independently validated provider tombstone completion.
    ///
    /// # Errors
    ///
    /// Rejects missing/corrupt inventory or completion state.
    pub fn version_cleanup_item_completion(
        &self,
        operation_id: OperationId,
        item_index: u64,
    ) -> Result<Option<VersionCleanupItemCompletion>, RepositoryError> {
        cleanup_completion::item(&self.database, operation_id, item_index)
    }

    /// Returns terminal proof only after every exact sealed item completed.
    ///
    /// # Errors
    ///
    /// Rejects corrupt inventory, item completion or summary state.
    pub fn version_cleanup_completion(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VersionCleanupCompletion>, RepositoryError> {
        cleanup_completion::summary(&self.database, operation_id)
    }

    /// Returns one independently validated physical-reclamation confirmation.
    ///
    /// # Errors
    ///
    /// Rejects missing/corrupt completion or reclamation state.
    pub fn version_cleanup_item_reclamation(
        &self,
        operation_id: OperationId,
        item_index: u64,
    ) -> Result<Option<VersionCleanupItemReclamation>, RepositoryError> {
        cleanup_reclamation::item(&self.database, operation_id, item_index)
    }

    /// Returns terminal physical-byte accounting only after every item was reclaimed.
    ///
    /// # Errors
    ///
    /// Rejects corrupt completion, item reclamation or summary state.
    pub fn version_cleanup_reclamation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VersionCleanupReclamation>, RepositoryError> {
        cleanup_reclamation::summary(&self.database, operation_id)
    }

    /// Returns one stable, bounded page of direct members of a group.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identifiers and database failures.
    pub fn direct_group_members(
        &self,
        group_id: meshspan_domain::GroupId,
        after: Option<GroupMemberCursor>,
        limit: PageLimit,
    ) -> Result<Page<meshspan_domain::PrincipalId, GroupMemberCursor>, RepositoryError> {
        query::direct_group_members(&self.database, group_id, after, limit)
    }

    /// Returns one stable, bounded page of active direct-membership records.
    ///
    /// # Errors
    ///
    /// Rejects stale cursors, corrupt rows, malformed identifiers and database failures.
    pub fn direct_group_memberships(
        &self,
        group_id: meshspan_domain::GroupId,
        after: Option<GroupMemberCursor>,
        limit: PageLimit,
    ) -> Result<Page<GroupMembershipRecord, GroupMemberCursor>, RepositoryError> {
        query::direct_group_memberships(&self.database, group_id, after, limit)
    }

    /// Returns one exact active direct-membership record.
    ///
    /// # Errors
    ///
    /// Rejects corrupt rows, malformed identifiers and database failures.
    pub fn direct_group_membership(
        &self,
        group_id: meshspan_domain::GroupId,
        member_principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<GroupMembershipRecord>, RepositoryError> {
        query::direct_group_membership(&self.database, group_id, member_principal_id)
    }

    /// Resolves immutable evidence for one direct-membership mutation revision.
    ///
    /// # Errors
    ///
    /// Fails closed when the revision is invalid, absent history is malformed or more than one
    /// event claims the same authoritative group revision.
    pub fn group_membership_event(
        &self,
        group_id: GroupId,
        revision: Revision,
    ) -> Result<Option<GroupMembershipEventRecord>, RepositoryError> {
        query::group_membership_event(&self.database, group_id, revision)
    }

    /// Returns the authoritative active-voter and admitted-learner projection, if bootstrapped.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed identities, incarnations or unsupported role/state pairings.
    pub fn partition_membership(&self) -> Result<Option<AuthoritativeMembership>, RepositoryError> {
        membership::load(&self.database)
    }

    /// Creates a transactionally consistent SQLite backup and its exact manifest.
    ///
    /// # Errors
    ///
    /// Refuses an existing destination and reports IO, SQLite or state corruption.
    pub fn create_backup(
        &self,
        backup_id: meshspan_domain::BackupId,
        destination: &std::path::Path,
        created_at: meshspan_domain::UnixMicros,
    ) -> Result<PartitionBackupManifest, RepositoryError> {
        backup::create_partition_backup(&self.database, backup_id, destination, created_at)
    }

    /// Creates a complete state-machine snapshot bound to one proved quorum plan.
    ///
    /// # Errors
    ///
    /// Rejects absent/inconsistent consensus state and never overwrites an existing destination.
    pub fn create_snapshot(
        &self,
        snapshot_id: meshspan_domain::SnapshotId,
        destination: &std::path::Path,
        plan: &meshspan_consensus::CompiledQuorumPlan,
        created_at: meshspan_domain::UnixMicros,
    ) -> Result<PartitionSnapshotManifest, RepositoryError> {
        snapshot::create_snapshot(&self.database, snapshot_id, destination, plan, created_at)
    }

    /// Installs the immutable bootstrap plan or verifies the exact existing durable plan.
    ///
    /// # Errors
    ///
    /// Rejects a different existing plan, unsafe record or database failure.
    pub fn initialise_consensus_quorum_plan(
        &mut self,
        plan: &meshspan_consensus::CompiledQuorumPlan,
        updated_at: meshspan_domain::UnixMicros,
    ) -> Result<meshspan_consensus::ActiveQuorumPlan, ConsensusStoreError> {
        quorum_plan::initialise(&mut self.database, plan, updated_at)
    }

    /// Loads and independently re-proves the exact durable stable or joint phase.
    ///
    /// # Errors
    ///
    /// Rejects malformed, corrupt, stale or unproved durable state.
    pub fn load_active_consensus_quorum_plan(
        &self,
    ) -> Result<Option<meshspan_consensus::ActiveQuorumPlan>, ConsensusStoreError> {
        quorum_plan::load(&self.database)
    }

    /// Runs bounded relational/domain checks that go beyond SQLite structural integrity.
    ///
    /// # Errors
    ///
    /// Rejects an invalid finding bound and reports malformed persisted identifiers as corruption.
    pub fn check_invariants(&self, limit: PageLimit) -> Result<InvariantReport, RepositoryError> {
        verify::check_invariants(&self.database, limit)
    }

    /// Returns the underlying database after repository ownership is no longer needed.
    #[must_use]
    pub fn into_database(self) -> PartitionDatabase {
        self.database
    }
}

/// Closed authoritative repository rejection categories.
#[derive(Debug, Error)]
pub enum RepositoryError {
    /// SQLite, migration or integrity machinery rejected the operation.
    #[error("authoritative metadata store failed")]
    Store(#[from] MetadataStoreError),
    /// Direct SQLite access rejected the operation.
    #[error("authoritative metadata transaction failed")]
    Sqlite(#[from] rusqlite::Error),
    /// An operation ID is already committed for different semantic input.
    #[error("operation identity is already bound to different input")]
    OperationConflict,
    /// The supplied log position does not immediately follow applied state.
    #[error("committed log position is stale or discontinuous")]
    InvalidLogPosition,
    /// The compare-and-swap state revision is stale.
    #[error("expected state revision is stale")]
    StaleRevision,
    /// A per-volume converged-head compare-and-swap base is stale.
    #[error("expected converged volume head is stale")]
    StaleVolumeHead,
    /// A per-volume immutable retention-policy sequence is stale.
    #[error("expected version-retention policy is stale")]
    StaleRetentionPolicy,
    /// A service/operation authentication-policy sequence is stale.
    #[error("expected authentication policy is stale")]
    StaleAuthenticationPolicy,
    /// A snapshot-specific compare-and-swap revision is stale.
    #[error("expected volume snapshot revision is stale")]
    StaleSnapshot,
    /// A snapshot schedule's immutable configuration sequence is stale.
    #[error("expected snapshot schedule sequence is stale")]
    StaleSnapshotSchedule,
    /// A command violates a semantic precondition.
    #[error("authoritative command is invalid")]
    InvalidCommand,
    /// A bounded repository or graph limit would be exceeded.
    #[error("authoritative metadata capacity is exceeded")]
    CapacityExceeded,
    /// Persisted bytes or relationships violate the compiled contract.
    #[error("authoritative metadata invariant is corrupt")]
    CorruptState,
    /// A caller supplied an invalid explicit query bound.
    #[error("repository page limit is outside supported bounds")]
    InvalidPageLimit,
    /// Filesystem IO rejected backup creation or verification.
    #[error("metadata backup IO failed")]
    Io(#[from] std::io::Error),
    /// Backup creation never overwrites an existing path.
    #[error("metadata backup destination already exists")]
    BackupDestinationExists,
    /// Backup bytes or their embedded state do not match the supplied manifest.
    #[error("metadata backup does not match its manifest")]
    BackupMismatch,
    /// Snapshot bytes, consensus position, vote or quorum-plan proof do not agree.
    #[error("metadata snapshot does not match its consensus manifest")]
    SnapshotMismatch,
    /// Deterministic internal transaction interruption used by the crash-proof harness.
    #[error("injected authoritative transaction interruption")]
    InjectedFault,
}

impl RepositoryError {
    /// Reports whether an admission failure is a deterministic outcome of the supplied command.
    #[must_use]
    pub fn is_command_rejection(&self) -> bool {
        match self {
            Self::StaleRevision
            | Self::StaleVolumeHead
            | Self::StaleRetentionPolicy
            | Self::StaleAuthenticationPolicy
            | Self::StaleSnapshot
            | Self::StaleSnapshotSchedule
            | Self::InvalidCommand
            | Self::CapacityExceeded => true,
            Self::Sqlite(rusqlite::Error::SqliteFailure(error, _)) => {
                error.code == rusqlite::ErrorCode::ConstraintViolation
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod access_evaluation_tests;
#[cfg(test)]
mod access_query_tests;
#[cfg(test)]
mod access_revocation_tests;
#[cfg(test)]
mod cleanup_attestation_tests;
#[cfg(test)]
mod cleanup_completion_tests;
#[cfg(test)]
mod cleanup_inventory_tests;
#[cfg(test)]
mod cleanup_permit_tests;
#[cfg(test)]
mod cleanup_reclamation_tests;
#[cfg(test)]
mod principal_lifecycle_tests;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod snapshot_schedule_tests;
#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod version_cleanup_finalisation_tests;
#[cfg(test)]
mod version_cleanup_tests;
#[cfg(test)]
mod volume_creation_tests;
#[cfg(test)]
mod volume_head_tests;
