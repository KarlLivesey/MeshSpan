// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative command application and exact operation resolution.

mod access_evaluation;
mod access_query;
mod apply;
mod authentication_method;
mod authentication_method_creation;
#[cfg(test)]
mod authentication_method_creation_tests;
#[cfg(test)]
mod authentication_method_tests;
mod authentication_policy;
#[cfg(test)]
mod authentication_policy_tests;
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
mod membership;
mod namespace;
mod passkey_registration;
#[cfg(test)]
mod passkey_registration_tests;
mod query;
mod quorum_plan;
mod reachability;
mod receipt;
mod retention;
mod root_delegation;
mod root_delegation_evidence;
mod routing;
mod session;
mod session_access;
#[cfg(test)]
mod session_tests;
mod snapshot;
mod snapshot_schedule;
mod tags;
mod user_snapshot;
mod verify;
mod version_cleanup;
mod volume_head;

use meshspan_domain::{OperationId, Revision, ScopeId, ScopeRoute};
use thiserror::Error;

use crate::{MetadataStoreError, PartitionDatabase};

pub use access_evaluation::{AccessCapability, AccessDecision, AccessDenial, AccessRequest};
pub use access_query::{
    AccessActivationCursor, AccessActivationRecord, ObjectOwnerCursor, ObjectOwnerRecord,
    PermissionGrantRecord, ScopedGrantCursor, SubjectGrantCursor,
};
pub use authentication_method::{ApiKeyAuthentication, PasskeyVerificationMaterial};
pub use authentication_policy::AuthenticationPolicy;
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
pub use membership::AuthoritativeMembership;
pub use meshspan_domain::AuthenticationService;
pub use passkey_registration::{
    AuthenticationMethodCreationReplay, PasskeyRegistrationProfile, PasskeyRegistrationReplay,
};
pub use query::{
    GroupMemberCursor, NamespaceCursor, NamespaceRecord, Page, PageLimit, PrincipalKind,
    PrincipalRecord,
};
pub use reachability::{
    RetainedNamespaceRoot, RetainedNamespaceRootCursor, RetainedNamespaceRootPage,
    RetainedNamespaceRootSource,
};
pub use receipt::{ApplyDisposition, CommandReceipt, EntityKind, EntityReference, LogPosition};
pub use retention::VersionRetentionPolicy;
pub use session::{ApiKeySessionReplay, PasskeySessionReplay, SessionRevocationReplay};
pub use session_access::{
    BrowserSessionAccessRequest, BrowserSessionProtection, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest,
};
pub use snapshot::{PartitionSnapshotManifest, PreservedVote, restore_partition_snapshot};
pub use snapshot_schedule::{SnapshotSchedule, SnapshotScheduleCursor};
pub use user_snapshot::{
    SnapshotCursor, SnapshotExpiryCandidate, SnapshotExpiryCursor, VolumeSnapshot,
};
pub use verify::{InvariantFinding, InvariantKind, InvariantReport};
pub use version_cleanup::{VersionCleanupIntent, VersionCleanupState};
pub use volume_head::ConvergedVolumeHead;

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
mod volume_head_tests;
