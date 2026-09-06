// SPDX-License-Identifier: GPL-2.0-only

//! Typed authoritative state-machine commands and canonical request digests.

use std::fmt;

use meshspan_contracts::{
    BoundedItems, ReclamationReceipt, RemovalPermit, ShardIdentity, ShardReceipt, TombstoneReceipt,
};
use meshspan_domain::{
    AcknowledgementPolicyId, ActivationId, ActivationPolicyId, ApiKeyId, AssuranceLevel,
    AuditEventId, AuthenticationFactorClasses, AuthenticationMethodId,
    AuthenticationOperationClass, AuthenticationPolicyId, AuthenticationService,
    AvailabilityCellId, ComponentInstanceId, ContentManifestId, DelegatedMetadataScope,
    DelegationAdmission, DurationMicros, FailureScenario, FaultGroupClassId, FaultGroupId,
    FileVersionId, GrantId, GroupId, HandoffEvidence, HostId, JoinGrantId, LocalityPolicyId,
    LocalityRequirementId, MeshId, MetadataKeyRange, MetadataOperationFamily, NamespaceCommitId,
    NodeId, ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId, PrincipalId,
    ProtectionPolicyId, ProtectionScenarioId, RecoveryCodeId, Revision, Rights, RoleId, ScopeId,
    SessionId, SmbExportId, SnapshotId, SnapshotScheduleId, TagId, TargetId, UnixMicros, VolumeId,
    WorkId,
};
use meshspan_secret_envelope::{EncryptedSecretParts, RecipientEnvelopeParts};
use meshspan_work::{DrainScope, WorkDemand, WorkSignals, WorkSubject};
use sha2::{Digest, Sha256};

use crate::AdmitFederatedMutation;
use crate::RecordFederatedActorAttestation;
use crate::RecordName;
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, ApproveFederationRelationship,
    DesignateFederationSuccessor, ProposeFederationRelationship, RecoverFederationRelationship,
    RestrictFederationRelationship, RetireFederationRelationship, RevokeFederationRelationship,
    RevokeFederationSuccessorDesignation, RotateFederationTrustIdentity,
};
use crate::{
    AcknowledgeExternalCertificateInstallation, AcknowledgeMeshLocalCertificateInstallation,
    AcknowledgePublicCertificateInstallation, AcmeChallengeKind, AdvanceManualDnsTask,
    CertificateOrderCompletion, CheckpointCertificateOrder, ClaimCertificateOrder,
    CompleteCertificateOrder, ConfigureAcme, CreateMeshLocalCertificateAuthority,
    IssueMeshLocalCertificate, ProvisionAcme, PublishExternalCertificate, QueueCertificateOrder,
    RenewCertificateOrder,
};
use crate::{
    ActivateFederationGrantAssignment, CreateFederationGrantAssignment, IssueFederationGrant,
    ReplaceFederationGrant, RevokeFederationGrant, RevokeFederationGrantAssignment,
    RevokeFederationGrantAssignmentActivation,
};
use crate::{
    ClaimMetadataBackupRun, CompleteMetadataBackupRun, ConfigureBackupDestination,
    ConfigureMetadataBackupSchedule, MetadataBackupRunCompletion, QueueMetadataBackupRun,
    RecordBackupCopy, RecordBackupReclamation, RecordMetadataBackup, RenewMetadataBackupRun,
    RetireMetadataBackup, VerifyBackupCopy,
};
use crate::{IssueFederationStorageAllocation, RevokeFederationStorageAllocation};
use crate::{
    ResolveFederatedMutationQuarantine, RetainFederatedMutationQuarantine,
    SurfaceFederatedMutationQuarantine,
};

/// Context applied identically to every state-machine command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandContext {
    /// Idempotency identity of the logical mutation.
    pub operation_id: OperationId,
    /// Authenticated principal responsible for the command.
    pub actor_principal_id: PrincipalId,
    /// Stable audit-event identity allocated before consensus.
    pub audit_event_id: AuditEventId,
    /// Authoritative instant supplied by the leader and recorded in the log.
    pub occurred_at: UnixMicros,
    /// Optional compare-and-swap state revision.
    pub expected_revision: Option<Revision>,
}

/// Closed authoritative command families implemented by the Stage 2 kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthoritativeCommand {
    /// Creates the first mesh, administrator, host, node and partition records.
    BootstrapMesh(BootstrapMesh),
    /// Atomically bootstraps the first mesh and its administrator's usable login method.
    BootstrapAppliance(Box<BootstrapAppliance>),
    /// Confirms that the exact encrypted offline recovery bundle was saved separately.
    ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved),
    /// Creates one user principal.
    CreateUser(CreateUser),
    /// Creates one group principal.
    CreateGroup(CreateGroup),
    /// Changes one user or group between active, suspended and terminal retirement states.
    ChangePrincipalState(ChangePrincipalState),
    /// Adds one direct user/group membership and rebuilds exact closure rows.
    AddGroupMember(AddGroupMember),
    /// Removes one exact direct membership while retaining audit evidence.
    RemoveGroupMember(RemoveGroupMember),
    /// Creates a bounded self-service activation policy.
    CreateActivationPolicy(CreateActivationPolicy),
    /// Creates a volume root with one non-empty multi-principal owner set.
    CreateVolume(CreateVolume),
    /// Advances one volume's globally converged namespace head from exact local evidence.
    CommitConvergedVolumeHead(CommitConvergedVolumeHead),
    /// Pins one exact current converged namespace root as a read-only volume snapshot.
    CreateVolumeSnapshot(CreateVolumeSnapshot),
    /// Restores one exact snapshot root as a new authoritative namespace commit.
    RestoreVolumeSnapshot(RestoreVolumeSnapshot),
    /// Marks one snapshot as expiring without dropping its namespace root.
    RequestVolumeSnapshotExpiry(RequestVolumeSnapshotExpiry),
    /// Drops one exact expiring snapshot root without authorising byte reclamation.
    RemoveVolumeSnapshotRoot(RemoveVolumeSnapshotRoot),
    /// Creates or replaces one authoritative fixed-interval snapshot schedule.
    ConfigureSnapshotSchedule(ConfigureSnapshotSchedule),
    /// Materialises exactly one due occurrence from an authoritative snapshot schedule.
    RunSnapshotSchedule(RunSnapshotSchedule),
    /// Appends and selects one immutable per-volume file-version retention policy.
    ConfigureVersionRetention(ConfigureVersionRetention),
    /// Proposes cleanup from one exact proof; cross-node validation remains required.
    ProposeVersionCleanup(ProposeVersionCleanup),
    /// Registers a node-scoped Ed25519 key for cleanup reachability attestations.
    RegisterCleanupAttestationKey(RegisterCleanupAttestationKey),
    /// Records one required node incarnation's signed unreachable-version attestation.
    AttestVersionCleanup(AttestVersionCleanup),
    /// Finalises one fully attested, still-current cleanup proposal as deletion authority.
    AuthoriseVersionCleanup(AuthoriseVersionCleanup),
    /// Terminates one pending cleanup proposal without authorising deletion.
    CancelVersionCleanup(CancelVersionCleanup),
    /// Appends one bounded contiguous page to an authorised cleanup inventory.
    AppendVersionCleanupItems(AppendVersionCleanupItems),
    /// Seals one complete cleanup inventory before any removal permit can exist.
    SealVersionCleanupInventory(SealVersionCleanupInventory),
    /// Records one exact short-lived removal-permit attempt for a sealed item.
    IssueVersionCleanupPermit(IssueVersionCleanupPermit),
    /// Records one provider-confirmed durable tombstone for a sealed cleanup item.
    CompleteVersionCleanupItem(CompleteVersionCleanupItem),
    /// Records one provider-confirmed physical unlink for a completed cleanup item.
    ConfirmVersionCleanupReclamation(ConfirmVersionCleanupReclamation),
    /// Creates one folder or file record beneath an existing folder.
    CreateObject(CreateObject),
    /// Atomically points one logical object at a new immutable owner set.
    ReplaceObjectOwners(ReplaceObjectOwners),
    /// Enables or removes one folder's parent-grant inheritance boundary.
    SetObjectGrantInheritance(SetObjectGrantInheritance),
    /// Creates one descriptive tag with no authority semantics.
    CreateTag(CreateTag),
    /// Attaches one descriptive tag to a principal or logical object.
    AttachTag(AttachTag),
    /// Detaches one descriptive tag from a principal or logical object.
    DetachTag(DetachTag),
    /// Creates an allow-only global, volume or object permission grant.
    GrantPermission(GrantPermission),
    /// Atomically creates an activation policy and its allow-only permission grant.
    GrantPermissionWithActivation(GrantPermissionWithActivation),
    /// Revokes one exact permission grant immediately.
    RevokePermissionGrant(RevokePermissionGrant),
    /// Activates one pre-authorised grant for the requesting user.
    ActivateGrant(ActivateGrant),
    /// Activates one pre-authorised group for the requesting user.
    ActivateGroup(ActivateGroup),
    /// Revokes one exact current access activation.
    RevokeAccessActivation(RevokeAccessActivation),
    /// Creates one typed authentication method without persisting plaintext credentials.
    CreateAuthenticationMethod(CreateAuthenticationMethod),
    /// Appends and selects one immutable service/operation authentication policy.
    ConfigureAuthenticationPolicy(ConfigureAuthenticationPolicy),
    /// Revokes one exact authentication method immediately.
    RevokeAuthenticationMethod(RevokeAuthenticationMethod),
    /// Issues one bounded authentication session after an accepted authentication ceremony.
    IssueAuthenticationSession(IssueAuthenticationSession),
    /// Atomically replaces one current session after a fresh additional factor.
    StepUpAuthenticationSession(StepUpAuthenticationSession),
    /// Revokes one exact authentication session immediately.
    RevokeAuthenticationSession(RevokeAuthenticationSession),
    /// Creates a versioned desired component configuration.
    CreateComponent(CreateComponent),
    /// Selects a new validated desired configuration revision.
    ConfigureComponent(ConfigureComponent),
    /// Creates or replaces one bounded component assignment.
    AssignComponent(AssignComponent),
    /// Registers one identity-bound storage target and its first marker generation.
    RegisterStorageTarget(RegisterStorageTarget),
    /// Creates one named shared-failure group, creating its class when first used.
    CreateFaultGroup(CreateFaultGroup),
    /// Adds or removes one machine from one shared-failure group.
    SetHostFaultGroupMembership(SetHostFaultGroupMembership),
    /// Creates one immutable, named set of data-survival failure promises.
    CreateProtectionPolicy(CreateProtectionPolicy),
    /// Selects one existing protection policy as the volume-wide survival promise.
    AssignVolumeProtectionPolicy(AssignVolumeProtectionPolicy),
    /// Creates one named availability cell used by locality and acknowledgement policies.
    CreateAvailabilityCell(CreateAvailabilityCell),
    /// Adds or removes one machine from one availability cell.
    SetHostAvailabilityCellMembership(SetHostAvailabilityCellMembership),
    /// Adds or removes one storage target from one availability cell.
    SetTargetAvailabilityCellMembership(SetTargetAvailabilityCellMembership),
    /// Creates one immutable desired-locality policy.
    CreateLocalityPolicy(CreateLocalityPolicy),
    /// Selects one locality policy as the volume-wide inherited default.
    AssignVolumeLocalityPolicy(AssignVolumeLocalityPolicy),
    /// Creates one immutable write-acknowledgement policy.
    CreateAcknowledgementPolicy(CreateAcknowledgementPolicy),
    /// Selects one acknowledgement policy as the volume-wide inherited default.
    AssignVolumeAcknowledgementPolicy(AssignVolumeAcknowledgementPolicy),
    /// Creates or coalesces one durable maintenance job from exact health evidence.
    QueueMaintenanceWork(QueueMaintenanceWork),
    /// Excludes one target generation from new writes and atomically queues its evacuation.
    BeginStorageTargetDrain(BeginStorageTargetDrain),
    /// Fences new placement into one node or fault group before composing its target drains.
    BeginStorageScopeDrain(BeginStorageScopeDrain),
    /// Marks one fully evacuated node as retiring from every metadata membership.
    FenceStorageNodeDrainMembership(FenceStorageNodeDrainMembership),
    /// Commits the authoritative safe-to-detach proof for one drained node or fault group.
    CompleteStorageScopeDrain(CompleteStorageScopeDrain),
    /// Records one gateway's exact empty-catalogue proof for a draining target.
    AttestStorageTargetDrain(AttestStorageTargetDrain),
    /// Commits one bounded restart-safe volume rebalance scan page.
    CommitRebalanceScanPage(CommitRebalanceScanPage),
    /// Fences one eligible worker's bounded lease over a ready maintenance job.
    ClaimMaintenanceWork(ClaimMaintenanceWork),
    /// Extends the same live claim without changing its fence or assignment.
    RenewMaintenanceWork(RenewMaintenanceWork),
    /// Commits exact work evidence as terminal success or a bounded retry.
    CompleteMaintenanceWork(CompleteMaintenanceWork),
    /// Advances one protected stripe to a provider-confirmed replacement shard location.
    CommitShardRepair(CommitShardRepair),
    /// Commits the bounded summary of one complete provider scrub pass.
    CommitScrubPass(CommitScrubPass),
    /// Commits one returning target's complete inventory-verification pass.
    CommitTargetReconciliation(CommitTargetReconciliation),
    /// Publishes one volume or folder through explicitly selected SMB gateways.
    PublishSmbExport(PublishSmbExport),
    /// Withdraws one exact SMB export while retaining its audit history.
    WithdrawSmbExport(WithdrawSmbExport),
    /// Commits one immutable public-certificate configuration revision.
    ConfigureAcme(ConfigureAcme),
    /// Atomically commits protected ACME inputs, one configuration and its initial order.
    ProvisionAcme(Box<ProvisionAcme>),
    /// Creates one durable ACME order for an exact configuration revision.
    QueueCertificateOrder(QueueCertificateOrder),
    /// Fences one node as the sole executor of an actionable ACME order.
    ClaimCertificateOrder(ClaimCertificateOrder),
    /// Extends one still-current ACME order claim.
    RenewCertificateOrder(RenewCertificateOrder),
    /// Persists one validated ACME restart point under the current order fence.
    CheckpointCertificateOrder(CheckpointCertificateOrder),
    /// Creates or advances one exact manual DNS task under the current order fence.
    AdvanceManualDnsTask(AdvanceManualDnsTask),
    /// Commits an issued certificate generation or schedules a bounded retry.
    CompleteCertificateOrder(CompleteCertificateOrder),
    /// Records one gateway's exact live public-certificate generation.
    AcknowledgePublicCertificateInstallation(AcknowledgePublicCertificateInstallation),
    /// Atomically publishes one externally issued, validated and encrypted certificate generation.
    PublishExternalCertificate(Box<PublishExternalCertificate>),
    /// Records one gateway's exact live externally issued certificate generation.
    AcknowledgeExternalCertificateInstallation(AcknowledgeExternalCertificateInstallation),
    /// Creates the first encrypted mesh-local HTTPS signing authority and public trust anchor.
    CreateMeshLocalCertificateAuthority(Box<CreateMeshLocalCertificateAuthority>),
    /// Publishes one endpoint generation signed by the current mesh-local authority.
    IssueMeshLocalCertificate(Box<IssueMeshLocalCertificate>),
    /// Records one gateway's exact live mesh-local endpoint generation.
    AcknowledgeMeshLocalCertificateInstallation(AcknowledgeMeshLocalCertificateInstallation),
    /// Creates or replaces one encrypted metadata-backup destination.
    ConfigureBackupDestination(ConfigureBackupDestination),
    /// Creates or replaces one partition's automatic metadata-backup schedule.
    ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule),
    /// Atomically configures an explicitly enabled, consumer-restricted metrics exporter.
    ConfigureMetricsExporter(crate::ConfigureMetricsExporter),
    /// Reconciles automatically managed backup destinations and schedule from current topology.
    ReconcileMetadataBackupDefaults(crate::ReconcileMetadataBackupDefaults),
    /// Materialises one exact due automatic metadata-backup occurrence.
    QueueMetadataBackupRun(QueueMetadataBackupRun),
    /// Fences one node as the sole producer for a queued backup occurrence.
    ClaimMetadataBackupRun(ClaimMetadataBackupRun),
    /// Extends one unchanged live backup producer claim.
    RenewMetadataBackupRun(RenewMetadataBackupRun),
    /// Terminates one run as protected or explicitly incomplete.
    CompleteMetadataBackupRun(CompleteMetadataBackupRun),
    /// Admits one exact encrypted partition backup generation.
    RecordMetadataBackup(RecordMetadataBackup),
    /// Records one provider-confirmed encrypted backup copy.
    RecordBackupCopy(RecordBackupCopy),
    /// Records read-after-write verification of one unchanged backup copy.
    VerifyBackupCopy(VerifyBackupCopy),
    /// Retires an old backup and its copies against current retained-generation evidence.
    RetireMetadataBackup(RetireMetadataBackup),
    /// Records exact physical removal after authoritative retirement.
    RecordBackupReclamation(RecordBackupReclamation),
    /// Registers one node-local public key for encrypted secret generations.
    RegisterNodeWrappingKey(RegisterNodeWrappingKey),
    /// Commits one encrypted secret generation and every exact recipient envelope atomically.
    CommitSecretGeneration(CommitSecretGeneration),
    /// Issues one bounded administrator-authorised node join grant.
    IssueJoinGrant(IssueJoinGrant),
    /// Consumes a join grant to admit one certificate-bound learner node.
    ConsumeJoinGrant(ConsumeJoinGrant),
    /// Activates one admitted node after certificate-bound private-protocol negotiation.
    ActivateNode(ActivateNode),
    /// Registers an Ed25519 public key permitted to attest catalogue routes.
    RegisterRoutingSigner(RegisterRoutingSigner),
    /// Creates another metadata partition in the catalogue.
    CreateMetadataPartition(CreateMetadataPartition),
    /// Creates one initially active scope route.
    CreateScopeRoute(CreateScopeRoute),
    /// Installs a signed monotonic root-route projection at a non-root group.
    InstallScopeRouteProjection(InstallScopeRouteProjection),
    /// Begins destination catch-up while the source remains sole writer.
    BeginScopeHandoff(BeginScopeHandoff),
    /// Fences source writes at an exact state image.
    FreezeScopeHandoff(FreezeScopeHandoff),
    /// Activates a caught-up destination as sole writer.
    ActivateScopeHandoff(ActivateScopeHandoff),
    /// Restores source authority under a newer route fence.
    AbortScopeHandoff(AbortScopeHandoff),
    /// Starts a mutually approved relationship without granting authority yet.
    ProposeFederationRelationship(ProposeFederationRelationship),
    /// Atomically activates a proposal with both initial public trust identities.
    ApproveFederationRelationship(ApproveFederationRelationship),
    /// Rotates one side's public trust identity while retaining verification history.
    RotateFederationTrustIdentity(RotateFederationTrustIdentity),
    /// Narrows a live relationship under a newer authority fence.
    RestrictFederationRelationship(RestrictFederationRelationship),
    /// Restores a restricted relationship under a newer authority fence.
    RecoverFederationRelationship(RecoverFederationRelationship),
    /// Revokes a relationship and all older authority envelopes.
    RevokeFederationRelationship(RevokeFederationRelationship),
    /// Retires an already revoked relationship without deleting evidence.
    RetireFederationRelationship(RetireFederationRelationship),
    /// Issues an effective grant from every independent restriction.
    IssueFederationGrant(IssueFederationGrant),
    /// Replaces one immutable grant for renewal or explicit narrowing.
    ReplaceFederationGrant(ReplaceFederationGrant),
    /// Revokes one live federation grant while retaining its evidence.
    RevokeFederationGrant(RevokeFederationGrant),
    /// Assigns a swarm-targeted namespace grant to one local user or group.
    CreateFederationGrantAssignment(CreateFederationGrantAssignment),
    /// Revokes one local federation grant assignment immediately.
    RevokeFederationGrantAssignment(RevokeFederationGrantAssignment),
    /// Activates one pre-authorised local federation grant assignment.
    ActivateFederationGrantAssignment(ActivateFederationGrantAssignment),
    /// Revokes one current federation-assignment activation.
    RevokeFederationGrantAssignmentActivation(RevokeFederationGrantAssignmentActivation),
    /// Assigns one disjoint storage-grant slice to an exact provider node and target generation.
    IssueFederationStorageAllocation(IssueFederationStorageAllocation),
    /// Revokes one live provider allocation without deleting its authority history.
    RevokeFederationStorageAllocation(RevokeFederationStorageAllocation),
    /// Advances one signed home-swarm actor attestation.
    RecordFederatedActorAttestation(RecordFederatedActorAttestation),
    /// Persists a retiring swarm's signed pre-authorisation of one recovery successor.
    DesignateFederationSuccessor(DesignateFederationSuccessor),
    /// Persists the nominated successor's exact signed acceptance.
    AcceptFederationSuccessor(AcceptFederationSuccessor),
    /// Activates an accepted successor and permanently fences the retired swarm.
    ActivateFederationSuccessor(ActivateFederationSuccessor),
    /// Cancels a dormant successor designation before activation.
    RevokeFederationSuccessorDesignation(RevokeFederationSuccessorDesignation),
    /// Retains one signed, authoritatively reclassified disconnected mutation invisibly.
    RetainFederatedMutationQuarantine(RetainFederatedMutationQuarantine),
    /// Records one signed remote mutation as admissible at this exact consensus position.
    AdmitFederatedMutation(AdmitFederatedMutation),
    /// Makes retained quarantine visible to authorised recovery administration.
    SurfaceFederatedMutationQuarantine(SurfaceFederatedMutationQuarantine),
    /// Records an authorised recovery or discard choice for surfaced quarantine.
    ResolveFederatedMutationQuarantine(ResolveFederatedMutationQuarantine),
}

impl AuthoritativeCommand {
    /// Returns a deterministic digest over the complete semantic command and context.
    #[must_use]
    pub fn request_digest(&self, context: CommandContext) -> [u8; 32] {
        let mut digest = CanonicalDigest::new(b"meshspan.metadata.command.v1");
        digest.identifier(context.operation_id.as_bytes());
        digest.identifier(context.actor_principal_id.as_bytes());
        digest.identifier(context.audit_event_id.as_bytes());
        digest.signed(context.occurred_at.get());
        digest.optional_revision(context.expected_revision);
        self.update_digest(&mut digest);
        digest.finish()
    }

    // This is deliberately one exhaustive, side-effect-free dispatch table: splitting command
    // families across fallible routing layers would weaken the closed-command invariant.
    #[allow(clippy::too_many_lines)]
    fn update_digest(&self, digest: &mut CanonicalDigest) {
        match self {
            Self::BootstrapMesh(value) => value.update_digest(digest),
            Self::BootstrapAppliance(value) => value.update_digest(digest),
            Self::ConfirmRecoveryBundleSaved(value) => value.update_digest(digest),
            Self::CreateUser(value) => value.update_digest(digest),
            Self::CreateGroup(value) => value.update_digest(digest),
            Self::ChangePrincipalState(value) => value.update_digest(digest),
            Self::AddGroupMember(value) => value.update_digest(digest),
            Self::RemoveGroupMember(value) => value.update_digest(digest),
            Self::CreateActivationPolicy(value) => value.update_digest(digest),
            Self::CreateVolume(value) => value.update_digest(digest),
            Self::CommitConvergedVolumeHead(value) => value.update_digest(digest),
            Self::CreateVolumeSnapshot(value) => value.update_digest(digest),
            Self::RestoreVolumeSnapshot(value) => value.update_digest(digest),
            Self::RequestVolumeSnapshotExpiry(value) => value.update_digest(digest),
            Self::RemoveVolumeSnapshotRoot(value) => value.update_digest(digest),
            Self::ConfigureSnapshotSchedule(value) => value.update_digest(digest),
            Self::RunSnapshotSchedule(value) => value.update_digest(digest),
            Self::ConfigureVersionRetention(value) => value.update_digest(digest),
            Self::ProposeVersionCleanup(value) => value.update_digest(digest),
            Self::RegisterCleanupAttestationKey(value) => value.update_digest(digest),
            Self::AttestVersionCleanup(value) => value.update_digest(digest),
            Self::AuthoriseVersionCleanup(value) => value.update_digest(digest),
            Self::CancelVersionCleanup(value) => value.update_digest(digest),
            Self::AppendVersionCleanupItems(value) => value.update_digest(digest),
            Self::SealVersionCleanupInventory(value) => value.update_digest(digest),
            Self::IssueVersionCleanupPermit(value) => value.update_digest(digest),
            Self::CompleteVersionCleanupItem(value) => value.update_digest(digest),
            Self::ConfirmVersionCleanupReclamation(value) => value.update_digest(digest),
            Self::CreateObject(value) => value.update_digest(digest),
            Self::ReplaceObjectOwners(value) => value.update_digest(digest),
            Self::SetObjectGrantInheritance(value) => value.update_digest(digest),
            Self::CreateTag(value) => value.update_digest(digest),
            Self::AttachTag(value) => value.update_digest(digest),
            Self::DetachTag(value) => value.update_digest(digest),
            Self::GrantPermission(value) => value.update_digest(digest),
            Self::GrantPermissionWithActivation(value) => value.update_digest(digest),
            Self::RevokePermissionGrant(value) => value.update_digest(digest),
            Self::ActivateGrant(value) => value.update_digest(digest),
            Self::ActivateGroup(value) => value.update_digest(digest),
            Self::RevokeAccessActivation(value) => value.update_digest(digest),
            Self::CreateAuthenticationMethod(value) => value.update_digest(digest),
            Self::ConfigureAuthenticationPolicy(value) => value.update_digest(digest),
            Self::RevokeAuthenticationMethod(value) => value.update_digest(digest),
            Self::IssueAuthenticationSession(value) => value.update_digest(digest),
            Self::StepUpAuthenticationSession(value) => value.update_digest(digest),
            Self::RevokeAuthenticationSession(value) => value.update_digest(digest),
            Self::CreateComponent(value) => value.update_digest(digest),
            Self::ConfigureComponent(value) => value.update_digest(digest),
            Self::AssignComponent(value) => value.update_digest(digest),
            Self::RegisterStorageTarget(value) => value.update_digest(digest),
            Self::CreateFaultGroup(value) => value.update_digest(digest),
            Self::SetHostFaultGroupMembership(value) => value.update_digest(digest),
            Self::CreateProtectionPolicy(value) => value.update_digest(digest),
            Self::AssignVolumeProtectionPolicy(value) => value.update_digest(digest),
            Self::CreateAvailabilityCell(value) => value.update_digest(digest),
            Self::SetHostAvailabilityCellMembership(value) => value.update_digest(digest),
            Self::SetTargetAvailabilityCellMembership(value) => value.update_digest(digest),
            Self::CreateLocalityPolicy(value) => value.update_digest(digest),
            Self::AssignVolumeLocalityPolicy(value) => value.update_digest(digest),
            Self::CreateAcknowledgementPolicy(value) => value.update_digest(digest),
            Self::AssignVolumeAcknowledgementPolicy(value) => value.update_digest(digest),
            Self::QueueMaintenanceWork(value) => value.update_digest(digest),
            Self::BeginStorageTargetDrain(value) => value.update_digest(digest),
            Self::BeginStorageScopeDrain(value) => value.update_digest(digest),
            Self::FenceStorageNodeDrainMembership(value) => value.update_digest(digest),
            Self::CompleteStorageScopeDrain(value) => value.update_digest(digest),
            Self::AttestStorageTargetDrain(value) => value.update_digest(digest),
            Self::CommitRebalanceScanPage(value) => value.update_digest(digest),
            Self::ClaimMaintenanceWork(value) => value.update_digest(digest),
            Self::RenewMaintenanceWork(value) => value.update_digest(digest),
            Self::CompleteMaintenanceWork(value) => value.update_digest(digest),
            Self::CommitShardRepair(value) => value.update_digest(digest),
            Self::CommitScrubPass(value) => value.update_digest(digest),
            Self::CommitTargetReconciliation(value) => value.update_digest(digest),
            Self::PublishSmbExport(value) => value.update_digest(digest),
            Self::WithdrawSmbExport(value) => value.update_digest(digest),
            Self::ConfigureAcme(value) => value.update_digest(digest),
            Self::ProvisionAcme(value) => value.update_digest(digest),
            Self::QueueCertificateOrder(value) => value.update_digest(digest),
            Self::ClaimCertificateOrder(value) => value.update_digest(digest),
            Self::RenewCertificateOrder(value) => value.update_digest(digest),
            Self::CheckpointCertificateOrder(value) => value.update_digest(digest),
            Self::AdvanceManualDnsTask(value) => value.update_digest(digest),
            Self::CompleteCertificateOrder(value) => value.update_digest(digest),
            Self::AcknowledgePublicCertificateInstallation(value) => value.update_digest(digest),
            Self::PublishExternalCertificate(value) => value.update_digest(digest),
            Self::AcknowledgeExternalCertificateInstallation(value) => value.update_digest(digest),
            Self::CreateMeshLocalCertificateAuthority(value) => value.update_digest(digest),
            Self::IssueMeshLocalCertificate(value) => value.update_digest(digest),
            Self::AcknowledgeMeshLocalCertificateInstallation(value) => {
                value.update_digest(digest);
            }
            Self::ConfigureBackupDestination(value) => value.update_digest(digest),
            Self::ConfigureMetadataBackupSchedule(value) => value.update_digest(digest),
            Self::ConfigureMetricsExporter(value) => {
                digest.bytes(b"configure-metrics-exporter-v1");
                digest.unsigned(value.expected_sequence);
                digest.boolean(value.policy.enabled);
                digest.unsigned(
                    u64::try_from(value.policy.allowed_principals.len()).unwrap_or(u64::MAX),
                );
                for principal in &value.policy.allowed_principals {
                    digest.identifier(principal.as_bytes());
                }
            }
            Self::QueueMetadataBackupRun(value) => value.update_digest(digest),
            Self::ClaimMetadataBackupRun(value) => value.update_digest(digest),
            Self::RenewMetadataBackupRun(value) => value.update_digest(digest),
            Self::CompleteMetadataBackupRun(value) => value.update_digest(digest),
            Self::RecordMetadataBackup(value) => value.update_digest(digest),
            Self::RecordBackupCopy(value) => value.update_digest(digest),
            Self::VerifyBackupCopy(value) => value.update_digest(digest),
            Self::ReconcileMetadataBackupDefaults(value) => value.update_digest(digest),
            Self::RetireMetadataBackup(value) => value.update_digest(digest),
            Self::RecordBackupReclamation(value) => value.update_digest(digest),
            Self::RegisterNodeWrappingKey(value) => value.update_digest(digest),
            Self::CommitSecretGeneration(value) => value.update_digest(digest),
            Self::IssueJoinGrant(value) => value.update_digest(digest),
            Self::ConsumeJoinGrant(value) => value.update_digest(digest),
            Self::ActivateNode(value) => value.update_digest(digest),
            Self::RegisterRoutingSigner(value) => value.update_digest(digest),
            Self::CreateMetadataPartition(value) => value.update_digest(digest),
            Self::CreateScopeRoute(value) => value.update_digest(digest),
            Self::InstallScopeRouteProjection(value) => value.update_digest(digest),
            Self::BeginScopeHandoff(value) => value.update_digest(digest),
            Self::FreezeScopeHandoff(value) => value.update_digest(digest),
            Self::ActivateScopeHandoff(value) => value.update_digest(digest),
            Self::AbortScopeHandoff(value) => value.update_digest(digest),
            Self::ProposeFederationRelationship(value) => value.update_digest(digest),
            Self::ApproveFederationRelationship(value) => value.update_digest(digest),
            Self::RotateFederationTrustIdentity(value) => value.update_digest(digest),
            Self::RestrictFederationRelationship(value) => value.update_digest(digest),
            Self::RecoverFederationRelationship(value) => value.update_digest(digest),
            Self::RevokeFederationRelationship(value) => value.update_digest(digest),
            Self::RetireFederationRelationship(value) => value.update_digest(digest),
            Self::IssueFederationGrant(value) => value.update_digest(digest),
            Self::ReplaceFederationGrant(value) => value.update_digest(digest),
            Self::RevokeFederationGrant(value) => value.update_digest(digest),
            Self::CreateFederationGrantAssignment(value) => value.update_digest(digest),
            Self::RevokeFederationGrantAssignment(value) => value.update_digest(digest),
            Self::ActivateFederationGrantAssignment(value) => value.update_digest(digest),
            Self::RevokeFederationGrantAssignmentActivation(value) => value.update_digest(digest),
            Self::IssueFederationStorageAllocation(value) => value.update_digest(digest),
            Self::RevokeFederationStorageAllocation(value) => value.update_digest(digest),
            Self::RecordFederatedActorAttestation(value) => value.update_digest(digest),
            Self::DesignateFederationSuccessor(value) => value.update_digest(digest),
            Self::AcceptFederationSuccessor(value) => value.update_digest(digest),
            Self::ActivateFederationSuccessor(value) => value.update_digest(digest),
            Self::RevokeFederationSuccessorDesignation(value) => value.update_digest(digest),
            Self::RetainFederatedMutationQuarantine(value) => value.update_digest(digest),
            Self::AdmitFederatedMutation(value) => value.update_digest(digest),
            Self::SurfaceFederatedMutationQuarantine(value) => value.update_digest(digest),
            Self::ResolveFederatedMutationQuarantine(value) => value.update_digest(digest),
        }
    }
}

/// Initial one-node mesh records committed atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapMesh {
    /// Mesh identity.
    pub mesh_id: MeshId,
    /// Mesh display/canonical name.
    pub mesh_name: RecordName,
    /// First administrator user principal.
    pub administrator_id: PrincipalId,
    /// Administrator display/canonical name.
    pub administrator_name: RecordName,
    /// Built-in system-administrator role identity.
    pub administrator_role_id: RoleId,
    /// First physical host.
    pub host_id: HostId,
    /// Host display/canonical name.
    pub host_name: RecordName,
    /// First daemon node.
    pub node_id: NodeId,
    /// Node display/canonical name.
    pub node_name: RecordName,
    /// Display/canonical name of the already identity-bound partition.
    pub partition_name: RecordName,
}

/// Atomic first-appliance bootstrap with no default or temporarily missing credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapAppliance {
    /// First mesh, administrator and one-node authority records.
    pub mesh: BootstrapMesh,
    /// Initial login-capable passkey or API key owned by the first administrator.
    pub authentication: CreateAuthenticationMethod,
    /// Public offline authority and exact encrypted-bundle commitments.
    pub recovery: Box<BootstrapRecoveryIdentity>,
    /// Initial node public wrapping key whose private half remains in daemon state.
    pub node_wrapping_key: RegisterNodeWrappingKey,
    /// Mesh-signed certificate for the already active initial node identity.
    pub node_certificate: BootstrapNodeCertificate,
    /// Initial recoverable mesh-wide storage-permit authority.
    pub storage_permit_key_generation: Box<CommitSecretGeneration>,
    /// Initial recoverable gateway-only authentication-root authority.
    pub authentication_root_key_generation: Box<CommitSecretGeneration>,
    /// Initial recoverable online node-certificate authority private-key generation.
    pub online_authority_key_generation: Box<CommitSecretGeneration>,
}

/// Mesh-signed certificate material committed for the active initial node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapNodeCertificate {
    /// Signed public leaf certificate; the node private key remains in daemon state.
    pub certificate_der: Vec<u8>,
    /// Independently checked SHA-256 fingerprint of `certificate_der`.
    pub certificate_fingerprint: [u8; 32],
    /// Conservative metadata fence no later than the X.509 certificate lifetime.
    pub certificate_valid_until: UnixMicros,
}

/// Public offline authority committed atomically with the first mesh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapRecoveryIdentity {
    /// Initial offline-recovery X25519 public key.
    pub public_wrapping_key: [u8; 32],
    /// Domain-separated fingerprint of the public wrapping key.
    pub key_fingerprint: [u8; 32],
    /// Self-signed mesh root certificate in DER form.
    pub root_certificate_der: Vec<u8>,
    /// SHA-256 digest of the exact root certificate bytes.
    pub root_certificate_digest: [u8; 32],
    /// Root-signed online node-certificate authority certificate in DER form.
    pub online_authority_certificate_der: Vec<u8>,
    /// SHA-256 digest of the exact online-authority certificate bytes.
    pub online_authority_certificate_digest: [u8; 32],
    /// Digest of the exact encrypted portable recovery-bundle file.
    pub bundle_digest: [u8; 32],
    /// Non-reversible commitment to the short save-verification challenge.
    pub save_challenge_commitment: [u8; 32],
}

/// Exact proof transitioning one offline bundle from pending delivery to verified saved state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmRecoveryBundleSaved {
    /// Mesh whose offline bundle was saved.
    pub mesh_id: MeshId,
    /// Digest of the exact downloaded bundle.
    pub bundle_digest: [u8; 32],
    /// Commitment derived from the challenge entered by the administrator.
    pub save_challenge_commitment: [u8; 32],
}

/// New user record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUser {
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Display/canonical name.
    pub name: RecordName,
}

/// New group record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateGroup {
    /// Group/principal identity.
    pub group_id: GroupId,
    /// Display/canonical name.
    pub name: RecordName,
    /// Optional policy required before membership contributes rights.
    pub activation_policy_id: Option<ActivationPolicyId>,
}

/// Closed administrator-controlled principal lifecycle states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalLifecycleState {
    /// Principal may authenticate and contribute authority.
    Active,
    /// Principal is reversibly disabled without deleting history.
    Suspended,
    /// Principal is terminally disabled and cannot be reactivated.
    Retired,
}

/// One audited principal transition plus any required atomic owner replacements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangePrincipalState {
    /// Existing user or group principal.
    pub principal_id: PrincipalId,
    /// Exact desired lifecycle state.
    pub state: PrincipalLifecycleState,
    /// Non-blank bounded human audit reason.
    pub reason: String,
    /// Exact owner replacements required to avoid leaving a current object ownerless.
    pub owner_transfers: BoundedItems<ReplaceObjectOwners>,
}

/// One direct containing-group membership edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddGroupMember {
    /// Structurally containing group.
    pub containing_group_id: GroupId,
    /// User or group principal directly contained.
    pub member_principal_id: PrincipalId,
    /// Inclusive activation window start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive activation window end.
    pub valid_until: Option<UnixMicros>,
    /// Whether the user must explicitly activate this membership source.
    pub activation_required: bool,
}

/// Audited removal of one exact active direct group edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveGroupMember {
    /// Containing group of the exact edge.
    pub containing_group_id: GroupId,
    /// Direct user or group member being removed.
    pub member_principal_id: PrincipalId,
    /// Non-blank bounded human audit reason.
    pub reason: String,
}

/// Persisted self-service activation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateActivationPolicy {
    /// Stable policy identity.
    pub policy_id: ActivationPolicyId,
    /// Maximum active duration.
    pub maximum_duration: DurationMicros,
    /// Whether a non-blank reason is mandatory.
    pub reason_required: bool,
    /// Minimum current authentication assurance.
    pub minimum_assurance: AssuranceLevel,
    /// Inclusive absolute validity start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive absolute validity end.
    pub valid_until: Option<UnixMicros>,
}

/// New volume and root directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVolume {
    /// Volume identity.
    pub volume_id: VolumeId,
    /// Volume display/canonical name.
    pub name: RecordName,
    /// Root directory identity.
    pub root_object_id: ObjectId,
    /// Immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Non-empty user/group owner principals.
    pub owners: BoundedItems<PrincipalId>,
    /// Initial recoverable volume-content key committed in the same transaction.
    pub key_generation: Box<CommitSecretGeneration>,
}

/// Secret-envelope kind reserved for volume-content key-encryption keys.
pub const VOLUME_CONTENT_KEY_SECRET_KIND: u16 = 1;

/// Secret-envelope kind reserved for the mesh-wide storage-permit MAC key.
pub const STORAGE_PERMIT_KEY_SECRET_KIND: u16 = 2;

/// Secret-envelope kind reserved for the gateway-only mesh authentication root.
pub const AUTHENTICATION_ROOT_KEY_SECRET_KIND: u16 = 3;

/// Secret-envelope kind reserved for the rotatable online node-certificate authority key.
pub const ONLINE_AUTHORITY_KEY_SECRET_KIND: u16 = 4;

/// Secret-envelope kind reserved for ACME account private keys.
pub const ACME_ACCOUNT_KEY_SECRET_KIND: u16 = 5;

/// Secret-envelope kind reserved for ACME DNS publisher credentials and settings.
pub const ACME_CHALLENGE_SETTINGS_SECRET_KIND: u16 = 6;

/// Secret-envelope kind reserved for validated public certificate/private-key bundles.
pub const PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND: u16 = 7;

/// Encrypted private key for one in-flight externally issued certificate request.
pub const PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND: u16 = 8;

/// Encrypted private key for one mesh-local HTTPS certificate authority generation.
pub const MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND: u16 = 9;

/// Exact durable local outcome accepted as the source of a converged-head transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConvergedHeadEvidence {
    /// One ordinary branch publication, including initial volume publication.
    Publication {
        /// Stable local publication operation.
        operation_id: OperationId,
        /// Digest binding every local publication input.
        request_digest: [u8; 32],
        /// Digest binding the complete local publication result.
        result_digest: [u8; 32],
    },
    /// One deterministic multi-parent reconciliation transaction.
    Reconciliation {
        /// Stable local reconciliation operation.
        operation_id: OperationId,
        /// Digest binding the reconciliation application and both plans.
        request_digest: [u8; 32],
        /// Digest of the validated causal frontier and merge parents.
        causal_plan_digest: [u8; 32],
        /// Digest of the exact affected-path replay actions.
        replay_plan_digest: [u8; 32],
        /// Digest binding the complete local reconciliation result.
        result_digest: [u8; 32],
    },
}

/// Compare-and-swap of one volume's replicated globally converged namespace head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitConvergedVolumeHead {
    /// Volume whose single authoritative head advances.
    pub volume_id: VolumeId,
    /// Exact current head required, or none for the first converged publication.
    pub expected_namespace_commit_id: Option<NamespaceCommitId>,
    /// Immutable namespace commit selected as the new globally converged head.
    pub namespace_commit_id: NamespaceCommitId,
    /// Root object revision bound by `namespace_commit_id` in the local immutable store.
    pub root_object_revision_id: ObjectRevisionId,
    /// Exact durable local outcome from which this transition was proposed.
    pub evidence: ConvergedHeadEvidence,
}

/// Constant-metadata creation of one read-only snapshot at an exact converged head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVolumeSnapshot {
    /// Stable snapshot identity.
    pub snapshot_id: SnapshotId,
    /// Volume whose current converged root is pinned.
    pub volume_id: VolumeId,
    /// Exact current converged commit required by the request.
    pub namespace_commit_id: NamespaceCommitId,
    /// Human-facing and canonicalised snapshot name.
    pub name: RecordName,
    /// Optional automatic expiry instant.
    pub expires_at: Option<UnixMicros>,
    /// Whether automatic expiry and pressure reclamation are forbidden.
    pub protected_from_expiry: bool,
}

/// Authoritative compare-and-swap of one prepared whole-volume snapshot restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreVolumeSnapshot {
    /// Existing active or expiring snapshot selected for restore.
    pub snapshot_id: SnapshotId,
    /// Exact snapshot record revision observed by the requester.
    pub expected_snapshot_revision: Revision,
    /// Volume whose current namespace is restored.
    pub volume_id: VolumeId,
    /// Exact namespace commit pinned by the snapshot.
    pub snapshot_namespace_commit_id: NamespaceCommitId,
    /// Exact current converged head required before restore.
    pub expected_namespace_commit_id: NamespaceCommitId,
    /// Prepared immutable commit that selects the snapshot root.
    pub namespace_commit_id: NamespaceCommitId,
    /// Exact immutable root revision pinned by the snapshot.
    pub root_object_revision_id: ObjectRevisionId,
    /// Stable local preparation operation.
    pub source_operation_id: OperationId,
    /// Digest binding every local preparation input.
    pub source_request_digest: [u8; 32],
    /// Digest binding the complete durable local preparation result.
    pub source_result_digest: [u8; 32],
}

/// Closed, persistently encoded reason for moving a snapshot into expiring state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotExpiryReason {
    /// Explicit authorised request independent of automatic retention.
    Manual,
    /// Configured expiry instant has elapsed.
    RetentionAge,
    /// A schedule exceeds its current retained-snapshot count.
    RetentionCount,
}

/// Safe first phase of snapshot expiry; root removal remains separately guarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestVolumeSnapshotExpiry {
    /// Existing active snapshot.
    pub snapshot_id: SnapshotId,
    /// Exact snapshot revision observed by the requester.
    pub expected_snapshot_revision: Revision,
    /// Exact manual or automatically proven retention reason.
    pub reason: SnapshotExpiryReason,
}

/// Exact final transition that stops one expiring snapshot from retaining its root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoveVolumeSnapshotRoot {
    /// Expiring snapshot whose root reference is removed.
    pub snapshot_id: SnapshotId,
    /// Exact snapshot record revision observed by the requester.
    pub expected_snapshot_revision: Revision,
    /// Specific accepted expiry request authorising this later transition.
    pub expiry_operation_id: OperationId,
    /// Exact namespace commit whose snapshot reference is being dropped.
    pub namespace_commit_id: NamespaceCommitId,
    /// Exact immutable root revision whose snapshot reference is being dropped.
    pub root_object_revision_id: ObjectRevisionId,
}

/// One complete immutable revision of a fixed-interval volume snapshot schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigureSnapshotSchedule {
    /// Stable schedule identity.
    pub schedule_id: SnapshotScheduleId,
    /// Volume whose converged head will be captured.
    pub volume_id: VolumeId,
    /// Exact current schedule sequence, or zero when creating the schedule.
    pub expected_schedule_sequence: u64,
    /// Positive interval between scheduled occurrences.
    pub interval: DurationMicros,
    /// Optional count of newest snapshots retained by this schedule.
    pub retention_count: Option<u32>,
    /// Optional age after which snapshots created by this schedule become expirable.
    pub retention_duration: Option<DurationMicros>,
    /// Whether the schedule may be selected for execution.
    pub enabled: bool,
    /// Exact first or rescheduled occurrence.
    pub next_due_at: UnixMicros,
}

/// Exact execution of one due snapshot-schedule occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshotSchedule {
    /// Schedule being executed.
    pub schedule_id: SnapshotScheduleId,
    /// Exact current schedule revision observed by the scheduler.
    pub expected_schedule_sequence: u64,
    /// Due instant selected from authoritative schedule state.
    pub scheduled_for: UnixMicros,
    /// Stable identity allocated for the resulting snapshot.
    pub snapshot_id: SnapshotId,
    /// Exact current converged namespace commit required by the request.
    pub namespace_commit_id: NamespaceCommitId,
    /// Human-facing and canonicalised snapshot name.
    pub name: RecordName,
}

/// Closed trigger deciding when an otherwise eligible historical version is reclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionReclaimMode {
    /// Reclaim after the minimum age only when the storage target is under pressure.
    UnderPressure,
    /// Reclaim once the configured maximum age is reached.
    AfterMaximumAge,
    /// Reclaim eagerly as soon as the minimum age is reached.
    EagerAfterMinimumAge,
}

/// One complete immutable replacement for a volume's version-retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigureVersionRetention {
    /// Volume receiving the policy.
    pub volume_id: VolumeId,
    /// Exact currently selected policy sequence.
    pub expected_policy_sequence: u64,
    /// Whether future superseded versions enter ordinary history.
    pub history_enabled: bool,
    /// Ordinary minimum retention age.
    pub minimum_age: DurationMicros,
    /// Optional maximum retention age, never shorter than the minimum.
    pub maximum_age: Option<DurationMicros>,
    /// Optional number of newest historical versions retained regardless of age.
    pub minimum_versions: Option<u32>,
    /// Trigger used after other reachability and hard-retention guards pass.
    pub reclaim_mode: RetentionReclaimMode,
    /// Whether critical pressure may break the ordinary minimum as a last resort.
    pub soft_minimum_breakable: bool,
    /// Mandatory safety age for acknowledged concurrent alternatives.
    pub conflict_minimum_age: DurationMicros,
}

/// Exact terminal reachability evidence admitted as one replicated cleanup intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposeVersionCleanup {
    /// Volume whose retained-root set was exhausted.
    pub volume_id: VolumeId,
    /// Historical immutable version proved unreachable.
    pub version_id: FileVersionId,
    /// Content manifest selected by that version.
    pub manifest_id: ContentManifestId,
    /// Immutable manifest root carried by every physical shard identity.
    pub manifest_root_digest: [u8; 32],
    /// Durable filesystem scan operation that produced the proof.
    pub source_scan_operation_id: OperationId,
    /// Digest binding the scan candidate, policy and root authority.
    pub scan_request_digest: [u8; 32],
    /// Operation-independent digest of the exact candidate, policy and root authority.
    pub reachability_subject_digest: [u8; 32],
    /// Exact current retention policy sequence used by preliminary selection.
    pub retention_policy_sequence: u64,
    /// Metadata revision against which every retained root was enumerated.
    pub reachability_revision: Revision,
    /// Complete number of metadata-authoritative retained roots.
    pub retained_root_count: u64,
    /// Canonical digest of those roots in stable order.
    pub retained_root_digest: [u8; 32],
    /// Revision-independent digest used to compare the same root set after later commands.
    pub retained_root_set_digest: [u8; 32],
    /// Digest of unchanged node-local branch and lifecycle roots.
    pub local_roots_digest: [u8; 32],
    /// Terminal scanner digest proving the unreachable outcome.
    pub proof_result_digest: [u8; 32],
}

/// Public key authorised only for one node's cleanup reachability attestations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterCleanupAttestationKey {
    /// Existing admitted or active node.
    pub node_id: NodeId,
    /// Strictly increasing key generation for that node.
    pub generation: u64,
    /// Strict Ed25519 verifying-key bytes.
    pub verifying_key: [u8; 32],
}

/// Signed statement that one exact node incarnation found no local reference to a cleanup target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupAttestation {
    /// Replicated cleanup proposal being attested.
    pub cleanup_operation_id: OperationId,
    /// Revision that created the immutable participant snapshot.
    pub cleanup_revision: Revision,
    /// Required node identity.
    pub node_id: NodeId,
    /// Exact required node incarnation, fencing restored or restarted state.
    pub node_incarnation: u64,
    /// Exact cleanup-attestation key generation.
    pub key_generation: u64,
    /// Node-local durable reachability scan identity.
    pub scan_operation_id: OperationId,
    /// Exact node-local scan request digest, including its unique operation identity.
    pub scan_request_digest: [u8; 32],
    /// Operation-independent digest shared with the proposal and every honest peer scan.
    pub reachability_subject_digest: [u8; 32],
    /// Digest of the node's unchanged local branch and lifecycle roots.
    pub local_roots_digest: [u8; 32],
    /// Terminal unreachable result digest from that node's scanner.
    pub scan_result_digest: [u8; 32],
    /// Ed25519 signature over [`Self::signing_digest`].
    pub signature: [u8; 64],
}

impl VersionCleanupAttestation {
    /// Returns the domain-separated digest signed by the attesting node.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(b"meshspan.version-cleanup-attestation.v1\0");
        digest.update(&self.cleanup_operation_id.as_bytes());
        digest.update(&self.cleanup_revision.get().to_be_bytes());
        digest.update(&self.node_id.as_bytes());
        digest.update(&self.node_incarnation.to_be_bytes());
        digest.update(&self.key_generation.to_be_bytes());
        digest.update(&self.scan_operation_id.as_bytes());
        digest.update(&self.scan_request_digest);
        digest.update(&self.reachability_subject_digest);
        digest.update(&self.local_roots_digest);
        digest.update(&self.scan_result_digest);
        digest.finalize().into()
    }
}

/// One replicated signed cleanup reachability attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestVersionCleanup {
    /// Complete signed statement.
    pub attestation: VersionCleanupAttestation,
}

/// Exact proposal identity required for the terminal cleanup-authority transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoriseVersionCleanup {
    /// Pending replicated cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Revision that created the immutable participant snapshot.
    pub cleanup_revision: Revision,
    /// Operation-independent subject shared by every accepted attestation.
    pub reachability_subject_digest: [u8; 32],
}

/// Exact proposal identity terminated without granting deletion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelVersionCleanup {
    /// Pending replicated cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Revision that created the immutable participant snapshot.
    pub cleanup_revision: Revision,
    /// Operation-independent subject being abandoned.
    pub reachability_subject_digest: [u8; 32],
}

/// One exact physical shard placement belonging to an unreachable manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupItemPlacement {
    /// Stable per-item provider mutation identity used by every permit retry.
    pub removal_operation_id: OperationId,
    /// Exact immutable shard generation.
    pub shard: ShardIdentity,
    /// Exact registered folder target holding the shard.
    pub target_id: TargetId,
    /// Exact target generation fenced by the placement receipt.
    pub target_generation: u64,
    /// Exact storage node that owns this target generation and must report provider results.
    pub storage_node_id: NodeId,
}

/// One bounded contiguous page of exact physical cleanup items.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendVersionCleanupItems {
    /// Authorised cleanup proposal receiving the inventory.
    pub cleanup_operation_id: OperationId,
    /// Revision that created the proposal.
    pub cleanup_revision: Revision,
    /// Exact terminal revision that granted cleanup authority.
    pub authorisation_revision: Revision,
    /// Immutable total number of items expected across all pages.
    pub expected_item_count: u64,
    /// Zero-based index of the first item in this page.
    pub start_index: u64,
    /// Non-empty bounded placements in ascending contiguous item order.
    pub items: BoundedItems<VersionCleanupItemPlacement>,
}

/// Exact complete inventory digest admitted as permit-issuance authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealVersionCleanupInventory {
    /// Authorised cleanup proposal whose inventory becomes immutable.
    pub cleanup_operation_id: OperationId,
    /// Revision that created the proposal.
    pub cleanup_revision: Revision,
    /// Exact terminal revision that granted cleanup authority.
    pub authorisation_revision: Revision,
    /// Immutable expected item count.
    pub expected_item_count: u64,
    /// Rolling digest after the final ordered item.
    pub inventory_digest: [u8; 32],
}

/// One immutable short-lived permit attempt for a sealed physical cleanup item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueVersionCleanupPermit {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Exact sealed inventory revision.
    pub inventory_sealed_revision: Revision,
    /// Stable item position in that inventory.
    pub item_index: u64,
    /// Strictly increasing attempt sequence for this item.
    pub attempt_sequence: u64,
    /// Complete provider-verifiable permit generated by the current authority.
    pub permit: RemovalPermit,
}

/// One immutable provider-confirmed tombstone completion for a cleanup item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteVersionCleanupItem {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Exact sealed inventory revision.
    pub inventory_sealed_revision: Revision,
    /// Stable item position in that inventory.
    pub item_index: u64,
    /// Exact committed permit attempt accepted by the provider.
    pub permit_attempt_sequence: u64,
    /// Provider's exact durable tombstone receipt.
    pub receipt: TombstoneReceipt,
    /// mTLS-authenticated node that reported the provider result.
    pub reporter_node_id: NodeId,
    /// Current process incarnation of the reporting node.
    pub reporter_incarnation: u64,
}

/// One immutable provider-confirmed physical reclamation for a completed cleanup item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmVersionCleanupReclamation {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Stable item position in the sealed inventory.
    pub item_index: u64,
    /// Provider's exact durable physical-unlink receipt.
    pub receipt: ReclamationReceipt,
    /// mTLS-authenticated node that reported the provider result.
    pub reporter_node_id: NodeId,
    /// Current process incarnation of the reporting node.
    pub reporter_incarnation: u64,
}

/// Namespace object kind stored as a closed integer contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceObjectKind {
    /// Directory that may contain child objects.
    Folder,
    /// Regular file metadata record.
    File,
}

/// New folder or file beneath an existing directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateObject {
    /// Object identity.
    pub object_id: ObjectId,
    /// Owning volume.
    pub volume_id: VolumeId,
    /// Existing parent folder.
    pub parent_object_id: ObjectId,
    /// File or folder.
    pub kind: NamespaceObjectKind,
    /// Display/canonical child name.
    pub name: RecordName,
    /// Immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Non-empty user/group owner principals.
    pub owners: BoundedItems<PrincipalId>,
}

/// Complete atomic owner-set replacement for one logical object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaceObjectOwners {
    /// Existing active folder or file, including a volume root.
    pub object_id: ObjectId,
    /// Fresh immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Complete non-empty set of active user/group owners after replacement.
    pub owners: BoundedItems<PrincipalId>,
}

/// Explicit allow-only inheritance boundary on one folder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetObjectGrantInheritance {
    /// Existing active folder, including a volume root.
    pub object_id: ObjectId,
    /// Whether grants from parent objects, the volume and global scope stop here.
    pub stop_parent_grants: bool,
}

/// One descriptive tag definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTag {
    /// Stable tag identity.
    pub tag_id: TagId,
    /// Human-facing and canonicalised tag name.
    pub name: RecordName,
}

/// Closed entities that may carry descriptive tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagTarget {
    /// User or group principal.
    Principal(PrincipalId),
    /// Folder or file logical object.
    Object(ObjectId),
}

/// One descriptive tag attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachTag {
    /// Existing tag.
    pub tag_id: TagId,
    /// Existing active target.
    pub target: TagTarget,
}

/// One descriptive tag detachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachTag {
    /// Existing tag.
    pub tag_id: TagId,
    /// Exact currently attached target.
    pub target: TagTarget,
}

/// Permission scope with no ambiguous nullable combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionScope {
    /// All present and future volumes/objects.
    Global,
    /// One volume and its objects.
    Volume(VolumeId),
    /// One exact object within its volume.
    Object {
        /// Containing volume.
        volume_id: VolumeId,
        /// Exact object.
        object_id: ObjectId,
    },
}

/// Allow-only inheritance behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantInheritance {
    /// Exact scoped object/volume only.
    Object,
    /// Descendants only.
    Descendants,
    /// Scoped object/volume and descendants.
    ObjectAndDescendants,
}

/// New allow-only permission grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantPermission {
    /// Grant identity.
    pub grant_id: GrantId,
    /// User or group receiving the rights.
    pub subject_principal_id: PrincipalId,
    /// Global, volume or object scope.
    pub scope: PermissionScope,
    /// Protocol-neutral non-empty rights.
    pub rights: Rights,
    /// Descendant behaviour.
    pub inheritance: GrantInheritance,
    /// Inclusive validity start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive validity end.
    pub valid_until: Option<UnixMicros>,
    /// Optional self-activation requirement.
    pub activation_policy_id: Option<ActivationPolicyId>,
}

/// Atomic activation policy plus the only grant that initially references it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantPermissionWithActivation {
    /// New bounded activation policy.
    pub policy: CreateActivationPolicy,
    /// New grant whose activation policy must equal `policy.policy_id`.
    pub grant: GrantPermission,
}

/// Audited revocation of one exact active allow grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokePermissionGrant {
    /// Exact active grant to revoke.
    pub grant_id: GrantId,
    /// Non-blank bounded human audit reason.
    pub reason: String,
}

/// One user's time-bounded activation of a pre-authorised grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateGrant {
    /// Activation record identity.
    pub activation_id: ActivationId,
    /// User receiving active rights.
    pub principal_id: PrincipalId,
    /// Exact grant being activated.
    pub grant_id: GrantId,
    /// Exact policy expected on the grant.
    pub policy_id: ActivationPolicyId,
    /// Audit reason supplied by the user.
    pub reason: String,
    /// Requested duration.
    pub duration: DurationMicros,
    /// Current session expiry.
    pub session_expires_at: UnixMicros,
    /// Current authentication assurance.
    pub assurance: AssuranceLevel,
    /// Digest binding the authentication ceremony/session.
    pub authentication_digest: [u8; 32],
}

/// One user's time-bounded activation of a pre-authorised group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateGroup {
    /// Activation record identity.
    pub activation_id: ActivationId,
    /// User receiving active group-derived rights.
    pub principal_id: PrincipalId,
    /// Exact group being activated.
    pub group_id: GroupId,
    /// Exact policy expected on the group.
    pub policy_id: ActivationPolicyId,
    /// Bounded audit reason supplied by the user.
    pub reason: String,
    /// Requested duration.
    pub duration: DurationMicros,
    /// Current session expiry.
    pub session_expires_at: UnixMicros,
    /// Current authentication assurance.
    pub assurance: AssuranceLevel,
    /// Digest binding the authentication ceremony/session.
    pub authentication_digest: [u8; 32],
}

/// Audited revocation of one exact activation owned by one exact user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeAccessActivation {
    /// Exact current activation to revoke.
    pub activation_id: ActivationId,
    /// Expected owning user, preventing confused-deputy revocation.
    pub principal_id: PrincipalId,
    /// Non-blank bounded human audit reason.
    pub reason: String,
}

/// One typed, protocol-neutral authentication method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAuthenticationMethod {
    /// Stable common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// User who owns and may authenticate with the method.
    pub principal_id: PrincipalId,
    /// Human-readable bounded method label.
    pub label: String,
    /// Non-empty protocol-compatibility bitset: HTTPS 1, headless API 2, SMB 4.
    pub service_scope: u8,
    /// Exclusive method expiry, or no automatic expiry.
    pub expires_at: Option<UnixMicros>,
    /// Exactly one credential family and its bounded typed evidence.
    pub credential: NewAuthenticationCredential,
}

/// Credential evidence admitted atomically with its common method.
#[derive(Clone, Eq, PartialEq)]
pub enum NewAuthenticationCredential {
    /// One `WebAuthn` public-key credential.
    Passkey {
        /// Opaque authenticator credential identity.
        credential_id: Vec<u8>,
        /// Accepted COSE public-key algorithm identifier.
        public_key_algorithm: i32,
        /// Canonical public-key bytes interpreted by the passkey verifier.
        public_key: Vec<u8>,
        /// Initial authenticator signature counter.
        signature_counter: u64,
        /// Optional authenticator GUID/AAGUID.
        authenticator_guid: Option<[u8; 16]>,
        /// Bounded authenticator transport bitset.
        transports: u8,
        /// Whether the credential is eligible for backup/synchronisation.
        backup_eligible: bool,
        /// Whether it is currently reported as backed up.
        backup_state: bool,
    },
    /// One encrypted TOTP seed and its exact verification parameters.
    Totp {
        /// Authenticated-encryption envelope; never plaintext seed material.
        secret_ciphertext: Vec<u8>,
        /// Accepted hash algorithm.
        algorithm: TotpAlgorithm,
        /// Decimal code digits.
        digits: u8,
        /// Timestep in seconds.
        period_seconds: u16,
        /// Number of adjacent time steps accepted by policy.
        accepted_step_window: u8,
    },
    /// One non-empty bounded set of independently single-use recovery codes.
    RecoveryCodes {
        /// Digest-only code records.
        codes: BoundedItems<NewRecoveryCode>,
    },
    /// One login-capable scoped API key.
    ApiKey {
        /// Stable public identity; the secret itself remains outside metadata.
        key_id: ApiKeyId,
        /// Digest of the high-entropy secret key.
        key_digest: [u8; 32],
        /// Authenticated-encryption envelope for SMB proof verification, when scoped for SMB.
        smb_verifier_ciphertext: Option<Vec<u8>>,
        /// Non-empty, server-defined least-privilege capability bitset.
        scopes: u64,
        /// Inclusive first instant at which authentication is accepted.
        valid_from: UnixMicros,
    },
}

impl fmt::Debug for NewAuthenticationCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passkey {
                credential_id,
                public_key_algorithm,
                public_key,
                signature_counter,
                authenticator_guid,
                transports,
                backup_eligible,
                backup_state,
            } => formatter
                .debug_struct("Passkey")
                .field("credential_id_length", &credential_id.len())
                .field("public_key_algorithm", public_key_algorithm)
                .field("public_key_length", &public_key.len())
                .field("signature_counter", signature_counter)
                .field("authenticator_guid", authenticator_guid)
                .field("transports", transports)
                .field("backup_eligible", backup_eligible)
                .field("backup_state", backup_state)
                .finish(),
            Self::Totp {
                secret_ciphertext,
                algorithm,
                digits,
                period_seconds,
                accepted_step_window,
            } => formatter
                .debug_struct("Totp")
                .field("secret_ciphertext", &"[REDACTED]")
                .field("ciphertext_length", &secret_ciphertext.len())
                .field("algorithm", algorithm)
                .field("digits", digits)
                .field("period_seconds", period_seconds)
                .field("accepted_step_window", accepted_step_window)
                .finish(),
            Self::RecoveryCodes { codes } => formatter
                .debug_struct("RecoveryCodes")
                .field("code_count", &codes.len())
                .field("code_digests", &"[REDACTED]")
                .finish(),
            Self::ApiKey {
                key_id,
                scopes,
                valid_from,
                smb_verifier_ciphertext,
                ..
            } => formatter
                .debug_struct("ApiKey")
                .field("key_id", key_id)
                .field("key_digest", &"[REDACTED]")
                .field(
                    "smb_verifier_ciphertext",
                    &smb_verifier_ciphertext.as_ref().map(Vec::len),
                )
                .field("scopes", scopes)
                .field("valid_from", valid_from)
                .finish(),
        }
    }
}

/// Accepted TOTP hash algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 for interoperability with existing authenticators.
    Sha1 = 1,
    /// HMAC-SHA-256.
    Sha256 = 2,
    /// HMAC-SHA-512.
    Sha512 = 3,
}

/// One digest-only single-use recovery code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewRecoveryCode {
    /// Stable public code identity.
    pub code_id: RecoveryCodeId,
    /// Digest of the high-entropy code; plaintext never enters metadata.
    pub code_digest: [u8; 32],
}

/// Immediate revocation of one exact authentication method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeAuthenticationMethod {
    /// Exact method to revoke.
    pub method_id: AuthenticationMethodId,
    /// Expected owner, preventing confused-deputy revocation.
    pub principal_id: PrincipalId,
    /// Non-blank bounded audit reason.
    pub reason: String,
}

/// One complete immutable replacement for a service/operation authentication policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigureAuthenticationPolicy {
    /// Stable identity allocated to this immutable policy revision.
    pub policy_id: AuthenticationPolicyId,
    /// Connector family governed by the policy.
    pub service: AuthenticationService,
    /// Operation family governed by the policy.
    pub operation_class: AuthenticationOperationClass,
    /// Exact currently selected policy sequence.
    pub expected_policy_sequence: u64,
    /// Method classes which may contribute to the authentication proof.
    pub allowed_factor_classes: AuthenticationFactorClasses,
    /// Minimum number of distinct current methods required.
    pub minimum_factor_count: u8,
    /// Maximum lifetime of a session used for this operation family.
    pub maximum_session_duration: DurationMicros,
    /// Maximum age of the latest factor when recent step-up is required.
    pub maximum_step_up_age: Option<DurationMicros>,
}

/// Accepted authentication ceremony converted into a mesh-wide bounded session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueAuthenticationSession {
    /// Stable session identity.
    pub session_id: SessionId,
    /// User authenticated by the ceremony.
    pub principal_id: PrincipalId,
    /// Digest of the bearer token; raw tokens never enter authoritative metadata.
    pub token_digest: [u8; 32],
    /// Digest of the independently presented CSRF token for browser mutations.
    pub csrf_digest: [u8; 32],
    /// Optional bounded device/session label selected by the user.
    pub client_label: SessionClientLabel,
    /// Whether the browser may persist the cookie beyond the current browser session.
    pub persistent_cookie: bool,
    /// Connector family for which this session was established.
    pub service: AuthenticationService,
    /// Exact current method evidence accepted by the authentication ceremony.
    pub factors: BoundedItems<SessionAuthenticationFactor>,
    /// Exclusive absolute expiry.
    pub expires_at: UnixMicros,
}

/// Atomic current-session replacement after one fresh additional factor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepUpAuthenticationSession {
    /// Exact live session whose retained primary proof is carried into the replacement.
    pub source_session_id: SessionId,
    /// Stable replacement session identity.
    pub replacement_session_id: SessionId,
    /// User authenticated by the source session.
    pub principal_id: PrincipalId,
    /// Digest of the replacement bearer token.
    pub token_digest: [u8; 32],
    /// Digest of the replacement CSRF token.
    pub csrf_digest: [u8; 32],
    /// Fresh TOTP or recovery-code evidence accepted by the step-up ceremony.
    pub additional_factor: SessionAuthenticationFactor,
    /// Exclusive absolute replacement expiry.
    pub expires_at: UnixMicros,
}

/// Exact public three-state session-label intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionClientLabel {
    /// The property was omitted.
    Missing,
    /// The property was explicitly null.
    Null,
    /// The property supplied one non-empty label.
    Value(String),
}

/// Exact typed credential evidence accepted as one session factor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAuthenticationFactor {
    /// Accepted `WebAuthn` assertion and its monotonic authenticator state.
    Passkey {
        /// Common authentication-method identity.
        method_id: AuthenticationMethodId,
        /// Exact credential generation observed by the verifier.
        credential_generation: u64,
        /// Exact method revision observed by the verifier.
        method_revision: Revision,
        /// Credential identity whose assertion was accepted.
        credential_id: Vec<u8>,
        /// Signature counter reported by the accepted assertion.
        signature_counter: u64,
        /// Current authenticator backup-state flag.
        backup_state: bool,
    },
    /// Accepted TOTP code bound to one time step.
    Totp {
        /// Common authentication-method identity.
        method_id: AuthenticationMethodId,
        /// Exact credential generation observed by the verifier.
        credential_generation: u64,
        /// Exact method revision observed by the verifier.
        method_revision: Revision,
        /// Time step whose code was accepted; must advance monotonically.
        accepted_step: u64,
    },
    /// Accepted single-use recovery code.
    RecoveryCode {
        /// Common authentication-method identity.
        method_id: AuthenticationMethodId,
        /// Exact credential generation observed by the verifier.
        credential_generation: u64,
        /// Exact method revision observed by the verifier.
        method_revision: Revision,
        /// Exact code record consumed by this transaction.
        code_id: RecoveryCodeId,
    },
    /// Accepted scoped API key.
    ApiKey {
        /// Common authentication-method identity.
        method_id: AuthenticationMethodId,
        /// Exact credential generation observed by the verifier.
        credential_generation: u64,
        /// Exact method revision observed by the verifier.
        method_revision: Revision,
        /// Public key identity resolved by the verifier.
        key_id: ApiKeyId,
    },
}

impl SessionAuthenticationFactor {
    /// Returns the common method identity independently of credential family.
    #[must_use]
    pub const fn method_id(&self) -> AuthenticationMethodId {
        match self {
            Self::Passkey { method_id, .. }
            | Self::Totp { method_id, .. }
            | Self::RecoveryCode { method_id, .. }
            | Self::ApiKey { method_id, .. } => *method_id,
        }
    }

    /// Returns the exact credential generation observed by the verifier.
    #[must_use]
    pub const fn credential_generation(&self) -> u64 {
        match self {
            Self::Passkey {
                credential_generation,
                ..
            }
            | Self::Totp {
                credential_generation,
                ..
            }
            | Self::RecoveryCode {
                credential_generation,
                ..
            }
            | Self::ApiKey {
                credential_generation,
                ..
            } => *credential_generation,
        }
    }

    /// Returns the exact method revision observed by the verifier.
    #[must_use]
    pub const fn method_revision(&self) -> Revision {
        match self {
            Self::Passkey {
                method_revision, ..
            }
            | Self::Totp {
                method_revision, ..
            }
            | Self::RecoveryCode {
                method_revision, ..
            }
            | Self::ApiKey {
                method_revision, ..
            } => *method_revision,
        }
    }
}

/// Immediate revocation of one exact session belonging to one exact user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeAuthenticationSession {
    /// Exact session to revoke.
    pub session_id: SessionId,
    /// Expected owning user, preventing confused-deputy revocation.
    pub principal_id: PrincipalId,
}

/// New desired component instance and its first configuration revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateComponent {
    /// Component instance identity.
    pub instance_id: ComponentInstanceId,
    /// Stable capability contract kind from `meshspan-contracts`.
    pub component_kind: u8,
    /// Display/canonical instance name.
    pub name: RecordName,
    /// Stable lowercase implementation identifier.
    pub implementation_id: String,
    /// Contract major version.
    pub contract_major: u16,
    /// Contract minor version.
    pub contract_minor: u16,
    /// Configuration schema version.
    pub schema_version: u32,
    /// Bounded canonical non-secret configuration.
    pub canonical_configuration: Vec<u8>,
    /// Digest of the canonical configuration.
    pub configuration_digest: [u8; 32],
}

impl CreateComponent {
    /// Validates one component declaration at a caller-selected configuration byte bound.
    pub(crate) fn validate_shape(
        &self,
        maximum_configuration_bytes: usize,
    ) -> Result<(), RepositoryCommandError> {
        let identifier_is_valid = !self.implementation_id.is_empty()
            && self.implementation_id.len() <= 80
            && self
                .implementation_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.implementation_id.starts_with('-')
            && !self.implementation_id.ends_with('-');
        let configuration_digest: [u8; 32] = Sha256::digest(&self.canonical_configuration).into();
        if !(1..=10).contains(&self.component_kind)
            || self.contract_major == 0
            || self.schema_version == 0
            || self.canonical_configuration.len() > maximum_configuration_bytes
            || configuration_digest != self.configuration_digest
            || !identifier_is_valid
        {
            Err(RepositoryCommandError::InvalidComponent)
        } else {
            Ok(())
        }
    }
}

/// New desired configuration revision for an existing component instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureComponent {
    /// Existing component instance.
    pub instance_id: ComponentInstanceId,
    /// Configuration schema version.
    pub schema_version: u32,
    /// Bounded canonical non-secret configuration.
    pub canonical_configuration: Vec<u8>,
    /// Digest of the canonical configuration.
    pub configuration_digest: [u8; 32],
}

/// Desired placement/attachment of a component instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignComponent {
    /// Existing component instance.
    pub instance_id: ComponentInstanceId,
    /// Closed assignment family, such as mesh, host, node or fault group.
    pub assignment_kind: u8,
    /// Non-nil identity interpreted only under `assignment_kind`.
    pub assignment_id: [u8; 16],
    /// Closed desired assignment state.
    pub desired_state: u8,
}

/// Authoritative capacity ceiling for one registered storage target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageUsageLimit {
    /// Percentage of the target's measured capacity.
    Percent(u8),
    /// Fixed maximum physical bytes owned by `MeshSpan`.
    Bytes(u64),
}

impl StorageUsageLimit {
    /// Validates a value received from a command or wire boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero, percentages above 100 and zero-byte ceilings.
    pub const fn validate(self) -> Result<Self, RepositoryCommandError> {
        match self {
            Self::Percent(value) if value > 0 && value <= 100 => Ok(self),
            Self::Bytes(value) if value > 0 => Ok(self),
            Self::Percent(_) | Self::Bytes(_) => {
                Err(RepositoryCommandError::InvalidStorageUsageLimit)
            }
        }
    }
}

/// First authoritative generation of one locally capability-probed folder target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterStorageTarget {
    /// Stable target identity independent of the local path.
    pub target_id: TargetId,
    /// Node that exclusively owns this generation.
    pub node_id: NodeId,
    /// Expected host of the owning node, binding the physical failure boundary.
    pub host_id: HostId,
    /// New provider component atomically selected for this target.
    pub provider: CreateComponent,
    /// Human-readable target name; never a path or identity.
    pub name: RecordName,
    /// Initial positive authority-fenced marker generation.
    pub generation: u64,
    /// Digest of the exact durable marker written beneath the provider folder.
    pub marker_fingerprint: [u8; 32],
    /// Optional observed backing-device identity evidence.
    pub backing_device_fingerprint: Option<[u8; 32]>,
    /// Optional observed filesystem identity evidence.
    pub filesystem_fingerprint: Option<[u8; 32]>,
    /// MeshSpan-owned physical capacity ceiling.
    pub usage_limit: StorageUsageLimit,
}

/// One administrator-defined shared machine-failure boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateFaultGroup {
    /// Stable identity of the class, such as building, power source or hypervisor.
    pub class_id: FaultGroupClassId,
    /// Human-readable class name, reused exactly by every group in this class.
    pub class_name: RecordName,
    /// Stable identity of this concrete shared-failure group.
    pub group_id: FaultGroupId,
    /// Human-readable group name within the class.
    pub group_name: RecordName,
}

/// Desired membership of one machine in one shared-failure group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetHostFaultGroupMembership {
    /// Existing shared-failure group.
    pub group_id: FaultGroupId,
    /// Existing non-retired machine.
    pub host_id: HostId,
    /// `true` to add the machine or `false` to remove it.
    pub present: bool,
}

/// One named simultaneous failure scenario within a protection policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionScenarioConfiguration {
    /// Stable scenario identity retained in acknowledgement evidence.
    pub scenario_id: ProtectionScenarioId,
    /// Human-readable scenario name.
    pub name: RecordName,
    /// Non-empty bounded set of fault classes and simultaneous failure counts.
    pub scenario: FailureScenario,
}

/// One immutable data-survival policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProtectionPolicy {
    /// Stable identity of this policy revision.
    pub policy_id: ProtectionPolicyId,
    /// Human-readable policy name.
    pub name: RecordName,
    /// Non-empty ordered scenarios which must each be survived.
    pub scenarios: BoundedItems<ProtectionScenarioConfiguration>,
}

/// Volume-wide selection of one existing immutable survival policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignVolumeProtectionPolicy {
    /// Existing volume receiving the policy.
    pub volume_id: VolumeId,
    /// Existing active protection policy.
    pub policy_id: ProtectionPolicyId,
}

/// One administrator-defined availability locality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAvailabilityCell {
    /// Stable availability-cell identity.
    pub cell_id: AvailabilityCellId,
    /// Human-readable cell name.
    pub name: RecordName,
    /// Optional presentation parent; placement still evaluates explicit membership.
    pub parent_cell_id: Option<AvailabilityCellId>,
}

/// Desired membership of one machine in one availability cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetHostAvailabilityCellMembership {
    /// Existing availability cell.
    pub cell_id: AvailabilityCellId,
    /// Existing non-retired machine.
    pub host_id: HostId,
    /// `true` to add the machine or `false` to remove it.
    pub present: bool,
}

/// Desired membership of one storage target in one availability cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetTargetAvailabilityCellMembership {
    /// Existing availability cell.
    pub cell_id: AvailabilityCellId,
    /// Existing non-retired storage target.
    pub target_id: TargetId,
    /// `true` to add the target or `false` to remove it.
    pub present: bool,
}

/// One complete-local placement requirement inside an availability cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalityRequirementConfiguration {
    /// Stable requirement identity retained in placement and repair evidence.
    pub requirement_id: LocalityRequirementId,
    /// Cell which must independently reconstruct the selected version.
    pub cell_id: AvailabilityCellId,
    /// Optional failure-survival promise evaluated using only targets inside the cell.
    pub local_protection_policy_id: Option<ProtectionPolicyId>,
}

/// One immutable desired-locality policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateLocalityPolicy {
    /// Stable policy identity.
    pub policy_id: LocalityPolicyId,
    /// Human-readable policy name.
    pub name: RecordName,
    /// Optional maximum lag before incomplete locality becomes urgent repair debt.
    pub maximum_lag: Option<DurationMicros>,
    /// Non-empty ordered set of cells which each require a complete local copy.
    pub requirements: BoundedItems<LocalityRequirementConfiguration>,
}

/// Volume-wide selection of one existing immutable locality policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignVolumeLocalityPolicy {
    /// Existing volume receiving the inherited default.
    pub volume_id: VolumeId,
    /// Existing active locality policy.
    pub policy_id: LocalityPolicyId,
}

/// Whether a write acknowledges local durability or waits for a converged strong barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcknowledgementConsistencyClass {
    /// Commit a durable local branch and reconcile wider promises automatically.
    Eventual = 1,
    /// Wait for every required predicate and the globally converged metadata commit.
    Strong = 2,
}

/// Explicit outcome when a strong acknowledgement cannot meet its deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StrongFallbackMode {
    /// Retain the operation as pending for later completion.
    RemainPending = 1,
    /// Return failure at the deadline while retaining safe staged work.
    FailAtDeadline = 2,
    /// Explicitly permit a weaker eventual branch receipt at the deadline.
    Eventual = 3,
}

/// How one cell participates in acknowledgement and placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcknowledgementCellRole {
    /// This cell's predicates must complete before a strong acknowledgement.
    RequiredBeforeCommit = 1,
    /// Copy here automatically without delaying acknowledgement.
    Eventual = 2,
    /// Never place this policy's content in this cell.
    Excluded = 3,
}

/// One cell-specific acknowledgement predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgementCellRequirement {
    /// Availability cell receiving this role.
    pub cell_id: AvailabilityCellId,
    /// Whether the cell blocks, follows, or is excluded from placement.
    pub role: AcknowledgementCellRole,
    /// Optional required durable target count within the cell.
    pub minimum_durable_targets: Option<u16>,
    /// Optional required distinct machine count within the cell.
    pub minimum_distinct_nodes: Option<u16>,
    /// Optional local failure-survival promise.
    pub local_protection_policy_id: Option<ProtectionPolicyId>,
}

/// One immutable write-acknowledgement policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAcknowledgementPolicy {
    /// Stable policy identity.
    pub policy_id: AcknowledgementPolicyId,
    /// Human-readable policy name.
    pub name: RecordName,
    /// Availability-first or strong publication semantics.
    pub consistency: AcknowledgementConsistencyClass,
    /// Minimum durable targets before any acknowledgement.
    pub minimum_durable_targets: u16,
    /// Minimum distinct machines represented by those targets.
    pub minimum_distinct_nodes: u16,
    /// Optional deadline used only by strong policies.
    pub strong_wait: Option<DurationMicros>,
    /// Explicit result when a strong deadline cannot be met.
    pub fallback: StrongFallbackMode,
    /// Protection scenarios that must be proved before acknowledgement.
    pub required_scenarios: BoundedItems<ProtectionScenarioId>,
    /// Per-cell placement and acknowledgement roles.
    pub cells: BoundedItems<AcknowledgementCellRequirement>,
}

/// Volume-wide selection of one existing immutable acknowledgement policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignVolumeAcknowledgementPolicy {
    /// Existing volume receiving the inherited default.
    pub volume_id: VolumeId,
    /// Existing active acknowledgement policy.
    pub policy_id: AcknowledgementPolicyId,
}

/// One exact deduplicated maintenance job admitted to authoritative scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueMaintenanceWork {
    /// Stable job identity returned by every exact deduplication replay.
    pub work_id: WorkId,
    /// Semantic identity shared by findings that require the same physical outcome.
    pub deduplication_key: [u8; 32],
    /// Closed, generation-bound repair, scrub, drain, rebalance or return subject.
    pub subject: WorkSubject,
    /// Current safety and demand evidence used to derive queue priority.
    pub signals: WorkSignals,
    /// Maximum bytes retained while one attempt executes this work.
    pub demand: WorkDemand,
    /// Earliest authority-agreed instant at which a worker may claim this job.
    pub next_attempt_at: UnixMicros,
}

/// Atomic transition from writable target to durable resumable evacuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginStorageTargetDrain {
    /// Exact target-drain work; its subject must name the same live target generation.
    pub work: QueueMaintenanceWork,
    /// Allows safe removal once bytes remain recoverable even if desired protection is temporarily
    /// below policy. This never permits data loss.
    pub allow_temporary_degraded: bool,
    /// Requests physical cleanup only after authority commits safe-to-detach evidence.
    pub cleanup_requested: bool,
}

/// Authoritative node or fault-group placement fence composed from ordinary target drains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginStorageScopeDrain {
    /// Stable drain identity used to derive idempotent child target work.
    pub drain_id: WorkId,
    /// Exact node incarnation or fault group to drain; target scope is rejected.
    pub scope: DrainScope,
    /// Allows physical removal after recoverability is proved despite temporary policy debt.
    pub allow_temporary_degraded: bool,
    /// Requests eventual physical cleanup for every child target after safe proof.
    pub cleanup_requested: bool,
}

/// Exact transition from evacuated node to consensus-membership retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceStorageNodeDrainMembership {
    /// Existing live node drain.
    pub drain_id: WorkId,
    /// Exact node bound by that drain.
    pub node_id: NodeId,
    /// Incarnation captured when the drain began.
    pub node_incarnation: u64,
}

/// Terminal proof request for one fully evacuated and, when applicable, consensus-retired scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteStorageScopeDrain {
    /// Existing live scope drain.
    pub drain_id: WorkId,
    /// Digest over the exact scope, every terminal child proof and current membership exclusion.
    pub safety_evidence_digest: [u8; 32],
}

/// One snapshotted gateway's claim-bound proof that a draining target has no current routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestStorageTargetDrain {
    /// Drain job whose participant snapshot contains this gateway.
    pub work_id: WorkId,
    /// Live claim generation fencing this evacuation attempt.
    pub claim_generation: u64,
    /// Exact gateway producing the local catalogue proof.
    pub worker_node_id: NodeId,
    /// Current gateway incarnation; stale processes cannot attest.
    pub worker_incarnation: u64,
    /// Unpredictable claim fence committed by this worker.
    pub fence: u64,
    /// Draining target bound into the work subject.
    pub target_id: TargetId,
    /// Exact target incarnation being removed from authority.
    pub target_generation: u64,
    /// Metadata revision caught up before the gateway performed its empty-catalogue scan.
    pub observed_authority_revision: Revision,
    /// Canonical digest proving an empty current-route catalogue for this target generation.
    pub empty_catalogue_digest: [u8; 32],
}

/// Stable keyset position in a volume's protected-stripe catalogue.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RebalanceScanCursor {
    /// Publication owning the last scanned stripe.
    pub publication_operation_id: OperationId,
    /// Zero-based stripe index inside that publication.
    pub stripe_index: u64,
}

/// One claim-bound, bounded and restart-safe volume rebalance scan checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitRebalanceScanPage {
    /// Existing claimed rebalance job.
    pub work_id: WorkId,
    /// Live claim generation fencing this attempt.
    pub claim_generation: u64,
    /// Exact worker committing the checkpoint.
    pub worker_node_id: NodeId,
    /// Current worker incarnation.
    pub worker_incarnation: u64,
    /// Unpredictable live claim fence.
    pub fence: u64,
    /// Volume bound into the rebalance subject.
    pub volume_id: VolumeId,
    /// Exact configuration revision whose policy the scan evaluated.
    pub topology_revision: Revision,
    /// Previously committed cursor, or `None` for the first page.
    pub after: Option<RebalanceScanCursor>,
    /// Last scanned cursor when another page remains; `None` makes this the terminal page.
    pub next: Option<RebalanceScanCursor>,
    /// Number of complete stripes examined in this page.
    pub scanned_stripes: u16,
    /// Number of strict improvements admitted as repair work from this page.
    pub queued_repairs: u16,
    /// Newer configuration revision terminating obsolete work without scanning stale policy.
    pub superseded_by_revision: Option<Revision>,
    /// Canonical digest of the exact ordered page and its selected improvements.
    pub page_digest: [u8; 32],
}

/// One new fenced execution attempt over a durable maintenance job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimMaintenanceWork {
    /// Existing ready job.
    pub work_id: WorkId,
    /// Worker authenticated by the private node boundary.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Next monotonically increasing claim generation.
    pub claim_generation: u64,
    /// Positive unpredictable fence carried by every work result.
    pub fence: u64,
    /// Short-lived authoritative lease end.
    pub lease_expires_at: UnixMicros,
}

/// Extension of one still-current maintenance claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewMaintenanceWork {
    /// Claimed job.
    pub work_id: WorkId,
    /// Exact current claim generation.
    pub claim_generation: u64,
    /// Worker owning the claim.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence.
    pub fence: u64,
    /// New bounded lease end, later than the current lease.
    pub lease_expires_at: UnixMicros,
}

/// Terminal evidence or explicit retry from one still-current maintenance claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteMaintenanceWork {
    /// Claimed job.
    pub work_id: WorkId,
    /// Exact current claim generation.
    pub claim_generation: u64,
    /// Worker owning the claim.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence.
    pub fence: u64,
    /// Validated authoritative effect or bounded retry evidence.
    pub outcome: MaintenanceWorkCompletion,
}

/// Exact result of one fenced maintenance attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceWorkCompletion {
    /// A separately committed domain operation proves the job's requested effect.
    Succeeded {
        /// Exact idempotency identity of the authoritative effect.
        effect_operation_id: OperationId,
        /// Revision committed by that operation.
        effect_revision: Revision,
        /// Exact committed operation-result digest.
        effect_result_digest: [u8; 32],
    },
    /// No safety claim is made; the job returns to the queue after a bounded delay.
    Retry {
        /// Digest of typed, redacted attempt failure evidence.
        failure_digest: [u8; 32],
        /// Future authority-agreed instant for another claim.
        retry_at: UnixMicros,
    },
    /// Bounded progress was durably checkpointed; another claim should continue the same job.
    Continue {
        /// Digest of the exact durable progress checkpoint.
        progress_digest: [u8; 32],
        /// Future authority-agreed instant for the next bounded claim.
        retry_at: UnixMicros,
    },
}

/// One copy-on-write shard replacement committed under a live repair claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitShardRepair {
    /// Existing claimed repair job.
    pub work_id: WorkId,
    /// Exact current claim generation.
    pub claim_generation: u64,
    /// Worker owning the claim.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live claim fence.
    pub fence: u64,
    /// Volume bound into the repair subject.
    pub volume_id: VolumeId,
    /// Immutable manifest bound into the repair subject.
    pub manifest_id: ContentManifestId,
    /// Compare-and-swap generation of the active stripe-location catalogue.
    pub source_layout_generation: u64,
    /// Last durable receipt for the location being replaced.
    pub source_receipt: ShardReceipt,
    /// New provider-confirmed receipt for the same immutable shard bytes.
    pub replacement_receipt: ShardReceipt,
}

/// Durable summary of one complete, independently verified storage-target scrub pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitScrubPass {
    /// Existing claimed scrub job.
    pub work_id: WorkId,
    /// Exact current claim generation.
    pub claim_generation: u64,
    /// Worker owning the claim.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live claim fence.
    pub fence: u64,
    /// Storage target bound into the scrub subject.
    pub target_id: TargetId,
    /// Exact target generation inspected by the pass.
    pub target_generation: u64,
    /// Total observations across every bounded page in the pass.
    pub observation_count: u64,
    /// Total bytes read and independently digested by healthy or corrupt observations.
    pub verified_bytes: u64,
    /// Observations whose bytes exactly matched committed inventory.
    pub healthy_count: u64,
    /// Committed inventory entries whose bytes were absent.
    pub missing_count: u64,
    /// Present bytes that contradicted committed length or digest.
    pub corrupt_count: u64,
    /// Entries for which local IO could not produce trustworthy evidence.
    pub unreadable_count: u64,
    /// Locally discovered bytes with no corresponding committed inventory entry.
    pub unexpected_count: u64,
    /// Entries deliberately postponed by a bounded resource decision.
    pub deferred_count: u64,
    /// Canonical digest covering target identity and every ordered scrub observation.
    pub evidence_digest: [u8; 32],
}

/// Durable summary of one returning target's complete inventory-verification pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitTargetReconciliation {
    /// Existing claimed reconciliation job.
    pub work_id: WorkId,
    /// Exact current claim generation.
    pub claim_generation: u64,
    /// Worker owning the claim.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live claim fence.
    pub fence: u64,
    /// Returning storage target bound into the reconciliation subject.
    pub target_id: TargetId,
    /// Exact marker generation inspected by the pass.
    pub target_generation: u64,
    /// Total observations across every bounded page in the pass.
    pub observation_count: u64,
    /// Total bytes read and independently digested by healthy or corrupt observations.
    pub verified_bytes: u64,
    /// Observations whose bytes exactly matched committed inventory.
    pub healthy_count: u64,
    /// Committed inventory entries whose bytes were absent.
    pub missing_count: u64,
    /// Present bytes that contradicted committed length or digest.
    pub corrupt_count: u64,
    /// Entries for which local IO could not produce trustworthy evidence.
    pub unreadable_count: u64,
    /// Locally discovered bytes with no corresponding current catalogue route.
    pub unexpected_count: u64,
    /// Entries deliberately postponed by a bounded resource decision.
    pub deferred_count: u64,
    /// Canonical digest covering target identity and every ordered observation.
    pub evidence_digest: [u8; 32],
}

/// Explicit gateway selection for one SMB export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmbExportGatewaySelection {
    /// Every currently eligible gateway may publish the export.
    AllEligible,
    /// Only the non-empty bounded node set may publish the export.
    Selected(BoundedItems<NodeId>),
}

/// Replicated publication of one logical directory as an SMB share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishSmbExport {
    /// Stable export identity.
    pub export_id: SmbExportId,
    /// Volume containing the exported root.
    pub volume_id: VolumeId,
    /// Existing folder exposed as the share root.
    pub root_object_id: ObjectId,
    /// User-visible case-insensitive share name.
    pub share_name: RecordName,
    /// Eligible gateway policy.
    pub gateways: SmbExportGatewaySelection,
    /// Whether every post-tree packet must be encrypted.
    pub encryption_required: bool,
}

/// Audited withdrawal of one current SMB export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawSmbExport {
    /// Existing active export.
    pub export_id: SmbExportId,
    /// Non-blank bounded human audit reason.
    pub reason: String,
}

/// First public secret-wrapping-key generation for one exact active node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterNodeWrappingKey {
    /// Node which exclusively retains the matching private key.
    pub node_id: NodeId,
    /// Positive immutable key generation, initially one.
    pub generation: u64,
    /// Canonical X25519 public key bytes.
    pub public_key: [u8; 32],
    /// Domain-separated fingerprint of `public_key`.
    pub key_fingerprint: [u8; 32],
}

/// One encrypted secret generation plus its complete bounded recipient set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSecretGeneration {
    /// Authenticated secret ciphertext and immutable context.
    pub secret: EncryptedSecretParts,
    /// One authenticated data-key envelope for every exact authorised recipient.
    pub recipients: Vec<RecipientEnvelopeParts>,
}

/// Non-empty subset of roles a join grant may admit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinRoles(u8);

impl JoinRoles {
    /// Storage-capable daemon role.
    pub const STORAGE: u8 = 1;
    /// Access-gateway daemon role.
    pub const GATEWAY: u8 = 2;
    /// Node may join metadata replication as a learner and later become eligible for promotion.
    pub const METADATA_ELIGIBLE: u8 = 4;

    /// Validates one non-empty known role bitset.
    ///
    /// # Errors
    ///
    /// Rejects no roles or unknown role bits.
    pub const fn new(bits: u8) -> Result<Self, RepositoryCommandError> {
        if bits == 0 || bits & !7 != 0 {
            Err(RepositoryCommandError::InvalidJoinRoles)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns the canonical persisted bitset.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Reports whether this grant permits metadata learner enrolment.
    #[must_use]
    pub const fn metadata_eligible(self) -> bool {
        self.0 & Self::METADATA_ELIGIBLE != 0
    }
}

/// Stable construction errors for validated command values.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum RepositoryCommandError {
    /// Join-role bits are empty or unknown.
    #[error("join grant roles are invalid")]
    InvalidJoinRoles,
    /// Storage usage ceiling is zero or outside the percentage range.
    #[error("storage usage limit is invalid")]
    InvalidStorageUsageLimit,
    /// Component identity, contract or canonical configuration is invalid.
    #[error("component declaration is invalid")]
    InvalidComponent,
}

/// One administrator-created, digest-only pre-authorisation for node enrolment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueJoinGrant {
    /// Stable grant identity.
    pub join_grant_id: JoinGrantId,
    /// SHA-256 of the high-entropy code; raw code is returned once outside replicated state.
    pub secret_digest: [u8; 32],
    /// Non-empty roles this code may grant.
    pub allowed_roles: JoinRoles,
    /// Bounded total successful consumptions.
    pub maximum_uses: u16,
    /// Absolute expiry.
    pub expires_at: UnixMicros,
}

/// Certificate-bound node enrolment authorised solely by a valid join grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeJoinGrant {
    /// Exact grant being consumed.
    pub join_grant_id: JoinGrantId,
    /// Digest derived from the presented raw code.
    pub secret_digest: [u8; 32],
    /// Existing host or new host identity.
    pub host_id: HostId,
    /// Name supplied only when atomically creating the host.
    pub new_host_name: Option<RecordName>,
    /// Joining node identity generated by the daemon.
    pub node_id: NodeId,
    /// Human-facing node name.
    pub node_name: RecordName,
    /// Positive node-local incarnation.
    pub incarnation: u64,
    /// Requested subset of roles no broader than the grant.
    pub requested_roles: JoinRoles,
    /// Node-owned public secret-wrapping key staged until authenticated activation.
    pub wrapping_public_key: [u8; 32],
    /// Private QUIC endpoint staged until authenticated activation.
    pub private_endpoint: String,
    /// Signed public leaf certificate; the node private key never enters this command.
    pub certificate_der: Vec<u8>,
    /// Independently checked SHA-256 fingerprint of `certificate_der`.
    pub certificate_fingerprint: [u8; 32],
    /// Absolute certificate expiry.
    pub certificate_valid_until: UnixMicros,
}

/// Certificate-bound completion of one staged node admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateNode {
    /// Exact admitted node proven by the mTLS leaf and `NodeHello`.
    pub node_id: NodeId,
    /// Positive process incarnation proven during private negotiation.
    pub incarnation: u64,
    /// Exact staged endpoint proven reachable by the accepting gateway.
    pub private_endpoint: String,
    /// Digest of the validated roles, protocol versions, features and component support.
    pub capability_digest: [u8; 32],
}

/// Ed25519 signature and committed key identity for one resulting route state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteAttestation {
    /// Enrolled node whose active public key verifies the route.
    pub signer_node_id: NodeId,
    /// Exact signing-key generation.
    pub signer_generation: u64,
    /// Ed25519 signature over `ScopeRoute::signing_payload()`.
    pub signature: [u8; 64],
}

/// Public route-signing key registration; private signing material remains node-local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterRoutingSigner {
    /// Existing enrolled node.
    pub node_id: NodeId,
    /// Monotonic node key generation.
    pub generation: u64,
    /// Strict Ed25519 verifying key bytes.
    pub verifying_key: [u8; 32],
}

/// Another metadata partition addressable by catalogue routes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateMetadataPartition {
    /// New partition identity.
    pub partition_id: PartitionId,
    /// Human-facing partition name.
    pub name: RecordName,
    /// Closed partition kind defined by the schema.
    pub partition_kind: u8,
}

/// First active owner of a newly routed scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateScopeRoute {
    /// Permanent root group owning the delegation directory and initial route.
    pub root_partition_id: PartitionId,
    /// Exact delegatable operation-family/key-range scope.
    pub scope: DelegatedMetadataScope,
    /// Initial positive route epoch.
    pub routing_epoch: u64,
    /// Signature over the resulting active route.
    pub attestation: RouteAttestation,
}

/// Starts one fenced scope movement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginScopeHandoff {
    /// Existing routed scope.
    pub scope_id: ScopeId,
    /// Different destination partition.
    pub destination_partition_id: PartitionId,
    /// New route epoch.
    pub routing_epoch: u64,
    /// Capacity-relative membership and load evidence for the destination group.
    pub admission: DelegationAdmission,
    /// Signature over the resulting preparing route.
    pub attestation: RouteAttestation,
}

/// Installs one root-attested route projection into a non-root metadata group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallScopeRouteProjection {
    /// Exact root-owned route state; a child cannot construct or broaden it.
    pub route: meshspan_domain::RootDelegatedRoute,
    /// Root routing-key signature over `route.signing_payload()`.
    pub attestation: RouteAttestation,
}

/// Stops source writes at an exact revision and snapshot digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreezeScopeHandoff {
    /// Existing routed scope.
    pub scope_id: ScopeId,
    /// Current handoff route epoch.
    pub routing_epoch: u64,
    /// Exact source fence.
    pub evidence: HandoffEvidence,
    /// Signature over the resulting frozen route.
    pub attestation: RouteAttestation,
}

/// Makes the destination sole writer after exact fence installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivateScopeHandoff {
    /// Existing routed scope.
    pub scope_id: ScopeId,
    /// Expected destination partition.
    pub destination_partition_id: PartitionId,
    /// Current handoff route epoch.
    pub routing_epoch: u64,
    /// Exact installed source fence.
    pub evidence: HandoffEvidence,
    /// Signature over the resulting active route.
    pub attestation: RouteAttestation,
}

/// Cancels an unfinished handoff and restores source authority at a newer fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortScopeHandoff {
    /// Existing routed scope.
    pub scope_id: ScopeId,
    /// New route epoch used to fence all handoff messages.
    pub routing_epoch: u64,
    /// Stable non-zero audit reason code.
    pub reason_code: u32,
    /// Signature over the resulting active route.
    pub attestation: RouteAttestation,
}

macro_rules! digest_simple_record {
    ($type:ty, $tag:literal, |$value:ident, $digest:ident| $body:block) => {
        impl $type {
            fn update_digest(&self, digest: &mut CanonicalDigest) {
                let $value = self;
                let $digest = digest;
                $digest.bytes($tag);
                $body
            }
        }
    };
}

digest_simple_record!(BootstrapMesh, b"bootstrap", |value, digest| {
    digest.identifier(value.mesh_id.as_bytes());
    digest.name(&value.mesh_name);
    digest.identifier(value.administrator_id.as_bytes());
    digest.name(&value.administrator_name);
    digest.identifier(value.administrator_role_id.as_bytes());
    digest.identifier(value.host_id.as_bytes());
    digest.name(&value.host_name);
    digest.identifier(value.node_id.as_bytes());
    digest.name(&value.node_name);
    digest.name(&value.partition_name);
});
digest_simple_record!(
    BootstrapAppliance,
    b"bootstrap-appliance",
    |value, digest| {
        value.mesh.update_digest(digest);
        value.authentication.update_digest(digest);
        digest.bytes(&value.recovery.public_wrapping_key);
        digest.bytes(&value.recovery.key_fingerprint);
        digest.bytes(&value.recovery.root_certificate_der);
        digest.bytes(&value.recovery.root_certificate_digest);
        digest.bytes(&value.recovery.online_authority_certificate_der);
        digest.bytes(&value.recovery.online_authority_certificate_digest);
        digest.bytes(&value.recovery.bundle_digest);
        digest.bytes(&value.recovery.save_challenge_commitment);
        value.node_wrapping_key.update_digest(digest);
        digest.bytes(&value.node_certificate.certificate_der);
        digest.bytes(&value.node_certificate.certificate_fingerprint);
        digest.signed(value.node_certificate.certificate_valid_until.get());
        value.storage_permit_key_generation.update_digest(digest);
        value
            .authentication_root_key_generation
            .update_digest(digest);
        value.online_authority_key_generation.update_digest(digest);
    }
);
digest_simple_record!(
    ConfirmRecoveryBundleSaved,
    b"confirm-recovery-bundle-saved",
    |value, digest| {
        digest.identifier(value.mesh_id.as_bytes());
        digest.bytes(&value.bundle_digest);
        digest.bytes(&value.save_challenge_commitment);
    }
);
digest_simple_record!(CreateUser, b"create-user", |value, digest| {
    digest.identifier(value.principal_id.as_bytes());
    digest.name(&value.name);
});
digest_simple_record!(CreateGroup, b"create-group", |value, digest| {
    digest.identifier(value.group_id.as_bytes());
    digest.name(&value.name);
    digest.optional_identifier(value.activation_policy_id.map(ActivationPolicyId::as_bytes));
});
digest_simple_record!(AddGroupMember, b"add-group-member", |value, digest| {
    digest.identifier(value.containing_group_id.as_bytes());
    digest.identifier(value.member_principal_id.as_bytes());
    digest.optional_instant(value.valid_from);
    digest.optional_instant(value.valid_until);
    digest.boolean(value.activation_required);
});
digest_simple_record!(
    ChangePrincipalState,
    b"change-principal-state",
    |value, digest| {
        digest.identifier(value.principal_id.as_bytes());
        digest.byte(match value.state {
            PrincipalLifecycleState::Active => 1,
            PrincipalLifecycleState::Suspended => 2,
            PrincipalLifecycleState::Retired => 3,
        });
        digest.bytes(value.reason.as_bytes());
        digest.unsigned(u64::try_from(value.owner_transfers.len()).unwrap_or(u64::MAX));
        for transfer in value.owner_transfers.as_slice() {
            transfer.update_digest(digest);
        }
    }
);
digest_simple_record!(
    RemoveGroupMember,
    b"remove-group-member",
    |value, digest| {
        digest.identifier(value.containing_group_id.as_bytes());
        digest.identifier(value.member_principal_id.as_bytes());
        digest.bytes(value.reason.as_bytes());
    }
);
digest_simple_record!(
    CreateActivationPolicy,
    b"activation-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.unsigned(value.maximum_duration.get());
        digest.boolean(value.reason_required);
        digest.byte(assurance_code(value.minimum_assurance));
        digest.optional_instant(value.valid_from);
        digest.optional_instant(value.valid_until);
    }
);
digest_simple_record!(
    CreateVolumeSnapshot,
    b"create-volume-snapshot",
    |value, digest| {
        digest.identifier(value.snapshot_id.as_bytes());
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.namespace_commit_id.as_bytes());
        digest.name(&value.name);
        digest.optional_instant(value.expires_at);
        digest.boolean(value.protected_from_expiry);
    }
);
digest_simple_record!(
    RestoreVolumeSnapshot,
    b"restore-volume-snapshot",
    |value, digest| {
        digest.identifier(value.snapshot_id.as_bytes());
        digest.unsigned(value.expected_snapshot_revision.get());
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.snapshot_namespace_commit_id.as_bytes());
        digest.identifier(value.expected_namespace_commit_id.as_bytes());
        digest.identifier(value.namespace_commit_id.as_bytes());
        digest.identifier(value.root_object_revision_id.as_bytes());
        digest.identifier(value.source_operation_id.as_bytes());
        digest.bytes(&value.source_request_digest);
        digest.bytes(&value.source_result_digest);
    }
);
digest_simple_record!(
    RequestVolumeSnapshotExpiry,
    b"request-volume-snapshot-expiry",
    |value, digest| {
        digest.identifier(value.snapshot_id.as_bytes());
        digest.unsigned(value.expected_snapshot_revision.get());
        digest.byte(snapshot_expiry_reason_code(value.reason));
    }
);
digest_simple_record!(
    RemoveVolumeSnapshotRoot,
    b"remove-volume-snapshot-root",
    |value, digest| {
        digest.identifier(value.snapshot_id.as_bytes());
        digest.unsigned(value.expected_snapshot_revision.get());
        digest.identifier(value.expiry_operation_id.as_bytes());
        digest.identifier(value.namespace_commit_id.as_bytes());
        digest.identifier(value.root_object_revision_id.as_bytes());
    }
);

const fn snapshot_expiry_reason_code(reason: SnapshotExpiryReason) -> u8 {
    match reason {
        SnapshotExpiryReason::Manual => 1,
        SnapshotExpiryReason::RetentionAge => 2,
        SnapshotExpiryReason::RetentionCount => 3,
    }
}
digest_simple_record!(
    ConfigureSnapshotSchedule,
    b"configure-snapshot-schedule",
    |value, digest| {
        digest.identifier(value.schedule_id.as_bytes());
        digest.identifier(value.volume_id.as_bytes());
        digest.unsigned(value.expected_schedule_sequence);
        digest.unsigned(value.interval.get());
        digest.optional_unsigned(value.retention_count.map(u64::from));
        digest.optional_unsigned(value.retention_duration.map(DurationMicros::get));
        digest.boolean(value.enabled);
        digest.signed(value.next_due_at.get());
    }
);
digest_simple_record!(
    RunSnapshotSchedule,
    b"run-snapshot-schedule",
    |value, digest| {
        digest.identifier(value.schedule_id.as_bytes());
        digest.unsigned(value.expected_schedule_sequence);
        digest.signed(value.scheduled_for.get());
        digest.identifier(value.snapshot_id.as_bytes());
        digest.identifier(value.namespace_commit_id.as_bytes());
        digest.name(&value.name);
    }
);
digest_simple_record!(
    ConfigureVersionRetention,
    b"configure-version-retention",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.unsigned(value.expected_policy_sequence);
        digest.boolean(value.history_enabled);
        digest.unsigned(value.minimum_age.get());
        digest.optional_unsigned(value.maximum_age.map(DurationMicros::get));
        digest.optional_unsigned(value.minimum_versions.map(u64::from));
        digest.byte(match value.reclaim_mode {
            RetentionReclaimMode::UnderPressure => 1,
            RetentionReclaimMode::AfterMaximumAge => 2,
            RetentionReclaimMode::EagerAfterMinimumAge => 3,
        });
        digest.boolean(value.soft_minimum_breakable);
        digest.unsigned(value.conflict_minimum_age.get());
    }
);
digest_simple_record!(
    ProposeVersionCleanup,
    b"propose-version-cleanup",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.version_id.as_bytes());
        digest.identifier(value.manifest_id.as_bytes());
        digest.bytes(&value.manifest_root_digest);
        digest.identifier(value.source_scan_operation_id.as_bytes());
        digest.bytes(&value.scan_request_digest);
        digest.bytes(&value.reachability_subject_digest);
        digest.unsigned(value.retention_policy_sequence);
        digest.unsigned(value.reachability_revision.get());
        digest.unsigned(value.retained_root_count);
        digest.bytes(&value.retained_root_digest);
        digest.bytes(&value.retained_root_set_digest);
        digest.bytes(&value.local_roots_digest);
        digest.bytes(&value.proof_result_digest);
    }
);
digest_simple_record!(
    RegisterCleanupAttestationKey,
    b"register-cleanup-attestation-key",
    |value, digest| {
        digest.identifier(value.node_id.as_bytes());
        digest.unsigned(value.generation);
        digest.bytes(&value.verifying_key);
    }
);
digest_simple_record!(
    AttestVersionCleanup,
    b"attest-version-cleanup",
    |value, digest| {
        let value = value.attestation;
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.cleanup_revision.get());
        digest.identifier(value.node_id.as_bytes());
        digest.unsigned(value.node_incarnation);
        digest.unsigned(value.key_generation);
        digest.identifier(value.scan_operation_id.as_bytes());
        digest.bytes(&value.scan_request_digest);
        digest.bytes(&value.reachability_subject_digest);
        digest.bytes(&value.local_roots_digest);
        digest.bytes(&value.scan_result_digest);
        digest.bytes(&value.signature);
    }
);
digest_simple_record!(
    AuthoriseVersionCleanup,
    b"authorise-version-cleanup",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.cleanup_revision.get());
        digest.bytes(&value.reachability_subject_digest);
    }
);
digest_simple_record!(
    CancelVersionCleanup,
    b"cancel-version-cleanup",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.cleanup_revision.get());
        digest.bytes(&value.reachability_subject_digest);
    }
);
digest_simple_record!(
    AppendVersionCleanupItems,
    b"append-version-cleanup-items",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.cleanup_revision.get());
        digest.unsigned(value.authorisation_revision.get());
        digest.unsigned(value.expected_item_count);
        digest.unsigned(value.start_index);
        digest.unsigned(u64::try_from(value.items.len()).unwrap_or(u64::MAX));
        for item in value.items.as_slice() {
            digest.identifier(item.removal_operation_id.as_bytes());
            digest.bytes(&item.shard.manifest_digest);
            digest.unsigned(item.shard.stripe_index);
            digest.unsigned(u64::from(item.shard.shard_index));
            digest.unsigned(u64::from(item.shard.generation));
            digest.identifier(item.target_id.as_bytes());
            digest.unsigned(item.target_generation);
            digest.identifier(item.storage_node_id.as_bytes());
        }
    }
);
digest_simple_record!(
    SealVersionCleanupInventory,
    b"seal-version-cleanup-inventory",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.cleanup_revision.get());
        digest.unsigned(value.authorisation_revision.get());
        digest.unsigned(value.expected_item_count);
        digest.bytes(&value.inventory_digest);
    }
);
digest_simple_record!(
    IssueVersionCleanupPermit,
    b"issue-version-cleanup-permit",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.inventory_sealed_revision.get());
        digest.unsigned(value.item_index);
        digest.unsigned(value.attempt_sequence);
        let permit = value.permit;
        digest.identifier(permit.operation_id.as_bytes());
        digest.identifier(permit.mesh_id.as_bytes());
        digest.identifier(permit.target_id.as_bytes());
        digest.bytes(&permit.shard.manifest_digest);
        digest.unsigned(permit.shard.stripe_index);
        digest.unsigned(u64::from(permit.shard.shard_index));
        digest.unsigned(u64::from(permit.shard.generation));
        digest.unsigned(permit.target_generation);
        digest.unsigned(permit.authority_epoch);
        digest.unsigned(permit.catalogue_revision.get());
        digest.signed(permit.expires_at.get());
        digest.bytes(&permit.permit_digest);
    }
);
digest_simple_record!(
    CompleteVersionCleanupItem,
    b"complete-version-cleanup-item",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.inventory_sealed_revision.get());
        digest.unsigned(value.item_index);
        digest.unsigned(value.permit_attempt_sequence);
        let receipt = value.receipt;
        digest.identifier(receipt.operation_id.as_bytes());
        digest.bytes(&receipt.shard.manifest_digest);
        digest.unsigned(receipt.shard.stripe_index);
        digest.unsigned(u64::from(receipt.shard.shard_index));
        digest.unsigned(u64::from(receipt.shard.generation));
        digest.identifier(receipt.target_id.as_bytes());
        digest.unsigned(receipt.target_generation);
        digest.bytes(&receipt.permit_digest);
        digest.bytes(&receipt.tombstone_digest);
        digest.identifier(value.reporter_node_id.as_bytes());
        digest.unsigned(value.reporter_incarnation);
    }
);
digest_simple_record!(
    ConfirmVersionCleanupReclamation,
    b"confirm-version-cleanup-reclamation",
    |value, digest| {
        digest.identifier(value.cleanup_operation_id.as_bytes());
        digest.unsigned(value.item_index);
        let receipt = value.receipt;
        let tombstone = receipt.tombstone;
        digest.identifier(tombstone.operation_id.as_bytes());
        digest.bytes(&tombstone.shard.manifest_digest);
        digest.unsigned(tombstone.shard.stripe_index);
        digest.unsigned(u64::from(tombstone.shard.shard_index));
        digest.unsigned(u64::from(tombstone.shard.generation));
        digest.identifier(tombstone.target_id.as_bytes());
        digest.unsigned(tombstone.target_generation);
        digest.bytes(&tombstone.permit_digest);
        digest.bytes(&tombstone.tombstone_digest);
        digest.signed(receipt.bytes_unlinked_at.get());
        digest.unsigned(receipt.reclaimed_bytes);
        digest.bytes(&receipt.reclamation_digest);
        digest.identifier(value.reporter_node_id.as_bytes());
        digest.unsigned(value.reporter_incarnation);
    }
);
digest_simple_record!(CreateVolume, b"create-volume", |value, digest| {
    digest.identifier(value.volume_id.as_bytes());
    digest.name(&value.name);
    digest.identifier(value.root_object_id.as_bytes());
    digest.identifier(value.owner_set_id.as_bytes());
    digest.principals(&value.owners);
    value.key_generation.update_digest(digest);
});
digest_simple_record!(
    CommitConvergedVolumeHead,
    b"commit-converged-volume-head",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.optional_identifier(
            value
                .expected_namespace_commit_id
                .map(NamespaceCommitId::as_bytes),
        );
        digest.identifier(value.namespace_commit_id.as_bytes());
        digest.identifier(value.root_object_revision_id.as_bytes());
        digest.converged_head_evidence(value.evidence);
    }
);
digest_simple_record!(CreateObject, b"create-object", |value, digest| {
    digest.identifier(value.object_id.as_bytes());
    digest.identifier(value.volume_id.as_bytes());
    digest.identifier(value.parent_object_id.as_bytes());
    digest.byte(match value.kind {
        NamespaceObjectKind::Folder => 1,
        NamespaceObjectKind::File => 2,
    });
    digest.name(&value.name);
    digest.identifier(value.owner_set_id.as_bytes());
    digest.principals(&value.owners);
});
digest_simple_record!(
    ReplaceObjectOwners,
    b"replace-object-owners",
    |value, digest| {
        digest.identifier(value.object_id.as_bytes());
        digest.identifier(value.owner_set_id.as_bytes());
        digest.principals(&value.owners);
    }
);
digest_simple_record!(
    SetObjectGrantInheritance,
    b"set-object-grant-inheritance",
    |value, digest| {
        digest.identifier(value.object_id.as_bytes());
        digest.boolean(value.stop_parent_grants);
    }
);
digest_simple_record!(CreateTag, b"create-tag", |value, digest| {
    digest.identifier(value.tag_id.as_bytes());
    digest.name(&value.name);
});
digest_simple_record!(AttachTag, b"attach-tag", |value, digest| {
    digest.identifier(value.tag_id.as_bytes());
    digest.tag_target(value.target);
});
digest_simple_record!(DetachTag, b"detach-tag", |value, digest| {
    digest.identifier(value.tag_id.as_bytes());
    digest.tag_target(value.target);
});
digest_simple_record!(GrantPermission, b"grant-permission", |value, digest| {
    digest.identifier(value.grant_id.as_bytes());
    digest.identifier(value.subject_principal_id.as_bytes());
    digest.permission_scope(value.scope);
    digest.unsigned(u64::from(value.rights.bits()));
    digest.byte(match value.inheritance {
        GrantInheritance::Object => 1,
        GrantInheritance::Descendants => 2,
        GrantInheritance::ObjectAndDescendants => 3,
    });
    digest.optional_instant(value.valid_from);
    digest.optional_instant(value.valid_until);
    digest.optional_identifier(value.activation_policy_id.map(ActivationPolicyId::as_bytes));
});
digest_simple_record!(
    GrantPermissionWithActivation,
    b"grant-permission-with-activation",
    |value, digest| {
        value.policy.update_digest(digest);
        value.grant.update_digest(digest);
    }
);
digest_simple_record!(
    RevokePermissionGrant,
    b"revoke-permission-grant",
    |value, digest| {
        digest.identifier(value.grant_id.as_bytes());
        digest.bytes(value.reason.as_bytes());
    }
);
digest_simple_record!(ActivateGrant, b"activate-grant", |value, digest| {
    digest.identifier(value.activation_id.as_bytes());
    digest.identifier(value.principal_id.as_bytes());
    digest.identifier(value.grant_id.as_bytes());
    digest.identifier(value.policy_id.as_bytes());
    digest.bytes(value.reason.as_bytes());
    digest.unsigned(value.duration.get());
    digest.signed(value.session_expires_at.get());
    digest.byte(assurance_code(value.assurance));
    digest.bytes(&value.authentication_digest);
});
digest_simple_record!(ActivateGroup, b"activate-group", |value, digest| {
    digest.identifier(value.activation_id.as_bytes());
    digest.identifier(value.principal_id.as_bytes());
    digest.identifier(value.group_id.as_bytes());
    digest.identifier(value.policy_id.as_bytes());
    digest.bytes(value.reason.as_bytes());
    digest.unsigned(value.duration.get());
    digest.signed(value.session_expires_at.get());
    digest.byte(assurance_code(value.assurance));
    digest.bytes(&value.authentication_digest);
});
digest_simple_record!(
    RevokeAccessActivation,
    b"revoke-access-activation",
    |value, digest| {
        digest.identifier(value.activation_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
        digest.bytes(value.reason.as_bytes());
    }
);
digest_simple_record!(
    CreateAuthenticationMethod,
    b"create-authentication-method",
    |value, digest| {
        digest.identifier(value.method_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
        digest.bytes(value.label.as_bytes());
        digest.byte(value.service_scope);
        digest.optional_instant(value.expires_at);
        match &value.credential {
            NewAuthenticationCredential::Passkey {
                credential_id,
                public_key_algorithm,
                public_key,
                signature_counter,
                authenticator_guid,
                transports,
                backup_eligible,
                backup_state,
            } => {
                digest.byte(1);
                digest.bytes(credential_id);
                digest.signed(i64::from(*public_key_algorithm));
                digest.bytes(public_key);
                digest.unsigned(*signature_counter);
                digest.optional_identifier(*authenticator_guid);
                digest.byte(*transports);
                digest.boolean(*backup_eligible);
                digest.boolean(*backup_state);
            }
            NewAuthenticationCredential::Totp {
                secret_ciphertext,
                algorithm,
                digits,
                period_seconds,
                accepted_step_window,
            } => {
                digest.byte(2);
                digest.bytes(secret_ciphertext);
                digest.byte(*algorithm as u8);
                digest.byte(*digits);
                digest.unsigned(u64::from(*period_seconds));
                digest.byte(*accepted_step_window);
            }
            NewAuthenticationCredential::RecoveryCodes { codes } => {
                digest.byte(3);
                digest.unsigned(u64::try_from(codes.len()).unwrap_or(u64::MAX));
                for code in codes.as_slice() {
                    digest.identifier(code.code_id.as_bytes());
                    digest.bytes(&code.code_digest);
                }
            }
            NewAuthenticationCredential::ApiKey {
                key_id,
                key_digest,
                smb_verifier_ciphertext,
                scopes,
                valid_from,
            } => {
                digest.byte(4);
                digest.identifier(key_id.as_bytes());
                digest.bytes(key_digest);
                match smb_verifier_ciphertext {
                    Some(ciphertext) => {
                        digest.byte(1);
                        digest.bytes(ciphertext);
                    }
                    None => digest.byte(0),
                }
                digest.unsigned(*scopes);
                digest.signed(valid_from.get());
            }
        }
    }
);
digest_simple_record!(
    RevokeAuthenticationMethod,
    b"revoke-authentication-method",
    |value, digest| {
        digest.identifier(value.method_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
        digest.bytes(value.reason.as_bytes());
    }
);
digest_simple_record!(
    ConfigureAuthenticationPolicy,
    b"configure-authentication-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.byte(value.service.scope_bit());
        digest.byte(value.operation_class.code());
        digest.unsigned(value.expected_policy_sequence);
        digest.byte(value.allowed_factor_classes.bits());
        digest.byte(value.minimum_factor_count);
        digest.unsigned(value.maximum_session_duration.get());
        digest.optional_unsigned(value.maximum_step_up_age.map(DurationMicros::get));
    }
);
digest_simple_record!(
    IssueAuthenticationSession,
    b"issue-authentication-session",
    |value, digest| {
        digest.identifier(value.session_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
        digest.bytes(&value.token_digest);
        digest.bytes(&value.csrf_digest);
        match &value.client_label {
            SessionClientLabel::Missing => digest.byte(1),
            SessionClientLabel::Null => digest.byte(2),
            SessionClientLabel::Value(label) => {
                digest.byte(3);
                digest.bytes(label.as_bytes());
            }
        }
        digest.boolean(value.persistent_cookie);
        digest.byte(value.service.scope_bit());
        digest.unsigned(u64::try_from(value.factors.len()).unwrap_or(u64::MAX));
        for factor in value.factors.as_slice() {
            digest.identifier(factor.method_id().as_bytes());
            digest.unsigned(factor.credential_generation());
            digest.unsigned(factor.method_revision().get());
            match factor {
                SessionAuthenticationFactor::Passkey {
                    credential_id,
                    signature_counter,
                    backup_state,
                    ..
                } => {
                    digest.byte(1);
                    digest.bytes(credential_id);
                    digest.unsigned(*signature_counter);
                    digest.boolean(*backup_state);
                }
                SessionAuthenticationFactor::Totp { accepted_step, .. } => {
                    digest.byte(2);
                    digest.unsigned(*accepted_step);
                }
                SessionAuthenticationFactor::RecoveryCode { code_id, .. } => {
                    digest.byte(3);
                    digest.identifier(code_id.as_bytes());
                }
                SessionAuthenticationFactor::ApiKey { key_id, .. } => {
                    digest.byte(4);
                    digest.identifier(key_id.as_bytes());
                }
            }
        }
        digest.signed(value.expires_at.get());
    }
);
digest_simple_record!(
    StepUpAuthenticationSession,
    b"step-up-authentication-session",
    |value, digest| {
        digest.identifier(value.source_session_id.as_bytes());
        digest.identifier(value.replacement_session_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
        digest.bytes(&value.token_digest);
        digest.bytes(&value.csrf_digest);
        digest.identifier(value.additional_factor.method_id().as_bytes());
        digest.unsigned(value.additional_factor.credential_generation());
        digest.unsigned(value.additional_factor.method_revision().get());
        match &value.additional_factor {
            SessionAuthenticationFactor::Totp { accepted_step, .. } => {
                digest.byte(2);
                digest.unsigned(*accepted_step);
            }
            SessionAuthenticationFactor::RecoveryCode { code_id, .. } => {
                digest.byte(3);
                digest.identifier(code_id.as_bytes());
            }
            SessionAuthenticationFactor::Passkey { .. }
            | SessionAuthenticationFactor::ApiKey { .. } => digest.byte(0),
        }
        digest.signed(value.expires_at.get());
    }
);
digest_simple_record!(
    RevokeAuthenticationSession,
    b"revoke-authentication-session",
    |value, digest| {
        digest.identifier(value.session_id.as_bytes());
        digest.identifier(value.principal_id.as_bytes());
    }
);
digest_simple_record!(CreateComponent, b"create-component", |value, digest| {
    digest.identifier(value.instance_id.as_bytes());
    digest.byte(value.component_kind);
    digest.name(&value.name);
    digest.bytes(value.implementation_id.as_bytes());
    digest.unsigned(u64::from(value.contract_major));
    digest.unsigned(u64::from(value.contract_minor));
    digest.unsigned(u64::from(value.schema_version));
    digest.bytes(&value.canonical_configuration);
    digest.bytes(&value.configuration_digest);
});
digest_simple_record!(
    ConfigureComponent,
    b"configure-component",
    |value, digest| {
        digest.identifier(value.instance_id.as_bytes());
        digest.unsigned(u64::from(value.schema_version));
        digest.bytes(&value.canonical_configuration);
        digest.bytes(&value.configuration_digest);
    }
);
digest_simple_record!(AssignComponent, b"assign-component", |value, digest| {
    digest.identifier(value.instance_id.as_bytes());
    digest.byte(value.assignment_kind);
    digest.identifier(value.assignment_id);
    digest.byte(value.desired_state);
});
digest_simple_record!(
    crate::ReconcileMetadataBackupDefaults,
    b"reconcile-backup-defaults",
    |value, digest| {
        digest.identifier(value.partition_id.as_bytes());
        digest.unsigned(value.expected_topology_revision.get());
        digest.unsigned(value.expected_defaults_revision.get());
    }
);
digest_simple_record!(
    ConfigureBackupDestination,
    b"configure-backup-destination",
    |value, digest| {
        digest.identifier(value.destination_id.as_bytes());
        digest.unsigned(value.expected_destination_revision.get());
        digest.name(&value.name);
        match value.binding {
            crate::BackupDestinationBinding::RegisteredTarget {
                target_id,
                target_generation,
            } => {
                digest.byte(1);
                digest.identifier(target_id.as_bytes());
                digest.unsigned(target_generation);
            }
            crate::BackupDestinationBinding::FederatedMesh {
                remote_mesh_id,
                provider_generation,
            } => {
                digest.byte(2);
                digest.identifier(remote_mesh_id.as_bytes());
                digest.unsigned(provider_generation);
            }
            crate::BackupDestinationBinding::ComponentProvider {
                instance_id,
                provider_generation,
            } => {
                digest.byte(3);
                digest.identifier(instance_id.as_bytes());
                digest.unsigned(provider_generation);
            }
        }
        digest.byte(match value.failure_relationship {
            crate::BackupFailureRelationship::Unknown => 1,
            crate::BackupFailureRelationship::Overlapping => 2,
            crate::BackupFailureRelationship::Independent => 3,
        });
        digest.bytes(&value.failure_evidence_digest);
        digest.byte(u8::from(value.enabled));
    }
);
digest_simple_record!(
    ConfigureMetadataBackupSchedule,
    b"configure-metadata-backup-schedule",
    |value, digest| {
        digest.identifier(value.partition_id.as_bytes());
        digest.unsigned(value.expected_schedule_sequence);
        digest.unsigned(value.interval.get());
        digest.unsigned(u64::from(value.retained_generations));
        digest.byte(value.minimum_verified_copies);
        digest.byte(value.minimum_independent_copies);
        digest.boolean(value.enabled);
        digest.signed(value.next_due_at.get());
    }
);
digest_simple_record!(
    QueueMetadataBackupRun,
    b"queue-metadata-backup-run",
    |value, digest| {
        digest.identifier(value.backup_id.as_bytes());
        digest.identifier(value.partition_id.as_bytes());
        digest.unsigned(value.expected_schedule_sequence);
        digest.signed(value.scheduled_for.get());
    }
);
digest_simple_record!(
    ClaimMetadataBackupRun,
    b"claim-metadata-backup-run",
    |value, digest| {
        digest.identifier(value.backup_id.as_bytes());
        update_backup_claim_digest(value.claim, digest);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    RenewMetadataBackupRun,
    b"renew-metadata-backup-run",
    |value, digest| {
        digest.identifier(value.backup_id.as_bytes());
        update_backup_claim_digest(value.claim, digest);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    CompleteMetadataBackupRun,
    b"complete-metadata-backup-run",
    |value, digest| {
        digest.identifier(value.backup_id.as_bytes());
        match value.outcome {
            MetadataBackupRunCompletion::Protected { result_digest } => {
                digest.byte(1);
                digest.bytes(&result_digest);
            }
            MetadataBackupRunCompletion::Incomplete { result_digest } => {
                digest.byte(2);
                digest.bytes(&result_digest);
            }
        }
    }
);
digest_simple_record!(
    RecordMetadataBackup,
    b"record-metadata-backup",
    |value, digest| {
        digest.signed(value.source_created_at.get());
        digest.identifier(value.backup_id.as_bytes());
        digest.identifier(value.partition_id.as_bytes());
        digest.identifier(value.mesh_id.as_bytes());
        digest.unsigned(value.last_log_index);
        digest.unsigned(value.last_log_term);
        digest.unsigned(value.state_revision.get());
        digest.unsigned(u64::from(value.schema_version));
        digest.unsigned(value.source_byte_length);
        digest.bytes(&value.source_digest);
        digest.bytes(&value.manifest_digest);
        digest.unsigned(value.encrypted_byte_length);
        digest.bytes(&value.encrypted_digest);
        update_backup_claim_digest(value.claim, digest);
        digest.identifier(value.initial_copy.destination_id.as_bytes());
        digest.unsigned(value.initial_copy.provider_generation);
        digest.bytes(value.initial_copy.object_reference.as_bytes());
        digest.unsigned(value.initial_copy.byte_length);
        digest.bytes(&value.initial_copy.copy_digest);
    }
);

fn update_backup_claim_digest(value: crate::MetadataBackupRunClaim, digest: &mut CanonicalDigest) {
    digest.unsigned(value.claim_generation);
    digest.identifier(value.worker_node_id.as_bytes());
    digest.unsigned(value.worker_incarnation);
    digest.unsigned(value.fence);
}
digest_simple_record!(RecordBackupCopy, b"record-backup-copy", |value, digest| {
    digest.identifier(value.backup_id.as_bytes());
    digest.identifier(value.destination_id.as_bytes());
    digest.unsigned(value.provider_generation);
    digest.bytes(value.object_reference.as_bytes());
    digest.unsigned(value.byte_length);
    digest.bytes(&value.copy_digest);
});
digest_simple_record!(VerifyBackupCopy, b"verify-backup-copy", |value, digest| {
    digest.identifier(value.backup_id.as_bytes());
    digest.identifier(value.destination_id.as_bytes());
    digest.unsigned(value.provider_generation);
    digest.bytes(&value.copy_digest);
});
digest_simple_record!(
    RetireMetadataBackup,
    b"retire-metadata-backup",
    |value, digest| {
        digest.identifier(value.backup_id.as_bytes());
        digest.unsigned(value.expected_backup_revision.get());
        digest.unsigned(value.expected_schedule_sequence);
        for backup_id in &value.retained_backups {
            digest.identifier(backup_id.as_bytes());
        }
    }
);
digest_simple_record!(
    RecordBackupReclamation,
    b"record-backup-reclamation",
    |value, digest| {
        let receipt = value.receipt;
        digest.identifier(receipt.operation_id.as_bytes());
        digest.identifier(receipt.object.backup_id.as_bytes());
        digest.identifier(receipt.object.destination_id.as_bytes());
        digest.unsigned(receipt.object.provider_generation);
        digest.unsigned(receipt.object.byte_length);
        digest.bytes(&receipt.object.digest);
        digest.unsigned(receipt.retirement_revision.get());
    }
);
digest_simple_record!(
    RegisterStorageTarget,
    b"register-storage-target",
    |value, digest| {
        digest.identifier(value.target_id.as_bytes());
        digest.identifier(value.node_id.as_bytes());
        digest.identifier(value.host_id.as_bytes());
        value.provider.update_digest(digest);
        digest.name(&value.name);
        digest.unsigned(value.generation);
        digest.bytes(&value.marker_fingerprint);
        match value.backing_device_fingerprint {
            Some(fingerprint) => {
                digest.byte(1);
                digest.bytes(&fingerprint);
            }
            None => digest.byte(0),
        }
        match value.filesystem_fingerprint {
            Some(fingerprint) => {
                digest.byte(1);
                digest.bytes(&fingerprint);
            }
            None => digest.byte(0),
        }
        match value.usage_limit {
            StorageUsageLimit::Percent(percent) => {
                digest.byte(1);
                digest.unsigned(u64::from(percent));
            }
            StorageUsageLimit::Bytes(bytes) => {
                digest.byte(2);
                digest.unsigned(bytes);
            }
        }
    }
);
digest_simple_record!(CreateFaultGroup, b"create-fault-group", |value, digest| {
    digest.identifier(value.class_id.as_bytes());
    digest.name(&value.class_name);
    digest.identifier(value.group_id.as_bytes());
    digest.name(&value.group_name);
});
digest_simple_record!(
    SetHostFaultGroupMembership,
    b"set-host-fault-group-membership",
    |value, digest| {
        digest.identifier(value.group_id.as_bytes());
        digest.identifier(value.host_id.as_bytes());
        digest.boolean(value.present);
    }
);
digest_simple_record!(
    CreateProtectionPolicy,
    b"create-protection-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.name(&value.name);
        digest.unsigned(u64::try_from(value.scenarios.len()).unwrap_or(u64::MAX));
        for scenario in value.scenarios.as_slice() {
            digest.identifier(scenario.scenario_id.as_bytes());
            digest.name(&scenario.name);
            digest.unsigned(u64::try_from(scenario.scenario.terms().len()).unwrap_or(u64::MAX));
            for term in scenario.scenario.terms() {
                digest.identifier(term.class_id.as_bytes());
                digest.unsigned(u64::from(term.failure_count));
            }
        }
    }
);
digest_simple_record!(
    AssignVolumeProtectionPolicy,
    b"assign-volume-protection-policy",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.policy_id.as_bytes());
    }
);
digest_simple_record!(
    CreateAvailabilityCell,
    b"create-availability-cell",
    |value, digest| {
        digest.identifier(value.cell_id.as_bytes());
        digest.name(&value.name);
        digest.optional_identifier(value.parent_cell_id.map(AvailabilityCellId::as_bytes));
    }
);
digest_simple_record!(
    SetHostAvailabilityCellMembership,
    b"set-host-availability-cell-membership",
    |value, digest| {
        digest.identifier(value.cell_id.as_bytes());
        digest.identifier(value.host_id.as_bytes());
        digest.boolean(value.present);
    }
);
digest_simple_record!(
    SetTargetAvailabilityCellMembership,
    b"set-target-availability-cell-membership",
    |value, digest| {
        digest.identifier(value.cell_id.as_bytes());
        digest.identifier(value.target_id.as_bytes());
        digest.boolean(value.present);
    }
);
digest_simple_record!(
    CreateLocalityPolicy,
    b"create-locality-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.name(&value.name);
        digest.optional_unsigned(value.maximum_lag.map(DurationMicros::get));
        digest.unsigned(u64::try_from(value.requirements.len()).unwrap_or(u64::MAX));
        for requirement in value.requirements.as_slice() {
            digest.identifier(requirement.requirement_id.as_bytes());
            digest.identifier(requirement.cell_id.as_bytes());
            digest.optional_identifier(
                requirement
                    .local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes),
            );
        }
    }
);
digest_simple_record!(
    AssignVolumeLocalityPolicy,
    b"assign-volume-locality-policy",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.policy_id.as_bytes());
    }
);
digest_simple_record!(
    CreateAcknowledgementPolicy,
    b"create-acknowledgement-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.name(&value.name);
        digest.byte(value.consistency as u8);
        digest.unsigned(u64::from(value.minimum_durable_targets));
        digest.unsigned(u64::from(value.minimum_distinct_nodes));
        digest.optional_unsigned(value.strong_wait.map(DurationMicros::get));
        digest.byte(value.fallback as u8);
        digest.unsigned(u64::try_from(value.required_scenarios.len()).unwrap_or(u64::MAX));
        for scenario_id in value.required_scenarios.as_slice() {
            digest.identifier(scenario_id.as_bytes());
        }
        digest.unsigned(u64::try_from(value.cells.len()).unwrap_or(u64::MAX));
        for cell in value.cells.as_slice() {
            digest.identifier(cell.cell_id.as_bytes());
            digest.byte(cell.role as u8);
            digest.optional_unsigned(cell.minimum_durable_targets.map(u64::from));
            digest.optional_unsigned(cell.minimum_distinct_nodes.map(u64::from));
            digest.optional_identifier(
                cell.local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes),
            );
        }
    }
);
digest_simple_record!(
    AssignVolumeAcknowledgementPolicy,
    b"assign-volume-acknowledgement-policy",
    |value, digest| {
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.policy_id.as_bytes());
    }
);
digest_simple_record!(
    QueueMaintenanceWork,
    b"queue-maintenance-work",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.bytes(&value.deduplication_key);
        digest.bytes(&value.subject.encode());
        digest.boolean(value.signals.data_unavailable);
        digest.unsigned(u64::from(value.signals.remaining_recovery_margin));
        digest.unsigned(u64::from(value.signals.protection_debt));
        digest.unsigned(u64::from(value.signals.locality_debt));
        digest.unsigned(u64::from(value.signals.instability));
        digest.unsigned(u64::from(value.signals.access_heat));
        digest.signed(value.signals.created_at.get());
        digest.optional_instant(value.signals.due_at);
        digest.unsigned(value.demand.in_flight_bytes);
        digest.signed(value.next_attempt_at.get());
    }
);
digest_simple_record!(
    BeginStorageTargetDrain,
    b"begin-storage-target-drain",
    |value, digest| {
        value.work.update_digest(digest);
        digest.boolean(value.allow_temporary_degraded);
        digest.boolean(value.cleanup_requested);
    }
);
digest_simple_record!(
    BeginStorageScopeDrain,
    b"begin-storage-scope-drain",
    |value, digest| {
        digest.identifier(value.drain_id.as_bytes());
        digest.bytes(&WorkSubject::Drain(value.scope).encode());
        digest.boolean(value.allow_temporary_degraded);
        digest.boolean(value.cleanup_requested);
    }
);
digest_simple_record!(
    FenceStorageNodeDrainMembership,
    b"fence-storage-node-drain-membership",
    |value, digest| {
        digest.identifier(value.drain_id.as_bytes());
        digest.identifier(value.node_id.as_bytes());
        digest.unsigned(value.node_incarnation);
    }
);
digest_simple_record!(
    CompleteStorageScopeDrain,
    b"complete-storage-scope-drain",
    |value, digest| {
        digest.identifier(value.drain_id.as_bytes());
        digest.bytes(&value.safety_evidence_digest);
    }
);
digest_simple_record!(
    AttestStorageTargetDrain,
    b"attest-storage-target-drain",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.identifier(value.target_id.as_bytes());
        digest.unsigned(value.target_generation);
        digest.unsigned(value.observed_authority_revision.get());
        digest.bytes(&value.empty_catalogue_digest);
    }
);
digest_simple_record!(
    ClaimMaintenanceWork,
    b"claim-maintenance-work",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.claim_generation);
        digest.unsigned(value.fence);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    RenewMaintenanceWork,
    b"renew-maintenance-work",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    CompleteMaintenanceWork,
    b"complete-maintenance-work",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        match value.outcome {
            MaintenanceWorkCompletion::Succeeded {
                effect_operation_id,
                effect_revision,
                effect_result_digest,
            } => {
                digest.byte(1);
                digest.identifier(effect_operation_id.as_bytes());
                digest.unsigned(effect_revision.get());
                digest.bytes(&effect_result_digest);
            }
            MaintenanceWorkCompletion::Retry {
                failure_digest,
                retry_at,
            } => {
                digest.byte(2);
                digest.bytes(&failure_digest);
                digest.signed(retry_at.get());
            }
            MaintenanceWorkCompletion::Continue {
                progress_digest,
                retry_at,
            } => {
                digest.byte(3);
                digest.bytes(&progress_digest);
                digest.signed(retry_at.get());
            }
        }
    }
);
digest_simple_record!(
    CommitShardRepair,
    b"commit-shard-repair",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.identifier(value.volume_id.as_bytes());
        digest.identifier(value.manifest_id.as_bytes());
        digest.unsigned(value.source_layout_generation);
        digest_shard_receipt(digest, value.source_receipt);
        digest_shard_receipt(digest, value.replacement_receipt);
    }
);
digest_simple_record!(CommitScrubPass, b"commit-scrub-pass", |value, digest| {
    digest.identifier(value.work_id.as_bytes());
    digest.unsigned(value.claim_generation);
    digest.identifier(value.worker_node_id.as_bytes());
    digest.unsigned(value.worker_incarnation);
    digest.unsigned(value.fence);
    digest.identifier(value.target_id.as_bytes());
    digest.unsigned(value.target_generation);
    digest.unsigned(value.observation_count);
    digest.unsigned(value.verified_bytes);
    digest.unsigned(value.healthy_count);
    digest.unsigned(value.missing_count);
    digest.unsigned(value.corrupt_count);
    digest.unsigned(value.unreadable_count);
    digest.unsigned(value.unexpected_count);
    digest.unsigned(value.deferred_count);
    digest.bytes(&value.evidence_digest);
});
digest_simple_record!(
    CommitTargetReconciliation,
    b"commit-target-reconciliation",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.identifier(value.target_id.as_bytes());
        digest.unsigned(value.target_generation);
        digest.unsigned(value.observation_count);
        digest.unsigned(value.verified_bytes);
        digest.unsigned(value.healthy_count);
        digest.unsigned(value.missing_count);
        digest.unsigned(value.corrupt_count);
        digest.unsigned(value.unreadable_count);
        digest.unsigned(value.unexpected_count);
        digest.unsigned(value.deferred_count);
        digest.bytes(&value.evidence_digest);
    }
);
digest_simple_record!(
    CommitRebalanceScanPage,
    b"commit-rebalance-scan-page",
    |value, digest| {
        digest.identifier(value.work_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.identifier(value.volume_id.as_bytes());
        digest.unsigned(value.topology_revision.get());
        for cursor in [value.after, value.next] {
            if let Some(cursor) = cursor {
                digest.byte(1);
                digest.identifier(cursor.publication_operation_id.as_bytes());
                digest.unsigned(cursor.stripe_index);
            } else {
                digest.byte(0);
            }
        }
        digest.unsigned(u64::from(value.scanned_stripes));
        digest.unsigned(u64::from(value.queued_repairs));
        if let Some(revision) = value.superseded_by_revision {
            digest.byte(1);
            digest.unsigned(revision.get());
        } else {
            digest.byte(0);
        }
        digest.bytes(&value.page_digest);
    }
);
digest_simple_record!(PublishSmbExport, b"publish-smb-export", |value, digest| {
    digest.identifier(value.export_id.as_bytes());
    digest.identifier(value.volume_id.as_bytes());
    digest.identifier(value.root_object_id.as_bytes());
    digest.name(&value.share_name);
    match &value.gateways {
        SmbExportGatewaySelection::AllEligible => digest.byte(1),
        SmbExportGatewaySelection::Selected(nodes) => {
            digest.byte(2);
            let mut identifiers = nodes
                .as_slice()
                .iter()
                .map(|node| node.as_bytes())
                .collect::<Vec<_>>();
            identifiers.sort_unstable();
            digest.unsigned(u64::try_from(identifiers.len()).unwrap_or(u64::MAX));
            for identifier in identifiers {
                digest.identifier(identifier);
            }
        }
    }
    digest.boolean(value.encryption_required);
});
digest_simple_record!(
    WithdrawSmbExport,
    b"withdraw-smb-export",
    |value, digest| {
        digest.identifier(value.export_id.as_bytes());
        digest.bytes(value.reason.as_bytes());
    }
);
digest_simple_record!(ConfigureAcme, b"configure-acme", |value, digest| {
    digest.identifier(value.config_id.as_bytes());
    digest.bytes(value.directory_url.as_bytes());
    digest.identifier(value.account_key.secret_id);
    digest.unsigned(value.account_key.generation);
    digest.byte(match value.challenge_kind {
        AcmeChallengeKind::Http01 => 1,
        AcmeChallengeKind::Dns01 => 2,
    });
    if let Some(settings) = value.challenge_settings {
        digest.byte(1);
        digest.identifier(settings.secret_id);
        digest.unsigned(settings.generation);
    } else {
        digest.byte(0);
    }
    digest.unsigned(u64::try_from(value.certificate_names.len()).unwrap_or(u64::MAX));
    for name in value.certificate_names.as_slice() {
        digest.bytes(name.as_bytes());
    }
});
digest_simple_record!(ProvisionAcme, b"provision-acme", |value, digest| {
    digest.bytes(&value.intent_digest);
    value.configuration.update_digest(digest);
    value.account_key_generation.update_digest(digest);
    if let Some(settings) = &value.challenge_settings_generation {
        digest.byte(1);
        settings.update_digest(digest);
    } else {
        digest.byte(0);
    }
    value.initial_order.update_digest(digest);
});
digest_simple_record!(
    QueueCertificateOrder,
    b"queue-certificate-order",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.identifier(value.config_id.as_bytes());
        digest.signed(value.next_attempt_at.get());
    }
);
digest_simple_record!(
    ClaimCertificateOrder,
    b"claim-certificate-order",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    RenewCertificateOrder,
    b"renew-certificate-order",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.signed(value.lease_expires_at.get());
    }
);
digest_simple_record!(
    CheckpointCertificateOrder,
    b"checkpoint-certificate-order",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.identifier(value.certificate_key.secret_id);
        digest.unsigned(value.certificate_key.generation);
        digest.bytes(&value.checkpoint);
    }
);
digest_simple_record!(
    AdvanceManualDnsTask,
    b"advance-manual-dns-task",
    |value, digest| {
        digest.bytes(&value.task_digest);
        digest.identifier(value.order_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        digest.bytes(value.record_name.as_bytes());
        digest.bytes(&value.record_value);
        digest.signed(value.expires_at.get());
        digest.byte(match value.phase {
            crate::ManualDnsTaskPhase::AwaitingPublication => 1,
            crate::ManualDnsTaskPhase::PublicationObserved => 2,
            crate::ManualDnsTaskPhase::AwaitingRemoval => 3,
            crate::ManualDnsTaskPhase::Complete => 4,
        });
    }
);
digest_simple_record!(
    CompleteCertificateOrder,
    b"complete-certificate-order",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.unsigned(value.claim_generation);
        digest.identifier(value.worker_node_id.as_bytes());
        digest.unsigned(value.worker_incarnation);
        digest.unsigned(value.fence);
        match &value.outcome {
            CertificateOrderCompletion::Restart {
                failure_digest,
                retry_at,
                retired_checkpoint_digest,
            } => {
                digest.byte(3);
                digest.bytes(failure_digest);
                digest.signed(retry_at.get());
                digest.bytes(retired_checkpoint_digest);
            }
            CertificateOrderCompletion::Retry {
                failure_digest,
                retry_at,
            } => {
                digest.byte(1);
                digest.bytes(failure_digest);
                digest.signed(retry_at.get());
            }
            CertificateOrderCompletion::Issued {
                certificate,
                not_before,
                not_after,
                result_digest,
            } => {
                digest.byte(2);
                certificate.update_digest(digest);
                digest.signed(not_before.get());
                digest.signed(not_after.get());
                digest.bytes(result_digest);
            }
        }
    }
);
digest_simple_record!(
    AcknowledgePublicCertificateInstallation,
    b"acknowledge-public-certificate-installation",
    |value, digest| {
        digest.identifier(value.order_id.as_bytes());
        digest.identifier(value.gateway_node_id.as_bytes());
        digest.unsigned(value.gateway_incarnation);
        digest.identifier(value.certificate.secret_id);
        digest.unsigned(value.certificate.generation);
        digest.bytes(&value.bundle_digest);
        digest.unsigned(value.observed_order_revision.get());
    }
);
digest_simple_record!(
    PublishExternalCertificate,
    b"publish-external-certificate",
    |value, digest| {
        digest.identifier(value.publication_id.as_bytes());
        digest.identifier(value.certificate_id.as_bytes());
        digest.unsigned(value.generation);
        digest.unsigned(value.certificate_names.len() as u64);
        for name in value.certificate_names.as_slice() {
            digest.bytes(name.as_bytes());
        }
        value.certificate.update_digest(digest);
        digest.bytes(&value.bundle_digest);
        digest.bytes(&value.chain_digest);
        digest.bytes(&value.public_key_fingerprint);
        digest.signed(value.not_before.get());
        digest.signed(value.not_after.get());
    }
);
digest_simple_record!(
    AcknowledgeExternalCertificateInstallation,
    b"acknowledge-external-certificate-installation",
    |value, digest| {
        digest.identifier(value.publication_id.as_bytes());
        digest.identifier(value.gateway_node_id.as_bytes());
        digest.unsigned(value.gateway_incarnation);
        digest.identifier(value.certificate.secret_id);
        digest.unsigned(value.certificate.generation);
        digest.bytes(&value.bundle_digest);
        digest.unsigned(value.observed_publication_revision.get());
    }
);
digest_simple_record!(
    CreateMeshLocalCertificateAuthority,
    b"create-mesh-local-certificate-authority",
    |value, digest| {
        digest.identifier(value.authority_id.as_bytes());
        digest.unsigned(value.generation);
        digest.bytes(&value.certificate_der);
        value.authority_key.update_digest(digest);
        digest.bytes(&value.certificate_digest);
        digest.signed(value.not_before.get());
        digest.signed(value.not_after.get());
    }
);
digest_simple_record!(
    IssueMeshLocalCertificate,
    b"issue-mesh-local-certificate",
    |value, digest| {
        digest.identifier(value.issuance_id.as_bytes());
        digest.identifier(value.authority_id.as_bytes());
        digest.unsigned(value.authority_generation);
        digest.bytes(&value.authority_certificate_digest);
        digest.identifier(value.certificate_id.as_bytes());
        digest.unsigned(value.generation);
        digest.unsigned(value.certificate_names.len() as u64);
        for name in value.certificate_names.as_slice() {
            digest.bytes(name.as_bytes());
        }
        value.certificate.update_digest(digest);
        digest.bytes(&value.bundle_digest);
        digest.bytes(&value.public_key_fingerprint);
        digest.signed(value.not_before.get());
        digest.signed(value.not_after.get());
    }
);
digest_simple_record!(
    AcknowledgeMeshLocalCertificateInstallation,
    b"acknowledge-mesh-local-certificate-installation",
    |value, digest| {
        digest.identifier(value.issuance_id.as_bytes());
        digest.identifier(value.gateway_node_id.as_bytes());
        digest.unsigned(value.gateway_incarnation);
        digest.identifier(value.certificate.secret_id);
        digest.unsigned(value.certificate.generation);
        digest.bytes(&value.bundle_digest);
        digest.unsigned(value.observed_issuance_revision.get());
    }
);
digest_simple_record!(
    RegisterNodeWrappingKey,
    b"register-node-wrapping-key",
    |value, digest| {
        digest.identifier(value.node_id.as_bytes());
        digest.unsigned(value.generation);
        digest.bytes(&value.public_key);
        digest.bytes(&value.key_fingerprint);
    }
);
digest_simple_record!(
    CommitSecretGeneration,
    b"commit-secret-generation",
    |value, digest| {
        digest.byte(value.secret.format_version);
        digest.unsigned(u64::from(value.secret.context.kind()));
        digest.identifier(value.secret.context.id());
        digest.unsigned(value.secret.context.generation());
        digest.bytes(&value.secret.nonce);
        digest.bytes(&value.secret.ciphertext);
        digest.bytes(&value.secret.digest);
        digest.unsigned(value.recipients.len() as u64);
        for envelope in &value.recipients {
            digest.byte(envelope.format_version);
            digest.unsigned(u64::from(envelope.context.kind()));
            digest.identifier(envelope.context.id());
            digest.unsigned(envelope.context.generation());
            digest.bytes(&envelope.recipient_public_key);
            digest.bytes(&envelope.ephemeral_public_key);
            digest.bytes(&envelope.salt);
            digest.bytes(&envelope.nonce);
            digest.bytes(&envelope.ciphertext);
            digest.bytes(&envelope.digest);
        }
    }
);
digest_simple_record!(IssueJoinGrant, b"issue-join-grant", |value, digest| {
    digest.identifier(value.join_grant_id.as_bytes());
    digest.bytes(&value.secret_digest);
    digest.byte(value.allowed_roles.bits());
    digest.unsigned(u64::from(value.maximum_uses));
    digest.signed(value.expires_at.get());
});
digest_simple_record!(ConsumeJoinGrant, b"consume-join-grant", |value, digest| {
    digest.identifier(value.join_grant_id.as_bytes());
    digest.bytes(&value.secret_digest);
    digest.identifier(value.host_id.as_bytes());
    digest.optional_name(value.new_host_name.as_ref());
    digest.identifier(value.node_id.as_bytes());
    digest.name(&value.node_name);
    digest.unsigned(value.incarnation);
    digest.byte(value.requested_roles.bits());
    digest.bytes(&value.wrapping_public_key);
    digest.bytes(value.private_endpoint.as_bytes());
    digest.bytes(&value.certificate_der);
    digest.bytes(&value.certificate_fingerprint);
    digest.signed(value.certificate_valid_until.get());
});
digest_simple_record!(ActivateNode, b"activate-node", |value, digest| {
    digest.identifier(value.node_id.as_bytes());
    digest.unsigned(value.incarnation);
    digest.bytes(value.private_endpoint.as_bytes());
    digest.bytes(&value.capability_digest);
});
digest_simple_record!(
    RegisterRoutingSigner,
    b"register-routing-signer",
    |value, digest| {
        digest.identifier(value.node_id.as_bytes());
        digest.unsigned(value.generation);
        digest.bytes(&value.verifying_key);
    }
);
digest_simple_record!(
    CreateMetadataPartition,
    b"create-metadata-partition",
    |value, digest| {
        digest.identifier(value.partition_id.as_bytes());
        digest.name(&value.name);
        digest.byte(value.partition_kind);
    }
);
digest_simple_record!(CreateScopeRoute, b"create-scope-route", |value, digest| {
    digest.identifier(value.root_partition_id.as_bytes());
    digest_delegated_scope(digest, value.scope);
    digest.unsigned(value.routing_epoch);
    digest.attestation(value.attestation);
});
digest_simple_record!(
    InstallScopeRouteProjection,
    b"install-scope-route-projection",
    |value, digest| {
        digest.bytes(&value.route.signing_payload());
        digest.attestation(value.attestation);
    }
);
digest_simple_record!(
    BeginScopeHandoff,
    b"begin-scope-handoff",
    |value, digest| {
        digest.identifier(value.scope_id.as_bytes());
        digest.identifier(value.destination_partition_id.as_bytes());
        digest.unsigned(value.routing_epoch);
        digest_delegation_admission(digest, value.admission);
        digest.attestation(value.attestation);
    }
);

fn digest_delegated_scope(digest: &mut CanonicalDigest, scope: DelegatedMetadataScope) {
    digest.identifier(scope.scope_id().as_bytes());
    digest.byte(match scope.family() {
        MetadataOperationFamily::RootControl => 1,
        MetadataOperationFamily::Identity => 2,
        MetadataOperationFamily::Authentication => 3,
        MetadataOperationFamily::Namespace => 4,
        MetadataOperationFamily::Configuration => 5,
        MetadataOperationFamily::Audit => 6,
        MetadataOperationFamily::StorageCatalogue => 7,
        MetadataOperationFamily::Work => 8,
    });
    match scope.key_range() {
        MetadataKeyRange::All => digest.byte(1),
        MetadataKeyRange::Bounded {
            start_inclusive,
            end_exclusive,
        } => {
            digest.byte(2);
            digest.bytes(&start_inclusive);
            digest.bytes(&end_exclusive);
        }
    }
}

fn digest_delegation_admission(digest: &mut CanonicalDigest, admission: DelegationAdmission) {
    digest.unsigned(u64::from(admission.eligible_member_count()));
    digest.byte(admission.planned_voter_count());
    digest.bytes(&admission.quorum_plan_digest());
    digest.bytes(&admission.load_evidence_digest());
    digest.signed(admission.measured_at().get());
}
digest_simple_record!(
    FreezeScopeHandoff,
    b"freeze-scope-handoff",
    |value, digest| {
        digest.identifier(value.scope_id.as_bytes());
        digest.unsigned(value.routing_epoch);
        digest.evidence(value.evidence);
        digest.attestation(value.attestation);
    }
);
digest_simple_record!(
    ActivateScopeHandoff,
    b"activate-scope-handoff",
    |value, digest| {
        digest.identifier(value.scope_id.as_bytes());
        digest.identifier(value.destination_partition_id.as_bytes());
        digest.unsigned(value.routing_epoch);
        digest.evidence(value.evidence);
        digest.attestation(value.attestation);
    }
);
digest_simple_record!(
    AbortScopeHandoff,
    b"abort-scope-handoff",
    |value, digest| {
        digest.identifier(value.scope_id.as_bytes());
        digest.unsigned(value.routing_epoch);
        digest.unsigned(u64::from(value.reason_code));
        digest.attestation(value.attestation);
    }
);

fn assurance_code(value: AssuranceLevel) -> u8 {
    match value {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}

fn digest_shard_receipt(digest: &mut CanonicalDigest, receipt: ShardReceipt) {
    digest.identifier(receipt.operation_id.as_bytes());
    digest.bytes(&receipt.shard.manifest_digest);
    digest.unsigned(receipt.shard.stripe_index);
    digest.unsigned(u64::from(receipt.shard.shard_index));
    digest.unsigned(u64::from(receipt.shard.generation));
    digest.unsigned(receipt.length);
    digest.bytes(&receipt.digest);
    digest.identifier(receipt.target_id.as_bytes());
    digest.unsigned(receipt.target_generation);
}

pub(crate) struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self(digest)
    }

    fn tag_target(&mut self, target: TagTarget) {
        match target {
            TagTarget::Principal(principal_id) => {
                self.byte(1);
                self.identifier(principal_id.as_bytes());
            }
            TagTarget::Object(object_id) => {
                self.byte(2);
                self.identifier(object_id.as_bytes());
            }
        }
    }

    fn converged_head_evidence(&mut self, evidence: ConvergedHeadEvidence) {
        match evidence {
            ConvergedHeadEvidence::Publication {
                operation_id,
                request_digest,
                result_digest,
            } => {
                self.byte(1);
                self.identifier(operation_id.as_bytes());
                self.bytes(&request_digest);
                self.bytes(&result_digest);
            }
            ConvergedHeadEvidence::Reconciliation {
                operation_id,
                request_digest,
                causal_plan_digest,
                replay_plan_digest,
                result_digest,
            } => {
                self.byte(2);
                self.identifier(operation_id.as_bytes());
                self.bytes(&request_digest);
                self.bytes(&causal_plan_digest);
                self.bytes(&replay_plan_digest);
                self.bytes(&result_digest);
            }
        }
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    pub(crate) fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    pub(crate) fn unsigned(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn signed(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn identifier(&mut self, value: [u8; 16]) {
        self.0.update(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.unsigned(u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.0.update(value);
    }

    pub(crate) fn name(&mut self, value: &RecordName) {
        self.bytes(value.display().as_bytes());
        self.bytes(value.canonical().as_bytes());
    }

    pub(crate) fn trust_identity(&mut self, value: crate::FederationTrustIdentity) {
        self.unsigned(value.generation);
        self.bytes(&value.certificate_fingerprint);
        self.bytes(&value.verifying_key);
        self.signed(value.valid_from.get());
        self.signed(value.valid_until.get());
    }

    fn optional_name(&mut self, value: Option<&RecordName>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.name(value);
            }
            None => self.byte(0),
        }
    }

    fn optional_revision(&mut self, value: Option<Revision>) {
        self.optional_unsigned(value.map(Revision::get));
    }

    pub(crate) fn optional_instant(&mut self, value: Option<UnixMicros>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.signed(value.get());
            }
            None => self.byte(0),
        }
    }

    pub(crate) fn optional_identifier(&mut self, value: Option<[u8; 16]>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.identifier(value);
            }
            None => self.byte(0),
        }
    }

    pub(crate) fn optional_unsigned(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.unsigned(value);
            }
            None => self.byte(0),
        }
    }

    fn principals(&mut self, values: &BoundedItems<PrincipalId>) {
        let mut identifiers: Vec<[u8; 16]> = values
            .as_slice()
            .iter()
            .map(|value| value.as_bytes())
            .collect();
        identifiers.sort_unstable();
        self.unsigned(u64::try_from(identifiers.len()).unwrap_or(u64::MAX));
        for identifier in identifiers {
            self.identifier(identifier);
        }
    }

    fn evidence(&mut self, value: HandoffEvidence) {
        self.unsigned(value.frozen_revision.get());
        self.bytes(&value.snapshot_digest);
    }

    fn attestation(&mut self, value: RouteAttestation) {
        self.identifier(value.signer_node_id.as_bytes());
        self.unsigned(value.signer_generation);
        self.bytes(&value.signature);
    }

    fn permission_scope(&mut self, scope: PermissionScope) {
        match scope {
            PermissionScope::Global => self.byte(1),
            PermissionScope::Volume(volume_id) => {
                self.byte(2);
                self.identifier(volume_id.as_bytes());
            }
            PermissionScope::Object {
                volume_id,
                object_id,
            } => {
                self.byte(3);
                self.identifier(volume_id.as_bytes());
                self.identifier(object_id.as_bytes());
            }
        }
    }
}
