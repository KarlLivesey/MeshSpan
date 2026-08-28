// SPDX-License-Identifier: GPL-2.0-only

//! Typed authoritative state-machine commands and canonical request digests.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, ComponentInstanceId,
    DurationMicros, GrantId, GroupId, HandoffEvidence, HostId, JoinGrantId, MeshId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId,
    PrincipalId, Revision, Rights, RoleId, ScopeId, SnapshotId, SnapshotScheduleId, TagId,
    UnixMicros, VolumeId,
};
use sha2::{Digest, Sha256};

use crate::RecordName;

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
    /// Creates one user principal.
    CreateUser(CreateUser),
    /// Creates one group principal.
    CreateGroup(CreateGroup),
    /// Adds one direct user/group membership and rebuilds exact closure rows.
    AddGroupMember(AddGroupMember),
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
    /// Creates or replaces one authoritative fixed-interval snapshot schedule.
    ConfigureSnapshotSchedule(ConfigureSnapshotSchedule),
    /// Materialises exactly one due occurrence from an authoritative snapshot schedule.
    RunSnapshotSchedule(RunSnapshotSchedule),
    /// Appends and selects one immutable per-volume file-version retention policy.
    ConfigureVersionRetention(ConfigureVersionRetention),
    /// Creates one folder or file record beneath an existing folder.
    CreateObject(CreateObject),
    /// Atomically points one logical object at a new immutable owner set.
    ReplaceObjectOwners(ReplaceObjectOwners),
    /// Creates one descriptive tag with no authority semantics.
    CreateTag(CreateTag),
    /// Attaches one descriptive tag to a principal or logical object.
    AttachTag(AttachTag),
    /// Detaches one descriptive tag from a principal or logical object.
    DetachTag(DetachTag),
    /// Creates an allow-only global, volume or object permission grant.
    GrantPermission(GrantPermission),
    /// Activates one pre-authorised grant for the requesting user.
    ActivateGrant(ActivateGrant),
    /// Activates one pre-authorised group for the requesting user.
    ActivateGroup(ActivateGroup),
    /// Creates a versioned desired component configuration.
    CreateComponent(CreateComponent),
    /// Selects a new validated desired configuration revision.
    ConfigureComponent(ConfigureComponent),
    /// Creates or replaces one bounded component assignment.
    AssignComponent(AssignComponent),
    /// Issues one bounded administrator-authorised node join grant.
    IssueJoinGrant(IssueJoinGrant),
    /// Consumes a join grant to admit one certificate-bound learner node.
    ConsumeJoinGrant(ConsumeJoinGrant),
    /// Registers an Ed25519 public key permitted to attest catalogue routes.
    RegisterRoutingSigner(RegisterRoutingSigner),
    /// Creates another metadata partition in the catalogue.
    CreateMetadataPartition(CreateMetadataPartition),
    /// Creates one initially active scope route.
    CreateScopeRoute(CreateScopeRoute),
    /// Begins destination catch-up while the source remains sole writer.
    BeginScopeHandoff(BeginScopeHandoff),
    /// Fences source writes at an exact state image.
    FreezeScopeHandoff(FreezeScopeHandoff),
    /// Activates a caught-up destination as sole writer.
    ActivateScopeHandoff(ActivateScopeHandoff),
    /// Restores source authority under a newer route fence.
    AbortScopeHandoff(AbortScopeHandoff),
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

    fn update_digest(&self, digest: &mut CanonicalDigest) {
        match self {
            Self::BootstrapMesh(value) => value.update_digest(digest),
            Self::CreateUser(value) => value.update_digest(digest),
            Self::CreateGroup(value) => value.update_digest(digest),
            Self::AddGroupMember(value) => value.update_digest(digest),
            Self::CreateActivationPolicy(value) => value.update_digest(digest),
            Self::CreateVolume(value) => value.update_digest(digest),
            Self::CommitConvergedVolumeHead(value) => value.update_digest(digest),
            Self::CreateVolumeSnapshot(value) => value.update_digest(digest),
            Self::RestoreVolumeSnapshot(value) => value.update_digest(digest),
            Self::RequestVolumeSnapshotExpiry(value) => value.update_digest(digest),
            Self::ConfigureSnapshotSchedule(value) => value.update_digest(digest),
            Self::RunSnapshotSchedule(value) => value.update_digest(digest),
            Self::ConfigureVersionRetention(value) => value.update_digest(digest),
            Self::CreateObject(value) => value.update_digest(digest),
            Self::ReplaceObjectOwners(value) => value.update_digest(digest),
            Self::CreateTag(value) => value.update_digest(digest),
            Self::AttachTag(value) => value.update_digest(digest),
            Self::DetachTag(value) => value.update_digest(digest),
            Self::GrantPermission(value) => value.update_digest(digest),
            Self::ActivateGrant(value) => value.update_digest(digest),
            Self::ActivateGroup(value) => value.update_digest(digest),
            Self::CreateComponent(value) => value.update_digest(digest),
            Self::ConfigureComponent(value) => value.update_digest(digest),
            Self::AssignComponent(value) => value.update_digest(digest),
            Self::IssueJoinGrant(value) => value.update_digest(digest),
            Self::ConsumeJoinGrant(value) => value.update_digest(digest),
            Self::RegisterRoutingSigner(value) => value.update_digest(digest),
            Self::CreateMetadataPartition(value) => value.update_digest(digest),
            Self::CreateScopeRoute(value) => value.update_digest(digest),
            Self::BeginScopeHandoff(value) => value.update_digest(digest),
            Self::FreezeScopeHandoff(value) => value.update_digest(digest),
            Self::ActivateScopeHandoff(value) => value.update_digest(digest),
            Self::AbortScopeHandoff(value) => value.update_digest(digest),
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
}

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
    /// Signed public leaf certificate; the node private key never enters this command.
    pub certificate_der: Vec<u8>,
    /// Independently checked SHA-256 fingerprint of `certificate_der`.
    pub certificate_fingerprint: [u8; 32],
    /// Absolute certificate expiry.
    pub certificate_valid_until: UnixMicros,
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
    /// Stable routed scope.
    pub scope_id: ScopeId,
    /// Existing owner partition.
    pub partition_id: PartitionId,
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
    /// Signature over the resulting preparing route.
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
digest_simple_record!(CreateVolume, b"create-volume", |value, digest| {
    digest.identifier(value.volume_id.as_bytes());
    digest.name(&value.name);
    digest.identifier(value.root_object_id.as_bytes());
    digest.identifier(value.owner_set_id.as_bytes());
    digest.principals(&value.owners);
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
    digest.bytes(&value.certificate_der);
    digest.bytes(&value.certificate_fingerprint);
    digest.signed(value.certificate_valid_until.get());
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
    digest.identifier(value.scope_id.as_bytes());
    digest.identifier(value.partition_id.as_bytes());
    digest.unsigned(value.routing_epoch);
    digest.attestation(value.attestation);
});
digest_simple_record!(
    BeginScopeHandoff,
    b"begin-scope-handoff",
    |value, digest| {
        digest.identifier(value.scope_id.as_bytes());
        digest.identifier(value.destination_partition_id.as_bytes());
        digest.unsigned(value.routing_epoch);
        digest.attestation(value.attestation);
    }
);
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

struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    fn new(domain: &[u8]) -> Self {
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

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    fn unsigned(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn signed(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    fn identifier(&mut self, value: [u8; 16]) {
        self.0.update(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.unsigned(u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.0.update(value);
    }

    fn name(&mut self, value: &RecordName) {
        self.bytes(value.display().as_bytes());
        self.bytes(value.canonical().as_bytes());
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

    fn optional_instant(&mut self, value: Option<UnixMicros>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.signed(value.get());
            }
            None => self.byte(0),
        }
    }

    fn optional_identifier(&mut self, value: Option<[u8; 16]>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.identifier(value);
            }
            None => self.byte(0),
        }
    }

    fn optional_unsigned(&mut self, value: Option<u64>) {
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
