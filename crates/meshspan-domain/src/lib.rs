// SPDX-License-Identifier: GPL-2.0-only

//! Pure `MeshSpan` domain types, decisions and deterministic state transitions.

mod access;
mod api_key;
mod bootstrap_material;
mod claim;
mod federation;
mod federation_access;
mod federation_graph;
mod federation_mutation;
mod federation_route;
mod federation_storage;
mod join_grant;
mod lifecycle;
mod operation;
mod partitioning;
mod primitives;
mod recovery_code;
mod routing;
mod seams;
mod secret_text;
mod session_token;
mod topology;
mod uuid;

pub use access::{
    AccessActivation, AccessActivationError, AccessActivationPolicy, AccessActivationRequest,
    AccessWindow, ActivationSubject, AssuranceLevel, AuthenticationFactorClasses,
    AuthenticationFactorClassesError, AuthenticationMethodKind, AuthenticationOperationClass,
    AuthenticationService, GroupGraph, GroupGraphError, MembershipChange, OwnerSet, OwnerSetError,
    Rights, RightsError,
};
pub use api_key::{
    ApiKeyBundle, ApiKeyBundleError, ApiKeyIssuanceKey, ApiKeyIssuanceKeyError,
    ENCODED_API_KEY_LENGTH,
};
pub use bootstrap_material::{
    InitialAuthenticationRootMaterial, InitialBootstrapMaterial, InitialBootstrapMaterialError,
    InitialOnlineAuthorityMaterial, InitialStoragePermitMaterial,
};
pub use claim::{ClaimBundle, ClaimBundleError, ENCODED_CLAIM_BUNDLE_LENGTH};
pub use federation::{
    DEFAULT_FEDERATION_OFFLINE_DURATION, FederatedPrincipal, FederationAccess, FederationPolicy,
    FederationPolicyError, FederationPreset, FederationResourceScope, NamespaceFederationPolicy,
    StorageFederationPolicy, StorageParticipation,
};
pub use federation_access::{
    FederatedMutationAdmission, FederatedMutationEvidence, FederationGrant, FederationGrantError,
    QuarantineReason, classify_federated_mutation,
};
pub use federation_graph::{FederationGraph, FederationGraphError, FederationRelationshipKind};
pub use federation_mutation::FederatedMutationAcknowledgement;
pub use federation_route::{
    FederationGrantRoute, FederationGrantRouteError, MAXIMUM_FEDERATION_ROUTE_MESHES,
};
pub use federation_storage::{
    FederationStorageAction, FederationStorageActionError, FederationStorageAllocation,
    FederationStorageAllocationError,
};
pub use join_grant::{
    JoinGrantBundle, JoinGrantBundleError, JoinGrantIssuanceKey, JoinGrantIssuanceKeyError,
    MAXIMUM_ENCODED_JOIN_GRANT_LENGTH,
};
pub use lifecycle::{LifecycleEvent, LifecycleState, LifecycleTransitionError};
pub use operation::{
    CommitOutcome, DurabilityScope, OperationDecision, OperationReceipt, classify_operation,
};
pub use partitioning::{
    DelegatedMetadataScope, DelegationAdmission, DelegationError, MetadataKeyRange,
    MetadataOperationFamily, RootDelegatedRoute,
};
pub use primitives::{
    ActivationId, ActivationPolicyId, ApiKeyId, AuditEventId, AuthenticationChallengeId,
    AuthenticationMethodId, AuthenticationPolicyId, BackupId, BranchId, ClaimId,
    ComponentInstanceId, ContentManifestId, DurationMicros, FaultGroupClassId, FaultGroupId,
    FederationAssignmentId, FederationGrantId, FederationRelationshipId,
    FederationStorageAllocationId, FederationSuccessionId, FileVersionId, GrantId, GroupId,
    HandleId, HostId, IdentifierError, JoinGrantId, LockId, MeshId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId, PrincipalId, QuarantineId,
    QuorumPlanId, RecoveryCodeId, Revision, RevisionError, RoleId, ScopeId, SessionId, SmbExportId,
    SnapshotId, SnapshotScheduleId, StageId, TagId, TargetId, UnixMicros, UploadId, VolumeId,
};
pub use recovery_code::{
    ENCODED_RECOVERY_CODE_LENGTH, RecoveryCodeBundle, RecoveryCodeBundleError,
    RecoveryCodeIssuanceKey, RecoveryCodeIssuanceKeyError,
};
pub use routing::{HandoffEvidence, RouteError, RouteState, ScopeRoute};
pub use seams::{Clock, EntropyError, RandomSource};
pub use session_token::{
    ENCODED_CSRF_TOKEN_LENGTH, ENCODED_SESSION_TOKEN_LENGTH, SessionCsrfBundle, SessionTokenBundle,
    SessionTokenBundleError,
};
pub use topology::{
    FailureScenario, FailureTerm, FaultGroupMember, ProtectionError, ProtectionLayout,
    ProtectionProof, Topology, prove_protection,
};
pub use uuid::uuid_v8;
