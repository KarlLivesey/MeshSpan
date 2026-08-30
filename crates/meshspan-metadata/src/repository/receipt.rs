// SPDX-License-Identifier: GPL-2.0-only

//! Stable, bounded command-result receipts stored for idempotent replay.

use meshspan_domain::{OperationId, Revision};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use super::RepositoryError;
use crate::PartitionDatabase;

const RECEIPT_VERSION: u8 = 1;
const RECEIPT_BYTES: usize = 42;

/// Exact committed replicated-log position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogPosition {
    /// Positive log index.
    pub index: u64,
    /// Positive leader term.
    pub term: u64,
}

/// Whether this invocation executed or resolved an earlier mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyDisposition {
    /// New semantic input committed.
    Applied,
    /// Identical semantic input had already committed.
    Replayed,
}

/// Closed entity families returned by Stage 2 commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EntityKind {
    /// Mesh bootstrap result.
    Mesh = 1,
    /// User principal.
    User = 2,
    /// Group principal.
    Group = 3,
    /// Direct group-membership edge, identified by the containing group.
    GroupMembership = 4,
    /// Access-activation policy.
    ActivationPolicy = 5,
    /// Volume and root namespace object.
    Volume = 6,
    /// Folder or file namespace object.
    NamespaceObject = 7,
    /// Allow-only permission grant.
    PermissionGrant = 8,
    /// Accepted time-bounded access activation.
    AccessActivation = 9,
    /// Replaceable component instance.
    ComponentInstance = 10,
    /// Desired component assignment.
    ComponentAssignment = 11,
    /// Administrator-issued node join grant.
    JoinGrant = 12,
    /// Certificate-bound enrolled node.
    Node = 13,
    /// Public key authorised to sign catalogue routes.
    RoutingSigner = 14,
    /// Metadata partition catalogue record.
    MetadataPartition = 15,
    /// Signed scope route or handoff transition.
    ScopeRoute = 16,
    /// Descriptive tag definition.
    Tag = 17,
    /// Descriptive principal/object tag edge.
    TagAttachment = 18,
    /// Read-only volume namespace snapshot.
    VolumeSnapshot = 19,
    /// Authoritative volume snapshot schedule.
    SnapshotSchedule = 20,
    /// Replicated unreachable-version cleanup intent.
    VersionCleanup = 21,
    /// Node-scoped public key for cleanup attestations.
    CleanupAttestationKey = 22,
    /// Mesh-wide authentication session.
    AuthenticationSession = 23,
    /// Autonomous swarm federation relationship.
    FederationRelationship = 24,
    /// One side's rotating public federation identity.
    FederationTrustIdentity = 25,
    /// Effective immutable federation authority grant.
    FederationGrant = 26,
    /// Signed home-swarm principal projection.
    FederatedPrincipalProjection = 27,
    /// Two-sided pre-authorised recovery succession.
    FederationSuccession = 28,
    /// Signed invisible federated mutation quarantine.
    FederationQuarantine = 29,
    /// Disjoint provider-node slice of one federated storage grant.
    FederationStorageAllocation = 30,
    /// Consensus-ordered admission of one signed federated namespace mutation.
    FederationMutationAdmission = 31,
    /// One user authentication method.
    AuthenticationMethod = 32,
    /// One immutable service/operation authentication-policy revision.
    AuthenticationPolicy = 33,
    /// Recipient-local user/group assignment of one swarm-targeted grant.
    FederationGrantAssignment = 34,
    /// Time-bounded activation of one federation grant assignment.
    FederationGrantAssignmentActivation = 35,
}

impl EntityKind {
    fn from_code(value: u8) -> Result<Self, RepositoryError> {
        match value {
            1 => Ok(Self::Mesh),
            2 => Ok(Self::User),
            3 => Ok(Self::Group),
            4 => Ok(Self::GroupMembership),
            5 => Ok(Self::ActivationPolicy),
            6 => Ok(Self::Volume),
            7 => Ok(Self::NamespaceObject),
            8 => Ok(Self::PermissionGrant),
            9 => Ok(Self::AccessActivation),
            10 => Ok(Self::ComponentInstance),
            11 => Ok(Self::ComponentAssignment),
            12 => Ok(Self::JoinGrant),
            13 => Ok(Self::Node),
            14 => Ok(Self::RoutingSigner),
            15 => Ok(Self::MetadataPartition),
            16 => Ok(Self::ScopeRoute),
            17 => Ok(Self::Tag),
            18 => Ok(Self::TagAttachment),
            19 => Ok(Self::VolumeSnapshot),
            20 => Ok(Self::SnapshotSchedule),
            21 => Ok(Self::VersionCleanup),
            22 => Ok(Self::CleanupAttestationKey),
            23 => Ok(Self::AuthenticationSession),
            24 => Ok(Self::FederationRelationship),
            25 => Ok(Self::FederationTrustIdentity),
            26 => Ok(Self::FederationGrant),
            27 => Ok(Self::FederatedPrincipalProjection),
            28 => Ok(Self::FederationSuccession),
            29 => Ok(Self::FederationQuarantine),
            30 => Ok(Self::FederationStorageAllocation),
            31 => Ok(Self::FederationMutationAdmission),
            32 => Ok(Self::AuthenticationMethod),
            33 => Ok(Self::AuthenticationPolicy),
            34 => Ok(Self::FederationGrantAssignment),
            35 => Ok(Self::FederationGrantAssignmentActivation),
            _ => Err(RepositoryError::CorruptState),
        }
    }
}

/// Protocol-neutral typed identity of a command result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityReference {
    /// Entity family.
    pub kind: EntityKind,
    /// Canonical non-nil entity identity.
    pub id: [u8; 16],
}

/// Exact persisted evidence for one committed authoritative operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandReceipt {
    /// New application or exact replay.
    pub disposition: ApplyDisposition,
    /// Operation identity.
    pub operation_id: OperationId,
    /// Canonical semantic request digest.
    pub request_digest: [u8; 32],
    /// Digest of the stored result payload.
    pub result_digest: [u8; 32],
    /// State revision created by the original operation.
    pub committed_revision: Revision,
    /// Log position of the original operation.
    pub committed_position: LogPosition,
    /// Current state-machine applied position after this invocation.
    pub applied_position: LogPosition,
    /// Typed result identity.
    pub entity: EntityReference,
}

pub(super) fn encode_result(
    entity: EntityReference,
    revision: Revision,
    position: LogPosition,
) -> Result<Vec<u8>, RepositoryError> {
    validate_position(position)?;
    let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
    bytes.push(RECEIPT_VERSION);
    bytes.push(entity.kind as u8);
    bytes.extend_from_slice(&entity.id);
    bytes.extend_from_slice(&revision.get().to_be_bytes());
    bytes.extend_from_slice(&position.term.to_be_bytes());
    bytes.extend_from_slice(&position.index.to_be_bytes());
    Ok(bytes)
}

pub(super) fn result_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub(super) fn validate_position(position: LogPosition) -> Result<(), RepositoryError> {
    if position.index == 0
        || position.term == 0
        || i64::try_from(position.index).is_err()
        || i64::try_from(position.term).is_err()
    {
        Err(RepositoryError::InvalidLogPosition)
    } else {
        Ok(())
    }
}

pub(super) fn resolve_operation(
    database: &PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<CommandReceipt>, RepositoryError> {
    let operation = operation_id.as_bytes();
    let row = database
        .connection()
        .query_row(
            "SELECT request_digest, result_payload, result_digest, revision,
                    committed_log_index
             FROM operations WHERE operation_id = ?1",
            [operation.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((request, payload, stored_result, revision, committed_index)) = row else {
        return Ok(None);
    };
    let applied = read_applied_position(database)?;
    decode_receipt(
        operation_id,
        &request,
        &payload,
        &stored_result,
        revision,
        committed_index,
        applied,
    )
    .map(Some)
}

fn read_applied_position(database: &PartitionDatabase) -> Result<LogPosition, RepositoryError> {
    let (index, term) = database.connection().query_row(
        "SELECT last_log_index, last_log_term FROM applied_state WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(LogPosition {
        index: u64::try_from(index).map_err(|_| RepositoryError::CorruptState)?,
        term: u64::try_from(term).map_err(|_| RepositoryError::CorruptState)?,
    })
}

pub(super) fn decode_receipt(
    operation_id: OperationId,
    request: &[u8],
    payload: &[u8],
    stored_result: &[u8],
    revision: i64,
    committed_index: i64,
    applied_position: LogPosition,
) -> Result<CommandReceipt, RepositoryError> {
    if request.len() != 32
        || stored_result.len() != 32
        || payload.len() != RECEIPT_BYTES
        || payload[0] != RECEIPT_VERSION
        || result_digest(payload).as_slice() != stored_result
    {
        return Err(RepositoryError::CorruptState);
    }
    let request_digest = request
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    let result_digest = stored_result
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    let entity_id = payload[2..18]
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    if entity_id == [0; 16] {
        return Err(RepositoryError::CorruptState);
    }
    let payload_revision = read_u64(payload, 18)?;
    let committed_term = read_u64(payload, 26)?;
    let payload_index = read_u64(payload, 34)?;
    let committed_revision = u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?;
    let database_index =
        u64::try_from(committed_index).map_err(|_| RepositoryError::CorruptState)?;
    if payload_revision != committed_revision || payload_index != database_index {
        return Err(RepositoryError::CorruptState);
    }
    let committed_position = LogPosition {
        index: database_index,
        term: committed_term,
    };
    validate_position(committed_position).map_err(|_| RepositoryError::CorruptState)?;
    Ok(CommandReceipt {
        disposition: ApplyDisposition::Replayed,
        operation_id,
        request_digest,
        result_digest,
        committed_revision: Revision::new(committed_revision),
        committed_position,
        applied_position,
        entity: EntityReference {
            kind: EntityKind::from_code(payload[1])?,
            id: entity_id,
        },
    })
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64, RepositoryError> {
    let end = start.checked_add(8).ok_or(RepositoryError::CorruptState)?;
    let value = bytes
        .get(start..end)
        .ok_or(RepositoryError::CorruptState)?
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    Ok(u64::from_be_bytes(value))
}
