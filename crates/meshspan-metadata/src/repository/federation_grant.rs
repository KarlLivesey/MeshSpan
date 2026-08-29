// SPDX-License-Identifier: GPL-2.0-only

//! Atomic effective grant issuance, immutable replacement and revocation.

use std::collections::BTreeSet;

use meshspan_domain::{
    DurationMicros, FederatedMutationAdmission, FederatedMutationEvidence, FederationAccess,
    FederationGrant, FederationGrantError, FederationGrantId, FederationPolicy,
    FederationResourceScope, MeshId, NamespaceFederationPolicy, Revision, StorageFederationPolicy,
    UnixMicros, classify_federated_mutation,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::federation_grant_command::policy_digest;
use crate::{
    AuthoritativeCommand, CommandContext, FederationGrantRestriction, IssueFederationGrant,
    ReplaceFederationGrant, RevokeFederationGrant,
};

const RELATIONSHIP_ACTIVE: i64 = 2;
const MAXIMUM_REASON_BYTES: usize = 512;

#[derive(Clone, Copy)]
struct RelationshipAuthority {
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    authority_epoch: u64,
}

#[derive(Clone, Copy)]
struct StoredGrantAuthority {
    relationship_id: meshspan_domain::FederationRelationshipId,
    subject_home_mesh_id: MeshId,
    subject_principal_id: meshspan_domain::PrincipalId,
    resource: FederationResourceScope,
    policy: FederationPolicy,
    authority_epoch: u64,
}

pub(super) fn classify_persisted_mutation(
    connection: &Connection,
    evidence: FederatedMutationEvidence,
) -> Result<FederatedMutationAdmission, RepositoryError> {
    let record = super::federation_grant_evidence::load_verified(connection, evidence.grant_id())?
        .ok_or(RepositoryError::InvalidCommand)?;
    let revoked_at = record
        .termination
        .as_ref()
        .map(|termination| termination.terminated_at);
    classify_federated_mutation(record.grant, evidence, revoked_at).map_err(|error| {
        if error == FederationGrantError::EvidenceMismatch {
            RepositoryError::InvalidCommand
        } else {
            RepositoryError::CorruptState
        }
    })
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::IssueFederationGrant(_)
            | AuthoritativeCommand::ReplaceFederationGrant(_)
            | AuthoritativeCommand::RevokeFederationGrant(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::IssueFederationGrant(value) => {
            issue(transaction, context, value, revision)
        }
        AuthoritativeCommand::ReplaceFederationGrant(value) => {
            replace(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeFederationGrant(value) => {
            revoke(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let relationship = load_relationship_authority(transaction, command.grant)?;
    validate_and_persist(
        transaction,
        context,
        command.grant,
        command.restrictions.as_slice(),
        relationship,
        revision,
    )?;
    Ok(grant_reference(command.grant.grant_id()))
}

fn replace(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ReplaceFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_reason(&command.reason)?;
    if command.predecessor_grant_id == command.grant.grant_id() {
        return Err(RepositoryError::InvalidCommand);
    }
    let predecessor = load_grant_authority(transaction, command.predecessor_grant_id)?;
    validate_successor_identity(predecessor, command.grant)?;
    if command.restricts_authority
        && !policy_is_no_broader(command.grant.policy(), predecessor.policy)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let relationship = load_relationship_authority(transaction, command.grant)?;
    validate_and_persist(
        transaction,
        context,
        command.grant,
        command.restrictions.as_slice(),
        relationship,
        revision,
    )?;
    let changed = transaction.execute(
        "UPDATE federation_grants SET state = 3, revoked_at = ?1, revision = ?2
         WHERE grant_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.predecessor_grant_id.as_bytes().as_slice()
        ],
    )?;
    require_one(changed)?;
    transaction.execute(
        "INSERT INTO federation_grant_successions(
            predecessor_grant_id, successor_grant_id, relationship_id,
            succession_kind, reason, succeeded_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command.predecessor_grant_id.as_bytes().as_slice(),
            command.grant.grant_id().as_bytes().as_slice(),
            command.grant.relationship_id().as_bytes().as_slice(),
            if command.restricts_authority { 2 } else { 1 },
            command.reason,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    persist_termination(
        transaction,
        command.predecessor_grant_id,
        if command.restricts_authority { 3 } else { 2 },
        &command.reason,
        context.occurred_at,
        revision,
    )?;
    Ok(grant_reference(command.grant.grant_id()))
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_reason(&command.reason)?;
    let stored = load_grant_authority(transaction, command.grant_id)?;
    if stored.authority_epoch != command.expected_authority_epoch {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE federation_grants SET state = 3, revoked_at = ?1, revision = ?2
         WHERE grant_id = ?3 AND state = 1 AND authority_epoch = ?4",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.grant_id.as_bytes().as_slice(),
            to_i64(command.expected_authority_epoch)?,
        ],
    )?;
    require_one(changed)?;
    persist_termination(
        transaction,
        command.grant_id,
        1,
        &command.reason,
        context.occurred_at,
        revision,
    )?;
    Ok(grant_reference(command.grant_id))
}

fn persist_termination(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
    kind: i64,
    reason: &str,
    occurred_at: UnixMicros,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_grant_terminations(
            grant_id, termination_kind, reason, terminated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            grant_id.as_bytes().as_slice(),
            kind,
            reason,
            occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn validate_and_persist(
    transaction: &Transaction<'_>,
    context: CommandContext,
    grant: FederationGrant,
    restrictions: &[FederationGrantRestriction],
    relationship: RelationshipAuthority,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_parties(grant, relationship)?;
    reject_retired_authority(transaction, grant)?;
    validate_restrictions(grant, restrictions, relationship)?;
    persist_grant(transaction, context, grant, revision)?;
    for restriction in restrictions {
        persist_restriction(transaction, grant.grant_id(), *restriction, revision)?;
    }
    Ok(())
}

fn reject_retired_authority(
    connection: &Connection,
    grant: FederationGrant,
) -> Result<(), RepositoryError> {
    let retired: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM federation_ownership_successions
            WHERE state = 3 AND retiring_mesh_id IN (?1, ?2)
         )",
        params![
            grant.subject().home_mesh_id().as_bytes().as_slice(),
            grant.resource().authority_mesh_id().as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if retired == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_parties(
    grant: FederationGrant,
    relationship: RelationshipAuthority,
) -> Result<(), RepositoryError> {
    let parties = [relationship.local_mesh_id, relationship.remote_mesh_id];
    if grant.authority_epoch() != relationship.authority_epoch
        || !parties.contains(&grant.subject().home_mesh_id())
        || !parties.contains(&grant.resource().authority_mesh_id())
        || grant.subject().home_mesh_id() == grant.resource().authority_mesh_id()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_restrictions(
    grant: FederationGrant,
    restrictions: &[FederationGrantRestriction],
    relationship: RelationshipAuthority,
) -> Result<(), RepositoryError> {
    if restrictions.len() != 2 {
        return Err(RepositoryError::InvalidCommand);
    }
    let imposing = restrictions
        .iter()
        .map(|value| value.imposing_mesh_id)
        .collect::<BTreeSet<_>>();
    if imposing != BTreeSet::from([relationship.local_mesh_id, relationship.remote_mesh_id]) {
        return Err(RepositoryError::InvalidCommand);
    }
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let effective =
        FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::InvalidCommand)?;
    if effective != grant.policy() || !policy_matches_resource(effective, grant.resource()) {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn persist_grant(
    transaction: &Transaction<'_>,
    context: CommandContext,
    grant: FederationGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let (resource_kind, authority, volume, object) = resource_columns(grant.resource());
    transaction.execute(
        "INSERT INTO federation_grants(
            grant_id, relationship_id, subject_home_mesh_id, subject_principal_id,
            resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
            valid_from, valid_until, state, effective_policy_digest, issued_at,
            revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, NULL, ?14)",
        params![
            grant.grant_id().as_bytes().as_slice(),
            grant.relationship_id().as_bytes().as_slice(),
            grant.subject().home_mesh_id().as_bytes().as_slice(),
            grant.subject().principal_id().as_bytes().as_slice(),
            resource_kind,
            authority.as_bytes().as_slice(),
            volume.map(meshspan_domain::VolumeId::as_bytes),
            object.map(meshspan_domain::ObjectId::as_bytes),
            to_i64(grant.authority_epoch())?,
            grant.valid_from().get(),
            grant.valid_until().map(UnixMicros::get),
            policy_digest(grant.policy()).as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn persist_restriction(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
    restriction: FederationGrantRestriction,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let digest = policy_digest(restriction.policy);
    match restriction.policy {
        FederationPolicy::Namespace(policy) => transaction.execute(
            "INSERT INTO federation_grant_restrictions(
                grant_id, imposing_mesh_id, policy_kind, rights, manage_sharing,
                maximum_storage_bytes, counts_towards_protection, serves_reads,
                maximum_offline_micros, policy_digest, revision
             ) VALUES (?1, ?2, 1, ?3, ?4, NULL, NULL, NULL, ?5, ?6, ?7)",
            params![
                grant_id.as_bytes().as_slice(),
                restriction.imposing_mesh_id.as_bytes().as_slice(),
                policy.access().rights().bits(),
                policy.access().may_manage_sharing(),
                optional_duration(policy.maximum_offline_duration())?,
                digest.as_slice(),
                to_i64(revision.get())?,
            ],
        )?,
        FederationPolicy::Storage(policy) => transaction.execute(
            "INSERT INTO federation_grant_restrictions(
                grant_id, imposing_mesh_id, policy_kind, rights, manage_sharing,
                maximum_storage_bytes, counts_towards_protection, serves_reads,
                maximum_offline_micros, policy_digest, revision
             ) VALUES (?1, ?2, 2, NULL, NULL, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                grant_id.as_bytes().as_slice(),
                restriction.imposing_mesh_id.as_bytes().as_slice(),
                to_i64(policy.maximum_storage_bytes())?,
                policy.participation().counts_towards_protection(),
                policy.participation().serves_reads(),
                optional_duration(policy.maximum_offline_duration())?,
                digest.as_slice(),
                to_i64(revision.get())?,
            ],
        )?,
    };
    Ok(())
}

fn load_relationship_authority(
    transaction: &Transaction<'_>,
    grant: FederationGrant,
) -> Result<RelationshipAuthority, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, state, authority_epoch
             FROM federation_relationships WHERE relationship_id = ?1",
            [grant.relationship_id().as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if row.2 != RELATIONSHIP_ACTIVE {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(RelationshipAuthority {
        local_mesh_id: parse_mesh(&row.0)?,
        remote_mesh_id: parse_mesh(&row.1)?,
        authority_epoch: positive(row.3)?,
    })
}

fn load_grant_authority(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
) -> Result<StoredGrantAuthority, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT relationship_id, subject_home_mesh_id, subject_principal_id,
                    resource_kind, authority_mesh_id, volume_id, object_id,
                    authority_epoch, effective_policy_digest
             FROM federation_grants WHERE grant_id = ?1 AND state = 1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let policy = load_effective_policy(transaction, grant_id)?;
    if row.8.as_slice() != policy_digest(policy) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(StoredGrantAuthority {
        relationship_id: parse_relationship(&row.0)?,
        subject_home_mesh_id: parse_mesh(&row.1)?,
        subject_principal_id: parse_principal(&row.2)?,
        resource: parse_resource(row.3, &row.4, row.5.as_deref(), row.6.as_deref())?,
        policy,
        authority_epoch: positive(row.7)?,
    })
}

fn load_effective_policy(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<FederationPolicy, RepositoryError> {
    let restrictions = load_restrictions(connection, grant_id)?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn load_restrictions(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Vec<FederationGrantRestriction>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT imposing_mesh_id, policy_kind, rights, manage_sharing, maximum_storage_bytes,
                counts_towards_protection, serves_reads, maximum_offline_micros,
                policy_digest
         FROM federation_grant_restrictions WHERE grant_id = ?1 ORDER BY imposing_mesh_id",
    )?;
    let rows = statement.query_map([grant_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Vec<u8>>(8)?,
        ))
    })?;
    let mut restrictions = Vec::new();
    for row in rows {
        let row = row?;
        let policy = parse_policy(row.1, row.2, row.3, row.4, row.5, row.6, row.7)?;
        if row.8.as_slice() != policy_digest(policy) {
            return Err(RepositoryError::CorruptState);
        }
        restrictions.push(FederationGrantRestriction {
            imposing_mesh_id: parse_mesh(&row.0)?,
            policy,
        });
    }
    if restrictions.len() != 2 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(restrictions)
}

pub(super) fn validate_stored_restriction_parties(
    restrictions: &[FederationGrantRestriction],
    local_mesh: &[u8],
    remote_mesh: &[u8],
) -> Result<(), RepositoryError> {
    let actual = restrictions
        .iter()
        .map(|restriction| restriction.imposing_mesh_id)
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([parse_mesh(local_mesh)?, parse_mesh(remote_mesh)?]);
    if actual == expected {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn validate_successor_identity(
    predecessor: StoredGrantAuthority,
    successor: FederationGrant,
) -> Result<(), RepositoryError> {
    if predecessor.relationship_id != successor.relationship_id()
        || predecessor.subject_home_mesh_id != successor.subject().home_mesh_id()
        || predecessor.subject_principal_id != successor.subject().principal_id()
        || predecessor.resource != successor.resource()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

pub(super) fn policy_is_no_broader(next: FederationPolicy, prior: FederationPolicy) -> bool {
    match (next, prior) {
        (FederationPolicy::Namespace(next), FederationPolicy::Namespace(prior)) => {
            next.access().rights().intersection(prior.access().rights()) == next.access().rights()
                && (!next.access().may_manage_sharing() || prior.access().may_manage_sharing())
                && duration_is_no_broader(
                    next.maximum_offline_duration(),
                    prior.maximum_offline_duration(),
                )
        }
        (FederationPolicy::Storage(next), FederationPolicy::Storage(prior)) => {
            next.maximum_storage_bytes() <= prior.maximum_storage_bytes()
                && (!next.participation().counts_towards_protection()
                    || prior.participation().counts_towards_protection())
                && (!next.participation().serves_reads() || prior.participation().serves_reads())
                && duration_is_no_broader(
                    next.maximum_offline_duration(),
                    prior.maximum_offline_duration(),
                )
        }
        _ => false,
    }
}

const fn duration_is_no_broader(
    next: Option<DurationMicros>,
    prior: Option<DurationMicros>,
) -> bool {
    match (next, prior) {
        (Some(next), Some(prior)) => next.get() <= prior.get(),
        (Some(_) | None, None) => true,
        (None, Some(_)) => false,
    }
}

fn policy_matches_resource(policy: FederationPolicy, resource: FederationResourceScope) -> bool {
    matches!(
        (policy, resource),
        (
            FederationPolicy::Namespace(_),
            FederationResourceScope::Volume { .. }
                | FederationResourceScope::Subtree { .. }
                | FederationResourceScope::File { .. }
        ) | (
            FederationPolicy::Storage(_),
            FederationResourceScope::StorageCapacity { .. }
        )
    )
}

fn resource_columns(
    resource: FederationResourceScope,
) -> (
    u8,
    MeshId,
    Option<meshspan_domain::VolumeId>,
    Option<meshspan_domain::ObjectId>,
) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => (1, owner_mesh_id, Some(volume_id), None),
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => (2, owner_mesh_id, Some(volume_id), Some(root_object_id)),
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => (3, owner_mesh_id, Some(volume_id), Some(object_id)),
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            (4, provider_mesh_id, None, None)
        }
    }
}

fn parse_policy(
    kind: i64,
    rights: Option<i64>,
    manage_sharing: Option<i64>,
    maximum_storage_bytes: Option<i64>,
    counts_towards_protection: Option<i64>,
    serves_reads: Option<i64>,
    maximum_offline_micros: Option<i64>,
) -> Result<FederationPolicy, RepositoryError> {
    let offline = maximum_offline_micros
        .map(positive)
        .transpose()?
        .map(DurationMicros::new);
    match kind {
        1 => {
            let bits = u32::try_from(rights.ok_or(RepositoryError::CorruptState)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            let rights = meshspan_domain::Rights::from_bits(bits)
                .map_err(|_| RepositoryError::CorruptState)?;
            let manage = parse_bool(manage_sharing)?;
            Ok(FederationPolicy::Namespace(NamespaceFederationPolicy::new(
                FederationAccess::new(rights, manage),
                offline,
            )))
        }
        2 => {
            let bytes = positive(maximum_storage_bytes.ok_or(RepositoryError::CorruptState)?)?;
            let participation = meshspan_domain::StorageParticipation::new(
                parse_bool(counts_towards_protection)?,
                parse_bool(serves_reads)?,
            );
            StorageFederationPolicy::new(bytes, participation, offline)
                .map(FederationPolicy::Storage)
                .map_err(|_| RepositoryError::CorruptState)
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_resource(
    kind: i64,
    authority: &[u8],
    volume: Option<&[u8]>,
    object: Option<&[u8]>,
) -> Result<FederationResourceScope, RepositoryError> {
    let authority = parse_mesh(authority)?;
    match (kind, volume, object) {
        (1, Some(volume), None) => Ok(FederationResourceScope::Volume {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
        }),
        (2, Some(volume), Some(object)) => Ok(FederationResourceScope::Subtree {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            root_object_id: parse_object(object)?,
        }),
        (3, Some(volume), Some(object)) => Ok(FederationResourceScope::File {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            object_id: parse_object(object)?,
        }),
        (4, None, None) => Ok(FederationResourceScope::StorageCapacity {
            provider_mesh_id: authority,
        }),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn validate_reason(reason: &str) -> Result<(), RepositoryError> {
    if reason.trim().is_empty()
        || reason.len() > MAXIMUM_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn parse_bool(value: Option<i64>) -> Result<bool, RepositoryError> {
    match value {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    parse_id(value, MeshId::from_bytes)
}

pub(super) fn parse_relationship(
    value: &[u8],
) -> Result<meshspan_domain::FederationRelationshipId, RepositoryError> {
    parse_id(value, meshspan_domain::FederationRelationshipId::from_bytes)
}

pub(super) fn parse_principal(
    value: &[u8],
) -> Result<meshspan_domain::PrincipalId, RepositoryError> {
    parse_id(value, meshspan_domain::PrincipalId::from_bytes)
}

fn parse_volume(value: &[u8]) -> Result<meshspan_domain::VolumeId, RepositoryError> {
    parse_id(value, meshspan_domain::VolumeId::from_bytes)
}

fn parse_object(value: &[u8]) -> Result<meshspan_domain::ObjectId, RepositoryError> {
    parse_id(value, meshspan_domain::ObjectId::from_bytes)
}

fn parse_id<T, E>(
    value: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, RepositoryError> {
    constructor(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}

fn optional_duration(value: Option<DurationMicros>) -> Result<Option<i64>, RepositoryError> {
    value.map(|value| to_i64(value.get())).transpose()
}

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn grant_reference(grant_id: FederationGrantId) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationGrant,
        id: grant_id.as_bytes(),
    }
}
