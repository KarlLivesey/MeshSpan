// SPDX-License-Identifier: GPL-2.0-only

//! Recipient-local assignment and activation of swarm-targeted namespace grants.

use std::collections::BTreeMap;

use meshspan_domain::{
    AccessActivationRequest, AccessWindow, ActivationSubject, FederationAssignmentId,
    FederationGrantId, FederationPolicy, GroupId, PrincipalId, Revision, Rights, UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::access_evaluation::subjects::load_effective_subjects_for_principal;
use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, federation_grant_evidence, identity};
use crate::{
    ActivateFederationGrantAssignment, AuthoritativeCommand, CommandContext,
    CreateFederationGrantAssignment, PartitionDatabase, RevokeFederationGrantAssignment,
    RevokeFederationGrantAssignmentActivation,
};

const MAXIMUM_ASSIGNMENTS: usize = 65_536;
const MAXIMUM_LINEAGE_LENGTH: usize = 4_096;

/// Current recipient-local authority for one user and swarm-targeted grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationGrantAssignmentAuthority {
    /// Union of current local assignment rights, already bounded by the swarm grant.
    pub effective_rights: Rights,
    /// Earliest finite expiry contributing to the requested rights.
    pub expires_at: Option<UnixMicros>,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::CreateFederationGrantAssignment(_)
            | AuthoritativeCommand::RevokeFederationGrantAssignment(_)
            | AuthoritativeCommand::ActivateFederationGrantAssignment(_)
            | AuthoritativeCommand::RevokeFederationGrantAssignmentActivation(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::CreateFederationGrantAssignment(value) => {
            create(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RevokeFederationGrantAssignment(value) => {
            revoke(transaction, context, value, revision)
        }
        AuthoritativeCommand::ActivateFederationGrantAssignment(value) => {
            activate(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeFederationGrantAssignmentActivation(value) => {
            revoke_activation(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

pub(super) fn evaluate(
    database: &PartitionDatabase,
    grant_id: FederationGrantId,
    principal_id: PrincipalId,
    identity_revision: Revision,
    requested_rights: Rights,
    now: UnixMicros,
) -> Result<Option<FederationGrantAssignmentAuthority>, RepositoryError> {
    if requested_rights.is_empty() {
        return Err(RepositoryError::InvalidCommand);
    }
    let grant = federation_grant_evidence::load_verified(database.connection(), grant_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    let FederationPolicy::Namespace(grant_policy) = grant.grant.policy() else {
        return Err(RepositoryError::InvalidCommand);
    };
    if !grant_is_current_for_local_recipient(database, &grant, now)? {
        return Ok(None);
    }
    let subjects =
        load_effective_subjects_for_principal(database, principal_id, identity_revision, now)?;
    let rows = load_assignments(database, grant_id, now)?;
    let mut rights = Rights::default();
    let mut expiries = BTreeMap::<u32, Option<UnixMicros>>::new();
    for row in rows {
        let Some(subject_expiry) = subjects.get(&row.subject_principal_id).copied() else {
            continue;
        };
        let activation_expiry = if row.activation_policy_id.is_some() {
            let Some(expiry) = load_activation_expiry(
                database,
                row.assignment_id,
                principal_id,
                identity_revision,
                row.revision,
                now,
            )?
            else {
                continue;
            };
            Some(expiry)
        } else {
            None
        };
        let effective = row.rights.intersection(grant_policy.access().rights());
        rights = rights.union(effective);
        let expiry = [
            subject_expiry,
            row.valid_until,
            activation_expiry,
            grant.grant.valid_until(),
        ]
        .into_iter()
        .flatten()
        .min();
        for bit_index in 0..13_u32 {
            let bit = 1_u32 << bit_index;
            if effective.bits() & bit != 0 {
                expiries
                    .entry(bit)
                    .and_modify(|current| {
                        if expiry.is_none() || current.is_some_and(|value| expiry > Some(value)) {
                            *current = expiry;
                        }
                    })
                    .or_insert(expiry);
            }
        }
    }
    if !rights.contains(requested_rights) {
        return Ok(None);
    }
    let expires_at = (0..13_u32)
        .filter_map(|bit_index| {
            let bit = 1_u32 << bit_index;
            (requested_rights.bits() & bit != 0).then(|| expiries.get(&bit).copied().flatten())
        })
        .flatten()
        .min();
    Ok(Some(FederationGrantAssignmentAuthority {
        effective_rights: rights,
        expires_at,
    }))
}

fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: CreateFederationGrantAssignment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.rights.is_empty() {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_window(command.valid_from, command.valid_until)?;
    identity::require_active_principal(transaction, command.subject_principal_id)?;
    if let Some(policy_id) = command.activation_policy_id {
        identity::require_policy(transaction, policy_id.as_bytes())?;
    }
    let grant = federation_grant_evidence::load_verified(transaction, command.grant_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    let FederationPolicy::Namespace(policy) = grant.grant.policy() else {
        return Err(RepositoryError::InvalidCommand);
    };
    if !grant_is_active_for_local_recipient(transaction, &grant)?
        || !policy.access().rights().contains(command.rights)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let assignment = command.assignment_id.as_bytes();
    let grant_id = command.grant_id.as_bytes();
    let subject = command.subject_principal_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let policy_id = command.activation_policy_id.map(|value| value.as_bytes());
    transaction.execute(
        "INSERT INTO federation_grant_assignments(
            assignment_id, grant_id, subject_principal_id, rights, valid_from, valid_until,
            activation_policy_id, created_by, created_at, state, revoked_at, revoked_by,
            revocation_reason, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, NULL, NULL, NULL, ?10)",
        params![
            assignment.as_slice(),
            grant_id.as_slice(),
            subject.as_slice(),
            command.rights.bits(),
            command.valid_from.map(UnixMicros::get),
            command.valid_until.map(UnixMicros::get),
            policy_id.as_ref().map(<[u8; 16]>::as_slice),
            actor.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    identity::update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FederationGrantAssignment,
        id: assignment,
    })
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationGrantAssignment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    identity::validate_audit_reason(&command.reason)?;
    let assignment = command.assignment_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let changed = transaction.execute(
        "UPDATE federation_grant_assignments
         SET state = 2, revoked_at = ?1, revoked_by = ?2, revocation_reason = ?3, revision = ?4
         WHERE assignment_id = ?5 AND state = 1 AND created_at <= ?1",
        params![
            context.occurred_at.get(),
            actor.as_slice(),
            command.reason,
            to_i64(revision.get())?,
            assignment.as_slice(),
        ],
    )?;
    require_one(changed)?;
    identity::update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FederationGrantAssignment,
        id: assignment,
    })
}

fn activate(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ActivateFederationGrantAssignment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    identity::require_user(transaction, command.principal_id)?;
    identity::validate_activation_session(
        transaction,
        command.principal_id,
        command.authentication_digest,
        command.assurance,
        command.session_expires_at,
        context.occurred_at,
    )?;
    let assignment_id = command.assignment_id.as_bytes();
    let assignment = transaction
        .query_row(
            "SELECT subject_principal_id, valid_from, valid_until, activation_policy_id, revision
             FROM federation_grant_assignments
             WHERE assignment_id = ?1 AND state = 1",
            [assignment_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let subject = principal(&assignment.0)?;
    if assignment.3.as_deref() != Some(command.policy_id.as_bytes().as_slice())
        || !subject_authorises_user(
            transaction,
            subject,
            command.principal_id,
            context.occurred_at,
        )?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let (policy, policy_revision) =
        identity::load_policy(transaction, command.policy_id.as_bytes())?;
    let identity_revision = identity::read_identity_revision(transaction)?;
    let activation = policy
        .activate(AccessActivationRequest {
            operation_id: context.operation_id,
            principal_id: command.principal_id,
            subject: ActivationSubject::FederationAssignment(command.assignment_id),
            source_is_authorized: true,
            identity_revision,
            source_revision: revision_from_i64(assignment.4)?,
            policy_revision,
            reason: &command.reason,
            duration: command.duration,
            now: context.occurred_at,
            session_expires_at: command.session_expires_at,
            assurance: command.assurance,
            source_window: AccessWindow {
                valid_from: assignment.1.map(UnixMicros::new),
                valid_until: assignment.2.map(UnixMicros::new),
            },
        })
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let activation_id = command.activation_id.as_bytes();
    transaction.execute(
        "INSERT INTO federation_grant_assignment_activations(
            activation_id, assignment_id, principal_id, policy_id, reason,
            authentication_digest, identity_revision, assignment_revision, policy_revision,
            activated_at, expires_at, revoked_at, revoked_by, revocation_reason, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   NULL, NULL, NULL, ?12)",
        params![
            activation_id.as_slice(),
            assignment_id.as_slice(),
            command.principal_id.as_bytes().as_slice(),
            command.policy_id.as_bytes().as_slice(),
            activation.reason(),
            command.authentication_digest.as_slice(),
            to_i64(activation.identity_revision().get())?,
            to_i64(activation.source_revision().get())?,
            to_i64(activation.policy_revision().get())?,
            activation.activated_at().get(),
            activation.expires_at().get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::FederationGrantAssignmentActivation,
        id: activation_id,
    })
}

fn revoke_activation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationGrantAssignmentActivation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    identity::validate_audit_reason(&command.reason)?;
    let activation = command.activation_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let changed = transaction.execute(
        "UPDATE federation_grant_assignment_activations
         SET revoked_at = ?1, revoked_by = ?2, revocation_reason = ?3, revision = ?4
         WHERE activation_id = ?5 AND principal_id = ?6
           AND revoked_at IS NULL AND activated_at <= ?1",
        params![
            context.occurred_at.get(),
            actor.as_slice(),
            command.reason,
            to_i64(revision.get())?,
            activation.as_slice(),
            command.principal_id.as_bytes().as_slice(),
        ],
    )?;
    require_one(changed)?;
    identity::update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FederationGrantAssignmentActivation,
        id: activation,
    })
}

#[derive(Clone, Copy)]
struct StoredAssignment {
    assignment_id: FederationAssignmentId,
    subject_principal_id: PrincipalId,
    rights: Rights,
    valid_until: Option<UnixMicros>,
    activation_policy_id: Option<[u8; 16]>,
    revision: Revision,
}

fn load_assignments(
    database: &PartitionDatabase,
    current_grant_id: FederationGrantId,
    now: UnixMicros,
) -> Result<Vec<StoredAssignment>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "WITH RECURSIVE lineage(grant_id, depth) AS (
            SELECT ?1, 0
            UNION ALL
            SELECT s.predecessor_grant_id, lineage.depth + 1
            FROM federation_grant_successions s
            JOIN lineage ON s.successor_grant_id = lineage.grant_id
            WHERE lineage.depth < ?2
         )
         SELECT a.assignment_id, a.subject_principal_id, a.rights, a.valid_until,
                a.activation_policy_id, a.revision
         FROM federation_grant_assignments a JOIN lineage USING(grant_id)
         WHERE a.state = 1 AND (a.valid_from IS NULL OR a.valid_from <= ?3)
           AND (a.valid_until IS NULL OR a.valid_until > ?3)
         ORDER BY a.assignment_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            current_grant_id.as_bytes().as_slice(),
            to_i64(
                u64::try_from(MAXIMUM_LINEAGE_LENGTH)
                    .map_err(|_| RepositoryError::CapacityExceeded)?,
            )?,
            now.get(),
            to_i64(
                u64::try_from(MAXIMUM_ASSIGNMENTS + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?,
            )?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut assignments = Vec::new();
    for row in rows {
        if assignments.len() == MAXIMUM_ASSIGNMENTS {
            return Err(RepositoryError::CapacityExceeded);
        }
        let row = row?;
        assignments.push(StoredAssignment {
            assignment_id: identifier(&row.0, FederationAssignmentId::from_bytes)?,
            subject_principal_id: principal(&row.1)?,
            rights: Rights::from_bits(
                u32::try_from(row.2).map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?,
            valid_until: row.3.map(UnixMicros::new),
            activation_policy_id: row.4.map(|value| identifier_bytes(&value)).transpose()?,
            revision: revision_from_i64(row.5)?,
        });
    }
    Ok(assignments)
}

fn load_activation_expiry(
    database: &PartitionDatabase,
    assignment_id: FederationAssignmentId,
    principal_id: PrincipalId,
    identity_revision: Revision,
    assignment_revision: Revision,
    now: UnixMicros,
) -> Result<Option<UnixMicros>, RepositoryError> {
    database
        .connection()
        .query_row(
            "SELECT MAX(a.expires_at)
             FROM federation_grant_assignment_activations a
             JOIN federation_grant_assignments fga USING(assignment_id)
             JOIN access_activation_policies ap ON ap.policy_id = a.policy_id
             WHERE a.assignment_id = ?1 AND a.principal_id = ?2
               AND a.revoked_at IS NULL AND a.activated_at <= ?3 AND a.expires_at > ?3
               AND a.identity_revision = ?4 AND a.assignment_revision = ?5
               AND a.policy_revision = ap.revision AND fga.activation_policy_id = a.policy_id",
            params![
                assignment_id.as_bytes().as_slice(),
                principal_id.as_bytes().as_slice(),
                now.get(),
                to_i64(identity_revision.get())?,
                to_i64(assignment_revision.get())?,
            ],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map(|value| value.map(UnixMicros::new))
        .map_err(RepositoryError::from)
}

fn grant_is_current_for_local_recipient(
    database: &PartitionDatabase,
    record: &super::FederationGrantRecord,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    grant_is_current_for_local_recipient_connection(database.connection(), record, now)
}

fn grant_is_current_for_local_recipient_connection(
    connection: &rusqlite::Connection,
    record: &super::FederationGrantRecord,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    if record.state != super::FederationGrantState::Active
        || now < record.grant.valid_from()
        || record.grant.valid_until().is_some_and(|until| now >= until)
    {
        return Ok(false);
    }
    let local_mesh: Vec<u8> = connection.query_row(
        "SELECT mesh_id FROM meshes WHERE (SELECT count(*) FROM meshes) = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(local_mesh.as_slice() == record.grant.recipient_mesh_id().as_bytes())
}

fn grant_is_active_for_local_recipient(
    connection: &rusqlite::Connection,
    record: &super::FederationGrantRecord,
) -> Result<bool, RepositoryError> {
    if record.state != super::FederationGrantState::Active {
        return Ok(false);
    }
    let local_mesh: Vec<u8> = connection.query_row(
        "SELECT mesh_id FROM meshes WHERE (SELECT count(*) FROM meshes) = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(local_mesh.as_slice() == record.grant.recipient_mesh_id().as_bytes())
}

fn subject_authorises_user(
    transaction: &Transaction<'_>,
    subject: PrincipalId,
    user: PrincipalId,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    if subject == user {
        return Ok(true);
    }
    let kind: Option<i64> = transaction
        .query_row(
            "SELECT principal_kind FROM principals WHERE principal_id = ?1 AND state = 1",
            [subject.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if kind != Some(2) {
        return Ok(false);
    }
    identity::active_group_path(
        transaction,
        GroupId::from_bytes(subject.as_bytes()).map_err(|_| RepositoryError::CorruptState)?,
        user,
        now.get(),
    )
}

fn validate_window(
    valid_from: Option<UnixMicros>,
    valid_until: Option<UnixMicros>,
) -> Result<(), RepositoryError> {
    if valid_from
        .zip(valid_until)
        .is_some_and(|(from, until)| from >= until)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn principal(bytes: &[u8]) -> Result<PrincipalId, RepositoryError> {
    identifier(bytes, PrincipalId::from_bytes)
}

fn identifier<T>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    constructor(identifier_bytes(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn identifier_bytes(bytes: &[u8]) -> Result<[u8; 16], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn revision_from_i64(value: i64) -> Result<Revision, RepositoryError> {
    Ok(Revision::new(
        u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?,
    ))
}
