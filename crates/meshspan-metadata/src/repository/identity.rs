// SPDX-License-Identifier: GPL-2.0-only

//! Mesh bootstrap, identity, nested group and permission mutations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use meshspan_domain::{
    AccessActivationPolicy, AccessActivationRequest, AccessWindow, ActivationSubject,
    AssuranceLevel, GroupId, PrincipalId, Revision, Rights,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::group_closure;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    ActivateGrant, ActivateGroup, AddGroupMember, CommandContext, CreateActivationPolicy,
    CreateGroup, CreateUser, GrantInheritance, GrantPermission, PermissionScope, RemoveGroupMember,
    RevokeAccessActivation, RevokePermissionGrant,
};

type ValidatedScope = (u8, Option<[u8; 16]>, Option<[u8; 16]>);

const PRINCIPAL_USER: u8 = 1;
const PRINCIPAL_GROUP: u8 = 2;
const ACTIVE_STATE: u8 = 1;
const MAXIMUM_MEMBERSHIP_EDGES: usize = 65_536;
const MAXIMUM_REVOCATION_REASON_BYTES: usize = 512;

struct MembershipEvent<'a> {
    containing_group_id: GroupId,
    member_principal_id: PrincipalId,
    event_kind: u8,
    reason: Option<&'a str>,
    context: CommandContext,
    revision: Revision,
}

pub(super) fn create_user(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateUser,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    insert_principal(
        transaction,
        command.principal_id,
        PRINCIPAL_USER,
        &command.name,
        context,
        revision,
    )?;
    let principal = command.principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
        [principal.as_slice()],
    )?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::User,
        id: principal,
    })
}

pub(super) fn create_group(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateGroup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if let Some(policy) = command.activation_policy_id {
        require_policy(transaction, policy.as_bytes())?;
    }
    insert_principal(
        transaction,
        command.group_id.principal_id(),
        PRINCIPAL_GROUP,
        &command.name,
        context,
        revision,
    )?;
    let group = command.group_id.as_bytes();
    let policy = command
        .activation_policy_id
        .map(meshspan_domain::ActivationPolicyId::as_bytes);
    transaction.execute(
        "INSERT INTO groups(principal_id, activation_policy_id) VALUES (?1, ?2)",
        params![group.as_slice(), policy.as_ref().map(<[u8; 16]>::as_slice)],
    )?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::Group,
        id: group,
    })
}

pub(super) fn add_group_member(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: AddGroupMember,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_window(
        command.valid_from.map(meshspan_domain::UnixMicros::get),
        command.valid_until.map(meshspan_domain::UnixMicros::get),
    )?;
    require_active_principal(transaction, command.member_principal_id)?;
    let group = command.containing_group_id.as_bytes();
    let group_policy: Option<Option<Vec<u8>>> = transaction
        .query_row(
            "SELECT activation_policy_id FROM groups WHERE principal_id = ?1",
            [group.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(group_policy) = group_policy else {
        return Err(RepositoryError::InvalidCommand);
    };
    if command.activation_required && group_policy.is_none() {
        return Err(RepositoryError::InvalidCommand);
    }
    let member = command.member_principal_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let updated = transaction.execute(
        "INSERT INTO group_memberships(
            containing_group_id, member_principal_id, valid_from, valid_until,
            activation_required, created_by, created_at, revision, state,
            removed_at, removed_by, removal_reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, NULL, NULL, NULL)
         ON CONFLICT(containing_group_id, member_principal_id) DO UPDATE SET
            valid_from = excluded.valid_from,
            valid_until = excluded.valid_until,
            activation_required = excluded.activation_required,
            created_by = excluded.created_by,
            created_at = excluded.created_at,
            revision = excluded.revision,
            state = 1,
            removed_at = NULL,
            removed_by = NULL,
            removal_reason = NULL
         WHERE group_memberships.state = 2",
        params![
            group.as_slice(),
            member.as_slice(),
            command.valid_from.map(meshspan_domain::UnixMicros::get),
            command.valid_until.map(meshspan_domain::UnixMicros::get),
            u8::from(command.activation_required),
            actor.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    insert_membership_event(
        transaction,
        &MembershipEvent {
            containing_group_id: command.containing_group_id,
            member_principal_id: command.member_principal_id,
            event_kind: 1,
            reason: None,
            context,
            revision,
        },
    )?;
    group_closure::rebuild(transaction, revision)?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::GroupMembership,
        id: group,
    })
}

pub(super) fn remove_group_member(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RemoveGroupMember,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_revocation_reason(&command.reason)?;
    let group = command.containing_group_id.as_bytes();
    let member = command.member_principal_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE group_memberships
         SET state = 2, removed_at = ?1, removed_by = ?2, removal_reason = ?3, revision = ?4
         WHERE containing_group_id = ?5 AND member_principal_id = ?6
           AND state = 1 AND created_at <= ?1",
        params![
            context.occurred_at.get(),
            actor.as_slice(),
            command.reason.as_str(),
            to_i64(revision.get())?,
            group.as_slice(),
            member.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    insert_membership_event(
        transaction,
        &MembershipEvent {
            containing_group_id: command.containing_group_id,
            member_principal_id: command.member_principal_id,
            event_kind: 2,
            reason: Some(&command.reason),
            context,
            revision,
        },
    )?;
    group_closure::rebuild(transaction, revision)?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::GroupMembership,
        id: group,
    })
}

fn insert_membership_event(
    transaction: &Transaction<'_>,
    event: &MembershipEvent<'_>,
) -> Result<(), RepositoryError> {
    let group = event.containing_group_id.as_bytes();
    let member = event.member_principal_id.as_bytes();
    let actor = event.context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO group_membership_events(
            containing_group_id, member_principal_id, event_kind, reason,
            actor_principal_id, occurred_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            group.as_slice(),
            member.as_slice(),
            event.event_kind,
            event.reason,
            actor.as_slice(),
            event.context.occurred_at.get(),
            to_i64(event.revision.get())?,
        ],
    )?;
    Ok(())
}

pub(super) fn create_activation_policy(
    transaction: &Transaction<'_>,
    command: &CreateActivationPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    AccessActivationPolicy::new(
        command.maximum_duration,
        command.reason_required,
        command.minimum_assurance,
        AccessWindow {
            valid_from: command.valid_from,
            valid_until: command.valid_until,
        },
    )
    .map_err(|_| RepositoryError::InvalidCommand)?;
    let policy = command.policy_id.as_bytes();
    transaction.execute(
        "INSERT INTO access_activation_policies(
            policy_id, maximum_duration_micros, reason_required, minimum_assurance,
            valid_from, valid_until, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            policy.as_slice(),
            to_i64(command.maximum_duration.get())?,
            u8::from(command.reason_required),
            assurance_code(command.minimum_assurance),
            command.valid_from.map(meshspan_domain::UnixMicros::get),
            command.valid_until.map(meshspan_domain::UnixMicros::get),
            to_i64(revision.get())?
        ],
    )?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::ActivationPolicy,
        id: policy,
    })
}

pub(super) fn grant_permission(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: GrantPermission,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.rights == Rights::default() {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_window(
        command.valid_from.map(meshspan_domain::UnixMicros::get),
        command.valid_until.map(meshspan_domain::UnixMicros::get),
    )?;
    require_active_principal(transaction, command.subject_principal_id)?;
    if let Some(policy) = command.activation_policy_id {
        require_policy(transaction, policy.as_bytes())?;
    }
    let (scope_kind, volume_id, object_id) = validate_scope(transaction, command.scope)?;
    let grant = command.grant_id.as_bytes();
    let subject = command.subject_principal_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let policy = command
        .activation_policy_id
        .map(meshspan_domain::ActivationPolicyId::as_bytes);
    transaction.execute(
        "INSERT INTO permission_grants(
            grant_id, subject_principal_id, scope_kind, volume_id, object_id, rights,
            inheritance, valid_from, valid_until, activation_policy_id, created_by,
            created_at, state, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13)",
        params![
            grant.as_slice(),
            subject.as_slice(),
            scope_kind,
            volume_id.as_ref().map(<[u8; 16]>::as_slice),
            object_id.as_ref().map(<[u8; 16]>::as_slice),
            command.rights.bits(),
            inheritance_code(command.inheritance),
            command.valid_from.map(meshspan_domain::UnixMicros::get),
            command.valid_until.map(meshspan_domain::UnixMicros::get),
            policy.as_ref().map(<[u8; 16]>::as_slice),
            actor.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::PermissionGrant,
        id: grant,
    })
}

pub(super) fn revoke_permission_grant(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokePermissionGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_revocation_reason(&command.reason)?;
    let grant = command.grant_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE permission_grants
         SET state = 2, revoked_at = ?1, revoked_by = ?2, revocation_reason = ?3, revision = ?4
         WHERE grant_id = ?5 AND state = 1 AND created_at <= ?1",
        params![
            context.occurred_at.get(),
            actor.as_slice(),
            command.reason.as_str(),
            to_i64(revision.get())?,
            grant.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::PermissionGrant,
        id: grant,
    })
}

pub(super) fn activate_grant(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ActivateGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    require_user(transaction, command.principal_id)?;
    validate_activation_session(
        transaction,
        command.principal_id,
        command.authentication_digest,
        command.assurance,
        command.session_expires_at,
        context.occurred_at,
    )?;
    let grant_id = command.grant_id.as_bytes();
    let grant = transaction
        .query_row(
            "SELECT subject_principal_id, valid_from, valid_until, activation_policy_id, revision
             FROM permission_grants WHERE grant_id = ?1 AND state = 1",
            [grant_id.as_slice()],
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
    let subject = parse_principal(&grant.0)?;
    if grant.3.as_deref() != Some(command.policy_id.as_bytes().as_slice()) {
        return Err(RepositoryError::InvalidCommand);
    }
    let source_authorised = subject == command.principal_id
        || active_group_path(
            transaction,
            GroupId::from_bytes(subject.as_bytes()).map_err(|_| RepositoryError::InvalidCommand)?,
            command.principal_id,
            context.occurred_at.get(),
        )?;
    let (policy, policy_revision) = load_policy(transaction, command.policy_id.as_bytes())?;
    let identity_revision = read_identity_revision(transaction)?;
    let activation = policy
        .activate(AccessActivationRequest {
            operation_id: context.operation_id,
            principal_id: command.principal_id,
            subject: ActivationSubject::Grant(command.grant_id),
            source_is_authorized: source_authorised,
            identity_revision,
            source_revision: Revision::new(parse_u64(grant.4)?),
            policy_revision,
            reason: &command.reason,
            duration: command.duration,
            now: context.occurred_at,
            session_expires_at: command.session_expires_at,
            assurance: command.assurance,
            source_window: AccessWindow {
                valid_from: grant.1.map(meshspan_domain::UnixMicros::new),
                valid_until: grant.2.map(meshspan_domain::UnixMicros::new),
            },
        })
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let activation_id = command.activation_id.as_bytes();
    let principal = command.principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO access_activations(
            activation_id, principal_id, group_id, grant_id, policy_id, reason,
            authentication_digest, identity_revision, source_revision, policy_revision,
            activated_at, expires_at, revoked_at, revision
         ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12)",
        params![
            activation_id.as_slice(),
            principal.as_slice(),
            grant_id.as_slice(),
            command.policy_id.as_bytes().as_slice(),
            activation.reason(),
            command.authentication_digest.as_slice(),
            to_i64(activation.identity_revision().get())?,
            to_i64(activation.source_revision().get())?,
            to_i64(activation.policy_revision().get())?,
            activation.activated_at().get(),
            activation.expires_at().get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::AccessActivation,
        id: activation_id,
    })
}

pub(super) fn activate_group(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ActivateGroup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    require_user(transaction, command.principal_id)?;
    validate_activation_session(
        transaction,
        command.principal_id,
        command.authentication_digest,
        command.assurance,
        command.session_expires_at,
        context.occurred_at,
    )?;
    let group_id = command.group_id.as_bytes();
    let group = transaction
        .query_row(
            "SELECT g.activation_policy_id, p.revision
             FROM groups g JOIN principals p ON p.principal_id = g.principal_id
             WHERE g.principal_id = ?1 AND p.state = 1",
            [group_id.as_slice()],
            |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if group.0.as_deref() != Some(command.policy_id.as_bytes().as_slice())
        || !active_structural_group_path(
            transaction,
            command.group_id,
            command.principal_id,
            context.occurred_at.get(),
        )?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let (policy, policy_revision) = load_policy(transaction, command.policy_id.as_bytes())?;
    let identity_revision = read_identity_revision(transaction)?;
    let activation = policy
        .activate(AccessActivationRequest {
            operation_id: context.operation_id,
            principal_id: command.principal_id,
            subject: ActivationSubject::Group(command.group_id),
            source_is_authorized: true,
            identity_revision,
            source_revision: Revision::new(parse_u64(group.1)?),
            policy_revision,
            reason: &command.reason,
            duration: command.duration,
            now: context.occurred_at,
            session_expires_at: command.session_expires_at,
            assurance: command.assurance,
            source_window: AccessWindow::default(),
        })
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let activation_id = command.activation_id.as_bytes();
    let principal = command.principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO access_activations(
            activation_id, principal_id, group_id, grant_id, policy_id, reason,
            authentication_digest, identity_revision, source_revision, policy_revision,
            activated_at, expires_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12)",
        params![
            activation_id.as_slice(),
            principal.as_slice(),
            group_id.as_slice(),
            command.policy_id.as_bytes().as_slice(),
            activation.reason(),
            command.authentication_digest.as_slice(),
            to_i64(activation.identity_revision().get())?,
            to_i64(activation.source_revision().get())?,
            to_i64(activation.policy_revision().get())?,
            activation.activated_at().get(),
            activation.expires_at().get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::AccessActivation,
        id: activation_id,
    })
}

pub(super) fn revoke_access_activation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeAccessActivation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_revocation_reason(&command.reason)?;
    let activation = command.activation_id.as_bytes();
    let principal = command.principal_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE access_activations
         SET revoked_at = ?1, revoked_by = ?2, revocation_reason = ?3, revision = ?4
         WHERE activation_id = ?5 AND principal_id = ?6
           AND revoked_at IS NULL AND activated_at <= ?1",
        params![
            context.occurred_at.get(),
            actor.as_slice(),
            command.reason.as_str(),
            to_i64(revision.get())?,
            activation.as_slice(),
            principal.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::AccessActivation,
        id: activation,
    })
}

fn validate_revocation_reason(reason: &str) -> Result<(), RepositoryError> {
    let valid = !reason.trim().is_empty()
        && reason.len() <= MAXIMUM_REVOCATION_REASON_BYTES
        && !reason.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn insert_principal(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
    kind: u8,
    name: &crate::RecordName,
    context: CommandContext,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let principal = principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO principals(
            principal_id, principal_kind, display_name, canonical_name, state,
            created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            principal.as_slice(),
            kind,
            name.display(),
            name.canonical(),
            ACTIVE_STATE,
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(())
}

fn validate_scope(
    transaction: &Transaction<'_>,
    scope: PermissionScope,
) -> Result<ValidatedScope, RepositoryError> {
    match scope {
        PermissionScope::Global => Ok((1, None, None)),
        PermissionScope::Volume(volume) => {
            require_volume(transaction, volume.as_bytes())?;
            Ok((2, Some(volume.as_bytes()), None))
        }
        PermissionScope::Object {
            volume_id,
            object_id,
        } => {
            let object = object_id.as_bytes();
            let stored: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT volume_id FROM namespace_objects WHERE object_id = ?1 AND state = 1",
                    [object.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if stored.as_deref() != Some(volume_id.as_bytes().as_slice()) {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok((3, Some(volume_id.as_bytes()), Some(object)))
        }
    }
}

fn require_volume(transaction: &Transaction<'_>, volume: [u8; 16]) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM volumes WHERE volume_id = ?1 AND state = 1)",
        [volume.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_active_principal(
    transaction: &Transaction<'_>,
    principal: PrincipalId,
) -> Result<(), RepositoryError> {
    let identifier = principal.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id = ?1 AND state = 1)",
        [identifier.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_user(
    transaction: &Transaction<'_>,
    principal: PrincipalId,
) -> Result<(), RepositoryError> {
    let identifier = principal.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM users u JOIN principals p ON p.principal_id = u.principal_id
            WHERE u.principal_id = ?1 AND p.state = 1
         )",
        [identifier.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_activation_session(
    transaction: &Transaction<'_>,
    principal: PrincipalId,
    authentication_digest: [u8; 32],
    assurance: AssuranceLevel,
    expires_at: meshspan_domain::UnixMicros,
    now: meshspan_domain::UnixMicros,
) -> Result<(), RepositoryError> {
    let principal = principal.as_bytes();
    let identity_revision = read_identity_revision(transaction)?;
    let valid: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_sessions
            WHERE token_digest = ?1 AND user_principal_id = ?2 AND assurance = ?3
              AND identity_revision = ?4 AND issued_at <= ?5 AND expires_at = ?6
              AND expires_at > ?5 AND revoked_at IS NULL
         )",
        params![
            authentication_digest.as_slice(),
            principal.as_slice(),
            assurance_code(assurance),
            to_i64(identity_revision.get())?,
            now.get(),
            expires_at.get(),
        ],
        |row| row.get(0),
    )?;
    if valid == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_policy(transaction: &Transaction<'_>, policy: [u8; 16]) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM access_activation_policies WHERE policy_id = ?1)",
        [policy.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn load_policy(
    transaction: &Transaction<'_>,
    policy: [u8; 16],
) -> Result<(AccessActivationPolicy, Revision), RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT maximum_duration_micros, reason_required, minimum_assurance,
                    valid_from, valid_until, revision
             FROM access_activation_policies WHERE policy_id = ?1",
            [policy.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let maximum = meshspan_domain::DurationMicros::new(parse_u64(row.0)?);
    let policy = AccessActivationPolicy::new(
        maximum,
        row.1 == 1,
        parse_assurance(row.2)?,
        AccessWindow {
            valid_from: row.3.map(meshspan_domain::UnixMicros::new),
            valid_until: row.4.map(meshspan_domain::UnixMicros::new),
        },
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    Ok((policy, Revision::new(parse_u64(row.5)?)))
}

fn active_group_path(
    transaction: &Transaction<'_>,
    containing_group: GroupId,
    member: PrincipalId,
    now: i64,
) -> Result<bool, RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT gm.containing_group_id, gm.member_principal_id
         FROM group_memberships gm
         JOIN groups g ON g.principal_id = gm.containing_group_id
         WHERE gm.state = 1 AND gm.activation_required = 0 AND g.activation_policy_id IS NULL
           AND (gm.valid_from IS NULL OR gm.valid_from <= ?1)
           AND (gm.valid_until IS NULL OR gm.valid_until > ?1)
         ORDER BY gm.containing_group_id, gm.member_principal_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            now,
            to_i64(
                u64::try_from(MAXIMUM_MEMBERSHIP_EDGES + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            )?
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut edges = BTreeMap::<PrincipalId, BTreeSet<PrincipalId>>::new();
    let mut count = 0_usize;
    for row in rows {
        let (group, child) = row?;
        edges
            .entry(parse_principal(&group)?)
            .or_default()
            .insert(parse_principal(&child)?);
        count += 1;
        if count > MAXIMUM_MEMBERSHIP_EDGES {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    let mut pending = VecDeque::from([containing_group.principal_id()]);
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop_front() {
        if !visited.insert(current) {
            continue;
        }
        for child in edges.get(&current).cloned().unwrap_or_default() {
            if child == member {
                return Ok(true);
            }
            if edges.contains_key(&child) {
                pending.push_back(child);
            }
        }
    }
    Ok(false)
}

fn active_structural_group_path(
    transaction: &Transaction<'_>,
    containing_group: GroupId,
    member: PrincipalId,
    now: i64,
) -> Result<bool, RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT containing_group_id, member_principal_id
         FROM group_memberships
         WHERE state = 1 AND (valid_from IS NULL OR valid_from <= ?1)
           AND (valid_until IS NULL OR valid_until > ?1)
         ORDER BY containing_group_id, member_principal_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            now,
            to_i64(
                u64::try_from(MAXIMUM_MEMBERSHIP_EDGES + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            )?
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut edges = BTreeMap::<PrincipalId, BTreeSet<PrincipalId>>::new();
    let mut count = 0_usize;
    for row in rows {
        let (group, child) = row?;
        edges
            .entry(parse_principal(&group)?)
            .or_default()
            .insert(parse_principal(&child)?);
        count += 1;
        if count > MAXIMUM_MEMBERSHIP_EDGES {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    Ok(path_exists(&edges, containing_group.principal_id(), member))
}

fn path_exists(
    edges: &BTreeMap<PrincipalId, BTreeSet<PrincipalId>>,
    root: PrincipalId,
    target: PrincipalId,
) -> bool {
    let mut pending = VecDeque::from([root]);
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop_front() {
        if !visited.insert(current) {
            continue;
        }
        for child in edges.get(&current).cloned().unwrap_or_default() {
            if child == target {
                return true;
            }
            if edges.contains_key(&child) {
                pending.push_back(child);
            }
        }
    }
    false
}

fn read_identity_revision(transaction: &Transaction<'_>) -> Result<Revision, RepositoryError> {
    let value =
        transaction.query_row("SELECT identity_revision FROM meshes LIMIT 2", [], |row| {
            row.get::<_, i64>(0)
        })?;
    Ok(Revision::new(parse_u64(value)?))
}

fn update_identity_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE meshes SET identity_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn validate_window(start: Option<i64>, end: Option<i64>) -> Result<(), RepositoryError> {
    if matches!((start, end), (Some(start), Some(end)) if end <= start) {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn parse_principal(value: &[u8]) -> Result<PrincipalId, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    PrincipalId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn parse_assurance(value: i64) -> Result<AssuranceLevel, RepositoryError> {
    match value {
        1 => Ok(AssuranceLevel::SingleFactor),
        2 => Ok(AssuranceLevel::MultiFactor),
        3 => Ok(AssuranceLevel::RecentStepUp),
        _ => Err(RepositoryError::CorruptState),
    }
}

const fn assurance_code(value: AssuranceLevel) -> u8 {
    match value {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}

const fn inheritance_code(value: GrantInheritance) -> u8 {
    match value {
        GrantInheritance::Object => 1,
        GrantInheritance::Descendants => 2,
        GrantInheritance::ObjectAndDescendants => 3,
    }
}
