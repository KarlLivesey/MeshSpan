// SPDX-License-Identifier: GPL-2.0-only

//! Audited principal lifecycle transitions and atomic last-owner protection.

use std::collections::BTreeSet;

use meshspan_domain::{ObjectId, PrincipalId, Revision};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{update_identity_revision, validate_audit_reason};
use crate::repository::apply::to_i64;
use crate::repository::{EntityKind, EntityReference, RepositoryError, namespace};
use crate::{ChangePrincipalState, CommandContext, PrincipalLifecycleState};

const ACTIVE_STATE: u8 = 1;
const SUSPENDED_STATE: u8 = 2;
const RETIRED_STATE: u8 = 3;
const PRINCIPAL_USER: u8 = 1;
const PRINCIPAL_GROUP: u8 = 2;
const SYSTEM_MANAGE_RIGHT: i64 = 1;
const MAXIMUM_OWNER_TRANSFERS: usize = 1_000;

struct StoredPrincipal {
    kind: u8,
    state: u8,
    created_at: i64,
}

struct LifecycleEvent<'a> {
    principal_id: PrincipalId,
    event_kind: u8,
    prior_state: Option<u8>,
    resulting_state: u8,
    reason: Option<&'a str>,
    context: CommandContext,
    revision: Revision,
}

pub(super) fn record_principal_created(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
    context: CommandContext,
    revision: Revision,
) -> Result<(), RepositoryError> {
    insert_event(
        transaction,
        &LifecycleEvent {
            principal_id,
            event_kind: 1,
            prior_state: None,
            resulting_state: ACTIVE_STATE,
            reason: None,
            context,
            revision,
        },
    )
}

pub(in crate::repository) fn change_principal_state(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ChangePrincipalState,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_audit_reason(&command.reason)?;
    if command.owner_transfers.len() > MAXIMUM_OWNER_TRANSFERS {
        return Err(RepositoryError::CapacityExceeded);
    }
    let stored = load_principal(transaction, command.principal_id)?;
    if context.occurred_at.get() < stored.created_at {
        return Err(RepositoryError::InvalidCommand);
    }
    let (resulting_state, event_kind) = validate_transition(stored.state, command.state)?;
    if resulting_state == ACTIVE_STATE {
        if !command.owner_transfers.is_empty() {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        require_surviving_administrator(transaction, command.principal_id, context)?;
        replace_last_ownership(transaction, context, command, revision)?;
    }
    update_principal(
        transaction,
        context,
        command.principal_id,
        stored.state,
        resulting_state,
        revision,
    )?;
    insert_event(
        transaction,
        &LifecycleEvent {
            principal_id: command.principal_id,
            event_kind,
            prior_state: Some(stored.state),
            resulting_state,
            reason: Some(&command.reason),
            context,
            revision,
        },
    )?;
    update_identity_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: entity_kind(stored.kind)?,
        id: command.principal_id.as_bytes(),
    })
}

fn load_principal(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
) -> Result<StoredPrincipal, RepositoryError> {
    let principal = principal_id.as_bytes();
    transaction
        .query_row(
            "SELECT principal_kind, state, created_at
             FROM principals WHERE principal_id = ?1",
            [principal.as_slice()],
            |row| {
                Ok(StoredPrincipal {
                    kind: row.get(0)?,
                    state: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)
}

fn validate_transition(
    current: u8,
    requested: PrincipalLifecycleState,
) -> Result<(u8, u8), RepositoryError> {
    match (current, requested) {
        (ACTIVE_STATE, PrincipalLifecycleState::Suspended) => Ok((SUSPENDED_STATE, 2)),
        (SUSPENDED_STATE, PrincipalLifecycleState::Active) => Ok((ACTIVE_STATE, 3)),
        (ACTIVE_STATE | SUSPENDED_STATE, PrincipalLifecycleState::Retired) => {
            Ok((RETIRED_STATE, 4))
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn require_surviving_administrator(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
    context: CommandContext,
) -> Result<(), RepositoryError> {
    let principal = principal_id.as_bytes();
    let now = context.occurred_at.get();
    let is_administrator: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM role_grants rg
            JOIN roles r ON r.role_id = rg.role_id
            WHERE rg.principal_id = ?1 AND (r.system_rights & ?2) = ?2
              AND (rg.valid_from IS NULL OR rg.valid_from <= ?3)
              AND (rg.valid_until IS NULL OR rg.valid_until > ?3)
              AND rg.activation_policy_id IS NULL
         )",
        params![principal.as_slice(), SYSTEM_MANAGE_RIGHT, now],
        |row| row.get(0),
    )?;
    if is_administrator == 0 {
        return Ok(());
    }
    let replacement_exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM role_grants rg
            JOIN roles r ON r.role_id = rg.role_id
            JOIN principals p ON p.principal_id = rg.principal_id
            WHERE rg.principal_id <> ?1 AND p.state = 1
              AND (r.system_rights & ?2) = ?2
              AND (rg.valid_from IS NULL OR rg.valid_from <= ?3)
              AND (rg.valid_until IS NULL OR rg.valid_until > ?3)
              AND rg.activation_policy_id IS NULL
         )",
        params![principal.as_slice(), SYSTEM_MANAGE_RIGHT, now],
        |row| row.get(0),
    )?;
    if replacement_exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn replace_last_ownership(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ChangePrincipalState,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let required = last_owned_objects(transaction, command.principal_id)?;
    let mut supplied_objects = BTreeSet::new();
    let mut supplied_owner_sets = BTreeSet::new();
    for transfer in command.owner_transfers.as_slice() {
        if transfer.owners.as_slice().contains(&command.principal_id)
            || !supplied_objects.insert(transfer.object_id)
            || !supplied_owner_sets.insert(transfer.owner_set_id)
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    let supplied_in_order = command
        .owner_transfers
        .as_slice()
        .iter()
        .map(|transfer| transfer.object_id);
    if supplied_objects != required || supplied_objects.iter().copied().ne(supplied_in_order) {
        return Err(RepositoryError::InvalidCommand);
    }
    namespace::replace_object_owner_sets(
        transaction,
        context,
        command.owner_transfers.as_slice(),
        revision,
    )
}

fn last_owned_objects(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
) -> Result<BTreeSet<ObjectId>, RepositoryError> {
    let principal = principal_id.as_bytes();
    let limit = i64::try_from(MAXIMUM_OWNER_TRANSFERS + 1)
        .map_err(|_| RepositoryError::CapacityExceeded)?;
    let mut statement = transaction.prepare(
        "SELECT n.object_id
         FROM namespace_objects n
         JOIN object_owners target ON target.owner_set_id = n.owner_set_id
         WHERE n.state = 1 AND target.owner_principal_id = ?1
           AND NOT EXISTS(
               SELECT 1 FROM object_owners alternative
               JOIN principals p ON p.principal_id = alternative.owner_principal_id
               WHERE alternative.owner_set_id = n.owner_set_id
                 AND alternative.owner_principal_id <> ?1 AND p.state = 1
           )
         ORDER BY n.object_id LIMIT ?2",
    )?;
    let rows = statement.query_map(params![principal.as_slice(), limit], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if objects.len() == MAXIMUM_OWNER_TRANSFERS {
            return Err(RepositoryError::CapacityExceeded);
        }
        let bytes: [u8; 16] = row?
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?;
        objects.insert(ObjectId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)?);
    }
    Ok(objects)
}

fn update_principal(
    transaction: &Transaction<'_>,
    context: CommandContext,
    principal_id: PrincipalId,
    prior_state: u8,
    resulting_state: u8,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let principal = principal_id.as_bytes();
    let retired_at = (resulting_state == RETIRED_STATE).then_some(context.occurred_at.get());
    let updated = transaction.execute(
        "UPDATE principals SET state = ?1, retired_at = ?2, revision = ?3
         WHERE principal_id = ?4 AND state = ?5 AND created_at <= ?6",
        params![
            resulting_state,
            retired_at,
            to_i64(revision.get())?,
            principal.as_slice(),
            prior_state,
            context.occurred_at.get(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn insert_event(
    transaction: &Transaction<'_>,
    event: &LifecycleEvent<'_>,
) -> Result<(), RepositoryError> {
    let principal = event.principal_id.as_bytes();
    let actor = event.context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO principal_lifecycle_events(
            principal_id, event_kind, prior_state, resulting_state, reason,
            changed_by, changed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            principal.as_slice(),
            event.event_kind,
            event.prior_state,
            event.resulting_state,
            event.reason,
            actor.as_slice(),
            event.context.occurred_at.get(),
            to_i64(event.revision.get())?,
        ],
    )?;
    Ok(())
}

const fn entity_kind(kind: u8) -> Result<EntityKind, RepositoryError> {
    match kind {
        PRINCIPAL_USER => Ok(EntityKind::User),
        PRINCIPAL_GROUP => Ok(EntityKind::Group),
        _ => Err(RepositoryError::InvalidCommand),
    }
}
