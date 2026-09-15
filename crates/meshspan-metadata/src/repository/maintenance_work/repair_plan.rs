// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned physical intent survives worker loss; it is never a durability receipt.

use meshspan_contracts::ReservationClass;
use meshspan_domain::{Revision, WorkId};
use meshspan_work::WorkSubject;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    AuthoritativeRepository, EntityReference, RepositoryError, entity, load_job_for_transition,
    require_live_claim, to_i64, validate_worker,
};
use crate::{
    AuthoritativeCommand, CommandContext, PlanShardRepair, decode_authoritative_command,
    encode_authoritative_command,
};

/// Last committed plan for one repair job, including its exact claim-specific control requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardRepairAttemptRecord {
    /// Context of the plan mutation, not the later physical write or effect.
    pub context: CommandContext,
    /// Immutable physical selection and current claim's control contexts.
    pub plan: PlanShardRepair,
    /// Revision which retained this claim's plan.
    pub revision: Revision,
}

impl AuthoritativeRepository {
    /// Loads the same physical repair intent after restart or worker takeover.
    /// # Errors
    /// Rejects malformed, oversized, unsupported or inconsistently indexed persisted plans.
    pub fn shard_repair_attempt(
        &self,
        work: WorkId,
    ) -> Result<Option<ShardRepairAttemptRecord>, RepositoryError> {
        load(self.database.connection(), work)
    }
}

pub(in crate::repository) fn plan(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &PlanShardRepair,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(
        transaction,
        value.claim.worker_node_id,
        value.claim.worker_incarnation,
    )?;
    let claim = require_live_claim(
        transaction,
        context,
        value.claim.work_id,
        value.claim.claim_generation,
        value.claim.worker_node_id,
        value.claim.worker_incarnation,
        value.claim.fence,
    )?;
    if claim.lease_expires_at != value.claim.lease_expires_at.get() {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_source(transaction, value)?;
    validate_contexts(context, value)?;
    if let Some(prior) = load(transaction, value.claim.work_id)? {
        validate_takeover(&prior.plan, value)?;
    }
    validate_control_operations(transaction, value)?;
    let bytes =
        encode_authoritative_command(context, &AuthoritativeCommand::PlanShardRepair(*value))
            .map_err(|_| RepositoryError::InvalidCommand)?;
    if bytes.len() > 1024 {
        return Err(RepositoryError::CapacityExceeded);
    }
    transaction.execute("INSERT INTO maintenance_repair_attempts(work_id, provider_operation_id,
        effect_operation_id, completion_operation_id, plan_operation_id, command_version, command_bytes, revision)
        VALUES (?1, ?2, ?3, ?4, ?5, 21, ?6, ?7)
        ON CONFLICT(work_id) DO UPDATE SET effect_operation_id = excluded.effect_operation_id,
        completion_operation_id = excluded.completion_operation_id, plan_operation_id = excluded.plan_operation_id,
        command_version = excluded.command_version, command_bytes = excluded.command_bytes, revision = excluded.revision",
        params![value.claim.work_id.as_bytes().as_slice(), value.intent.context.operation_id.as_bytes().as_slice(),
            value.effect_context.operation_id.as_bytes().as_slice(), value.completion_context.operation_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(), bytes, to_i64(revision.get())?])?;
    Ok(entity(value.claim.work_id))
}

pub(super) fn validate_effect(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &crate::CommitShardRepair,
) -> Result<(), RepositoryError> {
    // Pre-version-20 effects remain replayable. Once a plan exists, every effect is bound to it.
    let Some(record) = load(transaction, value.work_id)? else {
        return Ok(());
    };
    let plan = record.plan;
    let replacement = value.replacement_receipt;
    let claim_matches = plan.claim.claim_generation == value.claim_generation
        && plan.claim.worker_node_id == value.worker_node_id
        && plan.claim.worker_incarnation == value.worker_incarnation
        && plan.claim.fence == value.fence;
    let physical_matches = replacement.operation_id == plan.intent.context.operation_id
        && replacement.target_id == plan.intent.target_id
        && replacement.target_generation == plan.intent.target_generation
        && replacement.shard == plan.intent.shard
        && replacement.length == plan.intent.expected_length
        && replacement.digest == plan.intent.expected_digest;
    if !claim_matches
        || !physical_matches
        || context != plan.effect_context
        || value.source_layout_generation != plan.source_layout_generation
        || value.source_receipt != plan.source_receipt
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn load(
    connection: &Connection,
    work: WorkId,
) -> Result<Option<ShardRepairAttemptRecord>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT plan_operation_id, provider_operation_id,
        effect_operation_id, completion_operation_id, command_version,
        CASE WHEN length(command_bytes) <= 1024 THEN command_bytes ELSE NULL END, revision
        FROM maintenance_repair_attempts WHERE work_id = ?1",
            [work.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((operation, provider, effect, completion, version, bytes, revision)) = row else {
        return Ok(None);
    };
    if !matches!(version, 20 | 21) {
        return Err(RepositoryError::CorruptState);
    }
    let decoded = decode_authoritative_command(&bytes.ok_or(RepositoryError::CorruptState)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let AuthoritativeCommand::PlanShardRepair(plan) = decoded.command else {
        return Err(RepositoryError::CorruptState);
    };
    if (version == 20 && plan.intent.shard != plan.source_receipt.shard)
        || plan.claim.work_id != work
        || decoded.context.operation_id.as_bytes().as_slice() != operation
        || plan.intent.context.operation_id.as_bytes().as_slice() != provider
        || plan.effect_context.operation_id.as_bytes().as_slice() != effect
        || plan.completion_context.operation_id.as_bytes().as_slice() != completion
    {
        return Err(RepositoryError::CorruptState);
    }
    validate_contexts(decoded.context, &plan).map_err(|_| RepositoryError::CorruptState)?;
    let committed = connection.query_row(
        "SELECT request_digest, operation_kind, revision FROM operations WHERE operation_id = ?1",
        [decoded.context.operation_id.as_bytes().as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
    ).optional()?.ok_or(RepositoryError::CorruptState)?;
    if committed.0 != AuthoritativeCommand::PlanShardRepair(plan).request_digest(decoded.context)
        || committed.1 != 167
        || committed.2 != revision
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(ShardRepairAttemptRecord {
        context: decoded.context,
        plan,
        revision: Revision::new(super::positive(revision)?),
    }))
}

fn validate_source(
    transaction: &Transaction<'_>,
    value: &PlanShardRepair,
) -> Result<(), RepositoryError> {
    value
        .intent
        .validate()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let WorkSubject::Repair {
        volume_id,
        manifest_id,
        stripe_index,
        shard_index,
        source_generation,
    } = load_job_for_transition(transaction, value.claim.work_id)?.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let source = value.source_receipt;
    let intent = value.intent;
    if !super::repair::valid_receipt(source)
        || intent.reservation_class != ReservationClass::Repair
        || source_generation != value.source_layout_generation
        || source.shard.stripe_index != stripe_index
        || source.shard.shard_index != shard_index
        || !super::repair::valid_replacement_identity(source.shard, intent.shard)
        || source.length != intent.expected_length
        || intent.maximum_bytes != intent.expected_length
        || source.digest != intent.expected_digest
        || source.operation_id == intent.context.operation_id
        || (source.target_id == intent.target_id
            && source.target_generation == intent.target_generation)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if !super::entity_exists(
        transaction,
        "volumes",
        "volume_id",
        volume_id.as_bytes(),
        Some("state = 1"),
    )? || !super::repair::target_generation_exists(
        transaction,
        source.target_id,
        source.target_generation,
    )? || !super::repair::active_target_generation_exists(
        transaction,
        intent.target_id,
        intent.target_generation,
    )? {
        return Err(RepositoryError::InvalidCommand);
    }
    let current = transaction
        .query_row(
            "SELECT volume_id, manifest_digest, current_layout_generation
        FROM maintenance_repair_stripes WHERE manifest_id = ?1 AND stripe_index = ?2",
            params![manifest_id.as_bytes().as_slice(), to_i64(stripe_index)?],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    match current {
        Some((volume, digest, generation))
            if volume == volume_id.as_bytes()
                && digest == source.shard.manifest_digest
                && super::positive(generation)? == source_generation => {}
        None if source_generation == 1 => {}
        Some(_) | None => return Err(RepositoryError::InvalidCommand),
    }
    super::repair::validate_source_route(transaction, manifest_id, source)?;
    let completed: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM maintenance_repair_effects WHERE work_id = ?1)",
        [value.claim.work_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if completed {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_contexts(
    context: CommandContext,
    value: &PlanShardRepair,
) -> Result<(), RepositoryError> {
    let effect = value.effect_context;
    let completion = value.completion_context;
    if context.operation_id == value.intent.context.operation_id
        || effect.operation_id == completion.operation_id
        || effect.audit_event_id == completion.audit_event_id
    {
        return Err(RepositoryError::InvalidCommand);
    }
    for control in [effect, completion] {
        if control.operation_id == context.operation_id
            || control.operation_id == value.intent.context.operation_id
            || control.audit_event_id == context.audit_event_id
            || control.actor_principal_id != context.actor_principal_id
            || control.occurred_at != context.occurred_at
            || control.expected_revision.is_some()
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

fn validate_takeover(
    prior: &PlanShardRepair,
    next: &PlanShardRepair,
) -> Result<(), RepositoryError> {
    if prior.intent != next.intent
        || prior.source_receipt != next.source_receipt
        || prior.source_layout_generation != next.source_layout_generation
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if next.claim.claim_generation == prior.claim.claim_generation {
        if next != prior {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        if next.claim.claim_generation < prior.claim.claim_generation {
            return Err(RepositoryError::InvalidCommand);
        }
        let operations = [
            prior.effect_context.operation_id,
            prior.completion_context.operation_id,
        ];
        let audits = [
            prior.effect_context.audit_event_id,
            prior.completion_context.audit_event_id,
        ];
        for context in [next.effect_context, next.completion_context] {
            if operations.contains(&context.operation_id)
                || audits.contains(&context.audit_event_id)
            {
                return Err(RepositoryError::InvalidCommand);
            }
        }
    }
    Ok(())
}

fn validate_control_operations(
    transaction: &Transaction<'_>,
    value: &PlanShardRepair,
) -> Result<(), RepositoryError> {
    for operation in [
        value.effect_context.operation_id,
        value.completion_context.operation_id,
    ] {
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id = ?1)
            OR EXISTS(SELECT 1 FROM maintenance_repair_attempts WHERE work_id != ?2
                AND (effect_operation_id = ?1 OR completion_operation_id = ?1))",
            params![
                operation.as_bytes().as_slice(),
                value.claim.work_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        if exists {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}
