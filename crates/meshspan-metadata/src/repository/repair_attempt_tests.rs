// SPDX-License-Identifier: GPL-2.0-only

//! A replacement worker adopts the same physical repair and separately fenced control identities.

use super::*;
use crate::{PlanShardRepair, encode_authoritative_command};
use meshspan_contracts::{ContractVersion, RequestContext, ReservationClass, ShardPutIntent};

#[test]
fn repair_attempt_retains_physical_identity_across_reopen_and_claim_takeover()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("repair.sqlite3");
    let (mut fixture, mut plan) = prepare(&path)?;
    plan.intent.shard.generation = 2;
    fixture.apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))?;
    let retained = fixture
        .repository
        .shard_repair_attempt(plan.claim.work_id)?
        .ok_or("plan missing")?;
    assert_eq!(retained.plan, plan);
    assert_eq!(retained.revision, Revision::new(6));
    fixture = reopen(fixture, &path)?;
    assert_eq!(
        fixture
            .repository
            .shard_repair_attempt(plan.claim.work_id)?,
        Some(retained)
    );
    let claim = fixture.claim(plan.claim.work_id, 2, 778, 300);
    fixture.apply(7, 101, &AuthoritativeCommand::ClaimMaintenanceWork(claim))?;
    let next = PlanShardRepair {
        claim,
        effect_context: control(&fixture, 82, 182, 102)?,
        completion_context: control(&fixture, 83, 183, 102)?,
        ..plan
    };
    let changed = PlanShardRepair {
        intent: ShardPutIntent {
            context: RequestContext {
                operation_id: OperationId::from_bytes([99; 16])?,
                ..plan.intent.context
            },
            ..plan.intent
        },
        ..next
    };
    assert!(
        fixture
            .apply(8, 102, &AuthoritativeCommand::PlanShardRepair(changed))
            .is_err()
    );
    assert_eq!(
        fixture
            .repository
            .shard_repair_attempt(plan.claim.work_id)?,
        Some(retained)
    );
    reject_reused_control_identity(&mut fixture, &plan, &next);
    fixture.apply(8, 102, &AuthoritativeCommand::PlanShardRepair(next))?;
    let adopted = fixture
        .repository
        .shard_repair_attempt(plan.claim.work_id)?
        .ok_or("adopted plan missing")?;
    assert_eq!(adopted.plan.intent, plan.intent);
    assert_eq!(adopted.plan.source_receipt, plan.source_receipt);
    assert_eq!(adopted.plan.effect_context, next.effect_context);
    assert_eq!(adopted.plan.claim, claim);
    assert!(
        fixture
            .apply(9, 103, &AuthoritativeCommand::PlanShardRepair(plan))
            .is_err()
    );
    Ok(())
}

#[test]
fn repair_attempt_read_rejects_substituted_command_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("repair.sqlite3");
    let (mut fixture, plan) = prepare(&path)?;
    fixture.apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))?;
    let retained = fixture
        .repository
        .shard_repair_attempt(plan.claim.work_id)?
        .ok_or("plan missing")?;
    let changed = PlanShardRepair {
        intent: ShardPutIntent {
            expected_digest: [99; 32],
            ..plan.intent
        },
        ..plan
    };
    let bytes = encode_authoritative_command(
        retained.context,
        &AuthoritativeCommand::PlanShardRepair(changed),
    )?;
    fixture.repository.database.connection().execute(
        "UPDATE maintenance_repair_attempts SET command_bytes = ?1 WHERE work_id = ?2",
        rusqlite::params![bytes, plan.claim.work_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        fixture.repository.shard_repair_attempt(plan.claim.work_id),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn repair_attempt_fences_effect_identity_and_retains_versioned_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (mut fixture, plan) = prepare(&directory.path().join("repair.sqlite3"))?;
    fixture.apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))?;
    let retained = fixture
        .repository
        .shard_repair_attempt(plan.claim.work_id)?
        .ok_or("plan missing")?;
    let command = AuthoritativeCommand::PlanShardRepair(plan);
    let bytes = encode_authoritative_command(retained.context, &command)?;
    assert!(bytes.len() <= 1024);
    for version in [18, 19] {
        assert!(matches!(
            crate::decode_authoritative_entry_for_version(version, &bytes),
            Err(crate::MetadataCommandCodecError::Unsupported)
        ));
    }
    assert_eq!(
        crate::decode_authoritative_entry_for_version(20, &bytes)?.command,
        command
    );
    for length in 0..bytes.len() {
        assert!(crate::decode_authoritative_entry_for_version(20, &bytes[..length]).is_err());
    }
    let effect = effect(&fixture, &plan)?;
    let wrong = CommitShardRepair {
        replacement_receipt: ShardReceipt {
            operation_id: OperationId::from_bytes([99; 16])?,
            ..effect.replacement_receipt
        },
        ..effect
    };
    assert!(
        fixture
            .repository
            .apply_committed(
                LogPosition { index: 7, term: 1 },
                plan.effect_context,
                &AuthoritativeCommand::CommitShardRepair(wrong)
            )
            .is_err()
    );
    assert_eq!(fixture.repository.current_revision()?, Revision::new(6));
    let committed = fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        plan.effect_context,
        &AuthoritativeCommand::CommitShardRepair(effect),
    )?;
    assert_eq!(committed.operation_id, plan.effect_context.operation_id);
    let completion = CompleteMaintenanceWork {
        work_id: plan.claim.work_id,
        claim_generation: plan.claim.claim_generation,
        worker_node_id: plan.claim.worker_node_id,
        worker_incarnation: plan.claim.worker_incarnation,
        fence: plan.claim.fence,
        outcome: MaintenanceWorkCompletion::Succeeded {
            effect_operation_id: committed.operation_id,
            effect_revision: committed.committed_revision,
            effect_result_digest: committed.result_digest,
        },
    };
    fixture.repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        plan.completion_context,
        &AuthoritativeCommand::CompleteMaintenanceWork(completion),
    )?;
    assert_eq!(
        fixture.record(plan.claim.work_id)?.state,
        MaintenanceWorkState::Complete
    );
    Ok(())
}

#[test]
fn repair_attempt_migration_preserves_existing_schema_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("upgrade.sqlite3");
    let mut connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    crate::migration::migrate_partition_through(&mut connection, 120, 1)?;
    let digest: Vec<u8> = connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version = 120",
        [],
        |row| row.get(0),
    )?;
    crate::migration::migrate_partition(&mut connection, 2)?;
    drop(connection);
    let mut connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    crate::migration::migrate_partition(&mut connection, 3)?;
    assert_eq!(
        connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version = 120",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        digest
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM maintenance_repair_attempts",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    assert!(
        connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none()
    );
    Ok(())
}

fn reject_reused_control_identity(
    fixture: &mut Fixture,
    prior: &PlanShardRepair,
    next: &PlanShardRepair,
) {
    for effect_context in [
        CommandContext {
            operation_id: prior.completion_context.operation_id,
            ..next.effect_context
        },
        CommandContext {
            audit_event_id: prior.completion_context.audit_event_id,
            ..next.effect_context
        },
    ] {
        let changed = PlanShardRepair {
            effect_context,
            ..*next
        };
        assert!(
            fixture
                .apply(8, 102, &AuthoritativeCommand::PlanShardRepair(changed))
                .is_err()
        );
    }
}

fn effect(
    fixture: &Fixture,
    plan: &PlanShardRepair,
) -> Result<CommitShardRepair, meshspan_domain::IdentifierError> {
    Ok(CommitShardRepair {
        work_id: plan.claim.work_id,
        claim_generation: plan.claim.claim_generation,
        worker_node_id: plan.claim.worker_node_id,
        worker_incarnation: plan.claim.worker_incarnation,
        fence: plan.claim.fence,
        volume_id: fixture.volume,
        manifest_id: ContentManifestId::from_bytes([43; 16])?,
        source_layout_generation: plan.source_layout_generation,
        source_receipt: plan.source_receipt,
        replacement_receipt: ShardReceipt {
            operation_id: plan.intent.context.operation_id,
            shard: plan.intent.shard,
            length: plan.intent.expected_length,
            digest: plan.intent.expected_digest,
            target_id: plan.intent.target_id,
            target_generation: plan.intent.target_generation,
        },
    })
}

fn prepare(
    path: &std::path::Path,
) -> Result<(Fixture, PlanShardRepair), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::at(path)?;
    let source_target = TargetId::from_bytes([40; 16])?;
    let replacement_target = TargetId::from_bytes([41; 16])?;
    fixture.register_target(2, source_target, 50)?;
    fixture.register_target(3, replacement_target, 51)?;
    let work = WorkId::from_bytes([42; 16])?;
    let source = shard_receipt(44, source_target, 45)?;
    fixture.apply(
        4,
        60,
        &AuthoritativeCommand::QueueMaintenanceWork(fixture.repair_queue(
            work,
            ContentManifestId::from_bytes([43; 16])?,
            source.length,
        )),
    )?;
    let claim = fixture.claim(work, 1, 777, 100);
    fixture.apply(5, 61, &AuthoritativeCommand::ClaimMaintenanceWork(claim))?;
    let plan = PlanShardRepair {
        claim,
        source_layout_generation: 1,
        source_receipt: source,
        intent: ShardPutIntent {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([46; 16])?,
                deadline: UnixMicros::new(100),
                expected_revision: Some(Revision::new(5)),
            },
            target_id: replacement_target,
            target_generation: 1,
            reservation_class: ReservationClass::Repair,
            maximum_bytes: source.length,
            shard: source.shard,
            expected_length: source.length,
            expected_digest: source.digest,
        },
        effect_context: control(&fixture, 80, 180, 62)?,
        completion_context: control(&fixture, 81, 181, 62)?,
    };
    Ok((fixture, plan))
}

#[test]
fn repair_generation_advance_is_exact_persisted_and_version_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("generations.sqlite3");
    let (mut fixture, mut plan) = prepare(&path)?;
    plan.intent.shard.generation = 3;
    assert!(
        fixture
            .apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))
            .is_err()
    );
    assert_eq!(fixture.repository.current_revision()?, Revision::new(5));
    plan.intent.shard.generation = 2;
    fixture.apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))?;
    let effect = effect(&fixture, &plan)?;
    let command = AuthoritativeCommand::CommitShardRepair(effect);
    fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        plan.effect_context,
        &command,
    )?;
    for command in [AuthoritativeCommand::PlanShardRepair(plan), command] {
        let bytes = encode_authoritative_command(plan.effect_context, &command)?;
        assert!(matches!(
            crate::decode_authoritative_entry_for_version(20, &bytes),
            Err(crate::MetadataCommandCodecError::Unsupported)
        ));
        assert_eq!(
            crate::decode_authoritative_entry_for_version(21, &bytes)?.command,
            command
        );
    }
    fixture = reopen(fixture, &path)?;
    let stored = fixture
        .repository
        .shard_repair_effect(plan.effect_context.operation_id)?
        .ok_or("effect missing")?;
    assert_eq!(stored.source_receipt, plan.source_receipt);
    assert_eq!(stored.replacement_receipt, effect.replacement_receipt);
    assert_eq!(stored.source_receipt.shard.generation, 1);
    assert_eq!(stored.replacement_receipt.shard.generation, 2);
    Ok(())
}

fn control(
    fixture: &Fixture,
    operation: u8,
    audit: u8,
    now: i64,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: fixture.administrator,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(now),
        expected_revision: None,
    })
}

fn reopen(fixture: Fixture, path: &std::path::Path) -> Result<Fixture, Box<dyn std::error::Error>> {
    let Fixture {
        repository,
        administrator,
        node,
        host,
        volume,
    } = fixture;
    drop(repository);
    Ok(Fixture {
        repository: AuthoritativeRepository::new(PartitionDatabase::open_existing(
            path,
            UnixMicros::new(63),
        )?),
        administrator,
        node,
        host,
        volume,
    })
}

#[test]
fn migration122_preserves_legacy_repair_plan_and_both_original_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("legacy.sqlite3");
    let (mut fixture, plan) = prepare(&path)?;
    fixture.apply(6, 62, &AuthoritativeCommand::PlanShardRepair(plan))?;
    let effect = effect(&fixture, &plan)?;
    fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        plan.effect_context,
        &AuthoritativeCommand::CommitShardRepair(effect),
    )?;
    // Reconstruct schema 121, including removal of later log-accounting metadata.
    // The command and receipts retain their legacy same-generation representation.
    let database = &mut fixture.repository.database;
    let transaction = database.connection_mut().transaction()?;
    transaction.execute_batch(
        "ALTER TABLE maintenance_repair_effects DROP COLUMN replacement_shard_generation;
        ALTER TABLE maintenance_repair_attempts RENAME TO legacy_repair_attempts;",
    )?;
    transaction.execute_batch(include_str!(
        "../../schema/partition/121_repair_attempts.sql"
    ))?;
    transaction.execute_batch(
        "INSERT INTO maintenance_repair_attempts
        SELECT work_id, provider_operation_id, effect_operation_id, completion_operation_id,
            plan_operation_id, 20, command_bytes, revision FROM legacy_repair_attempts;
        DROP TABLE legacy_repair_attempts;
        DROP TABLE consensus_log_accounting;
        DELETE FROM schema_migrations WHERE version IN (122, 123);",
    )?;
    transaction.commit()?;
    fixture = reopen(fixture, &path)?;
    assert_eq!(
        fixture
            .repository
            .shard_repair_attempt(plan.claim.work_id)?
            .ok_or("plan missing")?
            .plan,
        plan
    );
    let stored = fixture
        .repository
        .shard_repair_effect(plan.effect_context.operation_id)?
        .ok_or("effect missing")?;
    assert_eq!(stored.source_receipt, effect.source_receipt);
    assert_eq!(stored.replacement_receipt, effect.replacement_receipt);
    assert_eq!(stored.replacement_receipt.shard.generation, 1);
    Ok(())
}
