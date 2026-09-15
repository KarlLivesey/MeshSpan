// SPDX-License-Identifier: GPL-2.0-only

#[path = "appliance_maintenance_setup.rs"]
mod setup;

use setup::{
    claimed_bootstrap_backup, save_and_verify_maintenance_recovery, upload_maintenance_fixture,
    wait_for_uploaded_convergence,
};

use super::{
    ShutdownOutcome, StorageTargetRuntime, compose_appliance_services,
    configure_lifecycle_mesh_with_response, current_time, initialise_daemon_node, lifecycle_config,
    open_root_repository_at, start_private_authority,
};
use crate::MaintenanceMetadataAuthority;
use meshspan_domain::{AuditEventId, DurationMicros, OperationId, UnixMicros, VolumeId, WorkId};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, MaintenanceWorkState, QueueMaintenanceWork,
};
use meshspan_work::{WorkKind, WorkSubject};
use std::{error::Error, sync::Arc};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_repair_does_not_starve_persisted_scrub_effect() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let config = lifecycle_config(directory.path(), &occupied.local_addr()?.to_string())?;
    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let private = start_private_authority(&mut node, &config, now).await?;
    let (restart, _requests) = tokio::sync::mpsc::unbounded_channel();
    let services = compose_appliance_services(&mut node, &private, &config, restart, now)?;
    let (delivery_stop, delivery_stopped) = tokio::sync::watch::channel(false);
    let delivery = tokio::spawn(
        services
            .namespace_delivery
            .clone()
            .run_until(delivery_stopped),
    );
    let proof = async {
        let (administrator, created) =
            configure_lifecycle_mesh_with_response(&node, services.router.clone()).await?;
        save_and_verify_maintenance_recovery(&services.router, &created).await?;
        let (volume, expected_head) =
            upload_maintenance_fixture(&services.router, &created.api_key, administrator).await?;
        wait_for_uploaded_convergence(
            node.local_state.state_directory().to_path_buf(),
            volume,
            expected_head,
        )
        .await?;
        let targets = Arc::clone(&services.storage_targets);
        // The real owner may synchronously wait for consensus/provider IO. Keep it on
        // the same owned blocking boundary used by the appliance reconciler.
        tokio::task::spawn_blocking(move || {
            let mut runtime = targets
                .lock()
                .map_err(|_| "storage owner poisoned".to_owned())?;
            prove_scrub_progress(&mut runtime, volume).map_err(|error| error.to_string())
        })
        .await??;
        Ok::<(), Box<dyn Error>>(())
    }
    .await;
    // Signal and join the real convergence owner before its authority is drained.
    // Even a failed blocking proof cannot abandon an admitted delivery operation.
    delivery_stop.send_replace(true);
    let delivery_result = delivery.await;
    drop(services);
    let mut cleanup = ShutdownOutcome::default();
    private.drain(&mut cleanup).await;
    cleanup.finish()?;
    delivery_result?;
    proof
}

fn prove_scrub_progress(
    runtime: &mut StorageTargetRuntime,
    volume: VolumeId,
) -> Result<(), Box<dyn Error>> {
    let now = current_time()?;
    let drain = setup::queue_empty_target_drain(runtime, now)?;
    let setup::QueuedMaintenanceFixture {
        unavailable_repair,
        repair,
        scrub,
        receipt,
    } = setup::queue_maintenance_fixture(runtime, volume, now)?;
    assert_only_local_candidates_are_reserved(runtime, repair, scrub, now)?;
    assert!(
        runtime
            .maintenance_progress
            .scrub_progress(scrub)?
            .is_none()
    );
    assert!(
        runtime
            .maintenance_authority
            .reader()
            .maintenance_effect_reference(scrub)?
            .is_none()
    );
    let backup = claimed_bootstrap_backup(runtime)?;
    let tick = runtime.run_maintenance_tick(now);
    // Reopen authoritative persistence independently: a tick/error count is not
    // evidence that this exact target generation was actually read and verified.
    let reopened = open_root_repository_at(&runtime.state_directory, now)?;
    let work = reopened
        .maintenance_work(scrub)?
        .ok_or("persisted scrub work")?;
    assert_eq!(
        work.state,
        MaintenanceWorkState::Complete,
        "blocked repair must not prevent this independent scrub; tick={tick:?}"
    );
    let effect = reopened
        .maintenance_effect_reference(scrub)?
        .ok_or("committed scrub effect")?;
    let pass = reopened
        .scrub_pass_effect(effect.operation_id)?
        .ok_or("scrub pass summary")?;
    assert_eq!(
        (pass.work_id, pass.target_id, pass.target_generation),
        (scrub, receipt.target_id, receipt.target_generation)
    );
    assert_eq!(pass.observation_count, 1);
    assert_eq!(pass.outcome_counts, [1, 0, 0, 0, 0, 0]);
    assert_eq!(pass.verified_bytes, receipt.length);
    let progress = runtime
        .maintenance_progress
        .scrub_progress(scrub)?
        .ok_or("persisted local scrub checkpoint")?;
    assert!(progress.complete);
    assert!(progress.revision > 0);
    assert!(
        tick.is_err(),
        "successful scrub must not hide repair deferral"
    );
    let unavailable = reopened
        .maintenance_work(unavailable_repair)?
        .ok_or("unprojected repair")?;
    assert_eq!(unavailable.state, MaintenanceWorkState::Queued);
    assert_eq!(
        unavailable.attempt_count, 0,
        "local manifest absence must not claim another executor's work"
    );
    assert_empty_target_drain_completed(&reopened, runtime.local_node_id, drain, now)?;
    assert_bootstrap_backup_protected(&reopened, backup, now)?;
    assert_repair_retry_schedule(runtime, repair, now)?;
    Ok(())
}

fn assert_only_local_candidates_are_reserved(
    runtime: &mut StorageTargetRuntime,
    repair: WorkId,
    scrub: WorkId,
    now: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    // Keep the real provider alive while modelling a runtime that has not opened this target.
    let active = std::mem::take(&mut runtime.active);
    let closed = runtime.next_maintenance_assignment(now, WorkKind::Scrub);
    runtime.active = active;
    let repair_selected = runtime
        .next_maintenance_assignment(now, WorkKind::Repair)
        .map_err(|()| "repair selection")?
        .map(|work| work.work_id);
    assert_eq!(
        (
            closed
                .map_err(|()| "closed target selection")?
                .map(|work| work.work_id),
            repair_selected
        ),
        (None, Some(repair)),
        "selection must skip unopened targets and manifests absent from this executor",
    );
    assert_eq!(
        runtime
            .next_maintenance_assignment(now, WorkKind::Scrub)
            .map_err(|()| "scrub selection")?
            .ok_or("scrub assignment")?
            .work_id,
        scrub,
    );
    // Inspection consumed only ephemeral scan positions; the composed tick starts fresh.
    runtime.maintenance_cursors.clear();
    Ok(())
}

fn assert_empty_target_drain_completed(
    reopened: &meshspan_metadata::AuthoritativeRepository,
    local_node: meshspan_domain::NodeId,
    expected: (WorkId, meshspan_work::DrainScope),
    tick: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let (work_id, scope) = expected;
    let work = reopened.maintenance_work(work_id)?.ok_or("drain work")?;
    assert_eq!(work.state, MaintenanceWorkState::Complete);
    assert_eq!(work.attempt_count, 1);
    let effect = reopened
        .maintenance_effect_reference(work_id)?
        .ok_or("terminal drain effect")?;
    assert_eq!(work.result_digest, Some(effect.result_digest));
    let drain = reopened.storage_drain(work_id)?.ok_or("completed drain")?;
    assert_eq!(drain.scope, scope);
    assert_eq!(
        drain.state,
        meshspan_metadata::StorageDrainState::SafeToDetach
    );
    assert!(drain.safe_at.is_some_and(|safe| safe >= tick));
    assert!(!reopened.target_drain_attestation_pending(work_id, local_node)?);
    Ok(())
}

fn assert_bootstrap_backup_protected(
    reopened: &meshspan_metadata::AuthoritativeRepository,
    before: meshspan_metadata::MetadataBackupRun,
    tick: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let run = reopened
        .metadata_backup_run(before.backup_id)?
        .ok_or("same bootstrap backup run")?;
    assert_eq!(
        run.state,
        meshspan_metadata::MetadataBackupRunState::Protected
    );
    assert_eq!(
        (
            run.partition_id,
            run.schedule_sequence,
            run.run_sequence,
            run.scheduled_for
        ),
        (
            before.partition_id,
            before.schedule_sequence,
            before.run_sequence,
            before.scheduled_for
        )
    );
    assert!(run.completed_at.is_some_and(|completed| completed >= tick));
    assert!(run.revision > before.revision);
    assert!(
        reopened
            .metadata_backup_run_claim(before.backup_id)?
            .is_none()
    );
    let backup = reopened
        .metadata_backup(before.backup_id)?
        .ok_or("recorded encrypted backup")?;
    assert_eq!(
        backup.state,
        meshspan_metadata::MetadataBackupState::Verified
    );
    assert_eq!(backup.partition_id, before.partition_id);
    let evidence = reopened.metadata_backup_protection_evidence(before.backup_id)?;
    assert_eq!(evidence.backup_id, before.backup_id);
    assert!(evidence.verified_copies >= u64::from(before.minimum_verified_copies));
    assert!(evidence.independent_copies >= u64::from(before.minimum_independent_copies));
    assert_eq!(run.result_digest, Some(evidence.digest));
    Ok(())
}

fn assert_repair_retry_schedule(
    runtime: &mut StorageTargetRuntime,
    repair: WorkId,
    now: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let first_retry = persisted_retry_time(runtime, repair, 1, now)?;
    assert_retry_state(runtime, repair, 1, first_retry)?;
    let early = UnixMicros::new(first_retry.get().checked_sub(1).ok_or("early tick")?);
    runtime
        .run_maintenance_tick(early)
        .map_err(|_| "independent early tick failed")?;
    assert_retry_state(runtime, repair, 1, first_retry)?;
    assert!(runtime.run_maintenance_tick(first_retry).is_err());
    let second_retry = persisted_retry_time(runtime, repair, 2, first_retry)?;
    assert_retry_state(runtime, repair, 2, second_retry)?;
    let next_tick = first_retry
        .checked_add(DurationMicros::new(1_000_000))
        .ok_or("next tick")?;
    let work = open_root_repository_at(&runtime.state_directory, next_tick)?
        .maintenance_work(repair)?
        .ok_or("retry job")?;
    // Repeated observation of this unchanged subject must not erase the durable
    // delay, including when a new scheduler generation re-admits the same work.
    runtime.maintenance_authority.commit(
        CommandContext {
            operation_id: OperationId::from_bytes([123; 16])?,
            actor_principal_id: runtime
                .maintenance_actor(next_tick)
                .map_err(|()| "maintenance actor")?,
            audit_event_id: AuditEventId::from_bytes([123; 16])?,
            occurred_at: next_tick,
            expected_revision: None,
        },
        &AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id: repair,
            deduplication_key: work.deduplication_key,
            subject: work.subject,
            signals: work.signals,
            demand: work.demand,
            next_attempt_at: next_tick,
        }),
    )?;
    assert!(
        runtime
            .next_maintenance_assignment(next_tick, WorkKind::Repair)
            .map_err(|()| "deferred selection")?
            .is_none()
    );
    runtime
        .run_maintenance_tick(next_tick)
        .map_err(|_| "next independent tick failed")?;
    assert_retry_state(runtime, repair, 2, second_retry)?;
    assert_repair_completes_when_destination_returns(runtime, repair, second_retry)?;
    Ok(())
}

fn assert_repair_completes_when_destination_returns(
    runtime: &mut StorageTargetRuntime,
    repair: WorkId,
    eligible_at: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let folder = runtime
        .state_directory
        .parent()
        .ok_or("fixture parent")?
        .join("replacement-storage");
    std::fs::create_dir(&folder)?;
    // The real configured-folder reconciler admits and opens the additional
    // provider, then runs the now-eligible repair through the same maintenance tick.
    runtime.configured_paths.push(folder);
    runtime.reconcile(eligible_at);
    assert_eq!(runtime.active.len(), 3);
    let reopened = open_root_repository_at(&runtime.state_directory, eligible_at)?;
    let work = reopened
        .maintenance_work(repair)?
        .ok_or("recovered repair")?;
    assert_eq!(work.state, MaintenanceWorkState::Complete);
    assert_eq!(
        work.attempt_count, 3,
        "successful planning and execution share one claim"
    );
    let effect = reopened
        .maintenance_effect_reference(repair)?
        .ok_or("repair effect")?;
    assert_eq!(work.result_digest, Some(effect.result_digest));
    let transition = reopened
        .shard_repair_effect(effect.operation_id)?
        .ok_or("repair transition")?;
    assert_eq!(transition.work_id, repair);
    assert_ne!(
        transition.source_receipt.target_id,
        transition.replacement_receipt.target_id
    );
    assert_eq!(
        transition.source_receipt.length,
        transition.replacement_receipt.length
    );
    assert_eq!(
        transition.source_receipt.digest,
        transition.replacement_receipt.digest
    );
    assert_eq!(transition.source_layout_generation, 1);
    assert_eq!(transition.replacement_layout_generation, 2);
    let catalogue = runtime
        .native_filesystem
        .maintenance_catalogue(eligible_at)?;
    let replacement = transition.replacement_receipt;
    let current = catalogue
        .shard_repair_candidate(
            replacement.target_id,
            replacement.target_generation,
            replacement.shard,
        )?
        .ok_or("installed replacement route")?;
    assert_eq!(current.source_receipt, replacement);
    assert_eq!(current.source_layout_generation, 2);
    super::super::repair::assert_deferral_time_and_revision(
        runtime,
        WorkSubject::Repair {
            volume_id: current.volume_id,
            manifest_id: current.manifest_id,
            stripe_index: replacement.shard.stripe_index,
            shard_index: replacement.shard.shard_index,
            source_generation: current.source_layout_generation,
        },
        eligible_at,
    )?;
    Ok(())
}

fn persisted_retry_time(
    runtime: &StorageTargetRuntime,
    repair: WorkId,
    generation: i64,
    tick: UnixMicros,
) -> Result<UnixMicros, Box<dyn Error>> {
    let connection = rusqlite::Connection::open_with_flags(
        runtime
            .state_directory
            .join(super::super::ROOT_AUTHORITY_DATABASE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (completed_at, retry_at): (i64, i64) = connection.query_row(
        "SELECT completed_at, retry_at FROM maintenance_work_claims
         WHERE work_id = ?1 AND claim_generation = ?2",
        rusqlite::params![repair.as_bytes().as_slice(), generation],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(completed_at >= tick.get());
    let delay = match generation {
        1 => 1_000_000,
        2 => 2_000_000,
        _ => return Err("unexpected retry generation".into()),
    };
    assert_eq!(retry_at.checked_sub(completed_at), Some(delay));
    Ok(UnixMicros::new(retry_at))
}

fn assert_retry_state(
    runtime: &StorageTargetRuntime,
    repair: WorkId,
    attempts: u64,
    retry_at: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let reopened = open_root_repository_at(&runtime.state_directory, retry_at)?;
    let work = reopened
        .maintenance_work(repair)?
        .ok_or("persisted repair")?;
    assert_eq!(work.state, MaintenanceWorkState::Queued);
    assert_eq!(work.attempt_count, attempts);
    assert_eq!(work.next_attempt_at, retry_at);
    assert!(work.completed_at.is_none());
    assert!(work.result_digest.is_none());
    assert!(reopened.maintenance_effect_reference(repair)?.is_none());
    // This is a test-only read of the existing terminal claim history. Production
    // has no public decoder for these typed deferral digests in this slice.
    let connection = rusqlite::Connection::open_with_flags(
        runtime
            .state_directory
            .join(super::super::ROOT_AUTHORITY_DATABASE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM maintenance_work_claims WHERE work_id = ?1",
        [repair.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let stored_attempts = i64::try_from(attempts)?;
    assert_eq!(count, stored_attempts, "one claim per attempted plan");
    let (state, digest, stored_retry): (i64, Vec<u8>, i64) = connection.query_row(
        "SELECT state, result_digest, retry_at FROM maintenance_work_claims
         WHERE work_id = ?1 AND claim_generation = ?2",
        rusqlite::params![repair.as_bytes().as_slice(), stored_attempts],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(state, 3, "claim completed as retry, not abandoned active");
    assert_eq!(stored_retry, retry_at.get());
    // SHA256 of the v1 reason domain followed by closed variant 1, computed
    // independently of the production reason encoder.
    assert_eq!(
        digest,
        [
            10, 236, 55, 83, 32, 150, 96, 28, 111, 125, 193, 204, 100, 2, 238, 130, 37, 159, 232,
            137, 247, 94, 52, 124, 47, 127, 51, 1, 155, 219, 97, 252
        ]
    );
    Ok(())
}

#[test]
fn maintenance_fences_fit_persistence_for_high_bit_entropy() -> Result<(), Box<dyn Error>> {
    for value in [0x80, 0xff] {
        let fence = super::super::random_maintenance_fence(&mut FenceEntropy(Some(value)))
            .map_err(|()| "nonzero entropy must produce a fence")?;
        assert!(fence > 0);
        assert!(
            i64::try_from(fence).is_ok(),
            "fence must fit SQLite INTEGER"
        );
    }
    assert!(super::super::random_maintenance_fence(&mut FenceEntropy(Some(0))).is_err());
    assert!(super::super::random_maintenance_fence(&mut FenceEntropy(None)).is_err());
    Ok(())
}

struct FenceEntropy(Option<u8>);

impl meshspan_domain::RandomSource for FenceEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), meshspan_domain::EntropyError> {
        destination.fill(self.0.ok_or(meshspan_domain::EntropyError)?);
        Ok(())
    }
}
