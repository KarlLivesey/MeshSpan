// SPDX-License-Identifier: GPL-2.0-only

//! Public API setup, durable work admission and readiness for the real maintenance fixture.

use super::super::current_stripe_targets;
use super::{StorageTargetRuntime, current_time, open_root_repository_at};
use crate::MaintenanceMetadataAuthority;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use meshspan_contracts::{ContractError, ContractVersion, RequestContext, ShardReceipt};
use meshspan_domain::{
    AuditEventId, DurationMicros, NamespaceCommitId, OperationId, PrincipalId, UnixMicros,
    VolumeId, WorkId,
};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, QueueMaintenanceWork};
use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};
use serde_json::{Value, json};
use std::error::Error;
use tower::ServiceExt;

/// Volume keys require the verified offline recipient, just as in the real
/// headless bootstrap workflow. Retain private temporary copies through verification.
pub(super) async fn save_and_verify_maintenance_recovery(
    router: &Router,
    created: &meshspan_api_contract::CreateMeshSetupResponse,
) -> Result<(), Box<dyn Error>> {
    let bundle = created.recovery_bundle.clone();
    let code = created.recovery_code.clone();
    let saved = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut bundle_file = tempfile::NamedTempFile::new()?;
        let mut code_file = tempfile::NamedTempFile::new()?;
        bundle_file.write_all(bundle.as_bytes())?;
        code_file.write_all(code.as_bytes())?;
        bundle_file.as_file().sync_all()?;
        code_file.as_file().sync_all()?;
        Ok::<_, std::io::Error>((bundle_file, code_file))
    })
    .await??;
    json_request(
        router,
        &created.api_key,
        "/api/latest/admin/recovery-bundle-verifications",
        json!({
            "operation_id": "00000000-0000-4000-8000-000000000073",
            "mesh_id": created.mesh_id,
            "recovery_challenge": created.recovery_challenge
        }),
        StatusCode::OK,
    )
    .await?;
    let bundle_matches =
        tokio::fs::read(saved.0.path()).await? == created.recovery_bundle.as_bytes();
    let code_matches = tokio::fs::read(saved.1.path()).await? == created.recovery_code.as_bytes();
    if !bundle_matches || !code_matches {
        return Err("saved recovery material changed during verification".into());
    }
    Ok(())
}

pub(super) async fn upload_maintenance_fixture(
    router: &Router,
    api_key: &str,
    administrator: PrincipalId,
) -> Result<(VolumeId, NamespaceCommitId), Box<dyn Error>> {
    let owner = meshspan_api_contract::OperationId::from_uuid_bytes(administrator.as_bytes())
        .ok_or("administrator UUID")?;
    let volume = json_request(
        router,
        api_key,
        "/api/latest/admin/volumes",
        json!({
            "operation_id": "00000000-0000-4000-8000-000000000074",
            "name": "Maintenance files", "owner_principal_ids": [owner.as_str()]
        }),
        StatusCode::CREATED,
    )
    .await?;
    let volume_text = volume["volume_id"].as_str().ok_or("volume id")?;
    let volume_id = VolumeId::from_bytes(crate::create_mesh_setup::parse_uuid(volume_text)?)?;
    let upload = json_request(router, api_key, &format!("/api/latest/volumes/{volume_text}/uploads"), json!({
        "operation_id": "00000000-0000-4000-8000-000000000075",
        "path": "scrub-evidence.txt", "disposition": {"mode": "create_new"}, "maximum_bytes": 1024
    }), StatusCode::CREATED).await?;
    let upload_id = upload["upload_id"].as_str().ok_or("upload id")?;
    let content = b"committed bytes survive unavailable repair placement";
    let digest = blake3::hash(content).to_hex().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::put(format!("/api/latest/uploads/{upload_id}/ranges/0"))
                .header("authorization", format!("Bearer {api_key}"))
                .header("content-type", "application/octet-stream")
                .header(
                    "MeshSpan-Operation-Id",
                    "00000000-0000-4000-8000-000000000076",
                )
                .header(
                    "MeshSpan-Stage-Fence",
                    upload["stage_fence"].as_u64().ok_or("stage fence")?,
                )
                .header("MeshSpan-Content-BLAKE3", &digest)
                .body(Body::from(content.as_slice()))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("range write returned {}", response.status()).into());
    }
    let checkpoint: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 64 * 1024).await?)?;
    let committed = json_request(router, api_key, &format!("/api/latest/uploads/{upload_id}/commits"), json!({
        "operation_id": "00000000-0000-4000-8000-000000000077",
        "stage_fence": checkpoint["stage_fence"], "expected_sequence": checkpoint["checkpoint_sequence"],
        "final_length": content.len(), "sparse": false, "expected_blake3": digest
    }), StatusCode::OK).await?;
    assert_eq!(committed["upload"]["state"], "committed");
    assert_eq!(
        committed["acknowledgement"]["acknowledged_consistency"],
        "eventual"
    );
    assert_eq!(
        committed["acknowledgement"]["durability_scope"],
        "node_local"
    );
    let expected_head = NamespaceCommitId::from_bytes(crate::create_mesh_setup::parse_uuid(
        committed["object"]["namespace_commit_id"]
            .as_str()
            .ok_or("uploaded namespace head")?,
    )?)?;
    Ok((volume_id, expected_head))
}

pub(super) async fn wait_for_uploaded_convergence(
    directory: std::path::PathBuf,
    volume: VolumeId,
    expected: NamespaceCommitId,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let path = directory.clone();
        let observed = tokio::task::spawn_blocking(move || {
            let now = current_time().map_err(|error| error.to_string())?;
            open_root_repository_at(&path, now)
                .map_err(|error| error.to_string())?
                .converged_volume_head(volume)
                .map_err(|error| error.to_string())
        })
        .await??;
        if observed.is_some_and(|head| head.namespace_commit_id == expected) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "upload head did not converge: expected {expected:?}, observed {observed:?}"
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn json_request(
    router: &Router,
    api_key: &str,
    path: &str,
    body: Value,
    expected: StatusCode,
) -> Result<Value, Box<dyn Error>> {
    let response = router
        .clone()
        .oneshot(
            Request::post(path)
                .header("authorization", format!("Bearer {api_key}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    if response.status() != expected {
        return Err(format!("{path} returned {}, expected {expected}", response.status()).into());
    }
    Ok(serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 64 * 1024).await?,
    )?)
}
pub(super) fn claimed_bootstrap_backup(
    runtime: &StorageTargetRuntime,
) -> Result<meshspan_metadata::MetadataBackupRun, Box<dyn Error>> {
    let reader = runtime.maintenance_authority.reader();
    let run = reader
        .unfinished_metadata_backup_run()?
        .ok_or("bootstrap backup run")?;
    assert_eq!(
        run.state,
        meshspan_metadata::MetadataBackupRunState::Claimed
    );
    assert!(run.completed_at.is_none());
    assert!(run.result_digest.is_none());
    let claim = reader
        .metadata_backup_run_claim(run.backup_id)?
        .ok_or("bootstrap backup claim")?;
    assert_eq!(claim.backup_id, run.backup_id);
    assert_eq!(claim.claim.worker_node_id, runtime.local_node_id);
    Ok(run)
}

pub(super) fn queue_work(
    runtime: &StorageTargetRuntime,
    subject: WorkSubject,
    identity: u8,
    now: UnixMicros,
) -> Result<WorkId, Box<dyn Error>> {
    let work_id = WorkId::from_bytes([identity; 16])?;
    runtime.maintenance_authority.commit(
        CommandContext {
            operation_id: OperationId::from_bytes([identity; 16])?,
            actor_principal_id: runtime
                .maintenance_actor(now)
                .map_err(|()| "maintenance actor")?,
            audit_event_id: AuditEventId::from_bytes([identity; 16])?,
            occurred_at: now,
            expected_revision: None,
        },
        &AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id,
            deduplication_key: [identity; 32],
            subject,
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 0,
                protection_debt: 1,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: now,
                due_at: Some(now),
            },
            demand: WorkDemand {
                in_flight_bytes: super::super::super::SCRUB_PAGE_IN_FLIGHT_BYTES,
            },
            next_attempt_at: now,
        }),
    )?;
    Ok(work_id)
}

/// Exact independently queued subjects sharing one committed source stripe.
pub(super) struct QueuedMaintenanceFixture {
    pub(super) repair: WorkId,
    pub(super) scrub: WorkId,
    pub(super) receipt: ShardReceipt,
}

pub(super) fn queue_maintenance_fixture(
    runtime: &StorageTargetRuntime,
    volume: VolumeId,
    now: UnixMicros,
) -> Result<QueuedMaintenanceFixture, Box<dyn Error>> {
    let catalogue = runtime.native_filesystem.maintenance_catalogue(now)?;
    let page = catalogue.committed_volume_stripes(volume, None, 1)?;
    let record = page.stripes.as_slice().first().ok_or("committed stripe")?;
    let receipt = *record
        .stripe
        .receipts
        .as_slice()
        .first()
        .ok_or("durable shard receipt")?;
    let candidate = catalogue
        .shard_repair_candidate(receipt.target_id, receipt.target_generation, receipt.shard)?
        .ok_or("current repair candidate")?;
    assert_no_repair_destination(runtime, volume, &record.stripe, now)?;
    let repair = queue_work(
        runtime,
        WorkSubject::Repair {
            volume_id: volume,
            manifest_id: candidate.manifest_id,
            stripe_index: record.cursor.stripe_index,
            shard_index: receipt.shard.shard_index,
            source_generation: candidate.source_layout_generation,
        },
        121,
        now,
    )?;
    let scrub = queue_work(
        runtime,
        WorkSubject::Scrub {
            target_id: receipt.target_id,
            target_generation: receipt.target_generation,
        },
        122,
        now,
    )?;
    Ok(QueuedMaintenanceFixture {
        repair,
        scrub,
        receipt,
    })
}

fn assert_no_repair_destination(
    runtime: &StorageTargetRuntime,
    volume: VolumeId,
    stripe: &meshspan_filesystem::CommittedProtectedStripe,
    now: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let targets = runtime.active.values().cloned().collect::<Vec<_>>();
    assert_eq!(targets.len(), 1, "fixture has no spare provider");
    let configuration = runtime
        .native_filesystem
        .maintenance_protection_configuration(&targets, volume, now)?;
    let current_targets = current_stripe_targets(stripe).map_err(|()| "stripe targets")?;
    assert!(current_targets.contains(&targets[0].context().target_id));
    let result = configuration.plan_repair(
        &meshspan_placement::FaultAwarePlacement::new(),
        RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([120; 16])?,
            deadline: now
                .checked_add(DurationMicros::new(super::super::MAINTENANCE_LEASE_MICROS))
                .ok_or("planning deadline")?,
            expected_revision: Some(runtime.maintenance_authority.reader().current_revision()?),
        },
        stripe.stripe.coding_layout(),
        0,
        &current_targets,
    );
    assert!(
        matches!(result, Err(ContractError::ResourceExhausted)),
        "{result:?}"
    );
    Ok(())
}
