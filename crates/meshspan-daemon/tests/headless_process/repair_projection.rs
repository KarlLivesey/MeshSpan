// SPDX-License-Identifier: GPL-2.0-only

//! A stale gateway follows committed repair routes after restart, without the old provider.

use meshspan_contracts::ShardReceipt;
use meshspan_filesystem::{DurableContentCatalog, RepairProjectionManifest};
use meshspan_metadata::{MaintenanceWorkState, PageLimit, ShardRepairEffectRecord};

use super::*;

const CONTENT: &[u8] = b"original bytes survive repair and a stale gateway restart";
const EMPTY_DRAIN_OPERATION: &str = "00000000-0000-4000-8000-000000000402";
const DRAIN_OPERATION: &str = "00000000-0000-4000-8000-000000000401";

#[tokio::test]
async fn stale_gateway_reads_original_bytes_after_committed_repair_and_provider_loss()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let gateway = ProcessFixture::new()?;
    let replacement = ProcessFixture::new()?;
    let mut processes = Vec::new();
    let proof = async {
        processes.push(root.start()?);
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &client, "claim_required").await?;
        let administrator = bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing setup API key")?;
        save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        wait_for_storage_folder_visibility(&root, &client, key).await?;
        let volume = create_volume(root.address, &client, key, &administrator).await?;
        // Publish before adding providers: the original immutable stripe has one route.
        upload_file(root.address, &client, key, &volume, CONTENT).await?;
        wait_for_file_surfaces(root.address, &client, key, &volume, CONTENT).await?;
        let (manifest, source) = original_route(&root)?;
        let join = issue_join_code(&root, &client, key).await?;
        processes.push(gateway.start_join(&join)?);
        let gateway_client = wait_for_client(&gateway.identity_path).await?;
        wait_for_status(gateway.address, &gateway_client, "configured").await?;
        wait_for_file_surfaces(gateway.address, &gateway_client, key, &volume, CONTENT).await?;
        assert_eq!(original_route(&gateway)?, (manifest, source));
        processes.push(replacement.start_join(&join)?);
        let replacement_client = wait_for_client(&replacement.identity_path).await?;
        wait_for_status(replacement.address, &replacement_client, "configured").await?;
        wait_for_live_provider(&replacement).await?;
        wait_for_three_voters([&root, &gateway, &replacement], &root.identity_path).await?;
        retire_empty_gateway(&gateway, &gateway_client, key).await?;
        // Keep this gateway's durable catalogue at the original route throughout the repair.
        stop_processes(&mut processes[1..2]);
        begin_drain(
            root.address,
            &client,
            key,
            serde_json::json!({
                "kind": "target", "target_id": uuid_text(source.target_id.as_bytes()),
                "generation": source.target_generation.to_string()
            }),
            DRAIN_OPERATION,
        )
        .await?;
        let effect = wait_for_repair(&root, &replacement, manifest, source).await?;
        assert_eq!(original_route(&gateway)?, (manifest, source));
        // The source process owns its only provider: stopping it makes that route unavailable.
        stop_processes(&mut processes[..1]);
        assert!(processes[0].try_wait()?.is_some());
        processes[1] = gateway.start()?;
        wait_for_status(gateway.address, &gateway_client, "configured").await?;
        wait_for_survivor_vote_convergence([&gateway, &replacement], &root.identity_path).await?;
        tokio::time::timeout(
            WAIT_LIMIT,
            wait_for_file_surfaces(gateway.address, &gateway_client, key, &volume, CONTENT),
        )
        .await
        .map_err(|_| "restarted stale gateway exceeded the original readback deadline")??;
        assert_projected(&gateway, manifest, &effect)?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(
        proof,
        [root.temporary, gateway.temporary, replacement.temporary],
    )
}

async fn retire_empty_gateway(
    gateway: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
) -> Result<(), Box<dyn Error>> {
    let journal = wait_for_live_provider(gateway).await?;
    let provider =
        rusqlite::Connection::open_with_flags(journal, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let receipts: i64 = provider.query_row(
        "SELECT COUNT(*) FROM provider_operations WHERE receipt IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        receipts, 0,
        "priming the remote catalogue must not store provider payloads"
    );
    drop(provider);
    let authorization = format!("Bearer {key}");
    let response = tokio::time::timeout(
        WAIT_LIMIT,
        request_with_headers(
            gateway.address,
            client,
            "GET",
            "/api/latest/admin/storage-folders?limit=100",
            None,
            &[("Authorization", authorization.as_str())],
        ),
    )
    .await
    .map_err(|_| "empty gateway target inventory timed out")??;
    require_status(&response, "200 OK", "identify empty gateway target")?;
    let inventory: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let folders = inventory["folders"]
        .as_array()
        .ok_or("missing gateway folder inventory")?;
    assert_eq!(
        folders.len(),
        1,
        "gateway fixture must have exactly one local target"
    );
    let folder = folders.first().ok_or("gateway target absent")?;
    assert_eq!(
        folder["node_id"],
        uuid_text(fixture_node_id(gateway)?.as_bytes())
    );
    let scope = serde_json::json!({
        "kind": "target", "target_id": folder["target_id"], "generation": folder["generation"]
    });
    begin_drain(
        gateway.address,
        client,
        key,
        scope.clone(),
        EMPTY_DRAIN_OPERATION,
    )
    .await?;
    wait_for_safe_empty_drain(gateway.address, client, key, &scope).await
}

async fn wait_for_safe_empty_drain(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    scope: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
    let authorization = format!("Bearer {key}");
    let path = format!("/api/latest/admin/storage-drains/{EMPTY_DRAIN_OPERATION}");
    loop {
        let response = tokio::time::timeout_at(
            deadline,
            request_with_headers(
                address,
                client,
                "GET",
                &path,
                None,
                &[("Authorization", authorization.as_str())],
            ),
        )
        .await
        .map_err(|_| "empty gateway drain did not become safe within 15s")??;
        require_status(&response, "200 OK", "observe empty gateway drain")?;
        let drain: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
        assert_eq!(drain["drain_id"], EMPTY_DRAIN_OPERATION);
        assert_eq!(&drain["scope"], scope);
        if drain["state"] == "safe_to_detach" {
            assert!(drain["safe_at_epoch_micros"].as_i64().is_some());
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                format!("empty gateway drain remained {} after 15s", drain["state"]).into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn original_route(
    fixture: &ProcessFixture,
) -> Result<(RepairProjectionManifest, ShardReceipt), Box<dyn Error>> {
    let catalogue =
        DurableContentCatalog::open(&fixture.state_path.join("filesystem"), UnixMicros::new(1))?;
    let page = catalogue.repair_projection_manifests(None, 2)?;
    assert_eq!(
        page.manifests.len(),
        1,
        "fixture must contain one original manifest"
    );
    let manifest = *page
        .manifests
        .as_slice()
        .first()
        .ok_or("missing original manifest")?;
    assert_eq!(
        manifest.content.manifest.logical_length,
        CONTENT.len() as u64
    );
    let stripe = catalogue.committed_protected_stripe(manifest.content, 0)?;
    assert_eq!(
        stripe.receipts.len(),
        1,
        "fixture must start with one source route"
    );
    Ok((
        manifest,
        *stripe
            .receipts
            .as_slice()
            .first()
            .ok_or("missing original receipt")?,
    ))
}

async fn begin_drain(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    scope: serde_json::Value,
    operation: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation, "scope": scope,
        "allow_temporary_degraded": true, "cleanup_requested": false
    }))?;
    let authorization = format!("Bearer {key}");
    let response = tokio::time::timeout(
        WAIT_LIMIT,
        request_with_headers(
            address,
            client,
            "POST",
            "/api/latest/admin/storage-drains",
            Some(&body),
            &[("Authorization", authorization.as_str())],
        ),
    )
    .await
    .map_err(|_| "public target-drain admission timed out")??;
    require_status(&response, "202 Accepted", "admit exact source-target drain")?;
    let admitted: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(admitted["operation_id"], operation);
    assert_eq!(admitted["drain"]["scope"], scope);
    // Source detachment requires every participant's attestation. Its later repair wait
    // does not bypass that predicate; only the empty-target phase waits for safe detachment.
    Ok(())
}

async fn wait_for_repair(
    root: &ProcessFixture,
    replacement: &ProcessFixture,
    manifest: RepairProjectionManifest,
    source: ShardReceipt,
) -> Result<ShardRepairEffectRecord, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(effect) = committed_repair(root, manifest)? {
            assert_eq!(effect.source_receipt, source);
            assert_eq!(effect.volume_id, manifest.volume_id);
            assert_eq!(effect.manifest_id, manifest.content.manifest.manifest_id);
            assert_eq!(effect.source_layout_generation, 1);
            assert_eq!(effect.replacement_layout_generation, 2);
            assert_eq!(
                effect.replacement_receipt.shard,
                meshspan_contracts::ShardIdentity {
                    generation: source
                        .shard
                        .generation
                        .checked_add(1)
                        .ok_or("generation exhausted")?,
                    ..source.shard
                }
            );
            assert_eq!(effect.replacement_receipt.length, source.length);
            assert_eq!(effect.replacement_receipt.digest, source.digest);
            assert_ne!(effect.replacement_receipt.target_id, source.target_id);
            let repository = authority(root)?;
            let target = repository
                .storage_target_provider_context_by_target(effect.replacement_receipt.target_id)?
                .ok_or("replacement target missing")?;
            assert_eq!(target.node_id, fixture_node_id(replacement)?);
            if committed_repair(replacement, manifest)? == Some(effect) {
                return Ok(effect);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "drain repair did not reach both surviving voters within 15s; root={}; replacement={}",
                repair_wait_state(root), repair_wait_state(replacement),
            ).into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn repair_wait_state(fixture: &ProcessFixture) -> String {
    let snapshot = || -> Result<String, Box<dyn Error>> {
        let repository = authority(fixture)?;
        let plan = repository
            .load_active_consensus_quorum_plan()?
            .ok_or("active quorum plan missing")?;
        let state = repository.load_consensus_state(plan.membership_epoch())?;
        let page = repository.maintenance_observation_page(None, PageLimit::new(16)?)?;
        let jobs: Vec<_> = page
            .items
            .iter()
            .map(|work| {
                (
                    work.work_id,
                    work.state,
                    work.attempt_count,
                    work.claim
                        .as_ref()
                        .map(|claim| (claim.worker_node_id, claim.lease_expires_at)),
                )
            })
            .collect();
        Ok(format!(
            "epoch={}, applied={}, jobs={jobs:?}, more={}",
            plan.membership_epoch(),
            state.applied_index,
            page.next.is_some()
        ))
    };
    // Diagnostics must never replace the actual repair timeout, including during a plan change.
    snapshot().unwrap_or_else(|error| format!("snapshot unavailable: {error}"))
}

fn authority(fixture: &ProcessFixture) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(
            &fixture.state_path.join("root-authority.sqlite3"),
            UnixMicros::new(1),
        )?,
    ))
}

fn committed_repair(
    fixture: &ProcessFixture,
    manifest: RepairProjectionManifest,
) -> Result<Option<ShardRepairEffectRecord>, Box<dyn Error>> {
    let repository = authority(fixture)?;
    let page = repository.shard_repair_effects(
        manifest.volume_id,
        manifest.content.manifest.manifest_id,
        None,
        PageLimit::new(2)?,
    )?;
    assert!(
        page.items.len() <= 1,
        "one source shard must produce one committed replacement"
    );
    let Some(effect) = page.items.first().copied() else {
        return Ok(None);
    };
    let retained = repository
        .shard_repair_attempt(effect.work_id)?
        .ok_or("repair performed IO without retaining its original plan")?;
    assert!(retained.revision < effect.revision);
    assert_eq!(retained.plan.source_receipt, effect.source_receipt);
    assert_eq!(
        retained.plan.source_layout_generation,
        effect.source_layout_generation
    );
    assert_eq!(
        retained.plan.effect_context.operation_id,
        effect.effect_operation_id
    );
    let intent = retained.plan.intent;
    assert_eq!(
        effect.replacement_receipt,
        ShardReceipt {
            operation_id: intent.context.operation_id,
            shard: intent.shard,
            target_id: intent.target_id,
            target_generation: intent.target_generation,
            length: intent.expected_length,
            digest: intent.expected_digest,
        }
    );
    let work = repository
        .maintenance_work(effect.work_id)?
        .ok_or("repair work missing")?;
    // The immutable effect and terminal work acknowledgement are separate commits.
    // Observing the former alone is not completion; retain the original bounded wait.
    if work.state != MaintenanceWorkState::Complete {
        return Ok(None);
    }
    let reference = repository
        .maintenance_effect_reference(effect.work_id)?
        .ok_or("repair work has no committed effect")?;
    assert_eq!(reference.operation_id, effect.effect_operation_id);
    assert_eq!(work.result_digest, Some(reference.result_digest));
    Ok(Some(effect))
}

fn assert_projected(
    gateway: &ProcessFixture,
    manifest: RepairProjectionManifest,
    effect: &ShardRepairEffectRecord,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(committed_repair(gateway, manifest)?, Some(*effect));
    let catalogue =
        DurableContentCatalog::open(&gateway.state_path.join("filesystem"), UnixMicros::new(1))?;
    let actual = catalogue
        .committed_content_by_manifest(manifest.content.manifest.manifest_id)?
        .ok_or("original manifest disappeared after restart")?;
    assert_eq!(actual, manifest.content);
    let stripe = catalogue.committed_protected_stripe(actual, 0)?;
    assert_eq!(stripe.receipts.as_slice(), &[effect.replacement_receipt]);
    assert!(
        catalogue
            .shard_repair_candidate(
                effect.source_receipt.target_id,
                effect.source_receipt.target_generation,
                effect.source_receipt.shard,
            )?
            .is_none()
    );
    Ok(())
}
