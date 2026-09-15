// SPDX-License-Identifier: GPL-2.0-only

//! Real worker SIGKILL after provider publication, before replicated backup admission.

use super::*;
use meshspan_contracts::BackupObjectIdentity;
use meshspan_domain::{BackupId, NodeId};
use meshspan_metadata::{MetadataBackupRunState, PageLimit};

#[path = "backup_takeover/provider_gate.rs"]
mod provider_gate;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real five-minute production backup lease; run separately from the edit/test gate"]
#[expect(
    clippy::print_stderr,
    reason = "Non-secret phase markers make this separate five-minute process proof observable"
)]
async fn surviving_daemon_retires_unadmitted_upload_after_worker_sigkill() -> TestResult {
    let fixtures = [
        ProcessFixture::new()?,
        ProcessFixture::new()?,
        ProcessFixture::new()?,
    ];
    let mut cleanup = ProcessCleanup(vec![fixtures[0].start()?]);
    let proof = async {
        let (clients, authorization) = bootstrap(&fixtures, &mut cleanup.0).await?;
        let gates = provider_gate::lock_catalogues(&fixtures).await?;
        let sequence =
            stage10::request_fresh_backup(fixtures[0].address, &clients[0], &authorization).await?;
        let interrupted =
            provider_gate::wait_for_published_intent(&fixtures[0], &gates, sequence).await?;
        let worker = fixtures
            .iter()
            .map(fixture_node_id)
            .collect::<TestResult<Vec<_>>>()?
            .iter()
            .position(|node| *node == interrupted.worker)
            .ok_or("unknown publishing worker")?;
        cleanup.0[worker].kill()?;
        let killed = cleanup.0[worker].wait()?;
        assert!(!killed.success());
        provider_gate::release(gates)?;
        eprintln!("backup takeover: publishing worker killed; waiting for its production lease");
        let survivor = (worker + 1) % fixtures.len();
        wait_for_successor(
            &fixtures[survivor],
            interrupted.object.backup_id,
            interrupted.worker,
        )
        .await?;
        eprintln!(
            "backup takeover: a different daemon abandoned the old run and claimed its successor"
        );
        cleanup.0[worker] = fixtures[worker].start()?;
        wait_for_status(fixtures[worker].address, &clients[worker], "configured").await?;
        wait_for_retirement(&fixtures[survivor], &interrupted).await?;
        let protected = backup_history::automatic_backup_history_for_schedule(
            fixtures[survivor].address,
            &clients[survivor],
            &authorization,
            sequence,
        )
        .await?;
        assert_ne!(
            protected,
            uuid_text(interrupted.object.backup_id.as_bytes())
        );
        for fixture in &fixtures {
            assert_eq!(
                fs::read(fixture.storage_path.join("operator-file.txt"))?,
                b"untouched"
            );
        }
        Ok(())
    }
    .await;
    stop_processes(&mut cleanup.0);
    retain_failure_state(proof, fixtures.map(|fixture| fixture.temporary))
}

async fn bootstrap(
    fixtures: &[ProcessFixture; 3],
    processes: &mut Vec<Child>,
) -> TestResult<(Vec<ClientConfig>, String)> {
    let root = &fixtures[0];
    let claim = wait_for_claim(&root.claim_path).await?;
    let client = wait_for_client(&root.identity_path).await?;
    wait_for_status(root.address, &client, "claim_required").await?;
    let created = create_process_mesh(root, &client, &claim).await?;
    let key = created["api_key"].as_str().ok_or("bootstrap key missing")?;
    save_and_verify_recovery_bundle(root, &client, key, &created).await?;
    wait_for_storage_folder_visibility(root, &client, key).await?;
    let join = issue_join_code(root, &client, key).await?;
    let authorization = format!("Bearer {key}");
    let mut clients = vec![client];
    for fixture in fixtures.iter().skip(1) {
        processes.push(fixture.start_join(&join)?);
        let client = wait_for_client(&fixture.identity_path).await?;
        wait_for_status(fixture.address, &client, "configured").await?;
        wait_for_storage_folder_visibility(fixture, &client, key).await?;
        clients.push(client);
    }
    wait_for_three_voters(
        [&fixtures[0], &fixtures[1], &fixtures[2]],
        &root.identity_path,
    )
    .await?;
    offline_backup::protected_backup(root, &clients[0], &authorization).await?;
    Ok((clients, authorization))
}

fn reader(fixture: &ProcessFixture) -> TestResult<AuthoritativeRepository> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(
            &fixture.state_path.join("root-authority.sqlite3"),
            UnixMicros::new(1),
        )?,
    ))
}

async fn wait_for_successor(
    fixture: &ProcessFixture,
    backup: BackupId,
    old_worker: NodeId,
) -> TestResult {
    let repository = reader(fixture)?;
    let journal = rusqlite::Connection::open_with_flags(
        fixture.state_path.join("root-authority.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let deadline = Instant::now() + Duration::from_secs(360);
    loop {
        let original = repository
            .metadata_backup_run(backup)?
            .ok_or("original run missing")?;
        if original.state == MetadataBackupRunState::Incomplete {
            assert!(original.completed_at.is_some());
            assert!(
                original
                    .result_digest
                    .is_some_and(|digest| digest != [0; 32])
            );
            assert!(repository.metadata_backup(backup)?.is_none());
            assert!(repository.metadata_backup_run_claim(backup)?.is_none());
            if let Some(next) = repository
                .metadata_backup_runs(None, PageLimit::new(1)?)?
                .items
                .first()
                && next.run_sequence > original.run_sequence
            {
                use rusqlite::OptionalExtension as _;
                let owner: Option<Vec<u8>> = journal.query_row(
                    "SELECT worker_node_id FROM metadata_backup_run_claims WHERE backup_id = ?1 ORDER BY claim_generation DESC LIMIT 1",
                    [next.backup_id.as_bytes().as_slice()], |row| row.get(0),
                ).optional()?;
                if let Some(owner) = owner {
                    assert_ne!(owner, old_worker.as_bytes());
                    return Ok(());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "backup takeover exceeded the production lease; original state: {:?}",
                original.state
            )
            .into());
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_retirement(
    fixture: &ProcessFixture,
    expected: &provider_gate::InterruptedUpload,
) -> TestResult {
    let repository = reader(fixture)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(retired) = repository.abandoned_backup_retirement(
            expected.object.backup_id,
            expected.object.destination_id,
        )? {
            assert_eq!(retired.command.receipt.object, expected.object);
            assert!(
                repository
                    .metadata_backup(expected.object.backup_id)?
                    .is_none()
            );
            let pending = repository.pending_backup_reclamations(None, PageLimit::new(100)?)?;
            if !pending
                .items
                .iter()
                .any(|candidate| candidate.object == expected.object)
                && !expected.published_path.exists()
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("rejoined provider did not finish exact orphan retirement".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}
