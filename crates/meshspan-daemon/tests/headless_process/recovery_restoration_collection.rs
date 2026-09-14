// SPDX-License-Identifier: GPL-2.0-only

//! Actual coordinator archive comparison, atomic receipt persistence and exact replay.

use super::{Error, ProcessFixture, recovery_restoration::hex};
use meshspan_daemon::{LocalNodeIdentity, OperatingSystemClock};
use meshspan_domain::Clock as _;
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, PartitionDatabase, RecoveryShardRestoration,
    RepositoryError,
};
use meshspan_recovery_bundle::RecoveredAuthority;
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path, process::Command};

pub(super) async fn collect(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    backup: &Path,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    let original_report = fs::read(output.join("restored.json"))?;
    let original_receipts = fs::read(output.join("receipts.bin"))?;
    let attestation =
        meshspan_api_contract::decode_recovery_restoration_attestation(&original_report)?;
    let claim = RecoveryShardRestoration::decode_message(
        authority.root_certificate_der(),
        &attestation.message,
    )?;
    assert_eq!(original_receipts.len(), 136);
    let receipt = meshspan_contracts::decode_shard_receipt_v1(&original_receipts[10..])?;
    rejects_partial_persistence(
        directory,
        authority,
        (&claim, &attestation.signature),
        receipt,
    )?;
    write_signed_wrong_operation(
        directory,
        output,
        &original_report,
        &original_receipts,
        &claim,
    )?;
    let rejected = super::offline_backup::run_command(command(
        root,
        directory,
        backup,
        output,
        "signed-wrong-shard",
    ))
    .await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(
        open(directory)?
            .recovery_restoration(
                authority,
                claim.target.target_id,
                (claim.source_target_id, claim.source_generation)
            )?
            .is_none()
    );
    fs::write(output.join("restored.json"), &original_report)?;
    fs::write(
        output.join("receipts.bin"),
        &original_receipts[..original_receipts.len() - 1],
    )?;
    let rejected = super::offline_backup::run_command(command(
        root,
        directory,
        backup,
        output,
        "truncated-restoration",
    ))
    .await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    fs::write(output.join("receipts.bin"), original_receipts)?;
    let accepted = super::offline_backup::run_command(command(
        root,
        directory,
        backup,
        output,
        "collected-restoration",
    ))
    .await?;
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout)?;
    assert_eq!(report["recorded"], true);
    assert_eq!(report["archive_matched"], true);
    assert_eq!(report["service_started"], false);
    assert_eq!(report["admission_ready"], false);
    verify_record(directory, authority, &claim, &report)?;
    let retry = super::offline_backup::run_command(command(
        root,
        directory,
        backup,
        output,
        "collected-restoration",
    ))
    .await?;
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&retry.stdout)?,
        report
    );
    verify_record(directory, authority, &claim, &report)?;
    assert!(!directory.join("collected-restoration/build").exists());
    Ok(())
}

fn write_signed_wrong_operation(
    directory: &Path,
    output: &Path,
    original_report: &[u8],
    original_receipts: &[u8],
    claim: &RecoveryShardRestoration,
) -> Result<(), Box<dyn Error>> {
    // A valid node signature cannot authorise the wrong archived shard operation.
    let mut wrong = meshspan_contracts::decode_shard_receipt_v1(&original_receipts[10..])?;
    wrong.operation_id = meshspan_domain::OperationId::from_bytes([203; 16])?;
    let mut changed = original_receipts[..10].to_vec();
    changed.extend_from_slice(&meshspan_contracts::encode_shard_receipt_v1(wrong));
    let mut false_claim = claim.clone();
    false_claim.receipts_digest = Sha256::digest(&changed).into();
    let mut false_report: serde_json::Value = serde_json::from_slice(original_report)?;
    let identity = LocalNodeIdentity::open(&directory.join("identity.pk8"), "replacement.invalid")?;
    false_report["receipts_sha256"] = hex(&false_claim.receipts_digest)?.into();
    false_report["installation_message"] = hex(&false_claim.installation_message()?)?.into();
    false_report["installation_signature"] =
        hex(&identity.sign_enrolment_transcript(&false_claim.installation_message()?)?)?.into();
    fs::write(
        output.join("restored.json"),
        serde_json::to_vec(&false_report)?,
    )?;
    fs::write(output.join("receipts.bin"), changed)?;
    Ok(())
}

fn rejects_partial_persistence(
    directory: &Path,
    authority: &RecoveredAuthority,
    evidence: (&RecoveryShardRestoration, &[u8]),
    receipt: meshspan_contracts::ShardReceipt,
) -> Result<(), Box<dyn Error>> {
    let mut repo = open(directory)?;
    let source = (evidence.0.source_target_id, evidence.0.source_generation);
    assert!(
        repo.record_recovery_restoration(
            authority,
            evidence,
            [Ok(receipt), Err(RepositoryError::CorruptState)],
            OperatingSystemClock.now()
        )
        .is_err()
    );
    assert!(
        repo.recovery_restoration(authority, evidence.0.target.target_id, source)?
            .is_none()
    );
    let sql = rusqlite::Connection::open(directory.join("coordinator/prepared.sqlite3"))?;
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM partition_recovery_shards",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    sql.execute_batch("CREATE TRIGGER injected_restore_write BEFORE INSERT ON partition_recovery_shards BEGIN SELECT RAISE(ABORT, 'injected'); END;")?;
    assert!(
        repo.record_recovery_restoration(
            authority,
            evidence,
            [Ok(receipt)],
            OperatingSystemClock.now()
        )
        .is_err()
    );
    sql.execute_batch("DROP TRIGGER injected_restore_write;")?;
    assert!(
        repo.recovery_restoration(authority, evidence.0.target.target_id, source)?
            .is_none()
    );
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM partition_recovery_shards",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

fn verify_record(
    directory: &Path,
    authority: &RecoveredAuthority,
    claim: &RecoveryShardRestoration,
    report: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let repo = open(directory)?;
    let result = repo
        .recovery_restoration(
            authority,
            claim.target.target_id,
            (claim.source_target_id, claim.source_generation),
        )?
        .ok_or("missing restoration")?;
    assert_eq!(&result.restoration, claim);
    let mut visited = 0;
    repo.visit_recovery_restored_shards(authority, |stored, receipt| {
        assert_eq!(stored, claim);
        assert_eq!(receipt.target_id, claim.target.target_id);
        visited += 1;
        Ok(())
    })?;
    assert_eq!(visited, claim.receipt_count);
    assert!(matches!(
        repo.visit_recovery_restored_shards(authority, |_, _| Err(
            RepositoryError::OperationConflict
        )),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(
        report["recorded_at_unix_micros"],
        result.recorded_at.get().to_string()
    );
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert!(
        repo.recovery_storage_target_marker(claim.target.target_id, claim.target.generation)?
            .is_none()
    );
    Ok(())
}

fn open(directory: &Path) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    let database = PartitionDatabase::open_existing(
        &directory.join("coordinator/prepared.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    database.check_integrity()?;
    Ok(AuthoritativeRepository::new(database))
}

fn command(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    output: &Path,
    work: &str,
) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("collect-recovery-restoration")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(output)
        .arg(directory.join(work));
    command
}
