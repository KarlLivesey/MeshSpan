// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use meshspan_domain::{ClaimBundle, EntropyError, NodeId, RandomSource, UnixMicros};
use meshspan_metadata::{LocalClaimMutationDisposition, LocalClaimState, LocalDatabase};
use tempfile::TempDir;

use crate::{
    ClaimEnsureDisposition, ClaimFile, ClaimFileError, FirstBootClaimError, FirstBootClaimService,
};

const FINGERPRINT: [u8; 32] = [9; 32];

#[test]
fn first_start_and_restart_preserve_one_exact_claim() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    let mut random = SequentialRandom(1);

    let created = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(20),
        &mut random,
    )?;
    assert_eq!(created.disposition, ClaimEnsureDisposition::Created);
    let persisted = database
        .active_local_claim()?
        .ok_or("created claim is not active")?;
    let presented = ClaimFile::read(&output)?;
    assert_eq!(created.claim_id, Some(persisted.claim_id));
    assert_eq!(presented.claim_id(), persisted.claim_id);
    assert_eq!(presented.secret_digest(), persisted.secret_digest);

    let existing = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(30),
        &mut FailingRandom,
    )?;
    assert_eq!(existing.disposition, ClaimEnsureDisposition::Existing);
    assert_eq!(existing.claim_id, created.claim_id);
    Ok(())
}

#[test]
fn startup_recovers_file_first_creation_without_new_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    let claim = ClaimBundle::generate(&mut SequentialRandom(20))?;
    let claim_id = claim.claim_id();
    let digest = claim.secret_digest();
    ClaimFile::create(&output, &claim)?;

    let recovered = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(25),
        &mut FailingRandom,
    )?;
    assert_eq!(recovered.disposition, ClaimEnsureDisposition::Recovered);
    assert_eq!(recovered.claim_id, Some(claim_id));
    assert_eq!(
        database
            .active_local_claim()?
            .ok_or("recovered claim is not active")?
            .secret_digest,
        digest
    );
    Ok(())
}

#[test]
fn missing_active_output_fails_without_changing_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    let created = create_claim(&mut database, &output)?;
    fs::remove_file(&output)?;

    let result = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(30),
        &mut SequentialRandom(50),
    );
    assert!(matches!(result, Err(FirstBootClaimError::OutputMissing)));
    assert_eq!(
        database.active_local_claim()?.map(|record| record.claim_id),
        created.claim_id
    );
    Ok(())
}

#[test]
fn rotation_recovers_interruption_and_exact_retry_never_rotates_twice()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    let first = create_claim(&mut database, &output)?;
    let first_id = first.claim_id.ok_or("first claim identity is missing")?;

    let rotated = FirstBootClaimService::rotate(
        &mut database,
        first_id,
        FINGERPRINT,
        &output,
        UnixMicros::new(30),
        &mut SequentialRandom(60),
    )?;
    assert_eq!(rotated.disposition, LocalClaimMutationDisposition::Applied);
    let rotated_digest = ClaimFile::read(&output)?.secret_digest();
    let replayed = FirstBootClaimService::rotate(
        &mut database,
        first_id,
        FINGERPRINT,
        &output,
        UnixMicros::new(40),
        &mut FailingRandom,
    )?;
    assert_eq!(
        replayed.disposition,
        LocalClaimMutationDisposition::Replayed
    );
    assert_eq!(replayed.claim_id, rotated.claim_id);
    assert_eq!(ClaimFile::read(&output)?.secret_digest(), rotated_digest);

    let pending = ClaimBundle::generate(&mut SequentialRandom(110))?;
    let pending_id = pending.claim_id();
    ClaimFile::replace(&output, &pending)?;
    let recovered = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(50),
        &mut FailingRandom,
    )?;
    assert_eq!(recovered.disposition, ClaimEnsureDisposition::Recovered);
    assert_eq!(recovered.claim_id, Some(pending_id));
    assert_eq!(
        database.active_local_claim()?.map(|record| record.claim_id),
        Some(pending_id)
    );
    Ok(())
}

#[test]
fn consumption_rejects_substitution_then_cleans_up_and_replays()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    create_claim(&mut database, &output)?;
    let encoded = ClaimFile::read(&output)?.expose_encoded();
    let mut substituted = encoded.to_string();
    let final_character = substituted.pop().ok_or("claim encoding is empty")?;
    substituted.push(if final_character == 'a' { 'b' } else { 'a' });

    let rejected =
        FirstBootClaimService::consume(&mut database, &substituted, &output, UnixMicros::new(30));
    assert!(matches!(rejected, Err(FirstBootClaimError::Metadata(_))));
    assert!(output.exists());
    assert!(database.active_local_claim()?.is_some());

    let consumed =
        FirstBootClaimService::consume(&mut database, &encoded, &output, UnixMicros::new(30))?;
    assert_eq!(consumed.disposition, LocalClaimMutationDisposition::Applied);
    assert!(consumed.output_removed);
    assert!(!output.exists());
    let replayed =
        FirstBootClaimService::consume(&mut database, &encoded, &output, UnixMicros::new(30))?;
    assert_eq!(
        replayed.disposition,
        LocalClaimMutationDisposition::Replayed
    );
    assert!(!replayed.output_removed);
    Ok(())
}

#[test]
fn startup_finishes_cleanup_after_consumption_commit() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    create_claim(&mut database, &output)?;
    let claim = ClaimFile::read(&output)?;
    database.consume_local_claim(claim.claim_id(), claim.secret_digest(), UnixMicros::new(30))?;

    let inactive = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(40),
        &mut FailingRandom,
    )?;
    assert_eq!(inactive.disposition, ClaimEnsureDisposition::Inactive);
    assert_eq!(inactive.claim_id, None);
    assert!(!output.exists());
    assert_eq!(
        database
            .latest_local_claim()?
            .ok_or("consumed history is missing")?
            .state,
        LocalClaimState::Consumed
    );
    Ok(())
}

#[test]
fn identity_and_output_metadata_are_validated_before_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, mut database) = open_database()?;
    let output = output_path(&directory);
    create_claim(&mut database, &output)?;

    let mismatch = FirstBootClaimService::ensure(
        &mut database,
        [8; 32],
        &output,
        UnixMicros::new(30),
        &mut FailingRandom,
    );
    assert!(matches!(
        mismatch,
        Err(FirstBootClaimError::NodeIdentityMismatch)
    ));

    fs::set_permissions(&output, fs::Permissions::from_mode(0o644))?;
    let unsafe_output = FirstBootClaimService::ensure(
        &mut database,
        FINGERPRINT,
        &output,
        UnixMicros::new(30),
        &mut FailingRandom,
    );
    assert!(matches!(
        unsafe_output,
        Err(FirstBootClaimError::File(ClaimFileError::Unsafe))
    ));
    Ok(())
}

fn open_database() -> Result<(TempDir, LocalDatabase), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        NodeId::from_bytes([7; 16])?,
        UnixMicros::new(10),
    )?;
    Ok((directory, database))
}

fn output_path(directory: &TempDir) -> std::path::PathBuf {
    directory.path().join("claim.txt")
}

fn create_claim(
    database: &mut LocalDatabase,
    output: &Path,
) -> Result<crate::ClaimEnsureOutcome, FirstBootClaimError> {
    FirstBootClaimService::ensure(
        database,
        FINGERPRINT,
        output,
        UnixMicros::new(20),
        &mut SequentialRandom(1),
    )
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}
