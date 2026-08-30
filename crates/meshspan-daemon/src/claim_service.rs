// SPDX-License-Identifier: GPL-2.0-only

//! Crash-safe composition of secret claim output and digest-only local metadata.

use std::path::Path;

use meshspan_domain::{ClaimBundle, ClaimBundleError, ClaimId, RandomSource, UnixMicros};
use meshspan_metadata::{
    LocalClaimError, LocalClaimMutationDisposition, LocalClaimRecord, LocalClaimState,
    LocalDatabase, NewLocalClaim,
};
use thiserror::Error;

use crate::{ClaimFile, ClaimFileError};

/// How daemon startup resolved the node's first-boot claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimEnsureDisposition {
    /// A new claim was generated and durably recorded.
    Created,
    /// A complete secret-file-first transition was recovered after interruption.
    Recovered,
    /// The existing active claim and its output already agreed.
    Existing,
    /// Terminal claim history exists and no active claim remains.
    Inactive,
}

/// Non-secret result of ensuring first-boot claim state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimEnsureOutcome {
    /// Startup resolution performed by the service.
    pub disposition: ClaimEnsureDisposition,
    /// Active public claim identity, absent after terminal consumption.
    pub claim_id: Option<ClaimId>,
}

/// Non-secret result of an explicit local claim rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimRotationOutcome {
    /// Whether this call applied or replayed the exact durable transition.
    pub disposition: LocalClaimMutationDisposition,
    /// Public identity of the replacement claim.
    pub claim_id: ClaimId,
}

/// Non-secret result of consuming one claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimConsumptionOutcome {
    /// Whether this call applied or replayed the exact durable transition.
    pub disposition: LocalClaimMutationDisposition,
    /// Whether the matching local secret output still existed and was removed.
    pub output_removed: bool,
}

/// Stable first-boot composition failure without secret or path contents.
#[derive(Debug, Error)]
pub enum FirstBootClaimError {
    /// Claim generation or parsing failed.
    #[error("claim material is invalid or unavailable")]
    Bundle(#[from] ClaimBundleError),
    /// Protected local secret-file handling failed.
    #[error("protected claim output failed")]
    File(#[from] ClaimFileError),
    /// Digest-only lifecycle persistence failed or rejected the transition.
    #[error("local claim lifecycle failed")]
    Metadata(#[from] LocalClaimError),
    /// The supplied node public-key fingerprint does not own this claim history.
    #[error("claim node identity does not match")]
    NodeIdentityMismatch,
    /// Durable state and the protected output disagree in a way that cannot be recovered safely.
    #[error("claim state and protected output conflict")]
    Conflict,
    /// An active claim exists but its exact secret output is no longer present.
    #[error("active claim output is missing; explicitly rotate the claim")]
    OutputMissing,
}

/// Daemon boundary for first-boot claim creation, recovery, rotation and consumption.
pub struct FirstBootClaimService;

impl FirstBootClaimService {
    /// Ensures startup has one consistent active claim or known terminal history.
    ///
    /// The secret file is always made durable before its verifier enters SQLite.
    /// This ordering lets restart recover an interrupted creation or rotation without
    /// ever persisting plaintext claim material.
    ///
    /// # Errors
    ///
    /// Fails closed for unsafe output, mismatched identity, missing active secret,
    /// conflicting history, unavailable entropy or persistence failure.
    pub fn ensure(
        database: &mut LocalDatabase,
        node_public_key_fingerprint: [u8; 32],
        output_path: &Path,
        now: UnixMicros,
        random: &mut impl RandomSource,
    ) -> Result<ClaimEnsureOutcome, FirstBootClaimError> {
        validate_node_fingerprint(node_public_key_fingerprint)?;
        let active = database.active_local_claim()?;
        let output = read_optional_output(output_path)?;
        match (active, output) {
            (Some(record), Some(bundle)) => recover_or_accept_active(
                database,
                record,
                &bundle,
                node_public_key_fingerprint,
                now,
            ),
            (Some(record), None) => {
                validate_record_owner(record, node_public_key_fingerprint)?;
                Err(FirstBootClaimError::OutputMissing)
            }
            (None, Some(bundle)) => recover_without_active(
                database,
                &bundle,
                node_public_key_fingerprint,
                output_path,
                now,
            ),
            (None, None) => create_or_report_inactive(
                database,
                node_public_key_fingerprint,
                output_path,
                now,
                random,
            ),
        }
    }

    /// Explicitly replaces an expected active claim using file-first crash recovery.
    ///
    /// `expected_claim_id` makes retry after a lost response replay the completed
    /// rotation rather than issuing another claim.
    ///
    /// # Errors
    ///
    /// Fails closed for stale identity, unsafe/conflicting output, unavailable entropy
    /// or persistence failure.
    pub fn rotate(
        database: &mut LocalDatabase,
        expected_claim_id: ClaimId,
        node_public_key_fingerprint: [u8; 32],
        output_path: &Path,
        now: UnixMicros,
        random: &mut impl RandomSource,
    ) -> Result<ClaimRotationOutcome, FirstBootClaimError> {
        validate_node_fingerprint(node_public_key_fingerprint)?;
        let active = database
            .active_local_claim()?
            .ok_or(FirstBootClaimError::Conflict)?;
        validate_record_owner(active, node_public_key_fingerprint)?;
        if active.claim_id != expected_claim_id {
            return replay_rotation(database, active, expected_claim_id, output_path);
        }

        let output = read_optional_output(output_path)?;
        match output.as_ref() {
            Some(bundle) if bundle.claim_id() != active.claim_id => {
                return complete_rotation(database, active, bundle, now);
            }
            Some(bundle) if !digests_match(bundle.secret_digest(), active.secret_digest) => {
                return Err(FirstBootClaimError::Conflict);
            }
            Some(_) | None => {}
        }

        let replacement = ClaimBundle::generate(random)?;
        match output {
            Some(_) => ClaimFile::replace(output_path, &replacement)?,
            None => ClaimFile::create(output_path, &replacement)?,
        }
        complete_rotation(database, active, &replacement, now)
    }

    /// Consumes an exact claim and then removes only its matching secret output.
    ///
    /// A retry after SQLite commit replays the same terminal transition and retries
    /// output cleanup. A wrong verifier never changes either durable domain.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale or substituted claims and any persistence/output failure.
    pub fn consume(
        database: &mut LocalDatabase,
        encoded_claim: &str,
        output_path: &Path,
        now: UnixMicros,
    ) -> Result<ClaimConsumptionOutcome, FirstBootClaimError> {
        let claim = ClaimBundle::parse(encoded_claim)?;
        let secret_digest = claim.secret_digest();
        let disposition = database.consume_local_claim(claim.claim_id(), secret_digest, now)?;
        let output_removed =
            ClaimFile::remove_if_matches(output_path, claim.claim_id(), secret_digest)?;
        Ok(ClaimConsumptionOutcome {
            disposition,
            output_removed,
        })
    }
}

fn recover_or_accept_active(
    database: &mut LocalDatabase,
    active: LocalClaimRecord,
    output: &ClaimBundle,
    node_public_key_fingerprint: [u8; 32],
    now: UnixMicros,
) -> Result<ClaimEnsureOutcome, FirstBootClaimError> {
    validate_record_owner(active, node_public_key_fingerprint)?;
    if output.claim_id() == active.claim_id {
        if !digests_match(output.secret_digest(), active.secret_digest) {
            return Err(FirstBootClaimError::Conflict);
        }
        return Ok(ClaimEnsureOutcome {
            disposition: ClaimEnsureDisposition::Existing,
            claim_id: Some(active.claim_id),
        });
    }
    let outcome = complete_rotation(database, active, output, now)?;
    Ok(ClaimEnsureOutcome {
        disposition: ClaimEnsureDisposition::Recovered,
        claim_id: Some(outcome.claim_id),
    })
}

fn recover_without_active(
    database: &mut LocalDatabase,
    output: &ClaimBundle,
    node_public_key_fingerprint: [u8; 32],
    output_path: &Path,
    now: UnixMicros,
) -> Result<ClaimEnsureOutcome, FirstBootClaimError> {
    if let Some(latest) = database.latest_local_claim()? {
        validate_record_owner(latest, node_public_key_fingerprint)?;
        if latest.state == LocalClaimState::Consumed
            && output.claim_id() == latest.claim_id
            && digests_match(output.secret_digest(), latest.secret_digest)
        {
            ClaimFile::remove_if_matches(output_path, latest.claim_id, latest.secret_digest)?;
            return Ok(ClaimEnsureOutcome {
                disposition: ClaimEnsureDisposition::Inactive,
                claim_id: None,
            });
        }
        return Err(FirstBootClaimError::Conflict);
    }
    let claim_id = output.claim_id();
    database.create_local_claim(new_claim(output, node_public_key_fingerprint, now))?;
    Ok(ClaimEnsureOutcome {
        disposition: ClaimEnsureDisposition::Recovered,
        claim_id: Some(claim_id),
    })
}

fn create_or_report_inactive(
    database: &mut LocalDatabase,
    node_public_key_fingerprint: [u8; 32],
    output_path: &Path,
    now: UnixMicros,
    random: &mut impl RandomSource,
) -> Result<ClaimEnsureOutcome, FirstBootClaimError> {
    if let Some(latest) = database.latest_local_claim()? {
        validate_record_owner(latest, node_public_key_fingerprint)?;
        return if latest.state == LocalClaimState::Consumed {
            Ok(ClaimEnsureOutcome {
                disposition: ClaimEnsureDisposition::Inactive,
                claim_id: None,
            })
        } else {
            Err(FirstBootClaimError::Conflict)
        };
    }
    let claim = ClaimBundle::generate(random)?;
    let claim_id = claim.claim_id();
    ClaimFile::create(output_path, &claim)?;
    database.create_local_claim(new_claim(&claim, node_public_key_fingerprint, now))?;
    Ok(ClaimEnsureOutcome {
        disposition: ClaimEnsureDisposition::Created,
        claim_id: Some(claim_id),
    })
}

fn complete_rotation(
    database: &mut LocalDatabase,
    active: LocalClaimRecord,
    replacement: &ClaimBundle,
    now: UnixMicros,
) -> Result<ClaimRotationOutcome, FirstBootClaimError> {
    if replacement.claim_id() == active.claim_id {
        return Err(FirstBootClaimError::Conflict);
    }
    let claim_id = replacement.claim_id();
    let disposition = database.rotate_local_claim(
        active.claim_id,
        new_claim(replacement, active.node_public_key_fingerprint, now),
        now,
    )?;
    Ok(ClaimRotationOutcome {
        disposition,
        claim_id,
    })
}

fn replay_rotation(
    database: &mut LocalDatabase,
    active: LocalClaimRecord,
    expected_claim_id: ClaimId,
    output_path: &Path,
) -> Result<ClaimRotationOutcome, FirstBootClaimError> {
    let prior = database
        .local_claim_record(expected_claim_id)?
        .ok_or(FirstBootClaimError::Conflict)?;
    let rotated_at = prior.rotated_at.ok_or(FirstBootClaimError::Conflict)?;
    if prior.state != LocalClaimState::Rotated {
        return Err(FirstBootClaimError::Conflict);
    }
    let output = ClaimFile::read(output_path).map_err(|error| match error {
        ClaimFileError::Missing => FirstBootClaimError::OutputMissing,
        other => FirstBootClaimError::File(other),
    })?;
    if output.claim_id() != active.claim_id
        || !digests_match(output.secret_digest(), active.secret_digest)
    {
        return Err(FirstBootClaimError::Conflict);
    }
    let disposition = database.rotate_local_claim(
        expected_claim_id,
        new_claim(
            &output,
            active.node_public_key_fingerprint,
            active.created_at,
        ),
        rotated_at,
    )?;
    Ok(ClaimRotationOutcome {
        disposition,
        claim_id: active.claim_id,
    })
}

fn read_optional_output(path: &Path) -> Result<Option<ClaimBundle>, FirstBootClaimError> {
    match ClaimFile::read(path) {
        Ok(claim) => Ok(Some(claim)),
        Err(ClaimFileError::Missing) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn new_claim(
    claim: &ClaimBundle,
    node_public_key_fingerprint: [u8; 32],
    created_at: UnixMicros,
) -> NewLocalClaim {
    NewLocalClaim {
        claim_id: claim.claim_id(),
        node_public_key_fingerprint,
        secret_digest: claim.secret_digest(),
        created_at,
    }
}

fn validate_node_fingerprint(fingerprint: [u8; 32]) -> Result<(), FirstBootClaimError> {
    if fingerprint == [0; 32] {
        Err(FirstBootClaimError::NodeIdentityMismatch)
    } else {
        Ok(())
    }
}

fn validate_record_owner(
    record: LocalClaimRecord,
    fingerprint: [u8; 32],
) -> Result<(), FirstBootClaimError> {
    if digests_match(record.node_public_key_fingerprint, fingerprint) {
        Ok(())
    } else {
        Err(FirstBootClaimError::NodeIdentityMismatch)
    }
}

fn digests_match(expected: [u8; 32], presented: [u8; 32]) -> bool {
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (expected, presented)| {
            difference | (expected ^ presented)
        })
        == 0
}
