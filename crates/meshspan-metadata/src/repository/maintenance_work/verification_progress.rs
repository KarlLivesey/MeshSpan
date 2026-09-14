// SPDX-License-Identifier: GPL-2.0-only

//! Validated read-only progress common to completed scrub and returning-target verification.

use super::{AuthoritativeRepository, RepositoryError, exact, nonnegative, positive};
use meshspan_domain::{TargetId, WorkId};
use meshspan_work::WorkSubject;
use rusqlite::OptionalExtension;

/// Exact accumulated work in an authoritative complete verification pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceVerificationProgress {
    /// Classified inventory records, including unhealthy and deferred records.
    pub observations: u64,
    /// Bytes independently read and digested, not an execution budget.
    pub verified_bytes: u64,
}

impl AuthoritativeRepository {
    /// Reads exact verification progress for a scrub or reconciliation job.
    ///
    /// # Errors
    /// Rejects a non-verification job, mismatched target generation, corrupt totals or IO.
    pub fn maintenance_verification_progress(
        &self,
        work_id: WorkId,
    ) -> Result<Option<MaintenanceVerificationProgress>, RepositoryError> {
        let record = self
            .maintenance_work(work_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let (table, target, generation) = match record.subject {
            WorkSubject::Scrub {
                target_id,
                target_generation,
            } => ("maintenance_scrub_effects", target_id, target_generation),
            WorkSubject::Reconcile {
                target_id,
                target_generation,
            } => (
                "maintenance_reconciliation_effects",
                target_id,
                target_generation,
            ),
            _ => return Err(RepositoryError::InvalidCommand),
        };
        // Table selection is exclusively the closed internal subject above, never caller text.
        let query = format!(
            "SELECT target_id, target_generation, observation_count, verified_bytes,
            healthy_count, missing_count, corrupt_count, unreadable_count, unexpected_count,
            deferred_count, evidence_digest FROM {table} WHERE work_id = ?1"
        );
        self.database
            .connection()
            .query_row(&query, [work_id.as_bytes().as_slice()], |row| {
                decode(row, target, generation).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .optional()
            .map_err(Into::into)
    }
}

fn decode(
    row: &rusqlite::Row<'_>,
    target: TargetId,
    generation: u64,
) -> Result<MaintenanceVerificationProgress, RepositoryError> {
    let observed_target =
        TargetId::from_bytes(exact(row.get(0)?)?).map_err(|_| RepositoryError::CorruptState)?;
    let observed_generation = positive(row.get(1)?)?;
    let observations = nonnegative(row.get(2)?)?;
    let verified_bytes = nonnegative(row.get(3)?)?;
    let mut classified = 0_u64;
    for index in 4..10 {
        classified = classified
            .checked_add(nonnegative(row.get(index)?)?)
            .ok_or(RepositoryError::CorruptState)?;
    }
    let digest: [u8; 32] = exact(row.get(10)?)?;
    if observed_target != target
        || observed_generation != generation
        || classified != observations
        || digest == [0; 32]
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(MaintenanceVerificationProgress {
        observations,
        verified_bytes,
    })
}
