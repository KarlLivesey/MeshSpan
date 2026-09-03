// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_domain::{
    BackupDestinationId, BackupId, DurationMicros, MeshId, NodeId, PartitionId, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    BackupDestinationCursor, LocalMetadataBackupStaging, MetadataBackupProtectionEvidence,
    MetadataBackupRun, MetadataBackupRunClaim, MetadataBackupRunClaimRecord,
    MetadataBackupRunState,
};

use crate::{
    MetadataBackupCompletionOutcome, MetadataBackupCycle, MetadataBackupCycleError,
    MetadataBackupCyclePlacement, MetadataBackupDispatchOutcome, MetadataBackupPlacementPage,
    MetadataBackupWorker, MetadataBackupWorkerLimits, MetadataBackupWorkerOutcome,
    PreparedMetadataBackup,
};

#[test]
fn worker_resumes_destination_cursor_then_completes_and_releases()
-> Result<(), Box<dyn std::error::Error>> {
    let run = run()?;
    let claim = claim(run.backup_id)?;
    let prepared = prepared(run)?;
    let mut cycle = MemoryCycle {
        run,
        claim,
        prepared,
        dispatches: 0,
        placements: 0,
        completions: 0,
        releases: 0,
    };
    let mut worker = MetadataBackupWorker::default();
    let limits = MetadataBackupWorkerLimits {
        lease_duration: DurationMicros::new(1_000),
        provider_timeout: DurationMicros::new(100),
        destination_page_items: 2,
    };

    let first = worker.run_once(&mut cycle, UnixMicros::new(20), limits)?;
    let next = BackupDestinationCursor {
        destination_id: BackupDestinationId::from_bytes([8; 16])?,
    };
    assert!(matches!(
        first,
        MetadataBackupWorkerOutcome::Progress {
            backup_id,
            published: 1,
            next: cursor,
            ..
        } if backup_id == run.backup_id && cursor == next
    ));
    assert_eq!(cycle.completions, 0);
    assert_eq!(cycle.releases, 0);

    let second = worker.run_once(&mut cycle, UnixMicros::new(30), limits)?;
    assert!(matches!(
        second,
        MetadataBackupWorkerOutcome::Protected {
            backup_id,
            revision,
            evidence,
        } if backup_id == run.backup_id
            && revision == Revision::new(9)
            && evidence.verified_copies == 2
    ));
    assert_eq!(cycle.dispatches, 2);
    assert_eq!(cycle.placements, 2);
    assert_eq!(cycle.completions, 1);
    assert_eq!(cycle.releases, 1);
    Ok(())
}

struct MemoryCycle {
    run: MetadataBackupRun,
    claim: MetadataBackupRunClaimRecord,
    prepared: PreparedMetadataBackup,
    dispatches: usize,
    placements: usize,
    completions: usize,
    releases: usize,
}

impl MetadataBackupCycle for MemoryCycle {
    fn dispatch(
        &mut self,
        _now: UnixMicros,
        _lease_duration: DurationMicros,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupCycleError> {
        self.dispatches += 1;
        let outcome = if self.dispatches == 1 {
            MetadataBackupDispatchOutcome::Claimed {
                run: self.run,
                claim: self.claim,
            }
        } else {
            let mut recorded = self.run;
            recorded.state = MetadataBackupRunState::Recorded;
            MetadataBackupDispatchOutcome::AwaitingProtection {
                run: recorded,
                claim: self.claim,
            }
        };
        Ok(outcome)
    }

    fn prepare(
        &mut self,
        _run: MetadataBackupRun,
        _now: UnixMicros,
    ) -> Result<PreparedMetadataBackup, MetadataBackupCycleError> {
        Ok(self.prepared.clone())
    }

    fn place(
        &mut self,
        input: MetadataBackupCyclePlacement<'_>,
    ) -> Result<MetadataBackupPlacementPage, MetadataBackupCycleError> {
        self.placements += 1;
        let expected = BackupDestinationCursor {
            destination_id: BackupDestinationId::from_bytes([8; 16])
                .map_err(|_| invalid_cycle_error())?,
        };
        if self.placements == 1 {
            assert_eq!(input.after, None);
            Ok(MetadataBackupPlacementPage {
                published: 1,
                evidence: evidence(input.run.backup_id, 1),
                next: Some(expected),
            })
        } else {
            assert_eq!(input.after, Some(expected));
            Ok(MetadataBackupPlacementPage {
                published: 1,
                evidence: evidence(input.run.backup_id, 2),
                next: None,
            })
        }
    }

    fn complete(
        &mut self,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<MetadataBackupCompletionOutcome, MetadataBackupCycleError> {
        self.completions += 1;
        Ok(MetadataBackupCompletionOutcome::Protected {
            backup_id,
            completed_at: now,
            revision: Revision::new(9),
            evidence: evidence(backup_id, 2),
        })
    }

    fn release(
        &mut self,
        prepared: &PreparedMetadataBackup,
    ) -> Result<(), MetadataBackupCycleError> {
        assert_eq!(prepared, &self.prepared);
        self.releases += 1;
        Ok(())
    }
}

fn run() -> Result<MetadataBackupRun, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupRun {
        backup_id: BackupId::from_bytes([2; 16])?,
        partition_id: PartitionId::from_bytes([3; 16])?,
        schedule_sequence: 1,
        run_sequence: 1,
        scheduled_for: UnixMicros::new(10),
        minimum_verified_copies: 2,
        minimum_independent_copies: 1,
        state: MetadataBackupRunState::Claimed,
        completed_at: None,
        result_digest: None,
        revision: Revision::new(4),
    })
}

fn claim(
    backup_id: BackupId,
) -> Result<MetadataBackupRunClaimRecord, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupRunClaimRecord {
        backup_id,
        claim: MetadataBackupRunClaim {
            claim_generation: 1,
            worker_node_id: NodeId::from_bytes([4; 16])?,
            worker_incarnation: 1,
            fence: 7,
        },
        lease_expires_at: UnixMicros::new(1_000),
        revision: Revision::new(5),
    })
}

fn prepared(
    run: MetadataBackupRun,
) -> Result<PreparedMetadataBackup, meshspan_domain::IdentifierError> {
    Ok(PreparedMetadataBackup {
        encrypted_path: PathBuf::from("/unused/backup.msbackup"),
        staging: LocalMetadataBackupStaging {
            evidence: BackupFileEvidence {
                source: BackupSourceManifest {
                    backup_id: run.backup_id,
                    partition_id: run.partition_id,
                    mesh_id: MeshId::from_bytes([5; 16])?,
                    last_log_index: 5,
                    last_log_term: 1,
                    state_revision: 6,
                    schema_version: 13,
                    byte_length: 100,
                    digest: [6; 32],
                    created_at: UnixMicros::new(20),
                },
                byte_length: 120,
                digest: [7; 32],
            },
            relative_file_name: "backup.msbackup".to_owned(),
            prepared_at: UnixMicros::new(20),
            revision: 1,
        },
    })
}

fn evidence(backup_id: BackupId, copies: u64) -> MetadataBackupProtectionEvidence {
    MetadataBackupProtectionEvidence {
        backup_id,
        verified_copies: copies,
        independent_copies: copies.saturating_sub(1),
        digest: [u8::try_from(copies).unwrap_or(u8::MAX); 32],
    }
}

fn invalid_cycle_error() -> MetadataBackupCycleError {
    MetadataBackupCycleError::Placement(crate::MetadataBackupPlacementError::InvalidProjection)
}
