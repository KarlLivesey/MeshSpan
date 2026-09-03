// SPDX-License-Identifier: GPL-2.0-only

use std::cell::Cell;

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    BackupId, EntropyError, MeshId, PartitionId, PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, MetadataBackupProtectionEvidence, MetadataBackupRecord,
    MetadataBackupRun, MetadataBackupRunState, MetadataBackupState, RepositoryError,
};

use crate::{
    MetadataBackupCompletionAuthority, MetadataBackupCompletionOutcome,
    MetadataBackupCompletionService,
};

#[test]
fn completion_waits_for_canonical_thresholds_then_commits_exact_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let backup_id = BackupId::from_bytes([1; 16])?;
    let authority = MemoryAuthority::new(run(backup_id)?, backup(backup_id)?);
    let actor = PrincipalId::from_bytes([4; 16])?;
    let mut random = CounterRandom::default();
    let awaiting = MetadataBackupCompletionService::new(&authority, &mut random, actor)
        .complete_if_protected(backup_id, UnixMicros::new(20))?;
    assert_eq!(
        awaiting,
        MetadataBackupCompletionOutcome::AwaitingCopies {
            evidence: authority.evidence.get(),
        }
    );
    assert_eq!(authority.commit_count.get(), 0);

    authority.evidence.set(MetadataBackupProtectionEvidence {
        backup_id,
        verified_copies: 3,
        independent_copies: 2,
        digest: [9; 32],
    });
    let completed = MetadataBackupCompletionService::new(&authority, &mut random, actor)
        .complete_if_protected(backup_id, UnixMicros::new(30))?;
    let MetadataBackupCompletionOutcome::Protected {
        backup_id: completed_id,
        completed_at,
        revision,
        evidence,
    } = completed
    else {
        return Err("protected evidence did not complete the run".into());
    };
    assert_eq!(completed_id, backup_id);
    assert_eq!(completed_at, UnixMicros::new(30));
    assert_eq!(revision, Revision::new(2));
    assert_eq!(evidence.digest, [9; 32]);
    assert_eq!(authority.run.get().state, MetadataBackupRunState::Protected);
    assert_eq!(authority.backup.get().state, MetadataBackupState::Verified);
    assert_eq!(authority.commit_count.get(), 1);
    Ok(())
}

struct MemoryAuthority {
    run: Cell<MetadataBackupRun>,
    backup: Cell<MetadataBackupRecord>,
    evidence: Cell<MetadataBackupProtectionEvidence>,
    commit_count: Cell<u64>,
}

impl MemoryAuthority {
    fn new(run: MetadataBackupRun, backup: MetadataBackupRecord) -> Self {
        Self {
            run: Cell::new(run),
            backup: Cell::new(backup),
            evidence: Cell::new(MetadataBackupProtectionEvidence {
                backup_id: run.backup_id,
                verified_copies: 1,
                independent_copies: 1,
                digest: [8; 32],
            }),
            commit_count: Cell::new(0),
        }
    }
}

impl MetadataBackupCompletionAuthority for MemoryAuthority {
    fn metadata_backup_run(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRun>, RepositoryError> {
        Ok((self.run.get().backup_id == backup_id).then(|| self.run.get()))
    }

    fn metadata_backup_protection_evidence(
        &self,
        backup_id: BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError> {
        let evidence = self.evidence.get();
        if evidence.backup_id == backup_id {
            Ok(evidence)
        } else {
            Err(RepositoryError::CorruptState)
        }
    }

    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        Ok((self.backup.get().backup_id == backup_id).then(|| self.backup.get()))
    }

    fn commit_metadata_backup_completion(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let AuthoritativeCommand::CompleteMetadataBackupRun(value) = command else {
            return Err(MetadataAuthorityRequestError::Rejected);
        };
        let evidence = self.evidence.get();
        let supplied_digest = match value.outcome {
            meshspan_metadata::MetadataBackupRunCompletion::Protected { result_digest }
            | meshspan_metadata::MetadataBackupRunCompletion::Incomplete { result_digest } => {
                result_digest
            }
        };
        if value.backup_id != self.run.get().backup_id || supplied_digest != evidence.digest {
            return Err(MetadataAuthorityRequestError::Rejected);
        }
        self.commit_count.set(self.commit_count.get() + 1);
        let revision = self
            .run
            .get()
            .revision
            .next()
            .map_err(|_| MetadataAuthorityRequestError::Failed)?;
        let mut run = self.run.get();
        run.state = MetadataBackupRunState::Protected;
        run.completed_at = Some(context.occurred_at);
        run.result_digest = Some(evidence.digest);
        run.revision = revision;
        self.run.set(run);
        let mut backup = self.backup.get();
        backup.state = MetadataBackupState::Verified;
        backup.verified_at = Some(context.occurred_at);
        backup.revision = revision;
        self.backup.set(backup);
        Ok(receipt(context, command, value.backup_id, revision))
    }
}

fn receipt(
    context: CommandContext,
    command: &AuthoritativeCommand,
    backup_id: BackupId,
    revision: Revision,
) -> CommandReceipt {
    let position = LogPosition {
        index: revision.get(),
        term: 1,
    };
    CommandReceipt {
        disposition: ApplyDisposition::Applied,
        operation_id: context.operation_id,
        request_digest: command.request_digest(context),
        result_digest: [10; 32],
        committed_revision: revision,
        committed_position: position,
        applied_position: position,
        entity: EntityReference {
            kind: EntityKind::MetadataBackupRun,
            id: backup_id.as_bytes(),
        },
    }
}

fn run(backup_id: BackupId) -> Result<MetadataBackupRun, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupRun {
        backup_id,
        partition_id: PartitionId::from_bytes([2; 16])?,
        schedule_sequence: 1,
        run_sequence: 1,
        scheduled_for: UnixMicros::new(10),
        minimum_verified_copies: 3,
        minimum_independent_copies: 2,
        state: MetadataBackupRunState::Recorded,
        completed_at: None,
        result_digest: None,
        revision: Revision::new(1),
    })
}

fn backup(backup_id: BackupId) -> Result<MetadataBackupRecord, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupRecord {
        backup_id,
        partition_id: PartitionId::from_bytes([2; 16])?,
        mesh_id: MeshId::from_bytes([3; 16])?,
        last_log_index: 1,
        last_log_term: 1,
        state_revision: Revision::new(1),
        schema_version: 1,
        source_byte_length: 100,
        source_digest: [5; 32],
        manifest_digest: [6; 32],
        encrypted_byte_length: 120,
        encrypted_digest: [7; 32],
        state: MetadataBackupState::Recorded,
        created_at: UnixMicros::new(10),
        verified_at: None,
        revision: Revision::new(1),
    })
}

#[derive(Default)]
struct CounterRandom(u8);

impl RandomSource for CounterRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.0.wrapping_add(u8::try_from(index).unwrap_or(u8::MAX));
        }
        Ok(())
    }
}
