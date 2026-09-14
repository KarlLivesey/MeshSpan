// SPDX-License-Identifier: GPL-2.0-only

//! Local staging reclamation after authoritative unadmitted-run abandonment.

use meshspan_domain::BackupId;
use meshspan_metadata::MetadataBackupRunState;

use super::{
    MetadataBackupPreparationError, MetadataBackupPreparationService, PreparedMetadataBackup,
    encrypted_file_name,
};
use crate::ConsensusAuthenticationAuthority;

pub(crate) struct AbandonedStagingCleanup {
    pub next: Option<BackupId>,
    pub reclaimed: usize,
    pub failed: usize,
}

impl<Random> MetadataBackupPreparationService<'_, ConsensusAuthenticationAuthority, Random> {
    /// Reclaims one page using committed terminal state plus exact local ownership.
    /// A missing catalogue entry or expired claim alone never permits deletion.
    pub(crate) fn release_abandoned_page(
        &mut self,
        after: Option<BackupId>,
    ) -> Result<AbandonedStagingCleanup, MetadataBackupPreparationError> {
        let page = self.local.metadata_backup_staging_page(after, 16)?;
        let mut result = AbandonedStagingCleanup {
            next: page.next,
            reclaimed: 0,
            failed: 0,
        };
        for staging in page.items {
            let source = staging.evidence.source;
            let reader = self.authority.reader();
            let Some(run) = reader.metadata_backup_run(source.backup_id)? else {
                continue;
            };
            if run.partition_id != source.partition_id
                || run.state != MetadataBackupRunState::Incomplete
                || run.completed_at.is_none()
                || run.result_digest.is_none()
                || reader.metadata_backup(source.backup_id)?.is_some()
                || reader
                    .metadata_backup_run_claim(source.backup_id)?
                    .is_some()
            {
                continue;
            }
            let prepared = PreparedMetadataBackup {
                encrypted_path: self.directory.join(encrypted_file_name(source.backup_id)),
                staging,
            };
            // A broken local file cannot indefinitely starve later journal entries.
            // The retained record retries on the next sweep; callers report failures.
            match self.release(&prepared) {
                Ok(()) => result.reclaimed += 1,
                Err(_) => result.failed += 1,
            }
        }
        Ok(result)
    }
}
