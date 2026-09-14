// SPDX-License-Identifier: GPL-2.0-only

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::BackupDestinationId;
use meshspan_metadata::{
    AuthoritativeCommand, BackupDestinationRecord, BackupReclamationCandidate,
    BackupReclamationCursor, CommandContext, CommandReceipt, Page, PageLimit, RepositoryError,
    RetireMetadataBackup,
};

pub(crate) trait BackupRetentionAuthority {
    fn unadmitted(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<meshspan_metadata::AbandonedBackupPublication, BackupReclamationCursor>,
        RepositoryError,
    >;
    fn candidate(&self) -> Result<Option<RetireMetadataBackup>, RepositoryError>;
    fn pending(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupReclamationCandidate, BackupReclamationCursor>, RepositoryError>;
    fn destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError>;
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl BackupRetentionAuthority for crate::ConsensusAuthenticationAuthority {
    fn unadmitted(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<meshspan_metadata::AbandonedBackupPublication, BackupReclamationCursor>,
        RepositoryError,
    > {
        self.reader().abandoned_backup_publications(after, limit)
    }
    fn candidate(&self) -> Result<Option<RetireMetadataBackup>, RepositoryError> {
        self.reader().metadata_backup_retirement_candidate()
    }
    fn pending(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupReclamationCandidate, BackupReclamationCursor>, RepositoryError> {
        self.reader().pending_backup_reclamations(after, limit)
    }
    fn destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        self.reader().backup_destination(destination_id)
    }
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}
