// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated authority boundary for backup publication.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{BackupDestinationId, BackupId};
use meshspan_metadata::{
    AuthoritativeCommand, BackupCopyRecord, BackupDestinationRecord, CommandContext,
    CommandReceipt, MetadataBackupRecord, RepositoryError,
};

use crate::ConsensusAuthenticationAuthority;

/// Replicated reads and mutations required to publish one metadata backup copy.
pub trait BackupPublicationAuthority {
    /// Loads an existing backup generation.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed replicated state.
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError>;

    /// Loads the exact configured destination and provider generation.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed replicated state.
    fn backup_destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError>;

    /// Loads an existing copy for retry reconciliation.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed replicated state.
    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError>;

    /// Commits one catalogue transition through current consensus authority.
    ///
    /// # Errors
    ///
    /// Never reports success without a durable authoritative receipt.
    fn commit_backup_publication(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl BackupPublicationAuthority for ConsensusAuthenticationAuthority {
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        self.reader().metadata_backup(backup_id)
    }

    fn backup_destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        self.reader().backup_destination(destination_id)
    }

    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError> {
        self.reader().backup_copy(backup_id, destination_id)
    }

    fn commit_backup_publication(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}
