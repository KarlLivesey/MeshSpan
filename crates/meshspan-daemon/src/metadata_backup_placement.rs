// SPDX-License-Identifier: GPL-2.0-only

//! Bounded resumable placement of one encrypted backup across configured destinations.

use meshspan_backup::BackupFileEvidence;
use meshspan_domain::{PrincipalId, UnixMicros};
use meshspan_metadata::{
    BackupDestinationCursor, BackupDestinationRecord, MetadataBackupProtectionEvidence,
    MetadataBackupRun, MetadataBackupRunClaim, MetadataBackupRunState, Page, PageLimit,
    RepositoryError,
};
use thiserror::Error;

use crate::{
    BackupPublicationError, BackupPublicationOutcome, BackupPublicationRequest,
    ConsensusAuthenticationAuthority,
};

/// Replicated inventory and evidence reads required by backup placement.
pub trait MetadataBackupPlacementAuthority {
    /// Returns one bounded page of currently active destinations.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid bounds or malformed destination state.
    fn active_backup_destinations(
        &self,
        after: Option<BackupDestinationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupDestinationRecord, BackupDestinationCursor>, RepositoryError>;

    /// Recomputes canonical evidence after each verified publication.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed copy or destination state.
    fn metadata_backup_protection_evidence(
        &self,
        backup_id: meshspan_domain::BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError>;
}

impl MetadataBackupPlacementAuthority for ConsensusAuthenticationAuthority {
    fn active_backup_destinations(
        &self,
        after: Option<BackupDestinationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupDestinationRecord, BackupDestinationCursor>, RepositoryError> {
        self.reader().active_backup_destinations(after, limit)
    }

    fn metadata_backup_protection_evidence(
        &self,
        backup_id: meshspan_domain::BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError> {
        self.reader().metadata_backup_protection_evidence(backup_id)
    }
}

/// Destination-specific provider resolution plus exact publication.
pub trait MetadataBackupDestinationWriter {
    /// Publishes one encrypted generation through the destination's exact provider binding.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable providers, stale bindings, changed bytes or invalid receipts.
    fn publish_destination(
        &mut self,
        destination: &BackupDestinationRecord,
        request: &BackupPublicationRequest<'_>,
    ) -> Result<BackupPublicationOutcome, BackupPublicationError>;
}

/// Result of one finite destination-placement page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupPlacementPage {
    /// Destinations successfully published during this pass.
    pub published: usize,
    /// Canonical verified-copy evidence after the last publication.
    pub evidence: MetadataBackupProtectionEvidence,
    /// Next destination seek position, absent once protected or at inventory end.
    pub next: Option<BackupDestinationCursor>,
}

/// Stateless bounded coordinator over replaceable destination writers.
pub struct MetadataBackupPlacementService<'a, Authority, Writer> {
    authority: &'a Authority,
    writer: &'a mut Writer,
}

impl<'a, Authority, Writer> MetadataBackupPlacementService<'a, Authority, Writer> {
    /// Binds one placement pass to current replicated authority and provider resolution.
    #[must_use]
    pub const fn new(authority: &'a Authority, writer: &'a mut Writer) -> Self {
        Self { authority, writer }
    }
}

impl<Authority, Writer> MetadataBackupPlacementService<'_, Authority, Writer>
where
    Authority: MetadataBackupPlacementAuthority,
    Writer: MetadataBackupDestinationWriter,
{
    /// Publishes at most `page_items` destinations, stopping as soon as policy is protected.
    ///
    /// Restarting from no cursor is safe because each destination publication is exactly
    /// replayable. The explicit cursor avoids repeated successful provider IO during one run.
    ///
    /// # Errors
    ///
    /// Rejects mismatched run/evidence, terminal runs, invalid time bounds, malformed pages and
    /// any provider or catalogue publication failure.
    pub fn publish_page(
        &mut self,
        input: MetadataBackupPlacementInput<'_>,
    ) -> Result<MetadataBackupPlacementPage, MetadataBackupPlacementError> {
        validate_input(&input)?;
        let mut evidence = self
            .authority
            .metadata_backup_protection_evidence(input.run.backup_id)?;
        validate_evidence(input.run, evidence)?;
        if protected(input.run, evidence) {
            return Ok(MetadataBackupPlacementPage {
                published: 0,
                evidence,
                next: None,
            });
        }
        let page = self
            .authority
            .active_backup_destinations(input.after, PageLimit::new(input.page_items)?)?;
        let mut published = 0_usize;
        for destination in &page.items {
            let request = BackupPublicationRequest {
                encrypted_source: input.encrypted_source,
                evidence: input.backup,
                destination_id: destination.destination_id,
                claim: input.claim,
                actor_principal_id: input.actor_principal_id,
                now: input.now,
                deadline: input.deadline,
            };
            let outcome = self.writer.publish_destination(destination, &request)?;
            if outcome.backup.backup_id != input.run.backup_id
                || outcome.copy.backup_id != input.run.backup_id
                || outcome.copy.destination_id != destination.destination_id
            {
                return Err(MetadataBackupPlacementError::InvalidProjection);
            }
            published = published
                .checked_add(1)
                .ok_or(MetadataBackupPlacementError::Capacity)?;
            evidence = self
                .authority
                .metadata_backup_protection_evidence(input.run.backup_id)?;
            validate_evidence(input.run, evidence)?;
            if protected(input.run, evidence) {
                return Ok(MetadataBackupPlacementPage {
                    published,
                    evidence,
                    next: None,
                });
            }
        }
        Ok(MetadataBackupPlacementPage {
            published,
            evidence,
            next: page.next,
        })
    }
}

/// Complete inputs shared by every destination in one placement page.
#[derive(Clone, Copy, Debug)]
pub struct MetadataBackupPlacementInput<'a> {
    /// Claimed or recorded run whose captured thresholds control completion.
    pub run: MetadataBackupRun,
    /// Exact claim required when the first provider copy admits the generation.
    pub claim: MetadataBackupRunClaim,
    /// Closed encrypted backup container.
    pub encrypted_source: &'a std::path::Path,
    /// Exact source/container evidence.
    pub backup: BackupFileEvidence,
    /// Authoritative automation principal.
    pub actor_principal_id: PrincipalId,
    /// Authority time for this pass.
    pub now: UnixMicros,
    /// Strict provider IO deadline.
    pub deadline: UnixMicros,
    /// Prior destination seek position.
    pub after: Option<BackupDestinationCursor>,
    /// Maximum destinations attempted in this pass.
    pub page_items: usize,
}

fn validate_input(
    input: &MetadataBackupPlacementInput<'_>,
) -> Result<(), MetadataBackupPlacementError> {
    input.backup.source.validate()?;
    if input.run.backup_id != input.backup.source.backup_id
        || !matches!(
            input.run.state,
            MetadataBackupRunState::Claimed | MetadataBackupRunState::Recorded
        )
        || input.claim.claim_generation == 0
        || input.claim.worker_incarnation == 0
        || input.claim.fence == 0
        || input.now.get() < 0
        || input.deadline <= input.now
    {
        Err(MetadataBackupPlacementError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_evidence(
    run: MetadataBackupRun,
    evidence: MetadataBackupProtectionEvidence,
) -> Result<(), MetadataBackupPlacementError> {
    if evidence.backup_id == run.backup_id && evidence.digest != [0; 32] {
        Ok(())
    } else {
        Err(MetadataBackupPlacementError::InvalidProjection)
    }
}

fn protected(run: MetadataBackupRun, evidence: MetadataBackupProtectionEvidence) -> bool {
    evidence.verified_copies >= u64::from(run.minimum_verified_copies)
        && evidence.independent_copies >= u64::from(run.minimum_independent_copies)
}

/// Closed failure from one bounded destination-placement page.
#[derive(Debug, Error)]
pub enum MetadataBackupPlacementError {
    /// Run, claim, backup evidence, time or page input is invalid.
    #[error("metadata backup placement input is invalid")]
    InvalidInput,
    /// Destination publication or protection evidence contradicted the requested run.
    #[error("metadata backup placement projection is invalid")]
    InvalidProjection,
    /// A bounded placement counter cannot advance safely.
    #[error("metadata backup placement capacity was exceeded")]
    Capacity,
    /// Replicated metadata could not be read safely.
    #[error("metadata backup placement metadata failed")]
    Repository(#[from] RepositoryError),
    /// One destination publication failed closed.
    #[error("metadata backup destination publication failed")]
    Publication(#[from] BackupPublicationError),
    /// Backup source evidence was malformed.
    #[error("metadata backup placement source evidence was invalid")]
    Backup(#[from] meshspan_backup::BackupError),
}
