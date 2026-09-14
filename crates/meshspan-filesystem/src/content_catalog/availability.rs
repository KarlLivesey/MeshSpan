// SPDX-License-Identifier: GPL-2.0-only

//! Incremental survivor checks without keeping a database transaction open across provider IO.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_contracts::{CodingScheme, ContractError};
use meshspan_domain::{AvailabilityCellId, ContentManifestId, OperationId, TargetId, VolumeId};
use rusqlite::{OptionalExtension, params};
use thiserror::Error;

use super::{ContentCatalogError, DurableContentCatalog};
use crate::{
    ContentShardRouter, ProtectedShardRepairer, PublishedContentReference, StripeReadRequest,
};

/// Fixed policy-selected targets for global and required complete-local read checks.
pub struct ReadAvailabilityScopes {
    /// Targets which may contribute globally.
    pub targets: BTreeSet<TargetId>,
    /// Independently decodable target sets for each required complete-local cell.
    pub required_cells: BTreeMap<AvailabilityCellId, BTreeSet<TargetId>>,
}

/// Progress through one local catalogue and a fixed survivor/locality selection.
///
/// Completion covers every committed publication in this volume, including retained versions
/// and incomplete optional replication. It is not a mesh-wide inventory, protection proof,
/// decryption-key check, future availability lease or authority to restart a node.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VolumeReadAvailabilityProgress {
    /// Fully checked publications, including valid empty files.
    pub publications: u64,
    /// Stripes reconstructed in the global survivor set and every required cell.
    pub stripes: u64,
    /// Whether the complete local committed-publication index was exhausted unchanged.
    pub complete: bool,
}

/// A process-local resumable scan. Restart starts a fresh scan, never restores stale evidence.
///
/// The scan owns its catalogue connection, allowing an IO worker to retain it between ticks
/// without self-referential borrows. It exposes no writes. SQLite data-version
/// checks detect commits through other connections. No read transaction spans provider IO.
/// Target sets are fixed for the scan; their owning metadata revision, scope
/// completeness and final publication fence remain the update coordinator's responsibility.
pub struct VolumeReadAvailabilityProbe {
    catalogue: DurableContentCatalog,
    volume: VolumeId,
    survivors: BTreeSet<TargetId>,
    required_cells: BTreeMap<AvailabilityCellId, BTreeSet<TargetId>>,
    data_version: i64,
    after: Option<OperationId>,
    current: Option<Publication>,
    progress: VolumeReadAvailabilityProgress,
}

#[derive(Clone, Copy)]
struct Publication {
    content: PublishedContentReference,
    chunks: u64,
    next_chunk: u64,
}

impl DurableContentCatalog {
    /// Starts a read-only scan of this volume against global and required-cell survivors.
    ///
    /// # Errors
    /// Rejects required-cell targets outside the global survivor set and database failure.
    pub fn into_read_availability(
        self,
        volume: VolumeId,
        survivors: BTreeSet<TargetId>,
        required_cells: BTreeMap<AvailabilityCellId, BTreeSet<TargetId>>,
    ) -> Result<VolumeReadAvailabilityProbe, VolumeReadAvailabilityError> {
        if required_cells
            .values()
            .any(|targets| !targets.is_subset(&survivors))
        {
            return Err(ContractError::InvalidInput.into());
        }
        let data_version = data_version(&self)?;
        Ok(VolumeReadAvailabilityProbe {
            catalogue: self,
            volume,
            survivors,
            required_cells,
            data_version,
            after: None,
            current: None,
            progress: VolumeReadAvailabilityProgress::default(),
        })
    }
}

impl VolumeReadAvailabilityProbe {
    /// Continues with a later volume while retaining the original catalogue-change fence.
    ///
    /// # Errors
    /// Rejects unfinished scans, non-increasing volume identities, invalid cell selectors and
    /// catalogue changes. No new connection or freshness baseline is substituted.
    pub fn next_volume(
        &mut self,
        volume: VolumeId,
        survivors: BTreeSet<TargetId>,
        required_cells: BTreeMap<AvailabilityCellId, BTreeSet<TargetId>>,
    ) -> Result<(), VolumeReadAvailabilityError> {
        self.check_unchanged()?;
        if !self.progress.complete
            || volume <= self.volume
            || required_cells
                .values()
                .any(|targets| !targets.is_subset(&survivors))
        {
            return Err(ContractError::InvalidInput.into());
        }
        self.volume = volume;
        self.survivors = survivors;
        self.required_cells = required_cells;
        self.after = None;
        self.current = None;
        self.progress = VolumeReadAvailabilityProgress::default();
        Ok(())
    }

    /// Verifies at most one stripe in every required scope, under the supplied read deadline.
    ///
    /// Each scope reads at most the coding layout's slice bound. Calls resume at the next
    /// stripe; empty publications still consume a step. Failed checks do not advance progress.
    /// Call this on the owned storage worker, not an async executor thread.
    ///
    /// # Errors
    /// Refuses changed catalogues, unsupported legacy layouts, missing/corrupt records and
    /// insufficient verified survivors. A changed catalogue requires a new scan.
    pub fn advance<R: ContentShardRouter, C: CodingScheme>(
        &mut self,
        verifier: &ProtectedShardRepairer<R, C>,
        request: StripeReadRequest,
    ) -> Result<VolumeReadAvailabilityProgress, VolumeReadAvailabilityError> {
        if request.deadline <= request.observed_at
            || request.observed_at.get() < 0
            || request.authorization_revision == meshspan_domain::Revision::ZERO
        {
            return Err(ContractError::InvalidInput.into());
        }
        self.check_unchanged()?;
        if self.progress.complete {
            return Ok(self.progress);
        }
        if self.current.is_none() {
            self.current = self.next_publication()?;
        }
        let Some(mut publication) = self.current else {
            self.check_unchanged()?;
            self.progress.complete = true;
            return Ok(self.progress);
        };
        if publication.next_chunk < publication.chunks {
            self.verify_stripe(verifier, request, publication)?;
            self.check_unchanged()?;
            publication.next_chunk += 1;
            self.progress.stripes = self
                .progress
                .stripes
                .checked_add(1)
                .ok_or(ContractError::ResourceExhausted)?;
        }
        self.check_unchanged()?;
        if publication.next_chunk == publication.chunks {
            self.progress.publications = self
                .progress
                .publications
                .checked_add(1)
                .ok_or(ContractError::ResourceExhausted)?;
            self.after = Some(publication.content.publication_operation_id);
            self.current = None;
        } else {
            self.current = Some(publication);
        }
        Ok(self.progress)
    }

    /// Rechecks catalogue freshness before returning retained progress, including completion.
    ///
    /// # Errors
    /// Rejects intervening commits through another connection or database failure.
    pub fn progress(&self) -> Result<VolumeReadAvailabilityProgress, VolumeReadAvailabilityError> {
        self.check_unchanged()?;
        Ok(self.progress)
    }

    fn check_unchanged(&self) -> Result<(), VolumeReadAvailabilityError> {
        if data_version(&self.catalogue)? != self.data_version {
            return Err(VolumeReadAvailabilityError::CatalogueChanged);
        }
        Ok(())
    }

    fn verify_stripe<R: ContentShardRouter, C: CodingScheme>(
        &self,
        verifier: &ProtectedShardRepairer<R, C>,
        request: StripeReadRequest,
        publication: Publication,
    ) -> Result<(), VolumeReadAvailabilityError> {
        let stripe = self
            .catalogue
            .committed_protected_stripe(publication.content, publication.next_chunk)?;
        for scope in std::iter::once(&self.survivors).chain(self.required_cells.values()) {
            let targets: BTreeSet<_> = stripe
                .receipts
                .as_slice()
                .iter()
                .map(|receipt| receipt.target_id)
                .filter(|target| scope.contains(target))
                .collect();
            verifier.verify_read_availability(
                request,
                &stripe,
                &targets.into_iter().collect::<Vec<_>>(),
            )?;
        }
        Ok(())
    }

    fn next_publication(&self) -> Result<Option<Publication>, VolumeReadAvailabilityError> {
        let after = self.after.map_or([0; 16], OperationId::as_bytes);
        let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = self
            .catalogue
            .connection
            .query_row(
                "SELECT operation_id, manifest_id, format_version, chunk_count
             FROM content_publications WHERE volume_id = ?1 AND operation_id > ?2 AND state = 2
             ORDER BY operation_id LIMIT 1",
                params![self.volume.as_bytes().as_slice(), after.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(ContentCatalogError::from)?;
        row.map(|(operation, manifest, format, chunks)| {
            if format != 2 {
                return Err(VolumeReadAvailabilityError::UnsupportedLayout);
            }
            let operation = OperationId::from_bytes(
                operation
                    .try_into()
                    .map_err(|_| ContentCatalogError::Corrupt)?,
            )
            .map_err(|_| ContentCatalogError::Corrupt)?;
            let manifest = ContentManifestId::from_bytes(
                manifest
                    .try_into()
                    .map_err(|_| ContentCatalogError::Corrupt)?,
            )
            .map_err(|_| ContentCatalogError::Corrupt)?;
            let content = self
                .catalogue
                .committed_content_by_manifest(manifest)?
                .filter(|content| content.publication_operation_id == operation)
                .ok_or(ContentCatalogError::Corrupt)?;
            let layout = self.catalogue.committed_layout(content)?;
            let chunks = u64::try_from(chunks).map_err(|_| ContentCatalogError::Corrupt)?;
            let expected = content
                .manifest
                .logical_length
                .div_ceil(layout.layout.chunk_bytes);
            if chunks != expected {
                return Err(ContentCatalogError::Corrupt.into());
            }
            Ok(Publication {
                content,
                chunks,
                next_chunk: 0,
            })
        })
        .transpose()
    }
}

fn data_version(catalogue: &DurableContentCatalog) -> Result<i64, ContentCatalogError> {
    catalogue
        .connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(Into::into)
}

/// A failed scan never supplies restart, reclamation or protection authority.
#[derive(Debug, Error)]
pub enum VolumeReadAvailabilityError {
    /// Another connection changed this catalogue; discard all progress and start again.
    #[error("content catalogue changed during availability verification")]
    CatalogueChanged,
    /// This probe cannot establish survivor availability for a legacy unprotected layout.
    #[error("content availability requires a supported protected layout")]
    UnsupportedLayout,
    /// Catalogue IO or stored metadata failed validation.
    #[error(transparent)]
    Catalogue(#[from] ContentCatalogError),
    /// Read authority, provider bytes or survivor capacity failed validation.
    #[error(transparent)]
    Read(#[from] ContractError),
}
