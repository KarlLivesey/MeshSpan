// SPDX-License-Identifier: GPL-2.0-only

use std::cell::Cell;
use std::path::Path;

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, MeshId, NodeId, PartitionId, PrincipalId,
    Revision, UnixMicros,
};
use meshspan_metadata::{
    BackupCopyRecord, BackupCopyState, BackupDestinationBinding, BackupDestinationCursor,
    BackupDestinationRecord, BackupDestinationState, BackupFailureRelationship,
    MetadataBackupProtectionEvidence, MetadataBackupRecord, MetadataBackupRun,
    MetadataBackupRunClaim, MetadataBackupRunState, MetadataBackupState, Page, PageLimit,
    RepositoryError,
};

use crate::{
    BackupPublicationError, BackupPublicationOutcome, BackupPublicationRequest,
    MetadataBackupDestinationWriter, MetadataBackupPlacementAuthority,
    MetadataBackupPlacementInput, MetadataBackupPlacementService,
};

#[test]
fn placement_pages_and_stops_immediately_when_captured_policy_is_met()
-> Result<(), Box<dyn std::error::Error>> {
    let backup_id = BackupId::from_bytes([1; 16])?;
    let destinations = [
        destination(10, BackupFailureRelationship::Overlapping)?,
        destination(11, BackupFailureRelationship::Independent)?,
        destination(12, BackupFailureRelationship::Independent)?,
    ];
    let authority = MemoryAuthority::new(backup_id, destinations.clone());
    let mut writer = MemoryWriter::new(&authority, backup(backup_id)?);
    let input = placement_input(backup_id)?;

    let first = MetadataBackupPlacementService::new(&authority, &mut writer).publish_page(
        MetadataBackupPlacementInput {
            page_items: 1,
            ..input
        },
    )?;
    assert_eq!(first.published, 1);
    assert_eq!(first.evidence.verified_copies, 1);
    assert_eq!(
        first.next,
        Some(BackupDestinationCursor {
            destination_id: destinations[0].destination_id,
        })
    );

    let second = MetadataBackupPlacementService::new(&authority, &mut writer).publish_page(
        MetadataBackupPlacementInput {
            after: first.next,
            page_items: 2,
            ..input
        },
    )?;
    assert_eq!(second.published, 1);
    assert_eq!(second.evidence.verified_copies, 2);
    assert_eq!(second.evidence.independent_copies, 1);
    assert_eq!(second.next, None);
    assert_eq!(writer.publications.get(), 2);
    Ok(())
}

struct MemoryAuthority {
    backup_id: BackupId,
    destinations: [BackupDestinationRecord; 3],
    verified: Cell<u64>,
    independent: Cell<u64>,
}

impl MemoryAuthority {
    const fn new(backup_id: BackupId, destinations: [BackupDestinationRecord; 3]) -> Self {
        Self {
            backup_id,
            destinations,
            verified: Cell::new(0),
            independent: Cell::new(0),
        }
    }

    fn evidence(&self) -> MetadataBackupProtectionEvidence {
        MetadataBackupProtectionEvidence {
            backup_id: self.backup_id,
            verified_copies: self.verified.get(),
            independent_copies: self.independent.get(),
            digest: [20_u8.wrapping_add(u8::try_from(self.verified.get()).unwrap_or(u8::MAX)); 32],
        }
    }
}

impl MetadataBackupPlacementAuthority for MemoryAuthority {
    fn active_backup_destinations(
        &self,
        after: Option<BackupDestinationCursor>,
        _limit: PageLimit,
    ) -> Result<Page<BackupDestinationRecord, BackupDestinationCursor>, RepositoryError> {
        if after.is_none() {
            return Ok(Page {
                items: vec![self.destinations[0].clone()],
                next: Some(BackupDestinationCursor {
                    destination_id: self.destinations[0].destination_id,
                }),
            });
        }
        Ok(Page {
            items: self.destinations[1..].to_vec(),
            next: None,
        })
    }

    fn metadata_backup_protection_evidence(
        &self,
        backup_id: BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError> {
        if backup_id == self.backup_id {
            Ok(self.evidence())
        } else {
            Err(RepositoryError::CorruptState)
        }
    }
}

struct MemoryWriter<'a> {
    authority: &'a MemoryAuthority,
    backup: MetadataBackupRecord,
    publications: Cell<usize>,
}

impl<'a> MemoryWriter<'a> {
    const fn new(authority: &'a MemoryAuthority, backup: MetadataBackupRecord) -> Self {
        Self {
            authority,
            backup,
            publications: Cell::new(0),
        }
    }
}

impl MetadataBackupDestinationWriter for MemoryWriter<'_> {
    fn publish_destination(
        &mut self,
        destination: &BackupDestinationRecord,
        request: &BackupPublicationRequest<'_>,
    ) -> Result<BackupPublicationOutcome, BackupPublicationError> {
        if destination.destination_id != request.destination_id
            || request.evidence.source.backup_id != self.backup.backup_id
        {
            return Err(BackupPublicationError::InvalidInput);
        }
        self.publications.set(self.publications.get() + 1);
        self.authority
            .verified
            .set(self.authority.verified.get() + 1);
        if destination.failure_relationship == BackupFailureRelationship::Independent {
            self.authority
                .independent
                .set(self.authority.independent.get() + 1);
        }
        Ok(BackupPublicationOutcome {
            backup: self.backup,
            copy: BackupCopyRecord {
                backup_id: self.backup.backup_id,
                destination_id: destination.destination_id,
                provider_generation: destination.binding.provider_generation(),
                object_reference: "memory-backup".to_owned(),
                byte_length: self.backup.encrypted_byte_length,
                copy_digest: self.backup.encrypted_digest,
                state: BackupCopyState::Verified,
                stored_at: request.now,
                verified_at: Some(request.now),
                revision: Revision::new(2),
            },
        })
    }
}

fn placement_input(
    backup_id: BackupId,
) -> Result<MetadataBackupPlacementInput<'static>, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupPlacementInput {
        run: MetadataBackupRun {
            backup_id,
            partition_id: PartitionId::from_bytes([2; 16])?,
            schedule_sequence: 1,
            run_sequence: 1,
            scheduled_for: UnixMicros::new(10),
            minimum_verified_copies: 2,
            minimum_independent_copies: 1,
            state: MetadataBackupRunState::Claimed,
            completed_at: None,
            result_digest: None,
            revision: Revision::new(1),
        },
        claim: MetadataBackupRunClaim {
            claim_generation: 1,
            worker_node_id: NodeId::from_bytes([3; 16])?,
            worker_incarnation: 1,
            fence: 4,
        },
        encrypted_source: Path::new("/unused/backup.msbackup"),
        backup: evidence(backup_id)?,
        actor_principal_id: PrincipalId::from_bytes([5; 16])?,
        now: UnixMicros::new(20),
        deadline: UnixMicros::new(100),
        after: None,
        page_items: 1,
    })
}

fn evidence(backup_id: BackupId) -> Result<BackupFileEvidence, meshspan_domain::IdentifierError> {
    Ok(BackupFileEvidence {
        source: BackupSourceManifest {
            backup_id,
            partition_id: PartitionId::from_bytes([2; 16])?,
            mesh_id: MeshId::from_bytes([6; 16])?,
            last_log_index: 1,
            last_log_term: 1,
            state_revision: 1,
            schema_version: 1,
            byte_length: 100,
            digest: [7; 32],
            created_at: UnixMicros::new(10),
        },
        byte_length: 120,
        digest: [8; 32],
    })
}

fn backup(backup_id: BackupId) -> Result<MetadataBackupRecord, meshspan_domain::IdentifierError> {
    let evidence = evidence(backup_id)?;
    Ok(MetadataBackupRecord {
        backup_id,
        partition_id: evidence.source.partition_id,
        mesh_id: evidence.source.mesh_id,
        last_log_index: evidence.source.last_log_index,
        last_log_term: evidence.source.last_log_term,
        state_revision: Revision::new(evidence.source.state_revision),
        schema_version: evidence.source.schema_version,
        source_byte_length: evidence.source.byte_length,
        source_digest: evidence.source.digest,
        manifest_digest: evidence.source.catalogue_digest(),
        encrypted_byte_length: evidence.byte_length,
        encrypted_digest: evidence.digest,
        state: MetadataBackupState::Recorded,
        created_at: UnixMicros::new(20),
        verified_at: None,
        revision: Revision::new(2),
    })
}

fn destination(
    identity: u8,
    failure_relationship: BackupFailureRelationship,
) -> Result<BackupDestinationRecord, meshspan_domain::IdentifierError> {
    Ok(BackupDestinationRecord {
        destination_id: BackupDestinationId::from_bytes([identity; 16])?,
        display_name: format!("Destination {identity}"),
        canonical_name: format!("destination {identity}"),
        binding: BackupDestinationBinding::ComponentProvider {
            instance_id: ComponentInstanceId::from_bytes([identity + 20; 16])?,
            provider_generation: 1,
        },
        failure_relationship,
        failure_evidence_digest: [identity + 40; 32],
        state: BackupDestinationState::Active,
        created_at: UnixMicros::new(1),
        revision: Revision::new(1),
    })
}
