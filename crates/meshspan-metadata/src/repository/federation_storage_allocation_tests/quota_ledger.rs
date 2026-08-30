// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::ShardIdentity;
use meshspan_domain::{FederationStorageAction, OperationId, UnixMicros};

use super::{Fixture, allocation, apply_allocation, authority_request, prepare_storage_authority};
use crate::{
    AuthoritativeRepository, FederationStorageAllocationAuthority,
    FederationStorageQuotaDisposition, FederationStorageQuotaError, FederationStorageUsage,
    FederationStorageWriteAbsence, FederationStorageWriteCompletion,
    FederationStorageWriteReservationRequest, FederationStorageWriteState, LocalDatabase,
};

#[test]
fn reservations_are_bounded_idempotent_deduplicated_and_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let first = request(40, 41, fixture.authority(30)?, shard(42))?;
    let (disposition, reserved) = fixture
        .local
        .reserve_federated_storage_write(fixture.authority(30)?, first)?;
    assert_eq!(disposition, FederationStorageQuotaDisposition::Applied);
    assert_eq!(reserved.state, FederationStorageWriteState::Reserved);
    assert_usage(&fixture, 50, 0, 30)?;

    let (disposition, replay) = fixture
        .local
        .reserve_federated_storage_write(fixture.authority(30)?, first)?;
    assert_eq!(disposition, FederationStorageQuotaDisposition::Replayed);
    assert_eq!(replay, reserved);
    assert_usage(&fixture, 50, 0, 30)?;

    let conflicting = FederationStorageWriteReservationRequest {
        request_digest: [99; 32],
        ..first
    };
    assert!(matches!(
        fixture
            .local
            .reserve_federated_storage_write(fixture.authority(30)?, conflicting),
        Err(FederationStorageQuotaError::Conflict)
    ));
    let too_large = request(43, 44, fixture.authority(21)?, shard(45))?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_storage_write(fixture.authority(21)?, too_large),
        Err(FederationStorageQuotaError::CapacityExceeded)
    ));
    assert!(
        fixture
            .local
            .federated_storage_write(too_large.operation_id)?
            .is_none()
    );

    let first_completion = completion(first, 20, 46, 47, 18);
    let (disposition, committed) = fixture
        .local
        .commit_federated_storage_write(first_completion)?;
    assert_eq!(disposition, FederationStorageQuotaDisposition::Applied);
    assert_eq!(committed.state, FederationStorageWriteState::Committed);
    assert_eq!(committed.affected_bytes, Some(20));
    assert_eq!(committed.charged_bytes, Some(20));
    assert_usage(&fixture, 50, 20, 0)?;
    assert_eq!(
        fixture
            .local
            .commit_federated_storage_write(first_completion)?
            .0,
        FederationStorageQuotaDisposition::Replayed
    );

    let deduplicated = request(48, 49, fixture.authority(30)?, first.shard)?;
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(30)?, deduplicated)?;
    let duplicate_completion = completion(deduplicated, 20, 46, 50, 19);
    let (_, duplicate) = fixture
        .local
        .commit_federated_storage_write(duplicate_completion)?;
    assert_eq!(duplicate.charged_bytes, Some(0));
    assert_usage(&fixture, 50, 20, 0)?;

    let local_path = fixture.local_path.clone();
    let node_id = fixture.repository_ids.provider_node;
    drop(fixture.local);
    fixture.local = LocalDatabase::open(&local_path, node_id, UnixMicros::new(20))?;
    assert_eq!(
        fixture
            .local
            .federated_storage_write(first.operation_id)?
            .ok_or("committed reservation missing after reopen")?,
        committed
    );
    assert_usage(&fixture, 50, 20, 0)
}

#[test]
fn expired_capacity_requires_explicit_absence_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let request = request(60, 61, fixture.authority(20)?, shard(62))?;
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(20)?, request)?;
    let absence = FederationStorageWriteAbsence {
        operation_id: request.operation_id,
        permit_digest: request.permit_digest,
        absence_evidence_digest: [63; 32],
        completed_at: request.expires_at,
    };
    assert!(matches!(
        fixture
            .local
            .release_absent_federated_storage_write(FederationStorageWriteAbsence {
                completed_at: UnixMicros::new(request.expires_at.get() - 1),
                ..absence
            }),
        Err(FederationStorageQuotaError::Conflict)
    ));
    assert_usage(&fixture, 50, 0, 20)?;
    let (disposition, released) = fixture
        .local
        .release_absent_federated_storage_write(absence)?;
    assert_eq!(disposition, FederationStorageQuotaDisposition::Applied);
    assert_eq!(released.state, FederationStorageWriteState::Released);
    assert_usage(&fixture, 50, 0, 0)?;
    assert_eq!(
        fixture
            .local
            .release_absent_federated_storage_write(absence)?
            .0,
        FederationStorageQuotaDisposition::Replayed
    );
    assert!(matches!(
        fixture
            .local
            .release_absent_federated_storage_write(FederationStorageWriteAbsence {
                absence_evidence_digest: [64; 32],
                ..absence
            }),
        Err(FederationStorageQuotaError::Conflict)
    ));
    Ok(())
}

#[test]
fn quota_transitions_roll_back_atomically_and_corruption_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let reserved_request = request(70, 71, fixture.authority(30)?, shard(72))?;
    prove_reservation_rollback(&mut fixture, reserved_request)?;
    prove_completion_rollback(&mut fixture, reserved_request)?;
    prove_release_rollback(&mut fixture)?;
    prove_corrupt_evidence_fails_closed(&fixture, reserved_request)
}

fn prove_reservation_rollback(
    fixture: &mut QuotaFixture,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    fixture.local.connection().execute_batch(
        "CREATE TEMP TRIGGER inject_reservation_failure
         BEFORE INSERT ON local_federation_storage_reservations
         BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
    )?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_storage_write(fixture.authority(30)?, request),
        Err(FederationStorageQuotaError::Database(_))
    ));
    assert!(
        fixture
            .local
            .federated_storage_usage(fixture.allocation.allocation_id())?
            .is_none()
    );
    fixture
        .local
        .connection()
        .execute_batch("DROP TRIGGER inject_reservation_failure;")?;
    Ok(())
}

fn prove_completion_rollback(
    fixture: &mut QuotaFixture,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(30)?, request)?;
    fixture.local.connection().execute_batch(
        "CREATE TEMP TRIGGER inject_completion_failure
         BEFORE UPDATE OF state ON local_federation_storage_reservations
         WHEN NEW.state = 2
         BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END;",
    )?;
    let completion = completion(request, 20, 73, 74, 18);
    assert!(matches!(
        fixture.local.commit_federated_storage_write(completion),
        Err(FederationStorageQuotaError::Database(_))
    ));
    assert_usage(fixture, 50, 0, 30)?;
    assert_eq!(
        fixture
            .local
            .federated_storage_write(request.operation_id)?
            .ok_or("reservation disappeared after rollback")?
            .state,
        FederationStorageWriteState::Reserved
    );
    let shard_count: i64 = fixture.local.connection().query_row(
        "SELECT COUNT(*) FROM local_federation_storage_shards",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(shard_count, 0);
    fixture
        .local
        .connection()
        .execute_batch("DROP TRIGGER inject_completion_failure;")?;
    fixture.local.commit_federated_storage_write(completion)?;
    Ok(())
}

fn prove_release_rollback(fixture: &mut QuotaFixture) -> Result<(), Box<dyn std::error::Error>> {
    let releasable = request(75, 76, fixture.authority(20)?, shard(77))?;
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(20)?, releasable)?;
    let absence = FederationStorageWriteAbsence {
        operation_id: releasable.operation_id,
        permit_digest: releasable.permit_digest,
        absence_evidence_digest: [78; 32],
        completed_at: releasable.expires_at,
    };
    fixture.local.connection().execute_batch(
        "CREATE TEMP TRIGGER inject_release_failure
         BEFORE UPDATE OF state ON local_federation_storage_reservations
         WHEN NEW.state = 3
         BEGIN SELECT RAISE(ABORT, 'injected release failure'); END;",
    )?;
    assert!(matches!(
        fixture
            .local
            .release_absent_federated_storage_write(absence),
        Err(FederationStorageQuotaError::Database(_))
    ));
    assert_usage(fixture, 50, 20, 20)?;
    assert_eq!(
        fixture
            .local
            .federated_storage_write(releasable.operation_id)?
            .ok_or("reservation disappeared after release rollback")?
            .state,
        FederationStorageWriteState::Reserved
    );
    fixture
        .local
        .connection()
        .execute_batch("DROP TRIGGER inject_release_failure;")?;
    fixture
        .local
        .release_absent_federated_storage_write(absence)?;
    assert_usage(fixture, 50, 20, 0)?;
    Ok(())
}

fn prove_corrupt_evidence_fails_closed(
    fixture: &QuotaFixture,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    fixture.local.connection().execute(
        "UPDATE local_federation_storage_reservations
         SET result_digest = zeroblob(32) WHERE operation_id = ?1",
        [request.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        fixture.local.federated_storage_write(request.operation_id),
        Err(FederationStorageQuotaError::CorruptState)
    ));
    Ok(())
}

#[test]
fn malformed_or_wrong_node_reservations_fail_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let authority = fixture.authority(10)?;
    let baseline = request(80, 81, authority, shard(82))?;
    for invalid in [
        FederationStorageWriteReservationRequest {
            action: FederationStorageAction::Get,
            ..baseline
        },
        FederationStorageWriteReservationRequest {
            permit_digest: [0; 32],
            ..baseline
        },
        FederationStorageWriteReservationRequest {
            expires_at: UnixMicros::new(
                baseline.issued_at.get()
                    + i64::try_from(crate::MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS)?
                    + 1,
            ),
            ..baseline
        },
    ] {
        assert!(matches!(
            fixture
                .local
                .reserve_federated_storage_write(authority, invalid),
            Err(FederationStorageQuotaError::Invalid)
        ));
    }
    let wrong_path = fixture.directory.path().join("wrong-node.sqlite3");
    let wrong_node = meshspan_domain::NodeId::from_bytes([83; 16])?;
    let mut wrong_database = LocalDatabase::open(&wrong_path, wrong_node, UnixMicros::new(15))?;
    assert!(matches!(
        wrong_database.reserve_federated_storage_write(authority, baseline),
        Err(FederationStorageQuotaError::Invalid)
    ));
    assert!(
        fixture
            .local
            .federated_storage_usage(fixture.allocation.allocation_id())?
            .is_none()
    );
    Ok(())
}

struct QuotaFixture {
    directory: tempfile::TempDir,
    local_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    repository_ids: super::FixtureIds,
    allocation: meshspan_domain::FederationStorageAllocation,
    local: LocalDatabase,
}

impl QuotaFixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let source = Fixture::open()?;
        let Fixture {
            _directory: directory,
            file_path: _,
            mut repository,
            ids,
        } = source;
        prepare_storage_authority(&mut repository, ids)?;
        let allocation = allocation(ids, 30, 31, 1, 50, 10, 90)?;
        apply_allocation(&mut repository, 5, 32, ids, allocation)?;
        let local_path = directory.path().join("local.sqlite3");
        let local = LocalDatabase::open(&local_path, ids.provider_node, UnixMicros::new(15))?;
        Ok(Self {
            directory,
            local_path,
            repository,
            repository_ids: ids,
            allocation,
            local,
        })
    }

    fn authority(
        &self,
        requested_bytes: u64,
    ) -> Result<FederationStorageAllocationAuthority, Box<dyn std::error::Error>> {
        self.repository
            .active_federation_storage_allocation_authority(authority_request(
                self.repository_ids,
                self.allocation,
                requested_bytes,
                15,
            ))?
            .ok_or_else(|| "active storage allocation authority missing".into())
    }
}

fn request(
    operation_seed: u8,
    digest_seed: u8,
    authority: FederationStorageAllocationAuthority,
    shard: ShardIdentity,
) -> Result<FederationStorageWriteReservationRequest, meshspan_domain::IdentifierError> {
    Ok(FederationStorageWriteReservationRequest {
        operation_id: OperationId::from_bytes([operation_seed; 16])?,
        request_digest: [digest_seed; 32],
        capability_nonce: [operation_seed.saturating_add(1); 32],
        shard,
        action: FederationStorageAction::Put,
        permit_digest: [operation_seed.saturating_add(2); 32],
        expires_at: UnixMicros::new(20),
        issued_at: authority.observed_at(),
    })
}

const fn shard(seed: u8) -> ShardIdentity {
    ShardIdentity {
        manifest_digest: [seed; 32],
        stripe_index: 1,
        shard_index: 2,
        generation: 1,
    }
}

const fn completion(
    request: FederationStorageWriteReservationRequest,
    affected_bytes: u64,
    content_seed: u8,
    result_seed: u8,
    completed_at: i64,
) -> FederationStorageWriteCompletion {
    FederationStorageWriteCompletion {
        operation_id: request.operation_id,
        permit_digest: request.permit_digest,
        affected_bytes,
        content_digest: [content_seed; 32],
        result_digest: [result_seed; 32],
        completed_at: UnixMicros::new(completed_at),
    }
}

fn assert_usage(
    fixture: &QuotaFixture,
    maximum_bytes: u64,
    committed_bytes: u64,
    reserved_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture
            .local
            .federated_storage_usage(fixture.allocation.allocation_id())?,
        Some(FederationStorageUsage {
            allocation_id: fixture.allocation.allocation_id(),
            maximum_bytes,
            committed_bytes,
            reserved_bytes,
        })
    );
    Ok(())
}
