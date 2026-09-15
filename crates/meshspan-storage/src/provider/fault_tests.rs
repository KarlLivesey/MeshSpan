// SPDX-License-Identifier: GPL-2.0-only

//! Ambiguous packed-write failure proofs through the composed provider path.

use std::fs;

use meshspan_contracts::{
    BoundedBytes, ContractVersion, PutShardRequest, RequestContext, ReservationClass,
    ReserveStorageRequest, ShardIdentity, StoragePermitMacKey,
};
use meshspan_domain::{
    EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use tempfile::tempdir;

use super::{FolderShardStore, FolderShardStoreError, StoragePermitVerifier};
use crate::pack::PackFault;
use crate::{CapacityPolicy, FolderRegistration, RegisteredFolder, UsageLimit};

struct FixedRandom;

#[test]
fn expired_put_recovers_exact_outcome_after_lost_response_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("storage");
    let state_path = directory.path().join("state");
    std::fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut FixedRandom)?;
    let fingerprint = folder.marker().fingerprint();
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut FixedRandom,
    )?;
    let request = put_request(&mut store, registration, 61, 4, b"one exact repair attempt")?;
    let authority = resolution_authority(registration, &request)?;
    assert_eq!(
        store.resolve_put(request.identity(), authority, UnixMicros::new(11))?,
        meshspan_contracts::ShardPutResolution::Unknown,
    );
    store.pack.inject_fault(PackFault::FullBeforeWrite);
    assert!(matches!(
        store.put_exact(&request, UnixMicros::new(12)),
        Err(FolderShardStoreError::ResourceExhausted)
    ));
    assert_eq!(
        store.resolve_put(request.identity(), authority, UnixMicros::new(13))?,
        meshspan_contracts::ShardPutResolution::Prepared,
    );
    store.pack.inject_fault(PackFault::LostResultAfterCommit);
    assert!(matches!(
        store.put_exact(&request, UnixMicros::new(20)),
        Err(FolderShardStoreError::Unavailable)
    ));
    drop(store);
    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut store = FolderShardStore::reopen(
        folder,
        &state_path,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(2_000),
        &mut FixedRandom,
    )?;
    let original = request.identity();
    reject_untrusted_resolution(&mut store, original, authority)?;
    let meshspan_contracts::ShardPutResolution::Verified(recovered) =
        store.resolve_put(original, authority, UnixMicros::new(2_001))?
    else {
        return Err("durable original operation was not resolved".into());
    };
    assert_eq!(recovered.operation_id, request.context.operation_id);
    assert_eq!(recovered.shard, request.shard);
    assert_eq!(recovered.length, 24);
    assert_eq!(recovered.digest, request.expected_digest);
    assert_eq!(store.journal.capacity()?.committed_bytes, 24);
    assert_eq!(store.journal.capacity()?.reserved_bytes, 0);
    assert_eq!(
        store.resolve_put(original, authority, UnixMicros::new(2_002))?,
        meshspan_contracts::ShardPutResolution::Verified(recovered)
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 24);
    let mut changed = original;
    changed.context.deadline = UnixMicros::new(999);
    assert!(matches!(
        store.resolve_put(changed, authority, UnixMicros::new(2_003)),
        Err(FolderShardStoreError::Journal(
            crate::TargetJournalError::OperationConflict
        ))
    ));
    let database = rusqlite::Connection::open(store.folder.pack_database_path(1)?)?;
    database.execute(
        "UPDATE shards SET stored_bytes = ?1 WHERE shard_identity = ?2",
        rusqlite::params![
            [0_u8; 24].as_slice(),
            crate::shard::encode_shard(request.shard).as_slice(),
        ],
    )?;
    assert!(matches!(
        store.resolve_put(original, authority, UnixMicros::new(2_004)),
        Err(FolderShardStoreError::Corrupt)
    ));
    Ok(())
}

fn reject_untrusted_resolution(
    store: &mut FolderShardStore,
    original: meshspan_contracts::ShardPutIdentity,
    authority: meshspan_contracts::ShardWritePermit,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forged = authority;
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        store.resolve_put(original, forged, UnixMicros::new(2_001)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.resolve_put(original, authority, UnixMicros::new(3_000)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    let mut stale = authority;
    stale.authorization_revision = Revision::ZERO;
    stale.permit_digest =
        meshspan_contracts::write_permit_mac(&StoragePermitMacKey::from_bytes([42; 32])?, stale);
    assert!(matches!(
        store.resolve_put(original, stale, UnixMicros::new(2_001)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert_eq!(store.journal.capacity()?.committed_bytes, 0);
    assert_eq!(store.journal.capacity()?.reserved_bytes, 24);
    Ok(())
}

fn resolution_authority(
    registration: FolderRegistration,
    request: &PutShardRequest,
) -> Result<meshspan_contracts::ShardWritePermit, Box<dyn std::error::Error>> {
    let mut permit = meshspan_contracts::ShardWritePermit {
        operation_id: request.context.operation_id,
        mesh_id: registration.mesh_id,
        target_id: registration.target_id,
        target_generation: registration.generation,
        shard: request.shard,
        reservation_class: request.reservation.class,
        maximum_bytes: request.expected_length,
        authorization_revision: Revision::new(10),
        expires_at: UnixMicros::new(3_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest =
        meshspan_contracts::write_permit_mac(&StoragePermitMacKey::from_bytes([42; 32])?, permit);
    Ok(permit)
}

#[test]
fn required_journal_reopen_preserves_receipts_and_never_recreates_missing_history()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage = directory.path().join("storage");
    let state = directory.path().join("state");
    fs::create_dir(&storage)?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage, registration, &mut FixedRandom)?;
    let marker = folder.marker();
    let mut store = FolderShardStore::open(
        folder,
        &state,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut FixedRandom,
    )?;
    let request = put_request(&mut store, registration, 9, 1, b"restored committed bytes")?;
    let receipt = store.put_exact(&request, UnixMicros::new(20))?;
    // A second connection observes the committed WAL state while the original writer is open.
    let journal = crate::TargetJournal::reopen(
        &state,
        marker,
        policy(),
        UnixMicros::new(21),
        &mut FixedRandom,
    )?;
    assert_eq!(journal.capacity()?.committed_bytes, 24);
    drop(journal);
    drop(store);
    let folder = RegisteredFolder::reopen(&storage, registration, marker.fingerprint())?;
    let mut store = FolderShardStore::reopen(
        folder,
        &state,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(22),
        &mut FixedRandom,
    )?;
    assert_eq!(store.put_exact(&request, UnixMicros::new(23))?, receipt);
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    assert_eq!(
        store.pack.get_exact(request.shard)?.as_slice(),
        b"restored committed bytes"
    );
    drop(store);
    let journal_path = state
        .join("storage-targets")
        .join(format!("{}.sqlite3", registration.target_id));
    let saved = state.join("saved-journal.sqlite3");
    fs::rename(&journal_path, &saved)?;
    let folder = RegisteredFolder::reopen(&storage, registration, marker.fingerprint())?;
    assert!(
        FolderShardStore::reopen(
            folder,
            &state,
            policy(),
            verifier(registration.mesh_id)?,
            UnixMicros::new(24),
            &mut FixedRandom
        )
        .is_err()
    );
    assert!(!journal_path.exists());
    fs::rename(saved, journal_path)?;
    Ok(())
}

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(17);
        Ok(())
    }
}

#[test]
fn full_short_and_lost_result_failpoints_recover_exact_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    let state_path = directory.path().join("state");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let policy = policy();
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let fingerprint = folder.marker().fingerprint();
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy,
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut random,
    )?;

    let full = put_request(&mut store, registration, 4, 1, b"full failure")?;
    store.pack.inject_fault(PackFault::FullBeforeWrite);
    assert!(matches!(
        store.put_exact(&full, UnixMicros::new(20)),
        Err(FolderShardStoreError::ResourceExhausted)
    ));
    assert!(store.inventory(None, 10)?.entries.is_empty());
    store.put_exact(&full, UnixMicros::new(21))?;

    let short = put_request(&mut store, registration, 5, 2, b"short write rollback")?;
    store
        .pack
        .inject_fault(PackFault::ShortWriteAfterShardInsert);
    assert!(matches!(
        store.put_exact(&short, UnixMicros::new(22)),
        Err(FolderShardStoreError::Unavailable)
    ));
    assert!(store.pack.get_exact(short.shard).is_err());
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    store.put_exact(&short, UnixMicros::new(23))?;

    let lost = put_request(&mut store, registration, 6, 3, b"durable lost result")?;
    store.pack.inject_fault(PackFault::LostResultAfterCommit);
    assert!(matches!(
        store.put_exact(&lost, UnixMicros::new(24)),
        Err(FolderShardStoreError::Unavailable)
    ));
    assert_eq!(
        store.pack.get_exact(lost.shard)?.as_slice(),
        lost.bytes.as_slice()
    );
    assert_eq!(store.inventory(None, 10)?.entries.len(), 2);
    drop(store);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy,
        verifier(registration.mesh_id)?,
        UnixMicros::new(30),
        &mut random,
    )?;
    let recovery = store.recover_pending(None, 10, UnixMicros::new(31))?;
    assert_eq!(recovery.committed.len(), 1);
    assert_eq!(recovery.committed.as_slice()[0].shard, lost.shard);
    assert_eq!(recovery.awaiting_bytes, 0);
    assert_eq!(store.inventory(None, 10)?.entries.len(), 3);
    assert!(
        store
            .recover_pending(None, 10, UnixMicros::new(32))?
            .committed
            .is_empty()
    );
    Ok(())
}

#[test]
fn rollover_routes_old_and_incomplete_shards_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    let state_path = directory.path().join("state");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let fingerprint = folder.marker().fingerprint();
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut random,
    )?;
    store.journal.set_pack_limits(crate::journal::PackLimits {
        payload_bytes: 30,
        records: 2,
    });
    let first = put_request(&mut store, registration, 41, 1, b"older durable bytes")?;
    store.pack.inject_fault(PackFault::LostResultAfterCommit);
    assert!(matches!(
        store.put_exact(&first, UnixMicros::new(20)),
        Err(FolderShardStoreError::Unavailable)
    ));
    let second = put_request(&mut store, registration, 42, 2, b"newer durable bytes")?;
    store.put_exact(&second, UnixMicros::new(21))?;
    assert_eq!(store.journal.pack_sequence(first.shard)?, Some(1));
    assert_eq!(store.journal.pack_sequence(second.shard)?, Some(2));
    assert!(store.folder.pack_database_path(2)?.is_file());
    drop(store);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(30),
        &mut random,
    )?;
    let recovered = store.recover_pending(None, 10, UnixMicros::new(31))?;
    assert_eq!(recovered.committed.len(), 1);
    assert_eq!(recovered.committed.as_slice()[0].shard, first.shard);
    assert_eq!(
        store.put_exact(&first, UnixMicros::new(32))?,
        recovered.committed.as_slice()[0]
    );
    let page = store.scrub(None, 10, UnixMicros::new(33))?;
    assert_eq!(page.observations.len(), 2);
    assert!(
        page.observations
            .as_slice()
            .iter()
            .all(|item| item.outcome == meshspan_contracts::ScrubOutcome::Healthy)
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 38);
    verify_routed_read_and_removal(&mut store, registration, &first)?;
    Ok(())
}

fn verify_routed_read_and_removal(
    store: &mut FolderShardStore,
    registration: FolderRegistration,
    request: &PutShardRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = StoragePermitMacKey::from_bytes([42; 32])?;
    let mut permit = meshspan_contracts::ShardReadPermit {
        operation_id: request.context.operation_id,
        mesh_id: registration.mesh_id,
        target_id: registration.target_id,
        target_generation: registration.generation,
        shard: request.shard,
        authorization_revision: Revision::new(5),
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest = meshspan_contracts::read_permit_mac(&key, permit);
    assert_eq!(
        store
            .get_exact(request.context, permit, UnixMicros::new(40))?
            .as_slice(),
        request.bytes.as_slice()
    );
    let mut removal = meshspan_contracts::RemovalPermit {
        operation_id: OperationId::from_bytes([50; 16])?,
        mesh_id: registration.mesh_id,
        target_id: registration.target_id,
        target_generation: registration.generation,
        shard: request.shard,
        authority_epoch: 7,
        catalogue_revision: Revision::new(5),
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    removal.permit_digest = meshspan_contracts::removal_permit_mac(&key, removal);
    let receipt = store.tombstone(removal, UnixMicros::new(41))?;
    store.unlink_tombstoned(receipt, UnixMicros::new(42))?;
    assert_eq!(store.journal.capacity()?.committed_bytes, 19);
    assert!(matches!(
        store.get_exact(request.context, permit, UnixMicros::new(43)),
        Err(FolderShardStoreError::NotFound)
    ));
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    Ok(())
}

fn put_request(
    store: &mut FolderShardStore,
    registration: FolderRegistration,
    operation: u8,
    shard_index: u16,
    payload: &[u8],
) -> Result<PutShardRequest, Box<dyn std::error::Error>> {
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([operation; 16])?,
        deadline: UnixMicros::new(1_000),
        expected_revision: Some(Revision::new(5)),
    };
    let bytes = BoundedBytes::copy_from(payload, 1_024)?;
    let reservation = store.reserve(ReserveStorageRequest {
        context,
        target_id: registration.target_id,
        target_generation: registration.generation,
        class: ReservationClass::ForegroundWrite,
        bytes: u64::try_from(bytes.len())?,
        observed_at: UnixMicros::new(10),
    })?;
    Ok(PutShardRequest {
        context,
        reservation,
        shard: ShardIdentity {
            manifest_digest: [7; 32],
            stripe_index: 8,
            shard_index,
            generation: 9,
        },
        expected_length: u64::try_from(bytes.len())?,
        expected_digest: blake3::hash(bytes.as_slice()).into(),
        bytes,
    })
}

fn registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes([1; 16])?,
        target_id: TargetId::from_bytes([2; 16])?,
        generation: 3,
        usage_limit: UsageLimit::DEFAULT,
    })
}

const fn policy() -> CapacityPolicy {
    CapacityPolicy {
        usage_limit: UsageLimit::DEFAULT,
        repair_reserve_bytes: 100,
        revision: Revision::new(1),
    }
}

fn verifier(mesh_id: MeshId) -> Result<StoragePermitVerifier, Box<dyn std::error::Error>> {
    Ok(StoragePermitVerifier::new(
        mesh_id,
        7,
        Revision::new(1),
        StoragePermitMacKey::from_bytes([42; 32])?,
    )?)
}
