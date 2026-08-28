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
