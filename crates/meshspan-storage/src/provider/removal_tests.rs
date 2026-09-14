// SPDX-License-Identifier: GPL-2.0-only

//! Exact removal-authority and crash-boundary proofs for the composed folder store.

use std::fs;

use meshspan_contracts::{
    BoundedBytes, ContractVersion, PutShardRequest, RemovalPermit, RequestContext,
    ReservationClass, ReserveStorageRequest, ShardIdentity, StoragePermitMacKey, TombstoneReceipt,
    removal_permit_mac,
};
use meshspan_domain::{
    EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use tempfile::tempdir;

use super::{
    FolderShardStore, FolderShardStoreError, StoragePermitVerifier, removal_request_digest,
};
use crate::journal::{JournalTombstoneRequest, PrepareTombstoneResult};
use crate::pack::PackTombstoneRequest;
use crate::{CapacityPolicy, FolderRegistration, RegisteredFolder, UsageLimit};

const REMOVAL_EPOCH: u64 = 7;
const CATALOGUE_REVISION: Revision = Revision::new(11);
const PERMIT_KEY: [u8; 32] = [42; 32];

#[test]
fn tombstone_receipt_replays_after_restart_without_admitting_stale_new_removals()
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
    let removed = put_request(&mut store, registration, 8192, 4)?;
    let retained = put_request(&mut store, registration, 8192, 5)?;
    store.put_exact(&removed, UnixMicros::new(20))?;
    store.put_exact(&retained, UnixMicros::new(21))?;
    let permit = signed_removal(registration, removed.shard)?;
    let receipt = store.tombstone(permit, UnixMicros::new(30))?;
    drop(store);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut newer = verifier(registration.mesh_id)?;
    newer.advance_minimum_catalogue_revision(Revision::new(12))?;
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy(),
        newer,
        UnixMicros::new(40),
        &mut random,
    )?;
    assert_eq!(store.tombstone(permit, UnixMicros::new(41))?, receipt);
    reject_forged_and_stale_authority(&mut store, permit)?;
    let mut stale_new = signed_removal(registration, retained.shard)?;
    stale_new.operation_id = OperationId::from_bytes([99; 16])?;
    stale_new.permit_digest =
        removal_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, stale_new);
    assert!(matches!(
        store.tombstone(stale_new, UnixMicros::new(42)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert_eq!(store.journal.capacity()?.committed_bytes, 16384);
    let inventory = store.inventory(None, 10)?;
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries.as_slice()[0].shard, retained.shard);
    Ok(())
}

pub(super) struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(19);
        Ok(())
    }
}

#[test]
fn tombstone_crash_recovery_and_guarded_unlink_are_exactly_once()
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
    let put = put_request(&mut store, registration, 131_072, 4)?;
    store.put_exact(&put, UnixMicros::new(20))?;
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    assert_eq!(
        store.journal.capacity()?.committed_bytes,
        put.expected_length
    );

    let permit = signed_removal(registration, put.shard)?;
    reject_forged_and_stale_authority(&mut store, permit)?;
    let receipt = leave_pack_tombstone_without_journal_commit(&mut store, permit, put.shard)?;
    drop(store);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy,
        verifier(registration.mesh_id)?,
        UnixMicros::new(40),
        &mut random,
    )?;
    recover_and_unlink_once(&mut store, permit, receipt, put.expected_length)
}

fn reject_forged_and_stale_authority(
    store: &mut FolderShardStore,
    permit: RemovalPermit,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forged = permit;
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        store.tombstone(forged, UnixMicros::new(30)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    let mut stale_epoch = permit;
    stale_epoch.authority_epoch += 1;
    let signing_key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    stale_epoch.permit_digest = removal_permit_mac(&signing_key, stale_epoch);
    assert!(matches!(
        store.tombstone(stale_epoch, UnixMicros::new(30)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn applied_catalogue_revision_permanently_fences_older_removal_permits()
-> Result<(), Box<dyn std::error::Error>> {
    let registration = registration()?;
    let permit = signed_removal(
        registration,
        ShardIdentity {
            manifest_digest: [6; 32],
            stripe_index: 7,
            shard_index: 8,
            generation: 9,
        },
    )?;
    let mut verifier = verifier(registration.mesh_id)?;
    assert!(verifier.authenticates_removal(permit));

    verifier.advance_minimum_catalogue_revision(Revision::new(12))?;
    assert!(!verifier.authenticates_removal(permit));
    assert!(matches!(
        verifier.advance_minimum_catalogue_revision(CATALOGUE_REVISION),
        Err(FolderShardStoreError::Stale)
    ));
    assert!(matches!(
        StoragePermitVerifier::new(
            registration.mesh_id,
            REMOVAL_EPOCH,
            Revision::ZERO,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        ),
        Err(FolderShardStoreError::InvalidInput)
    ));
    Ok(())
}

fn leave_pack_tombstone_without_journal_commit(
    store: &mut FolderShardStore,
    permit: RemovalPermit,
    shard: ShardIdentity,
) -> Result<TombstoneReceipt, Box<dyn std::error::Error>> {
    let request_digest = removal_request_digest(permit);
    let journal_request = JournalTombstoneRequest {
        permit,
        request_digest,
        now: UnixMicros::new(31),
    };
    assert_eq!(
        store.journal.prepare_tombstone(journal_request)?,
        PrepareTombstoneResult::Prepared
    );
    let receipt = store.pack.tombstone_exact(PackTombstoneRequest {
        permit,
        request_digest,
        now: UnixMicros::new(31),
    })?;
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    assert!(store.pack.get_exact(shard).is_err());
    assert!(
        store
            .unlink_tombstoned(receipt, UnixMicros::new(32))
            .is_err()
    );
    Ok(receipt)
}

fn recover_and_unlink_once(
    store: &mut FolderShardStore,
    permit: RemovalPermit,
    receipt: TombstoneReceipt,
    stored_length: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let recovered = store.recover_pending_tombstones(None, 10, UnixMicros::new(41))?;
    assert_eq!(recovered.committed.as_slice(), &[receipt]);
    assert_eq!(recovered.awaiting_pack, 0);
    assert!(recovered.next_cursor.is_none());
    assert!(store.inventory(None, 10)?.entries.is_empty());
    assert_eq!(store.tombstone(permit, UnixMicros::new(42))?, receipt);
    assert_eq!(store.journal.capacity()?.committed_bytes, stored_length);
    assert!(
        store
            .recover_pending_tombstones(None, 10, UnixMicros::new(42))?
            .committed
            .is_empty()
    );

    let mut forged_receipt = receipt;
    forged_receipt.tombstone_digest[0] ^= 1;
    assert!(
        store
            .unlink_tombstoned(forged_receipt, UnixMicros::new(43))
            .is_err()
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, stored_length);
    let reclamation = store.unlink_tombstoned(receipt, UnixMicros::new(44))?;
    assert_eq!(reclamation.tombstone, receipt);
    assert_eq!(reclamation.bytes_unlinked_at, UnixMicros::new(44));
    assert_eq!(reclamation.reclaimed_bytes, stored_length);
    assert_eq!(
        reclamation.reclamation_digest,
        meshspan_contracts::reclamation_receipt_digest(receipt, UnixMicros::new(44), stored_length,)
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 0);
    let space = store.pack.observe_space()?;
    assert!(space.database_bytes > 131_072);
    assert!(space.reusable_bytes >= 122_880);
    assert!(space.reusable_bytes < space.database_bytes);
    assert_eq!(
        store.unlink_tombstoned(receipt, UnixMicros::new(45))?,
        reclamation
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 0);
    Ok(())
}

#[test]
fn automatic_cow_reclamation_survives_both_sides_of_publication()
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
    let removed = put_request(&mut store, registration, 2 * 1024 * 1024, 4)?;
    let kept = put_request(&mut store, registration, 4_096, 5)?;
    store.put_exact(&removed, UnixMicros::new(20))?;
    let kept_receipt = store.put_exact(&kept, UnixMicros::new(21))?;
    let permit = signed_removal(registration, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    let reclaimed = store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    let before = store.pack.observe_space()?;
    assert!(before.reusable_bytes >= 1024 * 1024);

    for (fault, now) in [
        (crate::pack::PackFault::BeforeCompactionPublish, 30),
        (crate::pack::PackFault::AfterCompactionPublish, 40),
    ] {
        store.pack.inject_fault(fault);
        assert!(matches!(
            store.compact_next_pack(UnixMicros::new(now)),
            Err(FolderShardStoreError::Unavailable)
        ));
        assert_eq!(
            store.pack.get_exact(kept.shard)?.as_slice(),
            kept.bytes.as_slice()
        );
        drop(store);
        let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
        store = FolderShardStore::open(
            folder,
            &state_path,
            policy(),
            verifier(registration.mesh_id)?,
            UnixMicros::new(now + 1),
            &mut random,
        )?;
        assert_eq!(
            store.put_exact(&kept, UnixMicros::new(now + 2))?,
            kept_receipt
        );
        assert_eq!(
            store.unlink_tombstoned(tombstone, UnixMicros::new(now + 3))?,
            reclaimed
        );
        store.check_health()?;
    }
    let after = store.pack.observe_space()?;
    assert!(before.database_bytes - after.database_bytes >= 1024 * 1024);
    assert_eq!(after.reusable_bytes, 0);
    assert_eq!(store.compact_next_pack(UnixMicros::new(50))?, None);
    assert_eq!(store.journal.capacity()?.committed_bytes, 4_096);
    assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
    assert_eq!(
        store.pack.get_exact(kept.shard)?.as_slice(),
        kept.bytes.as_slice()
    );
    Ok(())
}

pub(super) fn registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes([1; 16])?,
        target_id: TargetId::from_bytes([2; 16])?,
        generation: 3,
        usage_limit: UsageLimit::DEFAULT,
    })
}

pub(super) const fn policy() -> CapacityPolicy {
    CapacityPolicy {
        usage_limit: UsageLimit::DEFAULT,
        repair_reserve_bytes: 100,
        revision: Revision::new(1),
    }
}

pub(super) fn verifier(
    mesh_id: MeshId,
) -> Result<StoragePermitVerifier, Box<dyn std::error::Error>> {
    Ok(StoragePermitVerifier::new(
        mesh_id,
        REMOVAL_EPOCH,
        CATALOGUE_REVISION,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    )?)
}

pub(super) fn put_request(
    store: &mut FolderShardStore,
    registration: FolderRegistration,
    length: usize,
    operation: u8,
) -> Result<PutShardRequest, Box<dyn std::error::Error>> {
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([operation; 16])?,
        deadline: UnixMicros::new(1_000),
        expected_revision: Some(Revision::new(5)),
    };
    // Span many overflow pages so guarded removal also proves reusable pack-space accounting.
    let bytes = BoundedBytes::from_vec(vec![19; length], length)?;
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
            manifest_digest: [6; 32],
            stripe_index: 7,
            shard_index: u16::from(operation) + 4,
            generation: 9,
        },
        expected_length: u64::try_from(bytes.len())?,
        expected_digest: blake3::hash(bytes.as_slice()).into(),
        bytes,
    })
}

pub(super) fn signed_removal(
    registration: FolderRegistration,
    shard: ShardIdentity,
) -> Result<RemovalPermit, Box<dyn std::error::Error>> {
    let mut permit = RemovalPermit {
        operation_id: OperationId::from_bytes([10; 16])?,
        mesh_id: registration.mesh_id,
        target_id: registration.target_id,
        shard,
        target_generation: registration.generation,
        authority_epoch: REMOVAL_EPOCH,
        catalogue_revision: CATALOGUE_REVISION,
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    permit.permit_digest = removal_permit_mac(&key, permit);
    Ok(permit)
}
