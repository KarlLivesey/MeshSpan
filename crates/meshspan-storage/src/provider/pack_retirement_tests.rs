// SPDX-License-Identifier: GPL-2.0-only

use super::removal_tests::{
    FixedRandom, policy, put_request, registration, signed_removal, verifier,
};
use super::{FolderShardStore, FolderShardStoreError};
use crate::RegisteredFolder;
use meshspan_domain::UnixMicros;
use std::fs;
use tempfile::tempdir;

#[test]
fn completed_reclamation_replays_without_the_payload_pack() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    let state_path = directory.path().join("state");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let mut store = FolderShardStore::open(
        folder,
        &state_path,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut random,
    )?;
    store.journal.set_pack_limits(crate::journal::PackLimits {
        payload_bytes: 1024,
        records: 1,
    });
    let removed = put_request(&mut store, registration, 128, 30)?;
    let original = store.put_exact(&removed, UnixMicros::new(20))?;
    let kept = put_request(&mut store, registration, 128, 31)?;
    store.put_exact(&kept, UnixMicros::new(21))?;
    let permit = signed_removal(registration, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    let reclaimed = store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    store.select_pack(kept.shard, UnixMicros::new(24))?;
    let source = store.folder.pack_database_path(1)?;
    fs::remove_file(source)?;
    assert_eq!(store.put_exact(&removed, UnixMicros::new(25))?, original);
    assert_eq!(store.tombstone(permit, UnixMicros::new(26))?, tombstone);
    assert_eq!(
        store.unlink_tombstoned(tombstone, UnixMicros::new(27))?,
        reclaimed
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 128);
    Ok(())
}

#[test]
fn retired_pack_replays_exact_receipts_across_restart_cuts()
-> Result<(), Box<dyn std::error::Error>> {
    for cut in 0..3 {
        let (directory, mut store, removed, kept) = retirement_store()?;
        let registration = registration()?;
        let fingerprint = store.folder.marker().fingerprint();
        let original = store.put_exact(&removed, UnixMicros::new(21))?;
        let permit = signed_removal(registration, removed.shard)?;
        let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
        let reclaimed = store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
        store.select_pack(kept.shard, UnixMicros::new(24))?;
        let source = store.folder.pack_database_path(1)?;
        assert!(store.journal.prepare_pack_retirement(1)?);
        if cut == 1 {
            fs::remove_file(&source)?;
        } else if cut == 2 {
            store.folder.retire_pack_files(1)?;
        }
        drop(store);
        let folder =
            RegisteredFolder::reopen(&directory.path().join("target"), registration, fingerprint)?;
        let mut store = FolderShardStore::reopen(
            folder,
            &directory.path().join("state"),
            policy(),
            verifier(registration.mesh_id)?,
            UnixMicros::new(30),
            &mut FixedRandom,
        )?;
        assert!(store.compact_next_pack(UnixMicros::new(31))?.is_some());
        assert!(!source.exists());
        assert_eq!(store.journal.pack_sequences(10)?, vec![2]);
        assert!(!store.journal.pack_retirement_pending(1)?);
        assert_eq!(store.put_exact(&removed, UnixMicros::new(32))?, original);
        assert_eq!(store.tombstone(permit, UnixMicros::new(33))?, tombstone);
        assert_eq!(
            store.unlink_tombstoned(tombstone, UnixMicros::new(34))?,
            reclaimed
        );
        let mut forged = tombstone;
        forged.permit_digest = [99; 32];
        assert!(
            store
                .unlink_tombstoned(forged, UnixMicros::new(35))
                .is_err()
        );
        assert_eq!(store.journal.capacity()?.committed_bytes, 128);
        assert_eq!(
            store.pack.get_exact(kept.shard)?.as_slice(),
            kept.bytes.as_slice()
        );
        assert_eq!(store.compact_next_pack(UnixMicros::new(36))?, None);
        assert!(!source.exists());
        store.check_health()?;
    }
    Ok(())
}

#[test]
fn retirement_waits_for_journal_reclamation_and_preserves_active_pack()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut store, removed, kept) = retirement_store()?;
    assert_eq!(store.compact_next_pack(UnixMicros::new(21))?, None);
    assert!(!store.journal.prepare_pack_retirement(1)?);
    let permit = signed_removal(registration()?, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    assert!(!store.journal.prepare_pack_retirement(1)?);
    store
        .pack
        .unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    assert!(!store.journal.prepare_pack_retirement(1)?);
    store.unlink_tombstoned(tombstone, UnixMicros::new(24))?;
    assert!(store.journal.prepare_pack_retirement(1)?);
    assert!(!store.journal.prepare_pack_retirement(2)?);
    // The cursor already examined pack 1 before reclamation; visit pack 2, then wrap.
    assert_eq!(store.compact_next_pack(UnixMicros::new(25))?, None);
    assert!(store.compact_next_pack(UnixMicros::new(26))?.is_some());
    assert!(!store.folder.pack_database_path(1)?.exists());
    assert_eq!(
        store.pack.get_exact(kept.shard)?.as_slice(),
        kept.bytes.as_slice()
    );
    Ok(())
}

#[test]
fn retirement_rechecks_source_identity_before_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut store, removed, kept) = retirement_store()?;
    let permit = signed_removal(registration()?, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    store.select_pack(kept.shard, UnixMicros::new(24))?;
    let source = store.folder.pack_database_path(1)?;
    let connection = rusqlite::Connection::open(&source)?;
    connection.execute("UPDATE pack_state SET pack_sequence = 99", [])?;
    connection.close().map_err(|(_, error)| error)?;
    assert!(matches!(
        store.compact_next_pack(UnixMicros::new(25)),
        Err(FolderShardStoreError::Corrupt)
    ));
    assert!(source.is_file());
    assert!(store.journal.pack_retirement_pending(1)?);
    assert_eq!(store.journal.pack_sequences(10)?, vec![1, 2]);
    assert!(store.observe_pack_space().is_err());
    assert_eq!(store.journal.capacity()?.committed_bytes, 128);
    Ok(())
}

#[test]
fn incomplete_replay_pins_pack_after_payload_reclamation() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, mut store, removed, _kept) = retirement_store()?;
    let registration = registration()?;
    let mut duplicate = put_request(&mut store, registration, 128, 44)?;
    duplicate.shard = removed.shard;
    let request = crate::JournalPutRequest {
        reservation: duplicate.reservation,
        request_digest: super::put_request_digest(&duplicate),
        shard: duplicate.shard,
        expected_length: duplicate.expected_length,
        expected_digest: duplicate.expected_digest,
        now: UnixMicros::new(21),
    };
    store.journal.prepare_put(request)?;
    let permit = signed_removal(registration, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    assert!(!store.journal.prepare_pack_retirement(1)?);
    assert_eq!(store.journal.pending_puts(None, 10)?.puts.len(), 1);
    assert!(store.folder.pack_database_path(1)?.exists());
    Ok(())
}

#[test]
fn retired_routes_reject_new_puts_without_recreating_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut store, removed, _kept) = retirement_store()?;
    let registration = registration()?;
    let permit = signed_removal(registration, removed.shard)?;
    let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
    store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    store.compact_next_pack(UnixMicros::new(24))?;
    let mut duplicate = put_request(&mut store, registration, 128, 44)?;
    duplicate.shard = removed.shard;
    assert!(matches!(
        store.put_exact(&duplicate, UnixMicros::new(25)),
        Err(FolderShardStoreError::Journal(
            crate::TargetJournalError::OperationConflict
        ))
    ));
    assert!(!store.folder.pack_database_path(1)?.exists());
    assert_eq!(store.journal.capacity()?.committed_bytes, 128);
    Ok(())
}

#[test]
fn blocked_retirement_does_not_starve_later_packs() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut store, first, second) = retirement_store()?;
    let registration = registration()?;
    let active = put_request(&mut store, registration, 128, 32)?;
    store.put_exact(&active, UnixMicros::new(21))?;
    for (shard, operation) in [(first.shard, 50), (second.shard, 51)] {
        let mut permit = signed_removal(registration, shard)?;
        permit.operation_id = meshspan_domain::OperationId::from_bytes([operation; 16])?;
        permit.permit_digest = meshspan_contracts::removal_permit_mac(
            &meshspan_contracts::StoragePermitMacKey::from_bytes([42; 32])?,
            permit,
        );
        let tombstone = store.tombstone(permit, UnixMicros::new(22))?;
        store.unlink_tombstoned(tombstone, UnixMicros::new(23))?;
    }
    store.select_pack(active.shard, UnixMicros::new(24))?;
    let source = store.folder.pack_database_path(1)?;
    let connection = rusqlite::Connection::open(&source)?;
    connection.execute("UPDATE pack_state SET pack_sequence = 99", [])?;
    connection.close().map_err(|(_, error)| error)?;
    assert!(matches!(
        store.compact_next_pack(UnixMicros::new(25)),
        Err(FolderShardStoreError::Corrupt)
    ));
    assert!(store.compact_next_pack(UnixMicros::new(26))?.is_some());
    assert!(!store.folder.pack_database_path(2)?.exists());
    assert!(source.exists());
    assert_eq!(store.compact_next_pack(UnixMicros::new(27))?, None);
    assert!(matches!(
        store.compact_next_pack(UnixMicros::new(28)),
        Err(FolderShardStoreError::Corrupt)
    ));
    assert!(source.exists());
    assert!(store.observe_pack_space().is_err());
    assert_eq!(
        store.pack.get_exact(active.shard)?.as_slice(),
        active.bytes.as_slice()
    );
    Ok(())
}

fn retirement_store() -> Result<
    (
        tempfile::TempDir,
        FolderShardStore,
        meshspan_contracts::PutShardRequest,
        meshspan_contracts::PutShardRequest,
    ),
    Box<dyn std::error::Error>,
> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut FixedRandom)?;
    let mut store = FolderShardStore::open(
        folder,
        &directory.path().join("state"),
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut FixedRandom,
    )?;
    store.journal.set_pack_limits(crate::journal::PackLimits {
        payload_bytes: 1024,
        records: 1,
    });
    let removed = put_request(&mut store, registration, 128, 30)?;
    store.put_exact(&removed, UnixMicros::new(20))?;
    let kept = put_request(&mut store, registration, 128, 31)?;
    store.put_exact(&kept, UnixMicros::new(20))?;
    Ok((directory, store, removed, kept))
}
