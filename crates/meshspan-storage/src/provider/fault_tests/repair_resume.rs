// SPDX-License-Identifier: GPL-2.0-only

//! Repair-only resumption preserves physical identity and capacity through expired admissions.

use super::*;
use meshspan_contracts::{ShardPutIntent, ShardPutResolution};

#[test]
fn expired_repair_resumes_original_admission_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage = directory.path().join("storage");
    let state = directory.path().join("state");
    fs::create_dir(&storage)?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage, registration, &mut FixedRandom)?;
    let fingerprint = folder.marker().fingerprint();
    let mut store = FolderShardStore::open(
        folder,
        &state,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(1),
        &mut FixedRandom,
    )?;
    let (intent, bytes) = repair_intent(registration)?;
    let reservation = store.reserve(ReserveStorageRequest {
        context: intent.context,
        target_id: intent.target_id,
        target_generation: intent.target_generation,
        class: intent.reservation_class,
        bytes: intent.maximum_bytes,
        observed_at: UnixMicros::new(10),
    })?;
    let request = PutShardRequest {
        context: intent.context,
        reservation,
        shard: intent.shard,
        expected_length: intent.expected_length,
        expected_digest: intent.expected_digest,
        bytes,
    };
    store.pack.inject_fault(PackFault::FullBeforeWrite);
    assert!(matches!(
        store.put_exact(&request, UnixMicros::new(11)),
        Err(FolderShardStoreError::ResourceExhausted)
    ));
    drop(store);
    let folder = RegisteredFolder::reopen(&storage, registration, fingerprint)?;
    let mut store = FolderShardStore::reopen(
        folder,
        &state,
        policy(),
        verifier(registration.mesh_id)?,
        UnixMicros::new(2_000),
        &mut FixedRandom,
    )?;
    let authority = resolution_authority(registration, &request)?;
    assert_eq!(
        store.resolve_put(request.identity(), authority, UnixMicros::new(2_001))?,
        ShardPutResolution::Prepared
    );
    // The repair still has live authority, but the original byte admission has expired.
    reject_changed_resume(&mut store, &request, authority)?;
    assert!(matches!(
        store.put_exact(&request, UnixMicros::new(2_002)),
        Err(FolderShardStoreError::InvalidInput)
    ));
    assert_eq!(
        store.prepare_repair_put(intent, authority, UnixMicros::new(2_002))?,
        meshspan_contracts::RepairPutAdmission::Prepared(request.identity())
    );
    let receipt = store.finish_repair_put(&request, authority, UnixMicros::new(2_003))?;
    assert_eq!(receipt.operation_id, intent.context.operation_id);
    assert_eq!(receipt.target_id, intent.target_id);
    assert_eq!(receipt.length, 24);
    assert_eq!(receipt.digest, intent.expected_digest);
    assert_eq!(store.journal.capacity()?.committed_bytes, 24);
    assert_eq!(store.journal.capacity()?.reserved_bytes, 0);
    assert_eq!(
        store.prepare_repair_put(intent, authority, UnixMicros::new(2_004))?,
        meshspan_contracts::RepairPutAdmission::Verified(receipt)
    );
    assert_eq!(
        store.finish_repair_put(&request, authority, UnixMicros::new(2_005))?,
        receipt
    );
    assert_eq!(store.journal.capacity()?.committed_bytes, 24);
    Ok(())
}

fn repair_intent(
    registration: FolderRegistration,
) -> Result<(ShardPutIntent, BoundedBytes), Box<dyn std::error::Error>> {
    let bytes = BoundedBytes::copy_from(b"one exact repair attempt", 1_024)?;
    Ok((
        ShardPutIntent {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([81; 16])?,
                deadline: UnixMicros::new(1_000),
                expected_revision: Some(Revision::new(5)),
            },
            target_id: registration.target_id,
            target_generation: registration.generation,
            reservation_class: ReservationClass::Repair,
            maximum_bytes: 24,
            shard: ShardIdentity {
                manifest_digest: [7; 32],
                stripe_index: 8,
                shard_index: 4,
                generation: 9,
            },
            expected_length: 24,
            expected_digest: blake3::hash(bytes.as_slice()).into(),
        },
        bytes,
    ))
}

fn reject_changed_resume(
    store: &mut FolderShardStore,
    request: &PutShardRequest,
    authority: meshspan_contracts::ShardWritePermit,
) -> Result<(), Box<dyn std::error::Error>> {
    let intent = request.identity().intent();
    let mut forged = authority;
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        store.prepare_repair_put(intent, forged, UnixMicros::new(2_001)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.finish_repair_put(request, forged, UnixMicros::new(2_001)),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.prepare_repair_put(intent, authority, authority.expires_at),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.finish_repair_put(request, authority, authority.expires_at),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.prepare_repair_put(
            ShardPutIntent {
                expected_digest: [99; 32],
                ..intent
            },
            authority,
            UnixMicros::new(2_001)
        ),
        Err(FolderShardStoreError::Journal(
            crate::TargetJournalError::OperationConflict
        ))
    ));
    let mut substituted = request.clone();
    substituted.bytes = BoundedBytes::copy_from(&[99; 24], 1_024)?;
    assert!(matches!(
        store.finish_repair_put(&substituted, authority, UnixMicros::new(2_001)),
        Err(FolderShardStoreError::InvalidInput)
    ));
    let mut foreground = authority;
    foreground.reservation_class = ReservationClass::ForegroundWrite;
    foreground.permit_digest = meshspan_contracts::write_permit_mac(
        &StoragePermitMacKey::from_bytes([42; 32])?,
        foreground,
    );
    assert!(matches!(
        store.prepare_repair_put(
            ShardPutIntent {
                reservation_class: ReservationClass::ForegroundWrite,
                ..intent
            },
            foreground,
            UnixMicros::new(2_001)
        ),
        Err(FolderShardStoreError::Unauthorized)
    ));
    assert_eq!(store.journal.capacity()?.committed_bytes, 0);
    assert_eq!(store.journal.capacity()?.reserved_bytes, 24);
    Ok(())
}
