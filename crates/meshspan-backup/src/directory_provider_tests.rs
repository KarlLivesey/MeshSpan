// SPDX-License-Identifier: GPL-2.0-only

use std::io::Cursor;

use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupProvider, BackupReadRequest,
    BackupStoreRequest, BackupVerifyRequest, ContractError, ContractVersion, RequestContext,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::DirectoryBackupProvider;

#[test]
fn exact_stream_survives_restart_replays_and_retires_once() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let destination_id = BackupDestinationId::from_bytes([1; 16])?;
    let bytes = b"encrypted metadata backup";
    let object = identity(destination_id, BackupId::from_bytes([2; 16])?, bytes);
    let store = BackupStoreRequest {
        context: context(3, 10)?,
        object,
    };
    let receipt = {
        let mut provider = DirectoryBackupProvider::open(
            directory.path(),
            destination_id,
            1,
            1_024,
            UnixMicros::new(1),
        )?;
        let receipt = provider.store_exact(store, &mut Cursor::new(bytes), UnixMicros::new(2))?;
        assert_eq!(
            provider.verify_exact(
                &BackupVerifyRequest {
                    context: context(4, 10)?,
                    object,
                    object_reference: receipt.object_reference.clone(),
                },
                UnixMicros::new(3),
            )?,
            meshspan_contracts::BackupObjectReceipt {
                operation_id: OperationId::from_bytes([4; 16])?,
                object,
                object_reference: receipt.object_reference.clone(),
            }
        );
        let mut returned = Vec::new();
        let read = provider.read_exact(
            &BackupReadRequest {
                context: context(5, 10)?,
                object,
                object_reference: receipt.object_reference.clone(),
            },
            &mut returned,
            UnixMicros::new(3),
        )?;
        assert_eq!(returned, bytes);
        assert_eq!(read.byte_length, bytes.len() as u64);
        assert_eq!(read.digest, object.digest);
        receipt
    };

    let mut reopened = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        1_024,
        UnixMicros::new(4),
    )?;
    assert_eq!(
        reopened.store_exact(store, &mut Cursor::new(bytes), UnixMicros::new(5))?,
        receipt
    );
    let mut same_object_new_operation = store;
    same_object_new_operation.context = context(8, 10)?;
    assert_eq!(
        reopened
            .store_exact(
                same_object_new_operation,
                &mut Cursor::new(bytes),
                UnixMicros::new(5),
            )?
            .object,
        object
    );
    let mut changed = store;
    changed.object.digest = [9; 32];
    assert_eq!(
        reopened.store_exact(changed, &mut Cursor::new(bytes), UnixMicros::new(5)),
        Err(ContractError::Conflict)
    );
    let deletion = BackupDeleteRequest {
        context: context(6, 11)?,
        object,
        object_reference: receipt.object_reference.clone(),
        retirement_revision: Revision::new(11),
    };
    let deleted = reopened.delete_exact(&deletion, UnixMicros::new(6))?;
    assert_eq!(deleted.object, object);
    assert_eq!(
        reopened.delete_exact(&deletion, UnixMicros::new(7))?,
        deleted
    );
    assert_eq!(
        reopened.verify_exact(
            &BackupVerifyRequest {
                context: context(7, 12)?,
                object,
                object_reference: receipt.object_reference,
            },
            UnixMicros::new(8),
        ),
        Err(ContractError::NotFound)
    );
    Ok(())
}

#[test]
fn deletion_retry_renews_deadline_after_restart_without_changing_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination = BackupDestinationId::from_bytes([1; 16])?;
    let object = identity(destination, BackupId::from_bytes([2; 16])?, b"bytes");
    let mut provider =
        DirectoryBackupProvider::open(directory.path(), destination, 1, 1024, UnixMicros::new(1))?;
    let stored = provider.store_exact(
        BackupStoreRequest {
            context: context(3, 10)?,
            object,
        },
        &mut Cursor::new(b"bytes"),
        UnixMicros::new(2),
    )?;
    let mut deletion = BackupDeleteRequest {
        context: context(4, 11)?,
        object,
        object_reference: stored.object_reference,
        retirement_revision: Revision::new(11),
    };
    let receipt = provider.delete_exact(&deletion, UnixMicros::new(3))?;
    drop(provider);
    let mut reopened = DirectoryBackupProvider::open(
        directory.path(),
        destination,
        1,
        1024,
        UnixMicros::new(101),
    )?;
    assert_eq!(
        reopened.delete_exact(&deletion, UnixMicros::new(101)),
        Err(ContractError::DeadlineExceeded)
    );
    deletion.context.deadline = UnixMicros::new(200);
    assert_eq!(
        reopened.delete_exact(&deletion, UnixMicros::new(101))?,
        receipt
    );
    deletion.object.digest = [99; 32];
    assert_eq!(
        reopened.delete_exact(&deletion, UnixMicros::new(102)),
        Err(ContractError::Conflict)
    );
    Ok(())
}

#[test]
fn rejected_stream_and_capacity_claim_publish_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination_id = BackupDestinationId::from_bytes([10; 16])?;
    let bytes = b"four";
    let object = identity(destination_id, BackupId::from_bytes([11; 16])?, bytes);
    let mut provider =
        DirectoryBackupProvider::open(directory.path(), destination_id, 1, 4, UnixMicros::new(1))?;
    let request = BackupStoreRequest {
        context: context(12, 1)?,
        object,
    };
    assert_eq!(
        provider.store_exact(request, &mut Cursor::new(b"thr"), UnixMicros::new(2)),
        Err(ContractError::Corrupt)
    );
    let pending_entries = std::fs::read_dir(
        directory
            .path()
            .join(".meshspan-backups")
            .join(destination_id.to_string().replace('-', ""))
            .join("objects"),
    )?
    .collect::<Result<Vec<_>, _>>()?;
    assert!(pending_entries.is_empty());
    let receipt = provider.store_exact(request, &mut Cursor::new(bytes), UnixMicros::new(2))?;
    let second = BackupStoreRequest {
        context: context(13, 2)?,
        object: identity(destination_id, BackupId::from_bytes([14; 16])?, b"x"),
    };
    assert_eq!(
        provider.store_exact(second, &mut Cursor::new(b"x"), UnixMicros::new(3)),
        Err(ContractError::ResourceExhausted)
    );
    assert!(
        directory
            .path()
            .join("ordinary-sibling.txt")
            .try_exists()
            .is_ok_and(|exists| !exists)
    );
    assert!(!receipt.object_reference.as_str().is_empty());
    Ok(())
}

#[test]
fn changed_provider_bytes_are_reported_as_corrupt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination_id = BackupDestinationId::from_bytes([20; 16])?;
    let bytes = b"authenticated ciphertext";
    let object = identity(destination_id, BackupId::from_bytes([21; 16])?, bytes);
    let mut provider = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        1_024,
        UnixMicros::new(1),
    )?;
    let receipt = provider.store_exact(
        BackupStoreRequest {
            context: context(22, 1)?,
            object,
        },
        &mut Cursor::new(bytes),
        UnixMicros::new(2),
    )?;
    std::fs::write(
        directory
            .path()
            .join(".meshspan-backups")
            .join(destination_id.to_string().replace('-', ""))
            .join("objects")
            .join(receipt.object_reference.as_str()),
        b"substituted ciphertext",
    )?;
    let forged_reference =
        meshspan_contracts::BackupObjectReference::new("../catalogue.sqlite3".to_owned())?;
    assert_eq!(
        provider.verify_exact(
            &BackupVerifyRequest {
                context: context(24, 2)?,
                object,
                object_reference: forged_reference,
            },
            UnixMicros::new(3),
        ),
        Err(ContractError::Conflict)
    );
    assert_eq!(
        provider.verify_exact(
            &BackupVerifyRequest {
                context: context(23, 2)?,
                object,
                object_reference: receipt.object_reference,
            },
            UnixMicros::new(3),
        ),
        Err(ContractError::Corrupt)
    );
    Ok(())
}

#[test]
fn changed_capacity_policy_preserves_existing_objects_and_limits_new_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination_id = BackupDestinationId::from_bytes([25; 16])?;
    let bytes = b"four";
    let object = identity(destination_id, BackupId::from_bytes([26; 16])?, bytes);
    let receipt = {
        let mut provider = DirectoryBackupProvider::open(
            directory.path(),
            destination_id,
            1,
            4,
            UnixMicros::new(1),
        )?;
        provider.store_exact(
            BackupStoreRequest {
                context: context(27, 1)?,
                object,
            },
            &mut Cursor::new(bytes),
            UnixMicros::new(2),
        )?
    };
    let mut reduced =
        DirectoryBackupProvider::open(directory.path(), destination_id, 1, 2, UnixMicros::new(3))?;
    let mut returned = Vec::new();
    reduced.read_exact(
        &BackupReadRequest {
            context: context(28, 2)?,
            object,
            object_reference: receipt.object_reference,
        },
        &mut returned,
        UnixMicros::new(4),
    )?;
    assert_eq!(returned, bytes);
    assert_eq!(
        reduced.store_exact(
            BackupStoreRequest {
                context: context(29, 3)?,
                object: identity(destination_id, BackupId::from_bytes([30; 16])?, b"x"),
            },
            &mut Cursor::new(b"x"),
            UnixMicros::new(5)
        ),
        Err(ContractError::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn restart_and_changed_operation_retry_discard_only_unpublished_staging()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination = BackupDestinationId::from_bytes([50; 16])?;
    let open = || {
        DirectoryBackupProvider::open(directory.path(), destination, 1, 1_024, UnixMicros::new(1))
    };
    let provider = open()?;
    let objects = directory
        .path()
        .join(".meshspan-backups")
        .join(destination.to_string().replace('-', ""))
        .join("objects");
    let orphan = objects.join("pending-11111111111111111111111111111111");
    let sibling = objects.join("pending-not-an-operation");
    std::fs::write(&orphan, b"partial backup")?;
    std::fs::write(&sibling, b"not selected")?;
    drop(provider);
    let mut provider = open()?;
    assert!(!orphan.try_exists()?);
    assert_eq!(std::fs::read(&sibling)?, b"not selected");
    std::fs::write(&orphan, b"prior failed attempt")?;
    let object = identity(destination, BackupId::from_bytes([51; 16])?, b"final");
    let receipt = provider.store_exact(
        BackupStoreRequest {
            context: context(52, 1)?,
            object,
        },
        &mut Cursor::new(b"final"),
        UnixMicros::new(2),
    )?;
    assert!(!orphan.try_exists()?);
    assert_eq!(
        std::fs::read(objects.join(receipt.object_reference.as_str()))?,
        b"final"
    );
    assert_eq!(std::fs::read(&sibling)?, b"not selected");
    Ok(())
}

#[test]
fn independent_destinations_can_share_one_registered_folder()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first_id = BackupDestinationId::from_bytes([30; 16])?;
    let second_id = BackupDestinationId::from_bytes([31; 16])?;

    let first =
        DirectoryBackupProvider::open(directory.path(), first_id, 1, 1_024, UnixMicros::new(1))?;
    let second =
        DirectoryBackupProvider::open(directory.path(), second_id, 1, 1_024, UnixMicros::new(1))?;

    assert_eq!(first.describe(), second.describe());
    Ok(())
}

#[test]
fn shared_destination_serialises_replay_and_releases_ownership_after_the_last_user()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination_id = BackupDestinationId::from_bytes([40; 16])?;
    let bytes = b"one encrypted object";
    let open = || {
        DirectoryBackupProvider::open(
            directory.path(),
            destination_id,
            1,
            bytes.len() as u64,
            UnixMicros::new(1),
        )
    };
    let shared = crate::SharedBackupProvider::new(open()?);
    // This is the original local-worker failure when the remote service already owns it.
    assert!(matches!(
        open(),
        Err(crate::DirectoryBackupProviderError::AlreadyOwned)
    ));
    let store = BackupStoreRequest {
        context: context(41, 1)?,
        object: identity(destination_id, BackupId::from_bytes([42; 16])?, bytes),
    };
    let mut first = shared.clone();
    let mut second = shared.clone();
    let (first_receipt, second_receipt) = std::thread::scope(|scope| {
        let first_worker = scope
            .spawn(move || first.store_exact(store, &mut Cursor::new(bytes), UnixMicros::new(2)));
        let second_worker = scope
            .spawn(move || second.store_exact(store, &mut Cursor::new(bytes), UnixMicros::new(2)));
        (first_worker.join(), second_worker.join())
    });
    let receipt = first_receipt.map_err(|_| "first backup worker panicked")??;
    assert_eq!(
        second_receipt.map_err(|_| "second backup worker panicked")??,
        receipt
    );
    let mut survivor = shared.clone();
    drop(shared);
    assert!(matches!(
        open(),
        Err(crate::DirectoryBackupProviderError::AlreadyOwned)
    ));
    let mut excess = store;
    excess.context = context(43, 2)?;
    excess.object.backup_id = BackupId::from_bytes([44; 16])?;
    assert_eq!(
        survivor.store_exact(excess, &mut Cursor::new(bytes), UnixMicros::new(3)),
        Err(ContractError::ResourceExhausted)
    );
    drop(survivor);
    let reopened = open()?;
    let mut returned = Vec::new();
    let read = reopened.read_exact(
        &BackupReadRequest {
            context: context(45, 2)?,
            object: store.object,
            object_reference: receipt.object_reference,
        },
        &mut returned,
        UnixMicros::new(4),
    )?;
    assert_eq!(returned, bytes);
    assert_eq!(read.digest, store.object.digest);
    Ok(())
}

fn identity(
    destination_id: BackupDestinationId,
    backup_id: BackupId,
    bytes: &[u8],
) -> BackupObjectIdentity {
    BackupObjectIdentity {
        backup_id,
        destination_id,
        provider_generation: 1,
        byte_length: bytes.len() as u64,
        digest: Sha256::digest(bytes).into(),
    }
}

fn context(
    operation: u8,
    expected_revision: u64,
) -> Result<RequestContext, meshspan_domain::IdentifierError> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([operation; 16])?,
        deadline: UnixMicros::new(100),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}
