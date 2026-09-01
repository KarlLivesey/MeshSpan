// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use meshspan_domain::{
    EntropyError, HostId, MeshId, NodeId, PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LocalDatabase, LocalTargetState, LogPosition,
    StorageTargetRegistrationContext,
};
use tempfile::tempdir;

use crate::{
    StorageTargetRegistrationAuthority, StorageTargetRegistrationAuthorityError,
    StorageTargetRegistrationError, StorageTargetRegistrationService,
};

#[derive(Clone, Copy)]
enum ReceiptMode {
    Exact,
    WrongEntity,
}

struct FakeAuthority {
    context: Option<StorageTargetRegistrationContext>,
    commits: Arc<AtomicUsize>,
    mode: ReceiptMode,
}

impl StorageTargetRegistrationAuthority for FakeAuthority {
    fn registration_context(
        &self,
        node_id: NodeId,
        _now: UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, StorageTargetRegistrationAuthorityError>
    {
        Ok(self.context.filter(|context| context.node_id == node_id))
    }

    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, StorageTargetRegistrationAuthorityError> {
        self.commits.fetch_add(1, Ordering::Relaxed);
        let AuthoritativeCommand::RegisterStorageTarget(target) = command else {
            return Err(StorageTargetRegistrationAuthorityError::Failed);
        };
        let kind = match self.mode {
            ReceiptMode::Exact => EntityKind::StorageTarget,
            ReceiptMode::WrongEntity => EntityKind::Volume,
        };
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [91; 32],
            committed_revision: Revision::new(2),
            committed_position: LogPosition { index: 2, term: 1 },
            applied_position: LogPosition { index: 2, term: 1 },
            entity: EntityReference {
                kind,
                id: target.target_id.as_bytes(),
            },
        })
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

#[test]
fn registration_is_restart_safe_and_does_not_recommit_an_active_target()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let local_path = directory.path().join("local.sqlite3");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    fs::write(storage_path.join("sibling.txt"), b"untouched")?;
    let context = context()?;
    let commits = Arc::new(AtomicUsize::new(0));
    let local = LocalDatabase::open(&local_path, context.node_id, UnixMicros::new(1))?;
    let mut service = StorageTargetRegistrationService::new(
        local,
        authority(Some(context), Arc::clone(&commits), ReceiptMode::Exact),
        FixedRandom(10),
    );
    let folder = service.register(&storage_path, UnixMicros::new(10))?;
    let fingerprint = folder.marker().fingerprint();
    assert_eq!(commits.load(Ordering::Relaxed), 1);
    assert_eq!(fs::read(storage_path.join("sibling.txt"))?, b"untouched");
    drop(folder);
    drop(service);

    let local = LocalDatabase::open_existing(&local_path, UnixMicros::new(20))?;
    let mut service = StorageTargetRegistrationService::new(
        local,
        authority(Some(context), Arc::clone(&commits), ReceiptMode::Exact),
        FixedRandom(100),
    );
    let reopened = service.register(&storage_path, UnixMicros::new(20))?;
    assert_eq!(reopened.marker().fingerprint(), fingerprint);
    assert_eq!(commits.load(Ordering::Relaxed), 1);
    drop(reopened);
    drop(service);

    let local = LocalDatabase::open_existing(&local_path, UnixMicros::new(21))?;
    let record = local
        .local_target_by_path(
            fs::canonicalize(&storage_path)?
                .as_os_str()
                .as_encoded_bytes(),
        )?
        .ok_or("active local target was missing")?;
    assert_eq!(record.state, LocalTargetState::Active);
    Ok(())
}

#[test]
fn unavailable_setup_touches_nothing_and_bad_receipt_resumes_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let local_path = directory.path().join("local.sqlite3");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let context = context()?;
    let commits = Arc::new(AtomicUsize::new(0));
    let local = LocalDatabase::open(&local_path, context.node_id, UnixMicros::new(1))?;
    let mut service = StorageTargetRegistrationService::new(
        local,
        authority(None, Arc::clone(&commits), ReceiptMode::Exact),
        FixedRandom(20),
    );
    assert!(matches!(
        service.register(&storage_path, UnixMicros::new(10)),
        Err(StorageTargetRegistrationError::NotConfigured)
    ));
    assert!(!storage_path.join(".meshspan").exists());
    drop(service);

    let local = LocalDatabase::open_existing(&local_path, UnixMicros::new(11))?;
    let mut service = StorageTargetRegistrationService::new(
        local,
        authority(
            Some(context),
            Arc::clone(&commits),
            ReceiptMode::WrongEntity,
        ),
        FixedRandom(30),
    );
    assert!(matches!(
        service.register(&storage_path, UnixMicros::new(11)),
        Err(StorageTargetRegistrationError::Conflict)
    ));
    drop(service);
    assert_eq!(commits.load(Ordering::Relaxed), 1);

    let local = LocalDatabase::open_existing(&local_path, UnixMicros::new(12))?;
    let mut service = StorageTargetRegistrationService::new(
        local,
        authority(Some(context), Arc::clone(&commits), ReceiptMode::Exact),
        FixedRandom(90),
    );
    service.register(&storage_path, UnixMicros::new(12))?;
    assert_eq!(commits.load(Ordering::Relaxed), 2);
    Ok(())
}

fn context() -> Result<StorageTargetRegistrationContext, meshspan_domain::IdentifierError> {
    Ok(StorageTargetRegistrationContext {
        mesh_id: MeshId::from_bytes([1; 16])?,
        node_id: NodeId::from_bytes([2; 16])?,
        host_id: HostId::from_bytes([3; 16])?,
        actor_principal_id: PrincipalId::from_bytes([4; 16])?,
    })
}

fn authority(
    context: Option<StorageTargetRegistrationContext>,
    commits: Arc<AtomicUsize>,
    mode: ReceiptMode,
) -> FakeAuthority {
    FakeAuthority {
        context,
        commits,
        mode,
    }
}
