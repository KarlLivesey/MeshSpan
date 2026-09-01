// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ContractKind, StorageProvider};
use meshspan_domain::{EntropyError, MeshId, NodeId, RandomSource, Revision, TargetId, UnixMicros};
use meshspan_metadata::{
    STORAGE_PERMIT_KEY_SECRET_KIND, SecretGenerationRecord, StorageTargetProviderContext,
    StorageUsageLimit,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use meshspan_storage::{FolderRegistration, RegisteredFolder, UsageLimit};

use crate::{
    LocalWrappingKey, RegisteredStorageTarget, SecretGenerationAuthority,
    SecretGenerationAuthorityError, StoragePermitAuthority, StorageProviderOpeningError,
    StorageProviderOpeningService,
};

#[test]
fn registered_folder_opens_and_reopens_as_the_exact_live_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let storage_path = directory.path().join("storage");
    let state_path = directory.path().join("state");
    let key_path = directory.path().join("node.key");
    std::fs::create_dir(&storage_path)?;
    std::fs::create_dir(&state_path)?;
    let local = LocalWrappingKey::open_or_create(&key_path)?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut FixedRandom(1))?;
    let fingerprint = folder.marker().fingerprint();
    let authority = FakeAuthority::new(record(registration.mesh_id, local.public_key())?);
    let target = RegisteredStorageTarget::from_validated_parts(folder, context()?);
    let mut opening = StorageProviderOpeningService::new(
        authority.clone(),
        local,
        state_path.clone(),
        7,
        FixedRandom(30),
    )?;

    let provider = opening.open(target, UnixMicros::new(10))?;
    assert_eq!(provider.describe().contract, ContractKind::StorageProvider);
    drop(provider);
    drop(opening);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut changed_policy = context()?;
    changed_policy.usage_limit = StorageUsageLimit::Percent(90);
    changed_policy.policy_revision = Revision::new(6);
    changed_policy.catalogue_revision = Revision::new(6);
    let target = RegisteredStorageTarget::from_validated_parts(folder, changed_policy);
    let mut opening = StorageProviderOpeningService::new(
        authority,
        LocalWrappingKey::open(&key_path)?,
        state_path,
        7,
        FixedRandom(60),
    )?;
    assert_eq!(
        opening
            .open(target, UnixMicros::new(20))?
            .describe()
            .contract,
        ContractKind::StorageProvider
    );
    Ok(())
}

#[test]
fn identity_substitution_and_missing_permit_authority_fail_before_provider_open()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let storage_path = directory.path().join("storage");
    let state_path = directory.path().join("state");
    std::fs::create_dir(&storage_path)?;
    std::fs::create_dir(&state_path)?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let registration = registration()?;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut FixedRandom(70))?;
    let fingerprint = folder.marker().fingerprint();
    let mut wrong = context()?;
    wrong.target_id = TargetId::from_bytes([9; 16])?;
    let target = RegisteredStorageTarget::from_validated_parts(folder, wrong);
    let mut opening = StorageProviderOpeningService::new(
        FakeAuthority::missing(),
        &local,
        state_path,
        1,
        FixedRandom(90),
    )?;
    assert!(matches!(
        opening.open(target, UnixMicros::new(10)),
        Err(StorageProviderOpeningError::InvalidTarget)
    ));
    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let target = RegisteredStorageTarget::from_validated_parts(folder, context()?);
    assert!(matches!(
        opening.open(target, UnixMicros::new(11)),
        Err(StorageProviderOpeningError::Permit(
            crate::StoragePermitLoadingError::NotFound
        ))
    ));
    Ok(())
}

fn registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes([1; 16])?,
        target_id: TargetId::from_bytes([2; 16])?,
        generation: 1,
        usage_limit: UsageLimit::percent(95)?,
    })
}

fn context() -> Result<StorageTargetProviderContext, Box<dyn std::error::Error>> {
    Ok(StorageTargetProviderContext {
        mesh_id: MeshId::from_bytes([1; 16])?,
        node_id: NodeId::from_bytes([3; 16])?,
        target_id: TargetId::from_bytes([2; 16])?,
        generation: 1,
        usage_limit: StorageUsageLimit::Percent(95),
        policy_revision: Revision::new(4),
        catalogue_revision: Revision::new(5),
    })
}

fn record(
    mesh_id: MeshId,
    recipient: WrappingPublicKey,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh_id.as_bytes(), 1)?,
        &[6; 32],
        &[recipient],
        &mut FixedRandom(100),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

#[derive(Clone)]
struct FakeAuthority(Option<SecretGenerationRecord>);

impl FakeAuthority {
    const fn new(record: SecretGenerationRecord) -> Self {
        Self(Some(record))
    }

    const fn missing() -> Self {
        Self(None)
    }
}

impl SecretGenerationAuthority for FakeAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok(self
            .0
            .as_ref()
            .filter(|record| record.secret.context() == context)
            .cloned())
    }
}

impl StoragePermitAuthority for FakeAuthority {
    fn latest_generation(
        &self,
        _mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        Ok(self
            .0
            .as_ref()
            .map(|record| record.secret.context().generation()))
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
