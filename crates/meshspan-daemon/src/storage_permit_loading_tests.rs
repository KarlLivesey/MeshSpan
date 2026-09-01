// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ShardIdentity, ShardReadPermit, StoragePermitMacKey, read_permit_mac};
use meshspan_domain::{
    EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use meshspan_metadata::{STORAGE_PERMIT_KEY_SECRET_KIND, SecretGenerationRecord};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};

use crate::{
    LocalWrappingKey, SecretGenerationAuthority, SecretGenerationAuthorityError,
    StoragePermitAuthority, StoragePermitLoadingError, StoragePermitLoadingService,
};

#[test]
fn latest_local_generation_becomes_a_storage_permit_capability()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let mesh_id = MeshId::from_bytes([1; 16])?;
    let records = vec![
        generation_record(mesh_id, 1, &[7; 32], &[local.public_key()], 10)?,
        generation_record(mesh_id, 2, &[8; 32], &[local.public_key()], 20)?,
    ];
    let service = StoragePermitLoadingService::new(FakeAuthority::records(records), local);

    let loaded = service.load_latest(mesh_id)?;
    let permit = read_permit(mesh_id)?;
    assert_eq!(
        read_permit_mac(&loaded, permit),
        read_permit_mac(&StoragePermitMacKey::from_bytes([8; 32])?, permit)
    );
    Ok(())
}

#[test]
fn exact_generation_recipient_and_key_validation_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let mesh_id = MeshId::from_bytes([2; 16])?;
    let other = WrappingPrivateKey::from_bytes([3; 32])?.public_key();

    assert_error(
        FakeAuthority::missing(),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::NotFound,
    );
    assert_error(
        FakeAuthority::records(vec![generation_record(mesh_id, 1, &[4; 32], &[other], 30)?]),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::NotRecipient,
    );
    assert_error(
        FakeAuthority::records(vec![generation_record(
            mesh_id,
            1,
            &[5; 31],
            &[local.public_key()],
            40,
        )?]),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::Failed,
    );
    assert_error(
        FakeAuthority::records(vec![generation_record(
            mesh_id,
            1,
            &[0; 32],
            &[local.public_key()],
            50,
        )?]),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::Failed,
    );
    assert_error(
        FakeAuthority::missing(),
        &local,
        mesh_id,
        0,
        StoragePermitLoadingError::InvalidInput,
    );
    Ok(())
}

#[test]
fn duplicate_recipient_and_unavailable_authority_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let mesh_id = MeshId::from_bytes([6; 16])?;
    let mut duplicate = generation_record(mesh_id, 1, &[7; 32], &[local.public_key()], 60)?;
    duplicate.recipients.push(duplicate.recipients[0].clone());
    assert_error(
        FakeAuthority::records(vec![duplicate]),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::Failed,
    );
    assert_error(
        FakeAuthority::unavailable(),
        &local,
        mesh_id,
        1,
        StoragePermitLoadingError::Unavailable,
    );
    Ok(())
}

fn assert_error(
    authority: FakeAuthority,
    local: &LocalWrappingKey,
    mesh_id: MeshId,
    generation: u64,
    expected: StoragePermitLoadingError,
) {
    assert_eq!(
        StoragePermitLoadingService::new(authority, local)
            .load(mesh_id, generation)
            .err(),
        Some(expected)
    );
}

fn read_permit(mesh_id: MeshId) -> Result<ShardReadPermit, Box<dyn std::error::Error>> {
    Ok(ShardReadPermit {
        operation_id: OperationId::from_bytes([11; 16])?,
        mesh_id,
        target_id: TargetId::from_bytes([12; 16])?,
        target_generation: 1,
        shard: ShardIdentity {
            manifest_digest: [13; 32],
            stripe_index: 14,
            shard_index: 15,
            generation: 16,
        },
        authorization_revision: Revision::new(17),
        expires_at: UnixMicros::new(18),
        permit_digest: [0; 32],
    })
}

fn generation_record(
    mesh_id: MeshId,
    generation: u64,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random_seed: u8,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(
            STORAGE_PERMIT_KEY_SECRET_KIND,
            mesh_id.as_bytes(),
            generation,
        )?,
        plaintext,
        recipients,
        &mut FixedRandom(random_seed),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(generation),
    })
}

#[derive(Clone)]
enum FakeAuthority {
    Records(Vec<SecretGenerationRecord>),
    Unavailable,
}

impl FakeAuthority {
    fn records(records: Vec<SecretGenerationRecord>) -> Self {
        Self::Records(records)
    }

    fn missing() -> Self {
        Self::Records(Vec::new())
    }

    const fn unavailable() -> Self {
        Self::Unavailable
    }
}

impl SecretGenerationAuthority for FakeAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        match self {
            Self::Records(records) => Ok(records
                .iter()
                .find(|record| record.secret.context() == context)
                .cloned()),
            Self::Unavailable => Err(SecretGenerationAuthorityError::Unavailable),
        }
    }
}

impl StoragePermitAuthority for FakeAuthority {
    fn latest_generation(
        &self,
        _mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        match self {
            Self::Records(records) => Ok(records
                .iter()
                .map(|record| record.secret.context().generation())
                .max()),
            Self::Unavailable => Err(SecretGenerationAuthorityError::Unavailable),
        }
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
