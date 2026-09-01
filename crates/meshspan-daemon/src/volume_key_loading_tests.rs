// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ContentManifestId, EntropyError, RandomSource, Revision, VolumeId};
use meshspan_filesystem::{
    ContentEncryptionKey, ContentKeyEnvelopeCipher, VolumeContentKeys, VolumeKeyEncryptionKey,
};
use meshspan_metadata::{SecretGenerationRecord, VOLUME_CONTENT_KEY_SECRET_KIND};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};

use crate::{
    LocalWrappingKey, VolumeKeyAuthority, VolumeKeyAuthorityError, VolumeKeyLoadingError,
    VolumeKeyLoadingService,
};

#[test]
fn exact_local_envelope_becomes_the_non_exportable_filesystem_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let volume_id = VolumeId::from_bytes([1; 16])?;
    let record = generation_record(volume_id, &[7; 32], &[local.public_key()], 10)?;
    let service = VolumeKeyLoadingService::new(FakeAuthority::record(record), local);

    let loaded = service.load(volume_id, 1)?;
    assert_eq!(loaded.generation(), 1);
    let manifest_id = ContentManifestId::from_bytes([2; 16])?;
    let actual_content_key = ContentEncryptionKey::from_bytes([8; 32])?;
    let expected_content_key = ContentEncryptionKey::from_bytes([8; 32])?;
    let actual = ContentKeyEnvelopeCipher::new(loaded).wrap(
        manifest_id,
        &actual_content_key,
        &mut FixedRandom(20),
    )?;
    let expected = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [7; 32])?)
        .wrap(manifest_id, &expected_content_key, &mut FixedRandom(20))?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn protected_source_wraps_with_latest_and_reopens_the_recorded_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let volume_id = VolumeId::from_bytes([21; 16])?;
    let manifest_id = ContentManifestId::from_bytes([22; 16])?;
    let record = generation_record(volume_id, &[23; 32], &[local.public_key()], 24)?;
    let source = VolumeKeyLoadingService::new(FakeAuthority::record(record), local);

    let wrapped = source.wrap_content_key(
        volume_id,
        manifest_id,
        &ContentEncryptionKey::from_bytes([25; 32])?,
        &mut FixedRandom(26),
    )?;
    let expected = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [23; 32])?)
        .wrap(
            manifest_id,
            &ContentEncryptionKey::from_bytes([25; 32])?,
            &mut FixedRandom(26),
        )?;
    assert_eq!(wrapped, expected);

    let reopened = source.unwrap_content_key(volume_id, manifest_id, wrapped)?;
    let comparison_key = VolumeKeyEncryptionKey::from_bytes(2, [27; 32])?;
    let actual = ContentKeyEnvelopeCipher::new(comparison_key).wrap(
        manifest_id,
        &reopened,
        &mut FixedRandom(28),
    )?;
    let expected = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(2, [27; 32])?)
        .wrap(
            manifest_id,
            &ContentEncryptionKey::from_bytes([25; 32])?,
            &mut FixedRandom(28),
        )?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn absent_wrong_or_duplicate_local_recipient_fails_before_key_construction()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let local_public = local.public_key();
    let volume_id = VolumeId::from_bytes([3; 16])?;
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::missing(), &local)
            .load(volume_id, 1)
            .err(),
        Some(VolumeKeyLoadingError::NotFound)
    );
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::missing(), &local)
            .load_latest(volume_id)
            .err(),
        Some(VolumeKeyLoadingError::NotFound)
    );

    let other = WrappingPrivateKey::from_bytes([4; 32])?.public_key();
    let wrong_recipient = generation_record(volume_id, &[9; 32], &[other], 30)?;
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::record(wrong_recipient), &local)
            .load(volume_id, 1)
            .err(),
        Some(VolumeKeyLoadingError::NotRecipient)
    );

    let mut duplicate = generation_record(volume_id, &[9; 32], &[local_public], 40)?;
    duplicate.recipients.push(duplicate.recipients[0].clone());
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::record(duplicate), &local)
            .load(volume_id, 1)
            .err(),
        Some(VolumeKeyLoadingError::Failed)
    );
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::missing(), &local)
            .load(volume_id, 0)
            .err(),
        Some(VolumeKeyLoadingError::InvalidInput)
    );
    Ok(())
}

#[test]
fn substituted_or_invalid_plaintext_and_authority_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let volume_id = VolumeId::from_bytes([5; 16])?;
    let other_volume = VolumeId::from_bytes([6; 16])?;
    let wrong_context = generation_record(other_volume, &[10; 32], &[local.public_key()], 50)?;
    assert_failed(&local, volume_id, wrong_context);

    let mut zero_revision = generation_record(volume_id, &[10; 32], &[local.public_key()], 55)?;
    zero_revision.revision = Revision::ZERO;
    assert_failed(&local, volume_id, zero_revision);

    let short_key = generation_record(volume_id, &[11; 31], &[local.public_key()], 60)?;
    assert_failed(&local, volume_id, short_key);
    let zero_key = generation_record(volume_id, &[0; 32], &[local.public_key()], 70)?;
    assert_failed(&local, volume_id, zero_key);

    let secret_source = generation_record(volume_id, &[12; 32], &[local.public_key()], 80)?;
    let envelope_source = generation_record(volume_id, &[12; 32], &[local.public_key()], 90)?;
    let substituted = SecretGenerationRecord {
        secret: secret_source.secret,
        recipients: envelope_source.recipients,
        revision: Revision::new(1),
    };
    assert_failed(&local, volume_id, substituted);

    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::unavailable(), &local)
            .load(volume_id, 1)
            .err(),
        Some(VolumeKeyLoadingError::Unavailable)
    );
    Ok(())
}

fn assert_failed(local: &LocalWrappingKey, volume_id: VolumeId, record: SecretGenerationRecord) {
    assert_eq!(
        VolumeKeyLoadingService::new(FakeAuthority::record(record), local)
            .load(volume_id, 1)
            .err(),
        Some(VolumeKeyLoadingError::Failed)
    );
}

fn generation_record(
    volume_id: VolumeId,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random_seed: u8,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(VOLUME_CONTENT_KEY_SECRET_KIND, volume_id.as_bytes(), 1)?,
        plaintext,
        recipients,
        &mut FixedRandom(random_seed),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

#[derive(Clone)]
enum FakeAuthority {
    Record(SecretGenerationRecord),
    Missing,
    Unavailable,
}

impl FakeAuthority {
    fn record(record: SecretGenerationRecord) -> Self {
        Self::Record(record)
    }

    const fn missing() -> Self {
        Self::Missing
    }

    const fn unavailable() -> Self {
        Self::Unavailable
    }
}

impl VolumeKeyAuthority for FakeAuthority {
    fn latest_generation(
        &self,
        _volume_id: VolumeId,
    ) -> Result<Option<u64>, VolumeKeyAuthorityError> {
        match self {
            Self::Record(record) => Ok(Some(record.secret.context().generation())),
            Self::Missing => Ok(None),
            Self::Unavailable => Err(VolumeKeyAuthorityError::Unavailable),
        }
    }

    fn secret_generation(
        &self,
        _context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, VolumeKeyAuthorityError> {
        match self {
            Self::Record(record) => Ok(Some(record.clone())),
            Self::Missing => Ok(None),
            Self::Unavailable => Err(VolumeKeyAuthorityError::Unavailable),
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
