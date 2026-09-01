// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{EntropyError, RandomSource};

use crate::{
    EncryptedSecret, MAXIMUM_SECRET_BYTES, RecipientKeyEnvelope, SecretContext,
    SecretEnvelopeError, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};

#[test]
fn each_exact_recipient_opens_the_same_secret() -> Result<(), Box<dyn std::error::Error>> {
    let context = context(1)?;
    let first = WrappingPrivateKey::from_bytes([11; 32])?;
    let second = WrappingPrivateKey::from_bytes([23; 32])?;
    let recipients = [first.public_key(), second.public_key()];
    let plaintext = b"one protected volume key generation";
    let (secret, envelopes) = encrypt_secret(
        context,
        plaintext,
        &recipients,
        &mut SequentialRandom::new(31),
    )?;

    for private in [&first, &second] {
        let fingerprint = private.public_key().fingerprint();
        let envelope = envelopes
            .iter()
            .find(|candidate| candidate.recipient_fingerprint() == Ok(fingerprint))
            .ok_or("recipient envelope missing")?;
        let key = envelope.open(private)?;
        assert_eq!(secret.decrypt(&key)?.expose(), plaintext);
    }
    assert_eq!(envelopes.len(), 2);
    Ok(())
}

#[test]
fn wrong_recipient_and_generation_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let intended = WrappingPrivateKey::from_bytes([17; 32])?;
    let wrong = WrappingPrivateKey::from_bytes([19; 32])?;
    let (secret, envelopes) = encrypt_secret(
        context(1)?,
        b"protected secret",
        &[intended.public_key()],
        &mut SequentialRandom::new(41),
    )?;
    assert!(matches!(
        envelopes[0].open(&wrong),
        Err(SecretEnvelopeError::Corrupt)
    ));

    let mut changed = envelopes[0].parts();
    changed.context = context(2)?;
    assert_eq!(
        RecipientKeyEnvelope::from_parts(changed),
        Err(SecretEnvelopeError::Corrupt)
    );

    let key = envelopes[0].open(&intended)?;
    let mut changed_secret = secret.parts();
    changed_secret.context = context(2)?;
    assert_eq!(
        EncryptedSecret::from_parts(changed_secret),
        Err(SecretEnvelopeError::Corrupt)
    );
    assert_eq!(secret.decrypt(&key)?.expose(), b"protected secret");
    Ok(())
}

#[test]
fn every_persisted_envelope_field_is_digest_bound() -> Result<(), Box<dyn std::error::Error>> {
    let recipient = WrappingPrivateKey::from_bytes([5; 32])?;
    let (_, envelopes) = encrypt_secret(
        context(1)?,
        b"secret",
        &[recipient.public_key()],
        &mut SequentialRandom::new(51),
    )?;
    let original = envelopes[0].parts();

    let changed_context = context(2)?;
    assert_corrupt_envelope(changed_envelope(&original, |parts| {
        parts.format_version ^= 1;
    }));
    assert_corrupt_envelope(changed_envelope(&original, |parts| {
        parts.context = changed_context;
    }));
    assert_corrupt_envelope(changed_envelope(&original, |parts| {
        parts.recipient_public_key[0] ^= 1;
    }));
    assert_corrupt_envelope(changed_envelope(&original, |parts| {
        parts.ephemeral_public_key[0] ^= 1;
    }));
    assert_corrupt_envelope(changed_envelope(&original, |parts| parts.salt[0] ^= 1));
    assert_corrupt_envelope(changed_envelope(&original, |parts| parts.nonce[0] ^= 1));
    assert_corrupt_envelope(changed_envelope(&original, |parts| {
        parts.ciphertext[0] ^= 1;
    }));
    assert_corrupt_envelope(changed_envelope(&original, |parts| parts.digest[0] ^= 1));
    Ok(())
}

#[test]
fn every_persisted_secret_field_is_digest_bound() -> Result<(), Box<dyn std::error::Error>> {
    let recipient = WrappingPrivateKey::from_bytes([7; 32])?;
    let (secret, _) = encrypt_secret(
        context(1)?,
        b"secret",
        &[recipient.public_key()],
        &mut SequentialRandom::new(61),
    )?;
    let original = secret.parts();

    let mut changed = original.clone();
    changed.format_version ^= 1;
    assert_corrupt_secret(changed);
    let mut changed = original.clone();
    changed.context = context(2)?;
    assert_corrupt_secret(changed);
    let mut changed = original.clone();
    changed.nonce[0] ^= 1;
    assert_corrupt_secret(changed);
    let mut changed = original.clone();
    changed.ciphertext[0] ^= 1;
    assert_corrupt_secret(changed);
    let mut changed = original;
    changed.digest[0] ^= 1;
    assert_corrupt_secret(changed);
    Ok(())
}

#[test]
fn low_order_recipient_and_bad_entropy_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let low_order = WrappingPublicKey::from_bytes([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])?;
    assert_eq!(
        encrypt_secret(
            context(1)?,
            b"secret",
            &[low_order],
            &mut SequentialRandom::new(3)
        ),
        Err(SecretEnvelopeError::InvalidRecipient)
    );
    let recipient = WrappingPrivateKey::from_bytes([13; 32])?;
    assert_eq!(
        encrypt_secret(
            context(1)?,
            b"secret",
            &[recipient.public_key()],
            &mut ZeroRandom
        ),
        Err(SecretEnvelopeError::Entropy)
    );
    assert_eq!(
        encrypt_secret(
            context(1)?,
            b"secret",
            &[recipient.public_key()],
            &mut FailingRandom
        ),
        Err(SecretEnvelopeError::Entropy)
    );
    Ok(())
}

#[test]
fn plaintext_and_recipient_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let recipient = WrappingPrivateKey::from_bytes([29; 32])?.public_key();
    let mut random = SequentialRandom::new(71);
    assert_eq!(
        encrypt_secret(context(1)?, &[], &[recipient], &mut random),
        Err(SecretEnvelopeError::InvalidInput)
    );
    assert_eq!(
        encrypt_secret(
            context(1)?,
            &vec![1; MAXIMUM_SECRET_BYTES + 1],
            &[recipient],
            &mut random,
        ),
        Err(SecretEnvelopeError::InvalidInput)
    );
    assert_eq!(
        encrypt_secret(context(1)?, b"secret", &[], &mut random),
        Err(SecretEnvelopeError::InvalidInput)
    );
    assert_eq!(
        encrypt_secret(context(1)?, b"secret", &[recipient, recipient], &mut random),
        Err(SecretEnvelopeError::InvalidInput)
    );
    Ok(())
}

fn context(generation: u64) -> Result<SecretContext, SecretEnvelopeError> {
    SecretContext::new(1, [9; 16], generation)
}

fn assert_corrupt_envelope(parts: crate::RecipientEnvelopeParts) {
    assert_eq!(
        RecipientKeyEnvelope::from_parts(parts),
        Err(SecretEnvelopeError::Corrupt)
    );
}

fn assert_corrupt_secret(parts: crate::EncryptedSecretParts) {
    assert_eq!(
        EncryptedSecret::from_parts(parts),
        Err(SecretEnvelopeError::Corrupt)
    );
}

fn changed_envelope(
    source: &crate::RecipientEnvelopeParts,
    change: impl FnOnce(&mut crate::RecipientEnvelopeParts),
) -> crate::RecipientEnvelopeParts {
    let mut changed = source.clone();
    change(&mut changed);
    changed
}

struct SequentialRandom {
    next: u8,
}

impl SequentialRandom {
    const fn new(next: u8) -> Self {
        Self { next }
    }
}

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1).max(1);
        }
        Ok(())
    }
}

struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(0);
        Ok(())
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}
