// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::MeshId;
use meshspan_secret_envelope::{
    MAXIMUM_SECRET_RECIPIENTS, SecretContext, WrappingPrivateKey, encrypt_secret,
};

use super::{SequentialRandom, ZeroRandom};
use crate::{RecoveredSecret, create_recovery_bundle};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_secret_recovery_preserves_ciphertext_and_only_wraps_selected_recipients() -> TestResult
{
    let (bundle, code, _) =
        create_recovery_bundle(MeshId::from_bytes([5; 16])?, &mut SequentialRandom::new(11))?;
    let authority = bundle.open(&code)?;
    let old = WrappingPrivateKey::from_bytes([12; 32])?;
    let first = WrappingPrivateKey::from_bytes([13; 32])?;
    let second = WrappingPrivateKey::from_bytes([14; 32])?;
    let (secret, envelopes) = encrypt_secret(
        SecretContext::new(1, [6; 16], 4)?,
        b"historical key material",
        &[old.public_key(), authority.public_wrapping_key()],
        &mut SequentialRandom::new(21),
    )?;
    let recovered = authority.recover_secret(
        &secret,
        &envelopes,
        &[second.public_key(), first.public_key()],
        &mut SequentialRandom::new(31),
    )?;
    assert_eq!(recovered.secret, secret);
    assert_eq!(recovered.recipients.len(), 3);
    for key in [&first, &second, authority.wrapping_key()] {
        assert_eq!(open(&recovered, key)?.expose(), b"historical key material");
    }
    assert!(
        recovered
            .recipients
            .iter()
            .all(|envelope| envelope.open(&old).is_err())
    );
    Ok(())
}

#[test]
fn secret_recovery_rejects_missing_duplicate_and_substituted_evidence() -> TestResult {
    let (bundle, code, _) =
        create_recovery_bundle(MeshId::from_bytes([5; 16])?, &mut SequentialRandom::new(41))?;
    let authority = bundle.open(&code)?;
    let target = WrappingPrivateKey::from_bytes([17; 32])?;
    let context = SecretContext::new(1, [6; 16], 1)?;
    let (secret, envelopes) = encrypt_secret(
        context,
        b"exact old secret",
        &[authority.public_wrapping_key()],
        &mut SequentialRandom::new(51),
    )?;
    let (substituted, _) = encrypt_secret(
        context,
        b"another ciphertext with the same context",
        &[authority.public_wrapping_key()],
        &mut SequentialRandom::new(61),
    )?;
    for supplied in [vec![], vec![envelopes[0].clone(), envelopes[0].clone()]] {
        assert!(
            authority
                .recover_secret(
                    &secret,
                    &supplied,
                    &[target.public_key()],
                    &mut SequentialRandom::new(71)
                )
                .is_err()
        );
    }
    assert!(
        authority
            .recover_secret(
                &substituted,
                &envelopes,
                &[target.public_key()],
                &mut SequentialRandom::new(71)
            )
            .is_err()
    );
    for recipients in [
        vec![],
        vec![target.public_key(); 2],
        vec![authority.public_wrapping_key()],
        vec![target.public_key(); MAXIMUM_SECRET_RECIPIENTS],
    ] {
        assert!(
            authority
                .recover_secret(
                    &secret,
                    &envelopes,
                    &recipients,
                    &mut SequentialRandom::new(71)
                )
                .is_err()
        );
    }
    assert!(
        authority
            .recover_secret(&secret, &envelopes, &[target.public_key()], &mut ZeroRandom)
            .is_err()
    );
    Ok(())
}

#[test]
fn fresh_recovery_keys_are_encrypted_and_the_online_key_matches_its_certificate() -> TestResult {
    let mesh = MeshId::from_bytes([5; 16])?;
    let (bundle, code, _) = create_recovery_bundle(mesh, &mut SequentialRandom::new(81))?;
    let authority = bundle.open(&code)?;
    let target = WrappingPrivateKey::from_bytes([18; 32])?;
    let context = SecretContext::new(2, mesh.as_bytes(), 2)?;
    let mut random = SequentialRandom::new(91);
    let permit = authority.fresh_operational_key(context, &[target.public_key()], &mut random)?;
    let key = open(&permit, &target)?;
    assert_eq!(key.expose().len(), 32);
    assert_ne!(key.expose(), &[0; 32]);
    assert_eq!(
        open(&permit, authority.wrapping_key())?.expose(),
        key.expose()
    );
    let (certificate, online) = authority.fresh_online_authority(
        SecretContext::new(3, mesh.as_bytes(), 2)?,
        &[target.public_key()],
        &mut random,
    )?;
    meshspan_certificates::OnlineCertificateAuthority::from_pkcs8_and_certificate(
        open(&online, &target)?.expose(),
        &certificate,
    )?;
    assert_ne!(certificate, authority.root_certificate_der());
    let wrong = SecretContext::new(2, [6; 16], 2)?;
    assert!(
        authority
            .fresh_operational_key(wrong, &[target.public_key()], &mut random)
            .is_err()
    );
    assert!(
        authority
            .fresh_online_authority(wrong, &[target.public_key()], &mut random)
            .is_err()
    );
    assert!(
        authority
            .fresh_operational_key(context, &[target.public_key()], &mut ZeroRandom)
            .is_err()
    );
    assert!(
        authority
            .fresh_online_authority(context, &[target.public_key()], &mut ZeroRandom)
            .is_err()
    );
    Ok(())
}

fn open(
    material: &RecoveredSecret,
    recipient: &WrappingPrivateKey,
) -> Result<meshspan_secret_envelope::SecretPlaintext, Box<dyn std::error::Error>> {
    let envelope = material
        .recipients
        .iter()
        .find(|envelope| envelope.recipient_public_key() == Ok(recipient.public_key()))
        .ok_or("recipient missing")?;
    Ok(material.secret.decrypt(&envelope.open(recipient)?)?)
}
