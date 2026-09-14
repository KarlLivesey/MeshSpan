// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{Revision, UnixMicros};
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretContext, SecretPlaintext, WrappingPrivateKey,
};

use super::{Fixture, TestResult};
use crate::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeRepository, CommitSecretGeneration,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, PartitionDatabase, STORAGE_PERMIT_KEY_SECRET_KIND,
};

#[test]
fn recovery_keys_use_successor_heads_and_preserve_authentication_ciphertext() -> TestResult {
    let fixture = Fixture::new()?;
    let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("live.sqlite3"),
        UnixMicros::new(30),
    )?);
    let mesh = fixture.manifest.partition.mesh_id;
    let replacement = WrappingPrivateKey::from_bytes([61; 32])?;
    let original_gateway = crate::test_support::node_wrapping_private_key()?;
    let mut random = crate::test_support::SequentialRandom(101);
    let material = source.prepare_recovery_control_keys(
        &fixture.authority,
        &[replacement.public_key()],
        &[],
        &mut random,
    )?;
    assert_eq!(
        material.online_authority_key.secret.context,
        SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh.as_bytes(), 2)?
    );
    assert_eq!(
        material.storage_permit_key.secret.context,
        SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh.as_bytes(), 2)?
    );
    meshspan_certificates::OnlineCertificateAuthority::from_pkcs8_and_certificate(
        open(&material.online_authority_key, &replacement)?.expose(),
        &material.online_certificate_der,
    )?;
    let new_permit = open(&material.storage_permit_key, &replacement)?;
    assert_eq!(new_permit.expose().len(), 32);
    assert_ne!(new_permit.expose(), &[202; 32]);
    assert_eq!(
        new_permit.expose(),
        open(
            &material.storage_permit_key,
            fixture.authority.wrapping_key()
        )?
        .expose()
    );
    assert!(open(&material.storage_permit_key, &original_gateway).is_err());

    let authentication =
        SecretContext::new(AUTHENTICATION_ROOT_KEY_SECRET_KIND, mesh.as_bytes(), 1)?;
    let before = source
        .secret_generation(authentication)?
        .ok_or("source root missing")?;
    let retained = source.prepare_recovery_secret(
        &fixture.authority,
        authentication,
        &[replacement.public_key()],
        &mut random,
    )?;
    assert_eq!(retained.secret, before.secret.parts());
    assert_eq!(open(&retained, &replacement)?.expose(), &[203; 32]);
    assert!(open(&retained, &original_gateway).is_err());
    assert_eq!(
        source
            .secret_generation(authentication)?
            .ok_or("root disappeared")?,
        before
    );
    assert_eq!(source.latest_storage_permit_generation(mesh)?, Some(1));
    assert_eq!(source.latest_online_authority_generation(mesh)?, Some(1));
    assert_eq!(source.current_revision()?, Revision::new(1));
    Ok(())
}

#[test]
fn recovery_key_planning_rejects_another_authority_and_invalid_recipients() -> TestResult {
    let fixture = Fixture::new()?;
    let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("live.sqlite3"),
        UnixMicros::new(30),
    )?);
    let mesh = fixture.manifest.partition.mesh_id;
    let (bundle, code, _) = meshspan_recovery_bundle::create_recovery_bundle(
        mesh,
        &mut crate::test_support::SequentialRandom(111),
    )?;
    let other = bundle.open(&code)?;
    let key = WrappingPrivateKey::from_bytes([62; 32])?;
    let mut random = crate::test_support::SequentialRandom(121);
    assert!(
        source
            .prepare_recovery_control_keys(&other, &[key.public_key()], &[], &mut random)
            .is_err()
    );
    let authentication =
        SecretContext::new(AUTHENTICATION_ROOT_KEY_SECRET_KIND, mesh.as_bytes(), 1)?;
    assert!(
        source
            .prepare_recovery_secret(&other, authentication, &[key.public_key()], &mut random)
            .is_err()
    );
    for recipients in [
        vec![],
        vec![key.public_key(); 2],
        vec![fixture.authority.public_wrapping_key()],
    ] {
        assert!(
            source
                .prepare_recovery_control_keys(&fixture.authority, &recipients, &[], &mut random)
                .is_err()
        );
        assert!(
            source
                .prepare_recovery_secret(
                    &fixture.authority,
                    authentication,
                    &recipients,
                    &mut random
                )
                .is_err()
        );
        if !recipients.is_empty() {
            assert!(
                source
                    .prepare_recovery_control_keys(
                        &fixture.authority,
                        &[key.public_key()],
                        &recipients,
                        &mut random
                    )
                    .is_err()
            );
        }
    }
    let missing = SecretContext::new(AUTHENTICATION_ROOT_KEY_SECRET_KIND, mesh.as_bytes(), 99)?;
    assert!(
        source
            .prepare_recovery_secret(
                &fixture.authority,
                missing,
                &[key.public_key()],
                &mut random
            )
            .is_err()
    );
    Ok(())
}

fn open(
    command: &CommitSecretGeneration,
    key: &WrappingPrivateKey,
) -> Result<SecretPlaintext, Box<dyn std::error::Error>> {
    let selected = command
        .recipients
        .iter()
        .find(|recipient| recipient.recipient_public_key == key.public_key().as_bytes())
        .ok_or("recipient absent")?;
    let envelope = RecipientKeyEnvelope::from_parts(selected.clone())?;
    Ok(EncryptedSecret::from_parts(command.secret.clone())?.decrypt(&envelope.open(key)?)?)
}
