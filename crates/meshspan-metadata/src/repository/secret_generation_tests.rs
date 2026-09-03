// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, EntropyError, HostId, MeshId, NodeId,
    OperationId, PartitionId, PrincipalId, RandomSource, Revision, RoleId, UnixMicros,
};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, BootstrapRecoveryIdentity, CommandContext,
    CommitSecretGeneration, ConfirmRecoveryBundleSaved, CreateAuthenticationMethod,
    NewAuthenticationCredential, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PartitionDatabase,
    RecordName,
};

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    private_key: WrappingPrivateKey,
    recovery_private_key: WrappingPrivateKey,
}

#[test]
fn ciphertext_and_recipient_commit_atomically_replay_and_decrypt_after_read()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(true)?;
    let secret_context = SecretContext::new(1, [30; 16], 1)?;
    let plaintext = b"persistent volume content key";
    let command = secret_command(
        secret_context,
        plaintext,
        &[
            fixture.private_key.public_key(),
            fixture.recovery_private_key.public_key(),
        ],
        40,
    )?;
    let command_context = context(41, fixture.administrator, 42, 30, Some(2))?;
    let receipt = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        command_context,
        &command,
    )?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    assert_eq!(receipt.entity.kind, EntityKind::SecretGeneration);
    assert_eq!(receipt.entity.id, secret_context.id());

    let stored = fixture
        .repository
        .secret_generation(secret_context)?
        .ok_or("secret generation missing")?;
    assert_eq!(stored.recipients.len(), 2);
    let node_envelope = stored
        .recipients
        .iter()
        .find(|recipient| {
            recipient.recipient_fingerprint().ok()
                == Some(fixture.private_key.public_key().fingerprint())
        })
        .ok_or("node recipient missing")?;
    let key = node_envelope.open(&fixture.private_key)?;
    assert_eq!(stored.secret.decrypt(&key)?.expose(), plaintext);
    assert_eq!(stored.revision, Revision::new(3));

    let replay = fixture.repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        command_context,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    Ok(())
}

#[test]
fn unregistered_recipient_rolls_back_ciphertext_and_envelopes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(true)?;
    let secret_context = SecretContext::new(1, [50; 16], 1)?;
    let unregistered = WrappingPrivateKey::from_bytes([51; 32])?.public_key();
    let command = secret_command(
        secret_context,
        b"must not persist",
        &[fixture.recovery_private_key.public_key(), unregistered],
        52,
    )?;
    let result = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(53, fixture.administrator, 54, 30, Some(2))?,
        &command,
    );
    assert!(matches!(result, Err(RepositoryError::Sqlite(_))));
    assert_eq!(fixture.repository.secret_generation(secret_context)?, None);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(2));
    Ok(())
}

#[test]
fn pending_recovery_or_missing_recovery_recipient_blocks_secret_provisioning()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pending = fixture(false)?;
    let pending_context = SecretContext::new(1, [60; 16], 1)?;
    let recoverable = secret_command(
        pending_context,
        b"not safe until bundle save is verified",
        &[
            pending.private_key.public_key(),
            pending.recovery_private_key.public_key(),
        ],
        61,
    )?;
    assert!(matches!(
        pending.repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(62, pending.administrator, 63, 30, Some(1))?,
            &recoverable,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(pending.repository.secret_generation(pending_context)?, None);

    let mut verified = fixture(true)?;
    let omitted_context = SecretContext::new(1, [70; 16], 1)?;
    let omitted = secret_command(
        omitted_context,
        b"recovery recipient was omitted",
        &[verified.private_key.public_key()],
        71,
    )?;
    assert!(matches!(
        verified.repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(72, verified.administrator, 73, 30, Some(2))?,
            &omitted,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        verified.repository.secret_generation(omitted_context)?,
        None
    );
    Ok(())
}

#[test]
fn public_certificate_requires_every_gateway_and_recovery_recipient()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(true)?;
    let secret_context = SecretContext::new(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, [80; 16], 1)?;
    let missing_gateway = secret_command(
        secret_context,
        b"encrypted certificate bundle",
        &[fixture.recovery_private_key.public_key()],
        81,
    )?;
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(82, fixture.administrator, 83, 30, Some(2))?,
            &missing_gateway,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(fixture.repository.secret_generation(secret_context)?, None);

    let complete = secret_command(
        secret_context,
        b"encrypted certificate bundle",
        &[
            fixture.private_key.public_key(),
            fixture.recovery_private_key.public_key(),
        ],
        84,
    )?;
    fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(85, fixture.administrator, 86, 30, Some(2))?,
        &complete,
    )?;
    assert_eq!(
        fixture
            .repository
            .secret_generation(secret_context)?
            .ok_or("certificate secret missing")?
            .recipients
            .len(),
        2
    );
    Ok(())
}

fn fixture(verify_recovery: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("secret-generation.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let node = NodeId::from_bytes([4; 16])?;
    let mesh_id = MeshId::from_bytes([7; 16])?;
    let recovery_private_key = WrappingPrivateKey::from_bytes([19; 32])?;
    let recovery_public_key = recovery_private_key.public_key();
    let certificate = vec![13; 64];
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(5, administrator, 6, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapAppliance(Box::new(
            crate::test_support::bootstrap_appliance(
                BootstrapMesh {
                    mesh_id,
                    mesh_name: RecordName::new("Secret mesh")?,
                    administrator_id: administrator,
                    administrator_name: RecordName::new("Administrator")?,
                    administrator_role_id: RoleId::from_bytes([8; 16])?,
                    host_id: HostId::from_bytes([3; 16])?,
                    host_name: RecordName::new("Host")?,
                    node_id: node,
                    node_name: RecordName::new("Node")?,
                    partition_name: RecordName::new("Root authority")?,
                },
                CreateAuthenticationMethod {
                    method_id: AuthenticationMethodId::from_bytes([9; 16])?,
                    principal_id: administrator,
                    label: "Initial API key".to_owned(),
                    service_scope: 7,
                    expires_at: None,
                    credential: NewAuthenticationCredential::ApiKey {
                        key_id: ApiKeyId::from_bytes([10; 16])?,
                        key_digest: [11; 32],
                        smb_verifier_ciphertext: Some(vec![12; 65]),
                        scopes: 7,
                        valid_from: UnixMicros::new(10),
                    },
                },
                Box::new(BootstrapRecoveryIdentity {
                    public_wrapping_key: recovery_public_key.as_bytes(),
                    key_fingerprint: recovery_public_key.fingerprint(),
                    online_authority_certificate_digest: Sha256::digest(&certificate).into(),
                    online_authority_certificate_der: certificate.clone(),
                    root_certificate_digest: Sha256::digest(&certificate).into(),
                    root_certificate_der: certificate,
                    bundle_digest: [14; 32],
                    save_challenge_commitment: [15; 32],
                }),
            )?,
        )),
    )?;
    if verify_recovery {
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(16, administrator, 17, 15, Some(1))?,
            &AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                mesh_id,
                bundle_digest: [14; 32],
                save_challenge_commitment: [15; 32],
            }),
        )?;
    }
    let private_key = crate::test_support::node_wrapping_private_key()?;
    Ok(Fixture {
        _directory: directory,
        repository,
        administrator,
        private_key,
        recovery_private_key,
    })
}

fn secret_command(
    secret_context: SecretContext,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random_seed: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        secret_context,
        plaintext,
        recipients,
        &mut SecretRandom(random_seed),
    )?;
    Ok(AuthoritativeCommand::CommitSecretGeneration(
        CommitSecretGeneration {
            secret: secret.parts(),
            recipients: recipients
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        },
    ))
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: Option<u64>,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: expected_revision.map(Revision::new),
    })
}

struct SecretRandom(u8);

impl RandomSource for SecretRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
