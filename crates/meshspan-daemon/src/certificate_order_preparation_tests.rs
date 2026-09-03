// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, EntropyError, NodeId, PrincipalId, RandomSource,
    Revision, UnixMicros,
};
use meshspan_metadata::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND, AcmeChallengeKind,
    AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderCheckpointRecord, CertificateOrderClaim, CertificateOrderRecord,
    CertificateOrderState, CommandContext, CommandReceipt, EntityKind, EntityReference,
    LogPosition, SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretContext, SecretPlaintext, WrappingPrivateKey,
    WrappingPublicKey, encrypt_secret,
};

use crate::{
    CertificateOrderAssignment, CertificateOrderPreparationAuthority,
    CertificateOrderPreparationAuthorityError, CertificateOrderPreparationService,
    SecretGenerationAuthority, SecretGenerationAuthorityError, SecretGenerationDecryptor,
    SecretGenerationDecryptorError,
};

#[test]
fn preparation_creates_one_encrypted_leaf_key_then_reuses_it_after_worker_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let local_key = WrappingPrivateKey::from_bytes([1; 32])?;
    let recovery_key = WrappingPrivateKey::from_bytes([2; 32])?;
    let recipients = sorted_recipients(&[&local_key, &recovery_key]);
    let account_reference = SecretGenerationReference {
        secret_id: [3; 16],
        generation: 1,
    };
    let account_context = SecretContext::new(
        ACME_ACCOUNT_KEY_SECRET_KIND,
        account_reference.secret_id,
        account_reference.generation,
    )?;
    let mut account_scalar = [0_u8; 32];
    account_scalar[31] = 1;
    let account_record = encrypted_record(
        account_context,
        &account_scalar,
        &recipients,
        &mut IncrementingRandom(10),
    )?;
    let authority = FakeAuthority::new(recipients, account_context, account_record);
    let decryptor = TestDecryptor(local_key);
    let order_id = CertificateOrderId::from_bytes([4; 16])?;

    let mut service =
        CertificateOrderPreparationService::new(&authority, &decryptor, IncrementingRandom(30));
    let first = service.prepare(
        PrincipalId::from_bytes([5; 16])?,
        UnixMicros::new(20),
        assignment(order_id, account_reference, 55, None)?,
    )?;
    assert_eq!(first.machine.order_epoch(), 55);
    assert_eq!(first.machine.dns_names(), &["files.example.test"]);
    assert_eq!(
        first.certificate_key_reference.secret_id,
        order_id.as_bytes()
    );
    assert_eq!(first.certificate_key_reference.generation, 1);
    assert_eq!(authority.commit_count(), 1);
    let fingerprint = first.certificate_key.public_key_fingerprint();
    let checkpoint = CertificateOrderCheckpointRecord {
        order_id,
        claim_generation: 1,
        worker_node_id: NodeId::from_bytes([6; 16])?,
        worker_incarnation: 1,
        fence: 55,
        certificate_key: first.certificate_key_reference,
        checkpoint: first.machine.encode_checkpoint()?,
        checkpoint_digest: [7; 32],
        revision: Revision::new(8),
    };
    drop(first);

    let replacement = service.prepare(
        PrincipalId::from_bytes([5; 16])?,
        UnixMicros::new(30),
        assignment(order_id, account_reference, 56, Some(checkpoint))?,
    )?;
    assert_eq!(replacement.machine.order_epoch(), 56);
    assert_eq!(
        replacement.certificate_key.public_key_fingerprint(),
        fingerprint
    );
    assert_eq!(authority.commit_count(), 1);
    assert!(replacement.csr_der.starts_with(&[0x30]));
    Ok(())
}

#[test]
fn preparation_decrypts_automatic_dns_settings_into_zeroising_runtime_state()
-> Result<(), Box<dyn std::error::Error>> {
    let local_key = WrappingPrivateKey::from_bytes([1; 32])?;
    let recipients = sorted_recipients(&[&local_key]);
    let account_reference = SecretGenerationReference {
        secret_id: [3; 16],
        generation: 1,
    };
    let account_context = SecretContext::new(
        ACME_ACCOUNT_KEY_SECRET_KIND,
        account_reference.secret_id,
        account_reference.generation,
    )?;
    let mut account_scalar = [0_u8; 32];
    account_scalar[31] = 1;
    let account_record = encrypted_record(
        account_context,
        &account_scalar,
        &recipients,
        &mut IncrementingRandom(10),
    )?;
    let settings_reference = SecretGenerationReference {
        secret_id: [8; 16],
        generation: 2,
    };
    let settings_context = SecretContext::new(
        ACME_CHALLENGE_SETTINGS_SECRET_KIND,
        settings_reference.secret_id,
        settings_reference.generation,
    )?;
    let settings = b"canonical-encrypted-provider-settings";
    let settings_record = encrypted_record(
        settings_context,
        settings,
        &recipients,
        &mut IncrementingRandom(20),
    )?;
    let authority = FakeAuthority::new(recipients, account_context, account_record);
    authority.add_record(settings_context, settings_record)?;
    let decryptor = TestDecryptor(local_key);
    let order_id = CertificateOrderId::from_bytes([4; 16])?;
    let mut assigned = assignment(order_id, account_reference, 55, None)?;
    assigned.configuration.challenge_kind = AcmeChallengeKind::Dns01;
    assigned.configuration.challenge_settings = Some(settings_reference);
    let prepared =
        CertificateOrderPreparationService::new(&authority, &decryptor, IncrementingRandom(30))
            .prepare(
                PrincipalId::from_bytes([5; 16])?,
                UnixMicros::new(20),
                assigned,
            )?;
    assert_eq!(
        prepared
            .challenge_settings
            .as_ref()
            .map(SecretPlaintext::expose),
        Some(settings.as_slice())
    );
    Ok(())
}

fn assignment(
    order_id: CertificateOrderId,
    account_key: SecretGenerationReference,
    fence: u64,
    checkpoint: Option<CertificateOrderCheckpointRecord>,
) -> Result<CertificateOrderAssignment, Box<dyn std::error::Error>> {
    let config_id = AcmeConfigurationId::from_bytes([9; 16])?;
    Ok(CertificateOrderAssignment {
        order: CertificateOrderRecord {
            order_id,
            config_id,
            state: CertificateOrderState::Claimed,
            next_attempt_at: UnixMicros::new(10),
            attempt_count: if fence == 55 { 1 } else { 2 },
            certificate: None,
            claim: Some(CertificateOrderClaim {
                generation: if fence == 55 { 1 } else { 2 },
                worker_node_id: NodeId::from_bytes([6; 16])?,
                worker_incarnation: 1,
                fence,
                lease_expires_at: UnixMicros::new(100),
            }),
            revision: Revision::new(10),
        },
        configuration: AcmeConfigurationRecord {
            provisioning_intent_digest: None,
            config_id,
            directory_url: "https://acme.example.test/directory".to_owned(),
            account_key,
            challenge_kind: AcmeChallengeKind::Http01,
            challenge_settings: None,
            certificate_names: vec!["files.example.test".to_owned()],
            revision: Revision::new(3),
        },
        checkpoint,
    })
}

fn sorted_recipients(keys: &[&WrappingPrivateKey]) -> Vec<WrappingPublicKey> {
    let mut recipients = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>();
    recipients.sort_by_key(|recipient| recipient.fingerprint());
    recipients
}

fn encrypted_record(
    context: SecretContext,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(context, plaintext, recipients, random)?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

struct FakeAuthority {
    recipients: Vec<WrappingPublicKey>,
    state: Mutex<FakeState>,
}

struct FakeState {
    records: Vec<(SecretContext, SecretGenerationRecord)>,
    receipt: Option<CommandReceipt>,
    commits: usize,
}

impl FakeAuthority {
    fn new(
        recipients: Vec<WrappingPublicKey>,
        account_context: SecretContext,
        account_record: SecretGenerationRecord,
    ) -> Self {
        Self {
            recipients,
            state: Mutex::new(FakeState {
                records: vec![(account_context, account_record)],
                receipt: None,
                commits: 0,
            }),
        }
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }

    fn add_record(
        &self,
        context: SecretContext,
        record: SecretGenerationRecord,
    ) -> Result<(), &'static str> {
        self.state
            .lock()
            .map_err(|_| "authority state poisoned")?
            .records
            .push((context, record));
        Ok(())
    }
}

impl SecretGenerationAuthority for &FakeAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| SecretGenerationAuthorityError::Failed)?;
        Ok(state
            .records
            .iter()
            .find(|(candidate, _)| *candidate == context)
            .map(|(_, record)| record.clone()))
    }
}

impl CertificateOrderPreparationAuthority for &FakeAuthority {
    fn certificate_key_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderPreparationAuthorityError> {
        Ok(self.recipients.clone())
    }

    fn resolve_certificate_key_commit(
        &self,
        _operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderPreparationAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| CertificateOrderPreparationAuthorityError::Failed)?
            .receipt)
    }

    fn commit_certificate_key(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderPreparationAuthorityError> {
        let AuthoritativeCommand::CommitSecretGeneration(generation) = command else {
            return Err(CertificateOrderPreparationAuthorityError::Failed);
        };
        let secret = EncryptedSecret::from_parts(generation.secret.clone())
            .map_err(|_| CertificateOrderPreparationAuthorityError::Failed)?;
        let recipients = generation
            .recipients
            .iter()
            .cloned()
            .map(RecipientKeyEnvelope::from_parts)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CertificateOrderPreparationAuthorityError::Failed)?;
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [11; 32],
            committed_revision: Revision::new(12),
            committed_position: LogPosition { index: 12, term: 1 },
            applied_position: LogPosition { index: 12, term: 1 },
            entity: EntityReference {
                kind: EntityKind::SecretGeneration,
                id: secret.context().id(),
            },
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| CertificateOrderPreparationAuthorityError::Failed)?;
        state.records.push((
            secret.context(),
            SecretGenerationRecord {
                secret,
                recipients,
                revision: receipt.committed_revision,
            },
        ));
        state.receipt = Some(receipt);
        state.commits = state.commits.saturating_add(1);
        Ok(receipt)
    }
}

struct TestDecryptor(WrappingPrivateKey);

impl SecretGenerationDecryptor for &TestDecryptor {
    fn public_key(&self) -> WrappingPublicKey {
        self.0.public_key()
    }

    fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, SecretGenerationDecryptorError> {
        let data_key = recipient
            .open(&self.0)
            .map_err(|_| SecretGenerationDecryptorError::Failed)?;
        secret
            .decrypt(&data_key)
            .map_err(|_| SecretGenerationDecryptorError::Failed)
    }
}

struct IncrementingRandom(u8);

impl RandomSource for IncrementingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
