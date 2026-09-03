// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{
    CertificateOrderId, EntropyError, NodeId, PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CertificateOrderClaim, CertificateOrderCompletion,
    CommandContext, CommandReceipt, EntityKind, EntityReference, LogPosition,
};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};

use crate::{
    CertificateOrderCompletionAuthority, CertificateOrderCompletionAuthorityError,
    CertificateOrderCompletionService, CertificateOrderIssuance,
};

type CertificateParts = (Vec<Vec<u8>>, Vec<u8>);

#[test]
fn issuance_commits_one_atomic_secret_for_every_recipient_and_replays_without_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let private_keys = [
        WrappingPrivateKey::from_bytes([11; 32])?,
        WrappingPrivateKey::from_bytes([12; 32])?,
        WrappingPrivateKey::from_bytes([13; 32])?,
    ];
    let recipients = private_keys
        .iter()
        .map(WrappingPrivateKey::public_key)
        .collect();
    let authority = FakeAuthority::new(recipients);
    let (chain, key) = certificate_parts()?;
    let expected = PublicCertificateBundle::new(chain.clone(), key.clone())?;
    let mut service = CertificateOrderCompletionService::new(&authority, FixedRandom(30));
    let commit = service.complete(
        PrincipalId::from_bytes([2; 16])?,
        UnixMicros::new(100),
        &issuance(order_id, chain.clone(), key.clone())?,
    )?;
    assert_eq!(commit.bundle_digest, expected.digest());
    assert_eq!(commit.revision, Revision::new(9));
    assert_atomic_certificate(&authority.command()?, &private_keys, &expected)?;

    let mut replay = CertificateOrderCompletionService::new(&authority, RejectRandom);
    let replayed = replay.complete(
        PrincipalId::from_bytes([2; 16])?,
        UnixMicros::new(120),
        &issuance(order_id, chain, key)?,
    )?;
    assert_eq!(replayed, commit);
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

fn certificate_parts() -> Result<CertificateParts, Box<dyn std::error::Error>> {
    let authority = CertificateAuthority::new()?;
    let issued = authority.issue_node("files.example.test")?;
    Ok((
        vec![issued.certificate_der().to_vec()],
        issued.private_key().to_vec(),
    ))
}

fn issuance(
    order_id: CertificateOrderId,
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
) -> Result<CertificateOrderIssuance, Box<dyn std::error::Error>> {
    Ok(CertificateOrderIssuance {
        order_id,
        claim: CertificateOrderClaim {
            generation: 3,
            worker_node_id: NodeId::from_bytes([4; 16])?,
            worker_incarnation: 5,
            fence: 6,
            lease_expires_at: UnixMicros::new(500),
        },
        bundle: PublicCertificateBundle::new(chain, key)?,
        not_before: UnixMicros::new(90),
        not_after: UnixMicros::new(1_000),
    })
}

fn assert_atomic_certificate(
    command: &AuthoritativeCommand,
    private_keys: &[WrappingPrivateKey],
    expected: &PublicCertificateBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let AuthoritativeCommand::CompleteCertificateOrder(completion) = command else {
        return Err("wrong command family".into());
    };
    let CertificateOrderCompletion::Issued { certificate, .. } = &completion.outcome else {
        return Err("wrong completion family".into());
    };
    assert_eq!(certificate.recipients.len(), private_keys.len());
    let encrypted =
        meshspan_secret_envelope::EncryptedSecret::from_parts(certificate.secret.clone())?;
    for private_key in private_keys {
        let recipient = certificate
            .recipients
            .iter()
            .map(|parts| meshspan_secret_envelope::RecipientKeyEnvelope::from_parts(parts.clone()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|recipient| {
                recipient.recipient_fingerprint().ok()
                    == Some(private_key.public_key().fingerprint())
            })
            .ok_or("recipient envelope missing")?;
        let data_key = recipient.open(private_key)?;
        let plaintext = encrypted.decrypt(&data_key)?;
        assert_eq!(plaintext.expose(), expected.encode()?.as_slice());
    }
    Ok(())
}

struct FakeAuthority {
    recipients: Vec<WrappingPublicKey>,
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    command: Option<AuthoritativeCommand>,
    receipt: Option<CommandReceipt>,
    commits: usize,
}

impl FakeAuthority {
    fn new(recipients: Vec<WrappingPublicKey>) -> Self {
        Self {
            recipients,
            state: Mutex::new(FakeState::default()),
        }
    }

    fn command(&self) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
        self.state
            .lock()
            .map_err(|_| "fake authority lock failed")?
            .command
            .clone()
            .ok_or_else(|| "command missing".into())
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }
}

impl CertificateOrderCompletionAuthority for &FakeAuthority {
    fn resolve_certificate_order_completion(
        &self,
        _operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCompletionAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| CertificateOrderCompletionAuthorityError::Failed)?
            .receipt)
    }

    fn certificate_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderCompletionAuthorityError> {
        Ok(self.recipients.clone())
    }

    fn complete_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCompletionAuthorityError> {
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [8; 32],
            committed_revision: Revision::new(9),
            committed_position: LogPosition { index: 9, term: 1 },
            applied_position: LogPosition { index: 9, term: 1 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: match command {
                    AuthoritativeCommand::CompleteCertificateOrder(value) => {
                        value.order_id.as_bytes()
                    }
                    _ => return Err(CertificateOrderCompletionAuthorityError::Failed),
                },
            },
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| CertificateOrderCompletionAuthorityError::Failed)?;
        state.command = Some(command.clone());
        state.receipt = Some(receipt);
        state.commits = state.commits.saturating_add(1);
        Ok(receipt)
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

struct RejectRandom;

impl RandomSource for RejectRandom {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}
