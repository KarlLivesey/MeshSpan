// SPDX-License-Identifier: GPL-2.0-only

use std::future::Future;
use std::sync::Mutex;
use std::time::SystemTime;

use meshspan_acme::{
    AcmeAccountKey, AcmeChallengePreference, AcmeOrderMachine, AcmeOrderRequest, AcmeTransport,
    AcmeTransportError, AcmeTransportRequest, Http01Challenge,
};
use meshspan_certificates::{CertificateAuthority, ExternalCertificateRequestKey};
use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, EntropyError, NodeId, PrincipalId, RandomSource,
    Revision, UnixMicros,
};
use meshspan_metadata::{
    AcmeChallengeKind, AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderClaim, CertificateOrderRecord, CertificateOrderState, CommandContext,
    CommandReceipt, EntityKind, EntityReference, LogPosition, SecretGenerationReference,
};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;

use crate::{
    CertificateOrderAssignment, CertificateOrderCompletionAuthority,
    CertificateOrderCompletionAuthorityError, CertificateOrderCompletionService,
    CertificateOrderExecution, CertificateOrderResultError, CertificateOrderResultService,
    PreparedCertificateOrder,
};

#[test]
fn trusted_terminal_result_commits_once_and_untrusted_chain_commits_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let now = current_unix_micros()?;
    let certificate_authority = CertificateAuthority::new()?;
    let execution = execution(now)?;
    let certificate = certificate_authority.issue_public_endpoint(
        &execution.assignment().configuration.certificate_names,
        execution.certificate_key(),
    )?;
    let response = pem_certificate(&certificate);
    let trusted = CertificateOrderResultService::new(roots(&certificate_authority)?)?;
    let authority = RecordingCompletionAuthority::new(vec![
        WrappingPrivateKey::from_bytes([8; 32])?.public_key(),
    ]);
    let mut completion = CertificateOrderCompletionService::new(&authority, FixedRandom(30));

    let committed = trusted.complete(
        &mut completion,
        PrincipalId::from_bytes([7; 16])?,
        now,
        &execution,
        &response,
    )?;

    assert_eq!(committed.revision, Revision::new(20));
    assert_eq!(authority.commit_count(), 1);

    let untrusted = CertificateOrderResultService::new(roots(&CertificateAuthority::new()?)?)?;
    let rejected_authority = RecordingCompletionAuthority::new(Vec::new());
    let mut rejected_completion =
        CertificateOrderCompletionService::new(&rejected_authority, FixedRandom(60));
    assert!(matches!(
        untrusted.complete(
            &mut rejected_completion,
            PrincipalId::from_bytes([7; 16])?,
            now,
            &execution,
            &response,
        ),
        Err(CertificateOrderResultError::InvalidTrust)
    ));
    assert_eq!(rejected_authority.commit_count(), 0);
    Ok(())
}

fn execution(
    now: UnixMicros,
) -> Result<
    CertificateOrderExecution<UnavailableTransport, Http01Challenge>,
    Box<dyn std::error::Error>,
> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let config_id = AcmeConfigurationId::from_bytes([2; 16])?;
    let names = vec![
        "*.files.example.test".to_owned(),
        "files.example.test".to_owned(),
    ];
    let lease_expires_at = UnixMicros::new(
        now.get()
            .checked_add(3_600_000_000)
            .ok_or("lease overflow")?,
    );
    let claim = CertificateOrderClaim {
        generation: 1,
        worker_node_id: NodeId::from_bytes([3; 16])?,
        worker_incarnation: 1,
        fence: 5,
        lease_expires_at,
    };
    let machine = AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        AcmeOrderRequest::new(names.clone())?,
        AcmeChallengePreference::Http01,
        claim.fence,
    )?;
    let certificate_key = ExternalCertificateRequestKey::generate()?;
    let csr_der = certificate_key.certificate_signing_request(&names)?;
    let prepared = PreparedCertificateOrder {
        assignment: CertificateOrderAssignment {
            order: CertificateOrderRecord {
                order_id,
                config_id,
                state: CertificateOrderState::Claimed,
                next_attempt_at: now,
                attempt_count: 1,
                certificate: None,
                claim: Some(claim),
                revision: Revision::new(6),
            },
            configuration: AcmeConfigurationRecord {
                config_id,
                directory_url: "https://ca.example.test/directory".to_owned(),
                account_key: SecretGenerationReference {
                    secret_id: [4; 16],
                    generation: 1,
                },
                challenge_kind: AcmeChallengeKind::Http01,
                challenge_settings: None,
                certificate_names: names,
                revision: Revision::new(7),
            },
            checkpoint: None,
        },
        machine,
        account_key: account_key()?,
        certificate_key,
        csr_der,
        certificate_key_reference: SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        },
    };
    Ok(CertificateOrderExecution::new(
        prepared,
        UnavailableTransport,
        Http01Challenge::new(),
    ))
}

fn account_key() -> Result<AcmeAccountKey, Box<dyn std::error::Error>> {
    let mut scalar = [0_u8; 32];
    scalar[31] = 1;
    Ok(AcmeAccountKey::from_secret_bytes(&scalar)?)
}

fn roots(authority: &CertificateAuthority) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(authority.certificate_der().to_vec()))?;
    Ok(roots)
}

fn current_unix_micros() -> Result<UnixMicros, Box<dyn std::error::Error>> {
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_micros();
    Ok(UnixMicros::new(i64::try_from(micros)?))
}

struct UnavailableTransport;

impl AcmeTransport for UnavailableTransport {
    fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<meshspan_acme::AcmeHttpResponse, AcmeTransportError>> + Send
    {
        std::future::ready(Err(AcmeTransportError::Unavailable))
    }
}

struct RecordingCompletionAuthority {
    recipients: Vec<WrappingPublicKey>,
    commits: Mutex<usize>,
}

impl RecordingCompletionAuthority {
    fn new(recipients: Vec<WrappingPublicKey>) -> Self {
        Self {
            recipients,
            commits: Mutex::new(0),
        }
    }

    fn commit_count(&self) -> usize {
        self.commits.lock().map_or(0, |value| *value)
    }
}

impl CertificateOrderCompletionAuthority for &RecordingCompletionAuthority {
    fn resolve_certificate_order_completion(
        &self,
        _operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCompletionAuthorityError> {
        Ok(None)
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
        let AuthoritativeCommand::CompleteCertificateOrder(value) = command else {
            return Err(CertificateOrderCompletionAuthorityError::Failed);
        };
        let mut commits = self
            .commits
            .lock()
            .map_err(|_| CertificateOrderCompletionAuthorityError::Failed)?;
        *commits = commits.saturating_add(1);
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [9; 32],
            committed_revision: Revision::new(20),
            committed_position: LogPosition { index: 20, term: 2 },
            applied_position: LogPosition { index: 20, term: 2 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: value.order_id.as_bytes(),
            },
        })
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

fn pem_certificate(der: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut base64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let value = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        base64.push(ALPHABET[((value >> 18) & 63) as usize]);
        base64.push(ALPHABET[((value >> 12) & 63) as usize]);
        base64.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize]
        } else {
            b'='
        });
        base64.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize]
        } else {
            b'='
        });
    }
    let mut pem = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in base64.chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    pem
}
