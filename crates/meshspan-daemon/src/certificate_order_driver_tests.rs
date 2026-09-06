// SPDX-License-Identifier: GPL-2.0-only

use std::future::Future;
use std::sync::{Arc, Mutex};

use meshspan_acme::{
    AcmeAccountKey, AcmeChallengePreference, AcmeHttpResponse, AcmeOrderMachine, AcmeOrderRequest,
    AcmeResponseHeaders, AcmeTransport, AcmeTransportError, AcmeTransportRequest, Http01Challenge,
};
use meshspan_certificates::{CertificateAuthority, ExternalCertificateRequestKey};
use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, Clock, DurationMicros, EntropyError, NodeId,
    OperationId, PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    AcmeChallengeKind, AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderClaim, CertificateOrderRecord, CertificateOrderState, CommandContext,
    CommandReceipt, EntityKind, EntityReference, LogPosition, SecretGenerationReference,
};
use meshspan_secret_envelope::WrappingPublicKey;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;

use crate::{
    CertificateOrderAssignment, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointAuthorityError, CertificateOrderCompletionAuthority,
    CertificateOrderCompletionAuthorityError, CertificateOrderDriveOutcome,
    CertificateOrderDrivePolicy, CertificateOrderDriver, CertificateOrderExecution,
    CertificateOrderFailureClass, CertificateOrderResultService, PreparedCertificateOrder,
};

mod deadlines;
mod remote_response;
mod retirement;
mod tls_retry;

#[test]
fn publication_policy_is_bounded_independently_of_request_timeouts() {
    let request_timeout = DurationMicros::new(1_000_000);
    for lifetime in [0, 1_000_000, 7 * 24 * 60 * 60 * 1_000_000 + 1] {
        assert!(
            CertificateOrderDrivePolicy::new(request_timeout, DurationMicros::new(lifetime), 1)
                .is_err()
        );
    }
    for lifetime in [
        1_000_001,
        24 * 60 * 60 * 1_000_000,
        7 * 24 * 60 * 60 * 1_000_000,
    ] {
        assert!(
            CertificateOrderDrivePolicy::new(request_timeout, DurationMicros::new(lifetime), 1)
                .is_ok()
        );
    }
}

#[tokio::test]
async fn drive_yields_only_after_authoritative_checkpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = RecordingAuthority::default();
    let mut execution = CertificateOrderExecution::new(
        prepared()?,
        DirectoryTransport::available()?,
        Http01Challenge::new(),
    );
    let mut driver = driver(
        authority.clone(),
        1,
        FixedClock(UnixMicros::new(20_000_000)),
    )?;

    let outcome = driver.drive(&mut execution).await?;

    assert_eq!(outcome, CertificateOrderDriveOutcome::Yielded { steps: 1 });
    assert_eq!(authority.checkpoint_count(), 1);
    assert_eq!(authority.completion_count(), 0);
    Ok(())
}

#[tokio::test]
async fn transport_failure_is_durably_requeued() -> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let mut execution = CertificateOrderExecution::new(
        prepared()?,
        DirectoryTransport::unavailable(),
        Http01Challenge::new(),
    );
    let mut driver = driver(
        authority.clone(),
        8,
        FixedClock(UnixMicros::new(20_000_000)),
    )?;

    let outcome = driver.drive(&mut execution).await?;

    assert!(matches!(
        outcome,
        CertificateOrderDriveOutcome::Retried {
            failure_class: CertificateOrderFailureClass::Transport,
            ..
        }
    ));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    Ok(())
}

fn driver<C: Clock>(
    authority: RecordingAuthority,
    maximum_steps: usize,
    clock: C,
) -> Result<CertificateOrderDriver<RecordingAuthority, SharedRandom, C>, Box<dyn std::error::Error>>
{
    driver_with_policy(
        authority,
        clock,
        CertificateOrderDrivePolicy::new(
            DurationMicros::new(1_000_000),
            DurationMicros::new(24 * 60 * 60 * 1_000_000),
            maximum_steps,
        )?,
    )
}

fn driver_with_policy<C: Clock>(
    authority: RecordingAuthority,
    clock: C,
    policy: CertificateOrderDrivePolicy,
) -> Result<CertificateOrderDriver<RecordingAuthority, SharedRandom, C>, Box<dyn std::error::Error>>
{
    let certificate_authority = CertificateAuthority::new()?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(
        certificate_authority.certificate_der().to_vec(),
    ))?;
    Ok(CertificateOrderDriver::new(
        authority.clone(),
        authority.clone(),
        authority,
        SharedRandom::default(),
        clock,
        policy,
        CertificateOrderResultService::new(roots)?,
    ))
}

#[tokio::test]
async fn ca_retry_after_reaches_the_authoritative_retry_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let response = AcmeHttpResponse::new(
        429,
        AcmeResponseHeaders::new(vec![("retry-after".to_owned(), "3600".to_owned())])?,
        br#"{"type":"urn:ietf:params:acme:error:rateLimited"}"#.to_vec(),
    )?;
    let mut execution = CertificateOrderExecution::new(
        prepared()?,
        DirectoryTransport(Some(Ok(response))),
        Http01Challenge::new(),
    );
    let outcome = driver(
        authority.clone(),
        8,
        FixedClock(UnixMicros::new(20_000_000)),
    )?
    .drive(&mut execution)
    .await?;
    let CertificateOrderDriveOutcome::Retried { commit, .. } = outcome else {
        return Err("CA rate limit must be durably requeued".into());
    };
    assert_eq!(commit.retry_at, UnixMicros::new(3_620_000_000));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    Ok(())
}

fn prepared() -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let config_id = AcmeConfigurationId::from_bytes([3; 16])?;
    let claim = CertificateOrderClaim {
        generation: 1,
        worker_node_id: NodeId::from_bytes([4; 16])?,
        worker_incarnation: 1,
        fence: 55,
        lease_expires_at: UnixMicros::new(120_000_000),
    };
    let names = vec!["files.example.test".to_owned()];
    let machine = AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        AcmeOrderRequest::new(names.clone())?,
        AcmeChallengePreference::Http01,
        claim.fence,
    )?;
    let certificate_key = ExternalCertificateRequestKey::generate()?;
    let csr_der = certificate_key.certificate_signing_request(&names)?;
    Ok(PreparedCertificateOrder {
        assignment: CertificateOrderAssignment {
            order: CertificateOrderRecord {
                order_id,
                config_id,
                state: CertificateOrderState::Claimed,
                next_attempt_at: UnixMicros::new(10_000_000),
                attempt_count: 1,
                certificate: None,
                claim: Some(claim),
                revision: Revision::new(6),
            },
            configuration: AcmeConfigurationRecord {
                provisioning_intent_digest: None,
                config_id,
                directory_url: "https://ca.example.test/directory".to_owned(),
                account_key: SecretGenerationReference {
                    secret_id: [5; 16],
                    generation: 1,
                },
                challenge_kind: AcmeChallengeKind::Http01,
                challenge_settings: None,
                certificate_names: names,
                configured_by: PrincipalId::from_bytes([2; 16])?,
                revision: Revision::new(7),
            },
            checkpoint: None,
        },
        machine,
        account_key: account_key()?,
        challenge_settings: None,
        certificate_key,
        csr_der,
        certificate_key_reference: SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        },
    })
}

fn account_key() -> Result<AcmeAccountKey, Box<dyn std::error::Error>> {
    let mut scalar = [0_u8; 32];
    scalar[31] = 1;
    Ok(AcmeAccountKey::from_secret_bytes(&scalar)?)
}

struct DirectoryTransport(Option<Result<AcmeHttpResponse, AcmeTransportError>>);

impl DirectoryTransport {
    fn available() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(Some(Ok(AcmeHttpResponse::new(
            200,
            AcmeResponseHeaders::new(Vec::new())?,
            br#"{"newNonce":"https://ca.example.test/nonce","newAccount":"https://ca.example.test/account","newOrder":"https://ca.example.test/order"}"#.to_vec(),
        )?))))
    }

    const fn unavailable() -> Self {
        Self(Some(Err(AcmeTransportError::Unavailable)))
    }
}

impl AcmeTransport for DirectoryTransport {
    fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send {
        std::future::ready(
            self.0
                .take()
                .unwrap_or(Err(AcmeTransportError::Unavailable)),
        )
    }
}

#[derive(Clone, Copy)]
struct FixedClock(UnixMicros);

impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        self.0
    }
}

#[derive(Clone, Default)]
struct SharedRandom(Arc<Mutex<u8>>);

impl RandomSource for SharedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let mut next = self.0.lock().map_err(|_| EntropyError)?;
        for byte in destination {
            *next = next.wrapping_add(1);
            *byte = *next;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingAuthority(Arc<Mutex<AuthorityState>>);

#[derive(Default)]
struct AuthorityState {
    checkpoints: usize,
    checkpoint_at: Option<UnixMicros>,
    completions: usize,
    completion: Option<AuthoritativeCommand>,
}

impl RecordingAuthority {
    fn checkpoint_count(&self) -> usize {
        self.0.lock().map_or(0, |state| state.checkpoints)
    }

    fn checkpoint_at(&self) -> Option<UnixMicros> {
        self.0.lock().ok()?.checkpoint_at
    }

    fn completion_count(&self) -> usize {
        self.0.lock().map_or(0, |state| state.completions)
    }

    fn retry_deadline(&self) -> Option<UnixMicros> {
        let state = self.0.lock().ok()?;
        match state.completion.as_ref()? {
            AuthoritativeCommand::CompleteCertificateOrder(command) => match command.outcome {
                meshspan_metadata::CertificateOrderCompletion::Retry { retry_at, .. }
                | meshspan_metadata::CertificateOrderCompletion::Restart { retry_at, .. } => {
                    Some(retry_at)
                }
                meshspan_metadata::CertificateOrderCompletion::Issued { .. } => None,
            },
            _ => None,
        }
    }
}

impl CertificateOrderCheckpointAuthority for RecordingAuthority {
    fn resolve_certificate_order_checkpoint(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError> {
        Ok(None)
    }

    fn checkpoint_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)?;
        state.checkpoints += 1;
        state.checkpoint_at = Some(context.occurred_at);
        receipt(context, command, Revision::new(10))
    }
}

impl CertificateOrderCompletionAuthority for RecordingAuthority {
    fn resolve_certificate_order_completion(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCompletionAuthorityError> {
        Ok(None)
    }

    fn certificate_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderCompletionAuthorityError> {
        Err(CertificateOrderCompletionAuthorityError::Failed)
    }

    fn complete_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCompletionAuthorityError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CertificateOrderCompletionAuthorityError::Failed)?;
        state.completions += 1;
        state.completion = Some(command.clone());
        receipt(context, command, Revision::new(11))
            .map_err(|_| CertificateOrderCompletionAuthorityError::Failed)
    }
}

fn receipt(
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError> {
    let order_id = match command {
        AuthoritativeCommand::CheckpointCertificateOrder(value) => value.order_id,
        AuthoritativeCommand::CompleteCertificateOrder(value) => value.order_id,
        _ => return Err(CertificateOrderCheckpointAuthorityError::Failed),
    };
    Ok(CommandReceipt {
        disposition: ApplyDisposition::Applied,
        operation_id: context.operation_id,
        request_digest: command.request_digest(context),
        result_digest: [9; 32],
        committed_revision: revision,
        committed_position: LogPosition {
            index: revision.get(),
            term: 1,
        },
        applied_position: LogPosition {
            index: revision.get(),
            term: 1,
        },
        entity: EntityReference {
            kind: EntityKind::CertificateOrder,
            id: order_id.as_bytes(),
        },
    })
}
