// SPDX-License-Identifier: GPL-2.0-only

use std::future::Future;
use std::sync::Mutex;

use meshspan_acme::{
    AcmeAccountKey, AcmeChallengePreference, AcmeHttpResponse, AcmeOrderMachine, AcmeOrderRequest,
    AcmeResponseHeaders, AcmeTransport, AcmeTransportError, AcmeTransportRequest, Http01Challenge,
};
use meshspan_certificates::ExternalCertificateRequestKey;
use meshspan_contracts::{ContractVersion, RequestContext};
use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, NodeId, OperationId, PrincipalId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AcmeChallengeKind, AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderClaim, CertificateOrderRecord, CertificateOrderState, CommandContext,
    CommandReceipt, EntityKind, EntityReference, LogPosition, SecretGenerationReference,
};

use crate::{
    CertificateOrderAssignment, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointAuthorityError, CertificateOrderCheckpointService,
    CertificateOrderExecution, CertificateOrderStepResult, PreparedCertificateOrder,
};

#[tokio::test]
async fn validated_remote_step_advances_then_commits_before_next_action()
-> Result<(), Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let prepared = prepared(order_id)?;
    let transport = OneResponseTransport(Some(AcmeHttpResponse::new(
        200,
        AcmeResponseHeaders::new(Vec::new())?,
        br#"{"newNonce":"https://ca.example.test/nonce","newAccount":"https://ca.example.test/account","newOrder":"https://ca.example.test/order"}"#.to_vec(),
    )?));
    let authority = RecordingCheckpointAuthority::default();
    let mut execution = CertificateOrderExecution::new(prepared, transport, Http01Challenge::new());
    let result = execution
        .execute_step(
            &CertificateOrderCheckpointService::new(&authority),
            PrincipalId::from_bytes([2; 16])?,
            UnixMicros::new(20),
            request_context()?,
            UnixMicros::new(80),
        )
        .await?;

    assert!(matches!(
        result,
        CertificateOrderStepResult::Checkpointed(_)
    ));
    assert!(matches!(
        execution.machine().action()?,
        meshspan_acme::AcmeMachineAction::AcquireNonce { .. }
    ));
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

fn prepared(
    order_id: CertificateOrderId,
) -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
    let config_id = AcmeConfigurationId::from_bytes([3; 16])?;
    let claim = CertificateOrderClaim {
        generation: 1,
        worker_node_id: NodeId::from_bytes([4; 16])?,
        worker_incarnation: 1,
        fence: 55,
        lease_expires_at: UnixMicros::new(100),
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
                next_attempt_at: UnixMicros::new(10),
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

fn request_context() -> Result<RequestContext, Box<dyn std::error::Error>> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([8; 16])?,
        deadline: UnixMicros::new(90),
        expected_revision: Some(Revision::new(7)),
    })
}

struct OneResponseTransport(Option<AcmeHttpResponse>);

impl AcmeTransport for OneResponseTransport {
    fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send {
        std::future::ready(self.0.take().ok_or(AcmeTransportError::Unavailable))
    }
}

#[derive(Default)]
struct RecordingCheckpointAuthority {
    state: Mutex<Option<CommandReceipt>>,
}

impl RecordingCheckpointAuthority {
    fn commit_count(&self) -> usize {
        usize::from(self.state.lock().is_ok_and(|state| state.is_some()))
    }
}

impl CertificateOrderCheckpointAuthority for &RecordingCheckpointAuthority {
    fn resolve_certificate_order_checkpoint(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError> {
        Ok(*self
            .state
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)?)
    }

    fn checkpoint_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError> {
        let order_id = match command {
            AuthoritativeCommand::CheckpointCertificateOrder(value) => value.order_id,
            _ => return Err(CertificateOrderCheckpointAuthorityError::Failed),
        };
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [9; 32],
            committed_revision: Revision::new(10),
            committed_position: LogPosition { index: 10, term: 1 },
            applied_position: LogPosition { index: 10, term: 1 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: order_id.as_bytes(),
            },
        };
        *self
            .state
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)? = Some(receipt);
        Ok(receipt)
    }
}
