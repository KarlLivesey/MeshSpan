// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, NodeId, PrincipalId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AcmeChallengeKind, AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderClaim, CertificateOrderCompletion, CertificateOrderRecord,
    CertificateOrderState, CommandContext, CommandReceipt, EntityKind, EntityReference,
    LogPosition, SecretGenerationReference,
};
use meshspan_secret_envelope::WrappingPublicKey;

use crate::{
    CertificateOrderAssignment, CertificateOrderCompletionAuthority,
    CertificateOrderCompletionAuthorityError, CertificateOrderFailureClass,
    CertificateOrderRetryError, CertificateOrderRetryService,
};

const SECOND: i64 = 1_000_000;

#[test]
fn retry_is_bounded_authoritative_and_exactly_replayable() -> Result<(), Box<dyn std::error::Error>>
{
    let assignment = assignment(UnixMicros::new(1_000 * SECOND))?;
    let authority = RecordingAuthority::default();
    let service = CertificateOrderRetryService::new(&authority);
    let failed_at = UnixMicros::new(100 * SECOND);
    let retry_after = UnixMicros::new(400 * SECOND);

    let committed = service.retry(
        PrincipalId::from_bytes([7; 16])?,
        failed_at,
        &assignment,
        CertificateOrderFailureClass::Transport,
        Some(retry_after),
    )?;

    assert_eq!(committed.retry_at, retry_after);
    assert_ne!(committed.failure_digest, [0; 32]);
    assert_eq!(committed.revision, Revision::new(20));
    assert_eq!(authority.commit_count(), 1);
    let command = authority.command()?.ok_or("missing command")?;
    let AuthoritativeCommand::CompleteCertificateOrder(command) = command else {
        return Err("wrong command family".into());
    };
    assert_eq!(command.order_id, assignment.order.order_id);
    assert!(matches!(
        command.outcome,
        CertificateOrderCompletion::Retry {
            failure_digest,
            retry_at: value,
        } if failure_digest == committed.failure_digest && value == retry_after
    ));

    let replayed = service.retry(
        PrincipalId::from_bytes([7; 16])?,
        failed_at,
        &assignment,
        CertificateOrderFailureClass::Transport,
        Some(retry_after),
    )?;
    assert_eq!(replayed, committed);
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

#[test]
fn retry_rejects_stale_claim_before_authority_work() -> Result<(), Box<dyn std::error::Error>> {
    let assignment = assignment(UnixMicros::new(100 * SECOND))?;
    let authority = RecordingAuthority::default();
    let result = CertificateOrderRetryService::new(&authority).retry(
        PrincipalId::from_bytes([7; 16])?,
        UnixMicros::new(100 * SECOND),
        &assignment,
        CertificateOrderFailureClass::Certificate,
        None,
    );
    assert!(matches!(
        result,
        Err(CertificateOrderRetryError::InvalidInput)
    ));
    assert_eq!(authority.commit_count(), 0);
    Ok(())
}

fn assignment(
    lease_expires_at: UnixMicros,
) -> Result<CertificateOrderAssignment, Box<dyn std::error::Error>> {
    let config_id = AcmeConfigurationId::from_bytes([2; 16])?;
    Ok(CertificateOrderAssignment {
        order: CertificateOrderRecord {
            order_id: CertificateOrderId::from_bytes([1; 16])?,
            config_id,
            state: CertificateOrderState::Claimed,
            next_attempt_at: UnixMicros::new(1),
            attempt_count: 1,
            certificate: None,
            claim: Some(CertificateOrderClaim {
                generation: 3,
                worker_node_id: NodeId::from_bytes([3; 16])?,
                worker_incarnation: 4,
                fence: 5,
                lease_expires_at,
            }),
            revision: Revision::new(6),
        },
        configuration: AcmeConfigurationRecord {
            provisioning_intent_digest: None,
            config_id,
            directory_url: "https://ca.example.test/directory".to_owned(),
            account_key: SecretGenerationReference {
                secret_id: [4; 16],
                generation: 1,
            },
            challenge_kind: AcmeChallengeKind::Http01,
            challenge_settings: None,
            certificate_names: vec!["files.example.test".to_owned()],
            configured_by: PrincipalId::from_bytes([2; 16])?,
            revision: Revision::new(7),
        },
        checkpoint: None,
    })
}

#[derive(Default)]
struct RecordingAuthority {
    state: Mutex<AuthorityState>,
}

#[derive(Default)]
struct AuthorityState {
    command: Option<AuthoritativeCommand>,
    receipt: Option<CommandReceipt>,
    commits: usize,
}

impl RecordingAuthority {
    fn command(&self) -> Result<Option<AuthoritativeCommand>, Box<dyn std::error::Error>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "authority lock failed")?
            .command
            .clone())
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }
}

impl CertificateOrderCompletionAuthority for &RecordingAuthority {
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
        Err(CertificateOrderCompletionAuthorityError::Failed)
    }

    fn complete_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCompletionAuthorityError> {
        let AuthoritativeCommand::CompleteCertificateOrder(value) = command else {
            return Err(CertificateOrderCompletionAuthorityError::Failed);
        };
        let receipt = CommandReceipt {
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
