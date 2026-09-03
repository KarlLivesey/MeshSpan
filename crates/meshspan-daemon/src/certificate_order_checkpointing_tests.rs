// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_acme::{AcmeChallengePreference, AcmeOrderMachine, AcmeOrderRequest};
use meshspan_domain::{CertificateOrderId, NodeId, PrincipalId, Revision, UnixMicros};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CertificateOrderClaim, CommandContext, CommandReceipt,
    EntityKind, EntityReference, LogPosition, SecretGenerationReference,
};

use crate::{
    CertificateOrderCheckpoint, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointAuthorityError, CertificateOrderCheckpointError,
    CertificateOrderCheckpointService,
};

#[test]
fn checkpoint_commits_exact_machine_once_and_replays_the_same_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let service = CertificateOrderCheckpointService::new(&authority);
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let machine = machine(55)?;
    let claim = claim(55)?;
    let input = || CertificateOrderCheckpoint {
        order_id,
        claim,
        certificate_key: SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        },
        machine: &machine,
    };
    let first = service.checkpoint(
        PrincipalId::from_bytes([2; 16])?,
        UnixMicros::new(20),
        &input(),
    )?;
    let second = service.checkpoint(
        PrincipalId::from_bytes([2; 16])?,
        UnixMicros::new(20),
        &input(),
    )?;

    assert_eq!(first, second);
    assert_eq!(first.revision, Revision::new(9));
    assert_ne!(first.checkpoint_digest, [0; 32]);
    assert_eq!(authority.commit_count(), 1);
    let command = authority.command()?.ok_or("checkpoint command missing")?;
    let AuthoritativeCommand::CheckpointCertificateOrder(command) = command else {
        return Err("wrong command family".into());
    };
    assert_eq!(command.order_id, order_id);
    assert_eq!(command.claim_generation, 3);
    assert_eq!(command.fence, 55);
    assert_eq!(command.checkpoint, machine.encode_checkpoint()?);
    Ok(())
}

#[test]
fn expired_mismatched_and_completed_machine_inputs_never_reach_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let service = CertificateOrderCheckpointService::new(&authority);
    let order_id = CertificateOrderId::from_bytes([3; 16])?;
    let mismatched = machine(56)?;
    let result = service.checkpoint(
        PrincipalId::from_bytes([4; 16])?,
        UnixMicros::new(20),
        &CertificateOrderCheckpoint {
            order_id,
            claim: claim(55)?,
            certificate_key: SecretGenerationReference {
                secret_id: order_id.as_bytes(),
                generation: 1,
            },
            machine: &mismatched,
        },
    );
    assert!(matches!(
        result,
        Err(CertificateOrderCheckpointError::InvalidInput)
    ));

    let matching = machine(55)?;
    let result = service.checkpoint(
        PrincipalId::from_bytes([4; 16])?,
        UnixMicros::new(100),
        &CertificateOrderCheckpoint {
            order_id,
            claim: claim(55)?,
            certificate_key: SecretGenerationReference {
                secret_id: order_id.as_bytes(),
                generation: 1,
            },
            machine: &matching,
        },
    );
    assert!(matches!(
        result,
        Err(CertificateOrderCheckpointError::InvalidInput)
    ));
    assert_eq!(authority.commit_count(), 0);
    Ok(())
}

fn machine(fence: u64) -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    Ok(AcmeOrderMachine::new(
        "https://acme.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        AcmeChallengePreference::Http01,
        fence,
    )?)
}

fn claim(fence: u64) -> Result<CertificateOrderClaim, Box<dyn std::error::Error>> {
    Ok(CertificateOrderClaim {
        generation: 3,
        worker_node_id: NodeId::from_bytes([5; 16])?,
        worker_incarnation: 2,
        fence,
        lease_expires_at: UnixMicros::new(100),
    })
}

#[derive(Default)]
struct RecordingAuthority {
    state: Mutex<RecordingState>,
}

#[derive(Default)]
struct RecordingState {
    command: Option<AuthoritativeCommand>,
    receipt: Option<CommandReceipt>,
    commits: usize,
}

impl RecordingAuthority {
    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }

    fn command(
        &self,
    ) -> Result<Option<AuthoritativeCommand>, CertificateOrderCheckpointAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)?
            .command
            .clone())
    }
}

impl CertificateOrderCheckpointAuthority for &RecordingAuthority {
    fn resolve_certificate_order_checkpoint(
        &self,
        _operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)?
            .receipt)
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
            result_digest: [6; 32],
            committed_revision: Revision::new(9),
            committed_position: LogPosition { index: 9, term: 1 },
            applied_position: LogPosition { index: 9, term: 1 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: order_id.as_bytes(),
            },
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| CertificateOrderCheckpointAuthorityError::Failed)?;
        state.command = Some(command.clone());
        state.receipt = Some(receipt);
        state.commits = state.commits.saturating_add(1);
        Ok(receipt)
    }
}
