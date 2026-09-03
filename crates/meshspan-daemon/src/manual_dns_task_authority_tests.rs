// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_acme::{ManualDnsTask, ManualDnsTaskAuthority, ManualDnsTaskPhase};
use meshspan_contracts::ContractError;
use meshspan_domain::{
    CertificateOrderId, Clock, NodeId, OperationId, PrincipalId, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CertificateOrderClaim, CommandContext, CommandReceipt,
    EntityKind, EntityReference, LogPosition,
};

use crate::{ConsensusManualDnsTaskAuthority, ManualDnsTaskCommitAuthority};

#[tokio::test]
async fn exact_transition_commits_once_and_resolves_a_lost_response()
-> Result<(), Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let authority = RecordingAuthority::default();
    let adapter = ConsensusManualDnsTaskAuthority::new(
        &authority,
        FixedClock,
        order_id,
        CertificateOrderClaim {
            generation: 2,
            worker_node_id: NodeId::from_bytes([3; 16])?,
            worker_incarnation: 4,
            fence: 5,
            lease_expires_at: UnixMicros::new(100),
        },
        PrincipalId::from_bytes([6; 16])?,
    );
    let task = ManualDnsTask {
        task_digest: [7; 32],
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: b"txt-value".to_vec(),
        expires_at: UnixMicros::new(90),
        order_epoch: 5,
        phase: ManualDnsTaskPhase::AwaitingPublication,
    };
    adapter.advance(&task).await?;
    adapter.advance(&task).await?;
    assert_eq!(authority.commit_count()?, 1);
    let command = authority.command()?.ok_or("command missing")?;
    let AuthoritativeCommand::AdvanceManualDnsTask(command) = command else {
        return Err("wrong command".into());
    };
    assert_eq!(command.task_digest, task.task_digest);
    assert_eq!(command.order_id, order_id);
    assert_eq!(command.fence, 5);
    Ok(())
}

#[tokio::test]
async fn wrong_order_epoch_never_reaches_consensus() -> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let adapter = ConsensusManualDnsTaskAuthority::new(
        &authority,
        FixedClock,
        CertificateOrderId::from_bytes([1; 16])?,
        CertificateOrderClaim {
            generation: 2,
            worker_node_id: NodeId::from_bytes([3; 16])?,
            worker_incarnation: 4,
            fence: 5,
            lease_expires_at: UnixMicros::new(100),
        },
        PrincipalId::from_bytes([6; 16])?,
    );
    let task = ManualDnsTask {
        task_digest: [7; 32],
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: b"txt-value".to_vec(),
        expires_at: UnixMicros::new(90),
        order_epoch: 8,
        phase: ManualDnsTaskPhase::AwaitingPublication,
    };
    assert_eq!(adapter.advance(&task).await, Err(ContractError::Stale));
    assert_eq!(authority.commit_count()?, 0);
    Ok(())
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(10)
    }
}

#[derive(Default)]
struct RecordingAuthority {
    stored: Mutex<Option<(CommandReceipt, AuthoritativeCommand)>>,
    commits: Mutex<usize>,
}

impl RecordingAuthority {
    fn commit_count(&self) -> Result<usize, ContractError> {
        self.commits
            .lock()
            .map(|value| *value)
            .map_err(|_| ContractError::Unavailable)
    }

    fn command(&self) -> Result<Option<AuthoritativeCommand>, ContractError> {
        self.stored
            .lock()
            .map(|stored| stored.as_ref().map(|value| value.1.clone()))
            .map_err(|_| ContractError::Unavailable)
    }
}

impl ManualDnsTaskCommitAuthority for &RecordingAuthority {
    fn resolve_manual_dns_task(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, ContractError> {
        self.stored
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .map(|stored| {
                stored
                    .as_ref()
                    .filter(|value| value.0.operation_id == operation_id)
                    .map(|value| value.0)
            })
    }

    fn commit_manual_dns_task(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, ContractError> {
        *self
            .commits
            .lock()
            .map_err(|_| ContractError::Unavailable)? += 1;
        let AuthoritativeCommand::AdvanceManualDnsTask(task) = command else {
            return Err(ContractError::InternalContract);
        };
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [8; 32],
            committed_revision: Revision::new(9),
            committed_position: LogPosition { term: 1, index: 2 },
            applied_position: LogPosition { term: 1, index: 2 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: task.order_id.as_bytes(),
            },
        };
        *self.stored.lock().map_err(|_| ContractError::Unavailable)? =
            Some((receipt, command.clone()));
        Ok(receipt)
    }
}
