// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI64, Ordering},
};

use meshspan_acme::{ManualDnsTask, ManualDnsTaskAuthority, ManualDnsTaskPhase};
use meshspan_contracts::ContractError;
use meshspan_domain::{
    CertificateOrderId, Clock, NodeId, OperationId, PrincipalId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AdvanceManualDnsTask, ApplyDisposition, AuthoritativeCommand, CertificateOrderClaim,
    CommandContext, CommandReceipt, EntityKind, EntityReference, LogPosition,
};

use crate::{ConsensusManualDnsTaskAuthority, ManualDnsTaskCommitAuthority};

#[tokio::test]
async fn exact_transition_commits_once_across_clock_progress_and_adapter_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let authority = RecordingAuthority::default();
    let clock = AdjustableClock::new(10);
    let adapter = ConsensusManualDnsTaskAuthority::new(
        &authority,
        clock.clone(),
        order_id,
        active_claim()?,
        PrincipalId::from_bytes([6; 16])?,
    );
    let task = manual_task();
    adapter.advance(&task).await?;
    clock.set(11);
    adapter.advance(&task).await?;
    assert_eq!(authority.commit_count()?, 1);
    drop(adapter);
    clock.set(12);
    let recovered = ConsensusManualDnsTaskAuthority::new(
        &authority,
        clock,
        order_id,
        active_claim()?,
        PrincipalId::from_bytes([6; 16])?,
    );
    recovered.advance(&task).await?;
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
        active_claim()?,
        PrincipalId::from_bytes([6; 16])?,
    );
    let mut task = manual_task();
    task.order_epoch = 8;
    assert_eq!(adapter.advance(&task).await, Err(ContractError::Stale));
    assert_eq!(authority.commit_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn confirmed_task_recovers_a_lost_commit_reply_without_a_second_write()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority {
        lose_reply: AtomicBool::new(true),
        ..RecordingAuthority::default()
    };
    let clock = AdjustableClock::new(10);
    let adapter = ConsensusManualDnsTaskAuthority::new(
        &authority,
        clock.clone(),
        CertificateOrderId::from_bytes([1; 16])?,
        active_claim()?,
        PrincipalId::from_bytes([6; 16])?,
    );
    let task = manual_task();
    assert_eq!(
        adapter.advance(&task).await,
        Err(ContractError::Unavailable)
    );
    assert_eq!(authority.commit_count()?, 1);
    clock.set(11);
    adapter.advance(&task).await?;
    assert_eq!(authority.commit_count()?, 1);
    Ok(())
}

#[tokio::test]
async fn unavailable_or_stale_task_observation_never_falls_back_to_a_write()
-> Result<(), Box<dyn std::error::Error>> {
    for error in [ContractError::Unavailable, ContractError::Stale] {
        let authority = RecordingAuthority {
            observation_error: Some(error),
            ..RecordingAuthority::default()
        };
        let adapter = ConsensusManualDnsTaskAuthority::new(
            &authority,
            FixedClock,
            CertificateOrderId::from_bytes([1; 16])?,
            active_claim()?,
            PrincipalId::from_bytes([6; 16])?,
        );
        assert_eq!(adapter.advance(&manual_task()).await, Err(error));
        assert_eq!(authority.commit_count()?, 0);
    }
    Ok(())
}

fn active_claim() -> Result<CertificateOrderClaim, Box<dyn std::error::Error>> {
    Ok(CertificateOrderClaim {
        generation: 2,
        worker_node_id: NodeId::from_bytes([3; 16])?,
        worker_incarnation: 4,
        fence: 5,
        lease_expires_at: UnixMicros::new(100),
    })
}

fn manual_task() -> ManualDnsTask {
    ManualDnsTask {
        task_digest: [7; 32],
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: b"txt-value".to_vec(),
        expires_at: UnixMicros::new(90),
        order_epoch: 5,
        phase: ManualDnsTaskPhase::AwaitingPublication,
    }
}

struct FixedClock;

#[derive(Clone)]
struct AdjustableClock(Arc<AtomicI64>);

impl AdjustableClock {
    fn new(now: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now)))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for AdjustableClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.load(Ordering::SeqCst))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(10)
    }
}

#[derive(Default)]
struct RecordingAuthority {
    stored: Mutex<Option<(CommandReceipt, AuthoritativeCommand)>>,
    commits: Mutex<usize>,
    observation_error: Option<ContractError>,
    lose_reply: AtomicBool,
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
    fn manual_dns_task_transition_satisfied(
        &self,
        _now: UnixMicros,
        transition: &AdvanceManualDnsTask,
    ) -> Result<bool, ContractError> {
        if let Some(error) = self.observation_error {
            return Err(error);
        }
        let Some(AuthoritativeCommand::AdvanceManualDnsTask(stored)) = self.command()? else {
            return Ok(false);
        };
        Ok(stored == *transition)
    }

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
        if self.lose_reply.swap(false, Ordering::SeqCst) {
            return Err(ContractError::Unavailable);
        }
        Ok(receipt)
    }
}
