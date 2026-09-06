// SPDX-License-Identifier: GPL-2.0-only

use std::{
    collections::BTreeMap,
    error::Error,
    future::Future,
    sync::{Arc, Mutex},
};

use meshspan_contracts::{
    BoundedBytes, CertificateChallenge, CertificateChallengeCleanup, CertificateChallengeKind,
    CertificateChallengeRequest, ContractError, ContractVersion, RequestContext,
};
use meshspan_domain::{OperationId, Revision, UnixMicros};

use crate::{
    AcmeAccountKey, AcmeChallengeExecution, AcmeChallengeRecord, AcmeHttpResponse,
    AcmeMachineAction, AcmeMachineEvent, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport,
    AcmeTransportError, AcmeTransportRequest, AuthoritativeTxtObserver, Dns01Payload,
    ManualDns01Challenge, ManualDnsTask, ManualDnsTaskAuthority, ManualDnsTaskPhase,
};

type Tasks = Arc<Mutex<BTreeMap<[u8; 32], ManualDnsTask>>>;
type Records = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

#[tokio::test]
async fn executor_waits_for_manual_removal_and_resumes_after_provider_restart()
-> Result<(), Box<dyn Error>> {
    let tasks = Tasks::default();
    let records = Records::default();
    let mut executor = AcmeStepExecutor::new(
        NoCaRequests,
        AcmeAccountKey::from_secret_bytes(&[1; 32])?,
        challenge(tasks.clone(), records.clone()),
    );
    let selected = AcmeChallengeRecord {
        kind: "dns-01".to_owned(),
        url: "https://ca.example.test/challenge/1".to_owned(),
        token: "token_dns".to_owned(),
        status: crate::AcmeResourceStatus::Pending,
    };
    let publish = AcmeMachineAction::PublishChallenge {
        dns_name: "files.example.test".to_owned(),
        wildcard: false,
        challenge: selected.clone(),
        order_epoch: 9,
    };
    let execution = AcmeChallengeExecution {
        publication: None,
        context: request()?.context,
        challenge_expires_at: UnixMicros::new(200),
        csr_der: &[],
    };
    assert_eq!(
        executor.execute(&publish, execution).await?,
        AcmeStepOutcome::Pending
    );
    let task = only_task(&tasks)?;
    records
        .lock()
        .map_err(|_| "record lock failed")?
        .insert(task.record_name, task.record_value);
    let AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengePublished { publication_digest }) =
        executor.execute(&publish, execution).await?
    else {
        return Err("observed publication must advance".into());
    };
    let cleanup = AcmeMachineAction::CleanupChallenge {
        dns_name: "files.example.test".to_owned(),
        wildcard: false,
        challenge: selected,
        publication_digest,
        order_epoch: 9,
    };
    let mut removal = execution;
    removal.context.deadline = UnixMicros::new(300);
    assert_eq!(
        executor.execute(&cleanup, removal).await?,
        AcmeStepOutcome::Pending
    );
    assert_eq!(
        only_task(&tasks)?.phase,
        ManualDnsTaskPhase::AwaitingRemoval
    );
    let (transport, signer, old_provider) = executor.into_parts();
    drop(old_provider);
    let mut recovered =
        AcmeStepExecutor::new(transport, signer, challenge(tasks.clone(), records.clone()));
    assert_eq!(
        recovered.execute(&cleanup, removal).await?,
        AcmeStepOutcome::Pending
    );
    records.lock().map_err(|_| "record lock failed")?.clear();
    assert_eq!(
        recovered.execute(&cleanup, removal).await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengeCleaned)
    );
    assert_eq!(
        recovered.execute(&cleanup, removal).await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengeCleaned)
    );
    assert_eq!(only_task(&tasks)?.phase, ManualDnsTaskPhase::Complete);
    Ok(())
}

struct NoCaRequests;

impl AcmeTransport for NoCaRequests {
    fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send {
        std::future::ready(Err(AcmeTransportError::Unavailable))
    }
}

#[tokio::test]
async fn task_survives_restart_and_advances_through_exact_dns_observation()
-> Result<(), Box<dyn Error>> {
    let tasks = Tasks::default();
    let records = Records::default();
    let request = request()?;
    let mut first = challenge(tasks.clone(), records.clone());
    let receipt = first.publish(&request).await?;
    assert_phase(&tasks, ManualDnsTaskPhase::AwaitingPublication)?;
    assert!(!first.is_visible(&request, receipt).await?);
    records.lock().map_err(|_| "record lock failed")?.insert(
        "_acme-challenge.files.example.test".to_owned(),
        b"txt-value".to_vec(),
    );
    assert!(first.is_visible(&request, receipt).await?);
    assert_phase(&tasks, ManualDnsTaskPhase::PublicationObserved)?;
    drop(first);

    let mut recovered = challenge(tasks.clone(), records.clone());
    assert_eq!(recovered.publish(&request).await?, receipt);
    assert_phase(&tasks, ManualDnsTaskPhase::PublicationObserved)?;
    let mut cleanup = request.clone();
    cleanup.context.deadline = UnixMicros::new(300);
    assert_eq!(
        recovered.cleanup(&cleanup, receipt).await?,
        CertificateChallengeCleanup::Pending
    );
    assert_phase(&tasks, ManualDnsTaskPhase::AwaitingRemoval)?;
    records.lock().map_err(|_| "record lock failed")?.clear();
    assert_eq!(
        recovered.cleanup(&cleanup, receipt).await?,
        CertificateChallengeCleanup::Complete
    );
    assert_phase(&tasks, ManualDnsTaskPhase::Complete)?;
    Ok(())
}

fn challenge(
    tasks: Tasks,
    records: Records,
) -> ManualDns01Challenge<MemoryAuthority, MemoryObserver> {
    ManualDns01Challenge::new(MemoryAuthority(tasks), MemoryObserver(records))
}

fn request() -> Result<CertificateChallengeRequest, Box<dyn Error>> {
    let payload = Dns01Payload::new("_acme-challenge.files.example.test", b"txt-value")?;
    Ok(CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([1; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(3)),
        },
        kind: CertificateChallengeKind::Dns01,
        identifier: BoundedBytes::copy_from(b"files.example.test", 253)?,
        challenge: payload.encode()?,
        expires_at: UnixMicros::new(200),
        order_epoch: 9,
    })
}

fn assert_phase(tasks: &Tasks, expected: ManualDnsTaskPhase) -> Result<(), Box<dyn Error>> {
    let task = only_task(tasks)?;
    assert_eq!(task.phase, expected);
    assert_eq!(task.record_name, "_acme-challenge.files.example.test");
    assert_eq!(task.record_value, b"txt-value");
    assert_eq!(task.expires_at, UnixMicros::new(200));
    Ok(())
}

fn only_task(tasks: &Tasks) -> Result<ManualDnsTask, Box<dyn Error>> {
    let tasks = tasks.lock().map_err(|_| "task lock failed")?;
    assert_eq!(
        tasks.len(),
        1,
        "one publication must retain exactly one task"
    );
    tasks
        .values()
        .next()
        .cloned()
        .ok_or_else(|| "missing task".into())
}

struct MemoryAuthority(Tasks);

impl ManualDnsTaskAuthority for MemoryAuthority {
    fn advance(
        &self,
        task: &ManualDnsTask,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .and_then(|mut tasks| {
                if let Some(current) = tasks.get(&task.task_digest) {
                    if !same_task(current, task) {
                        return Err(ContractError::Conflict);
                    }
                    if current.phase >= task.phase {
                        return Ok(());
                    }
                }
                tasks.insert(task.task_digest, task.clone());
                Ok(())
            });
        std::future::ready(result)
    }
}

fn same_task(left: &ManualDnsTask, right: &ManualDnsTask) -> bool {
    left.task_digest == right.task_digest
        && left.record_name == right.record_name
        && left.record_value == right.record_value
        && left.expires_at == right.expires_at
        && left.order_epoch == right.order_epoch
}

struct MemoryObserver(Records);

impl AuthoritativeTxtObserver for MemoryObserver {
    fn contains_txt(
        &self,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<bool, ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .map(|records| records.get(name).is_some_and(|stored| stored == value));
        std::future::ready(result)
    }
}
