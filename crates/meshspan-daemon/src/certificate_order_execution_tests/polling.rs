// SPDX-License-Identifier: GPL-2.0-only

use meshspan_acme::{AcmeDirectory, AcmeMachineEvent, AcmeOrder, AcmeResourceStatus};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use super::*;

const SECOND: i64 = 1_000_000;

#[tokio::test]
async fn successful_poll_hint_prevents_an_immediate_second_request()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = processing_order()?;
    let transport = OneResponseTransport(Some(processing_response("120")?));
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let mut execution = CertificateOrderExecution::new(prepared, transport, Http01Challenge::new());
    let actor = PrincipalId::from_bytes([2; 16])?;
    let context = poll_context(50)?;
    assert!(matches!(
        execution
            .execute_step(
                &checkpoint,
                actor,
                &FixedClock(UnixMicros::new(20 * SECOND)),
                context,
                UnixMicros::new(400 * SECOND)
            )
            .await?,
        CertificateOrderStepResult::Checkpointed(_)
    ));
    // The single response has been consumed. A second remote request would fail the test.
    assert_eq!(
        execution
            .execute_step(
                &checkpoint,
                actor,
                &FixedClock(UnixMicros::new(21 * SECOND)),
                context,
                UnixMicros::new(400 * SECOND)
            )
            .await?,
        CertificateOrderStepResult::Pending
    );
    assert_eq!(authority.commit_count()?, 1);
    assert_eq!(
        execution.machine().poll_not_before(),
        Some(UnixMicros::new(140 * SECOND))
    );
    Ok(())
}

#[tokio::test]
async fn checkpoint_restart_and_worker_replacement_preserve_the_receipt_time_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = AdjustableClock(Arc::new(AtomicI64::new(20 * SECOND)));
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = TimedTransport {
        clock: Arc::clone(&clock.0),
        calls: Arc::clone(&calls),
        responses: VecDeque::from([(21 * SECOND, processing_response("120")?)]),
    };
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let actor = PrincipalId::from_bytes([2; 16])?;
    let mut execution =
        CertificateOrderExecution::new(processing_order()?, transport, Http01Challenge::new());
    execution
        .execute_step(
            &checkpoint,
            actor,
            &clock,
            poll_context(50)?,
            UnixMicros::new(400 * SECOND),
        )
        .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let bytes = authority
        .state
        .lock()
        .map_err(|_| "checkpoint lock")?
        .last()
        .ok_or("missing checkpoint")?
        .1
        .clone();
    drop(execution);

    let mut replacement = processing_order()?;
    replacement.machine = AcmeOrderMachine::decode_checkpoint(&bytes)?;
    assert_eq!(
        replacement.machine.poll_not_before(),
        Some(UnixMicros::new(141 * SECOND))
    );
    replacement.machine.resume_under_fence(66)?;
    let claim = replacement
        .assignment
        .order
        .claim
        .as_mut()
        .ok_or("missing claim")?;
    claim.fence = 66;
    claim.generation = 2;
    let transport = TimedTransport {
        clock: Arc::clone(&clock.0),
        calls: Arc::clone(&calls),
        responses: VecDeque::from([(141 * SECOND, processing_response("0")?)]),
    };
    let mut execution =
        CertificateOrderExecution::new(replacement, transport, Http01Challenge::new());
    for instant in [22 * SECOND, 140 * SECOND, 141 * SECOND - 1] {
        clock.0.store(instant, Ordering::SeqCst);
        assert_eq!(
            execution
                .execute_step(
                    &checkpoint,
                    actor,
                    &clock,
                    poll_context(150)?,
                    UnixMicros::new(400 * SECOND)
                )
                .await?,
            CertificateOrderStepResult::Pending
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(authority.commit_count()?, 1);
    clock.0.store(141 * SECOND, Ordering::SeqCst);
    assert!(matches!(
        execution
            .execute_step(
                &checkpoint,
                actor,
                &clock,
                poll_context(150)?,
                UnixMicros::new(400 * SECOND)
            )
            .await?,
        CertificateOrderStepResult::Checkpointed(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(authority.commit_count()?, 2);
    assert_eq!(execution.machine().poll_not_before(), None);
    Ok(())
}

#[tokio::test]
async fn malformed_successful_retry_hint_does_not_advance_or_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = processing_order()?;
    let original = prepared.machine.encode_checkpoint()?;
    let mut execution = CertificateOrderExecution::new(
        prepared,
        OneResponseTransport(Some(processing_response("-1")?)),
        Http01Challenge::new(),
    );
    let authority = RecordingCheckpointAuthority::default();
    let outcome = execution
        .execute_step(
            &CertificateOrderCheckpointService::new(&authority),
            PrincipalId::from_bytes([2; 16])?,
            &FixedClock(UnixMicros::new(20 * SECOND)),
            poll_context(50)?,
            UnixMicros::new(400 * SECOND),
        )
        .await;
    assert!(matches!(
        outcome,
        Err(crate::CertificateOrderExecutionError::Worker(
            meshspan_acme::AcmeWorkerError::Protocol
        ))
    ));
    assert_eq!(authority.commit_count()?, 0);
    assert_eq!(execution.machine().encode_checkpoint()?, original);
    Ok(())
}

struct AdjustableClock(Arc<AtomicI64>);

impl meshspan_domain::Clock for AdjustableClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.load(Ordering::SeqCst))
    }
}

struct TimedTransport {
    clock: Arc<AtomicI64>,
    calls: Arc<AtomicUsize>,
    responses: VecDeque<(i64, AcmeHttpResponse)>,
}

impl AcmeTransport for TimedTransport {
    fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self
            .responses
            .pop_front()
            .ok_or(AcmeTransportError::Unavailable)
            .map(|(received_at, response)| {
                self.clock.store(received_at, Ordering::SeqCst);
                response
            });
        std::future::ready(result)
    }
}

fn processing_order() -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
    let mut value = prepared(CertificateOrderId::from_bytes([1; 16])?)?;
    value
        .assignment
        .order
        .claim
        .as_mut()
        .ok_or("missing claim")?
        .lease_expires_at = UnixMicros::new(500 * SECOND);
    value
        .machine
        .advance(AcmeMachineEvent::DirectoryDiscovered(AcmeDirectory {
            new_nonce: "https://ca.example.test/nonce".to_owned(),
            new_account: "https://ca.example.test/account".to_owned(),
            new_order: "https://ca.example.test/new-order".to_owned(),
        }))?;
    value
        .machine
        .advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    value.machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce_2".to_owned(),
    })?;
    value.machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        replay_nonce: "nonce_3".to_owned(),
        order: AcmeOrder {
            status: AcmeResourceStatus::Processing,
            dns_names: value.assignment.configuration.certificate_names.clone(),
            authorizations: vec!["https://ca.example.test/authorization/1".to_owned()],
            finalize: "https://ca.example.test/finalize/1".to_owned(),
            certificate: None,
        },
    })?;
    Ok(value)
}

fn processing_response(retry_after: &str) -> Result<AcmeHttpResponse, Box<dyn std::error::Error>> {
    Ok(AcmeHttpResponse::new(200, AcmeResponseHeaders::new(vec![
        ("replay-nonce".to_owned(), "nonce_4".to_owned()),
        ("retry-after".to_owned(), retry_after.to_owned()),
    ])?, br#"{"status":"processing","identifiers":[{"type":"dns","value":"files.example.test"}],"authorizations":["https://ca.example.test/authorization/1"],"finalize":"https://ca.example.test/finalize/1"}"#.to_vec())?)
}

fn poll_context(deadline_seconds: i64) -> Result<RequestContext, Box<dyn std::error::Error>> {
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(deadline_seconds * SECOND);
    Ok(context)
}
