// SPDX-License-Identifier: GPL-2.0-only

//! Response-time authority and cancellation, without sleeps or global clock changes.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use super::*;

#[tokio::test]
async fn successful_response_checkpoints_at_receipt_time() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = RecordingAuthority::default();
    let clock = SharedClock::new(20_000_000);
    let mut execution = execution(clock.clone(), 20_500_000)?;
    let outcome = driver(authority.clone(), 1, clock)?
        .drive(&mut execution)
        .await?;

    assert_eq!(outcome, CertificateOrderDriveOutcome::Yielded { steps: 1 });
    assert_eq!(authority.checkpoint_at(), Some(UnixMicros::new(20_500_000)));
    Ok(())
}

#[tokio::test]
async fn response_at_request_deadline_is_retried_without_checkpointing()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let clock = SharedClock::new(20_000_000);
    let mut execution = execution(clock.clone(), 21_000_000)?;
    let outcome = driver(authority.clone(), 1, clock)?
        .drive(&mut execution)
        .await?;

    assert!(matches!(
        outcome,
        CertificateOrderDriveOutcome::Retried {
            failure_class: CertificateOrderFailureClass::Transport,
            ..
        }
    ));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    assert!(matches!(
        execution.machine().action()?,
        meshspan_acme::AcmeMachineAction::DiscoverDirectory { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn response_after_claim_expiry_cannot_write_or_stop_the_worker()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let clock = SharedClock::new(20_000_000);
    let mut execution = execution(clock.clone(), 120_000_000)?;
    let outcome = driver(authority.clone(), 1, clock)?
        .drive(&mut execution)
        .await;

    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 0);
    assert_eq!(outcome?, CertificateOrderDriveOutcome::ClaimExpired);
    Ok(())
}

#[tokio::test]
async fn expired_claim_is_released_before_any_remote_step() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = RecordingAuthority::default();
    let clock = SharedClock::new(120_000_000);
    // If called, this transport would roll the test clock back: it must remain unused.
    let mut execution = execution(clock.clone(), 20_500_000)?;
    let outcome = driver(authority.clone(), 1, clock.clone())?
        .drive(&mut execution)
        .await;

    assert_eq!(outcome?, CertificateOrderDriveOutcome::ClaimExpired);
    assert_eq!(clock.now(), UnixMicros::new(120_000_000));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 0);
    Ok(())
}

#[tokio::test]
async fn claim_expiring_between_admission_and_execution_is_released()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let mut execution = CertificateOrderExecution::new(
        prepared()?,
        DirectoryTransport::available()?,
        Http01Challenge::new(),
    );
    let outcome = driver(
        authority.clone(),
        1,
        AdvancingClock(AtomicI64::new(119_999_998)),
    )?
    .drive(&mut execution)
    .await?;

    assert_eq!(outcome, CertificateOrderDriveOutcome::ClaimExpired);
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 0);
    assert!(matches!(
        execution.machine().action()?,
        meshspan_acme::AcmeMachineAction::DiscoverDirectory { .. }
    ));
    Ok(())
}

struct AdvancingClock(AtomicI64);

impl Clock for AdvancingClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.fetch_add(2, Ordering::SeqCst))
    }
}

#[tokio::test]
async fn last_claim_microsecond_waits_without_starting_an_invalid_request()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let clock = SharedClock::new(119_999_999);
    let mut execution = execution(clock.clone(), 20_500_000)?;
    let outcome = driver(authority.clone(), 1, clock.clone())?
        .drive(&mut execution)
        .await?;

    assert_eq!(outcome, CertificateOrderDriveOutcome::Pending);
    assert_eq!(clock.now(), UnixMicros::new(119_999_999));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 0);
    Ok(())
}

#[tokio::test]
async fn unresponsive_transport_is_cancelled_at_the_owned_request_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::default();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut execution = CertificateOrderExecution::new(
        prepared()?,
        NeverResponds(Arc::clone(&cancelled)),
        Http01Challenge::new(),
    );
    let mut worker = driver_with_policy(
        authority.clone(),
        FixedClock(UnixMicros::new(20_000_000)),
        CertificateOrderDrivePolicy::new(
            DurationMicros::new(10_000),
            DurationMicros::new(20_000),
            1,
        )?,
    )?;
    // This outer bound only detects a stuck test. The independently configured worker owns
    // the 10ms cancellation; OS scheduling latency is not a throughput assertion here.
    let outcome = tokio::time::timeout(Duration::from_secs(2), worker.drive(&mut execution)).await;

    assert!(outcome.is_ok(), "worker ignored its own 10ms deadline");
    assert!(matches!(
        outcome??,
        CertificateOrderDriveOutcome::Retried {
            failure_class: CertificateOrderFailureClass::Transport,
            ..
        }
    ));
    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    Ok(())
}

fn execution(
    clock: SharedClock,
    observed_at: i64,
) -> Result<
    CertificateOrderExecution<ClockAdvancingResponse, Http01Challenge>,
    Box<dyn std::error::Error>,
> {
    Ok(CertificateOrderExecution::new(
        prepared()?,
        ClockAdvancingResponse {
            clock,
            observed_at,
            response: DirectoryTransport::available()?,
        },
        Http01Challenge::new(),
    ))
}

#[derive(Clone)]
struct SharedClock(Arc<AtomicI64>);

impl SharedClock {
    fn new(now: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now)))
    }
}

impl Clock for SharedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.load(Ordering::SeqCst))
    }
}

struct ClockAdvancingResponse {
    clock: SharedClock,
    observed_at: i64,
    response: DirectoryTransport,
}

impl AcmeTransport for ClockAdvancingResponse {
    async fn send(
        &mut self,
        request: &AcmeTransportRequest,
    ) -> Result<AcmeHttpResponse, AcmeTransportError> {
        tokio::task::yield_now().await;
        self.clock.0.store(self.observed_at, Ordering::SeqCst);
        self.response.send(request).await
    }
}

struct NeverResponds(Arc<AtomicBool>);

impl AcmeTransport for NeverResponds {
    async fn send(
        &mut self,
        _request: &AcmeTransportRequest,
    ) -> Result<AcmeHttpResponse, AcmeTransportError> {
        let _cancellation = CancellationObserved(Arc::clone(&self.0));
        std::future::pending().await
    }
}

struct CancellationObserved(Arc<AtomicBool>);

impl Drop for CancellationObserved {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
