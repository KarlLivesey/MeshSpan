// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use quinn::Runtime as _;

#[tokio::test]
async fn exhausted_driver_admission_retains_owned_job_and_reports_rejection() {
    let owner = Drivers {
        admission: Mutex::new(Admission::Preparing(Vec::new())),
        drain: tokio::sync::Mutex::new(Drain::Pending),
        failures: AtomicU64::new(0),
        maximum: 1,
    };
    owner.start();
    let (release, blocked) = tokio::sync::oneshot::channel::<()>();
    owner.spawn(Box::pin(async move {
        assert!(blocked.await.is_ok());
    }));
    let (rejected, rejection) = tokio::sync::oneshot::channel::<()>();
    owner.spawn(Box::pin(async move {
        assert!(rejected.send(()).is_ok());
    }));
    assert!(
        rejection.await.is_err(),
        "over-capacity driver must not run"
    );
    assert_eq!(owner.failures.load(Ordering::Acquire), 1);
    assert!(matches!(&*owner.admission(), Admission::Running(jobs) if jobs.len() == 1));
    assert!(release.send(()).is_ok());
    assert_eq!(owner.shutdown().await, Err(()));
    assert_eq!(owner.shutdown().await, Err(()));
}

#[tokio::test]
#[expect(
    clippy::panic,
    reason = "Proves an owned Quinn driver panic remains a terminal shutdown failure"
)]
async fn driver_panic_is_observed_and_preserved_for_all_waiters() {
    let owner = Drivers::prepare();
    owner.start();
    let (panicking, started) = tokio::sync::oneshot::channel::<()>();
    owner.spawn(Box::pin(async move {
        assert!(panicking.send(()).is_ok());
        panic!("injected driver failure");
    }));
    assert!(started.await.is_ok());
    assert_eq!(owner.shutdown().await, Err(()));
    assert_eq!(owner.shutdown().await, Err(()));
    assert_eq!(owner.failures.load(Ordering::Acquire), 1);
}
