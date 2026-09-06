// SPDX-License-Identifier: GPL-2.0-only

//! A CA-side barrier interrupts a real client before consuming its checkpointed nonce.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use super::{Arc, AuthorityState, Error, Failure, Method, Mutex, TestAuthority};

pub(in super::super) struct AuthorizationInterruption {
    intercepted: AtomicBool,
    restored: AtomicBool,
    entered: Notify,
    released: Notify,
}

impl TestAuthority {
    pub(in super::super) fn interrupt_authorization(
        &self,
    ) -> Result<Arc<AuthorizationInterruption>, Box<dyn Error>> {
        let interruption = Arc::new(AuthorizationInterruption {
            intercepted: AtomicBool::new(false),
            restored: AtomicBool::new(false),
            entered: Notify::new(),
            released: Notify::new(),
        });
        self.state
            .lock()
            .map_err(|_| "CA mutex poisoned")?
            .interruption = Some(Arc::clone(&interruption));
        Ok(interruption)
    }
}

impl AuthorizationInterruption {
    pub(in super::super) async fn wait_until_intercepted(&self) -> Result<(), Box<dyn Error>> {
        tokio::time::timeout(super::super::WAIT_LIMIT, self.entered.notified()).await?;
        Ok(())
    }

    pub(in super::super) fn release_unprocessed_request(&self) {
        self.released.notify_one();
    }

    pub(in super::super) fn assert_restored(&self) -> Result<(), Box<dyn Error>> {
        if !self.intercepted.load(Ordering::SeqCst) || !self.restored.load(Ordering::SeqCst) {
            return Err("replacement did not restore challenge visibility before polling".into());
        }
        Ok(())
    }
}

pub(super) async fn before_request(
    state: &Mutex<AuthorityState>,
    method: &Method,
    route: &str,
) -> Result<bool, Failure> {
    let evidence = {
        let state = state.lock().map_err(|_| "CA mutex poisoned")?;
        if *method != Method::POST || route != "/authorization" || !state.validated {
            return Ok(false);
        }
        state.interruption.as_ref().map(|interruption| {
            (
                Arc::clone(interruption),
                state.validation_target,
                state.thumbprint.clone(),
            )
        })
    };
    let Some((interruption, target, thumbprint)) = evidence else {
        return Ok(false);
    };
    if !interruption.intercepted.swap(true, Ordering::SeqCst) {
        interruption.entered.notify_one();
        interruption.released.notified().await;
        return Ok(true);
    }
    // Independently re-probe the actual restarted listener before accepting its next request.
    target
        .validate(&format!(
            "{}.{}",
            super::TOKEN,
            thumbprint.ok_or("account missing")?
        ))
        .await?;
    interruption.restored.store(true, Ordering::SeqCst);
    Ok(false)
}
