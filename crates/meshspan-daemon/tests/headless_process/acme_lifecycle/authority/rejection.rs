// SPDX-License-Identifier: GPL-2.0-only

//! A terminal first authorisation and an independently identified replacement order.

use super::{
    AuthorityState, Duration, Error, Failure, Instant, Method, Mutex, TOKEN, TestAuthority,
};
use crate::acme_lifecycle::challenge::REPLACEMENT_TOKEN;

pub(super) struct OrderRejection {
    rejected_at: Option<Instant>,
    cleanup_observed: bool,
}

impl TestAuthority {
    pub(in super::super) fn reject_first_authorization(&self) -> Result<(), Box<dyn Error>> {
        self.state
            .lock()
            .map_err(|_| "CA mutex poisoned")?
            .rejection = Some(OrderRejection {
            rejected_at: None,
            cleanup_observed: false,
        });
        Ok(())
    }

    pub(in super::super) fn expects_replacement(&self) -> Result<bool, Box<dyn Error>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "CA mutex poisoned")?
            .rejection
            .is_some())
    }

    pub(in super::super) async fn assert_rejected_challenge_removed(
        &self,
    ) -> Result<(), Box<dyn Error>> {
        let (target, authorization) = {
            let state = self.state.lock().map_err(|_| "CA mutex poisoned")?;
            if state
                .rejection
                .as_ref()
                .and_then(|value| value.rejected_at)
                .is_none()
                || state.orders != 1
            {
                return Err("expected exactly one rejected order before restart".into());
            }
            (
                state.validation_target,
                format!(
                    "{TOKEN}.{}",
                    state.thumbprint.as_ref().ok_or("account missing")?
                ),
            )
        };
        target
            .assert_removed(&authorization)
            .await
            .map_err(|error| error.to_string().into())
    }
}

impl AuthorityState {
    pub(super) fn token(&self) -> &'static str {
        if self.orders <= 1 {
            TOKEN
        } else {
            REPLACEMENT_TOKEN
        }
    }

    pub(super) fn resource_url(&self, resource: &str) -> String {
        if self.orders <= 1 {
            format!("{}{resource}", self.endpoint)
        } else {
            format!("{}{resource}/{}", self.endpoint, self.orders)
        }
    }

    pub(super) fn resource(&self, route: &str) -> Result<&'static str, Failure> {
        for resource in ["/directory", "/nonce", "/account", "/new-order"] {
            if route == resource {
                return Ok(resource);
            }
        }
        for resource in [
            "/order",
            "/authorization",
            "/challenge",
            "/finalize",
            "/certificate",
        ] {
            let expected = if self.orders <= 1 {
                resource.to_owned()
            } else {
                format!("{resource}/{}", self.orders)
            };
            if route == expected {
                return Ok(resource);
            }
        }
        Err("unknown or superseded ACME resource".into())
    }

    pub(super) fn is_rejected(&self) -> bool {
        self.orders == 1 && self.validated && self.rejection.is_some()
    }

    pub(super) fn record_rejection(&mut self) -> Result<(), Failure> {
        if self.is_rejected() {
            let rejection = self.rejection.as_mut().ok_or("missing rejection plan")?;
            if rejection.rejected_at.is_none() {
                rejection.rejected_at = Some(Instant::now());
            }
        }
        Ok(())
    }
}

pub(super) async fn before_new_order(
    state: &Mutex<AuthorityState>,
    method: &Method,
    route: &str,
) -> Result<(), Failure> {
    if *method != Method::POST || route != "/new-order" {
        return Ok(());
    }
    let (target, authorization) = {
        let state = state.lock().map_err(|_| "CA mutex poisoned")?;
        if state.orders == 0 {
            return Ok(());
        }
        let rejection = state
            .rejection
            .as_ref()
            .ok_or("unexpected additional CA order")?;
        let rejected_at = rejection
            .rejected_at
            .ok_or("replacement preceded rejection")?;
        if state.orders != 1 || rejected_at.elapsed() < Duration::from_mins(5) {
            return Err(
                "replacement bypassed the real production backoff or duplicated an order".into(),
            );
        }
        (
            state.validation_target,
            format!(
                "{TOKEN}.{}",
                state.thumbprint.as_ref().ok_or("account missing")?
            ),
        )
    };
    target.assert_removed(&authorization).await?;
    state
        .lock()
        .map_err(|_| "CA mutex poisoned")?
        .rejection
        .as_mut()
        .ok_or("missing rejection plan")?
        .cleanup_observed = true;
    Ok(())
}

impl OrderRejection {
    pub(super) const fn is_complete(&self) -> bool {
        self.rejected_at.is_some() && self.cleanup_observed
    }
}
