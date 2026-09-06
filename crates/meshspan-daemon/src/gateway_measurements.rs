// SPDX-License-Identifier: GPL-2.0-only

//! Dispatch lifecycle instrumentation, separate from protocol and file-operation authority.

use std::sync::Arc;
use std::time::Instant;

use axum::{Router, extract::Request, extract::State, middleware::Next, response::Response};
use meshspan_contracts::{
    GatewayDispatchObservation, GatewayDispatchObserver, GatewayDispatchOutcome, GatewayProtocol,
};

use crate::{SmbConnectionHandler, SmbHandlerFuture};

pub(crate) fn observe_https(router: Router, observer: Arc<dyn GatewayDispatchObserver>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        observer,
        https_dispatch,
    ))
}

async fn https_dispatch(
    State(observer): State<Arc<dyn GatewayDispatchObserver>>,
    request: Request,
    next: Next,
) -> Response {
    let observation = DispatchLifetime::start(observer, GatewayProtocol::Https);
    let response = next.run(request).await;
    observation.finish(if response.status().is_server_error() {
        GatewayDispatchOutcome::Failed
    } else {
        GatewayDispatchOutcome::Returned
    });
    response
}

pub(crate) struct ObservedSmbHandler<Handler> {
    handler: Handler,
    observer: Arc<dyn GatewayDispatchObserver>,
}

impl<Handler> ObservedSmbHandler<Handler> {
    pub(crate) fn new(handler: Handler, observer: Arc<dyn GatewayDispatchObserver>) -> Self {
        Self { handler, observer }
    }
}

impl<Handler: SmbConnectionHandler> SmbConnectionHandler for ObservedSmbHandler<Handler> {
    type Error = Handler::Error;

    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        Box::pin(async move {
            let observation =
                DispatchLifetime::start(Arc::clone(&self.observer), GatewayProtocol::Smb);
            let result = self.handler.handle(request).await;
            observation.finish(if result.is_err() {
                GatewayDispatchOutcome::Failed
            } else {
                GatewayDispatchOutcome::Returned
            });
            result
        })
    }
}

struct DispatchLifetime {
    observer: Arc<dyn GatewayDispatchObserver>,
    protocol: GatewayProtocol,
    started: Instant,
    outcome: GatewayDispatchOutcome,
}

impl DispatchLifetime {
    fn start(observer: Arc<dyn GatewayDispatchObserver>, protocol: GatewayProtocol) -> Self {
        Self {
            observer,
            protocol,
            started: Instant::now(),
            outcome: GatewayDispatchOutcome::Cancelled,
        }
    }

    fn finish(mut self, outcome: GatewayDispatchOutcome) {
        self.outcome = outcome;
    }
}

impl Drop for DispatchLifetime {
    fn drop(&mut self) {
        self.observer.observe_dispatch(GatewayDispatchObservation {
            protocol: self.protocol,
            outcome: self.outcome,
            duration: self.started.elapsed(),
        });
    }
}

#[cfg(test)]
#[path = "gateway_measurements_tests.rs"]
mod tests;
