// SPDX-License-Identifier: GPL-2.0-only

use axum::{
    body::{Body, to_bytes},
    http::StatusCode,
    routing::get,
};
use meshspan_contracts::{RuntimeMetric, RuntimeMetricSource};
use std::future::{Future, pending, poll_fn};
use std::task::Poll;
use std::time::Duration;
use tower::ServiceExt;

use super::*;
use crate::runtime_observations::RuntimeObservations;

#[tokio::test]
async fn https_metrics_preserve_responses_and_distinguish_5xx_from_client_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let router = observe_https(
        Router::new()
            .route("/ok", get(|| async { "exact response bytes" }))
            .route("/failed", get(|| async { StatusCode::SERVICE_UNAVAILABLE })),
        Arc::new(observations.clone()),
    );
    for (uri, status, body) in [
        ("/ok", StatusCode::OK, "exact response bytes"),
        ("/failed", StatusCode::SERVICE_UNAVAILABLE, ""),
        ("/private-user-path", StatusCode::NOT_FOUND, ""),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", "Bearer should-never-be-a-metric")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), status);
        assert_eq!(
            to_bytes(response.into_body(), 1_024).await?.as_ref(),
            body.as_bytes()
        );
    }
    let metrics = observations.collect_metrics()?;
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsDispatches(3))
    );
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsServerErrors(1))
    );
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsCancelledDispatches(0))
    );
    let encoded = String::from_utf8(crate::encode_openmetrics(&metrics)?)?;
    assert!(encoded.contains("meshspan_v1_https_dispatch_duration_seconds_count 3\n"));
    for private in [
        "private-user-path",
        "should-never-be-a-metric",
        "exact response bytes",
    ] {
        assert!(!encoded.contains(private));
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_https_dispatch_records_one_cancellation_without_a_response()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let entered = Arc::new(tokio::sync::Notify::new());
    let notified = Arc::clone(&entered);
    let router = observe_https(
        Router::new().route(
            "/waiting",
            get(move || {
                let entered = Arc::clone(&notified);
                async move {
                    entered.notify_one();
                    pending::<StatusCode>().await
                }
            }),
        ),
        Arc::new(observations.clone()),
    );
    let task =
        tokio::spawn(router.oneshot(Request::builder().uri("/waiting").body(Body::empty())?));
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    task.abort();
    assert!(task.await.is_err_and(|error| error.is_cancelled()));
    let metrics = observations.collect_metrics()?;
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsDispatches(1))
    );
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsCancelledDispatches(1))
    );
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::HttpsServerErrors(0))
    );
    Ok(())
}

#[tokio::test]
async fn smb_metrics_preserve_payload_errors_and_no_response_and_observe_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let mut handler = ObservedSmbHandler::new(TestSmbHandler, Arc::new(observations.clone()));
    // An unpolled future never entered dispatch and must not count as a cancellation.
    drop(handler.handle(vec![4]));
    assert_eq!(handler.handle(vec![1, 7, 8]).await, Ok(Some(vec![1, 7, 8])));
    assert_eq!(handler.handle(vec![2]).await, Err(()));
    assert_eq!(handler.handle(vec![3]).await, Ok(None));
    {
        let future = handler.handle(vec![4]);
        tokio::pin!(future);
        assert!(poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await);
    }
    let metrics = observations.collect_metrics()?;
    assert!(metrics.samples().contains(&RuntimeMetric::SmbDispatches(4)));
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::SmbDispatchErrors(1))
    );
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::SmbCancelledDispatches(1))
    );
    assert!(metrics.samples().iter().any(|sample| matches!(sample,
        RuntimeMetric::SmbDispatchDuration(histogram) if histogram.count == 4)));
    Ok(())
}

struct TestSmbHandler;

impl SmbConnectionHandler for TestSmbHandler {
    type Error = ();
    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, ()> {
        Box::pin(async move {
            match request.first() {
                Some(2) => Err(()),
                Some(3) => Ok(None),
                Some(4) => pending().await,
                _ => Ok(Some(request)),
            }
        })
    }
}
