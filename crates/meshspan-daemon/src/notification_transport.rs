// SPDX-License-Identifier: GPL-2.0-only

//! Bounded in-process notification delivery. The outbox worker owns authority and retries.

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{HeaderValue, Request, Uri},
};
use hyper_util::rt::TokioIo;
use meshspan_api_contract::{NotificationDestination, decode_notification_destination};
use meshspan_metadata::{
    NotificationDeliveryOutcome, NotificationDeliveryRecord, NotificationDeliveryState,
    NotificationEventKind,
};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

/// In-process HTTPS and SMTP transport using explicit, certificate-verifying TLS trust.
///
/// This is not an authorisation service. Its caller must hold the current durable delivery
/// claim, verify the current channel configuration and decrypt its exact settings generation.
pub struct NotificationTransport {
    pub(crate) tls: Arc<ClientConfig>,
}

impl NotificationTransport {
    /// Injects the trust roots used to verify explicitly configured notification receivers.
    #[must_use]
    pub const fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// Makes one attempt within 35 seconds, without retrying or following redirects internally.
    ///
    /// Acceptance means the remote endpoint accepted it, not exactly-once execution or inbox
    /// arrival. Ambiguous results retain the delivery ID for the outbox's next attempt.
    pub async fn deliver(
        &self,
        destination: &NotificationDestination,
        delivery: &NotificationDeliveryRecord,
    ) -> NotificationDeliveryOutcome {
        let settings = match serde_json::to_vec(destination) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return NotificationDeliveryOutcome::Rejected,
        };
        if decode_notification_destination(&settings).is_err()
            || delivery.state != NotificationDeliveryState::Claimed
            || delivery.claim.is_none()
            || delivery.attempt == 0
            || !(0..=253_402_300_799_999_999).contains(&delivery.occurred_at.get())
        {
            return NotificationDeliveryOutcome::Rejected;
        }
        let attempt = async {
            match destination {
                NotificationDestination::Webhook {
                    endpoint,
                    bearer_token,
                } => self.webhook(endpoint, bearer_token, delivery).await,
                NotificationDestination::Email { .. } => {
                    crate::notification_smtp::send(self, destination, delivery).await
                }
            }
        };
        match tokio::time::timeout(Duration::from_secs(35), attempt).await {
            Ok(Ok(())) => NotificationDeliveryOutcome::Accepted,
            Ok(Err(DeliveryError::Rejected)) => NotificationDeliveryOutcome::Rejected,
            Ok(Err(DeliveryError::Retry)) | Err(_) => NotificationDeliveryOutcome::Retry,
        }
    }

    async fn webhook(
        &self,
        endpoint: &str,
        token: &str,
        delivery: &NotificationDeliveryRecord,
    ) -> Result<(), DeliveryError> {
        let uri: Uri = endpoint.parse().map_err(|_| DeliveryError::Rejected)?;
        let authority = uri.authority().ok_or(DeliveryError::Rejected)?;
        if uri.scheme_str() != Some("https")
            || authority.as_str().contains('@')
            || endpoint.contains('#')
            || authority.port_u16() == Some(0)
        {
            return Err(DeliveryError::Rejected);
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let tcp = TcpStream::connect((host, authority.port_u16().unwrap_or(443)))
            .await
            .map_err(|_| DeliveryError::Retry)?;
        let mut config = (*self.tls).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from(host.to_owned()).map_err(|_| DeliveryError::Rejected)?,
                tcp,
            )
            .await
            .map_err(|_| DeliveryError::Retry)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_headers(32)
            .max_buf_size(16 * 1024)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| DeliveryError::Retry)?;
        let auth = Zeroizing::new(format!("Bearer {token}"));
        let mut auth = HeaderValue::from_str(&auth).map_err(|_| DeliveryError::Rejected)?;
        auth.set_sensitive(true);
        let request = Request::builder()
            .method("POST")
            .uri(uri.path_and_query().map_or("/", |value| value.as_str()))
            .header("Host", authority.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", auth)
            .header("Connection", "close")
            .header(
                "Idempotency-Key",
                crate::create_mesh_setup::format_uuid(delivery.delivery_id.as_bytes()),
            )
            .body(Body::from(event_json(delivery)?))
            .map_err(|_| DeliveryError::Rejected)?;
        // Drive the connection in this owned future. Cancellation drops both halves; no detached
        // connection task survives a timeout, shutdown or failed notification.
        tokio::pin!(connection);
        let response = sender.send_request(request);
        tokio::pin!(response);
        let response = tokio::select! {
            biased;
            response = &mut response => response,
            // Connection: close may finish the driver in the same poll that delivers the
            // response to the request future. Consume that result before deciding it was lost.
            _result = &mut connection => response.await,
        }
        .map_err(|_| DeliveryError::Retry)?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            408 | 425 | 429 | 500..=599 => Err(DeliveryError::Retry),
            _ => Err(DeliveryError::Rejected),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeliveryError {
    Retry,
    Rejected,
}

pub(crate) fn event_json(delivery: &NotificationDeliveryRecord) -> Result<Vec<u8>, DeliveryError> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "delivery_id": crate::create_mesh_setup::format_uuid(delivery.delivery_id.as_bytes()),
        "event_id": crate::create_mesh_setup::format_uuid(delivery.event_id.as_bytes()),
        "kind": event_name(delivery.event_kind),
        "occurred_at_epoch_micros": delivery.occurred_at.get().to_string(),
    }))
    .map_err(|_| DeliveryError::Rejected)
}

pub(crate) const fn event_name(kind: NotificationEventKind) -> &'static str {
    match kind {
        NotificationEventKind::CertificateOrderQueued => "certificate_order_queued",
        NotificationEventKind::CertificateOrderCompleted => "certificate_order_completed",
        NotificationEventKind::ManualDnsTaskChanged => "manual_dns_task_changed",
        NotificationEventKind::BackupRunCompleted => "backup_run_completed",
    }
}
