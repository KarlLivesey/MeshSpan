// SPDX-License-Identifier: GPL-2.0-only

//! Real public configuration, encrypted storage, remote delivery, restart and exact retries.

use super::{Error, ProcessFixture, request_with_headers, require_status, response_body};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use meshspan_certificates::CertificateAuthority;
use meshspan_daemon::{HttpsServer, HttpsServerError};
use meshspan_domain::{InitialBootstrapMaterial, WorkId};
use meshspan_metadata::{AuthoritativeRepository, NotificationDeliveryState, PartitionDatabase};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const CHANNEL: &str = "00000000-0000-4000-8000-000000000301";
const TOKEN: &str = "test-notification-token-0123456789";
const API: &str = "/api/latest/admin/notifications";

#[tokio::test]
async fn notification_channel_delivers_retries_after_restart_and_retains_credentials()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut receiver = Receiver::start().await?;
    let trust = root.temporary.path().join("notification-trust.pem");
    std::fs::write(&trust, &receiver.anchor)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust).spawn()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing bootstrap key")?;
        super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        super::wait_for_storage_folder_visibility(&root, &client, key).await?;
        let request = configuration(&receiver.endpoint);
        let first_receipt = configure(&root, &client, key, &request).await?;
        assert_eq!(first_receipt["sequence"], 1);
        let anonymous =
            request_with_headers(root.address, &client, "PUT", API, Some(b"not JSON"), &[]).await?;
        require_status(
            &anonymous,
            "401 Unauthorized",
            "authenticate before reading configuration body",
        )?;
        queue_certificate(&root, &client, key, &receiver.endpoint).await?;
        let first = receiver.receive().await?;
        assert_eq!(first["kind"], "certificate_order_queued");
        assert_eq!(first["version"], 1);
        assert_eq!(first.as_object().ok_or("event not an object")?.len(), 5);
        let delivery = WorkId::from_bytes(parse(
            first["delivery_id"].as_str().ok_or("delivery ID absent")?,
        )?)?;
        await_delivery(&root, delivery, NotificationDeliveryState::Queued, 1).await?;
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.command().env("SSL_CERT_FILE", &trust).spawn()?;
        super::wait_for_status(root.address, &client, "configured").await?;
        let second = receiver.receive().await?;
        assert_eq!(
            second, first,
            "retry preserves exact payload and delivery identity"
        );
        await_delivery(&root, delivery, NotificationDeliveryState::Accepted, 2).await?;
        let mut disable = request.clone();
        disable["operation_id"] = json!("00000000-0000-4000-8000-000000000303");
        disable["expected_sequence"] = json!(1);
        disable["enabled"] = json!(false);
        disable["settings"] = json!({"mode": "retain"});
        assert_eq!(
            configure(&root, &client, key, &disable).await?["sequence"],
            2
        );
        assert_eq!(
            configure(&root, &client, key, &request).await?,
            first_receipt
        );
        let status = request_with_headers(
            root.address,
            &client,
            "GET",
            API,
            None,
            &[("Authorization", &format!("Bearer {key}"))],
        )
        .await?;
        require_status(&status, "200 OK", "read redacted channel status")?;
        let text = response_body(&status)?;
        assert!(!text.contains(TOKEN));
        assert!(!text.contains(&receiver.endpoint));
        let status: Value = serde_json::from_str(text)?;
        assert_eq!(status["channels"][0]["enabled"], false);
        assert_eq!(status["channels"][0]["sequence"], 2);
        let mut changed = request;
        changed["settings"]["destination"]["bearer_token"] = json!("changed-test-token-0123456789");
        let body = serde_json::to_vec(&changed)?;
        let rejected = request_with_headers(
            root.address,
            &client,
            "PUT",
            API,
            Some(&body),
            &[("Authorization", &format!("Bearer {key}"))],
        )
        .await?;
        require_status(&rejected, "409 Conflict", "reject changed private retry")?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::stop_processes(&mut processes);
    let stopped = receiver.stop().await;
    super::retain_failure_state(proof, [root.temporary])?;
    stopped
}

fn configuration(endpoint: &str) -> Value {
    json!({ "operation_id": "00000000-0000-4000-8000-000000000302", "channel_id": CHANNEL,
        "expected_sequence": 0, "display_name": "Operator alerts", "enabled": true, "event_filter": 1,
        "settings": { "mode": "replace", "destination": { "kind": "webhook", "endpoint": endpoint, "bearer_token": TOKEN } } })
}

async fn configure(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    request: &Value,
) -> Result<Value, Box<dyn Error>> {
    let body = serde_json::to_vec(request)?;
    let response = request_with_headers(
        root.address,
        client,
        "PUT",
        API,
        Some(&body),
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    require_status(&response, "200 OK", "commit notification configuration")?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

async fn queue_certificate(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    endpoint: &str,
) -> Result<(), Box<dyn Error>> {
    // The local origin deliberately has no ACME directory. Queuing itself is the committed fact;
    // CA unavailability must not prevent notifications or touch an external CA.
    let body = serde_json::to_vec(
        &json!({ "operation_id": "00000000-0000-4000-8000-000000000304",
        "directory_url": endpoint.replace("/events", "/directory"), "certificate_names": [super::CERTIFICATE_NAME], "challenge": {"kind": "http01"} }),
    )?;
    let response = request_with_headers(
        root.address,
        client,
        "POST",
        "/api/latest/admin/certificates/acme",
        Some(&body),
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    require_status(&response, "201 Created", "queue local certificate event")
}

async fn await_delivery(
    root: &ProcessFixture,
    id: WorkId,
    expected: NotificationDeliveryState,
    attempt: u64,
) -> Result<(), Box<dyn Error>> {
    let identity =
        meshspan_daemon::LocalNodeIdentity::open(&root.identity_path, super::CERTIFICATE_NAME)?;
    let node = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let partition = InitialBootstrapMaterial::root_partition_id(node)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &root.state_path.join("root-authority.sqlite3"),
            partition,
            super::UnixMicros::new(1),
        )?);
        if repository
            .notification_delivery(id)?
            .is_some_and(|delivery| delivery.state == expected && delivery.attempt == attempt)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("notification did not reach its expected durable outcome".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn parse(value: &str) -> Result<[u8; 16], Box<dyn Error>> {
    let compact = value.replace('-', "");
    if compact.len() != 32 || !compact.is_ascii() {
        return Err("invalid delivery UUID".into());
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

struct Receiver {
    endpoint: String,
    anchor: String,
    events: mpsc::Receiver<Value>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), HttpsServerError>>,
}

impl Receiver {
    async fn start() -> Result<Self, Box<dyn Error>> {
        let ca = CertificateAuthority::new()?;
        let (leaf, key) = ca.issue_node("localhost")?.into_parts();
        let tls =
            ServerConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf)],
                    PrivatePkcs8KeyDer::from(key).into(),
                )?;
        let (send, events) = mpsc::channel(8);
        let router = Router::new()
            .route("/events", post(receive_event))
            .fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })
            .layer(DefaultBodyLimit::max(4096))
            .with_state((send, Arc::new(AtomicUsize::new(0))));
        let server = HttpsServer::bind("127.0.0.1:0".parse()?, Arc::new(tls), router).await?;
        let endpoint = format!("https://localhost:{}/events", server.local_addr()?.port());
        let anchor = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(ca.certificate_der())
        );
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run_until(async {
            drop(stopped.await);
        }));
        Ok(Self {
            endpoint,
            anchor,
            events,
            shutdown,
            task,
        })
    }
    async fn receive(&mut self) -> Result<Value, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(15), self.events.recv())
            .await?
            .ok_or_else(|| "notification receiver stopped".into())
    }
    async fn stop(self) -> Result<(), Box<dyn Error>> {
        self.shutdown
            .send(())
            .map_err(|()| "notification receiver already stopped")?;
        self.task.await??;
        Ok(())
    }
}

async fn receive_event(
    State((send, attempts)): State<(mpsc::Sender<Value>, Arc<AtomicUsize>)>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
        || headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            != event["delivery_id"].as_str()
    {
        return StatusCode::FORBIDDEN;
    }
    if send.send(event).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    }
}
