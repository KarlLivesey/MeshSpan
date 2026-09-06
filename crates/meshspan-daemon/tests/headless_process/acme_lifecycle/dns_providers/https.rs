// SPDX-License-Identifier: GPL-2.0-only

//! Test-owned provider origin with actual TLS, bearer verification and exact record ownership.

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use meshspan_certificates::CertificateAuthority;
use meshspan_daemon::{HttpsServer, HttpsServerError};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde_json::{Value, json};
use tokio::{sync::oneshot, task::JoinHandle};

use super::{BEARER, Error, Provider, RECORD_ID, Record, SharedRecords, ZONE_ID};

pub(super) struct Server {
    pub endpoint: String,
    pub anchor_pem: String,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), HttpsServerError>>,
}

impl Server {
    pub async fn start(provider: Provider, records: SharedRecords) -> Result<Self, Box<dyn Error>> {
        let ca = CertificateAuthority::new()?;
        let name = match provider {
            Provider::Cloudflare => "api.cloudflare.com",
            Provider::Webhook => "localhost",
        };
        let (leaf, key) = ca.issue_node(name)?.into_parts();
        let tls =
            ServerConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf)],
                    PrivatePkcs8KeyDer::from(key).into(),
                )?;
        let router = Router::new()
            .fallback(handle)
            .layer(DefaultBodyLimit::max(16 * 1024))
            .with_state((provider, records));
        let address = match provider {
            Provider::Cloudflare => "127.0.0.1:443",
            Provider::Webhook => "127.0.0.1:0",
        };
        let server = HttpsServer::bind(address.parse()?, Arc::new(tls), router).await?;
        let endpoint = format!("https://{name}:{}/dns", server.local_addr()?.port());
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run_until(async {
            drop(stopped.await);
        }));
        Ok(Self {
            endpoint,
            anchor_pem: super::super::authority::pem(ca.certificate_der()),
            shutdown,
            task,
        })
    }

    pub async fn stop(self) -> Result<(), Box<dyn Error>> {
        let signal = self.shutdown.send(());
        self.task.await??;
        signal.map_err(|()| "HTTPS fixture stopped before shutdown")?;
        Ok(())
    }
}

async fn handle(
    State((provider, records)): State<(Provider, SharedRecords)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {BEARER}"))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let result = match provider {
        Provider::Cloudflare => cloudflare(&method, &uri, &body, &records),
        Provider::Webhook => webhook(&method, &uri, &body, &records),
    };
    match result {
        Ok(value) => axum::Json(value).into_response(),
        Err(message) => (StatusCode::BAD_REQUEST, message).into_response(),
    }
}

fn cloudflare(
    method: &Method,
    uri: &Uri,
    body: &[u8],
    records: &SharedRecords,
) -> Result<Value, &'static str> {
    let collection = format!("/client/v4/zones/{ZONE_ID}/dns_records");
    let mut state = records.lock().map_err(|_| "DNS records poisoned")?;
    let result = match (method, uri.path()) {
        (&Method::GET, route) if route == collection && body.is_empty() => {
            let query =
                form_urlencoded::parse(uri.query().ok_or("missing exact filters")?.as_bytes())
                    .into_owned()
                    .collect::<Vec<_>>();
            let field = |name: &str| {
                query
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            if query.len() != 6
                || field("type") != Some("TXT")
                || field("match") != Some("all")
                || field("per_page") != Some("2")
                || field("name.exact") != Some("_acme-challenge.meshspan.local")
            {
                return Err("unexpected Cloudflare filters");
            }
            let matches = state
                .managed
                .iter()
                .filter(|record| {
                    Some(record.value.as_str()) == field("content.exact")
                        && Some(record.ownership.as_str()) == field("comment.exact")
                })
                .map(record_json)
                .collect::<Vec<_>>();
            return Ok(
                json!({"success": true, "result": matches, "result_info": {"total_pages": 1}}),
            );
        }
        (&Method::POST, route) if route == collection => {
            let value: Value = serde_json::from_slice(body).map_err(|_| "invalid record JSON")?;
            if value.as_object().map(serde_json::Map::len) != Some(6)
                || value["type"] != "TXT"
                || value["ttl"] != 60
                || value["proxied"] != false
            {
                return Err("unexpected Cloudflare TXT settings");
            }
            let record = parse_record(&value, "content", "comment")?;
            if state.managed.is_some() {
                return Err("duplicate record creation");
            }
            state.managed = Some(record.clone());
            state.publications += 1;
            record_json(&record)
        }
        (&Method::DELETE, route)
            if route == format!("{collection}/{RECORD_ID}") && body.is_empty() =>
        {
            if state.managed.take().is_none() {
                return Err("deletion of an absent record");
            }
            state.removals += 1;
            json!({"id": RECORD_ID})
        }
        _ => return Err("unexpected Cloudflare request"),
    };
    Ok(json!({"success": true, "result": result}))
}

fn webhook(
    method: &Method,
    uri: &Uri,
    body: &[u8],
    records: &SharedRecords,
) -> Result<Value, &'static str> {
    if method != Method::POST || uri.path() != "/dns" || uri.query().is_some() {
        return Err("unexpected webhook request");
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| "invalid webhook JSON")?;
    if value.as_object().map(serde_json::Map::len) != Some(5) || value["version"] != 1 {
        return Err("unexpected webhook version or fields");
    }
    let record = parse_record(&value, "value", "ownership")?;
    let mut state = records.lock().map_err(|_| "DNS records poisoned")?;
    match value["action"].as_str() {
        Some("publish") => match &state.managed {
            Some(existing) if existing != &record => return Err("conflicting webhook publication"),
            Some(_) => {}
            None => {
                state.managed = Some(record.clone());
                state.publications += 1;
            }
        },
        Some("remove") => {
            if state.managed.as_ref() != Some(&record) {
                return Err("unowned webhook removal");
            }
            state.managed = None;
            state.removals += 1;
        }
        _ => return Err("unexpected webhook action"),
    }
    Ok(json!({"version": 1, "accepted": true, "ownership": record.ownership}))
}

fn parse_record(value: &Value, content: &str, ownership: &str) -> Result<Record, &'static str> {
    let record = Record {
        name: value["name"].as_str().ok_or("missing owner")?.to_owned(),
        value: value[content]
            .as_str()
            .ok_or("missing TXT value")?
            .to_owned(),
        ownership: value[ownership]
            .as_str()
            .ok_or("missing ownership")?
            .to_owned(),
    };
    if record.name != "_acme-challenge.meshspan.local"
        || record.value.len() != 43
        || record.ownership.is_empty()
    {
        return Err("invalid TXT owner, value or ownership");
    }
    Ok(record)
}

fn record_json(record: &Record) -> Value {
    json!({"id": RECORD_ID, "type": "TXT", "name": record.name,
        "content": record.value, "comment": record.ownership})
}
