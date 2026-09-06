// SPDX-License-Identifier: GPL-2.0-only

//! Minimal validating ACME peer for the real-process certificate lifecycle proof.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use meshspan_certificates::{CertificateAuthority, NodePublicIdentity};
use meshspan_daemon::{HttpsServer, HttpsServerError};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{sync::oneshot, task::JoinHandle};
use x509_parser::{
    certification_request::X509CertificationRequest,
    prelude::{FromDer as _, GeneralName, ParsedExtension},
};

use super::{
    CERTIFICATE_NAME, Error,
    challenge::{TOKEN, ValidationTarget},
};

type Failure = Box<dyn Error + Send + Sync>;

#[path = "authority/interruption.rs"]
mod interruption;
#[path = "authority/rejection.rs"]
mod rejection;
pub(super) use interruption::AuthorizationInterruption;

pub(super) struct TestAuthority {
    pub endpoint: String,
    pub anchor_pem: String,
    pub anchor_der: Vec<u8>,
    state: Arc<Mutex<AuthorityState>>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), HttpsServerError>>,
}

struct AuthorityState {
    ca: CertificateAuthority,
    endpoint: String,
    validation_target: ValidationTarget,
    nonce_index: usize,
    nonces: BTreeSet<String>,
    account: Option<VerifyingKey>,
    thumbprint: Option<String>,
    validated: bool,
    chain: Option<String>,
    orders: usize,
    finalisations: usize,
    observations: Vec<String>,
    polls: PollSchedule,
    interruption: Option<Arc<interruption::AuthorizationInterruption>>,
    rejection: Option<rejection::OrderRejection>,
}

impl TestAuthority {
    pub async fn start(validation_target: ValidationTarget) -> Result<Self, Box<dyn Error>> {
        let ca = CertificateAuthority::new()?;
        let anchor_der = ca.certificate_der().to_vec();
        let anchor_pem = pem(&anchor_der);
        let (leaf, key) = ca.issue_node("localhost")?.into_parts();
        let tls =
            ServerConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf)],
                    PrivatePkcs8KeyDer::from(key).into(),
                )?;
        let state = Arc::new(Mutex::new(AuthorityState {
            ca,
            endpoint: String::new(),
            validation_target,
            nonce_index: 0,
            nonces: BTreeSet::new(),
            account: None,
            thumbprint: None,
            validated: false,
            chain: None,
            orders: 0,
            finalisations: 0,
            observations: Vec::new(),
            polls: PollSchedule::default(),
            interruption: None,
            rejection: None,
        }));
        let router = Router::new()
            .fallback(handle)
            .layer(DefaultBodyLimit::max(256 * 1024))
            .with_state(Arc::clone(&state));
        let server = HttpsServer::bind("127.0.0.1:0".parse()?, Arc::new(tls), router).await?;
        let endpoint = format!("https://localhost:{}", server.local_addr()?.port());
        state
            .lock()
            .map_err(|_| "CA mutex poisoned")?
            .endpoint
            .clone_from(&endpoint);
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run_until(async {
            drop(stopped.await);
        }));
        Ok(Self {
            endpoint,
            anchor_pem,
            anchor_der,
            state,
            shutdown,
            task,
        })
    }

    pub fn assert_issued_once(&self) -> Result<(), Box<dyn Error>> {
        let state = self.state.lock().map_err(|_| "CA mutex poisoned")?;
        let expected_orders = if state.rejection.is_some() { 2 } else { 1 };
        if state.orders != expected_orders
            || state.finalisations != 1
            || !state.validated
            || state.chain.is_none()
            || state.polls.early_requests != 0
            || state.polls.fulfilled != BTreeSet::from(["/authorization", "/order"])
            || state
                .rejection
                .as_ref()
                .is_some_and(|proof| !proof.is_complete())
        {
            return Err(format!(
                "expected one validated issuance and both polling deadlines, saw orders={}, finalisations={}, validated={}, early_polls={}, fulfilled={:?}",
                state.orders, state.finalisations, state.validated,
                state.polls.early_requests, state.polls.fulfilled
            )
            .into());
        }
        Ok(())
    }

    pub fn observations(&self) -> Vec<String> {
        self.state.lock().map_or_else(
            |_| vec!["CA mutex poisoned".to_owned()],
            |state| state.observations.clone(),
        )
    }

    pub async fn assert_challenge_removed(&self) -> Result<(), Box<dyn Error>> {
        let (target, authorisation) = {
            let state = self.state.lock().map_err(|_| "CA mutex poisoned")?;
            (
                state.validation_target,
                format!(
                    "{}.{}",
                    state.token(),
                    state.thumbprint.as_ref().ok_or("account missing")?
                ),
            )
        };
        target
            .assert_removed(&authorisation)
            .await
            .map_err(|error| error.to_string().into())
    }

    pub async fn stop(self) -> Result<(), Box<dyn Error>> {
        self.shutdown
            .send(())
            .map_err(|()| "CA fixture stopped unexpectedly")?;
        self.task.await??;
        Ok(())
    }
}

async fn handle(
    State(state): State<Arc<Mutex<AuthorityState>>>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let outcome = async {
        if interruption::before_request(&state, &method, uri.path()).await? {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                "interrupted before processing",
            )
                .into_response());
        }
        respond(&state, &method, uri.path(), &body).await
    }
    .await;
    match outcome {
        Ok(response) => response,
        Err(error) => {
            if let Ok(mut state) = state.lock() {
                state.observations.push(error.to_string());
            }
            (StatusCode::BAD_REQUEST, "test CA rejected request").into_response()
        }
    }
}

async fn respond(
    state: &Mutex<AuthorityState>,
    method: &Method,
    route: &str,
    body: &[u8],
) -> Result<Response, Failure> {
    let (payload, probe) = {
        let mut state = state.lock().map_err(|_| "CA mutex poisoned")?;
        state.observations.push(format!("{method} {route}"));
        let resource = state.resource(route)?;
        state.polls.observe(resource)?;
        let payload = if *method == Method::POST {
            verify_jws(&mut state, route, body)?
        } else {
            Value::Null
        };
        let probe = if resource == "/challenge" {
            if payload != json!({}) {
                return Err("challenge notification must contain an empty object".into());
            }
            Some((
                state.validation_target,
                format!(
                    "{}.{}",
                    state.token(),
                    state.thumbprint.as_ref().ok_or("account missing")?
                ),
            ))
        } else {
            None
        };
        (payload, probe)
    };
    if let Some((target, expected)) = probe {
        target.validate(&expected).await?;
        state.lock().map_err(|_| "CA mutex poisoned")?.validated = true;
    }
    rejection::before_new_order(state, method, route).await?;
    let mut state = state.lock().map_err(|_| "CA mutex poisoned")?;
    let resource = state.resource(route)?;
    let (status, location, content) = route_response(&mut state, method, resource, &payload)?;
    state.nonce_index += 1;
    let nonce = format!("nonce_{}", state.nonce_index);
    state.nonces.insert(nonce.clone());
    let mut response = (status, content).into_response();
    response
        .headers_mut()
        .insert("replay-nonce", nonce.parse()?);
    if let Some(location) = location {
        response.headers_mut().insert("location", location.parse()?);
    }
    if matches!(resource, "/challenge" | "/finalize") {
        response.headers_mut().insert("retry-after", "2".parse()?);
    }
    Ok(response)
}

fn route_response(
    state: &mut AuthorityState,
    method: &Method,
    route: &str,
    payload: &Value,
) -> Result<(StatusCode, Option<String>, String), Failure> {
    let endpoint = &state.endpoint;
    let mut location = None;
    let mut status = StatusCode::OK;
    let content = match (method, route) {
        (&Method::GET, "/directory") => json!({
            "newNonce": format!("{endpoint}/nonce"),
            "newAccount": format!("{endpoint}/account"),
            "newOrder": format!("{endpoint}/new-order")
        })
        .to_string(),
        (&Method::HEAD, "/nonce") => String::new(),
        (&Method::POST, "/account") => {
            if payload != &json!({"termsOfServiceAgreed": true}) {
                return Err("unexpected account payload".into());
            }
            status = StatusCode::CREATED;
            location = Some(format!("{endpoint}/accounts/1"));
            json!({"status": "valid"}).to_string()
        }
        (&Method::POST, "/new-order") => {
            if payload != &json!({"identifiers": [{"type": "dns", "value": CERTIFICATE_NAME}]}) {
                return Err("unexpected order names".into());
            }
            state.orders += 1;
            state.validated = false;
            state.chain = None;
            status = StatusCode::CREATED;
            location = Some(state.resource_url("/order"));
            order(state).to_string()
        }
        (&Method::POST, "/authorization") => {
            require_empty_payload(payload)?;
            state.record_rejection()?;
            authorization(state).to_string()
        }
        (&Method::POST, "/challenge") => {
            state.polls.defer("/authorization");
            json!({"status": "valid"}).to_string()
        }
        (&Method::POST, "/order") => {
            require_empty_payload(payload)?;
            order(state).to_string()
        }
        (&Method::POST, "/finalize") => {
            if !state.validated || state.is_rejected() {
                return Err("finalisation preceded successful challenge validation".into());
            }
            let csr = URL_SAFE_NO_PAD.decode(text(payload, "csr")?)?;
            state.chain = Some(sign_csr(&state.ca, &csr)?);
            state.finalisations += 1;
            state.polls.defer("/order");
            order(state).to_string()
        }
        (&Method::POST, "/certificate") => {
            require_empty_payload(payload)?;
            state.chain.clone().ok_or("certificate not issued")?
        }
        _ => return Err("unexpected ACME method or resource".into()),
    };
    Ok((status, location, content))
}

fn order(state: &AuthorityState) -> Value {
    let status = if state.is_rejected() {
        "invalid"
    } else if state.polls.pending.contains_key("/order") {
        "processing"
    } else if state.chain.is_some() {
        "valid"
    } else if state.validated {
        "ready"
    } else {
        "pending"
    };
    let mut value = json!({
        "status": status,
        "identifiers": [{"type": "dns", "value": CERTIFICATE_NAME}],
        "authorizations": [state.resource_url("/authorization")],
        "finalize": state.resource_url("/finalize")
    });
    if status == "valid" {
        value["certificate"] = json!(state.resource_url("/certificate"));
    }
    value
}

#[derive(Default)]
struct PollSchedule {
    pending: BTreeMap<&'static str, Instant>,
    fulfilled: BTreeSet<&'static str>,
    early_requests: usize,
}

impl PollSchedule {
    fn defer(&mut self, resource: &'static str) {
        self.pending
            .insert(resource, Instant::now() + Duration::from_secs(2));
    }

    fn observe(&mut self, resource: &str) -> Result<(), Failure> {
        let Some(deadline) = self.pending.get(resource) else {
            return Ok(());
        };
        if Instant::now() < *deadline {
            self.early_requests += 1;
            return Err("request preceded CA Retry-After deadline".into());
        }
        let (resource, _) = self
            .pending
            .remove_entry(resource)
            .ok_or("missing poll schedule")?;
        self.fulfilled.insert(resource);
        Ok(())
    }
}

fn authorization(state: &AuthorityState) -> Value {
    let status = if state.is_rejected() {
        "invalid"
    } else if state.validated {
        "valid"
    } else {
        "pending"
    };
    json!({
        "status": status,
        "identifier": {"type": "dns", "value": CERTIFICATE_NAME},
        "challenges": [{
            "type": state.validation_target.kind(),
            "url": state.resource_url("/challenge"),
            "token": state.token(),
            "status": status
        }]
    })
}

fn verify_jws(state: &mut AuthorityState, route: &str, body: &[u8]) -> Result<Value, Failure> {
    let envelope: Value = serde_json::from_slice(body)?;
    let protected = text(&envelope, "protected")?;
    let payload = text(&envelope, "payload")?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected)?)?;
    if header["alg"] != "ES256"
        || header["url"] != format!("{}{route}", state.endpoint)
        || !state.nonces.remove(text(&header, "nonce")?)
    {
        return Err("invalid JWS algorithm, URL or nonce".into());
    }
    let key = if route == "/account" {
        let jwk = &header["jwk"];
        if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || header.get("kid").is_some() {
            return Err("invalid account JWK".into());
        }
        let mut sec1 = vec![4];
        sec1.extend(URL_SAFE_NO_PAD.decode(text(jwk, "x")?)?);
        sec1.extend(URL_SAFE_NO_PAD.decode(text(jwk, "y")?)?);
        let key = VerifyingKey::from_sec1_bytes(&sec1)?;
        if state
            .account
            .as_ref()
            .is_some_and(|existing| *existing != key)
        {
            return Err("replacement changed the configured account key".into());
        }
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            text(jwk, "x")?,
            text(jwk, "y")?
        );
        state.thumbprint = Some(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())));
        state.account = Some(key);
        key
    } else {
        if header["kid"] != format!("{}/accounts/1", state.endpoint) || header.get("jwk").is_some()
        {
            return Err("incorrect JWS account binding".into());
        }
        state.account.ok_or("account missing")?
    };
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(text(&envelope, "signature")?)?)?;
    key.verify(format!("{protected}.{payload}").as_bytes(), &signature)?;
    if payload.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
    }
}

fn sign_csr(ca: &CertificateAuthority, der: &[u8]) -> Result<String, Failure> {
    let (remaining, csr) = X509CertificationRequest::from_der(der).map_err(|_| "malformed CSR")?;
    if !remaining.is_empty()
        || csr.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
    {
        return Err("noncanonical CSR or unsupported signature".into());
    }
    let info = &csr.certification_request_info;
    let public = NodePublicIdentity::from_sec1(info.subject_pki.subject_public_key.data.as_ref())?;
    let key = VerifyingKey::from_sec1_bytes(info.subject_pki.subject_public_key.data.as_ref())?;
    key.verify(
        info.raw,
        &Signature::from_der(csr.signature_value.data.as_ref())?,
    )?;
    let names = csr
        .requested_extensions()
        .ok_or("missing CSR extensions")?
        .flat_map(|extension| {
            if let ParsedExtension::SubjectAlternativeName(names) = extension {
                names.general_names.as_slice()
            } else {
                &[]
            }
        })
        .collect::<Vec<_>>();
    if names != vec![&GeneralName::DNSName(CERTIFICATE_NAME)] {
        return Err("CSR DNS names differ from the validated order".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(format!(
        "{}{}",
        pem(&ca.sign_public_endpoint_identity(
            &public,
            &[CERTIFICATE_NAME.to_owned()],
            now.checked_sub(60)
                .ok_or("fixture host clock precedes epoch")?,
            now.checked_add(90 * 24 * 60 * 60)
                .ok_or("fixture host clock overflows")?,
        )?),
        pem(ca.certificate_der())
    ))
}

fn pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut output = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        for byte in line {
            output.push(char::from(*byte));
        }
        output.push('\n');
    }
    output.push_str("-----END CERTIFICATE-----\n");
    output
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, Failure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing text field {field}").into())
}

fn require_empty_payload(payload: &Value) -> Result<(), Failure> {
    if payload.is_null() {
        Ok(())
    } else {
        Err("POST-as-GET payload is not empty".into())
    }
}
