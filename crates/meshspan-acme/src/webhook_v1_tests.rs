// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::VecDeque, error::Error, future::Future};

use meshspan_contracts::ContractError;
use serde_json::json;

use crate::{
    WebhookDnsAction, WebhookDnsApi, WebhookDnsRecord, WebhookHttpRequest, WebhookHttpResponse,
    WebhookHttpTransport, WebhookV1Api,
};

const ENDPOINT: &str = "https://dns-automation.example.test/meshspan";
const MARKER: &str = "meshspan-acme:owned-record";
const TOKEN: &[u8] = b"protected-webhook-token";

#[tokio::test]
async fn sends_canonical_secret_safe_publish_and_remove_commands() -> Result<(), Box<dyn Error>> {
    let transport = ScriptedTransport::new([accepted()?, accepted()?]);
    let mut api = WebhookV1Api::new(transport);
    let record = record();
    api.apply(ENDPOINT, TOKEN, WebhookDnsAction::Publish, &record)
        .await?;
    api.apply(ENDPOINT, TOKEN, WebhookDnsAction::Remove, &record)
        .await?;
    let transport = api.into_transport();
    assert_eq!(transport.requests.len(), 2);
    assert_eq!(action(&transport.requests[0])?, "publish");
    assert_eq!(action(&transport.requests[1])?, "remove");
    assert!(transport.requests.iter().all(|request| {
        request.url == ENDPOINT
            && !request
                .body
                .windows(TOKEN.len())
                .any(|window| window == TOKEN)
    }));
    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_extra_and_wrong_ownership_responses() -> Result<(), Box<dyn Error>> {
    let invalid = [
        br#"{"version":1,"version":1,"accepted":true,"ownership":"meshspan-acme:owned-record"}"#
            .to_vec(),
        serde_json::to_vec(&json!({
            "accepted": true,
            "extra": true,
            "ownership": MARKER,
            "version": 1
        }))?,
        serde_json::to_vec(&json!({
            "accepted": true,
            "ownership": "meshspan-acme:different",
            "version": 1
        }))?,
    ];
    for body in invalid {
        let response = WebhookHttpResponse { status: 200, body };
        let mut api = WebhookV1Api::new(ScriptedTransport::new([response]));
        assert_eq!(
            api.apply(ENDPOINT, TOKEN, WebhookDnsAction::Publish, &record())
                .await,
            Err(ContractError::InternalContract)
        );
    }
    Ok(())
}

fn accepted() -> Result<WebhookHttpResponse, serde_json::Error> {
    Ok(WebhookHttpResponse {
        status: 200,
        body: serde_json::to_vec(&json!({
            "accepted": true,
            "ownership": MARKER,
            "version": 1
        }))?,
    })
}

fn record() -> WebhookDnsRecord<'static> {
    WebhookDnsRecord {
        name: "_acme-challenge.example.test",
        value: b"proof",
        ownership_marker: MARKER,
    }
}

fn action(request: &WebhookHttpRequest) -> Result<String, Box<dyn Error>> {
    let value: serde_json::Value = serde_json::from_slice(&request.body)?;
    value
        .get("action")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "missing action".into())
}

struct ScriptedTransport {
    responses: VecDeque<WebhookHttpResponse>,
    requests: Vec<WebhookHttpRequest>,
}

impl ScriptedTransport {
    fn new(responses: impl IntoIterator<Item = WebhookHttpResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl WebhookHttpTransport for ScriptedTransport {
    fn send(
        &mut self,
        request: &WebhookHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<WebhookHttpResponse, ContractError>> + Send {
        let result = if bearer_token == TOKEN {
            self.requests.push(request.clone());
            self.responses.pop_front().ok_or(ContractError::Unavailable)
        } else {
            Err(ContractError::Unauthorized)
        };
        std::future::ready(result)
    }
}
