// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::VecDeque, error::Error, future::Future};

use meshspan_contracts::ContractError;
use serde_json::json;

use crate::{
    CloudflareDnsApi, CloudflareHttpMethod, CloudflareHttpRequest, CloudflareHttpResponse,
    CloudflareHttpTransport, CloudflareTxtRecord, CloudflareV4Api,
};

const ID: &str = "0123456789abcdef0123456789abcdef";
const TOKEN: &[u8] = b"protected-api-token";

#[tokio::test]
async fn creates_recovers_and_deletes_one_exact_owned_record() -> Result<(), Box<dyn Error>> {
    let record = record();
    let transport = ScriptedTransport::new([
        list_response(&[], 1)?,
        record_response(&record)?,
        list_response(&[record_value(&record)], 1)?,
        delete_response()?,
    ]);
    let mut api = CloudflareV4Api::new(transport);
    api.ensure_txt(ID, TOKEN, &record).await?;
    api.remove_txt(ID, TOKEN, &record).await?;
    let transport = api.into_transport();
    assert_eq!(
        transport.methods(),
        [
            CloudflareHttpMethod::Get,
            CloudflareHttpMethod::Post,
            CloudflareHttpMethod::Get,
            CloudflareHttpMethod::Delete,
        ]
    );
    assert!(transport.requests.iter().all(|request| {
        !request.url.contains("protected-api-token")
            && !request
                .body
                .windows(TOKEN.len())
                .any(|window| window == TOKEN)
    }));
    Ok(())
}

#[tokio::test]
async fn duplicate_json_and_ambiguous_pages_fail_closed() -> Result<(), Box<dyn Error>> {
    let record = record();
    let duplicate = CloudflareHttpResponse {
        status: 200,
        body: br#"{"success":true,"success":true,"result":[],"result_info":{"total_pages":1}}"#
            .to_vec(),
    };
    let mut api = CloudflareV4Api::new(ScriptedTransport::new([duplicate]));
    assert_eq!(
        api.ensure_txt(ID, TOKEN, &record).await,
        Err(ContractError::InternalContract)
    );

    let mut api = CloudflareV4Api::new(ScriptedTransport::new([list_response(
        &[record_value(&record)],
        2,
    )?]));
    assert_eq!(
        api.ensure_txt(ID, TOKEN, &record).await,
        Err(ContractError::Conflict)
    );
    Ok(())
}

fn record() -> CloudflareTxtRecord<'static> {
    CloudflareTxtRecord {
        name: "_acme-challenge.example.test",
        value: b"proof",
        ttl_seconds: 60,
        ownership_marker: "meshspan-acme:marker",
    }
}

fn record_value(record: &CloudflareTxtRecord<'_>) -> serde_json::Value {
    json!({
        "comment": record.ownership_marker,
        "content": std::str::from_utf8(record.value).unwrap_or(""),
        "id": ID,
        "name": record.name,
        "type": "TXT"
    })
}

fn list_response(
    records: &[serde_json::Value],
    total_pages: u64,
) -> Result<CloudflareHttpResponse, serde_json::Error> {
    response(&json!({
        "result": records,
        "result_info": { "total_pages": total_pages },
        "success": true
    }))
}

fn record_response(
    record: &CloudflareTxtRecord<'_>,
) -> Result<CloudflareHttpResponse, serde_json::Error> {
    response(&json!({ "result": record_value(record), "success": true }))
}

fn delete_response() -> Result<CloudflareHttpResponse, serde_json::Error> {
    response(&json!({ "result": { "id": ID }, "success": true }))
}

fn response(value: &serde_json::Value) -> Result<CloudflareHttpResponse, serde_json::Error> {
    Ok(CloudflareHttpResponse {
        status: 200,
        body: serde_json::to_vec(&value)?,
    })
}

struct ScriptedTransport {
    responses: VecDeque<CloudflareHttpResponse>,
    requests: Vec<CloudflareHttpRequest>,
}

impl ScriptedTransport {
    fn new(responses: impl IntoIterator<Item = CloudflareHttpResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    fn methods(&self) -> Vec<CloudflareHttpMethod> {
        self.requests.iter().map(|request| request.method).collect()
    }
}

impl CloudflareHttpTransport for ScriptedTransport {
    fn send(
        &mut self,
        request: &CloudflareHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<CloudflareHttpResponse, ContractError>> + Send {
        let result = if bearer_token == TOKEN {
            self.requests.push(request.clone());
            self.responses.pop_front().ok_or(ContractError::Unavailable)
        } else {
            Err(ContractError::Unauthorized)
        };
        std::future::ready(result)
    }
}
