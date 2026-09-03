// SPDX-License-Identifier: GPL-2.0-only

use std::{
    collections::BTreeMap,
    error::Error,
    future::Future,
    sync::{Arc, Mutex},
};

use meshspan_contracts::ContractError;

use crate::{
    AuthoritativeTxtObserver, DnsTxtProvider, WebhookDnsAction, WebhookDnsApi, WebhookDnsProvider,
    WebhookDnsRecord, WebhookDnsSettings,
};

type Records = Arc<Mutex<BTreeMap<String, (Vec<u8>, String)>>>;

#[tokio::test]
async fn receipt_survives_restart_and_cleanup_remains_exact() -> Result<(), Box<dyn Error>> {
    let records = Records::default();
    let mut first = provider(records.clone())?;
    let receipt = first
        .publish_txt("_acme-challenge.example.test", b"proof", 41)
        .await?;
    assert!(
        first
            .is_txt_visible("_acme-challenge.example.test", b"proof", receipt)
            .await?
    );
    drop(first);

    let mut recovered = provider(records.clone())?;
    assert_eq!(
        recovered.receipt("_acme-challenge.example.test", b"proof", 41),
        receipt
    );
    recovered
        .remove_txt("_acme-challenge.example.test", b"proof", receipt)
        .await?;
    assert!(records.lock().map_err(|_| "record lock failed")?.is_empty());
    Ok(())
}

fn provider(
    records: Records,
) -> Result<WebhookDnsProvider<MemoryApi, MemoryObserver>, Box<dyn Error>> {
    let settings = WebhookDnsSettings::new(
        "https://dns-automation.example.test/meshspan".to_owned(),
        b"protected-webhook-token".to_vec(),
    )?;
    Ok(WebhookDnsProvider::new(
        settings,
        MemoryApi(records.clone()),
        MemoryObserver(records),
    ))
}

struct MemoryApi(Records);

impl WebhookDnsApi for MemoryApi {
    fn apply(
        &mut self,
        _endpoint: &str,
        _bearer_token: &[u8],
        action: WebhookDnsAction,
        record: &WebhookDnsRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .and_then(|mut records| match action {
                WebhookDnsAction::Publish => {
                    records.insert(
                        record.name.to_owned(),
                        (record.value.to_vec(), record.ownership_marker.to_owned()),
                    );
                    Ok(())
                }
                WebhookDnsAction::Remove => {
                    let exact = records.get(record.name).is_some_and(|stored| {
                        stored.0 == record.value && stored.1 == record.ownership_marker
                    });
                    if !exact {
                        return Err(ContractError::Stale);
                    }
                    records.remove(record.name);
                    Ok(())
                }
            });
        std::future::ready(result)
    }
}

struct MemoryObserver(Records);

impl AuthoritativeTxtObserver for MemoryObserver {
    fn contains_txt(
        &self,
        name: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<bool, ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .map(|records| records.get(name).is_some_and(|stored| stored.0 == value));
        std::future::ready(result)
    }
}
