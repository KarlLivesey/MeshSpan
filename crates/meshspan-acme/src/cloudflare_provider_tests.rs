// SPDX-License-Identifier: GPL-2.0-only

use std::{
    collections::BTreeMap,
    error::Error,
    future::Future,
    sync::{Arc, Mutex},
};

use meshspan_contracts::ContractError;

use crate::{
    AuthoritativeTxtObserver, CloudflareDnsApi, CloudflareDnsProvider, CloudflareDnsSettings,
    CloudflareTxtRecord, DnsTxtProvider,
};

type Records = Arc<Mutex<BTreeMap<String, (Vec<u8>, String)>>>;

#[tokio::test]
async fn marker_survives_reconstruction_and_cleanup_is_exact() -> Result<(), Box<dyn Error>> {
    let records = Records::default();
    let mut first = provider(records.clone())?;
    let receipt = first
        .publish_txt("_acme-challenge.example.test", b"proof", 9)
        .await?;
    assert!(
        first
            .is_txt_visible("_acme-challenge.example.test", b"proof", receipt)
            .await?
    );
    drop(first);

    let mut reconstructed = provider(records.clone())?;
    reconstructed
        .remove_txt("_acme-challenge.example.test", b"proof", receipt)
        .await?;
    assert!(records.lock().map_err(|_| "record lock failed")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn changed_value_never_deletes_the_owned_record() -> Result<(), Box<dyn Error>> {
    let records = Records::default();
    let mut provider = provider(records.clone())?;
    let receipt = provider
        .publish_txt("_acme-challenge.example.test", b"proof", 9)
        .await?;
    assert_eq!(
        provider
            .remove_txt("_acme-challenge.example.test", b"changed", receipt)
            .await,
        Err(ContractError::Stale)
    );
    assert_eq!(records.lock().map_err(|_| "record lock failed")?.len(), 1);
    Ok(())
}

fn provider(
    records: Records,
) -> Result<CloudflareDnsProvider<MemoryApi, MemoryObserver>, Box<dyn Error>> {
    let settings = CloudflareDnsSettings::new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )?;
    Ok(CloudflareDnsProvider::new(
        settings,
        MemoryApi(records.clone()),
        MemoryObserver(records),
        30,
    )?)
}

struct MemoryApi(Records);

impl CloudflareDnsApi for MemoryApi {
    fn ensure_txt(
        &mut self,
        _zone_id: &str,
        _api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .map(|mut records| {
                records.insert(
                    record.name.to_owned(),
                    (record.value.to_vec(), record.ownership_marker.to_owned()),
                );
            });
        std::future::ready(result)
    }

    fn remove_txt(
        &mut self,
        _zone_id: &str,
        _api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        let result = self
            .0
            .lock()
            .map_err(|_| ContractError::Unavailable)
            .and_then(|mut records| {
                let matches = records.get(record.name).is_some_and(|stored| {
                    stored.0 == record.value && stored.1 == record.ownership_marker
                });
                if !matches {
                    return Err(ContractError::Stale);
                }
                records.remove(record.name);
                Ok(())
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
