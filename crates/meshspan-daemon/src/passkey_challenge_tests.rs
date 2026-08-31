// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use meshspan_api_contract::CreatePasskeyChallengeRequest;
use meshspan_domain::{DurationMicros, EntropyError, NodeId, RandomSource, UnixMicros};
use meshspan_metadata::LocalDatabase;
use tempfile::tempdir;

use crate::{
    PasskeyCeremonyKey, PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError,
    PasskeyChallengeError, PasskeyChallengeService,
};

const OPERATION: &str = "00000000-0000-4000-8000-000000000071";

#[test]
fn challenge_is_exactly_replayed_after_restart_without_new_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let first_calls = Arc::new(AtomicUsize::new(0));
    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    let mut service = PasskeyChallengeService::new(
        database,
        CountingRandom::new(Arc::clone(&first_calls)),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        configuration()?,
    );
    let request = request()?;
    let first = service.create(&request, UnixMicros::new(1_000_000))?;
    assert_eq!(first.operation_id.as_str(), OPERATION);
    assert_eq!(first.challenge.len(), 43);
    assert_eq!(first.relying_party_id, "files.example.test");
    assert_eq!(first.timeout_milliseconds, 120_000);
    assert_eq!(first_calls.load(Ordering::SeqCst), 4);
    drop(service);

    let replay_calls = Arc::new(AtomicUsize::new(0));
    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let mut replay = PasskeyChallengeService::new(
        database,
        CountingRandom::new(Arc::clone(&replay_calls)),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        configuration()?,
    );
    let second = replay.create(&request, UnixMicros::new(2_000_000))?;
    assert_eq!(second, first);
    assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn changed_configuration_and_wrong_protection_key_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([2; 16])?;
    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    let mut service = PasskeyChallengeService::new(
        database,
        CountingRandom::new(Arc::new(AtomicUsize::new(0))),
        PasskeyCeremonyKey::from_bytes([7; 32])?,
        configuration()?,
    );
    service.create(&request()?, UnixMicros::new(1_000_000))?;
    drop(service);

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let changed = PasskeyChallengeConfiguration::new(
        "files.example.test".to_owned(),
        vec![
            "https://files.example.test".to_owned(),
            "https://other.files.example.test".to_owned(),
        ],
        DurationMicros::new(120_000_000),
    )?;
    let mut changed_service = PasskeyChallengeService::new(
        database,
        CountingRandom::new(Arc::new(AtomicUsize::new(0))),
        PasskeyCeremonyKey::from_bytes([7; 32])?,
        changed,
    );
    assert_eq!(
        changed_service.create(&request()?, UnixMicros::new(2_000_000)),
        Err(PasskeyChallengeError::Conflict)
    );
    drop(changed_service);

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(3_000_000))?;
    let mut wrong_key = PasskeyChallengeService::new(
        database,
        CountingRandom::new(Arc::new(AtomicUsize::new(0))),
        PasskeyCeremonyKey::from_bytes([8; 32])?,
        configuration()?,
    );
    assert_eq!(
        wrong_key.create(&request()?, UnixMicros::new(3_000_000)),
        Err(PasskeyChallengeError::Failed)
    );
    Ok(())
}

#[test]
fn configuration_and_entropy_boundaries_reject_hostile_values()
-> Result<(), Box<dyn std::error::Error>> {
    let invalid = [
        ("", "https://files.example.test"),
        ("Files.example.test", "https://files.example.test"),
        ("files..example.test", "https://files.example.test"),
        ("files.example.test", "http://files.example.test"),
        ("files.example.test", "https://files.example.test/path"),
        ("files.example.test", "https://user@files.example.test"),
        ("files.example.test", "https://unrelated.example.test"),
        ("files.example.test", "https://files.example.test:0"),
    ];
    for (relying_party, origin) in invalid {
        assert_eq!(
            PasskeyChallengeConfiguration::new(
                relying_party.to_owned(),
                vec![origin.to_owned()],
                DurationMicros::new(120_000_000),
            ),
            Err(PasskeyChallengeConfigurationError),
            "{relying_party} {origin}"
        );
    }
    assert_eq!(
        PasskeyChallengeConfiguration::new(
            "files.example.test".to_owned(),
            vec!["https://files.example.test".to_owned(); 2],
            DurationMicros::new(120_000_000),
        ),
        Err(PasskeyChallengeConfigurationError)
    );
    assert!(matches!(
        PasskeyCeremonyKey::from_bytes([0; 32]),
        Err(crate::PasskeyChallengeStateError::Invalid)
    ));

    let directory = tempdir()?;
    let database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        NodeId::from_bytes([3; 16])?,
        UnixMicros::new(1),
    )?;
    let mut service = PasskeyChallengeService::new(
        database,
        ZeroRandom,
        PasskeyCeremonyKey::from_bytes([1; 32])?,
        configuration()?,
    );
    assert_eq!(
        service.create(&request()?, UnixMicros::new(1_000_000)),
        Err(PasskeyChallengeError::Unavailable)
    );
    Ok(())
}

fn configuration() -> Result<PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError> {
    PasskeyChallengeConfiguration::new(
        "files.example.test".to_owned(),
        vec!["https://files.example.test".to_owned()],
        DurationMicros::new(120_000_000),
    )
}

fn request() -> Result<CreatePasskeyChallengeRequest, serde_json::Error> {
    serde_json::from_value(serde_json::json!({ "operation_id": OPERATION }))
}

struct CountingRandom {
    calls: Arc<AtomicUsize>,
}

impl CountingRandom {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls }
    }
}

impl RandomSource for CountingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let value = u8::try_from(self.calls.fetch_add(1, Ordering::SeqCst) + 1)
            .map_err(|_| EntropyError)?;
        destination.fill(value);
        Ok(())
    }
}

struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(0);
        Ok(())
    }
}
