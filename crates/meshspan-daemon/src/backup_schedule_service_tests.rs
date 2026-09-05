// SPDX-License-Identifier: GPL-2.0-only

use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{BackupSchedulePolicy, ConfigureBackupScheduleRequest};
use meshspan_domain::{PartitionId, UnixMicros, uuid_v8};

use super::RunningAuthority;
use crate::{
    BackupScheduleController, BackupScheduleError, BackupScheduleService,
    ConsensusAuthenticationAuthority, GatewaySessionIdentity,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_schedule_commits_replays_after_replacement_and_rejects_changed_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture =
        RunningAuthority::start_with_partition(PartitionId::from_bytes(uuid_v8([2; 16]))?).await?;
    let reader = fixture.reader.take().ok_or("reader consumed")?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Bearer {}",
            fixture.api_key.expose_encoded().as_str()
        ))?,
    );
    let authority = ConsensusAuthenticationAuthority::new(
        reader,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let mut service =
        BackupScheduleService::new(authority, GatewaySessionIdentity::new(fixture.node_id, 1)?);
    tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        let now = UnixMicros::new(40);
        assert_eq!(
            service.read(&HeaderMap::new(), now),
            Err(BackupScheduleError::Unauthenticated)
        );
        assert!(service.read(&headers, now)?.schedule.is_none());
        let first_request = request(20, 0)?;
        let first = service.configure(&headers, now, first_request.clone())?;
        assert_eq!(first.sequence, 1);
        assert_eq!(first.committed_revision, 2);
        let mut replacement = request(21, 1)?;
        replacement.policy.enabled = false;
        let second = service.configure(&headers, UnixMicros::new(50), replacement)?;
        assert_eq!(second.sequence, 2);
        assert_eq!(second.committed_revision, 3);
        let replay = service.configure(&headers, UnixMicros::new(60), first_request.clone())?;
        assert_eq!(replay, first);
        let current = service
            .read(&headers, UnixMicros::new(61))?
            .schedule
            .ok_or("schedule missing")?;
        assert_eq!(current.sequence, 2);
        assert!(!current.policy.enabled);
        assert_eq!(current.next_due_at_epoch_micros, 50);
        let mut changed = first_request;
        changed.policy.retained_generations += 1;
        assert_eq!(
            service.configure(&headers, UnixMicros::new(62), changed),
            Err(BackupScheduleError::Conflict)
        );
        assert_eq!(
            service.configure(&headers, UnixMicros::new(63), request(22, 0)?),
            Err(BackupScheduleError::Conflict)
        );
        assert_eq!(
            service
                .read(&headers, UnixMicros::new(64))?
                .schedule
                .ok_or("schedule missing")?
                .sequence,
            2
        );
        Ok(())
    })?;
    fixture.shutdown().await
}

fn request(
    marker: u8,
    expected_sequence: u64,
) -> Result<ConfigureBackupScheduleRequest, Box<dyn std::error::Error>> {
    Ok(ConfigureBackupScheduleRequest {
        operation_id: meshspan_api_contract::OperationId::from_uuid_bytes(uuid_v8([marker; 16]))
            .ok_or("operation ID")?,
        expected_sequence,
        policy: BackupSchedulePolicy {
            interval_seconds: 3600,
            retained_generations: 7,
            minimum_verified_copies: 2,
            minimum_independent_copies: 1,
            enabled: true,
        },
    })
}
