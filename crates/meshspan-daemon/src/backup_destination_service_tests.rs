// SPDX-License-Identifier: GPL-2.0-only

use super::{RunningAuthority, command_context};
use crate::create_mesh_setup::format_uuid;
use crate::{
    BackupDestinationController, BackupDestinationError, BackupDestinationService,
    ConsensusAuthenticationAuthority, GatewaySessionIdentity,
};
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    BackupDestinationStatus, ConfigureBackupDestinationRequest, ListBackupDestinationsQuery,
};
use meshspan_domain::{
    ComponentInstanceId, HostId, MeshId, PartitionId, TargetId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, ConfirmRecoveryBundleSaved, CreateComponent, RecordName,
    RegisterStorageTarget, StorageUsageLimit,
};
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_destination_service_creates_pauses_pages_and_replays_committed_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture =
        RunningAuthority::start_with_partition(PartitionId::from_bytes(uuid_v8([2; 16]))?).await?;
    register_target(&fixture).await?;
    let reader = fixture.reader.take().ok_or("reader consumed")?;
    let authority = ConsensusAuthenticationAuthority::new(
        reader,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let mut service =
        BackupDestinationService::new(authority, GatewaySessionIdentity::new(fixture.node_id, 1)?);
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Bearer {}",
            fixture.api_key.expose_encoded().as_str()
        ))?,
    );
    tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        let now = UnixMicros::new(40);
        assert_eq!(
            service.list(
                &HeaderMap::new(),
                now,
                ListBackupDestinationsQuery::default()
            ),
            Err(BackupDestinationError::Unauthenticated)
        );
        let first_request = request(20, 30, 0)?;
        let first = service.configure(&headers, now, first_request.clone())?;
        assert_eq!(first.committed_revision, 4);
        service.configure(&headers, now, request(21, 31, 0)?)?;
        let mut pause = request(22, 30, first.committed_revision)?;
        pause.enabled = false;
        let paused = service.configure(&headers, now, pause)?;
        assert_eq!(paused.committed_revision, 6);
        assert_eq!(
            service.configure(&headers, UnixMicros::new(50), first_request.clone())?,
            first
        );
        let mut changed = first_request;
        changed.enabled = false;
        assert_eq!(
            service.configure(&headers, now, changed),
            Err(BackupDestinationError::Conflict)
        );
        assert_eq!(
            service.configure(&headers, now, request(23, 30, 4)?),
            Err(BackupDestinationError::Conflict)
        );
        assert_inventory(&service, &headers)?;
        Ok(())
    })?;
    fixture.shutdown().await
}

fn assert_inventory(
    service: &BackupDestinationService,
    headers: &HeaderMap,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = UnixMicros::new(51);
    let first = service.list(
        headers,
        now,
        ListBackupDestinationsQuery {
            limit: Some(1),
            cursor: None,
        },
    )?;
    assert_eq!(first.destinations.len(), 1);
    assert_eq!(first.destinations[0].state, BackupDestinationStatus::Paused);
    assert_eq!(first.destinations[0].revision, 6);
    let url = first.next_page_url.ok_or("continuation missing")?;
    let raw = url.split_once('?').ok_or("query missing")?.1;
    let query = crate::backup_destination_administration::inventory::parse_query(Some(raw))?;
    let cursor = query.cursor.as_ref().ok_or("cursor missing")?;
    let future_cursor = cursor.replace(".6.", ".18446744073709551615.");
    assert_ne!(&future_cursor, cursor);
    assert_eq!(
        service.list(
            headers,
            now,
            ListBackupDestinationsQuery {
                limit: query.limit,
                cursor: Some(future_cursor),
            }
        ),
        Err(BackupDestinationError::InvalidInput)
    );
    let second = service.list(headers, now, query.clone())?;
    assert_eq!(second.destinations.len(), 1);
    assert_eq!(
        second.destinations[0].destination_id,
        format_uuid(uuid_v8([31; 16]))
    );
    assert!(second.next_page_url.is_none());
    assert_eq!(
        service.list(
            headers,
            now,
            ListBackupDestinationsQuery {
                limit: Some(2),
                ..query
            }
        ),
        Err(BackupDestinationError::InvalidInput)
    );
    Ok(())
}

async fn register_target(fixture: &RunningAuthority) -> Result<(), Box<dyn std::error::Error>> {
    fixture
        .handle
        .commit_or_resolve(
            command_context(fixture.administrator_id, 40, 41, 20, None)?,
            AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                mesh_id: MeshId::from_bytes([9; 16])?,
                bundle_digest: [92; 32],
                save_challenge_commitment: [93; 32],
            }),
        )
        .await?;
    let configuration = b"{\"usage_limit\":\"per-target\"}".to_vec();
    fixture
        .handle
        .commit_or_resolve(
            command_context(fixture.administrator_id, 42, 43, 30, None)?,
            AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
                target_id: TargetId::from_bytes(uuid_v8([32; 16]))?,
                node_id: fixture.node_id,
                host_id: HostId::from_bytes([11; 16])?,
                provider: CreateComponent {
                    instance_id: ComponentInstanceId::from_bytes(uuid_v8([33; 16]))?,
                    component_kind: 1,
                    name: RecordName::new("Folder provider")?,
                    implementation_id: "meshspan-folder".to_owned(),
                    contract_major: 1,
                    contract_minor: 0,
                    schema_version: 1,
                    configuration_digest: Sha256::digest(&configuration).into(),
                    canonical_configuration: configuration,
                },
                name: RecordName::new("Recovery folder")?,
                generation: 1,
                marker_fingerprint: [34; 32],
                backing_device_fingerprint: None,
                filesystem_fingerprint: None,
                usage_limit: StorageUsageLimit::Bytes(1_048_576),
            }),
        )
        .await?;
    Ok(())
}

fn request(
    operation: u8,
    destination: u8,
    revision: u64,
) -> Result<ConfigureBackupDestinationRequest, Box<dyn std::error::Error>> {
    Ok(ConfigureBackupDestinationRequest {
        operation_id: meshspan_api_contract::OperationId::from_uuid_bytes(uuid_v8([operation; 16]))
            .ok_or("operation ID")?,
        destination_id: format_uuid(uuid_v8([destination; 16])),
        expected_revision: revision,
        name: format!("Recovery {destination}"),
        target_id: format_uuid(uuid_v8([32; 16])),
        target_generation: "1".to_owned(),
        enabled: true,
    })
}
