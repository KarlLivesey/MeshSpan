// SPDX-License-Identifier: GPL-2.0-only

use super::{RunningAuthority, command_context};
use crate::create_mesh_setup::format_uuid;
use crate::{
    BackupHistoryController, BackupHistoryService, BackupScheduleError,
    ConsensusAuthenticationAuthority, GatewaySessionIdentity,
};
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::ListBackupRunsQuery;
use meshspan_domain::{AuthenticationMethodId, PartitionId, UnixMicros, uuid_v8};
use meshspan_metadata::{AuthoritativeCommand, RevokeAuthenticationMethod};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_history_binds_continuations_and_rechecks_committed_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let partition = PartitionId::from_bytes(uuid_v8([2; 16]))?;
    let mut fixture = RunningAuthority::start_with_partition(partition).await?;
    let reader = fixture.reader.take().ok_or("reader consumed")?;
    let authority = ConsensusAuthenticationAuthority::new(
        reader,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let service =
        BackupHistoryService::new(authority, GatewaySessionIdentity::new(fixture.node_id, 1)?);
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Bearer {}",
            fixture.api_key.expose_encoded().as_str()
        ))?,
    );
    let cursor = format!(
        "v1.bkr.{}.{}.1.1.2",
        format_uuid(partition.as_bytes()),
        format_uuid(fixture.administrator_id.as_bytes())
    );
    let query = ListBackupRunsQuery {
        limit: Some(1),
        cursor: Some(cursor.clone()),
    };
    tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        assert!(
            service
                .list(&headers, UnixMicros::new(40), &query)?
                .runs
                .is_empty()
        );
        for invalid in [
            ListBackupRunsQuery {
                limit: Some(2),
                ..query.clone()
            },
            ListBackupRunsQuery {
                cursor: Some(cursor.replace(".1.1.2", ".1.999.2")),
                ..query.clone()
            },
            ListBackupRunsQuery {
                cursor: Some(cursor.replace(
                    &format_uuid(partition.as_bytes()),
                    &format_uuid(uuid_v8([3; 16])),
                )),
                ..query.clone()
            },
            ListBackupRunsQuery {
                cursor: Some(cursor.replace(
                    &format_uuid(fixture.administrator_id.as_bytes()),
                    &format_uuid(uuid_v8([4; 16])),
                )),
                ..query.clone()
            },
            ListBackupRunsQuery {
                cursor: Some(format!("{cursor}0.")),
                ..query.clone()
            },
        ] {
            assert_eq!(
                service.list(&headers, UnixMicros::new(40), &invalid),
                Err(BackupScheduleError::InvalidInput)
            );
        }
        Ok(())
    })?;
    fixture
        .handle
        .commit_or_resolve(
            command_context(fixture.administrator_id, 80, 81, 50, None)?,
            AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([12; 16])?,
                principal_id: fixture.administrator_id,
                reason: "Revoke history access".to_owned(),
            }),
        )
        .await?;
    tokio::task::block_in_place(|| {
        assert_eq!(
            service.list(&headers, UnixMicros::new(51), &query),
            Err(BackupScheduleError::Unauthenticated)
        );
    });
    fixture.shutdown().await
}
