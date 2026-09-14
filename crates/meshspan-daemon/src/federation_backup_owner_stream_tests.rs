// SPDX-License-Identifier: GPL-2.0-only

//! Already-admitted owner operations retain provider capacity and exact FIN/digest semantics.

use super::{InternalConnection, RunningAuthority, TestResult, authority};
use meshspan_backup::{DirectoryBackupProvider, NamespacedBackupProvider};
use meshspan_cluster::{FederationBackupOwnerService, FederationBackupOwnerStreamContext};
use meshspan_contracts::{BackupProvider, BackupReadRequest, FederatedBackupRequest};
use meshspan_domain::{Clock, OperationId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::{
    WireLimits,
    v1::{DataFrame, data_control_envelope::Message, federated_backup_result::Outcome},
};
use meshspan_transport::{
    AuthenticatedFederationBackupRelay, StreamKind, accept_stream, federation_backup_relay_digest,
    open_stream, receive_data_control, send_data_frame,
};

type Provider = NamespacedBackupProvider<DirectoryBackupProvider>;
const PAYLOAD: &[u8] = &[214; 1024];

pub(super) async fn verify(
    fixture: &RunningAuthority,
    relay: &AuthenticatedFederationBackupRelay,
    internal: &InternalConnection,
    limits: WireLimits,
) -> TestResult<()> {
    let now = crate::OperatingSystemClock.now();
    let authority = authority(fixture)?;
    let admitted = meshspan_cluster::authorise_forwarded_backup(
        authority.reader(),
        fixture.node_id,
        1,
        relay,
        now,
    )?;
    let directory = tempfile::tempdir()?;
    let rejected = directory.path().join("small");
    let stored = directory.path().join("normal");
    std::fs::create_dir_all(&rejected)?;
    std::fs::create_dir_all(&stored)?;
    let physical = meshspan_contracts::federated_provider_backup_identity(
        admitted.scope(),
        admitted.request().object(),
    )?;
    let open = |root: &std::path::Path, capacity| -> TestResult<Provider> {
        Ok(NamespacedBackupProvider::new(
            admitted.scope(),
            admitted.request().object(),
            DirectoryBackupProvider::open(
                root,
                physical.destination_id,
                physical.provider_generation,
                capacity,
                now,
            )?,
        )?)
    };
    let (small, result) = cycle(
        fixture,
        relay,
        internal,
        (open(&rejected, 512)?, None),
        limits,
    )
    .await?;
    assert!(
        matches!(result, Outcome::Rejection(error) if error.code == i32::from(meshspan_protocol::v1::ErrorCode::Exhausted))
    );
    drop(small);
    let (provider, result) = cycle(
        fixture,
        relay,
        internal,
        (open(&stored, 2048)?, Some(&PAYLOAD[..5])),
        limits,
    )
    .await?;
    assert!(
        matches!(result, Outcome::Rejection(error) if error.code == i32::from(meshspan_protocol::v1::ErrorCode::Unavailable))
    );
    drop(provider); // Actual exclusive catalogue reopen after the incomplete owner upload.
    let (provider, result) = cycle(
        fixture,
        relay,
        internal,
        (open(&stored, 2048)?, Some(PAYLOAD)),
        limits,
    )
    .await?;
    let Outcome::Stored(receipt) = &result else {
        return Err("missing owner store receipt".into());
    };
    assert_eq!(receipt.object.as_ref().ok_or("object")?.byte_length, 1024);
    assert_eq!(
        receipt.operation_id,
        admitted.request().context().operation_id.as_bytes()
    );
    let reference =
        meshspan_contracts::BackupObjectReference::new(receipt.object_reference.clone())?;
    let (provider, replayed) =
        cycle(fixture, relay, internal, (provider, Some(PAYLOAD)), limits).await?;
    assert_eq!(replayed, result);
    let FederatedBackupRequest::Store(request) = admitted.request() else {
        return Err("store request".into());
    };
    let mut bytes = Vec::new();
    provider.read_exact(
        &BackupReadRequest {
            context: meshspan_contracts::RequestContext {
                operation_id: OperationId::from_bytes([194; 16])?,
                ..request.context
            },
            object: request.object,
            object_reference: reference,
        },
        &mut bytes,
        crate::OperatingSystemClock.now(),
    )?;
    assert_eq!(bytes, PAYLOAD);
    Ok(())
}

async fn cycle(
    fixture: &RunningAuthority,
    relay: &AuthenticatedFederationBackupRelay,
    internal: &InternalConnection,
    input: (Provider, Option<&[u8]>),
    limits: WireLimits,
) -> TestResult<(Provider, Outcome)> {
    let (mut send, mut receive) = open_stream(&internal.client, StreamKind::Data).await?;
    let stream = accept_stream(&internal.server).await?;
    let database = fixture.directory.path().join("partition.sqlite3");
    let node = fixture.node_id;
    let authenticated = relay.clone();
    let runtime = tokio::runtime::Handle::current();
    let (mut provider, source) = input;
    let worker = tokio::task::spawn_blocking(move || {
        let outcome = (|| -> TestResult<()> {
            let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
                &database,
                crate::OperatingSystemClock.now(),
            )?);
            FederationBackupOwnerService::new(&repository, node, 1).execute_stream(
                &authenticated,
                &mut provider,
                stream,
                FederationBackupOwnerStreamContext {
                    runtime: &runtime,
                    clock: &crate::OperatingSystemClock,
                    limits,
                },
            )?;
            Ok(())
        })()
        .map_err(|error| error.to_string());
        (provider, outcome)
    });
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let message = receive_data_control(&mut receive, limits)
            .await?
            .into_inner()
            .message
            .ok_or("ready")?;
        let Message::ForwardFederatedBackupReady(ready) = message else {
            return Err("unexpected ready".into());
        };
        assert_eq!(
            ready.request_digest,
            federation_backup_relay_digest(relay.forwarded(), limits)?
        );
        let ready = ready.ready.ok_or("ready payload")?;
        assert!(ready.signature.is_empty());
        if let Some(rejection) = ready.rejection {
            assert!(source.is_none(), "unexpected owner rejection");
            return Ok::<_, Box<dyn std::error::Error>>(Outcome::Rejection(rejection));
        }
        assert_eq!(ready.maximum_frame_bytes, 64);
        let source = source.ok_or("capacity rejection expected before bytes")?;
        let mut offset = 0;
        for chunk in source.chunks(64) {
            send_data_frame(
                &mut send,
                &DataFrame {
                    offset,
                    bytes: chunk.to_vec(),
                },
                limits,
            )
            .await?;
            offset += chunk.len() as u64;
        }
        send.finish()?;
        let message = receive_data_control(&mut receive, limits)
            .await?
            .into_inner()
            .message
            .ok_or("result")?;
        let Message::ForwardFederatedBackupResult(result) = message else {
            return Err("unexpected result".into());
        };
        assert_eq!(
            result.request_digest,
            federation_backup_relay_digest(relay.forwarded(), limits)?
        );
        let result = result.result.ok_or("result payload")?;
        assert!(result.signature.is_empty());
        Ok(result.outcome.ok_or("outcome")?)
    })
    .await;
    let (provider, completed) = worker.await?;
    completed?;
    Ok((provider, result??))
}
