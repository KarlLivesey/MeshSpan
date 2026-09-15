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
    let streams = open_stream(&internal.client, StreamKind::Data).await?;
    let stream = accept_stream(&internal.server).await?;
    let request_digest = federation_backup_relay_digest(relay.forwarded(), limits)?;
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
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        exchange_owner_stream(streams, request_digest, source, limits),
    )
    .await;
    let result = result
        .map_err(|error| format!("forwarded backup owner stream: {error}").into())
        .and_then(std::convert::identity);
    let (provider, completed) = worker.await?;
    let result = match (result, completed) {
        (Err(error), Err(completion)) => {
            return Err(format!("{error}; owner completion: {completion}").into());
        }
        (result, completion) => {
            completion?;
            result?
        }
    };
    Ok((provider, result))
}

/// The conversation owns both directions, so its timeout closes IO before the worker join.
async fn exchange_owner_stream(
    (mut send, mut receive): (quinn::SendStream, quinn::RecvStream),
    request_digest: [u8; 32],
    source: Option<&[u8]>,
    limits: WireLimits,
) -> TestResult<Outcome> {
    let message = receive_data_control(&mut receive, limits)
        .await?
        .into_inner()
        .message
        .ok_or("ready")?;
    let Message::ForwardFederatedBackupReady(ready) = message else {
        return Err("unexpected ready".into());
    };
    assert_eq!(ready.request_digest, request_digest);
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
    assert_eq!(result.request_digest, request_digest);
    let result = result.result.ok_or("result payload")?;
    assert!(result.signature.is_empty());
    Ok(result.outcome.ok_or("outcome")?)
}

#[tokio::test]
async fn timed_out_owner_exchange_closes_upload_before_joining_worker() -> TestResult<()> {
    let limits = WireLimits::new(8192, 16384, 256, 4096)?;
    let internal = InternalConnection::new(limits).await?;
    let streams = open_stream(&internal.client, StreamKind::Data).await?;
    let mut accepted = accept_stream(&internal.server).await?;
    let (release, gated) = tokio::sync::oneshot::channel();
    let mut worker = tokio::spawn(async move {
        let _withheld_ready = accepted.send;
        gated.await?;
        // Ready is deliberately withheld until after the client's exchange deadline.
        // The connection stays live: only cancellation of this upload can end this read.
        let mut byte = [0_u8; 1];
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(accepted.receive.read(&mut byte).await?)
    });
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        exchange_owner_stream(streams, [31; 32], Some(PAYLOAD), limits),
    )
    .await;
    let timed_out = outcome.is_err();
    release.send(()).map_err(|()| "owner gate closed")?;
    let completed = tokio::time::timeout(std::time::Duration::from_secs(1), &mut worker).await;
    let connection_remained_live =
        internal.client.close_reason().is_none() && internal.server.close_reason().is_none();
    // Even the deliberately failing borrowed-stream baseline observes its owned worker.
    internal.close().await;
    let read = match completed {
        Ok(result) => result
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?,
        Err(error) => {
            let joined = worker.await.map_err(|error| error.to_string())?;
            assert!(
                joined.is_err(),
                "closing the connection must end the retained upload"
            );
            return Err(
                format!("timed-out client retained upload while joining owner: {error}").into(),
            );
        }
    };
    assert!(
        timed_out,
        "withheld Ready must produce an unknown timeout outcome"
    );
    assert!(
        connection_remained_live,
        "upload cancellation closed the connection"
    );
    assert_eq!(
        read, None,
        "canceled client unexpectedly supplied upload bytes"
    );
    Ok(())
}
