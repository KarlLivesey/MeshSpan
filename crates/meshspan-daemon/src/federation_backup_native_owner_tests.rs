// SPDX-License-Identifier: GPL-2.0-only

//! Native owner ingress consumes real signed capabilities and shares registered-folder quotas.

use super::super::relay::InternalConnection;
use super::{Client, RunningAuthority, TestResult, context, interruption};
use crate::federation_sessions::{
    FederationBackupOwner, FederationSessionRuntimeError, FederationSessions,
};
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectReference, BackupProvider, BackupReadRequest,
    BackupVerifyRequest, ContractError, FederatedBackupRequest, FederatedBackupScope,
};
use meshspan_domain::{Clock, NodeId, Revision};
use meshspan_protocol::{
    encode_federation_frame,
    v1::{
        DataControlEnvelope, DataFrame, ForwardFederatedBackupRequest, RequestHeader,
        data_control_envelope::Message, federated_backup_result::Outcome,
    },
};
use meshspan_transport::{
    PeerBinding, PeerRegistry, StreamKind, accept_stream, open_stream, receive_data_control,
    receive_data_frame, send_data_control, send_data_frame,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type OwnerWorker = tokio::task::JoinHandle<Result<(), FederationSessionRuntimeError>>;
const OWNER_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub(super) async fn verify(
    client: &mut Client<'_, '_>,
    fixture: &RunningAuthority,
    sessions: &Arc<FederationSessions>,
    internal: InternalConnection,
) -> TestResult<()> {
    let owner = FederationBackupOwner::default();
    owner.attach(sessions)?;
    let mut request = super::super::request(crate::OperatingSystemClock.now())?;
    let FederatedBackupRequest::Store(store) = &mut request else {
        return Err("store".into());
    };
    store.context = context(230)?;
    let object = store.object;
    let bytes = [214_u8; 1024];
    let mut connection = OwnerConnection {
        owner,
        internal,
        partition: super::super::authority(fixture)?.reader().partition_id(),
    };
    let result = connection.cycle(client, &request, &bytes[..5]).await?;
    assert!(
        matches!(result, Outcome::Rejection(error) if error.code == i32::from(meshspan_protocol::v1::ErrorCode::Unavailable))
    );
    // An interrupted admitted upload retains its uncertain charge until exact retry resolves it.
    interruption::assert_usage(fixture, client.scope, 0, 1024)?;
    let result = connection.cycle(client, &request, &bytes).await?;
    let Outcome::Stored(receipt) = &result else {
        return Err("owner stored receipt".into());
    };
    assert_eq!(receipt.operation_id, [230; 16]);
    assert_eq!(
        receipt.object.as_ref().ok_or("object")?.digest,
        object.digest
    );
    let reference = BackupObjectReference::new(receipt.object_reference.clone())?;
    interruption::assert_usage(fixture, client.scope, 1024, 0)?;
    assert_eq!(connection.cycle(client, &request, &bytes).await?, result);
    // Direct and forwarded requests must reuse one catalogue, not fight for its exclusive lock.
    let read_request = BackupReadRequest {
        context: context(231)?,
        object,
        object_reference: reference.clone(),
    };
    let read = FederatedBackupRequest::Read(read_request.clone());
    assert!(matches!(
        connection.cycle(client, &read, &bytes).await?,
        Outcome::Read(_)
    ));
    connection
        .verify_sequential_read_after_terminal_fin(client, sessions, &read, &bytes)
        .await
        .map_err(|error| format!("native owner sequential read completion: {error}"))?;
    let registry = Arc::clone(sessions);
    let scope = client.scope;
    tokio::task::spawn_blocking(move || {
        verify_physical_read_exclusion(&registry, scope, &read_request, &bytes)
            .map_err(|error| error.to_string())
    })
    .await?
    .map_err(|error| format!("native owner physical read exclusion: {error}"))?;
    let verify = FederatedBackupRequest::Verify(BackupVerifyRequest {
        context: context(232)?,
        object,
        object_reference: reference.clone(),
    });
    assert!(matches!(
        client.cycle(&verify, &[]).await.map_err(|error| format!(
            "direct verification after native read lifetime proofs: {error}"
        ))?,
        Outcome::Verified(_)
    ));
    assert!(matches!(
        connection.cycle(client, &verify, &[]).await?,
        Outcome::Verified(_)
    ));
    let delete = FederatedBackupRequest::Delete(BackupDeleteRequest {
        context: context(233)?,
        object,
        object_reference: reference,
        retirement_revision: Revision::new(1),
    });
    assert!(matches!(
        connection.cycle(client, &delete, &[]).await?,
        Outcome::Deleted(_)
    ));
    interruption::assert_usage(fixture, client.scope, 0, 0)?;
    connection.internal.close().await;
    Ok(())
}

/// This controls a real provider write callback, not the later wire-completion seam.
fn verify_physical_read_exclusion(
    sessions: &FederationSessions,
    scope: FederatedBackupScope,
    request: &BackupReadRequest,
    expected: &[u8],
) -> TestResult<()> {
    let first = sessions.bind_backup_provider_for_test(scope, request.object)?;
    let second = sessions.bind_backup_provider_for_test(scope, request.object)?;
    let mut substituted = request.clone();
    substituted.object.backup_id = meshspan_domain::BackupId::from_bytes([234; 16])?;
    assert_ne!(substituted.object, request.object);
    let deadline = std::time::Instant::now() + proof_timeout(request.context.deadline);
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|threads| -> TestResult<()> {
        let worker = threads.spawn(|| {
            let mut sink = PausedReadSink {
                gate: Some((entered, released)),
                deadline,
                bytes: Vec::new(),
            };
            let receipt = first.read_exact(request, &mut sink, crate::OperatingSystemClock.now());
            (receipt, sink.bytes)
        });
        let entered =
            observed.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
        let mut competing_bytes = Vec::new();
        let competing = second.read_exact(
            request,
            &mut competing_bytes,
            crate::OperatingSystemClock.now(),
        );
        let mut substituted_bytes = Vec::new();
        let rejected = second.read_exact(
            &substituted,
            &mut substituted_bytes,
            crate::OperatingSystemClock.now(),
        );
        // Release and join even if admission returned an unexpected outcome.
        let released = release.send(());
        let completed = worker.join().map_err(|_| "physical read worker panicked")?;
        entered?;
        released.map_err(|_| "physical read gate closed")?;
        assert!(matches!(competing, Err(ContractError::Unavailable)));
        assert!(competing_bytes.is_empty());
        assert!(matches!(rejected, Err(ContractError::InvalidInput)));
        assert!(substituted_bytes.is_empty());
        let receipt = completed.0?;
        assert_eq!(completed.1, expected);
        assert_eq!(receipt.operation_id, request.context.operation_id);
        assert_eq!(receipt.byte_length, request.object.byte_length);
        assert_eq!(receipt.digest, request.object.digest);
        let mut next_bytes = Vec::new();
        let next =
            second.read_exact(request, &mut next_bytes, crate::OperatingSystemClock.now())?;
        assert_eq!(next_bytes, expected);
        assert_eq!(next, receipt);
        Ok(())
    })
}

struct PausedReadSink {
    gate: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
    deadline: std::time::Instant,
    bytes: Vec<u8>,
}

impl std::io::Write for PausedReadSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some((entered, released)) = self.gate.take() {
            entered
                .send(())
                .map_err(|_| std::io::Error::other("read observer closed"))?;
            // A regression from try_lock to a blocking lock cannot deadlock the second
            // read: this physical callback ends at the existing proof/request deadline.
            released
                .recv_timeout(
                    self.deadline
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn proof_timeout(deadline: meshspan_domain::UnixMicros) -> std::time::Duration {
    let remaining = deadline
        .get()
        .saturating_sub(crate::OperatingSystemClock.now().get());
    std::time::Duration::from_micros(u64::try_from(remaining).unwrap_or(0))
        .min(OWNER_EXCHANGE_TIMEOUT)
}

struct OwnerConnection {
    owner: FederationBackupOwner,
    internal: InternalConnection,
    partition: meshspan_domain::PartitionId,
}

impl OwnerConnection {
    async fn verify_sequential_read_after_terminal_fin(
        &mut self,
        client: &mut Client<'_, '_>,
        sessions: &FederationSessions,
        read: &FederatedBackupRequest,
        bytes: &[u8],
    ) -> TestResult<()> {
        let (entered, release) =
            sessions.pause_backup_provider_completion(client.scope, read.object())?;
        let (first, first_worker) = self
            .exchange(client, read, bytes)
            .await
            .map_err(|error| format!("first sequential read capability/setup: {error}"))?;
        let first = match first {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(release);
                let completed = first_worker.await?;
                return Err(format!("first read: {error}; owner completion: {completed:?}").into());
            }
        };
        // exchange independently consumes the exact receipt and clean FIN, without joining
        // the storage worker. Its physical provider call has ended before this terminal seam.
        let paused = tokio::time::timeout(proof_timeout(read.context().deadline), entered).await;
        let second = if matches!(paused, Ok(Ok(()))) {
            self.exchange(client, read, bytes).await
        } else {
            Err("owner terminal completion gate did not signal before the proof deadline".into())
        };
        // Release first, then observe both workers before propagating either join error.
        let released = release.send(());
        let (first_completed, second) = match second {
            Ok((outcome, worker)) => {
                let (first, second) = tokio::join!(first_worker, worker);
                (first, Ok((outcome, second)))
            }
            Err(error) => (first_worker.await, Err(error)),
        };
        let first_completed = first_completed?;
        let (second, second_completed) =
            second.map_err(|error| format!("second sequential read capability/setup: {error}"))?;
        let second_completed = second_completed?;
        paused??;
        released.map_err(|()| "provider completion gate closed")?;
        first_completed?;
        let Outcome::Read(receipt) = &first else {
            return Err("first sequential owner read receipt".into());
        };
        assert_eq!(receipt.operation_id, read.context().operation_id.as_bytes());
        assert_eq!(receipt.byte_length, read.object().byte_length);
        assert_eq!(receipt.digest, read.object().digest);
        if let Err(error) = &second_completed {
            assert!(matches!(error, FederationSessionRuntimeError::Unavailable));
            assert!(second.is_err(), "busy owner must not return a read receipt");
        }
        assert!(
            second_completed.is_ok(),
            "a read after verified terminal result and FIN must not be rejected by the previous completed owner's slot: {second_completed:?}; client received result: {}",
            second.is_ok()
        );
        assert_eq!(second?, first);
        Ok(())
    }

    async fn cycle(
        &mut self,
        client: &mut Client<'_, '_>,
        request: &FederatedBackupRequest,
        bytes: &[u8],
    ) -> TestResult<Outcome> {
        let (result, worker) = self.exchange(client, request, bytes).await?;
        let completed = worker.await?;
        match (result, completed) {
            (Err(error), Err(completion)) => {
                Err(format!("{error}; native owner completion: {completion}").into())
            }
            (result, completion) => {
                completion?;
                result.map_err(|error| {
                    format!(
                        "native owner exchange for operation {:?}: {error}",
                        request.context().operation_id
                    )
                    .into()
                })
            }
        }
    }

    async fn exchange(
        &mut self,
        client: &mut Client<'_, '_>,
        request: &FederatedBackupRequest,
        bytes: &[u8],
    ) -> TestResult<(TestResult<Outcome>, OwnerWorker)> {
        let outbound = client.permit(request).await.map_err(|error| {
            format!(
                "native owner capability for operation {:?}: {error}",
                request.context().operation_id
            )
        })?;
        let header = outbound.envelope().header.as_ref().ok_or("header")?;
        let limits = client.session.limits.wire;
        let gateway = NodeId::from_bytes([180; 16])?;
        let peer = PeerRegistry::new([PeerBinding {
            node_id: gateway,
            incarnation: 1,
            certificate_fingerprint: Sha256::digest(&self.internal.client_certificate).into(),
        }])?
        .authenticate_connection(&self.internal.server)?;
        let forwarded = ForwardFederatedBackupRequest {
            header: Some(RequestHeader {
                version: header.version,
                mesh_id: client.scope.provider_mesh_id.as_bytes().to_vec(),
                partition_id: self.partition.as_bytes().to_vec(),
                routing_epoch: 1,
                sender_node_id: gateway.as_bytes().to_vec(),
                sender_incarnation: 1,
                request_id: header.request_id.clone(),
                operation_id: header.operation_id.clone(),
                trace_id: header.trace_id.clone(),
                deadline_unix_micros: header.deadline_unix_micros,
            }),
            provider_node_id: client.scope.provider_node_id.as_bytes().to_vec(),
            request: encode_federation_frame(outbound.envelope(), limits)?,
            maximum_frame_bytes: 64,
        };
        let digest = meshspan_transport::federation_backup_relay_digest(&forwarded, limits)?;
        let (mut send, receive) = open_stream(&self.internal.client, StreamKind::Data).await?;
        let mut accepted = accept_stream(&self.internal.server).await?;
        send_data_control(
            &mut send,
            &DataControlEnvelope {
                message: Some(Message::ForwardFederatedBackupRequest(forwarded)),
            },
            limits,
        )
        .await?;
        let envelope = receive_data_control(&mut accepted.receive, limits).await?;
        let owner = self.owner.clone();
        let worker = tokio::spawn(async move {
            owner
                .serve(
                    meshspan_cluster::PeerDataStream {
                        peer,
                        stream: accepted,
                        limits,
                        routing_epoch: 1,
                    },
                    envelope,
                )
                .await
        });
        let result = tokio::time::timeout(
            OWNER_EXCHANGE_TIMEOUT,
            verify_owner_response((send, receive), request, bytes, limits, digest),
        )
        .await;
        let result = result.map_err(|error| {
            format!(
                "native backup owner exchange for operation {:?}: {error}",
                request.context().operation_id
            )
        });
        Ok((
            result.map_err(Into::into).and_then(std::convert::identity),
            worker,
        ))
    }
}

/// Own the response stream through exact framing, receipt correlation and terminal FIN.
async fn verify_owner_response(
    streams: (quinn::SendStream, quinn::RecvStream),
    request: &FederatedBackupRequest,
    bytes: &[u8],
    limits: meshspan_protocol::WireLimits,
    digest: [u8; 32],
) -> TestResult<Outcome> {
    let (mut send, mut receive) = streams;
    let ready = receive_data_control(&mut receive, limits)
        .await
        .map_err(|error| format!("owner Ready receive: {error}"))?
        .into_inner();
    let Some(Message::ForwardFederatedBackupReady(ready)) = ready.message else {
        return Err("owner ready".into());
    };
    assert_eq!(ready.request_digest, digest);
    let ready = ready.ready.ok_or("ready payload")?;
    assert!(ready.rejection.is_none());
    assert_eq!(ready.maximum_frame_bytes, 64);
    exchange_bytes(&mut send, &mut receive, request, bytes, limits)
        .await
        .map_err(|error| format!("owner byte exchange: {error}"))?;
    let result = receive_data_control(&mut receive, limits)
        .await
        .map_err(|error| format!("owner terminal result receive: {error}"))?
        .into_inner();
    let Some(Message::ForwardFederatedBackupResult(result)) = result.message else {
        return Err("owner result".into());
    };
    assert_eq!(result.request_digest, digest);
    let result = result.result.ok_or("result payload")?;
    assert!(result.signature.is_empty());
    let mut trailing = [0_u8; 1];
    assert_eq!(
        receive
            .read(&mut trailing)
            .await
            .map_err(|error| format!("owner terminal FIN receive: {error}"))?,
        None,
        "clean terminal FIN"
    );
    Ok::<_, Box<dyn std::error::Error>>(result.outcome.ok_or("outcome")?)
}

/// The independent client checks upload/download framing separately from control correlation.
async fn exchange_bytes(
    send: &mut quinn::SendStream,
    receive: &mut quinn::RecvStream,
    request: &FederatedBackupRequest,
    bytes: &[u8],
    limits: meshspan_protocol::WireLimits,
) -> TestResult<()> {
    match request {
        FederatedBackupRequest::Store(_) => {
            for (index, chunk) in bytes.chunks(64).enumerate() {
                send_data_frame(
                    send,
                    &DataFrame {
                        offset: u64::try_from(index)? * 64,
                        bytes: chunk.to_vec(),
                    },
                    limits,
                )
                .await?;
            }
        }
        FederatedBackupRequest::Read(_) => {
            let mut read = Vec::new();
            while read.len() < bytes.len() {
                let frame = receive_data_frame(receive, limits).await?;
                assert_eq!(frame.as_inner().offset, read.len() as u64);
                read.extend_from_slice(&frame.as_inner().bytes);
            }
            assert_eq!(read, bytes);
        }
        FederatedBackupRequest::Lookup(_)
        | FederatedBackupRequest::Verify(_)
        | FederatedBackupRequest::Delete(_) => {}
    }
    send.finish()?;
    Ok(())
}
