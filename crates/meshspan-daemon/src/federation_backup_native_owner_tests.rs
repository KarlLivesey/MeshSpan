// SPDX-License-Identifier: GPL-2.0-only

//! Native owner ingress consumes real signed capabilities and shares registered-folder quotas.

use super::super::relay::InternalConnection;
use super::{Client, RunningAuthority, TestResult, context, interruption};
use crate::federation_sessions::{FederationBackupOwner, FederationSessions};
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectReference, BackupReadRequest, BackupVerifyRequest,
    FederatedBackupRequest,
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
    let read = FederatedBackupRequest::Read(BackupReadRequest {
        context: context(231)?,
        object,
        object_reference: reference.clone(),
    });
    assert!(matches!(
        connection.cycle(client, &read, &bytes).await?,
        Outcome::Read(_)
    ));
    let verify = FederatedBackupRequest::Verify(BackupVerifyRequest {
        context: context(232)?,
        object,
        object_reference: reference.clone(),
    });
    assert!(matches!(
        client.cycle(&verify, &[]).await?,
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

struct OwnerConnection {
    owner: FederationBackupOwner,
    internal: InternalConnection,
    partition: meshspan_domain::PartitionId,
}

impl OwnerConnection {
    async fn cycle(
        &mut self,
        client: &mut Client<'_, '_>,
        request: &FederatedBackupRequest,
        bytes: &[u8],
    ) -> TestResult<Outcome> {
        let outbound = client.permit(request).await?;
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
        let (mut send, mut receive) = open_stream(&self.internal.client, StreamKind::Data).await?;
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
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let ready = receive_data_control(&mut receive, limits)
                .await?
                .into_inner();
            let Some(Message::ForwardFederatedBackupReady(ready)) = ready.message else {
                return Err("owner ready".into());
            };
            assert_eq!(ready.request_digest, digest);
            let ready = ready.ready.ok_or("ready payload")?;
            assert!(ready.rejection.is_none());
            assert_eq!(ready.maximum_frame_bytes, 64);
            exchange_bytes(&mut send, &mut receive, request, bytes, limits).await?;
            let result = receive_data_control(&mut receive, limits)
                .await?
                .into_inner();
            let Some(Message::ForwardFederatedBackupResult(result)) = result.message else {
                return Err("owner result".into());
            };
            assert_eq!(result.request_digest, digest);
            let result = result.result.ok_or("result payload")?;
            assert!(result.signature.is_empty());
            Ok::<_, Box<dyn std::error::Error>>(result.outcome.ok_or("outcome")?)
        })
        .await;
        worker.await??;
        result.map_err(|error| {
            format!(
                "native backup owner exchange for operation {:?}: {error}",
                request.context().operation_id
            )
        })?
    }
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
