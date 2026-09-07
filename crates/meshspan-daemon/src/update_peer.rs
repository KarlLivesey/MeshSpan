// SPDX-License-Identifier: GPL-2.0-only

//! Signed executable bytes use private data streams, never the consensus log.

use crate::update_artifact_store::{
    ArtifactChunk, ArtifactStoreError, TRANSFER_FRAME_BYTES, UpdateArtifactStore,
};
use meshspan_domain::{UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeRepository, UpdateManifest, UpdateRolloutRecord, UpdateRolloutState,
};
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, DataFrame, GetUpdateArtifactHeader, GetUpdateArtifactRequest,
        GetUpdateArtifactResult, UpdateArtifactIdentity, data_control_envelope::Message,
    },
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedPeer, StreamKind, receive_data_control, receive_data_frame,
    send_data_control, send_data_frame,
};
use sha2::{Digest as _, Sha256};
use std::{fs::File, path::Path, time::Duration};
use tokio::{io::AsyncReadExt, sync::mpsc};

pub(crate) const DEADLINE: Duration = Duration::from_mins(30);

/// Rechecks immutable candidate authentication and current explicit publisher enablement.
pub(crate) fn candidate(
    repository: &AuthoritativeRepository,
    id: WorkId,
) -> Result<UpdateRolloutRecord, UpdatePeerError> {
    let record = repository
        .update_rollout(id)?
        .ok_or(UpdatePeerError::Rejected)?;
    if !matches!(
        record.state,
        UpdateRolloutState::Running | UpdateRolloutState::Paused
    ) || !repository
        .update_signers()?
        .iter()
        .any(|key| key.signer_id == record.signer_id && key.enabled)
    {
        return Err(UpdatePeerError::Rejected);
    }
    Ok(record)
}

pub(crate) fn identity(
    id: WorkId,
    manifest: &UpdateManifest,
    target: &str,
) -> Result<UpdateArtifactIdentity, UpdatePeerError> {
    let artifact = manifest
        .artifact(target)
        .map_err(|_| UpdatePeerError::Rejected)?;
    let digest = artifact
        .sha256
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| UpdatePeerError::Rejected)?;
            u8::from_str_radix(text, 16).map_err(|_| UpdatePeerError::Rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UpdateArtifactIdentity {
        rollout_id: id.as_bytes().to_vec(),
        target: target.to_owned(),
        byte_length: artifact.size,
        digest,
    })
}

/// Runs only in an owned blocking job. Identity/authority checks precede executable IO.
pub(crate) fn prepare_source(
    repository: &AuthoritativeRepository,
    directory: &Path,
    peer: AuthenticatedPeer,
    request: &GetUpdateArtifactRequest,
    now: UnixMicros,
) -> Result<(UpdateArtifactIdentity, File), UpdatePeerError> {
    let header = request.header.as_ref().ok_or(UpdatePeerError::Rejected)?;
    let declared = request.artifact.as_ref().ok_or(UpdatePeerError::Rejected)?;
    let mesh = repository
        .local_mesh_id()?
        .ok_or(UpdatePeerError::Rejected)?;
    let active = repository
        .node_activation(peer.node_id())?
        .ok_or(UpdatePeerError::Rejected)?;
    let certificate = repository
        .active_node_certificate(peer.node_id())?
        .ok_or(UpdatePeerError::Rejected)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != repository.partition_id().as_bytes()
        || header.sender_node_id.as_slice() != peer.node_id().as_bytes()
        || header.sender_incarnation != peer.incarnation()
        || active.incarnation != peer.incarnation()
        || certificate.incarnation != peer.incarnation()
        || certificate.certificate_fingerprint != peer.certificate_fingerprint()
        || certificate.valid_until <= now
        || header.deadline_unix_micros <= now.get()
    {
        return Err(UpdatePeerError::Rejected);
    }
    let id = WorkId::from_bytes(
        declared
            .rollout_id
            .as_slice()
            .try_into()
            .map_err(|_| UpdatePeerError::Rejected)?,
    )
    .map_err(|_| UpdatePeerError::Rejected)?;
    let record = candidate(repository, id)?;
    let expected = identity(id, &record.manifest, &declared.target)?;
    if &expected != declared {
        return Err(UpdatePeerError::Rejected);
    }
    let file =
        UpdateArtifactStore::open(directory)?.open_verified(&record.manifest, &declared.target)?;
    Ok((expected, file))
}

pub(crate) async fn send(
    mut stream: AcceptedStream,
    expected: UpdateArtifactIdentity,
    file: File,
    limits: WireLimits,
    deadline: tokio::time::Instant,
) -> Result<(), UpdatePeerError> {
    if stream.kind != StreamKind::Data {
        return Err(UpdatePeerError::Rejected);
    }
    let transfer = async {
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::GetUpdateArtifactHeader(GetUpdateArtifactHeader {
                    artifact: Some(expected.clone()),
                })),
            },
            limits,
        )
        .await?;
        let mut file = tokio::fs::File::from_std(file);
        let mut bytes = vec![0; TRANSFER_FRAME_BYTES.min(limits.maximum_data_frame_bytes())];
        let mut offset = 0_u64;
        let mut digest = Sha256::new();
        loop {
            let count = file.read(&mut bytes).await?;
            if count == 0 {
                break;
            }
            let end = offset
                .checked_add(count as u64)
                .ok_or(UpdatePeerError::Rejected)?;
            if end > expected.byte_length {
                return Err(UpdatePeerError::Rejected);
            }
            digest.update(&bytes[..count]);
            send_data_frame(
                &mut stream.send,
                &DataFrame {
                    offset,
                    bytes: bytes[..count].to_vec(),
                },
                limits,
            )
            .await?;
            offset = end;
        }
        if offset != expected.byte_length || digest.finalize().as_slice() != expected.digest {
            return Err(UpdatePeerError::Rejected);
        }
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::GetUpdateArtifactResult(GetUpdateArtifactResult {
                    artifact: Some(expected),
                })),
            },
            limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(())
    };
    tokio::time::timeout_at(deadline, transfer)
        .await
        .map_err(|_| UpdatePeerError::Unavailable)?
}

/// Only sends Finish to the cache verifier after the exact terminal response and EOF.
pub(crate) async fn receive(
    stream: AcceptedStream,
    request: GetUpdateArtifactRequest,
    chunks: mpsc::Sender<ArtifactChunk>,
    limits: WireLimits,
) -> Result<(), UpdatePeerError> {
    let expected = request.artifact.clone().ok_or(UpdatePeerError::Rejected)?;
    if stream.kind != StreamKind::Data {
        return Err(UpdatePeerError::Rejected);
    }
    let AcceptedStream {
        mut send,
        mut receive,
        ..
    } = stream;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::GetUpdateArtifactRequest(request)),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    let header = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    if !matches!(header.message, Some(Message::GetUpdateArtifactHeader(value)) if value.artifact.as_ref() == Some(&expected))
    {
        return Err(UpdatePeerError::Rejected);
    }
    let mut offset = 0_u64;
    while offset < expected.byte_length {
        let frame = receive_data_frame(&mut receive, limits).await?.into_inner();
        if frame.offset != offset || frame.bytes.is_empty() {
            return Err(UpdatePeerError::Rejected);
        }
        offset = offset
            .checked_add(frame.bytes.len() as u64)
            .ok_or(UpdatePeerError::Rejected)?;
        if offset > expected.byte_length {
            return Err(UpdatePeerError::Rejected);
        }
        chunks
            .send(ArtifactChunk::Bytes(frame.bytes.into()))
            .await
            .map_err(|_| UpdatePeerError::Unavailable)?;
    }
    let result = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    if !matches!(result.message, Some(Message::GetUpdateArtifactResult(value)) if value.artifact.as_ref() == Some(&expected))
    {
        return Err(UpdatePeerError::Rejected);
    }
    if receive
        .read(&mut [0_u8; 1])
        .await
        .map_err(|_| UpdatePeerError::Unavailable)?
        .is_some()
    {
        return Err(UpdatePeerError::Rejected);
    }
    chunks
        .send(ArtifactChunk::Finish)
        .await
        .map_err(|_| UpdatePeerError::Unavailable)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdatePeerError {
    #[error("update peer evidence rejected")]
    Rejected,
    #[error("update peer is unavailable")]
    Unavailable,
    #[error("update metadata is unavailable")]
    Metadata(#[from] meshspan_metadata::RepositoryError),
    #[error("update artifact is unavailable")]
    Artifact(#[from] ArtifactStoreError),
    #[error("update stream failed")]
    Transport(#[from] meshspan_transport::TransportError),
    #[error("update file IO failed")]
    Io(#[from] std::io::Error),
}
