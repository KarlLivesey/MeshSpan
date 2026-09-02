// SPDX-License-Identifier: GPL-2.0-only

//! Bounded snapshot transfer over the production authenticated network.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use meshspan_domain::NodeId;
use meshspan_metadata::PartitionSnapshotManifest;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, LogPosition, SnapshotBegin, SnapshotChunk, SnapshotFinish, SnapshotResult,
};
use meshspan_transport::{
    SnapshotStager, StreamKind, VerifiedSnapshot, open_stream, receive_control, send_control,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};

use super::{ConsensusNetwork, ConsensusNetworkError};

const SNAPSHOT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_SNAPSHOT_BYTES: u64 = 512 * 1_024 * 1_024;
const SNAPSHOT_CHUNK_BYTES: usize = 48 * 1_024;

/// One immutable repository snapshot ready for transfer to an admitted learner.
pub struct OutboundConsensusSnapshot {
    /// Owned temporary snapshot file.
    pub path: PathBuf,
    /// Integrity, position and membership facts for the exact file.
    pub manifest: PartitionSnapshotManifest,
    /// Canonical active quorum plan matching the manifest digest.
    pub quorum_plan: Vec<u8>,
}

/// One fully framed and digest-verified snapshot awaiting atomic installation.
pub struct ReceivedConsensusSnapshot {
    /// Authenticated voter which supplied the snapshot.
    pub from: NodeId,
    /// Verified staging file and exact consensus metadata.
    pub snapshot: VerifiedSnapshot,
    /// Completion signal after the receiver atomically installs the snapshot.
    pub installed: oneshot::Sender<()>,
}

impl ConsensusNetwork {
    /// Transfers one exact snapshot and waits for the authenticated learner's install receipt.
    ///
    /// # Errors
    ///
    /// Rejects route, mTLS, framing, digest, timeout and receiver-install failures.
    pub async fn send_snapshot(
        &self,
        to: NodeId,
        snapshot: &OutboundConsensusSnapshot,
    ) -> Result<(), ConsensusNetworkError> {
        tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            self.send_snapshot_inner(to, snapshot),
        )
        .await
        .map_err(|_| ConsensusNetworkError::AuthorityStopped)?
    }

    async fn send_snapshot_inner(
        &self,
        to: NodeId,
        snapshot: &OutboundConsensusSnapshot,
    ) -> Result<(), ConsensusNetworkError> {
        let connection = self.connect_peer(to).await?;
        let (mut send, mut receive) = open_stream(&connection, StreamKind::Snapshot).await?;
        let manifest = snapshot.manifest;
        let included_position = LogPosition {
            term: manifest.backup.applied_position.term,
            index: manifest.backup.applied_position.index,
        };
        self.send_snapshot_envelope(
            &mut send,
            Message::SnapshotBegin(SnapshotBegin {
                snapshot_id: manifest.snapshot_id.as_bytes().to_vec(),
                included_position: Some(included_position),
                state_revision: manifest.backup.state_revision.get(),
                total_bytes: manifest.backup.byte_length,
                digest: manifest.backup.digest.to_vec(),
                format_version: manifest.backup.schema_version,
                membership_epoch: manifest.membership_epoch,
                quorum_plan_digest: manifest.quorum_plan_digest.to_vec(),
                quorum_plan: snapshot.quorum_plan.clone(),
            }),
        )
        .await?;
        self.send_snapshot_chunks(&mut send, snapshot).await?;
        self.send_snapshot_envelope(
            &mut send,
            Message::SnapshotFinish(SnapshotFinish {
                snapshot_id: manifest.snapshot_id.as_bytes().to_vec(),
                total_bytes: manifest.backup.byte_length,
                digest: manifest.backup.digest.to_vec(),
            }),
        )
        .await?;
        send.finish()?;
        self.verify_snapshot_result(
            to,
            &mut receive,
            manifest.snapshot_id.as_bytes(),
            included_position,
        )
        .await
    }

    async fn send_snapshot_chunks(
        &self,
        send: &mut quinn::SendStream,
        snapshot: &OutboundConsensusSnapshot,
    ) -> Result<(), ConsensusNetworkError> {
        let mut file = tokio::fs::File::open(&snapshot.path).await?;
        let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_BYTES];
        let mut offset = 0_u64;
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Ok(());
            }
            let bytes = buffer[..read].to_vec();
            self.send_snapshot_envelope(
                send,
                Message::SnapshotChunk(SnapshotChunk {
                    snapshot_id: snapshot.manifest.snapshot_id.as_bytes().to_vec(),
                    offset,
                    chunk_digest: Sha256::digest(&bytes).to_vec(),
                    bytes,
                }),
            )
            .await?;
            offset = offset
                .checked_add(
                    u64::try_from(read).map_err(|_| ConsensusNetworkError::InvalidConfiguration)?,
                )
                .ok_or(ConsensusNetworkError::InvalidConfiguration)?;
        }
    }

    async fn send_snapshot_envelope(
        &self,
        send: &mut quinn::SendStream,
        message: Message,
    ) -> Result<(), ConsensusNetworkError> {
        let operation_id = meshspan_domain::OperationId::from_bytes(super::request_identifier(
            self.next_request
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .max(1),
        ))?;
        send_control(
            send,
            &ControlEnvelope {
                header: Some(self.request_header(operation_id, i64::MAX)),
                message: Some(message),
            },
            self.wire_limits,
        )
        .await?;
        Ok(())
    }

    async fn verify_snapshot_result(
        &self,
        peer: NodeId,
        receive: &mut quinn::RecvStream,
        snapshot_id: [u8; 16],
        included_position: LogPosition,
    ) -> Result<(), ConsensusNetworkError> {
        let result = receive_control(receive, self.wire_limits).await?;
        self.verify_header(&result, peer, self.peer_incarnation(peer)?)?;
        let Message::SnapshotResult(result) = result
            .as_inner()
            .message
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?
        else {
            return Err(ConsensusNetworkError::InvalidTraffic);
        };
        if result.installed
            && result.snapshot_id == snapshot_id
            && result.included_position.as_ref() == Some(&included_position)
        {
            Ok(())
        } else {
            Err(ConsensusNetworkError::InvalidTraffic)
        }
    }

    pub(super) async fn receive_snapshot(
        &self,
        peer: NodeId,
        state_path: &Path,
        stream: &mut meshspan_transport::AcceptedStream,
        snapshots: &mpsc::Sender<ReceivedConsensusSnapshot>,
    ) -> Result<(), ConsensusNetworkError> {
        let first = receive_control(&mut stream.receive, self.wire_limits).await?;
        self.verify_header(&first, peer, self.peer_incarnation(peer)?)?;
        let Message::SnapshotBegin(begin) = first
            .as_inner()
            .message
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?
        else {
            return Err(ConsensusNetworkError::InvalidTraffic);
        };
        let staging_path = snapshot_staging_path(state_path, &begin.snapshot_id)?;
        remove_stale_stage(&staging_path)?;
        let stager = SnapshotStager::begin(
            &staging_path,
            begin,
            MAXIMUM_SNAPSHOT_BYTES,
            SNAPSHOT_CHUNK_BYTES,
        )?;
        let verified = self.receive_snapshot_chunks(peer, stream, stager).await?;
        let included_position = verified.included_position;
        let snapshot_id = verified.snapshot_id;
        let (installed, receive_installed) = oneshot::channel();
        snapshots
            .send(ReceivedConsensusSnapshot {
                from: peer,
                snapshot: verified,
                installed,
            })
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
        receive_installed
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
        self.send_snapshot_result(stream, snapshot_id, included_position)
            .await
    }

    async fn receive_snapshot_chunks(
        &self,
        peer: NodeId,
        stream: &mut meshspan_transport::AcceptedStream,
        mut stager: SnapshotStager,
    ) -> Result<VerifiedSnapshot, ConsensusNetworkError> {
        loop {
            let envelope = receive_control(&mut stream.receive, self.wire_limits).await?;
            self.verify_header(&envelope, peer, self.peer_incarnation(peer)?)?;
            match envelope
                .as_inner()
                .message
                .as_ref()
                .ok_or(ConsensusNetworkError::InvalidTraffic)?
            {
                Message::SnapshotChunk(chunk) => stager.append_chunk(chunk)?,
                Message::SnapshotFinish(finish) => {
                    return stager.finish(finish).map_err(Into::into);
                }
                _ => return Err(ConsensusNetworkError::InvalidTraffic),
            }
        }
    }

    async fn send_snapshot_result(
        &self,
        stream: &mut meshspan_transport::AcceptedStream,
        snapshot_id: [u8; 16],
        included_position: LogPosition,
    ) -> Result<(), ConsensusNetworkError> {
        self.send_snapshot_envelope(
            &mut stream.send,
            Message::SnapshotResult(SnapshotResult {
                snapshot_id: snapshot_id.to_vec(),
                installed: true,
                included_position: Some(included_position),
                error: None,
            }),
        )
        .await?;
        stream.send.finish()?;
        Ok(())
    }

    fn peer_incarnation(&self, peer: NodeId) -> Result<u64, ConsensusNetworkError> {
        self.peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .routes
            .get(&peer)
            .map(|route| route.incarnation)
            .ok_or(ConsensusNetworkError::InvalidTraffic)
    }
}

fn snapshot_staging_path(
    state_path: &Path,
    snapshot_id: &[u8],
) -> Result<PathBuf, ConsensusNetworkError> {
    let exact: [u8; 16] = snapshot_id
        .try_into()
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
    let mut suffix = String::with_capacity(32);
    for byte in exact {
        write!(&mut suffix, "{byte:02x}")
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
    }
    Ok(state_path.with_extension(format!("snapshot-{suffix}.stage")))
}

fn remove_stale_stage(staging_path: &Path) -> Result<(), ConsensusNetworkError> {
    match std::fs::symlink_metadata(staging_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(staging_path).map_err(Into::into)
        }
        Ok(_) => Err(ConsensusNetworkError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
