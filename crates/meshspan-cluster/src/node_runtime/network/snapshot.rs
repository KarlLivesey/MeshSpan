// SPDX-License-Identifier: GPL-2.0-only

//! Bounded snapshot transfer and staging over authenticated peer connections.

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

use super::{INCARNATION, PeerNetwork};
use crate::node_runtime::NodeRuntimeError;

const SNAPSHOT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAXIMUM_SNAPSHOT_BYTES: u64 = 512 * 1_024 * 1_024;
const SNAPSHOT_CHUNK_BYTES: usize = 48 * 1_024;

pub(in crate::node_runtime) struct OutboundSnapshot {
    pub path: PathBuf,
    pub manifest: PartitionSnapshotManifest,
    pub quorum_plan: Vec<u8>,
}

pub(in crate::node_runtime) struct ReceivedSnapshot {
    pub from: NodeId,
    pub snapshot: VerifiedSnapshot,
    pub installed: oneshot::Sender<()>,
}

impl PeerNetwork {
    pub(in crate::node_runtime) fn send_snapshot(&self, to: NodeId, snapshot: OutboundSnapshot) {
        if let Some(sender) = self.outbound_snapshots.get(&to) {
            let _full_or_closed = sender.try_send(snapshot);
        }
    }

    pub(super) fn spawn_snapshot_worker(
        &self,
        peer: NodeId,
        mut snapshots: mpsc::Receiver<OutboundSnapshot>,
    ) {
        let network = self.clone();
        tokio::spawn(async move {
            while let Some(snapshot) = snapshots.recv().await {
                let result = tokio::time::timeout(
                    SNAPSHOT_OPERATION_TIMEOUT,
                    network.send_snapshot_to_peer(peer, &snapshot),
                )
                .await;
                if matches!(result, Ok(Ok(()))) {
                    let _cleanup = tokio::fs::remove_file(&snapshot.path).await;
                }
            }
        });
    }

    async fn send_snapshot_to_peer(
        &self,
        to: NodeId,
        snapshot: &OutboundSnapshot,
    ) -> Result<(), NodeRuntimeError> {
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
        send.finish()
            .map_err(meshspan_transport::TransportError::from)?;
        self.verify_snapshot_result(
            &mut receive,
            &manifest.snapshot_id.as_bytes(),
            included_position,
        )
        .await
    }

    async fn send_snapshot_chunks(
        &self,
        send: &mut quinn::SendStream,
        snapshot: &OutboundSnapshot,
    ) -> Result<(), NodeRuntimeError> {
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
                    u64::try_from(read).map_err(|_| NodeRuntimeError::InvalidConfiguration)?,
                )
                .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        }
    }

    async fn verify_snapshot_result(
        &self,
        receive: &mut quinn::RecvStream,
        snapshot_id: &[u8],
        included_position: LogPosition,
    ) -> Result<(), NodeRuntimeError> {
        let result = receive_control(receive, self.wire_limits).await?;
        let Message::SnapshotResult(result) = result
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        if result.installed
            && result.snapshot_id == snapshot_id
            && result.included_position.as_ref() == Some(&included_position)
        {
            Ok(())
        } else {
            Err(NodeRuntimeError::InvalidConfiguration)
        }
    }

    async fn send_snapshot_envelope(
        &self,
        send: &mut quinn::SendStream,
        message: Message,
    ) -> Result<(), NodeRuntimeError> {
        send_control(
            send,
            &ControlEnvelope {
                header: Some(self.request_header()?),
                message: Some(message),
            },
            self.wire_limits,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn receive_snapshot(
        &self,
        peer: NodeId,
        state_path: &Path,
        stream: &mut meshspan_transport::AcceptedStream,
        snapshots: &mpsc::Sender<ReceivedSnapshot>,
    ) -> Result<(), NodeRuntimeError> {
        let first = receive_control(&mut stream.receive, self.wire_limits).await?;
        self.verify_header(&first, peer, INCARNATION)?;
        let Message::SnapshotBegin(begin) = first
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
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
            .send(ReceivedSnapshot {
                from: peer,
                snapshot: verified,
                installed,
            })
            .await
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        receive_installed
            .await
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        self.send_snapshot_result(stream, snapshot_id, included_position)
            .await
    }

    async fn receive_snapshot_chunks(
        &self,
        peer: NodeId,
        stream: &mut meshspan_transport::AcceptedStream,
        mut stager: SnapshotStager,
    ) -> Result<VerifiedSnapshot, NodeRuntimeError> {
        loop {
            let envelope = receive_control(&mut stream.receive, self.wire_limits).await?;
            self.verify_header(&envelope, peer, INCARNATION)?;
            match envelope
                .as_inner()
                .message
                .as_ref()
                .ok_or(NodeRuntimeError::InvalidConfiguration)?
            {
                Message::SnapshotChunk(chunk) => stager.append_chunk(chunk)?,
                Message::SnapshotFinish(finish) => {
                    return stager.finish(finish).map_err(Into::into);
                }
                _ => return Err(NodeRuntimeError::InvalidConfiguration),
            }
        }
    }

    async fn send_snapshot_result(
        &self,
        stream: &mut meshspan_transport::AcceptedStream,
        snapshot_id: [u8; 16],
        included_position: LogPosition,
    ) -> Result<(), NodeRuntimeError> {
        send_control(
            &mut stream.send,
            &ControlEnvelope {
                header: Some(self.request_header()?),
                message: Some(Message::SnapshotResult(SnapshotResult {
                    snapshot_id: snapshot_id.to_vec(),
                    installed: true,
                    included_position: Some(included_position),
                    error: None,
                })),
            },
            self.wire_limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(())
    }
}

fn snapshot_staging_path(
    state_path: &Path,
    snapshot_id: &[u8],
) -> Result<PathBuf, NodeRuntimeError> {
    let exact: [u8; 16] = snapshot_id
        .try_into()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let mut suffix = String::with_capacity(32);
    for byte in exact {
        write!(&mut suffix, "{byte:02x}").map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    }
    Ok(state_path.with_extension(format!("snapshot-{suffix}.stage")))
}

fn remove_stale_stage(staging_path: &Path) -> Result<(), NodeRuntimeError> {
    match std::fs::symlink_metadata(staging_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(staging_path).map_err(Into::into)
        }
        Ok(_) => Err(NodeRuntimeError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
