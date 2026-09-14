// SPDX-License-Identifier: GPL-2.0-only

//! Read-fence admission before quorum work and after the confirmed frontier is applied.

use std::path::Path;

use meshspan_cluster::{
    ConsensusNetwork, MetadataAuthorityHandle, MetadataAuthorityRequestError, PeerControlRequest,
    metadata_read_fence_response,
};
use meshspan_domain::{Clock as _, UnixMicros};
use meshspan_metadata::{ActiveNodeCertificate, AuthoritativeRepository};
use meshspan_protocol::v1::{ControlEnvelope, ErrorCode, RequestHeader};
use meshspan_transport::PeerBinding;

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    directory: &Path,
    request: &PeerControlRequest,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    let result = async {
        admit(directory, request).await?;
        let fence = authority.read_fence().await.map_err(|error| match error {
            MetadataAuthorityRequestError::NotLeader { .. }
            | MetadataAuthorityRequestError::Unavailable => ErrorCode::Unavailable,
            MetadataAuthorityRequestError::Conflict
            | MetadataAuthorityRequestError::Rejected
            | MetadataAuthorityRequestError::Failed
            | MetadataAuthorityRequestError::Unsupported => ErrorCode::InternalContract,
        })?;
        // Catch-up may have applied this caller's retirement, replacement or certificate rotation.
        admit(directory, request).await?;
        Ok(fence)
    }
    .await;
    metadata_read_fence_response(network, request.envelope.as_inner(), result)
}

async fn admit(directory: &Path, request: &PeerControlRequest) -> Result<(), ErrorCode> {
    let directory = directory.to_path_buf();
    let header = request
        .envelope
        .as_inner()
        .header
        .clone()
        .ok_or(ErrorCode::Invalid)?;
    let peer = PeerBinding {
        node_id: request.from,
        incarnation: request.sender_incarnation,
        certificate_fingerprint: request.certificate_fingerprint,
    };
    // The control dispatcher bounds owned requests; SQLite never runs on the async executor.
    tokio::task::spawn_blocking(move || {
        let now = crate::OperatingSystemClock.now();
        let repository =
            super::open_root_repository_at(&directory, now).map_err(|_| ErrorCode::Unavailable)?;
        admit_repository(&repository, peer, &header, now)
    })
    .await
    .map_err(|_| ErrorCode::Unavailable)?
}

fn admit_repository(
    repository: &AuthoritativeRepository,
    peer: PeerBinding,
    header: &RequestHeader,
    now: UnixMicros,
) -> Result<(), ErrorCode> {
    let mesh = repository
        .local_mesh_id()
        .map_err(|_| ErrorCode::Unavailable)?
        .ok_or(ErrorCode::Unauthorised)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != repository.partition_id().as_bytes()
    {
        return Err(ErrorCode::Unauthorised);
    }
    let certificate = repository
        .active_node_certificate(peer.node_id)
        .map_err(|_| ErrorCode::Unavailable)?
        .ok_or(ErrorCode::Unauthorised)?;
    admit_certificate(peer, header, &certificate, now)
}

fn admit_certificate(
    peer: PeerBinding,
    header: &RequestHeader,
    certificate: &ActiveNodeCertificate,
    now: UnixMicros,
) -> Result<(), ErrorCode> {
    let remaining = header
        .deadline_unix_micros
        .checked_sub(now.get())
        .ok_or(ErrorCode::Deadline)?;
    if !(1..=10_000_000).contains(&remaining) {
        return Err(ErrorCode::Deadline);
    }
    if header.sender_node_id.as_slice() != peer.node_id.as_bytes()
        || header.sender_incarnation != peer.incarnation
        || certificate.node_id != peer.node_id
        || certificate.incarnation != peer.incarnation
        || certificate.certificate_fingerprint != peer.certificate_fingerprint
        || certificate.valid_until <= now
    {
        return Err(ErrorCode::Unauthorised);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_domain::{NodeId, Revision};
    use meshspan_metadata::JoinRoles;

    #[test]
    fn fresh_read_admission_rejects_replaced_identity_expiry_and_unbounded_deadlines()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = NodeId::from_bytes([1; 16])?;
        let peer = PeerBinding {
            node_id: node,
            incarnation: 3,
            certificate_fingerprint: [2; 32],
        };
        let header = RequestHeader {
            sender_node_id: node.as_bytes().to_vec(),
            sender_incarnation: 3,
            deadline_unix_micros: 50,
            ..RequestHeader::default()
        };
        let certificate = ActiveNodeCertificate {
            node_id: node,
            incarnation: 3,
            roles: JoinRoles::new(JoinRoles::STORAGE)?,
            generation: 1,
            certificate_der: vec![1],
            certificate_fingerprint: [2; 32],
            valid_until: UnixMicros::new(100),
            revision: Revision::new(1),
        };
        let now = UnixMicros::new(10);
        assert_eq!(admit_certificate(peer, &header, &certificate, now), Ok(()));
        for field in 0..4 {
            let mut changed = certificate.clone();
            match field {
                0 => changed.node_id = NodeId::from_bytes([3; 16])?,
                1 => changed.incarnation += 1,
                2 => changed.certificate_fingerprint = [3; 32],
                _ => changed.valid_until = now,
            }
            assert_eq!(
                admit_certificate(peer, &header, &changed, now),
                Err(ErrorCode::Unauthorised)
            );
        }
        for deadline in [now.get(), i64::MIN, i64::MAX, now.get() + 10_000_001] {
            let mut changed = header.clone();
            changed.deadline_unix_micros = deadline;
            assert_eq!(
                admit_certificate(peer, &changed, &certificate, now),
                Err(ErrorCode::Deadline)
            );
        }
        for field in 0..2 {
            let mut changed = header.clone();
            if field == 0 {
                changed.sender_node_id = vec![3; 16];
            } else {
                changed.sender_incarnation += 1;
            }
            assert_eq!(
                admit_certificate(peer, &changed, &certificate, now),
                Err(ErrorCode::Unauthorised)
            );
        }
        Ok(())
    }
}
