// SPDX-License-Identifier: GPL-2.0-only

//! Fresh quorum read and exact local-prefix admission for secret-bearing enrollment.

use super::UserEnrollmentError;
use crate::private_consensus_runtime::PrivateConsensusRuntime;
use meshspan_cluster::{MetadataAuthorityHandle, MetadataAuthorityRequestError, MetadataReadFence};
use meshspan_domain::{Clock as _, OperationId, RandomSource as _, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use std::time::Duration;

const LOCAL_APPLY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn refresh(
    reader: &AuthoritativeRepository,
    authority: &MetadataAuthorityHandle,
    network: Option<&PrivateConsensusRuntime>,
    runtime: &tokio::runtime::Handle,
) -> Result<UnixMicros, UserEnrollmentError> {
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            // Discovery owns and drains its peer tasks before this local-apply deadline starts.
            let fence = acquire_fence(reader, authority, network).await?;
            tokio::time::timeout(LOCAL_APPLY_TIMEOUT, async {
                loop {
                    let caught_up = reader
                        .with_read_view(|reader| caught_up(reader, fence))
                        .map_err(|_| UserEnrollmentError::Failed)??;
                    if caught_up {
                        return Ok(crate::OperatingSystemClock.now());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .map_err(|_| UserEnrollmentError::Unavailable)?
        })
    })
}

async fn acquire_fence(
    reader: &AuthoritativeRepository,
    authority: &MetadataAuthorityHandle,
    runtime: Option<&PrivateConsensusRuntime>,
) -> Result<MetadataReadFence, UserEnrollmentError> {
    let Some(runtime) = runtime else {
        return authority.read_fence().await.map_err(authority_error);
    };
    let network = runtime
        .network()
        .map_err(|()| UserEnrollmentError::Unavailable)?;
    let plan = reader
        .load_active_consensus_quorum_plan()
        .map_err(|_| UserEnrollmentError::Failed)?
        .ok_or(UserEnrollmentError::Unavailable)?;
    let mut bytes = [0; 16];
    crate::OperatingSystemRandom
        .fill_bytes(&mut bytes)
        .map_err(|_| UserEnrollmentError::Failed)?;
    let operation = OperationId::from_bytes(meshspan_domain::uuid_v8(bytes))
        .map_err(|_| UserEnrollmentError::Failed)?;
    let local = authority.clone();
    crate::metadata_forwarding::discovery::discover(
        plan.voters().into_iter().collect(),
        None,
        move |candidate| {
            let network = network.clone();
            let local = local.clone();
            async move {
                if candidate == network.local_node_id() {
                    return local.read_fence().await.map_err(discovery_error);
                }
                let mut nonce = [0; 32];
                crate::OperatingSystemRandom
                    .fill_bytes(&mut nonce)
                    .map_err(|_| MetadataAuthorityRequestError::Failed)?;
                network
                    .fetch_metadata_read_fence(
                        candidate,
                        operation,
                        nonce,
                        crate::OperatingSystemClock.now(),
                    )
                    .await
                    .map_err(discovery_error)
            }
        },
    )
    .await
    .map_err(authority_error)
}

fn caught_up(
    reader: &AuthoritativeRepository,
    fence: MetadataReadFence,
) -> Result<bool, UserEnrollmentError> {
    if reader.partition_id() != fence.partition_id {
        return Err(UserEnrollmentError::Failed);
    }
    let plan = reader
        .load_active_consensus_quorum_plan()
        .map_err(|_| UserEnrollmentError::Failed)?
        .ok_or(UserEnrollmentError::Unavailable)?;
    if plan.membership_epoch() < fence.membership_epoch {
        return Ok(false);
    }
    if plan.membership_epoch() != fence.membership_epoch
        || plan.proof_digest() != fence.plan_digest
        || !plan.voters().contains(&fence.leader_node_id)
    {
        return Err(UserEnrollmentError::Unavailable);
    }
    let Some(entry) = reader
        .applied_consensus_entry(fence.applied)
        .map_err(|_| UserEnrollmentError::Failed)?
    else {
        return Ok(false);
    };
    if entry.entry_digest() != fence.applied_digest {
        return Err(UserEnrollmentError::Failed);
    }
    Ok(reader
        .current_revision()
        .map_err(|_| UserEnrollmentError::Failed)?
        >= fence.revision)
}

fn discovery_error(error: MetadataAuthorityRequestError) -> MetadataAuthorityRequestError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. } => {
            MetadataAuthorityRequestError::Unavailable
        }
        error @ (MetadataAuthorityRequestError::Unavailable
        | MetadataAuthorityRequestError::Conflict
        | MetadataAuthorityRequestError::Rejected
        | MetadataAuthorityRequestError::Unsupported
        | MetadataAuthorityRequestError::Failed) => error,
    }
}
fn authority_error(error: MetadataAuthorityRequestError) -> UserEnrollmentError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => UserEnrollmentError::Unavailable,
        MetadataAuthorityRequestError::Conflict
        | MetadataAuthorityRequestError::Rejected
        | MetadataAuthorityRequestError::Unsupported
        | MetadataAuthorityRequestError::Failed => UserEnrollmentError::Failed,
    }
}
