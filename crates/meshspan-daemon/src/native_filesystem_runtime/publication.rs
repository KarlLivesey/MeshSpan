// SPDX-License-Identifier: GPL-2.0-only

//! Completes a strong publication against replicated namespace authority.

use meshspan_domain::{Clock as _, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitConvergedVolumeHead, EntityKind,
};

use super::NativeFilesystemRuntimeError;
use crate::ConsensusAuthenticationAuthority;

pub(crate) fn commit_publication_head(
    authority: &ConsensusAuthenticationAuthority,
    context: CommandContext,
    publication: CommitConvergedVolumeHead,
    deadline: Option<UnixMicros>,
) -> Result<(), NativeFilesystemRuntimeError> {
    let confirmed = || {
        authority
            .reader()
            .namespace_publication_is_committed(&publication)
            .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)
    };
    if confirmed()? {
        return Ok(());
    }
    let command = AuthoritativeCommand::CommitConvergedVolumeHead(publication);
    let expected_digest = command.request_digest(context);
    let committed = match authority.commit_authoritative(context, &command) {
        Ok(receipt) => receipt,
        Err(error) => {
            // Another publisher can win after the initial read, or the command
            // can commit before its response is lost. Only exact durable history
            // resolves that uncertainty; an error itself never means success.
            if confirmed()? {
                return Ok(());
            }
            let failure = match error {
                meshspan_cluster::MetadataAuthorityRequestError::NotLeader { .. }
                | meshspan_cluster::MetadataAuthorityRequestError::Unavailable
                | meshspan_cluster::MetadataAuthorityRequestError::Conflict
                | meshspan_cluster::MetadataAuthorityRequestError::Rejected => {
                    NativeFilesystemRuntimeError::StrongBarrierPending
                }
                meshspan_cluster::MetadataAuthorityRequestError::Unsupported
                | meshspan_cluster::MetadataAuthorityRequestError::Failed => {
                    NativeFilesystemRuntimeError::StrongBarrierFailed
                }
            };
            if matches!(failure, NativeFilesystemRuntimeError::StrongBarrierPending)
                && wait_for_committed_publication(authority, &publication, deadline)?
            {
                return Ok(());
            }
            return Err(failure);
        }
    };
    if committed.entity.kind != EntityKind::Volume
        || committed.entity.id != publication.volume_id.as_bytes()
        || committed.request_digest != expected_digest
        || committed.operation_id != context.operation_id
        || committed.committed_revision.get() == 0
        || committed.result_digest == [0; 32]
    {
        return Err(NativeFilesystemRuntimeError::StrongBarrierFailed);
    }
    if !confirmed()? {
        return Err(NativeFilesystemRuntimeError::StrongBarrierFailed);
    }
    Ok(())
}

// The native filesystem caller owns a blocking worker. Poll only exact committed history;
// a rejected proposal supplies neither permission to resubmit nor evidence of success.
fn wait_for_committed_publication(
    authority: &ConsensusAuthenticationAuthority,
    publication: &CommitConvergedVolumeHead,
    deadline: Option<UnixMicros>,
) -> Result<bool, NativeFilesystemRuntimeError> {
    use std::time::{Duration, Instant};
    let remaining = deadline
        .and_then(|deadline| {
            deadline
                .get()
                .checked_sub(crate::OperatingSystemClock.now().get())
        })
        .and_then(|micros| u64::try_from(micros).ok())
        .map_or(Duration::ZERO, Duration::from_micros);
    let until = Instant::now()
        .checked_add(remaining)
        .ok_or(NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    loop {
        if authority
            .reader()
            .namespace_publication_is_committed(publication)
            .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?
        {
            return Ok(true);
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}
