// SPDX-License-Identifier: GPL-2.0-only

//! Completes a strong publication against replicated namespace authority.

use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitConvergedVolumeHead, EntityKind,
};

use super::NativeFilesystemRuntimeError;
use crate::ConsensusAuthenticationAuthority;

pub(crate) fn commit_publication_head(
    authority: &ConsensusAuthenticationAuthority,
    context: CommandContext,
    publication: CommitConvergedVolumeHead,
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
            return Err(match error {
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
            });
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
