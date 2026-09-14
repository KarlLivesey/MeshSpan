// SPDX-License-Identifier: GPL-2.0-only

//! Completes a strong publication against replicated namespace authority.

use meshspan_domain::{AuditEventId, Clock as _, OperationId, UnixMicros};
use meshspan_filesystem::{
    NamespacePublicationReceipt, VerifiedPublication, VersionPublicationStore,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitConvergedVolumeHead, ConvergedHeadEvidence,
    EntityKind,
};
use sha2::{Digest, Sha256};

use super::NativeFilesystemRuntimeError;
use crate::ConsensusAuthenticationAuthority;

const HEAD_AUDIT_ID_DOMAIN: &[u8] = b"meshspan.native.converged-head-audit.v1\0";

pub(crate) fn confirm_or_commit_publication(
    authority: &ConsensusAuthenticationAuthority,
    store: &VersionPublicationStore,
    receipt: NamespacePublicationReceipt,
    deadline: Option<UnixMicros>,
) -> Result<(), NativeFilesystemRuntimeError> {
    let immutable = store
        .verify_publication(receipt)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    let publication = publication_command(immutable);
    if authority
        .reader()
        .namespace_publication_is_committed(&publication)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?
    {
        return Ok(());
    }
    // Only recovery may use historical facts. A new proposal still requires the current head.
    let current = store
        .verify_publication_head(receipt)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    let current = current.publication();
    let context = CommandContext {
        operation_id: current.receipt().operation_id,
        actor_principal_id: current.created_by(),
        audit_event_id: head_audit_event_id(current.receipt().operation_id)?,
        occurred_at: current.created_at(),
        expected_revision: None,
    };
    commit_publication_head(authority, context, publication_command(current), deadline)
}

pub(crate) fn verify_committed_receipt(
    store: &meshspan_filesystem::VersionPublicationStore,
    receipt: meshspan_filesystem::NamespacePublicationReceipt,
) -> Result<(), NativeFilesystemRuntimeError> {
    let committed = store
        .resolve_namespace_publication(receipt.operation_id)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    let expected = meshspan_filesystem::NamespacePublicationReceipt {
        disposition: meshspan_filesystem::PublicationDisposition::Replayed,
        ..receipt
    };
    if committed == Some(expected) {
        Ok(())
    } else {
        Err(NativeFilesystemRuntimeError::StrongBarrierFailed)
    }
}

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

fn publication_command(verified: VerifiedPublication) -> CommitConvergedVolumeHead {
    let receipt = verified.receipt();
    CommitConvergedVolumeHead {
        volume_id: verified.volume_id(),
        expected_namespace_commit_id: verified.parent_namespace_commit_id(),
        namespace_commit_id: receipt.namespace_commit_id,
        root_object_revision_id: verified.root_object_revision_id(),
        evidence: ConvergedHeadEvidence::Publication {
            operation_id: receipt.operation_id,
            request_digest: receipt.request_digest,
            result_digest: verified.convergence_digest(),
        },
    }
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

fn head_audit_event_id(
    operation_id: OperationId,
) -> Result<AuditEventId, NativeFilesystemRuntimeError> {
    let mut digest = Sha256::new();
    digest.update(HEAD_AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(meshspan_domain::uuid_v8)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    AuditEventId::from_bytes(bytes).map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)
}
