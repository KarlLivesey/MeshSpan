// SPDX-License-Identifier: GPL-2.0-only

//! One bounded convergence step, composed around the existing immutable and metadata owners.

use meshspan_domain::{
    AuditEventId, Clock as _, InitialBootstrapMaterial, NamespaceCommitId, NodeId, OperationId,
    PrincipalId, RandomSource as _, UnixMicros, VolumeId, uuid_v8,
};
use meshspan_filesystem::{
    NamespaceConvergenceEvidence, NamespaceConvergenceJob, NamespaceConvergenceOutcome,
    NamespaceReconciliationApplication, PublicationError,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitConvergedVolumeHead, ConvergedHeadEvidence,
    ConvergedVolumeHead, EntityKind, PageLimit, VolumeInventoryCursor,
};
use sha2::{Digest, Sha256};

use super::{NativeGatewayHistory, NativeGatewaySyncError};
use crate::{
    ConsensusAuthenticationAuthority, OperatingSystemClock, OperatingSystemRandom,
    native_filesystem_runtime::NativeFilesystemRuntime,
};

struct Candidate {
    authority: ConsensusAuthenticationAuthority,
    volume: VolumeId,
    current: Option<ConvergedVolumeHead>,
    actor: PrincipalId,
    now: UnixMicros,
}

pub(super) async fn run_one(
    history: &NativeGatewayHistory,
    filesystem: &NativeFilesystemRuntime,
    node: NodeId,
    after: &mut Option<VolumeInventoryCursor>,
) -> Result<(), NativeGatewaySyncError> {
    let filesystem = filesystem.clone();
    let cursor = after.clone();
    let (next, candidate) =
        tokio::task::spawn_blocking(move || scan(&filesystem, node, cursor.as_ref()))
            .await
            .map_err(|_| NativeGatewaySyncError::Unavailable)??;
    *after = next;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let expected = candidate.current.map(|head| head.namespace_commit_id);
    let volume = candidate.volume;
    let application = application(candidate.actor, candidate.now)?;
    let job = history
        .execute(move |store| {
            store
                .prepare_namespace_convergence(volume, expected, application)
                .map_err(|_| NativeGatewaySyncError::Unavailable)
        })
        .await?;
    let Some(job) = job else {
        return Ok(());
    };
    if job.expected_head() != expected && expected != Some(job.selected_head()) {
        return history
            .execute(move |store| {
                store
                    .finish_namespace_convergence(&job, false)
                    .map_err(|_| NativeGatewaySyncError::Unavailable)
            })
            .await;
    }
    let saved = job.clone();
    let outcome = history
        .execute(move |store| {
            store
                .apply_namespace_convergence(&saved)
                .map_err(|_| NativeGatewaySyncError::Unavailable)
        })
        .await?;
    if let Some(head) = candidate
        .current
        .filter(|head| head.namespace_commit_id == job.selected_head())
    {
        if head.root_object_revision_id != outcome.root_object_revision_id {
            return Err(NativeGatewaySyncError::Invalid);
        }
    } else {
        let saved = job.clone();
        tokio::task::spawn_blocking(move || publish(&candidate.authority, &saved, outcome))
            .await
            .map_err(|_| NativeGatewaySyncError::Unavailable)??;
    }
    complete(history, node, job, outcome).await
}

fn scan(
    filesystem: &NativeFilesystemRuntime,
    node: NodeId,
    after: Option<&VolumeInventoryCursor>,
) -> Result<(Option<VolumeInventoryCursor>, Option<Candidate>), NativeGatewaySyncError> {
    let now = OperatingSystemClock.now();
    let authority = filesystem
        .convergence_authority(now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let page = authority
        .reader()
        .volume_inventory_candidates(
            after,
            PageLimit::new(1).map_err(|_| NativeGatewaySyncError::Invalid)?,
        )
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let Some(volume) = page
        .items
        .into_iter()
        .next()
        .filter(|volume| volume.state == 1)
    else {
        return Ok((page.next, None));
    };
    let registration = authority
        .reader()
        .storage_target_registration_context(node, now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?
        .ok_or(NativeGatewaySyncError::Unavailable)?;
    let current = authority
        .reader()
        .converged_volume_head(volume.volume_id)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    Ok((
        page.next,
        Some(Candidate {
            authority,
            volume: volume.volume_id,
            current,
            actor: registration.actor_principal_id,
            now,
        }),
    ))
}

fn application(
    actor: PrincipalId,
    now: UnixMicros,
) -> Result<NamespaceReconciliationApplication, NativeGatewaySyncError> {
    let mut operation = [0; 16];
    let mut commit = [0; 16];
    OperatingSystemRandom
        .fill_bytes(&mut operation)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    OperatingSystemRandom
        .fill_bytes(&mut commit)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    Ok(NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes(uuid_v8(operation))
            .map_err(|_| NativeGatewaySyncError::Invalid)?,
        namespace_commit_id: NamespaceCommitId::from_bytes(uuid_v8(commit))
            .map_err(|_| NativeGatewaySyncError::Invalid)?,
        created_by: actor,
        created_at: now,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
    })
}

fn publish(
    authority: &ConsensusAuthenticationAuthority,
    job: &NamespaceConvergenceJob,
    outcome: NamespaceConvergenceOutcome,
) -> Result<(), NativeGatewaySyncError> {
    let application = job.application();
    let mut digest = Sha256::new();
    digest.update(b"meshspan.namespace-convergence.audit.v1\0");
    digest.update(application.operation_id.as_bytes());
    let audit = digest.finalize()[..16]
        .try_into()
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let context = CommandContext {
        operation_id: application.operation_id,
        actor_principal_id: application.created_by,
        occurred_at: application.created_at,
        expected_revision: None,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
            .map_err(|_| NativeGatewaySyncError::Invalid)?,
    };
    let evidence = match outcome.evidence {
        NamespaceConvergenceEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        } => ConvergedHeadEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        },
        NamespaceConvergenceEvidence::Reconciliation(receipt) => {
            ConvergedHeadEvidence::Reconciliation {
                operation_id: receipt.operation_id,
                request_digest: receipt.request_digest,
                causal_plan_digest: receipt.causal_plan_digest,
                replay_plan_digest: receipt.replay_plan_digest,
                result_digest: receipt.result_digest,
            }
        }
    };
    let command = AuthoritativeCommand::CommitConvergedVolumeHead(CommitConvergedVolumeHead {
        volume_id: job.volume_id(),
        expected_namespace_commit_id: job.expected_head(),
        namespace_commit_id: job.selected_head(),
        root_object_revision_id: outcome.root_object_revision_id,
        evidence,
    });
    let receipt = authority
        .commit_authoritative(context, &command)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::Volume
        || receipt.entity.id != job.volume_id().as_bytes()
        || receipt.committed_revision.get() == 0
    {
        return Err(NativeGatewaySyncError::Invalid);
    }
    Ok(())
}

async fn complete(
    history: &NativeGatewayHistory,
    node: NodeId,
    job: NamespaceConvergenceJob,
    outcome: NamespaceConvergenceOutcome,
) -> Result<(), NativeGatewaySyncError> {
    let branch = InitialBootstrapMaterial::local_branch_id(node)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    history
        .execute(move |store| {
            store
                .retain_received_namespace_head(
                    branch,
                    job.volume_id(),
                    job.selected_head(),
                    outcome.root_object_revision_id,
                )
                .map_err(|_| NativeGatewaySyncError::Unavailable)?;
            match store.adopt_imported_namespace_head(
                branch,
                job.volume_id(),
                job.selected_head(),
                outcome.root_object_revision_id,
            ) {
                Ok(_) | Err(PublicationError::StaleHead) => {}
                Err(_) => return Err(NativeGatewaySyncError::Unavailable),
            }
            store
                .finish_namespace_convergence(&job, true)
                .map_err(|_| NativeGatewaySyncError::Unavailable)
        })
        .await
}
