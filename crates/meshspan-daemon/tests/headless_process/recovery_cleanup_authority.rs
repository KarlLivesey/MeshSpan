// SPDX-License-Identifier: GPL-2.0-only

//! Test-owned reachability evidence for the opaque shard never published in any namespace.
//! Every authorisation transition still commits through real private RPCs and the live Raft.
//! This is storage admission/lifecycle acceptance, not automatic retention-scanner acceptance.

use super::{CleanupClient, Error, random_id};
use ed25519_dalek::{Signer as _, SigningKey};
use meshspan_contracts::BoundedItems;
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::{
    Clock as _, ContentManifestId, DurationMicros, FileVersionId, OperationId, Revision,
};
use meshspan_filesystem::{
    ReachabilityRoot, ReachabilityRootSource, reachability_root_digest,
    reachability_root_set_digest,
};
use meshspan_metadata::{
    AppendVersionCleanupItems, AttestVersionCleanup, AuthoriseVersionCleanup, AuthoritativeCommand,
    AuthoritativeRepository, PageLimit, ProposeVersionCleanup, RegisterCleanupAttestationKey,
    RetainedNamespaceRootSource, SealVersionCleanupInventory, VersionCleanupAttestation,
    VersionCleanupItemPlacement,
};

pub(super) async fn prepare_cleanup(client: &CleanupClient) -> Result<OperationId, Box<dyn Error>> {
    let proposed = client
        .commit(|repository, revision| proposal(client, repository, revision))
        .await?;
    let cleanup = proposed.operation_id;
    attest(client, cleanup, proposed.committed_revision).await?;
    let intent = client
        .repository
        .version_cleanup_intent(cleanup)?
        .ok_or("cleanup intent missing")?;
    let authorised = client
        .commit(|_, _| {
            Ok(AuthoritativeCommand::AuthoriseVersionCleanup(
                AuthoriseVersionCleanup {
                    cleanup_operation_id: cleanup,
                    cleanup_revision: proposed.committed_revision,
                    reachability_subject_digest: intent.reachability_subject_digest,
                },
            ))
        })
        .await?;
    let operation = OperationId::from_bytes(random_id()?)?;
    seal(
        client,
        cleanup,
        proposed.committed_revision,
        authorised.committed_revision,
        operation,
    )
    .await?;
    client
        .commit(|repository, _| {
            let current = repository.version_cleanup_permit_authority(cleanup, 0)?;
            let epoch = repository
                .load_active_consensus_quorum_plan()?
                .ok_or("quorum plan missing")?
                .membership_epoch();
            Ok(meshspan_cluster::version_cleanup_removal_permit(
                current,
                client.io.write.mesh_id,
                operation,
                epoch,
                OperatingSystemClock.now(),
                DurationMicros::new(60_000_000),
                &client.io.key,
            )?)
        })
        .await?;
    Ok(cleanup)
}

fn proposal(
    client: &CleanupClient,
    repository: &AuthoritativeRepository,
    revision: Revision,
) -> Result<AuthoritativeCommand, Box<dyn Error>> {
    let page = repository.retained_namespace_roots(
        client.volume,
        revision,
        None,
        PageLimit::new(1000)?,
    )?;
    assert!(
        page.next.is_none(),
        "fixture unexpectedly exceeds one bounded root page"
    );
    let roots: Vec<_> = page
        .roots
        .into_iter()
        .map(|root| ReachabilityRoot {
            source: match root.source {
                RetainedNamespaceRootSource::ConvergedHead(volume) => {
                    ReachabilityRootSource::ConvergedHead(volume)
                }
                RetainedNamespaceRootSource::Snapshot(snapshot) => {
                    ReachabilityRootSource::Snapshot(snapshot)
                }
                RetainedNamespaceRootSource::Backup(commit) => {
                    ReachabilityRootSource::Backup(commit)
                }
            },
            namespace_commit_id: root.namespace_commit_id,
            root_object_revision_id: root.root_object_revision_id,
        })
        .collect();
    let mut proposal = ProposeVersionCleanup {
        volume_id: client.volume,
        version_id: FileVersionId::from_bytes(random_id()?)?,
        manifest_id: ContentManifestId::from_bytes(random_id()?)?,
        manifest_root_digest: client.io.write.shard.manifest_digest,
        source_scan_operation_id: OperationId::from_bytes(random_id()?)?,
        scan_request_digest: [241; 32],
        reachability_subject_digest: [242; 32],
        retention_policy_sequence: repository
            .version_retention_policy(client.volume)?
            .ok_or("retention policy missing")?
            .sequence,
        reachability_revision: revision,
        retained_root_count: u64::try_from(roots.len())?,
        retained_root_digest: reachability_root_digest(client.volume, revision, &roots)?,
        retained_root_set_digest: reachability_root_set_digest(client.volume, &roots)?,
        local_roots_digest: [243; 32],
        proof_result_digest: [0; 32],
    };
    proposal.proof_result_digest = terminal_digest(
        proposal.source_scan_operation_id,
        proposal.scan_request_digest,
        proposal.local_roots_digest,
    );
    Ok(AuthoritativeCommand::ProposeVersionCleanup(proposal))
}

async fn attest(
    client: &CleanupClient,
    cleanup: OperationId,
    revision: Revision,
) -> Result<(), Box<dyn Error>> {
    let intent = client
        .repository
        .version_cleanup_intent(cleanup)?
        .ok_or("cleanup intent missing")?;
    assert_eq!(
        intent.required_attestation_count, 2,
        "both live gateways must attest"
    );
    for (node, seed) in [
        (client.leader, 201),
        (client.io.network.local_node_id(), 202),
    ] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        client
            .commit(|_, _| {
                Ok(AuthoritativeCommand::RegisterCleanupAttestationKey(
                    RegisterCleanupAttestationKey {
                        node_id: node,
                        generation: 1,
                        verifying_key: key.verifying_key().to_bytes(),
                    },
                ))
            })
            .await?;
        client
            .commit(|repository, _| {
                let certificate = repository
                    .active_node_certificate(node)?
                    .ok_or("gateway certificate missing")?;
                let mut attestation = VersionCleanupAttestation {
                    cleanup_operation_id: cleanup,
                    cleanup_revision: revision,
                    node_id: node,
                    node_incarnation: certificate.incarnation,
                    key_generation: 1,
                    scan_operation_id: OperationId::from_bytes(random_id()?)?,
                    scan_request_digest: [seed; 32],
                    reachability_subject_digest: intent.reachability_subject_digest,
                    local_roots_digest: [seed; 32],
                    scan_result_digest: [0; 32],
                    signature: [0; 64],
                };
                attestation.scan_result_digest = terminal_digest(
                    attestation.scan_operation_id,
                    attestation.scan_request_digest,
                    attestation.local_roots_digest,
                );
                attestation.signature = key.sign(&attestation.signing_digest()).to_bytes();
                Ok(AuthoritativeCommand::AttestVersionCleanup(
                    AttestVersionCleanup { attestation },
                ))
            })
            .await?;
    }
    assert!(
        client
            .repository
            .version_cleanup_attestation_progress(cleanup)?
            .ok_or("attestation coverage missing")?
            .complete()
    );
    Ok(())
}

async fn seal(
    client: &CleanupClient,
    cleanup: OperationId,
    proposal: Revision,
    authorised: Revision,
    operation: OperationId,
) -> Result<(), Box<dyn Error>> {
    client
        .commit(|_, _| {
            Ok(AuthoritativeCommand::AppendVersionCleanupItems(
                AppendVersionCleanupItems {
                    cleanup_operation_id: cleanup,
                    cleanup_revision: proposal,
                    authorisation_revision: authorised,
                    expected_item_count: 1,
                    start_index: 0,
                    items: BoundedItems::new(
                        vec![VersionCleanupItemPlacement {
                            removal_operation_id: operation,
                            shard: client.io.write.shard,
                            target_id: client.io.write.target_id,
                            target_generation: client.io.write.target_generation,
                            storage_node_id: client.io.destination,
                        }],
                        1000,
                    )?,
                },
            ))
        })
        .await?;
    client
        .commit(|repository, _| {
            let inventory = repository
                .version_cleanup_inventory(cleanup)?
                .ok_or("inventory missing")?;
            Ok(AuthoritativeCommand::SealVersionCleanupInventory(
                SealVersionCleanupInventory {
                    cleanup_operation_id: cleanup,
                    cleanup_revision: proposal,
                    authorisation_revision: authorised,
                    expected_item_count: 1,
                    inventory_digest: inventory.inventory_digest,
                },
            ))
        })
        .await?;
    Ok(())
}

fn terminal_digest(operation: OperationId, request: [u8; 32], local_roots: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-result.v1\0");
    digest.update(&operation.as_bytes());
    digest.update(&request);
    digest.update(&local_roots);
    digest.update(&[4]);
    digest.finalize().into()
}
