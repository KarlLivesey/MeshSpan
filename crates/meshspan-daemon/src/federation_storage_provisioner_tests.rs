// SPDX-License-Identifier: GPL-2.0-only

//! Automatic quota provisioning through real consensus and an opened folder provider.

use super::{RunningAuthority, TestResult, commit, definition};
use crate::{
    ConsensusAuthenticationAuthority, NativeStorageTarget,
    federation_storage_provisioner::FederationStorageProvisioner,
};
use meshspan_domain::{FederationRelationshipId, Revision, TargetId, UnixMicros, uuid_v8};
use meshspan_metadata::{AuthoritativeCommand, FederationAllocationQuery, PageLimit};

#[path = "federation_storage_seal_tests.rs"]
mod seals;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_storage_provisioning_is_fenced_and_restart_idempotent() -> TestResult<()> {
    let mut fixture = RunningAuthority::start().await?;
    super::super::backup_destination_service_tests::register_target(&fixture).await?;
    let authority = ConsensusAuthenticationAuthority::new(
        fixture.reader.take().ok_or("reader")?,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let result = tokio::task::block_in_place(|| -> TestResult<()> {
        let grant = approve_storage(&fixture, &authority)?;
        let grant_id = grant.grant_id();
        let now = UnixMicros::new(400);
        let target = open_target(&fixture, &authority, now)?;
        let stale = authority
            .reader()
            .federation_storage_allocation_proposal(grant_id, target.context(), 256, now)?
            .ok_or("allocation proposal")?;
        let mut worker = FederationStorageProvisioner::default();
        worker
            .tick(&authority, [&target], now)
            .map_err(|()| "provisioning tick")?;
        let revision = authority.reader().current_revision()?;
        assert_eq!(revision.get(), stale.expected_revision.get() + 1);
        let query = FederationAllocationQuery {
            relationship_id: grant.relationship_id(),
            remote_mesh_id: meshspan_domain::MeshId::from_bytes([31; 16])?,
            grant_id,
            required_bytes: 1024,
            observed_at: now,
            snapshot_revision: revision,
            after: None,
            limit: PageLimit::new(1)?,
        };
        let page = authority
            .reader()
            .federation_storage_allocations_page(query)?;
        assert_eq!(page.items.len(), 1);
        let allocation = page
            .items
            .first()
            .ok_or("automatic allocation")?
            .allocation();
        assert_eq!(allocation.maximum_bytes(), 1024);
        assert_eq!(allocation.target_id(), target.context().target_id);
        assert_eq!(
            allocation.allocation_id(),
            stale.command.allocation.allocation_id()
        );
        // A stale smaller plan cannot replace or consume more quota after another commit.
        let context = super::super::command_context(
            fixture.administrator_id,
            120,
            160,
            400,
            Some(stale.expected_revision),
        )?;
        assert_eq!(
            authority.commit_authoritative(
                context,
                &AuthoritativeCommand::IssueFederationStorageAllocation(stale.command)
            ),
            Err(meshspan_cluster::MetadataAuthorityRequestError::Rejected)
        );
        // Dropping the transient scan cursor models a worker restart; no new allocation/revision.
        let mut restarted = FederationStorageProvisioner::default();
        for _ in 0..4 {
            restarted
                .tick(&authority, [&target], now)
                .map_err(|()| "rescan")?;
        }
        assert_eq!(authority.reader().current_revision()?, revision);
        assert!(
            authority
                .reader()
                .federation_storage_allocation_proposal(grant_id, target.context(), 1024, now)?
                .is_none()
        );
        assert!(
            authority
                .reader()
                .federation_storage_grants_for_provisioning(
                    None,
                    PageLimit::new(1)?,
                    UnixMicros::new(1000)
                )?
                .items
                .is_empty()
        );
        seals::verify_reassignment(&fixture, &authority, &target, allocation)
    });
    fixture.shutdown().await?;
    result
}

fn approve_storage(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
) -> TestResult<meshspan_domain::FederationGrant> {
    let relationship = FederationRelationshipId::from_bytes([30; 16])?;
    for (index, (command, _, _)) in super::super::federation_relationship::lifecycle(relationship)?
        .into_iter()
        .take(2)
        .enumerate()
    {
        commit(fixture, authority, 100 + u8::try_from(index)?, &command)?;
    }
    let definition = definition(relationship, 70, 1024)?;
    let grant = definition.grant.clone();
    commit(
        fixture,
        authority,
        110,
        &AuthoritativeCommand::IssueFederationGrant(definition),
    )?;
    Ok(grant)
}

fn open_target(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    now: UnixMicros,
) -> TestResult<NativeStorageTarget> {
    use meshspan_storage::{
        CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder,
        SharedStorageProvider, StoragePermitVerifier, UsageLimit,
    };
    let context = authority
        .reader()
        .storage_target_provider_context(fixture.node_id, TargetId::from_bytes(uuid_v8([32; 16]))?)?
        .ok_or("registered target")?;
    let folder_path = fixture.directory.path().join("automatic-storage");
    std::fs::create_dir(&folder_path)?;
    let limit = UsageLimit::Bytes(1_048_576);
    let folder = RegisteredFolder::register_new(
        &folder_path,
        FolderRegistration {
            mesh_id: context.mesh_id,
            target_id: context.target_id,
            generation: context.generation,
            usage_limit: limit,
        },
        &mut crate::OperatingSystemRandom,
    )?;
    let provider = SharedStorageProvider::new(FolderShardStore::open(
        folder,
        &fixture.directory.path().join("automatic-target-state"),
        CapacityPolicy {
            usage_limit: limit,
            repair_reserve_bytes: 0,
            revision: context.policy_revision,
        },
        StoragePermitVerifier::new(
            context.mesh_id,
            1,
            Revision::new(1),
            meshspan_contracts::StoragePermitMacKey::from_bytes([42; 32])?,
        )?,
        now,
        &mut crate::OperatingSystemRandom,
    )?);
    Ok(NativeStorageTarget::new(context, provider))
}
