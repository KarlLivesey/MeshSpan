// SPDX-License-Identifier: GPL-2.0-only

//! Storage grants and provider quota use real replicated commands and exact replay.

use super::{RunningAuthority, command_context};
use crate::ConsensusAuthenticationAuthority;
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationRelationshipId, FederationResourceScope, FederationStorageAllocation,
    FederationStorageAllocationId, MeshId, StorageFederationPolicy, StorageParticipation, TargetId,
    UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandReceipt, FederationGrantRestriction, FederationGrantState,
    FederationStorageAllocationState, IssueFederationGrant, IssueFederationStorageAllocation,
    ReplaceFederationGrant, RevokeFederationGrant, RevokeFederationStorageAllocation,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[path = "federation_backup_capacity_tests.rs"]
mod backup_capacity;
#[path = "federation_storage_provisioner_tests.rs"]
mod provisioning;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_storage_grant_and_quota_lifecycle_commits_through_consensus() -> TestResult<()>
{
    let mut fixture = RunningAuthority::start().await?;
    super::backup_destination_service_tests::register_target(&fixture).await?;
    let authority = ConsensusAuthenticationAuthority::new(
        fixture.reader.take().ok_or("reader")?,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let relationship_id = FederationRelationshipId::from_bytes([30; 16])?;
    let result = tokio::task::block_in_place(|| -> TestResult<()> {
        for (index, (command, _, _)) in super::federation_relationship::lifecycle(relationship_id)?
            .into_iter()
            .take(2)
            .enumerate()
        {
            commit(&fixture, &authority, 100 + u8::try_from(index)?, &command)?;
        }
        let original = definition(relationship_id, 70, 1024)?;
        let first = commit(
            &fixture,
            &authority,
            110,
            &AuthoritativeCommand::IssueFederationGrant(original.clone()),
        )?;
        let allocation = FederationStorageAllocation::new(
            FederationStorageAllocationId::from_bytes([72; 16])?,
            original.grant.grant_id(),
            fixture.node_id,
            TargetId::from_bytes(uuid_v8([32; 16]))?,
            1,
            512,
            UnixMicros::new(100),
            UnixMicros::new(900),
        )?;
        let issued = commit(
            &fixture,
            &authority,
            111,
            &AuthoritativeCommand::IssueFederationStorageAllocation(
                IssueFederationStorageAllocation {
                    allocation,
                    expected_grant_revision: first.committed_revision,
                },
            ),
        )?;
        let stored = authority
            .reader()
            .federation_storage_allocation(allocation.allocation_id())?
            .ok_or("allocation")?;
        assert_eq!(stored.allocation, allocation);
        assert_eq!(stored.state, FederationStorageAllocationState::Active);
        commit(
            &fixture,
            &authority,
            112,
            &AuthoritativeCommand::RevokeFederationStorageAllocation(
                RevokeFederationStorageAllocation {
                    allocation_id: allocation.allocation_id(),
                    expected_allocation_revision: issued.committed_revision,
                    reason: "Withdraw provider quota".into(),
                },
            ),
        )?;
        assert_eq!(
            authority
                .reader()
                .federation_storage_allocation(allocation.allocation_id())?
                .ok_or("revoked allocation")?
                .state,
            FederationStorageAllocationState::Revoked
        );
        replace_and_revoke(&fixture, &authority, &original)?;
        Ok(())
    });
    fixture.shutdown().await?;
    result
}

fn replace_and_revoke(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    original: &IssueFederationGrant,
) -> TestResult<()> {
    let replacement = definition(original.grant.relationship_id(), 71, 512)?;
    let new_id = replacement.grant.grant_id();
    commit(
        fixture,
        authority,
        113,
        &AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
            predecessor_grant_id: original.grant.grant_id(),
            grant: replacement.grant,
            restrictions: replacement.restrictions,
            restricts_authority: true,
            reason: "Narrow capacity".into(),
        }),
    )?;
    let old = authority
        .reader()
        .federation_grant(original.grant.grant_id())?
        .ok_or("predecessor")?;
    assert_eq!(old.state, FederationGrantState::Revoked);
    assert_eq!(old.successor_grant_id, Some(new_id));
    let current = authority
        .reader()
        .federation_grant(new_id)?
        .ok_or("replacement")?;
    assert_eq!(current.state, FederationGrantState::Active);
    assert_eq!(
        current.predecessor_grant_id,
        Some(original.grant.grant_id())
    );
    commit(
        fixture,
        authority,
        114,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: new_id,
            expected_authority_epoch: 1,
            reason: "End capacity sharing".into(),
        }),
    )?;
    assert_eq!(
        authority
            .reader()
            .federation_grant(new_id)?
            .ok_or("revoked grant")?
            .state,
        FederationGrantState::Revoked
    );
    Ok(())
}

fn definition(
    relationship: FederationRelationshipId,
    marker: u8,
    bytes: u64,
) -> TestResult<IssueFederationGrant> {
    let local = MeshId::from_bytes([9; 16])?;
    let remote = MeshId::from_bytes([31; 16])?;
    let policy = FederationPolicy::Storage(StorageFederationPolicy::new(
        bytes,
        StorageParticipation::new(true, false),
        false,
        None,
    )?);
    Ok(IssueFederationGrant {
        grant: FederationGrant::new(
            FederationGrantId::from_bytes([marker; 16])?,
            relationship,
            FederationGrantRoute::direct(local, remote)?,
            None,
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: local,
            },
            policy,
            1,
            UnixMicros::new(100),
            Some(UnixMicros::new(1000)),
        )?,
        restrictions: BoundedItems::new(
            vec![
                FederationGrantRestriction {
                    imposing_mesh_id: local,
                    policy,
                },
                FederationGrantRestriction {
                    imposing_mesh_id: remote,
                    policy,
                },
            ],
            2,
        )?,
    })
}

fn commit(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    marker: u8,
    command: &AuthoritativeCommand,
) -> TestResult<CommandReceipt> {
    let context = command_context(
        fixture.administrator_id,
        marker,
        marker + 40,
        200 + i64::from(marker),
        None,
    )?;
    let receipt = authority.commit_authoritative(context, command)?;
    assert_eq!(receipt.request_digest, command.request_digest(context));
    let replay = authority.commit_authoritative(context, command)?;
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(
        replay.disposition,
        meshspan_metadata::ApplyDisposition::Replayed
    );
    Ok(receipt)
}
