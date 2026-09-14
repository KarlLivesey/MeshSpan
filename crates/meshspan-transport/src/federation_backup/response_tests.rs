// SPDX-License-Identifier: GPL-2.0-only

use super::allocation_page_matches;
use meshspan_protocol::{
    encode_backup_allocation_cursor, federation_backup_allocation_request_digest_payload,
    v1::{
        FederatedBackupAllocation, FederatedBackupAllocationCursor, FederatedBackupAllocationPage,
        FederatedBackupScope, FetchFederatedBackupAllocations,
    },
};
use sha2::{Digest, Sha256};

#[test]
fn allocation_responses_bind_query_order_size_and_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = FetchFederatedBackupAllocations {
        grant_id: vec![4; 16],
        required_bytes: 10,
        cursor: Vec::new(),
        limit: 2,
        signature: vec![7; 64],
    };
    let mut page = FederatedBackupAllocationPage {
        request_digest: Sha256::digest(federation_backup_allocation_request_digest_payload(
            &request,
        )?)
        .to_vec(),
        authority_revision: 2,
        allocations: vec![allocation(5), allocation(6)],
        next_cursor: Vec::new(),
        signature: vec![9; 64],
    };
    assert!(allocation_page_matches(&request, &page)?);
    let mut reversed = page.clone();
    reversed.allocations.reverse();
    assert!(!allocation_page_matches(&request, &reversed)?);
    let mut substituted = page.clone();
    substituted.request_digest.fill(9);
    assert!(!allocation_page_matches(&request, &substituted)?);
    let mut too_small = page.clone();
    too_small
        .allocations
        .first_mut()
        .ok_or("allocation")?
        .maximum_bytes = 9;
    assert!(!allocation_page_matches(&request, &too_small)?);
    let mut wrong_grant = page.clone();
    wrong_grant
        .allocations
        .first_mut()
        .ok_or("allocation")?
        .scope
        .as_mut()
        .ok_or("scope")?
        .grant_id
        .fill(10);
    assert!(!allocation_page_matches(&request, &wrong_grant)?);
    let cursor = FederatedBackupAllocationCursor {
        format_version: 1,
        relationship_id: vec![1; 16],
        authority_epoch: 1,
        grant_id: vec![4; 16],
        required_bytes: 10,
        snapshot_revision: 2,
        valid_from_unix_micros: 1,
        valid_until_unix_micros: 100,
        allocation_id: vec![4; 16],
    };
    request.cursor = encode_backup_allocation_cursor(&cursor)?;
    page.request_digest = Sha256::digest(federation_backup_allocation_request_digest_payload(
        &request,
    )?)
    .to_vec();
    assert!(allocation_page_matches(&request, &page)?);
    page.authority_revision = 3;
    assert!(!allocation_page_matches(&request, &page)?);
    page.authority_revision = 2;
    page.next_cursor = encode_backup_allocation_cursor(&FederatedBackupAllocationCursor {
        allocation_id: vec![5; 16],
        ..cursor.clone()
    })?;
    assert!(
        !allocation_page_matches(&request, &page)?,
        "continuation skipped the last returned allocation"
    );
    page.next_cursor = encode_backup_allocation_cursor(&FederatedBackupAllocationCursor {
        allocation_id: vec![6; 16],
        ..cursor
    })?;
    assert!(allocation_page_matches(&request, &page)?);
    Ok(())
}

fn allocation(marker: u8) -> FederatedBackupAllocation {
    FederatedBackupAllocation {
        scope: Some(FederatedBackupScope {
            relationship_id: vec![1; 16],
            remote_mesh_id: vec![2; 16],
            provider_mesh_id: vec![3; 16],
            allocation_id: vec![marker; 16],
            grant_id: vec![4; 16],
            namespace_grant_id: vec![4; 16],
            provider_node_id: vec![7; 16],
            target_id: vec![8; 16],
            target_generation: 1,
            relationship_authority_epoch: 1,
            grant_revision: 1,
            allocation_revision: 2,
        }),
        maximum_bytes: 20,
        valid_from_unix_micros: 1,
        valid_until_unix_micros: 100,
    }
}
