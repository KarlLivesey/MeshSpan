// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_consensus::{DurableMutation, LogEntry, LogPosition, compile_plan, flat_plan};
use meshspan_domain::{MeshId, PartitionId, QuorumPlanId, Revision, TargetId};
use meshspan_metadata::{
    PartitionDatabase, VersionCleanupItem, VersionCleanupItemCompletion,
    VersionCleanupPermitAttempt,
};
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn fresh_frontier_requires_applied_exact_history_and_current_plan() -> TestResult {
    let directory = tempfile::tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let voter = NodeId::from_bytes([2; 16])?;
    let mut repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &directory.path().join("replica.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?);
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([3; 16])?,
        1,
        BTreeSet::from([voter]),
        BTreeSet::new(),
    )?)?;
    repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(1))?;
    let entry = LogEntry::new(
        LogPosition { term: 1, index: 1 },
        OperationId::from_bytes([4; 16])?,
        u16::MAX,
        b"MSCT\x01".to_vec(),
    )?;
    let fence = MetadataReadFence {
        partition_id: partition,
        leader_node_id: voter,
        term: 1,
        membership_epoch: 1,
        plan_digest: plan.proof_digest(),
        applied: entry.position,
        applied_digest: entry.entry_digest(),
        revision: Revision::ZERO,
    };
    assert_eq!(
        repository.with_read_view(|repo| caught_up(repo, fence))?,
        Ok(false)
    );
    repository.persist_consensus_mutation(
        1,
        &DurableMutation {
            vote_state: Some((1, None)),
            truncate_from: None,
            append: vec![entry.clone()],
            membership_epoch: None,
            quorum_plan: None,
        },
        UnixMicros::new(2),
    )?;
    assert_eq!(
        repository.with_read_view(|repo| caught_up(repo, fence))?,
        Ok(false)
    );
    repository.apply_term_confirmation(&entry)?;
    assert_eq!(
        repository.with_read_view(|repo| caught_up(repo, fence))?,
        Ok(true)
    );
    for field in 0..4 {
        let mut changed = fence;
        match field {
            0 => changed.applied_digest = [9; 32],
            1 => changed.plan_digest = [9; 32],
            2 => changed.leader_node_id = NodeId::from_bytes([9; 16])?,
            _ => changed.partition_id = PartitionId::from_bytes([9; 16])?,
        }
        assert!(
            repository
                .with_read_view(|repo| caught_up(repo, changed))?
                .is_err()
        );
    }
    assert_eq!(
        repository.with_read_view(|repo| caught_up(
            repo,
            MetadataReadFence {
                revision: Revision::new(1),
                ..fence
            }
        ))?,
        Ok(false)
    );
    drop(repository);
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &directory.path().join("replica.sqlite3"),
        UnixMicros::new(3),
    )?);
    assert_eq!(
        repository.with_read_view(|repo| caught_up(repo, fence))?,
        Ok(true)
    );
    Ok(())
}

#[test]
fn cleanup_requires_exact_latest_permit_owner_epoch_and_completion() -> TestResult {
    let (mut request, mut authority, fence) = fixture()?;
    let now = UnixMicros::new(10);
    let local = authority.item.storage_node_id;
    assert_eq!(request.admit_record(&authority, local, fence, now), Ok(()));
    for field in 0..5 {
        let mut changed = authority;
        match field {
            0 => changed.item.storage_node_id = NodeId::from_bytes([9; 16])?,
            1 => changed.attempt.permit.permit_digest = [9; 32],
            2 => changed.attempt.permit.operation_id = OperationId::from_bytes([9; 16])?,
            3 => changed.attempt.permit.target_generation += 1,
            _ => changed.attempt.permit.shard.generation += 1,
        }
        assert_eq!(
            request.admit_record(&changed, local, fence, now),
            Err(ContractError::Unauthorized)
        );
    }
    assert_eq!(
        request.admit_record(
            &authority,
            local,
            MetadataReadFence {
                membership_epoch: 2,
                ..fence
            },
            now
        ),
        Err(ContractError::Unauthorized)
    );
    assert_eq!(
        request.admit_record(&authority, local, fence, UnixMicros::new(100)),
        Err(ContractError::Unauthorized)
    );
    let permit = authority.attempt.permit;
    let receipt = TombstoneReceipt {
        operation_id: permit.operation_id,
        shard: permit.shard,
        target_id: permit.target_id,
        target_generation: permit.target_generation,
        permit_digest: permit.permit_digest,
        tombstone_digest: meshspan_contracts::tombstone_receipt_digest(permit),
    };
    request.evidence = Evidence::Reclaim(receipt);
    assert_eq!(
        request.admit_record(&authority, local, fence, now),
        Err(ContractError::Unauthorized)
    );
    authority.completion = Some(VersionCleanupItemCompletion {
        cleanup_operation_id: authority.attempt.cleanup_operation_id,
        item_index: 0,
        permit_attempt_sequence: 1,
        receipt,
        reporter_node_id: local,
        reporter_incarnation: 1,
        completion_operation_id: OperationId::from_bytes([8; 16])?,
        completed_at: now,
        revision: Revision::new(5),
    });
    // A committed tombstone stays reclaimable after permit expiry; no pre-unlink accounting exists.
    assert_eq!(
        request.admit_record(&authority, local, fence, UnixMicros::new(200)),
        Ok(())
    );
    request.evidence = Evidence::Reclaim(TombstoneReceipt {
        tombstone_digest: [9; 32],
        ..receipt
    });
    assert_eq!(
        request.admit_record(&authority, local, fence, now),
        Err(ContractError::Unauthorized)
    );
    Ok(())
}

#[test]
fn request_binding_rejects_substitution_federation_and_expiry_before_quorum() -> TestResult {
    let (request, authority, _) = fixture()?;
    let permit = authority.attempt.permit;
    let wire = meshspan_protocol::v1::DeleteShardRequest {
        header: Some(request.header.clone()),
        target_id: permit.target_id.as_bytes().to_vec(),
        target_generation: 1,
        shard: Some(meshspan_protocol::v1::ShardIdentity {
            manifest_digest: permit.shard.manifest_digest.to_vec(),
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        }),
        removal_permit: Some(meshspan_protocol::v1::VersionedPayload {
            format_version: 1,
            canonical_bytes: meshspan_data_plane::encode_removal_permit(permit),
        }),
        federation_capability_digest: Vec::new(),
        federation_capability: Vec::new(),
    };
    assert!(
        MaintenanceRequest::parse(
            &Message::DeleteShardRequest(wire.clone()),
            request.peer,
            1,
            UnixMicros::new(10)
        )
        .is_ok()
    );
    for field in 0..8 {
        let mut changed = wire.clone();
        match field {
            0 => changed.target_id = vec![9; 16],
            1 => changed.target_generation += 1,
            2 => changed.shard.as_mut().ok_or("shard")?.generation += 1,
            3 => changed.federation_capability_digest = vec![9; 32],
            4 => changed.header.as_mut().ok_or("header")?.sender_incarnation += 1,
            5 => {
                changed
                    .header
                    .as_mut()
                    .ok_or("header")?
                    .deadline_unix_micros = i64::MAX;
            }
            6 => changed.header.as_mut().ok_or("header")?.operation_id = vec![9; 16],
            _ => {
                changed
                    .removal_permit
                    .as_mut()
                    .ok_or("permit")?
                    .format_version = 2;
            }
        }
        assert!(
            MaintenanceRequest::parse(
                &Message::DeleteShardRequest(changed),
                request.peer,
                1,
                UnixMicros::new(10)
            )
            .is_err(),
            "accepted field {field}"
        );
    }
    assert!(
        MaintenanceRequest::parse(
            &Message::DeleteShardRequest(wire),
            request.peer,
            1,
            UnixMicros::new(100)
        )
        .is_err()
    );
    Ok(())
}

fn fixture() -> Result<
    (
        MaintenanceRequest,
        VersionCleanupStorageAuthority,
        MetadataReadFence,
    ),
    Box<dyn std::error::Error>,
> {
    let operation = OperationId::from_bytes([1; 16])?;
    let mesh = MeshId::from_bytes([2; 16])?;
    let local = NodeId::from_bytes([3; 16])?;
    let peer = PeerBinding {
        node_id: NodeId::from_bytes([4; 16])?,
        incarnation: 1,
        certificate_fingerprint: [5; 32],
    };
    let permit = RemovalPermit {
        operation_id: operation,
        mesh_id: mesh,
        target_id: TargetId::from_bytes([6; 16])?,
        shard: ShardIdentity {
            manifest_digest: [7; 32],
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        },
        target_generation: 1,
        authority_epoch: 1,
        catalogue_revision: Revision::new(4),
        expires_at: UnixMicros::new(100),
        permit_digest: [8; 32],
    };
    let authority = VersionCleanupStorageAuthority {
        item: VersionCleanupItem {
            item_index: 0,
            removal_operation_id: operation,
            shard: permit.shard,
            target_id: permit.target_id,
            target_generation: 1,
            storage_node_id: local,
            revision: Revision::new(3),
        },
        attempt: VersionCleanupPermitAttempt {
            cleanup_operation_id: OperationId::from_bytes([10; 16])?,
            item_index: 0,
            attempt_sequence: 1,
            permit,
            issue_operation_id: OperationId::from_bytes([11; 16])?,
            issued_at: UnixMicros::new(1),
            revision: Revision::new(4),
        },
        completion: None,
    };
    let request = MaintenanceRequest {
        header: RequestHeader {
            mesh_id: mesh.as_bytes().to_vec(),
            operation_id: operation.as_bytes().to_vec(),
            sender_node_id: peer.node_id.as_bytes().to_vec(),
            sender_incarnation: 1,
            deadline_unix_micros: 90,
            routing_epoch: 1,
            ..RequestHeader::default()
        },
        evidence: Evidence::Delete(permit),
        peer,
    };
    let fence = MetadataReadFence {
        partition_id: PartitionId::from_bytes([12; 16])?,
        leader_node_id: peer.node_id,
        term: 1,
        membership_epoch: 1,
        plan_digest: [13; 32],
        applied: LogPosition { term: 1, index: 4 },
        applied_digest: [14; 32],
        revision: Revision::new(4),
    };
    Ok((request, authority, fence))
}
