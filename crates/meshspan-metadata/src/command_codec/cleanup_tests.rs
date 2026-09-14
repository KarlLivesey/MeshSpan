// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    AppendVersionCleanupItems, CommandContext, CompleteVersionCleanupItem,
    ConfirmVersionCleanupReclamation, IssueVersionCleanupPermit, SealVersionCleanupInventory,
    VersionCleanupItemPlacement, decode_authoritative_command, encode_authoritative_command,
};
use meshspan_contracts::{
    BoundedItems, ReclamationReceipt, RemovalPermit, ShardIdentity, TombstoneReceipt,
};
use meshspan_domain::{AuditEventId, MeshId, PrincipalId, TargetId, UnixMicros};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn cleanup_lifecycle_preserves_every_field_and_rejects_truncated_or_extended_frames() -> TestResult
{
    let context = context()?;
    for (kind, command) in commands()? {
        let bytes = encode_authoritative_command(context, &command)?;
        let decoded = decode_authoritative_command(&bytes)?;
        assert_eq!(decoded.context, context);
        assert_eq!(decoded.command, command);
        assert_eq!(
            decoded.command.request_digest(decoded.context),
            command.request_digest(context)
        );
        assert_eq!(
            encode_authoritative_command(decoded.context, &decoded.command)?,
            bytes
        );
        // Header is 4 + 3*16 + 8 + (1 + 8) bytes for an explicit expected revision.
        assert_eq!(&bytes[69..71], &kind.to_be_bytes());
        for length in 0..bytes.len() {
            assert!(
                decode_authoritative_command(&bytes[..length]).is_err(),
                "tag {kind}, length {length}"
            );
        }
        let mut extended = bytes;
        extended.push(0);
        assert_eq!(
            decode_authoritative_command(&extended),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    Ok(())
}

#[test]
fn terminal_cleanup_has_an_independent_golden_layout() -> TestResult {
    let command = AuthoritativeCommand::AuthoriseVersionCleanup(AuthoriseVersionCleanup {
        cleanup_operation_id: OperationId::from_bytes([4; 16])?,
        cleanup_revision: Revision::new(0x0102_0304_0506_0708),
        reachability_subject_digest: [5; 32],
    });
    let mut expected = b"MSC\x04".to_vec();
    expected.extend([1; 16]);
    expected.extend([2; 16]);
    expected.extend([3; 16]);
    expected.extend([0, 0, 0, 0, 0, 0, 0, 10]);
    expected.extend([1, 0, 0, 0, 0, 0, 0, 0, 11]);
    expected.extend([0, 128]);
    expected.extend([4; 16]);
    expected.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    expected.extend([5; 32]);
    assert_eq!(
        encode_authoritative_command(context()?, &command)?,
        expected
    );
    assert_eq!(decode_authoritative_command(&expected)?.command, command);
    Ok(())
}

#[test]
fn cleanup_inventory_rejects_counts_and_ranges_before_allocating_placements() -> TestResult {
    for (start, total, count) in [
        (0, 1, 0),
        (0, 2000, 1001),
        (u64::MAX, u64::MAX, 1),
        (1, 1, 1),
    ] {
        let mut encoder = Encoder::new(128);
        encoder.identifier([1; 16])?;
        encoder.u64(2)?;
        encoder.u64(3)?;
        encoder.u64(total)?;
        encoder.u64(start)?;
        encoder.u16(count)?;
        let bytes = encoder.finish();
        assert_eq!(
            inventory::decode_append(&mut Decoder::new(&bytes)),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    let placement = placement()?;
    for count in [0, 1001] {
        let page = AppendVersionCleanupItems {
            cleanup_operation_id: OperationId::from_bytes([1; 16])?,
            cleanup_revision: Revision::new(2),
            authorisation_revision: Revision::new(3),
            expected_item_count: 2000,
            start_index: 0,
            items: BoundedItems::new(vec![placement; count], 1001)?,
        };
        assert_eq!(
            inventory::encode_append(&mut Encoder::new(1_000_000), &page),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    Ok(())
}

fn context() -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([1; 16])?,
        actor_principal_id: PrincipalId::from_bytes([2; 16])?,
        audit_event_id: AuditEventId::from_bytes([3; 16])?,
        occurred_at: UnixMicros::new(10),
        expected_revision: Some(Revision::new(11)),
    })
}

fn commands() -> Result<Vec<(u16, AuthoritativeCommand)>, Box<dyn std::error::Error>> {
    let cleanup_operation_id = OperationId::from_bytes([4; 16])?;
    let cleanup_revision = Revision::new(5);
    let reachability_subject_digest = [6; 32];
    let mut commands = vec![
        (
            PROPOSE,
            AuthoritativeCommand::ProposeVersionCleanup(ProposeVersionCleanup {
                volume_id: VolumeId::from_bytes([7; 16])?,
                version_id: FileVersionId::from_bytes([8; 16])?,
                manifest_id: ContentManifestId::from_bytes([9; 16])?,
                manifest_root_digest: [10; 32],
                source_scan_operation_id: OperationId::from_bytes([11; 16])?,
                scan_request_digest: [12; 32],
                reachability_subject_digest,
                retention_policy_sequence: 13,
                reachability_revision: Revision::new(14),
                retained_root_count: 15,
                retained_root_digest: [16; 32],
                retained_root_set_digest: [17; 32],
                local_roots_digest: [18; 32],
                proof_result_digest: [19; 32],
            }),
        ),
        (
            ATTEST,
            AuthoritativeCommand::AttestVersionCleanup(AttestVersionCleanup {
                attestation: VersionCleanupAttestation {
                    cleanup_operation_id,
                    cleanup_revision,
                    node_id: NodeId::from_bytes([20; 16])?,
                    node_incarnation: 21,
                    key_generation: 22,
                    scan_operation_id: OperationId::from_bytes([23; 16])?,
                    scan_request_digest: [24; 32],
                    reachability_subject_digest,
                    local_roots_digest: [25; 32],
                    scan_result_digest: [26; 32],
                    signature: [27; 64],
                },
            }),
        ),
        (
            AUTHORISE,
            AuthoritativeCommand::AuthoriseVersionCleanup(AuthoriseVersionCleanup {
                cleanup_operation_id,
                cleanup_revision,
                reachability_subject_digest,
            }),
        ),
        (
            CANCEL,
            AuthoritativeCommand::CancelVersionCleanup(CancelVersionCleanup {
                cleanup_operation_id,
                cleanup_revision,
                reachability_subject_digest,
            }),
        ),
        (
            APPEND,
            AuthoritativeCommand::AppendVersionCleanupItems(AppendVersionCleanupItems {
                cleanup_operation_id,
                cleanup_revision,
                authorisation_revision: Revision::new(28),
                expected_item_count: 30,
                start_index: 29,
                items: BoundedItems::new(vec![placement()?], 1000)?,
            }),
        ),
        (
            SEAL,
            AuthoritativeCommand::SealVersionCleanupInventory(SealVersionCleanupInventory {
                cleanup_operation_id,
                cleanup_revision,
                authorisation_revision: Revision::new(28),
                expected_item_count: 30,
                inventory_digest: [31; 32],
            }),
        ),
    ];
    commands.extend(receipt_commands(cleanup_operation_id)?);
    Ok(commands)
}

fn placement() -> Result<VersionCleanupItemPlacement, meshspan_domain::IdentifierError> {
    Ok(VersionCleanupItemPlacement {
        removal_operation_id: OperationId::from_bytes([32; 16])?,
        shard: ShardIdentity {
            manifest_digest: [33; 32],
            stripe_index: 34,
            shard_index: 35,
            generation: 36,
        },
        target_id: TargetId::from_bytes([37; 16])?,
        target_generation: 38,
        storage_node_id: NodeId::from_bytes([39; 16])?,
    })
}

fn receipt_commands(
    cleanup_operation_id: OperationId,
) -> Result<Vec<(u16, AuthoritativeCommand)>, meshspan_domain::IdentifierError> {
    let item = placement()?;
    let tombstone = TombstoneReceipt {
        operation_id: item.removal_operation_id,
        shard: item.shard,
        target_id: item.target_id,
        target_generation: item.target_generation,
        permit_digest: [40; 32],
        tombstone_digest: [41; 32],
    };
    Ok(vec![
        (
            ISSUE,
            AuthoritativeCommand::IssueVersionCleanupPermit(IssueVersionCleanupPermit {
                cleanup_operation_id,
                inventory_sealed_revision: Revision::new(42),
                item_index: 43,
                attempt_sequence: 44,
                permit: RemovalPermit {
                    operation_id: item.removal_operation_id,
                    mesh_id: MeshId::from_bytes([45; 16])?,
                    target_id: item.target_id,
                    shard: item.shard,
                    target_generation: item.target_generation,
                    authority_epoch: 46,
                    catalogue_revision: Revision::new(47),
                    expires_at: UnixMicros::new(48),
                    permit_digest: [40; 32],
                },
            }),
        ),
        (
            COMPLETE,
            AuthoritativeCommand::CompleteVersionCleanupItem(CompleteVersionCleanupItem {
                cleanup_operation_id,
                inventory_sealed_revision: Revision::new(42),
                item_index: 43,
                permit_attempt_sequence: 44,
                receipt: tombstone,
                reporter_node_id: item.storage_node_id,
                reporter_incarnation: 49,
            }),
        ),
        (
            RECLAIM,
            AuthoritativeCommand::ConfirmVersionCleanupReclamation(
                ConfirmVersionCleanupReclamation {
                    cleanup_operation_id,
                    item_index: 43,
                    receipt: ReclamationReceipt {
                        tombstone,
                        bytes_unlinked_at: UnixMicros::new(50),
                        reclaimed_bytes: 51,
                        reclamation_digest: [52; 32],
                    },
                    reporter_node_id: item.storage_node_id,
                    reporter_incarnation: 49,
                },
            ),
        ),
    ])
}
