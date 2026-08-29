// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::Revision;

#[test]
fn route_starts_at_root_and_delegates_without_two_writers() -> Result<(), Box<dyn std::error::Error>>
{
    let root = partition(1)?;
    let child = partition(2)?;
    let scope = DelegatedMetadataScope::new(
        ScopeId::from_bytes([3; 16])?,
        MetadataOperationFamily::Authentication,
        MetadataKeyRange::All,
    )?;
    let mut route = RootDelegatedRoute::new(root, scope, 1, 1)?;
    assert!(route.permits_write(root, 1));
    assert!(!route.permits_write(child, 1));

    route.begin_delegation(child, 2, admission(3, 3)?)?;
    assert!(route.permits_write(root, 2));
    assert!(!route.permits_write(child, 2));
    let evidence = HandoffEvidence {
        frozen_revision: Revision::new(7),
        snapshot_digest: [8; 32],
    };
    route.freeze(2, evidence)?;
    assert!(!route.permits_write(root, 2));
    assert!(!route.permits_write(child, 2));
    route.activate(child, 2, evidence)?;
    assert!(!route.permits_write(root, 2));
    assert!(route.permits_write(child, 2));
    assert_eq!(route.root_partition_id(), root);
    assert_eq!(route.route().ownership_epoch(), 2);
    Ok(())
}

#[test]
fn split_requires_membership_and_nonblank_evidence() {
    assert_eq!(
        DelegationAdmission::new(2, 3, [1; 32], [2; 32], UnixMicros::new(1)),
        Err(DelegationError::InsufficientEligibleMembers)
    );
    assert_eq!(
        DelegationAdmission::new(3, 3, [0; 32], [2; 32], UnixMicros::new(1)),
        Err(DelegationError::MissingAdmissionEvidence)
    );
}

#[test]
fn root_control_and_invalid_ranges_never_delegate() -> Result<(), Box<dyn std::error::Error>> {
    let scope_id = ScopeId::from_bytes([4; 16])?;
    assert_eq!(
        DelegatedMetadataScope::new(
            scope_id,
            MetadataOperationFamily::RootControl,
            MetadataKeyRange::All,
        ),
        Err(DelegationError::RootControlCannotMove)
    );
    assert_eq!(
        MetadataKeyRange::bounded([5; 16], [5; 16]),
        Err(DelegationError::InvalidKeyRange)
    );
    let range = MetadataKeyRange::bounded([5; 16], [7; 16])?;
    assert!(range.contains([5; 16]));
    assert!(!range.contains([7; 16]));
    Ok(())
}

#[test]
fn signing_payload_binds_capacity_relative_admission() -> Result<(), Box<dyn std::error::Error>> {
    let root = partition(10)?;
    let child = partition(11)?;
    let scope = DelegatedMetadataScope::new(
        ScopeId::from_bytes([12; 16])?,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::bounded([0; 16], [128; 16])?,
    )?;
    let mut first = RootDelegatedRoute::new(root, scope, 1, 1)?;
    let mut second = first;
    first.begin_delegation(child, 2, admission(3, 3)?)?;
    second.begin_delegation(child, 2, admission(4, 3)?)?;
    assert_ne!(first.signing_payload(), second.signing_payload());
    Ok(())
}

#[test]
fn durable_restore_rejects_scope_or_admission_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = partition(30)?;
    let child = partition(31)?;
    let first_scope = DelegatedMetadataScope::new(
        ScopeId::from_bytes([32; 16])?,
        MetadataOperationFamily::Work,
        MetadataKeyRange::All,
    )?;
    let other_scope = DelegatedMetadataScope::new(
        ScopeId::from_bytes([33; 16])?,
        MetadataOperationFamily::Work,
        MetadataKeyRange::All,
    )?;
    let active = ScopeRoute::new(first_scope.scope_id(), root, 1, 1)?;
    assert_eq!(
        RootDelegatedRoute::restore(root, other_scope, active, None),
        Err(DelegationError::InvalidRestoredState)
    );

    let mut preparing = active;
    preparing.begin_handoff(child, 2)?;
    assert_eq!(
        RootDelegatedRoute::restore(root, first_scope, preparing, None),
        Err(DelegationError::InvalidRestoredState)
    );
    assert!(
        RootDelegatedRoute::restore(root, first_scope, preparing, Some(admission(3, 3)?)).is_ok()
    );
    Ok(())
}

fn admission(
    eligible_member_count: u32,
    planned_voter_count: u8,
) -> Result<DelegationAdmission, DelegationError> {
    DelegationAdmission::new(
        eligible_member_count,
        planned_voter_count,
        [20; 32],
        [21; 32],
        UnixMicros::new(22),
    )
}

fn partition(value: u8) -> Result<PartitionId, crate::IdentifierError> {
    PartitionId::from_bytes([value; 16])
}
